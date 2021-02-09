#include "ascore.h"
#include "log.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#define AS_EPOLL_NUM 50

#define SOCKET_LAZY_INIT -1

#define SOCKET_TYPE_TCP 1
#define SOCKET_TYPE_UDP 2
#define SOCKET_TYPE_UDP_FAKE 4

#define AS_STATUS_CONNECTED 0x01
#define AS_STATUS_LISTENED 0x02
#define AS_STATUS_CLOSED 0x08
#define AS_STATUS_INEPOLL 0x10

#define EPOLL_TIMEOUT 500

struct as_loop_s
{
    as_socket_t *header;
    as_socket_t *last;
    int epfd;
};

typedef struct as_buffer_s
{
    struct as_buffer_s *next;
    unsigned char *data;
    size_t len;
    size_t wrote_len;
    void *wrote_cb;
    as_udp_t *udp;
} as_buffer_t;

struct as_socket_s
{
    as_loop_t *loop;
    struct as_socket_s *next;
    char type;
    void *data;
    struct as_socket_s *map;
    int fd;
    char is_srv;
    /*
     * 0x00: nothing
     * 0x_1: connected
     * 0x_2: listened
     * 0x_8: closed;
     * 0x1_: has epoll event
     */
    char status;
    uint32_t events;
    uint32_t read_flags;
    struct
    {
        as_buffer_t *header;
        as_buffer_t *last;
    } write_queue;
    struct sockaddr_storage addr;
    as_socket_destroying_f dest_cb;
};

struct as_tcp_s
{
    as_socket_t sck;
    as_tcp_accepted_f accept_cb;
    as_tcp_connected_f conned_cb;
    as_tcp_read_f read_cb;
};

struct as_udp_s
{
    as_socket_t sck;
    struct as_udp_s *udp_server;
    time_t udp_timeout;
    as_udp_accepted_f accept_cb;
    as_udp_read_f read_cb;
};

static int __set_timeout(int fd)
{
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    timeout.tv_sec = AS_SOCKET_TIMEOUT;
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) != 0)
        return 1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
}

static int __set_reuseaddr(int fd)
{
    int on = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

static int __set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1)
        return flags;
    flags = flags | O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static int __get_socket_error(int fd, char *serrno)
{
	socklen_t len = 1;
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, serrno, &len);
}

static void __as_socket_init(as_socket_t *sck, as_loop_t *loop, void *data, as_socket_destroying_f cb)
{
    memset(sck, 0, sizeof(as_socket_t));
    sck->loop = loop;
    sck->next = NULL;
    sck->data = data;
    sck->map = NULL;
    //we don't know ipv4 or ipv6
    //so not create socket in there
    sck->fd = SOCKET_LAZY_INIT;
    sck->dest_cb = cb;
    sck->write_queue.header = NULL;
    sck->write_queue.last = NULL;
}

static void __free_write_queue(as_socket_t *sck)
{
    void *p;
    as_buffer_t *asbuf = sck->write_queue.header;
    while(asbuf != NULL)
    {
        free(asbuf->data);
        p = asbuf;
        asbuf = asbuf->next;
        free(p);
    }
}

static void __socket_close_event(as_loop_t *loop)
{
    void *sfree;
    as_socket_t *s, *p;
    s = loop->header;
    p = NULL;
    while(s != NULL)
    {
        if(s->status & AS_STATUS_CLOSED)
        {
            if(p == NULL)
                loop->header = s->next;
            else
                p->next = s->next;
            if(s->next == NULL)
                loop->last = p;
            __free_write_queue(s);
            if(s->dest_cb != NULL)
            {
                s->dest_cb(s);
            }
            if(s->type != SOCKET_TYPE_UDP_FAKE)
            {
                if(s->fd > 0)
                {
                    close(s->fd);
                    LOG_DEBUG("%d is closed\n", s->fd);
                }
            }
            if(s->map != NULL)
                s->map->map = NULL;
            sfree = s;
            s = s->next;
            free(sfree);
            continue;
        }
        if(s->type == SOCKET_TYPE_UDP_FAKE)
        {
            if(difftime(time(NULL), ((as_udp_t *) s)->udp_timeout) > AS_SOCKET_TIMEOUT)
                as_close(s);
        }
        p = s;
        s = s->next;
    }
}

void __tcp_on_accept(as_tcp_t *tcp)
{
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    int fd = accept(tcp->sck.fd, (struct sockaddr *) &addr, &addrl);
    if(fd <= 0)
        return;
    LOG_DEBUG("fd = %d is inited\n", fd);
    __set_non_blocking(tcp->sck.fd);
    if(tcp->accept_cb == NULL)
        return;
    as_tcp_t *client = as_tcp_init(tcp->sck.loop, NULL, NULL);
    client->sck.fd = fd;
    memcpy(&client->sck.addr, &addr, addrl);
    client->sck.status = AS_STATUS_CONNECTED;
    if(tcp->accept_cb(tcp, client, &client->sck.data, &client->sck.dest_cb) != 0)
        as_close((as_socket_t *) client);
}

void __tcp_on_read(as_tcp_t *tcp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(&msg, '\0', sizeof(struct msghdr));
    memset(cntrlbuf, '\0', 64);
    msg.msg_control = cntrlbuf;
    msg.msg_controllen = 64;
    msg.msg_name = &addr;
    msg.msg_namelen = addrl;
    iov.iov_base = buf;
    iov.iov_len = AS_BUFFER_SIZE;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    while(1)
    {
        ssize_t read = recvmsg(tcp->sck.fd, &msg, MSG_NOSIGNAL);
        if(read > 0)
        {
            if(tcp->sck.read_flags & AS_READ_ONESHOT)
            {
                tcp->sck.events &= ~EPOLLIN;
                ev.data.fd = tcp->sck.fd;
                ev.data.ptr = tcp;
                ev.events = tcp->sck.events;
                epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
            }
            if(tcp->read_cb != NULL)
            {
                if(tcp->read_cb(tcp, &msg, buf, read) != 0)
                {
                    as_close((as_socket_t *) tcp);
                    free(buf);
                    return;
                }
            }
        }
        else if(read == 0)
        {
            as_close((as_socket_t *) tcp);
        }
        else
        {
            switch (errno)
            {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                as_close((as_socket_t *) tcp);
                break;
            }
        }
        break;
    }
    free(buf);
}

void __tcp_on_connected(as_tcp_t *tcp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    tcp->sck.status |= AS_STATUS_CONNECTED;
    tcp->sck.events &= ~EPOLLOUT;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
    if(tcp->conned_cb != NULL)
    {
        if(tcp->conned_cb(tcp, 0) != 0)
        {
            as_close((as_socket_t *) tcp);
            return;
        }
    }
}

void __tcp_on_write(as_tcp_t *tcp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    as_buffer_t *buf = tcp->sck.write_queue.header;
    if(buf != NULL)
    {
        if(buf->len == buf->wrote_len)
        {
            if(buf->wrote_cb != NULL)
            {
                if(((as_tcp_wrote_f) buf->wrote_cb)(tcp, buf->data, buf->len) != 0)
                {
                    as_close((as_socket_t *) tcp);
                    return;
                }
            }
            tcp->sck.write_queue.header = buf->next;
            free(buf->data);
            free(buf);
            buf = tcp->sck.write_queue.header;
        }
    }
    if(buf == NULL)
    {
        tcp->sck.events &= ~EPOLLOUT;
        ev.data.fd = tcp->sck.fd;
        ev.data.ptr = tcp;
        ev.events = tcp->sck.events;
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
        return;
    }
    while(1)
    {
        ssize_t wrtn = send(tcp->sck.fd, buf->data + buf->wrote_len, buf->len - buf->wrote_len, MSG_NOSIGNAL);
        if(wrtn > 0)
        {
            buf->wrote_len += wrtn;
        }
        else if(wrtn == 0)
        {
            as_close((as_socket_t *) tcp);
        }
        else
        {
            switch (errno)
            {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                as_close((as_socket_t *) tcp);
                break;
            }
        }
        break;
    }
}

void __udp_on_accept(as_udp_t *udp)
{
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(&msg, '\0', sizeof(struct msghdr));
    memset(cntrlbuf, '\0', 64);
    msg.msg_control = cntrlbuf;
    msg.msg_controllen = 64;
    msg.msg_name = &addr;
    msg.msg_namelen = addrl;
    iov.iov_base = buf;
    iov.iov_len = AS_BUFFER_SIZE;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ssize_t read = recvmsg(udp->sck.fd, &msg, MSG_NOSIGNAL);
    if(read > 0)
    {
        as_udp_t *client = as_udp_init(udp->sck.loop, NULL, NULL);
        client->sck.type = SOCKET_TYPE_UDP_FAKE;
        client->udp_server = udp;
        client->sck.fd = udp->sck.fd;
        client->udp_timeout = time(NULL);
        memcpy(&client->sck.addr, &addr, addrl);
        if(udp->accept_cb != NULL) 
        {
            if(udp->accept_cb(udp, client, &client->sck.data, &client->sck.dest_cb) != 0)
            {
                as_close((as_socket_t *) client);
                free(buf);
                return;
            }
        }
        if(client->read_cb != NULL)
        {
            if(client->read_cb(client, &msg, buf, read) != 0)
            {
                as_close((as_socket_t *) client);
                free(buf);
                return;
            }
        }
    }
    free(buf);
}

void __udp_on_read(as_udp_t *udp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(&msg, '\0', sizeof(struct msghdr));
    memset(cntrlbuf, '\0', 64);
    msg.msg_control = cntrlbuf;
    msg.msg_controllen = 64;
    msg.msg_name = &addr;
    msg.msg_namelen = addrl;
    iov.iov_base = buf;
    iov.iov_len = AS_BUFFER_SIZE;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    while(1)
    {
        ssize_t read = recvmsg(udp->sck.fd, &msg, MSG_NOSIGNAL);
        if(read > 0)
        {
            if(udp->sck.read_flags & AS_READ_ONESHOT)
            {
                udp->sck.events &= ~EPOLLIN;
                ev.data.fd = udp->sck.fd;
                ev.data.ptr = udp;
                ev.events = udp->sck.events;
                epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
            }
            if(udp->read_cb != NULL)
            {
                if(udp->read_cb(udp, &msg, buf, read) != 0)
                {
                    as_close((as_socket_t *) udp);
                    free(buf);
                    return;
                }
            }
        }
        else if(read == 0)
        {
            as_close((as_socket_t *) udp);
        }
        else
        {
            switch (errno)
            {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                as_close((as_socket_t *) udp);
                break;
            }
        }
        break;
    }
    free(buf);
}

void __udp_fake_on_write(as_udp_t *udp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    as_buffer_t *buf = udp->sck.write_queue.header;
    if(buf != NULL)
    {
        if(buf->len == buf->wrote_len)
        {
            buf->udp->udp_timeout = time(NULL);
            if(buf->wrote_cb != NULL)
            {
                if(((as_udp_wrote_f) buf->wrote_cb)(buf->udp, buf->data, buf->len) != 0)
                {
                    as_close((as_socket_t *) buf->udp);
                    udp->sck.write_queue.header = buf->next;
                    free(buf->data);
                    free(buf);
                    return;
                }
            }
            udp->sck.write_queue.header = buf->next;
            free(buf->data);
            free(buf);
            buf = udp->sck.write_queue.header;
        }
    }
    if(buf == NULL)
    {
        udp->sck.events &= ~EPOLLOUT;
        ev.data.fd = udp->sck.fd;
        ev.data.ptr = udp;
        ev.events = udp->sck.events;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
        return;
    }
    while(1)
    {
        ssize_t wrtn = sendto(udp->sck.fd, buf->data + buf->wrote_len, buf->len - buf->wrote_len, MSG_NOSIGNAL, (struct sockaddr *) &buf->udp->sck.addr, sizeof(buf->udp->sck.addr));
        if(wrtn > 0)
        {
            buf->wrote_len += wrtn;
        }
        else if(wrtn == 0)
        {
            as_close((as_socket_t *) buf->udp);
            udp->sck.write_queue.header = buf->next;
            free(buf->data);
            free(buf);
        }
        else
        {
            switch (errno)
            {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                as_close((as_socket_t *) udp);
                udp->sck.write_queue.header = buf->next;
                free(buf->data);
                free(buf);
                break;
            }
        }
        break;
    }
}

void __udp_on_write(as_udp_t *udp)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    as_buffer_t *buf = udp->sck.write_queue.header;
    if(buf != NULL)
    {
        if(buf->len == buf->wrote_len)
        {
            if(buf->wrote_cb != NULL)
            {
                if(((as_udp_wrote_f) buf->wrote_cb)(udp, buf->data, buf->len) != 0)
                {
                    as_close((as_socket_t *) udp);
                    return;
                }
            }
            udp->sck.write_queue.header = buf->next;
            free(buf->data);
            free(buf);
            buf = udp->sck.write_queue.header;
        }
    }
    if(buf == NULL)
    {
        udp->sck.events &= ~EPOLLOUT;
        ev.data.fd = udp->sck.fd;
        ev.data.ptr = udp;
        ev.events = udp->sck.events;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
        return;
    }
    while(1)
    {
        ssize_t wrtn = sendto(udp->sck.fd, buf->data + buf->wrote_len, buf->len - buf->wrote_len, MSG_NOSIGNAL, (struct sockaddr *) &udp->sck.addr, sizeof(udp->sck.addr));
        if(wrtn > 0)
        {
            buf->wrote_len += wrtn;
        }
        else if(wrtn == 0)
        {
            as_close((as_socket_t *) udp);
        }
        else
        {
            switch (errno)
            {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                as_close((as_socket_t *) udp);
                break;
            }
        }
        break;
    }
}

void __socket_handle_epollin(as_socket_t *sck)
{
    if(sck->type == SOCKET_TYPE_TCP)
    {
        if(sck->is_srv == 1)
            __tcp_on_accept((as_tcp_t *) sck);
        else
            __tcp_on_read((as_tcp_t *) sck);
    }
    else
    {
        if(sck->is_srv == 1)
            __udp_on_accept((as_udp_t *) sck);
        else
            __udp_on_read((as_udp_t *) sck);
    }
    
}

void __socket_handle_epollout(as_socket_t *sck)
{
    if(sck->type == SOCKET_TYPE_TCP)
    {
        if(sck->status & AS_STATUS_CONNECTED)
            __tcp_on_write((as_tcp_t *) sck);
        else
            __tcp_on_connected((as_tcp_t *) sck);
    }
    else
    {
        if(sck->is_srv == 1)
            __udp_fake_on_write((as_udp_t *) sck);
        else
            __udp_on_write((as_udp_t *) sck);
    }
    
}

as_loop_t *as_loop_init()
{
    as_loop_t *loop = (as_loop_t *) malloc(sizeof(as_loop_t));
    if(loop == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    loop->header = NULL;
    loop->epfd = epoll_create1(0);
    if(loop->epfd < 0)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    return loop;
}

as_tcp_t *as_tcp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb)
{
    as_tcp_t *tcp = (as_tcp_t *) malloc(sizeof(as_tcp_t));
    if(tcp == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    __as_socket_init(&tcp->sck, loop, data, cb);
    if(loop->header == NULL)
        loop->header = (as_socket_t *) tcp;
    else
        loop->last->next = (as_socket_t *) tcp;
    loop->last = (as_socket_t *) tcp;
    tcp->sck.type = SOCKET_TYPE_TCP;
    tcp->accept_cb = NULL;
    tcp->conned_cb = NULL;
    tcp->read_cb = NULL;
    return tcp;
}

int as_tcp_bind(as_tcp_t *tcp, struct sockaddr *addr, int flags)
{
    int on = 1;
    if(tcp->sck.fd != SOCKET_LAZY_INIT)
        return 1;
    tcp->sck.fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->sck.fd <= 0)
        return 1;
    LOG_DEBUG("fd = %d is inited\n", tcp->sck.fd);
    __set_timeout(tcp->sck.fd);
    __set_reuseaddr(tcp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        if(flags & AS_TCP_IPV6ONLY)
        {
            if(setsockopt(tcp->sck.fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(flags & AS_TCP_TPROXY)
        {
            //need root
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(tcp->sck.fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(tcp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(flags & AS_TCP_TPROXY)
        {
            //need root
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(tcp->sck.fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_tcp_listen(as_tcp_t *tcp, as_tcp_accepted_f cb)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    int rtn = listen(tcp->sck.fd, AS_MAX_LISTEN);
    if(rtn != 0)
        return rtn;
    tcp->sck.is_srv = 1;
    tcp->sck.status = AS_STATUS_INEPOLL | AS_STATUS_LISTENED;
    tcp->accept_cb = cb;
    tcp->sck.events = EPOLLIN;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    return 0;
}

int as_tcp_connect(as_tcp_t *tcp, struct sockaddr *addr, as_tcp_connected_f cb)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    tcp->sck.fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->sck.fd <= 0)
        return 1;
    LOG_DEBUG("fd = %d is inited\n", tcp->sck.fd);
    __set_timeout(tcp->sck.fd);
    __set_non_blocking(tcp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        int rtn = connect(tcp->sck.fd, addr, sizeof(struct sockaddr_in6));
        if(rtn != 0 && errno != EINPROGRESS)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        int rtn = connect(tcp->sck.fd, addr, sizeof(struct sockaddr_in));
        if(rtn != 0 && errno != EINPROGRESS)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    tcp->sck.status |= AS_STATUS_INEPOLL;
    tcp->conned_cb = cb;
    tcp->sck.events = EPOLLOUT;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    return 0;
}

int as_tcp_read_start(as_tcp_t *tcp, as_tcp_read_f cb, int flags)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(tcp->sck.fd <= 0)
        return 1;
    tcp->read_cb = cb;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    tcp->sck.events |= EPOLLIN;
    tcp->sck.read_flags = AS_READ_ONESHOT;
    ev.events = tcp->sck.events;
    if(tcp->sck.status & AS_STATUS_INEPOLL)
    {
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
    }
    else
    {
        tcp->sck.status |= AS_STATUS_INEPOLL;
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    }
    return 0;
}

int as_tcp_write(as_tcp_t *tcp, __const__ unsigned char *buf, __const__ size_t len, as_tcp_wrote_f cb)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(tcp->sck.fd <= 0)
        return -1;
    as_buffer_t *asbuf = (as_buffer_t *) malloc(sizeof(as_buffer_t));
    if(asbuf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asbuf->data = (unsigned char *) malloc(len);
    if(asbuf->data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memcpy(asbuf->data, buf, len);
    asbuf->len = len;
    asbuf->wrote_len = 0;
    asbuf->wrote_cb = cb;
    asbuf->next = NULL;
    if(tcp->sck.write_queue.header == NULL)
        tcp->sck.write_queue.header = asbuf;
    else
        tcp->sck.write_queue.last->next = asbuf;
    tcp->sck.write_queue.last = asbuf;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    tcp->sck.events |= EPOLLOUT;
    ev.events = tcp->sck.events;
    if(tcp->sck.status & AS_STATUS_INEPOLL)
    {
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
    }
    else
    {
        tcp->sck.status |= AS_STATUS_INEPOLL;
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    }
    return 0;
}

as_udp_t *as_udp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb)
{
    as_udp_t *udp = (as_udp_t *) malloc(sizeof(as_udp_t));
    if(udp == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    __as_socket_init(&udp->sck, loop, data, cb);
    if(loop->header == NULL)
        loop->header = (as_socket_t *) udp;
    else
        loop->last->next = (as_socket_t *) udp;
    loop->last = (as_socket_t *) udp;
    udp->udp_timeout = time(NULL);
    udp->sck.type = SOCKET_TYPE_UDP;
    udp->udp_server = NULL;
    udp->accept_cb = NULL;
    udp->read_cb = NULL;
    return udp;
}

int as_udp_bind(as_udp_t *udp, struct sockaddr *addr, int flags)
{
    int on = 1;
    if(udp->sck.fd != SOCKET_LAZY_INIT)
        return 1;
    udp->sck.fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(udp->sck.fd <= 0)
        return 1;
    LOG_DEBUG("fd = %d is inited\n", udp->sck.fd);
    __set_timeout(udp->sck.fd);
    __set_reuseaddr(udp->sck.fd);
    __set_non_blocking(udp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        if(flags & AS_UDP_IPV6ONLY)
        {
            if(setsockopt(udp->sck.fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(flags & AS_UDP_TPROXY)
        {
            //need root
            if(setsockopt(udp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(udp->sck.fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(udp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(flags & AS_UDP_TPROXY)
        {
            //need root
            if(setsockopt(udp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(udp->sck.fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(udp->sck.fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_udp_listen(as_udp_t *udp, as_udp_accepted_f cb)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    udp->sck.is_srv = 1;
    udp->sck.status = AS_STATUS_INEPOLL | AS_STATUS_LISTENED;
    udp->accept_cb = cb;
    udp->sck.events = EPOLLIN;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    ev.events = udp->sck.events;
    epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
    return 0;
}

int as_udp_connect(as_udp_t *udp, struct sockaddr *addr)
{
    if(udp->sck.fd != SOCKET_LAZY_INIT)
        return 1;
    udp->sck.fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(udp->sck.fd <= 0)
        return 1;
    LOG_DEBUG("fd = %d is inited\n", udp->sck.fd);
    __set_timeout(udp->sck.fd);
    __set_non_blocking(udp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_udp_read_start(as_udp_t *udp, as_udp_read_f cb, int flags)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(udp->sck.fd <= 0)
        return 1;
    udp->read_cb = cb;
    if(udp->sck.type == SOCKET_TYPE_UDP_FAKE)
        return 0;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    udp->sck.events |= EPOLLIN;
    udp->sck.read_flags = flags;
    ev.events = udp->sck.events;
    if(udp->sck.status & AS_STATUS_INEPOLL)
    {
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
    }
    else
    {
        udp->sck.status |= AS_STATUS_INEPOLL;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
    }
    return 0;
}

int as_udp_write(as_udp_t *udp, __const__ unsigned char *buf, __const__ size_t len, as_udp_wrote_f cb)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(udp->sck.type == SOCKET_TYPE_UDP_FAKE)
    {
        as_udp_t *udp_server = udp->udp_server;
        as_buffer_t *asbuf = (as_buffer_t *) malloc(sizeof(as_buffer_t));
        if(asbuf == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        asbuf->data = (unsigned char *) malloc(len);
        if(asbuf->data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        memcpy(asbuf->data, buf, len);
        asbuf->len = len;
        asbuf->wrote_len = 0;
        asbuf->wrote_cb = cb;
        asbuf->next = NULL;
        asbuf->udp = udp;
        if(udp_server->sck.write_queue.header == NULL)
            udp_server->sck.write_queue.header = asbuf;
        else
            udp_server->sck.write_queue.last->next = asbuf;
        udp_server->sck.write_queue.last = asbuf;
        ev.data.fd = udp_server->sck.fd;
        ev.data.ptr = udp_server;
        udp_server->sck.events |= EPOLLOUT;
        ev.events = udp_server->sck.events;
        epoll_ctl(udp_server->sck.loop->epfd, EPOLL_CTL_MOD, udp_server->sck.fd, &ev);
        return 0;
    }
    if(udp->sck.fd <= 0)
        return -1;
    as_buffer_t *asbuf = (as_buffer_t *) malloc(sizeof(as_buffer_t));
    if(asbuf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asbuf->data = (unsigned char *) malloc(len);
    if(asbuf->data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memcpy(asbuf->data, buf, len);
    asbuf->len = len;
    asbuf->wrote_len = 0;
    asbuf->wrote_cb = cb;
    asbuf->next = NULL;
    if(udp->sck.write_queue.header == NULL)
        udp->sck.write_queue.header = asbuf;
    else
        udp->sck.write_queue.last->next = asbuf;
    udp->sck.write_queue.last = asbuf;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    udp->sck.events |= EPOLLOUT;
    ev.events = udp->sck.events;
    if(udp->sck.status & AS_STATUS_INEPOLL)
    {
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
    }
    else
    {
        udp->sck.status |= AS_STATUS_INEPOLL;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
    }
    return 0;
}

void as_socket_map_bind(as_socket_t *sck1, as_socket_t *sck2)
{
    sck1->map = sck2;
    sck2->map = sck1;
}

int as_close(as_socket_t *sck)
{
    if(sck->status & AS_STATUS_INEPOLL)
        epoll_ctl(sck->loop->epfd, EPOLL_CTL_DEL, sck->fd, NULL);
    sck->status |= AS_STATUS_CLOSED;
    if(sck->map != NULL)
    {
        as_socket_t *sckmap = sck->map;
        if(sckmap->status & AS_STATUS_INEPOLL)
            epoll_ctl(sckmap->loop->epfd, EPOLL_CTL_DEL, sckmap->fd, NULL);
        sckmap->status |= AS_STATUS_CLOSED;
    }
    return 0;
}

void *as_socket_data(as_socket_t *sck)
{
    return sck->data;
}

as_loop_t *as_socket_loop(as_socket_t *sck)
{
    return sck->loop;
}

as_socket_t *as_socket_map(as_socket_t *sck)
{
    return sck->map;
}

int as_fd(as_socket_t *sck)
{
    return sck->fd;
}

int as_socket_error(as_socket_t *sck, char *serrno)
{
    return __get_socket_error(sck->fd, serrno);
}

struct sockaddr_storage *as_dest_addr(as_socket_t *sck)
{
    return &sck->addr;
}

int as_loop_run(as_loop_t *loop)
{
    struct epoll_event events[AS_EPOLL_NUM];
    int wait_count;
    while(1)
    {
        __socket_close_event(loop);
        wait_count = epoll_wait(loop->epfd, events, AS_EPOLL_NUM, EPOLL_TIMEOUT);
        for(int i = 0 ; i < wait_count; i++)
        {
            uint32_t events_flags = events[i].events;
            as_socket_t *sck = (as_socket_t *) events[i].data.ptr;
            if(events_flags & EPOLLERR || events_flags & EPOLLHUP)
            {
                if(sck->type == SOCKET_TYPE_TCP && sck->is_srv == 0 && sck->events & EPOLLOUT && !(sck->status & AS_STATUS_CONNECTED))
                {
                    as_tcp_t *tcp = (as_tcp_t *) sck;
                    if(tcp->conned_cb != NULL)
                    {
                        if(tcp->conned_cb(tcp, 1) != 0)
                            as_close(sck);
                    }
                    sck->events &= ~EPOLLOUT;
                }
                else
                {
                    as_close(sck);
                }
                continue;
            }            
            if(sck->status & AS_STATUS_CLOSED)
                continue;
            if(events_flags & EPOLLIN)
                __socket_handle_epollin(sck);
            if(events_flags & EPOLLOUT)
                __socket_handle_epollout(sck);
        }
    }
    return 0;
}
