#include "ascore.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#if defined __linux__
#include <sys/epoll.h>
#elif defined _WIN32 || defined __CYGWIN__
#include <Ws2tcpip.h>
#else
#include <sys/select.h>
#endif
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#define SOCKET_LAZY_INIT -1

#define SOCKET_TYPE_TCP 1
#define SOCKET_TYPE_UDP 2
#define SOCKET_TYPE_UDP_FAKE 4

#define AS_STATUS_CONNECTED 0x01
#define AS_STATUS_LISTENED 0x02
#define AS_STATUS_CLOSED 0x08
#define AS_STATUS_INEPOLL 0x10

#define IO_MUXING_TIMEOUT 500

#ifdef __linux__
#define AS_EPOLL_NUM 50
#else
#define AS_EVENTS_READ 0x01
#define AS_EVENTS_WRITE 0x02
#endif

#if defined _WIN32 || defined __CYGWIN__
typedef int socklen_t;
#define MSG_NOSIGNAL 0
#endif

struct as_loop_s
{
    as_socket_t *header;
    as_socket_t *last;
#ifdef __linux__
    int epfd;
#else
    fd_set read_set;
    fd_set write_set;
    fd_set except_set;
#endif
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
#if defined _WIN32 || defined __CYGWIN__
    u_long imode = 1L;
    return ioctlsocket(fd, FIONBIO, &imode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1)
        return flags;
    flags = flags | O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
#endif
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
#if !(defined _WIN32 || defined __CYGWIN__)
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
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
#endif
    while(1)
    {
#if defined _WIN32 || defined __CYGWIN__
        ssize_t read = recv(tcp->sck.fd, buf, AS_BUFFER_SIZE, 0);
#else
        ssize_t read = recvmsg(tcp->sck.fd, &msg, MSG_NOSIGNAL);
#endif
        if(read > 0)
        {
            if(tcp->sck.read_flags & AS_READ_ONESHOT)
            {
#ifdef __linux__
                tcp->sck.events &= ~EPOLLIN;
                ev.data.fd = tcp->sck.fd;
                ev.data.ptr = tcp;
                ev.events = tcp->sck.events;
                epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
#else
                tcp->sck.events &= ~AS_EVENTS_READ;
#endif
            }
            if(tcp->read_cb != NULL)
            {
                if(tcp->read_cb(
                    tcp
#if defined _WIN32 || defined __CYGWIN__
                    , NULL
#else
                    , &msg
#endif
                    , buf
                    , read) != 0)
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    tcp->sck.status |= AS_STATUS_CONNECTED;
#ifdef __linux__
    tcp->sck.events &= ~EPOLLOUT;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
#else
    tcp->sck.events &= ~AS_EVENTS_WRITE;
#endif
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
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
#ifdef __linux__
        tcp->sck.events &= ~EPOLLOUT;
        ev.data.fd = tcp->sck.fd;
        ev.data.ptr = tcp;
        ev.events = tcp->sck.events;
        epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_MOD, tcp->sck.fd, &ev);
#else
        tcp->sck.events &= ~AS_EVENTS_WRITE;
#endif
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
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
#if !(defined _WIN32 || defined __CYGWIN__)
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
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
#else
    ssize_t read = recvfrom(udp->sck.fd, buf, AS_BUFFER_SIZE, 0, (struct sockaddr *) &addr, &addrl);
#endif
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
            if(client->read_cb(
                client
#if defined _WIN32 || defined __CYGWIN__
                , NULL
#else
                , &msg
#endif
                , buf
                , read) != 0)
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    unsigned char *buf = (unsigned char *) malloc(AS_BUFFER_SIZE);
    if(buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
#if !(defined _WIN32 || defined __CYGWIN__)
    struct msghdr msg;
    char cntrlbuf[64];
    struct iovec iov;
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
#endif
    while(1)
    {
#if defined _WIN32 || defined __CYGWIN__
        ssize_t read = recvfrom(udp->sck.fd, buf, AS_BUFFER_SIZE, 0, (struct sockaddr *) &addr, &addrl);
#else
        ssize_t read = recvmsg(udp->sck.fd, &msg, MSG_NOSIGNAL);
#endif
        if(read > 0)
        {
            if(udp->sck.read_flags & AS_READ_ONESHOT)
            {
#ifdef __linux__
                udp->sck.events &= ~EPOLLIN;
                ev.data.fd = udp->sck.fd;
                ev.data.ptr = udp;
                ev.events = udp->sck.events;
                epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
#else
                udp->sck.events &= ~AS_EVENTS_READ;
#endif
            }
            if(udp->read_cb != NULL)
            {
                if(udp->read_cb(
                    udp
#if defined _WIN32 || defined __CYGWIN__
                    , NULL
#else
                    , &msg
#endif
                    , buf
                    , read) != 0)
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    as_buffer_t *buf = udp->sck.write_queue.header;
    if(buf != NULL)
    {
        if(buf->len == buf->wrote_len)
        {
            if(buf->udp != NULL)
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
            }
            udp->sck.write_queue.header = buf->next;
            free(buf->data);
            free(buf);
            buf = udp->sck.write_queue.header;
        }
    }
    if(buf == NULL)
    {
#ifdef __linux__
        udp->sck.events &= ~EPOLLOUT;
        ev.data.fd = udp->sck.fd;
        ev.data.ptr = udp;
        ev.events = udp->sck.events;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
#else
        udp->sck.events &= ~AS_EVENTS_WRITE;
#endif
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
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
#ifdef __linux__
        udp->sck.events &= ~EPOLLOUT;
        ev.data.fd = udp->sck.fd;
        ev.data.ptr = udp;
        ev.events = udp->sck.events;
        epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_MOD, udp->sck.fd, &ev);
#else
        udp->sck.events &= ~AS_EVENTS_WRITE;
#endif
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

void __socket_handle_read(as_socket_t *sck)
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

void __socket_handle_write(as_socket_t *sck)
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

void __as_close(as_socket_t *sck)
{
#ifdef __linux__
    if(sck->status & AS_STATUS_INEPOLL)
        epoll_ctl(sck->loop->epfd, EPOLL_CTL_DEL, sck->fd, NULL);
#endif
    sck->status |= AS_STATUS_CLOSED;
    if(sck->type == SOCKET_TYPE_UDP_FAKE)
    {
        as_udp_t *udp = (as_udp_t *) sck;
        for(as_buffer_t *asbuf = udp->udp_server->sck.write_queue.header; asbuf != NULL; asbuf = asbuf->next)
        {
            if(asbuf->udp == udp)
                asbuf->udp = NULL;
        } 
    }
}

as_loop_t *as_loop_init()
{
#if defined _WIN32 || defined __CYGWIN__
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
        return NULL;
#endif
    as_loop_t *loop = (as_loop_t *) malloc(sizeof(as_loop_t));
    if(loop == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    loop->header = NULL;
#ifdef __linux__
    loop->epfd = epoll_create1(0);
    if(loop->epfd < 0)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
#endif
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
#if !(defined _WIN32 || defined __CYGWIN__)
            //need root
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(tcp->sck.fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
#endif
        }
        if(bind(tcp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(flags & AS_TCP_TPROXY)
        {
#if !(defined _WIN32 || defined __CYGWIN__)
            //need root
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(tcp->sck.fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
#endif
        }
        if(bind(tcp->sck.fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_tcp_listen(as_tcp_t *tcp, as_tcp_accepted_f cb)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    int rtn = listen(tcp->sck.fd, AS_MAX_LISTEN);
    if(rtn != 0)
        return rtn;
    tcp->sck.is_srv = 1;
    tcp->sck.status = AS_STATUS_INEPOLL | AS_STATUS_LISTENED;
    tcp->accept_cb = cb;
#ifdef __linux__
    tcp->sck.events = EPOLLIN;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
#else
    tcp->sck.events = AS_EVENTS_READ;
#endif
    return 0;
}

int as_tcp_connect(as_tcp_t *tcp, struct sockaddr *addr, as_tcp_connected_f cb)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
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
#ifdef __linux__
    tcp->sck.events = EPOLLOUT;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = tcp->sck.events;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
#else
    tcp->sck.events = AS_EVENTS_WRITE;
#endif
    return 0;
}

int as_tcp_read_start(as_tcp_t *tcp, as_tcp_read_f cb, int flags)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    if(tcp->sck.fd <= 0)
        return 1;
    tcp->read_cb = cb;
    tcp->sck.read_flags = flags;
#ifdef __linux__
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    tcp->sck.events |= EPOLLIN;
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
#else
    tcp->sck.events |= AS_EVENTS_READ;
#endif
    return 0;
}

int as_tcp_write(as_tcp_t *tcp, __const__ unsigned char *buf, __const__ size_t len, as_tcp_wrote_f cb)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
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
#ifdef __linux__
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
#else
    tcp->sck.events |= AS_EVENTS_WRITE;
#endif
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
#if !(defined _WIN32 || defined __CYGWIN__)
            //need root
            if(setsockopt(udp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(udp->sck.fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
#endif
        }
        if(bind(udp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(flags & AS_UDP_TPROXY)
        {
#if !(defined _WIN32 || defined __CYGWIN__)
            //need root
            if(setsockopt(udp->sck.fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
            {
                LOG_ERR(MSG_NEED_ROOT);
                return 1;
            }
            if(setsockopt(udp->sck.fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
#endif
        }
        if(bind(udp->sck.fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&udp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_udp_listen(as_udp_t *udp, as_udp_accepted_f cb)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    udp->sck.is_srv = 1;
    udp->sck.status = AS_STATUS_INEPOLL | AS_STATUS_LISTENED;
    udp->accept_cb = cb;
#ifdef __linux__
    udp->sck.events = EPOLLIN;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    ev.events = udp->sck.events;
    epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
#else
    udp->sck.events = AS_EVENTS_READ;
#endif
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
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
    if(udp->sck.fd <= 0)
        return 1;
    udp->read_cb = cb;
    if(udp->sck.type == SOCKET_TYPE_UDP_FAKE)
        return 0;
    udp->sck.read_flags = flags;
#ifdef __linux__
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    udp->sck.events |= EPOLLIN;
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
#else
    udp->sck.events |= AS_EVENTS_READ;
#endif
    return 0;
}

int as_udp_write(as_udp_t *udp, __const__ unsigned char *buf, __const__ size_t len, as_udp_wrote_f cb)
{
#ifdef __linux__
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
#endif
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
#ifdef __linux__
        ev.data.fd = udp_server->sck.fd;
        ev.data.ptr = udp_server;
        udp_server->sck.events |= EPOLLOUT;
        ev.events = udp_server->sck.events;
        epoll_ctl(udp_server->sck.loop->epfd, EPOLL_CTL_MOD, udp_server->sck.fd, &ev);
#else
        udp_server->sck.events |= AS_EVENTS_WRITE;
#endif
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
#ifdef __linux__
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
#else
    udp->sck.events |= AS_EVENTS_WRITE;
#endif
    return 0;
}

void as_socket_map_bind(as_socket_t *sck1, as_socket_t *sck2)
{
    sck1->map = sck2;
    sck2->map = sck1;
}

int as_close(as_socket_t *sck)
{
    __as_close(sck);
    if(sck->map != NULL)
    {
        __as_close(sck->map);
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
#ifdef __linux__
    struct epoll_event events[AS_EPOLL_NUM];
#else
    int max_fd;
    struct timeval timeout_s;
    memset(&timeout_s, 0, sizeof(struct timeval));
    timeout_s.tv_usec = IO_MUXING_TIMEOUT * 1000;
#endif
    int wait_count;
    while(1)
    {
        __socket_close_event(loop);
#ifdef __linux__
        wait_count = epoll_wait(loop->epfd, events, AS_EPOLL_NUM, IO_MUXING_TIMEOUT);
        for(int i = 0; i < wait_count; i++)
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
                __socket_handle_read(sck);
            if(events_flags & EPOLLOUT)
                __socket_handle_write(sck);
        }
#else
        max_fd = 0;
        FD_ZERO(&loop->read_set);
        FD_ZERO(&loop->write_set);
        FD_ZERO(&loop->except_set);
        for(as_socket_t *sck = loop->header; sck != NULL; sck = sck->next)
        {
            if(sck->type == SOCKET_TYPE_UDP_FAKE)
                continue;
            if(sck->status & AS_STATUS_CLOSED)
                continue;
            if(sck->fd > max_fd)
                max_fd = sck->fd;
            FD_SET(sck->fd, &loop->except_set);
            if(sck->events & AS_EVENTS_READ)
                FD_SET(sck->fd, &loop->read_set);
            if(sck->events & AS_EVENTS_WRITE)
                FD_SET(sck->fd, &loop->write_set);
        }
        wait_count = select(max_fd + 1, &loop->read_set, &loop->write_set, &loop->except_set, &timeout_s);
        if(wait_count > 0)
        {
            for(as_socket_t *sck = loop->header; sck != NULL; sck = sck->next)
            {
                if(sck->type == SOCKET_TYPE_UDP_FAKE)
                    continue;
                if(sck->status & AS_STATUS_CLOSED)
                    continue;
                int fd = sck->fd;
                if(FD_ISSET(fd, &loop->except_set))
                {
                    if(sck->type == SOCKET_TYPE_TCP && sck->is_srv == 0 && sck->events & AS_EVENTS_WRITE && !(sck->status & AS_STATUS_CONNECTED))
                    {
                        as_tcp_t *tcp = (as_tcp_t *) sck;
                        if(tcp->conned_cb != NULL)
                        {
                            if(tcp->conned_cb(tcp, 1) != 0)
                                as_close(sck);
                        }
                        sck->events &= ~AS_EVENTS_WRITE;
                    }
                    else
                    {
                        as_close(sck);
                    }
                    continue;
                }
                if(sck->status & AS_STATUS_CLOSED)
                    continue;
                if(FD_ISSET(fd, &loop->read_set))
                    __socket_handle_read(sck);
                if(FD_ISSET(fd, &loop->write_set))
                    __socket_handle_write(sck);
            }
        }
        else if(wait_count < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            else
            {
                LOG_ERR(MSG_BUG, errno);
            }
        }
#endif
    }
    return 0;
}
