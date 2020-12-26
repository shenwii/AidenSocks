#include "ascore.h"
#include "thrdpool.h"
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

#define SOCKET_LAZY_INIT -1

#define SOCKET_TYPE_TCP 1
#define SOCKET_TYPE_UDP 2
#define SOCKET_TYPE_UDP_FAKE 4

#define EPOLL_TIMEOUT 100

#define EPOLL_ENEVTS_SERVER EPOLLIN
#define EPOLL_ENEVTS_CLIENT EPOLLIN | EPOLLONESHOT

#define ACTIVE_CLOSE 0x0F
#define ACTIVE_NOTHING 0
#define ACTIVE_EVENT 1

struct as_loop_s
{
    as_socket_t *header;
    as_socket_t *last;
    tpool_t *tpool;
    pthread_mutex_t lock;
    int epfd;
};

struct as_socket_s
{
    as_loop_t *loop;
    struct as_socket_s *next;
    char type;
    void *data;
    struct as_socket_s *map;
    int fd;
    char active;
    char is_srv;
    char handling;
    struct sockaddr_storage addr;
    as_socket_destroying_f dest_cb;
};

struct as_tcp_s
{
    as_socket_t sck;
    as_tcp_accepted_f accept_cb;
    as_tcp_read_f read_cb;
};

struct as_udp_s
{
    as_socket_t sck;
    time_t udp_timeout;
    as_udp_accepted_f accept_cb;
    as_udp_read_f read_cb;
};

typedef struct
{
    as_tcp_t *server;
    as_tcp_t *client;
} __thrd_parm_tcp_conn_t;

typedef struct
{
    as_tcp_t *client;
    char *buf;
    int size;
} __thrd_parm_tcp_read_t;

typedef struct
{
    as_udp_t *server;
    as_udp_t *client;
    char *buf;
    int size;
    struct msghdr *msg;
} __thrd_parm_udp_t;

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

static void *__thread_tcp_connect_handle(void *args)
{
    __thrd_parm_tcp_conn_t *parm = (__thrd_parm_tcp_conn_t *) args;
    if(parm->server->accept_cb == NULL) {
        as_close((as_socket_t *) parm->client);
        parm->client->sck.handling = 0;
        free(parm);
        return NULL;
    }
    if(parm->server->accept_cb(parm->server, parm->client, &parm->client->sck.data, &parm->client->sck.dest_cb) != 0)
        as_close((as_socket_t *) parm->client);
    parm->client->sck.handling = 0;
    free(parm);
    return NULL;
}

static void *__thread_tcp_read_handle(void *args)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    __thrd_parm_tcp_read_t *parm = (__thrd_parm_tcp_read_t *) args;
    if(parm->client->read_cb == NULL)
    {
        as_close((as_socket_t *) parm->client);
        parm->client->sck.handling = 0;
        free(parm->buf);
        free(parm);
        return NULL;
    }
    if(parm->client->read_cb(parm->client, parm->buf, parm->size) != 0)
    {
        as_close((as_socket_t *) parm->client);
    }
    else
    {
        ev.data.fd = parm->client->sck.fd;
        ev.data.ptr = parm->client;
        ev.events = EPOLL_ENEVTS_CLIENT;
        epoll_ctl(parm->client->sck.loop->epfd, EPOLL_CTL_MOD, parm->client->sck.fd, &ev);
    }
    parm->client->sck.handling = 0;
    free(parm->buf);
    free(parm);
    return NULL;
}

static void *__thread_udp_read_handle(void *args)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    __thrd_parm_udp_t *parm = (__thrd_parm_udp_t *) args;
    if(parm->client->read_cb == NULL)
    {
        as_close((as_socket_t *) parm->client);
    }
    else
    {
        if(parm->client->read_cb(parm->client, parm->msg, parm->buf, parm->size) != 0)
        {
            as_close((as_socket_t *) parm->client);
        }
        else
        {
            if(parm->client->sck.type != SOCKET_TYPE_UDP_FAKE)
            {
                ev.data.fd = parm->client->sck.fd;
                ev.data.ptr = parm->client;
                ev.events = EPOLL_ENEVTS_CLIENT;
                epoll_ctl(parm->client->sck.loop->epfd, EPOLL_CTL_MOD, parm->client->sck.fd, &ev);
            }
        }
    }
    parm->client->sck.handling = 0;
    free(parm->msg->msg_iov);
    free(parm->msg->msg_control);
    free(parm->msg);
    free(parm->buf);
    free(parm);
    return NULL;
}

static void *__thread_udp_connect_handle(void *args)
{
    __thrd_parm_udp_t *parm = (__thrd_parm_udp_t *) args;
    if(parm->server->accept_cb == NULL) {
        as_close((as_socket_t *) parm->client);
        parm->client->sck.handling = 0;
        free(parm);
        return NULL;
    }
    if(parm->server->accept_cb(parm->server, parm->client, &parm->client->sck.data, &parm->client->sck.dest_cb) != 0)
    {
        as_close((as_socket_t *) parm->client);
        parm->client->sck.handling = 0;
        free(parm);
        return NULL;
    }
    return __thread_udp_read_handle(parm);
}

static void __socket_handle(as_socket_t *sck)
{
    int fd;
    char *buf;
    int read;
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(struct sockaddr_storage);
    if(sck->type == SOCKET_TYPE_TCP)
    {
        if(sck->is_srv == 1)
        {
            fd = accept(sck->fd, (struct sockaddr *) &addr, &addrl);
            if(fd > 0)
            {
                LOG_DEBUG("fd = %d is inited\n", fd);
                as_tcp_t *client = as_tcp_init(sck->loop, NULL, NULL);
                client->sck.fd = fd;
                memcpy(&client->sck.addr, &addr, addrl);
                client->sck.handling = 1;
                __thrd_parm_tcp_conn_t *parm = (__thrd_parm_tcp_conn_t *) malloc(sizeof(__thrd_parm_tcp_conn_t));
                if(parm == NULL)
                {
                    LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                    abort();
                }
                parm->server = (as_tcp_t *) sck;
                parm->client = client;
                if(tpool_add_task(sck->loop->tpool, __thread_tcp_connect_handle, (void *) parm) != 0)
                    abort();
            }
        }
        else
        {
            buf = (char *) malloc(AS_BUFFER_SIZE);
            if(buf == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            read = recv(sck->fd, buf, AS_BUFFER_SIZE, MSG_NOSIGNAL);
            if(read <= 0)
            {
                free(buf);
                as_close(sck);
            }
            else
            {
                __thrd_parm_tcp_read_t *parm = (__thrd_parm_tcp_read_t *) malloc(sizeof(__thrd_parm_tcp_read_t));
                if(parm == NULL)
                {
                    LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                    abort();
                }
                parm->client = (as_tcp_t *) sck;
                parm->buf = buf;
                parm->size = read;
                sck->handling = 1;
                if(tpool_add_task(sck->loop->tpool, __thread_tcp_read_handle, (void *) parm) != 0)
                    abort();
            }
        }
    }
    if(sck->type == SOCKET_TYPE_UDP)
    {
        buf = (char *) malloc(AS_BUFFER_SIZE);
        if(buf == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        struct msghdr *msg = (struct msghdr *) malloc(sizeof(struct msghdr));
        if(msg == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        char *cntrlbuf = (char *) malloc(64);
        if(cntrlbuf == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        struct iovec *iov = (struct iovec *) malloc(sizeof(struct iovec));
        if(iov == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        memset(cntrlbuf, '\0', 64);
        msg->msg_control = cntrlbuf;
        msg->msg_controllen = 64;
        msg->msg_name = &addr;
        msg->msg_namelen = addrl;
        iov[0].iov_base = buf;
        iov[0].iov_len = AS_BUFFER_SIZE;
        msg->msg_iov = iov;
        msg->msg_iovlen = 1;
        read = recvmsg(sck->fd, msg, 0);
        if(read <= 0)
        {
            free(iov);
            free(cntrlbuf);
            free(msg);
            free(buf);
        }
        else
        {
            if(sck->is_srv == 1)
            {
                as_udp_t *client = as_udp_init(sck->loop, NULL, NULL);
                client->sck.type = SOCKET_TYPE_UDP_FAKE;
                client->sck.fd = sck->fd;
                client->read_cb = NULL;
                client->udp_timeout = time(NULL);
                memcpy(&client->sck.addr, &addr, addrl);

                __thrd_parm_udp_t *parm = (__thrd_parm_udp_t *) malloc(sizeof(__thrd_parm_udp_t));
                if(parm == NULL)
                {
                    LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                    abort();
                }
                parm->server = (as_udp_t *) sck;
                parm->msg = msg;
                parm->buf = buf;
                parm->client = client;
                parm->size = read;
                client->sck.handling = 1;
                if(tpool_add_task(sck->loop->tpool, __thread_udp_connect_handle, (void *) parm) != 0)
                {
                    LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                    abort();
                }
            }
            else
            {
                __thrd_parm_udp_t *parm = (__thrd_parm_udp_t *) malloc(sizeof(__thrd_parm_udp_t));
                if(parm == NULL)
                {
                    LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                    abort();
                }
                parm->server = NULL;
                parm->msg = msg;
                parm->buf = buf;
                parm->client = (as_udp_t *) sck;
                parm->size = read;
                sck->handling = 1;
                if(tpool_add_task(sck->loop->tpool, __thread_udp_read_handle, (void *) parm) != 0)
                    abort();
            }
        }
    }
}

static void __socket_close_event(as_loop_t *loop)
{
    as_socket_t *s, *p;
    pthread_mutex_lock(&loop->lock);
    s = loop->header;
    p = NULL;
    while(s != NULL)
    {
        if((s->active == ACTIVE_CLOSE) && s->handling == 0)
        {
            if(s->map != NULL && s->map->handling != 0)
            {
                p = s;
                s = s->next;
                continue;
            }
            if(p == NULL)
                loop->header = s->next;
            else
                p->next = s->next;
            if(s->next == NULL)
                loop->last = p;
            as_socket_t *c = s;
            s = s->next;
            if(c->dest_cb != NULL)
            {
                c->dest_cb(c);
            }
            if(c->type != SOCKET_TYPE_UDP_FAKE)
            {
                if(c->fd > 0)
                {
                    shutdown(c->fd, SHUT_RDWR);
                    close(c->fd);
                    LOG_DEBUG("%d is closed\n", c->fd);
                }
            }
            if(c->map != NULL)
                c->map->map = NULL;
            free(c);
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
    pthread_mutex_unlock(&loop->lock);
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
    if(pthread_mutex_init(&loop->lock, NULL) != 0)
    {
        free(loop);
        return NULL;
    }
    loop->tpool = tpool_create(AS_THREAD_NUM);
    if(loop->tpool == NULL)
    {
        free(loop);
        return NULL;
    }
    loop->epfd = epoll_create1(0);
    if(loop->epfd < 0)
    {
        tpool_destroy(loop->tpool);
        free(loop);
        return NULL;
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
    pthread_mutex_lock(&loop->lock);
    if(loop->header == NULL)
        loop->header = (as_socket_t *) tcp;
    else
        loop->last->next = (as_socket_t *) tcp;
    loop->last = (as_socket_t *) tcp;
    tcp->sck.next = NULL;
    tcp->accept_cb = NULL;
    tcp->read_cb = NULL;
    tcp->sck.dest_cb = cb;
    tcp->sck.loop = loop;
    tcp->sck.data = data;
    tcp->sck.map = NULL;
    tcp->sck.type = SOCKET_TYPE_TCP;
    tcp->sck.is_srv = 0;
    tcp->sck.active = ACTIVE_NOTHING;
    //we don't know ipv4 or ipv6
    //so not create socket in there
    tcp->sck.fd = SOCKET_LAZY_INIT;
    tcp->sck.handling = 0;
    pthread_mutex_unlock(&loop->lock);
    return tcp;
}

int as_tcp_bind(as_tcp_t *tcp, struct sockaddr *addr, int flags)
{
    int on = 1;
    tcp->sck.fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->sck.fd <= 0)
        return 1;
    LOG_DEBUG("fd = %d is inited\n", tcp->sck.fd);
    __set_timeout(tcp->sck.fd);
    __set_reuseaddr(tcp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        if(flags == AS_TCP_IPV6ONLY)
        {
            if(setsockopt(tcp->sck.fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(tcp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
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
    tcp->sck.active = ACTIVE_EVENT;
    tcp->accept_cb = cb;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = EPOLL_ENEVTS_SERVER;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    return 0;
}

int as_tcp_connect(as_tcp_t *tcp, struct sockaddr *addr)
{
    tcp->sck.fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    LOG_DEBUG("fd = %d is inited\n", tcp->sck.fd);
    if(tcp->sck.fd <= 0)
        return 1;
    __set_timeout(tcp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        if(connect(tcp->sck.fd, addr, sizeof(struct sockaddr_in6)) != 0)
        {
            close(tcp->sck.fd);
            return 1;
        }
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(connect(tcp->sck.fd, addr, sizeof(struct sockaddr_in)) != 0)
        {
            close(tcp->sck.fd);
            return 1;
        }
        memcpy(&tcp->sck.addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int as_tcp_read_start(as_tcp_t *tcp, as_tcp_read_f cb)
{
    struct epoll_event ev;
    if(tcp->sck.active == ACTIVE_CLOSE)
        return 2;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(tcp->sck.fd <= 0)
        return 1;
    tcp->read_cb = cb;
    tcp->sck.active = ACTIVE_EVENT;
    ev.data.fd = tcp->sck.fd;
    ev.data.ptr = tcp;
    ev.events = EPOLL_ENEVTS_CLIENT;
    epoll_ctl(tcp->sck.loop->epfd, EPOLL_CTL_ADD, tcp->sck.fd, &ev);
    return 0;
}

int as_tcp_write(as_tcp_t *tcp, __const__ char *buf, __const__ int len)
{
    if(tcp->sck.fd <= 0)
        return -1;
    if(tcp->sck.active == ACTIVE_CLOSE)
        return -1;
    if(len == 0)
        return 0;
    return send(tcp->sck.fd, buf, len, MSG_NOSIGNAL);
}

as_udp_t *as_udp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb)
{
    as_udp_t *udp = (as_udp_t *) malloc(sizeof(as_udp_t));
    if(udp == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    pthread_mutex_lock(&loop->lock);
    if(loop->header == NULL)
        loop->header = (as_socket_t *) udp;
    else
        loop->last->next = (as_socket_t *) udp;
    loop->last = (as_socket_t *) udp;
    udp->sck.next = NULL;
    udp->udp_timeout = time(NULL);
    udp->sck.dest_cb = cb;
    udp->sck.loop = loop;
    udp->sck.data = data;
    udp->sck.map = NULL;
    udp->sck.type = SOCKET_TYPE_UDP;
    udp->sck.is_srv = 0;
    udp->sck.active = ACTIVE_NOTHING;
    //we don't know ipv4 or ipv6
    //so not create socket in there
    udp->sck.fd = SOCKET_LAZY_INIT;
    udp->sck.handling = 0;
    pthread_mutex_unlock(&loop->lock);
    return udp;
}

int as_udp_bind(as_udp_t *udp, struct sockaddr *addr, int flags)
{
    int on = 1;
    if(udp->sck.fd != SOCKET_LAZY_INIT)
        return 1;
    udp->sck.fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    LOG_DEBUG("fd = %d is inited\n", udp->sck.fd);
    if(udp->sck.fd <= 0)
        return 1;
    __set_timeout(udp->sck.fd);
    __set_reuseaddr(udp->sck.fd);
    if(addr->sa_family == AF_INET6)
    {
        if((flags & 1) == 1)
        {
            if(setsockopt(udp->sck.fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(((flags >> 1) & 1) == 1)
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
        if(((flags >> 1) & 1) == 1)
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
    udp->accept_cb = cb;
    udp->sck.active = ACTIVE_EVENT;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    ev.events = EPOLL_ENEVTS_SERVER;
    epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
    return 0;
}

int as_udp_connect(as_udp_t *udp, struct sockaddr *addr)
{
    if(udp->sck.fd != SOCKET_LAZY_INIT)
        return 1;
    udp->sck.fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    LOG_DEBUG("fd = %d is inited\n", udp->sck.fd);
    if(udp->sck.fd <= 0)
        return 1;
    __set_timeout(udp->sck.fd);
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

int as_udp_read_start(as_udp_t *udp, as_udp_read_f cb)
{
    struct epoll_event ev;
    if(udp->sck.active == ACTIVE_CLOSE)
        return 2;
    memset(&ev, 0, sizeof(struct epoll_event));
    if(udp->sck.fd <= 0)
        return 1;
    udp->read_cb = cb;
    if(udp->sck.type == SOCKET_TYPE_UDP_FAKE)
        return 0;
    udp->sck.active = ACTIVE_EVENT;
    ev.data.fd = udp->sck.fd;
    ev.data.ptr = udp;
    ev.events = EPOLL_ENEVTS_CLIENT;
    epoll_ctl(udp->sck.loop->epfd, EPOLL_CTL_ADD, udp->sck.fd, &ev);
    return 0;
}

int as_udp_write(as_udp_t *udp, __const__ char *buf, __const__ int len)
{
    if(udp->sck.type == SOCKET_TYPE_UDP_FAKE)
        udp->udp_timeout = time(NULL);
    if(len == 0)
        return 0;
    return sendto(udp->sck.fd, buf, len, 0, (struct sockaddr *) &udp->sck.addr, sizeof(struct sockaddr_storage));
}

void as_socket_map_bind(as_socket_t *sck1, as_socket_t *sck2)
{
    sck1->map = sck2;
    sck2->map = sck1;
}

int as_thread_task(as_socket_t *sck, void *(*fun)(void *), void *arg)
{
    return tpool_add_task(sck->loop->tpool, fun, arg);
}

int as_close(as_socket_t *sck)
{
    if(sck->active == ACTIVE_EVENT && sck->fd > 0)
        epoll_ctl(sck->loop->epfd, EPOLL_CTL_DEL, sck->fd, NULL);
    sck->active = ACTIVE_CLOSE;
    if(sck->map != NULL)
    {
        as_socket_t *sckmap = sck->map;
        if(sckmap->active == ACTIVE_EVENT && sckmap->fd > 0)
            epoll_ctl(sckmap->loop->epfd, EPOLL_CTL_DEL, sckmap->fd, NULL);
        sckmap->active = ACTIVE_CLOSE;
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
            if(events_flags & EPOLLERR || events_flags & EPOLLHUP || (!(events_flags & EPOLLIN))) {
                as_close((as_socket_t *) events[i].data.ptr);
                continue;
            }
            __socket_handle((as_socket_t *) events[i].data.ptr);
        }
    }
    return 0;
}
