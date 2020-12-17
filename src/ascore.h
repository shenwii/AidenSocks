#ifndef _ASCORE_H
#define _ASCORE_H

#include <sys/socket.h>
#include <stdint.h>

#define AS_THREAD_NUM 50
#define AS_EPOLL_NUM 50

#define AS_SOCKET_TIMEOUT 10 //s
#define AS_MAX_LISTEN 128

#define AS_TCP_IPV6ONLY 0x01

#define AS_UDP_IPV6ONLY 0x01
#define AS_UDP_TPROXY 0x02

#define AS_BUFFER_SIZE 409600

typedef struct as_loop_s as_loop_t;
typedef struct as_socket_s as_socket_t;
typedef struct as_tcp_s as_tcp_t;
typedef struct as_udp_s as_udp_t;

typedef int (*as_socket_destroying_f)(as_socket_t *);

typedef int (*as_tcp_accepted_f)(as_tcp_t *, as_tcp_t *, void **, as_socket_destroying_f *);
typedef int (*as_tcp_read_f)(as_tcp_t *, __const__ char *, __const__ int);

typedef int (*as_udp_accepted_f)(as_udp_t *, as_udp_t *, void **, as_socket_destroying_f *);
typedef int (*as_udp_read_f)(as_udp_t *, __const__ struct msghdr *, __const__ char *, __const__ int);

as_loop_t *as_loop_init();

as_tcp_t *as_tcp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb);

int as_tcp_bind(as_tcp_t *tcp, struct sockaddr *addr, int flags);

int as_tcp_listen(as_tcp_t *tcp, as_tcp_accepted_f cb);

int as_tcp_connect(as_tcp_t *tcp, struct sockaddr *addr);

int as_tcp_read_start(as_tcp_t *tcp, as_tcp_read_f cb);

int as_tcp_write(as_tcp_t *tcp, __const__ char *buf, __const__ int len);

as_udp_t *as_udp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb);

int as_udp_bind(as_udp_t *udp, struct sockaddr *addr, int flags);

int as_udp_listen(as_udp_t *udp, as_udp_accepted_f cb);

int as_udp_connect(as_udp_t *udp, struct sockaddr *addr);

int as_udp_read_start(as_udp_t *udp, as_udp_read_f cb);

int as_udp_write(as_udp_t *udp, __const__ char *buf, __const__ int len);

void as_socket_map_bind(as_socket_t *sck1, as_socket_t *sck2);

int as_thread_task(as_socket_t *sck, void *(*fun)(void *), void *arg);

int as_close(as_socket_t *sck);

void *as_socket_data(as_socket_t *sck);

as_loop_t *as_socket_loop(as_socket_t *sck);

as_socket_t *as_socket_map(as_socket_t *sck);

int as_fd(as_socket_t *sck);

struct sockaddr_storage *as_dest_addr(as_socket_t *sck);

int as_loop_run(as_loop_t *loop);

#endif
