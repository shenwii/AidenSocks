#ifndef _ASCORE_H
#define _ASCORE_H

#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <ws2def.h>
#define msghdr _WSAMSG
#else
#include <sys/socket.h>
#endif
#include <stdio.h>

#define AS_READ_ONESHOT 0x01

#define AS_SOCKET_TIMEOUT 10 //s
#define AS_MAX_LISTEN 128

#define AS_TCP_IPV6ONLY 0x01
#define AS_TCP_TPROXY 0x02

#define AS_UDP_IPV6ONLY 0x01
#define AS_UDP_TPROXY 0x02

#define AS_BUFFER_SIZE 409600

#define AS_SOCKET_TYPE_TCP 0x01
#define AS_SOCKET_TYPE_UDP 0x02

typedef struct as_loop_s as_loop_t;
typedef struct as_socket_s as_socket_t;
typedef struct as_tcp_s as_tcp_t;
typedef struct as_udp_s as_udp_t;

typedef int (*as_socket_destroying_f)(as_socket_t *);

typedef int (*as_tcp_accepted_f)(as_tcp_t *, as_tcp_t *, void **, as_socket_destroying_f *);
typedef int (*as_tcp_connected_f)(as_tcp_t *, char);
typedef int (*as_tcp_read_f)(as_tcp_t *, __const__ struct msghdr *, __const__ unsigned char *, __const__ size_t);
typedef int (*as_tcp_wrote_f)(as_tcp_t *, __const__ unsigned char *, __const__ size_t);

typedef int (*as_udp_accepted_f)(as_udp_t *, as_udp_t *, void **, as_socket_destroying_f *);
typedef int (*as_udp_read_f)(as_udp_t *, __const__ struct msghdr *, __const__ unsigned char *, __const__ size_t);
typedef int (*as_udp_wrote_f)(as_udp_t *, __const__ unsigned char *, __const__ size_t);

typedef int (*as_resolved_f)(as_socket_t *, __const__ char, __const__ struct sockaddr *);

as_loop_t *as_loop_init();

as_tcp_t *as_tcp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb);

int as_tcp_bind(as_tcp_t *tcp, struct sockaddr *addr, int flags);

int as_tcp_listen(as_tcp_t *tcp, as_tcp_accepted_f cb);

int as_tcp_connect(as_tcp_t *tcp, struct sockaddr *addr, as_tcp_connected_f cb);

int as_tcp_read_start(as_tcp_t *tcp, as_tcp_read_f cb, int flags);

int as_tcp_write(as_tcp_t *tcp, __const__ unsigned char *buf, __const__ size_t len, as_tcp_wrote_f cb);

as_udp_t *as_udp_init(as_loop_t *loop, void *data, as_socket_destroying_f cb);

int as_udp_bind(as_udp_t *udp, struct sockaddr *addr, int flags);

int as_udp_listen(as_udp_t *udp, as_udp_accepted_f cb);

int as_udp_connect(as_udp_t *udp, struct sockaddr *addr);

int as_udp_read_start(as_udp_t *udp, as_udp_read_f cb, int flags);

int as_udp_write(as_udp_t *udp, __const__ unsigned char *buf, __const__ size_t len, as_udp_wrote_f cb);

int as_resolver(as_socket_t *sck, __const__ char *host, int ipv6_first, as_resolved_f cb);

void as_socket_map_bind(as_socket_t *sck1, as_socket_t *sck2);

int as_close(as_socket_t *sck);

void *as_socket_data(as_socket_t *sck);

as_loop_t *as_socket_loop(as_socket_t *sck);

as_socket_t *as_socket_map(as_socket_t *sck);

int as_fd(as_socket_t *sck);

int as_socket_type(as_socket_t *sck);

int as_socket_error(as_socket_t *sck, char *serrno);

struct sockaddr_storage *as_dest_addr(as_socket_t *sck);

int as_loop_run(as_loop_t *loop);

#endif
