#ifndef _COMMON_H
#define _COMMON_H

#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <sys/types.h>

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr);

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr);

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr);

char *address_str(struct sockaddr *addr);

#endif
