#ifndef _COMMON_H
#define _COMMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr);

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr);

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr);

char *address_str(struct sockaddr *addr);

int parse_asp_address(__const__ unsigned char *buf, __const__ int len, struct sockaddr* addr);

#endif
