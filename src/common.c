#include "common.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

static struct addrinfo *__gethostbyname(__const__ char *hostname)
{
    struct addrinfo *result = NULL;
    if(getaddrinfo(hostname, NULL, NULL, &result) != 0)
        return NULL;
    return result;
}

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr)
{
    if(inet_pton(AF_INET6, hostname, &((struct sockaddr_in6 *) addr)->sin6_addr) == 1)
    {
        ((struct sockaddr_in6 *) addr)->sin6_family = AF_INET6;
        return 0;
    }
    if(inet_pton(AF_INET, hostname, &((struct sockaddr_in *) addr)->sin_addr) == 1)
    {
        ((struct sockaddr_in *) addr)->sin_family = AF_INET;
        return 0;
    }
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    if(result->ai_family == AF_INET)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
    }
    if(result->ai_family == AF_INET6)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in6));
    }
    freeaddrinfo(result);
    return 0;
}

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr)
{
    struct addrinfo *p = NULL;
    if(inet_pton(AF_INET, hostname, &addr->sin_addr) == 1)
    {
        addr->sin_family = AF_INET;
        return 0;
    }
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    for(p = result; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET)
        {
            memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(result);
            return 0;
        }
    }
    freeaddrinfo(result);
    return 1;
}

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr)
{
    struct addrinfo *p = NULL;
    if(inet_pton(AF_INET6, hostname, &addr->sin6_addr) == 1)
    {
        addr->sin6_family = AF_INET6;
        return 0;
    }
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    for(p = result; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET6)
        {
            memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in6));
            freeaddrinfo(result);
            return 0;
        }
    }
    freeaddrinfo(result);
    return 1;
}

char *address_str(struct sockaddr* addr)
{
    static char addstr[100];
    char s[80];
    if(addr->sa_family == AF_INET)
    {
        inet_ntop(addr->sa_family, &((struct sockaddr_in *) addr)->sin_addr, s, 80);
        sprintf(addstr, "%s:%d", s, ntohs(((struct sockaddr_in *) addr)->sin_port));
    }
    else
    {
        inet_ntop(addr->sa_family, &((struct sockaddr_in6 *) addr)->sin6_addr, s, 80);
        sprintf(addstr, "[%s]:%d", s, ntohs(((struct sockaddr_in6 *) addr)->sin6_port));
    }
    return addstr;
}
