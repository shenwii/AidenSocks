#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"

static struct addrinfo *__gethostbyname(__const__ char *hostname)
{
    struct addrinfo *result = NULL;
    if(getaddrinfo(hostname, NULL, NULL, &result) != 0)
        return NULL;
    return result;
}

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr)
{
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

int parse_asp_address(__const__ unsigned char *buf, __const__ int len, struct sockaddr* addr)
{
    uint16_t *port;
    char dlen;
    char atyp;
    if(len == 0)
        return -1;
    atyp = buf[0];
    switch(atyp)
    {
        case 0x01:
            //ipv4
            if(len < 7)
                return -1;
            port = (uint16_t *) &buf[5];
            ((struct sockaddr_in *) addr)->sin_family = AF_INET;
            ((struct sockaddr_in *) addr)->sin_port = *port;
            memcpy(&((struct sockaddr_in *) addr)->sin_addr, (char *) &buf[1], 4);
            return 7;
        case 0x03:
            //domian
            if(len < 2)
                return -1;
            dlen = buf[1];
            if(len < dlen + 4)
                return -1;
            port = (uint16_t *) &buf[2 + dlen];
            {
                char addrstr[dlen + 1];
                memcpy(addrstr, (char *) &buf[2], dlen);
                addrstr[(int) dlen] = '\0';
                if(getfirsthostbyname(addrstr, addr) != 0)
                    return -1;
                if(addr->sa_family == AF_INET)
                    ((struct sockaddr_in *) addr)->sin_port = *port;
                else
                    ((struct sockaddr_in6 *) addr)->sin6_port = *port;
            }
            return dlen + 4;
        case 0x04:
            //ipv6
            if(len < 19)
                return -1;
            port = (uint16_t *) &buf[17];
            ((struct sockaddr_in6 *) addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *) addr)->sin6_port = *port;
            memcpy(&((struct sockaddr_in6 *) addr)->sin6_addr, (char *) &buf[1], 16);
            return 19;
        default:
            return -1;
    }
}
