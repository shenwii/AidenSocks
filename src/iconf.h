#ifndef _ICONF_H
#define _ICONF_H

#define CONF_DEFAULT_PORT 1520
#define CONF_DEFAULT_BIND_IPV4 "localhost"
#define CONF_DEFAULT_BIND_IPV6 "localhost"
#define CONF_DEFAULT_DNS_SERVER "8.8.8.8"
#define CONF_DEFAULT_DNS_PORT 53
#define CONF_DEFAULT_IPV6_FIRST 1
#define CONF_DEFAULT_TCP_TPROXY 0
#define CONF_EMPTY_STRING ""

#include <stdint.h>
#include "iniparser/iniparser.h"

typedef struct
{
    char baddr[255];
    char baddr6[255];
    uint16_t bport;
    char server[255];
    uint16_t port;
    char tcp_proxy_server[255];
    uint16_t tcp_proxy_port;
    char key[45];
    char dns_server[255];
    uint16_t dns_port;
    int ipv6_first;
    int tcp_tproxy;
} conf_t;

int conf_parse(conf_t *conf, __const__ char *filepath, __const__ char *secname);

#endif
