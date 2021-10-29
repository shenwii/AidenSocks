#include "iconf.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>

static char *__ckey(__const__ char *secname, __const__ char *prop)
{
    static char key[1024];
    char *tmp = key;
    while(*secname)
        *tmp++ = *secname++;
    *tmp++ = ':';
    while(*prop)
        *tmp++ = *prop++;
    *tmp = '\0';
    return key;
}

int conf_parse(conf_t *conf, __const__ char *filepath, __const__ char *secname)
{
    dictionary *ini;
    ini = iniparser_load(filepath);
    if(ini == NULL)
    {
        LOG_ERR("can not open file %s\n", filepath);
        return 1;
    }
    strcpy(conf->baddr, iniparser_getstring(ini, __ckey(secname, "bind_addr"), CONF_DEFAULT_BIND_IPV4));
    strcpy(conf->baddr6, iniparser_getstring(ini, __ckey(secname, "bind_addr6"), CONF_DEFAULT_BIND_IPV6));
    conf->bport = (uint16_t) iniparser_getint(ini, __ckey(secname, "bind_port"), CONF_DEFAULT_PORT);
    strcpy(conf->server, iniparser_getstring(ini, __ckey(secname, "server"), CONF_DEFAULT_BIND_IPV4));
    conf->port = (uint16_t) iniparser_getint(ini, __ckey(secname, "port"), CONF_DEFAULT_PORT);
    strcpy(conf->tcp_proxy_server, iniparser_getstring(ini, __ckey(secname, "tcp_proxy_server"), CONF_EMPTY_STRING));
    conf->tcp_proxy_port = (uint16_t) iniparser_getint(ini, __ckey(secname, "tcp_proxy_port"), CONF_DEFAULT_PORT);
    strcpy(conf->key, iniparser_getstring(ini, __ckey(secname, "key"), ""));
    strcpy(conf->dns_server, iniparser_getstring(ini, __ckey(secname, "dns_server"), CONF_DEFAULT_DNS_SERVER));
    conf->dns_port = (uint16_t) iniparser_getint(ini, __ckey(secname, "dns_port"), CONF_DEFAULT_DNS_PORT);
    conf->ipv6_first = (uint16_t) iniparser_getint(ini, __ckey(secname, "ipv6_first"), CONF_DEFAULT_IPV6_FIRST);
    iniparser_freedict(ini);
    return 0;
}
