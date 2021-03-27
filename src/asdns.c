#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "ascore.h"
#include "log.h"
#include "asprot.h"

unsigned char aes_key[AES_KEY_LEN / 8];

conf_t conf;

struct sockaddr_storage tcp_server_addr = {0};

struct sockaddr_storage udp_server_addr = {0};

struct sockaddr_storage dns_server_addr = {0};

static int __destroy(as_socket_t *sck);

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_remote_on_connected(as_tcp_t *remote, char status);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_worte(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_wrote(as_udp_t *clnt, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __usage(char *prog)
{
    printf("Usage: %s INI_FILE\n", prog);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv)
{
    as_loop_t *loop;
    as_tcp_t *tcp;
    as_udp_t *udp;
    struct sockaddr_in6 addr6 = {0};
    struct sockaddr_in addr = {0};
    if(argc < 2)
        return __usage(argv[0]);
    if(conf_parse(&conf, argv[1], "DNS") != 0)
    {
        LOG_ERR(MSG_PARSE_INI_FILE);
        return 1;
    }
    int b64kl = strlen(conf.key);
    if(B64_DECODE_LEN(conf.key, b64kl) != AES_KEY_LEN / 8)
    {
        LOG_ERR(MSG_KEY_LENGTH, conf.key);
        return 1;
    }
    if(b64_decode((unsigned char *) conf.key, b64kl, aes_key) <= 0)
    {
        LOG_ERR(MSG_BASE64_DECODE, conf.key);
        return 1;
    }
    loop = as_loop_init();
    if(getfirsthostbyname(conf.dns_server, (struct sockaddr *) &dns_server_addr) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.dns_server);
        return 1;
    }
    if(dns_server_addr.ss_family == AF_INET)
    {
        ((struct sockaddr_in *) &dns_server_addr)->sin_port = htons(conf.dns_port);
    }
    else
    {
        ((struct sockaddr_in6 *) &dns_server_addr)->sin6_port = htons(conf.dns_port);
    }
    if(getipv6hostbyname(conf.baddr6, &addr6) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.baddr6);
        return 1;
    }
    addr6.sin6_port = htons(conf.bport);
    if(getipv4hostbyname(conf.baddr, &addr) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.baddr);
        return 1;
    }
    addr.sin_port = htons(conf.bport);

    if(getfirsthostbyname(conf.server, (struct sockaddr*) &udp_server_addr) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.server);
        return 1;
    }
    if(udp_server_addr.ss_family == AF_INET)
    {
        ((struct sockaddr_in *) &udp_server_addr)->sin_port = htons(conf.port);
    }
    else
    {
        ((struct sockaddr_in6 *) &udp_server_addr)->sin6_port = htons(conf.port);
    }
    if(strcmp(conf.tcp_proxy_server, CONF_EMPTY_STRING) != 0)
    {
        if(getfirsthostbyname(conf.tcp_proxy_server, (struct sockaddr*) &tcp_server_addr) != 0)
        {
            LOG_ERR(MSG_RESOLV_HOST, conf.tcp_proxy_server);
            return 1;
        }
        if(tcp_server_addr.ss_family == AF_INET)
        {
            ((struct sockaddr_in *) &tcp_server_addr)->sin_port = htons(conf.tcp_proxy_port);
        }
        else
        {
            ((struct sockaddr_in6 *) &tcp_server_addr)->sin6_port = htons(conf.tcp_proxy_port);
        }
    }
    else
    {
        memcpy(&tcp_server_addr, &udp_server_addr, sizeof(struct sockaddr_storage));
    }

    //bind ipv6 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr6, AS_UDP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_UDP_BIND, conf.baddr6, conf.bport);
        return 1;
    }
    if(as_udp_listen(udp, __udp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_UDP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_UDP_LISTEN_ON, conf.baddr6, conf.bport);

    //bind ipv4 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr, 0) != 0)
    {
        LOG_ERR(MSG_UDP_BIND, conf.baddr, conf.bport);
        return 1;
    }
    if(as_udp_listen(udp, __udp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_UDP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_UDP_LISTEN_ON, conf.baddr, conf.bport);

    //bind ipv6 tcp address
    tcp = as_tcp_init(loop, NULL, NULL);
    if(as_tcp_bind(tcp, (struct sockaddr *) &addr6, AS_TCP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_TCP_BIND, conf.baddr6, conf.bport);
        return 1;
    }
    if(as_tcp_listen(tcp, __tcp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_TCP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr6, conf.bport);

    //bind ipv4 tcp address
    tcp = as_tcp_init(loop, NULL, NULL);
    if(as_tcp_bind(tcp, (struct sockaddr *) &addr, 0) != 0)
    {
        LOG_ERR(MSG_TCP_BIND, conf.baddr, conf.bport);
        return 1;
    }
    if(as_tcp_listen(tcp, __tcp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_TCP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr, conf.bport);
    as_loop_run(loop);
    return 0;
}

static int __destroy(as_socket_t *sck)
{
    asp_buffer_t *buf = (asp_buffer_t *) as_socket_data(sck);
    if(buf->len != 0)
        free(buf->buf);
    free(buf);
    return 0;
}

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    *data = malloc(sizeof(asp_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(asp_buffer_t));
    *cb = __destroy;
    if(as_tcp_connect(remote, (struct sockaddr*) &tcp_server_addr, __tcp_remote_on_connected) != 0)
        return 1;
    return 0;
}

static int __tcp_remote_on_connected(as_tcp_t *remote, char status)
{
    if(status != 0)
        return 1;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    unsigned char buf[19];
    size_t len;
    if(dns_server_addr.ss_family == AF_INET)
    {
        LOG_INFO("%s tcp connect to %s:%d\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), conf.dns_server, conf.dns_port);
        struct sockaddr_in *addr = (struct sockaddr_in *) &dns_server_addr;
        buf[0] = 0x01;
        memcpy(buf + 1, &addr->sin_addr, 4);
        memcpy(buf + 5, &addr->sin_port, 2);
        len = 7;
    }
    else
    {
        LOG_INFO("%s tcp connect to [%s]:%d\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), conf.dns_server, conf.dns_port);
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &dns_server_addr;
        buf[0] = 0x04;
        memcpy(buf + 1, &addr6->sin6_addr, 16);
        memcpy(buf + 17, &addr6->sin6_port, 2);
        len = 19;
    }
    unsigned char *sdata = malloc(ASP_MAX_DATA_LENGTH(len));
    size_t dlen;
    if(sdata == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x01, 0, buf, len, aes_key, sdata, &dlen);
    as_tcp_write(remote, sdata, dlen, NULL);
    free(sdata);
    return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    int rtn = asp_decrypt(remote, buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __tcp_remote_on_read_decrypt);
    if(rtn == -1)
        return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(status != 0)
    {
        return 1;
    }
    if(type == 0x11)
    {
        return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT) | as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
    }
    else if(type == 0x02)
    {
        as_tcp_write(clnt, buf, len, __tcp_client_on_wrote);
        return 0;
    }
    else
    {
        return 1;
    }
    return 0;
}

static int __tcp_remote_on_worte(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(len));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x02, 0, buf, len, aes_key, data, &dlen);
    as_tcp_write(remote, data, dlen, __tcp_remote_on_worte);
    free(data);
    return 0;
}

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
    return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
}

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    if(as_udp_connect(remote, (struct sockaddr *) &udp_server_addr) != 0)
        return 1;
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    *data = malloc(sizeof(asp_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(asp_buffer_t));
    *cb = __destroy;
    return as_udp_read_start(clnt, __udp_client_on_read, 0);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_udp_t *remote = (as_udp_t *) as_socket_map((as_socket_t *) clnt);
    unsigned char tbuf[19 + len];
    size_t tlen;
    if(dns_server_addr.ss_family == AF_INET)
    {
        LOG_INFO("%s udp send to %s:%d\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), conf.dns_server, conf.dns_port);
        struct sockaddr_in *addr = (struct sockaddr_in *) &dns_server_addr;
        tbuf[0] = 0x01;
        memcpy(tbuf + 1, &addr->sin_addr, 4);
        memcpy(tbuf + 5, &addr->sin_port, 2);
        tlen = 7;
    }
    else
    {
        LOG_INFO("%s udp send to [%s]:%d\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), conf.dns_server, conf.dns_port);
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &dns_server_addr;
        tbuf[0] = 0x04;
        memcpy(tbuf + 1, &addr6->sin6_addr, 16);
        memcpy(tbuf + 17, &addr6->sin6_port, 2);
        tlen = 19;
    }
    memcpy(&tbuf[tlen], buf, len);
    tlen += len;
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(tlen));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, (unsigned char *) tbuf, tlen, aes_key, (unsigned char *) data, &dlen);
    as_udp_write(remote, data, dlen, NULL);
    free(data);
    return as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT);
}

static int __udp_client_on_wrote(as_udp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    return as_udp_read_start((as_udp_t *) as_socket_map((as_socket_t *) clnt), __udp_remote_on_read, AS_READ_ONESHOT);
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_udp_t *clnt = (as_udp_t *) as_socket_map((as_socket_t *) remote);
    int rtn = asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __udp_remote_on_read_decrypt);
    if(rtn == -1)
        return as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    as_udp_t *remote = (as_udp_t *) parm;
    as_udp_t *clnt = (as_udp_t *) as_socket_map((as_socket_t *) remote);
    if(status != 0)
        return 1;
    if(type == 0x22)
    {
        as_udp_write(clnt, buf, len, __udp_client_on_wrote);
        return 0;
    }
    return 0;
}
