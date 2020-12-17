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

struct sockaddr_storage server_addr;

conf_t conf;

static int __destroy(as_socket_t *sck);

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len);

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len);

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
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;
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

    if(strcmp(conf.tcp_proxy_server, CONF_EMPTY_STRING) != 0)
    {
        if(getfirsthostbyname(conf.tcp_proxy_server, (struct sockaddr*) &server_addr) != 0)
            return 1;
        if(server_addr.ss_family == AF_INET)
        {
            ((struct sockaddr_in *) &server_addr)->sin_port = htons(conf.tcp_proxy_port);
        }
        else
        {
            ((struct sockaddr_in6 *) &server_addr)->sin6_port = htons(conf.tcp_proxy_port);
        }
    }
    else
    {
        if(getfirsthostbyname(conf.server, (struct sockaddr*) &server_addr) != 0)
            return 1;
        if(server_addr.ss_family == AF_INET)
        {
            ((struct sockaddr_in *) &server_addr)->sin_port = htons(conf.port);
        }
        else
        {
            ((struct sockaddr_in6 *) &server_addr)->sin6_port = htons(conf.port);
        }
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
    if(as_tcp_connect(remote, (struct sockaddr*) &server_addr) != 0)
        return 1;
    char hl = strlen(conf.dns_server);
    char buf[hl + 4];
    uint16_t pp = htons(conf.dns_port);
    buf[0] = 0x03;
    buf[1] = hl;
    memcpy(buf + 2, conf.dns_server, hl);
    memcpy(buf + hl + 2, (char *) &pp, 2);
    char *sdata = malloc(ASP_MAX_DATA_LENGTH(hl + 4));
    int dlen;
    if(sdata == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x01, 0, (unsigned char *) buf, hl + 4, aes_key, (unsigned char *) sdata, &dlen);
    int slen = as_tcp_write(remote, sdata, dlen);
    free(sdata);
    if(slen <= 0)
        return 1;
    *data = malloc(sizeof(asp_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(asp_buffer_t));
    *cb = __destroy;
    if(as_tcp_read_start(remote, __tcp_remote_on_read) != 0)
        return 1;
    return 0;
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    return asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __tcp_remote_on_read_decrypt);
}

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len)
{
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    if(status != 0)
    {
        return 1;
    }
    if(type == 0x11)
    {
        if(as_tcp_read_start(clnt, __tcp_client_on_read) != 0)
            return 1;
    }
    else if(type == 0x02)
    {
        if(as_tcp_write(clnt, buf, len) <= 0)
            return 1;
        return 0;
    }
    else
    {
        return 1;
    }
    return 0;
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
    if(remote == NULL)
        return 1;
    char *data = malloc(ASP_MAX_DATA_LENGTH(len));
    int dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x02, 0, (unsigned char *) buf, len, aes_key, (unsigned char *) data, &dlen);
    int slen = as_tcp_write(remote, data, dlen);
    free(data);
    if(slen <= 0)
        return 1;
    return 0;
}

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    if(as_udp_connect(remote, (struct sockaddr *) &server_addr) != 0)
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
    return as_udp_read_start(clnt, __udp_client_on_read);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    as_udp_t *remote = (as_udp_t *) as_socket_map((as_socket_t *) clnt);
    if(remote == NULL)
        return 1;
    char hl = strlen(conf.dns_server);
    char sbuf[hl + 4 + len];
    uint16_t pp = htons(conf.dns_port);
    sbuf[0] = 0x03;
    sbuf[1] = hl;
    memcpy(sbuf + 2, conf.dns_server, hl);
    memcpy(sbuf + hl + 2, (char *) &pp, 2);
    memcpy(sbuf + hl + 4, buf, len);
    char *data = malloc(ASP_MAX_DATA_LENGTH(hl + 4 + len));
    int dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, (unsigned char *) sbuf, hl + 4 + len, aes_key, (unsigned char *) data, &dlen);
    as_udp_write(remote, data, dlen);
    free(data);
    if(as_udp_read_start(remote, __udp_remote_on_read) != 0)
        return 1;
    return 0;
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    as_udp_t *clnt = (as_udp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    return asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __udp_remote_on_read_decrypt);
}

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len)
{
    as_udp_t *remote = (as_udp_t *) parm;
    as_udp_t *clnt = (as_udp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    if(status != 0)
        return 1;
    if(type == 0x22)
    {
        as_udp_write(clnt, buf, len);
        return 0;
    }
    return 0;
}
