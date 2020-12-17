#include <stdlib.h>
#include <stdint.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "ascore.h"
#include "log.h"
#include "asprot.h"

#define SOCKS5_VERSION 0x05

unsigned char aes_key[AES_KEY_LEN / 8];

typedef struct
{
    char ver;
    char cmd;
    char rsv;
    char atyp;
} __attribute__ ((__packed__)) s5_conn_header_t;

typedef struct
{
    char rsv[2];
    char frag;
    char atyp;
} __attribute__ ((__packed__)) s5_udp_forward_t;

typedef struct
{
    asp_buffer_t asp_buffer;
    char s5_status;
} __s5_buffer_t;

struct sockaddr_storage server_addr;

static int __destroy(as_socket_t *sck);

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __s5_auth(as_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_connect(as_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_tcp_forward(as_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_udp_forward(as_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len);

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len);

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
    conf_t conf;
    as_loop_t *loop;
    as_tcp_t *tcp;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;
    if(argc < 2)
        return __usage(argv[0]);
    if(conf_parse(&conf, argv[1], "Socks5") != 0)
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
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data(sck);
    if(s5_buf->asp_buffer.len != 0)
        free(s5_buf->asp_buffer.buf);
    free(s5_buf);
    return 0;
}

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    *data = malloc(sizeof(__s5_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(__s5_buffer_t));
    *cb = __destroy;
    return as_tcp_read_start(clnt, __tcp_client_on_read);
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    switch(s5_buf->s5_status)
    {
        case 0x00:
            return __s5_auth(clnt, buf, len);
        case 0x01:
            return __s5_connect(clnt, buf, len);
        case 0x02:
            return __s5_tcp_forward(clnt, buf, len);
        case 0x03:
            return __s5_udp_forward(clnt, buf, len);
        default:
            return 1;
    }
    return 0;
}

static int __s5_auth(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    char dlen;
    char method;
    char ver;
    char resbuf[2];
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    if(len <= 2)
        return 1;
    ver = buf[0];
    if(ver != SOCKS5_VERSION)
        return 1;
    dlen = buf[1];
    if(dlen != len - 2)
        return 1;
    char *tbuf = (char *) &buf[2];
    while(dlen--)
    {
        method = *tbuf++;
        if(method == 0x00)
        {
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            s5_buf->s5_status = 0x01;
            if(as_tcp_write(clnt, resbuf, 2) <= 0)
                return 1;
            return 0;
        }
    }
    resbuf[0] = SOCKS5_VERSION;
    resbuf[1] = 0xff;
    s5_buf->s5_status = 0xff;
    if(as_tcp_write(clnt, resbuf, 2) <= 0)
        return 1;
    return 0;
}

static int __s5_connect(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    s5_conn_header_t *header;
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    int headerlen = sizeof(s5_conn_header_t);
    char resbuf[10];
    memset(resbuf, 0, 10);
    if(len <= headerlen)
        return 1;
    header = (s5_conn_header_t *) buf;
    if(header->ver != SOCKS5_VERSION)
        return 1;
    char *data = (char *) &buf[headerlen];
    int data_len = len - headerlen;
    as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    int conn_sts = as_tcp_connect(remote, (struct sockaddr*) &server_addr);
    if(conn_sts != 0)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x05;
        resbuf[3] = 0x01;
        if(as_tcp_write(clnt, resbuf, 10) <= 0)
            return 1;
    }
    switch(header->cmd)
    {
        case 0x01:
        {
            switch(header->atyp)
            {
                case 1:
                {
                    if(data_len != 6)
                        return 1;
                }
                    break;
                case 3:
                {
                    if(data_len < 3)
                        return 1;
                    unsigned char hl = data[0];
                    if(data_len != hl + 3)
                        return 1;
                }
                    break;
                case 4:
                {
                    if(data_len != 18)
                        return 1;
                }
                    break;
                default:
                    return 1;
            }
            char *sdata = malloc(ASP_MAX_DATA_LENGTH(data_len + 1));
            int sdlen;
            if(sdata == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            asp_encrypt(0x01, 0, (unsigned char *) data - 1, data_len + 1, aes_key, (unsigned char *) sdata, &sdlen);
            int slen = as_tcp_write(remote, sdata, sdlen);
            free(sdata);
            if(slen <= 0)
                return 1;
            if(as_tcp_read_start(remote, __tcp_remote_on_read) != 0)
                return 1;
        }
            break;
        case 0x02:
            //bind not support
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            if(as_tcp_write(clnt, resbuf, 10) <= 0)
                return 1;
        case 0x03:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            resbuf[3] = 0x01;
            s5_buf->s5_status = 0x03;
            if(as_tcp_write(clnt, resbuf, 10) <= 0)
                return 1;
        default:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            if(as_tcp_write(clnt, resbuf, 10) <= 0)
                return 1;
    }
    return 0;
}

static int __s5_tcp_forward(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
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

static int __s5_udp_forward(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    s5_udp_forward_t *header;
    int headerlen = sizeof(s5_udp_forward_t);
    if(len <= headerlen)
        return 1;
    header = (s5_udp_forward_t *) buf;
    char *data = (char *) &buf[headerlen];
    int data_len = len - headerlen;
    as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    if(as_udp_connect(remote, (struct sockaddr *) &server_addr) != 0)
        return 1;
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    switch(header->atyp)
    {
        case 1:
        {
            if(data_len <= 6)
                return 1;
        }
            break;
        case 3:
        {
            if(data_len < 3)
                return 1;
            unsigned char hl = data[0];
            if(data_len <= hl + 3)
                return 1;
        }
            break;
        case 4:
        {
            if(data_len <= 18)
                return 1;
        }
            break;
        default:
            return 1;
    }
    char *sdata = malloc(ASP_MAX_DATA_LENGTH(data_len + 1));
    int sdlen;
    if(sdata == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, (unsigned char *) data - 1, data_len + 1, aes_key, (unsigned char *) sdata, &sdlen);
    as_udp_write(remote, sdata, sdlen);
    free(sdata);
    if(as_udp_read_start(remote, __udp_remote_on_read) != 0)
        return 1;
    return 0;
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    return asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) s5_buf, __tcp_remote_on_read_decrypt);
}

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len)
{
    char resbuf[10];
    memset(resbuf, 0, 10);
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    if(status != 0)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x05;
        resbuf[3] = 0x01;
        as_tcp_write(clnt, resbuf, 10);
        return 0;
    }
    if(type == 0x11)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x00;
        resbuf[3] = 0x01;
        if(as_tcp_write(clnt, resbuf, 10) <= 0)
            return 1;
        s5_buf->s5_status = 0x02;
        return 0;
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
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    return asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) s5_buf, __udp_remote_on_read_decrypt);
}

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len)
{
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(clnt == NULL)
        return 1;
    if(status != 0)
        return 1;
    if(type == 0x22)
    {
        char *data = (char *) malloc(len + 10);
        memset(data, 0, 10);
        data[3] = 0x01;
        memcpy(&data[10], buf, len);
        int slen = as_tcp_write(clnt, data, len + 10);
        free(data);
        if(slen <= 0)
            return 1;
        return 0;
    }
    else
    {
        return 1;
    }
}
