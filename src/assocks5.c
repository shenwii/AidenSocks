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
#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif


#define SOCKS5_VERSION 0x05

unsigned char aes_key[AES_KEY_LEN / 8];

typedef struct
{
    char ver;
    char cmd;
    char rsv;
    char atyp;
} __attribute__ ((__packed__)) __s5_conn_header_t;

typedef struct
{
    char rsv[2];
    char frag;
    char atyp;
} __attribute__ ((__packed__)) __s5_udp_forward_t;

typedef struct
{
    asp_buffer_t asp_buffer;
    char s5_status;
    unsigned char *conn_buf;
    size_t conn_buf_size;
} __s5_buffer_t;

struct sockaddr_storage tcp_server_addr;

struct sockaddr_storage udp_server_addr;

static int __socks5_address_str(__const__ unsigned char *buf, __const__ size_t len, char *addr_str);

static int __destroy(as_socket_t *sck);

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len);

static int __s5_auth(as_tcp_t *srv, __const__ unsigned char *buf, __const__ size_t len);

static int __s5_connect(as_tcp_t *srv, __const__ unsigned char *buf, __const__ size_t len);

static int __s5_tcp_forward(as_tcp_t *srv, __const__ unsigned char *buf, __const__ size_t len);

static int __s5_udp_forward(as_tcp_t *srv, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_connected(as_tcp_t *remote, char status);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_wrote(as_udp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

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

    //bind ipv6 tcp address
    tcp = as_tcp_init(loop, NULL, NULL);
    if(as_tcp_bind(tcp, (struct sockaddr *) &addr6, AS_TCP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_TCP_BIND, conf.baddr6, conf.bport);
        return 1;
    }
    if(as_tcp_listen(tcp, __tcp_client_on_accepted) != 0)
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
    if(as_tcp_listen(tcp, __tcp_client_on_accepted) != 0)
    {
        LOG_ERR(MSG_TCP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr, conf.bport);
    as_loop_run(loop);
    return 0;
}

static int __socks5_address_str(__const__ unsigned char *buf, __const__ size_t len, char *addr_str)
{
    char s[80];
    uint16_t *port;
    switch(buf[0])
    {
        case 1:
            if(len < 7)
                return -1;
            port = (uint16_t *) &buf[5];
            inet_ntop(AF_INET, &buf[1], s, 80);
            sprintf(addr_str, "%s:%d", s, ntohs(*port));
            return 7;
        case 3:
            if(len < 4)
                return -1;
            unsigned char hl = buf[1];
            if(len < hl + 4)
                return -1;
            port = (uint16_t *) &buf[2 + hl];
            sprintf(s,"%d", ntohs(*port));
            memcpy(addr_str, &buf[2], len - 4);
            addr_str[len - 4] = ':';
            memcpy(&addr_str[len - 3], s, strlen(s));
            addr_str[len - 3 + strlen(s)] = '\0';
            return hl + 4;
        case 4:
            if(len < 19)
                return -1;
            port = (uint16_t *) &buf[17];
            inet_ntop(AF_INET6, &buf[1], s, 80);
            sprintf(addr_str, "[%s]:%d", s, ntohs(*port));
            return 19;
        default:
            return -1;
    }
}

static int __destroy(as_socket_t *sck)
{
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data(sck);
    if(s5_buf->asp_buffer.len != 0)
        free(s5_buf->asp_buffer.buf);
    free(s5_buf);
    return 0;
}

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    *data = malloc(sizeof(__s5_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(__s5_buffer_t));
    *cb = __destroy;
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
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

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    if(s5_buf->s5_status == 0x02)
    {
        as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
        return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
    }
    else if(s5_buf->s5_status == 0x03)
    {
        as_udp_t *udp = (as_udp_t *) as_socket_map((as_socket_t *) clnt);
        if(udp != NULL)
            return as_udp_read_start(udp, __udp_remote_on_read, AS_READ_ONESHOT);
    }
    else
    {
        return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
    }
    return 0; 
}

static int __s5_auth(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    char dlen;
    char method;
    char ver;
    unsigned char resbuf[2];
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    if(len <= 2)
        return 1;
    ver = buf[0];
    if(ver != SOCKS5_VERSION)
        return 1;
    dlen = buf[1];
    if(dlen != len - 2)
        return 1;
    unsigned char *tbuf = (unsigned char *) &buf[2];
    while(dlen--)
    {
        method = *tbuf++;
        if(method == 0x00)
        {
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            s5_buf->s5_status = 0x01;
            as_tcp_write(clnt, resbuf, 2, __tcp_client_on_wrote);
            return 0;
        }
    }
    resbuf[0] = SOCKS5_VERSION;
    resbuf[1] = 0xff;
    s5_buf->s5_status = 0xff;
    as_tcp_write(clnt, resbuf, 2, __tcp_client_on_wrote);
    return 0;
}

static int __tcp_remote_on_connected(as_tcp_t *remote, char status)
{
    char addr_str[256];
    unsigned char resbuf[10];
    memset(resbuf, 0, 10);
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    __s5_conn_header_t *header = (__s5_conn_header_t *) s5_buf->conn_buf;
    unsigned char *data = (unsigned char *) &s5_buf->conn_buf[sizeof(__s5_conn_header_t)];
    size_t data_len = s5_buf->conn_buf_size - sizeof(__s5_conn_header_t);
    if(status != 0)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x05;
        resbuf[3] = 0x01;
        as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
        free(s5_buf->conn_buf);
        return 0;
    }
    switch(header->cmd)
    {
        case 0x01:
        {
            if(__socks5_address_str(data - 1, data_len + 1, addr_str) != data_len + 1)
            {
                free(s5_buf->conn_buf);
                return 1;
            }
            LOG_INFO("%s tcp connect to %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), addr_str);
            unsigned char *sdata = (unsigned char *) malloc(ASP_MAX_DATA_LENGTH(data_len + 1));
            size_t sdlen;
            if(sdata == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            asp_encrypt(0x01, 0, data - 1, data_len + 1, aes_key, (unsigned char *) sdata, &sdlen);
            as_tcp_write(remote, sdata, sdlen, NULL);
            free(sdata);
            as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
        }
            break;
        case 0x02:
            //bind not support
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
        case 0x03:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            resbuf[3] = 0x01;
            s5_buf->s5_status = 0x03;
            as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
        default:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
    }
    free(s5_buf->conn_buf);
    return 0;
}

static int __s5_connect(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    __s5_conn_header_t *header;
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    int headerlen = sizeof(__s5_conn_header_t);
    if(len <= headerlen)
        return 1;
    header = (__s5_conn_header_t *) buf;
    if(header->ver != SOCKS5_VERSION)
        return 1;
    as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    s5_buf->conn_buf = (unsigned char *) malloc(len);
    if(s5_buf->conn_buf == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memcpy(s5_buf->conn_buf, buf, len);
    s5_buf->conn_buf_size = len;
    return as_tcp_connect(remote, (struct sockaddr*) &tcp_server_addr, __tcp_remote_on_connected);
}

static int __s5_tcp_forward(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
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
    as_tcp_write(remote, data, dlen, __tcp_remote_on_wrote);
    free(data);
    return 0;
}

static int __s5_udp_forward(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    char addr_str[256];
    int addr_len;
    int headerlen = sizeof(__s5_udp_forward_t);
    if(len <= headerlen)
        return 1;
    unsigned char *data = (unsigned char *) &buf[headerlen];
    size_t data_len = len - headerlen;
    as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    if(as_udp_connect(remote, (struct sockaddr *) &udp_server_addr) != 0)
        return 1;
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    addr_len = __socks5_address_str(data - 1, data_len + 1, addr_str);
    if(addr_len == -1 || addr_len >= data_len + 1)
        return 1;
    LOG_INFO("%s udp send to %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), addr_str);
    unsigned char *sdata = malloc(ASP_MAX_DATA_LENGTH(data_len + 1));
    size_t sdlen;
    if(sdata == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, data - 1, data_len + 1, aes_key, sdata, &sdlen);
    as_udp_write(remote, sdata, sdlen, __udp_remote_on_wrote);
    free(sdata);
    if(as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT) != 0)
        return 1;
    return 0;
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    int rtn = asp_decrypt(remote, (unsigned char *) buf, len, aes_key, (asp_buffer_t *) s5_buf, __tcp_remote_on_read_decrypt);
    if(rtn == -1)
        return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    unsigned char resbuf[10];
    memset(resbuf, 0, 10);
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    if(status != 0)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x05;
        resbuf[3] = 0x01;
        as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
        return 0;
    }
    if(type == 0x11)
    {
        s5_buf->s5_status = 0x02;
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x00;
        resbuf[3] = 0x01;
        as_tcp_write(clnt, resbuf, 10, __tcp_client_on_wrote);
        as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
    }
    else if(type == 0x02)
    {
        as_tcp_write(clnt, buf, len, __tcp_client_on_wrote);
    }
    else
    {
        return 1;
    }
    return 0;
}

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    __s5_buffer_t *s5_buf = (__s5_buffer_t *) as_socket_data((as_socket_t *) clnt);
    int rtn = asp_decrypt(remote, buf, len, aes_key, (asp_buffer_t *) s5_buf, __udp_remote_on_read_decrypt);
    if(rtn == -1)
        return as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __udp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *remote = (as_tcp_t *) parm;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(status != 0)
        return 1;
    if(type == 0x22)
    {
        unsigned char *data = (unsigned char *) malloc(len + 10);
        memset(data, 0, 10);
        data[3] = 0x01;
        memcpy(&data[10], buf, len);
        as_tcp_write(clnt, data, len + 10, __tcp_client_on_wrote);
        free(data);
        return 0;
    }
    else
    {
        return 1;
    }
}

static int __udp_remote_on_wrote(as_udp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}
