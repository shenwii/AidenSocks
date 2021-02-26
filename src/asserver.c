#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if defined _WIN32 || defined __CYGWIN__
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "ascore.h"
#include "log.h"
#include "asprot.h"

typedef struct
{
    asp_buffer_t as_buf;
    char connect_status;
    char proc;
    uint16_t port;
    unsigned char *buf;
    size_t buf_len;
    int addr_len;
} __as_data_t;

unsigned char aes_key[AES_KEY_LEN / 8];

static int __destroy(as_socket_t *sck);

static int __tcp_client_dns_resolved(as_socket_t *sck, __const__ char status, __const__ struct sockaddr *addr);

static int __udp_client_dns_resolved(as_socket_t *sck, __const__ char status, __const__ struct sockaddr *addr);

static int __parse_asp_address(as_socket_t *sck, __const__ unsigned char *buf, __const__ int len, char *addr_str, as_resolved_f cb);

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_connected(as_tcp_t *remote, char status);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_accepted(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_wrote(as_udp_t *clnt, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

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
    as_udp_t *udp;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;
    if(argc < 2)
        return __usage(argv[0]);
    if(conf_parse(&conf, argv[1], "Server") != 0)
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
    //bind ipv6 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr6, AS_UDP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_UDP_BIND, conf.baddr6, conf.bport);
        return 1;
    }
    if(as_udp_listen(udp, __udp_client_on_accepted) != 0)
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
    if(as_udp_listen(udp, __udp_client_on_accepted) != 0)
    {
        LOG_ERR(MSG_UDP_LISTENED);
        return 1;
    }
    LOG_INFO(MSG_UDP_LISTEN_ON, conf.baddr, conf.bport);
    as_loop_run(loop);
    return 0;
}

static int __destroy(as_socket_t *sck)
{
    __as_data_t *data = (__as_data_t *) as_socket_data(sck);
    asp_buffer_t *buf = &data->as_buf;
    if(buf->len != 0)
        free(buf->buf);
    free(data);
    return 0;
}

static int __tcp_client_dns_resolved(as_socket_t *sck, __const__ char status, __const__ struct sockaddr *addr)
{
    as_tcp_t *clnt = (as_tcp_t *) sck;
    __as_data_t *as_data = (__as_data_t *) as_socket_data(sck);
    if(as_data->addr_len != as_data->buf_len)
        return 1;
    if(status == 0)
    {
        as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
        as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
        if(addr->sa_family == AF_INET)
        {
            ((struct sockaddr_in *) addr)->sin_port = as_data->port;
        }
        else
        {
            ((struct sockaddr_in6 *) addr)->sin6_port = as_data->port;
        }
        return as_tcp_connect(remote, (struct sockaddr*) addr, __tcp_remote_on_connected);
    }
    else
    {
        __as_data_t *as_data = (__as_data_t *) as_socket_data((as_socket_t *) clnt);
        unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(0));
        size_t dlen;
        if(data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        asp_encrypt(0x11, status, NULL, 0, aes_key, data, &dlen);
        as_data->connect_status = status;
        as_tcp_write(clnt, data, dlen, __tcp_client_on_wrote);
        free(data);
        return 0;
    }
}

static int __udp_client_dns_resolved(as_socket_t *sck, __const__ char status, __const__ struct sockaddr *addr)
{
    as_udp_t *clnt = (as_udp_t *) sck;
    __as_data_t *as_data = (__as_data_t *) as_socket_data(sck);
    if(as_data->addr_len == -1 || as_data->addr_len >= as_data->buf_len)
    {
        free(as_data->buf);
        return 1;
    }
    if(status == 0)
    {
        as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
        as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
        if(addr->sa_family == AF_INET)
        {
            ((struct sockaddr_in *) addr)->sin_port = as_data->port;
        }
        else
        {
            ((struct sockaddr_in6 *) addr)->sin6_port = as_data->port;
        }
        if(as_udp_connect(remote, (struct sockaddr*) addr) != 0)
        {
            free(as_data->buf);
            return 1;
        }
        if(as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT) != 0)
        {
            free(as_data->buf);
            return 1;
        }
        as_udp_write(remote, as_data->buf + as_data->addr_len, as_data->buf_len - as_data->addr_len, NULL);
        return 0;
    }
    else
    {
        free(as_data->buf);
        return 1;
    }
}

static int __parse_asp_address(as_socket_t *sck, __const__ unsigned char *buf, __const__ int len, char *addr_str, as_resolved_f cb)
{
    __as_data_t *as_data = (__as_data_t *) as_socket_data(sck);
    struct sockaddr_storage addr;
    char s[80];
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
            ((struct sockaddr_in *) &addr)->sin_family = AF_INET;
            ((struct sockaddr_in *) &addr)->sin_port = *port;
            memcpy(&((struct sockaddr_in *) &addr)->sin_addr, (char *) &buf[1], 4);
            inet_ntop(AF_INET, &buf[1], s, 80);
            sprintf(addr_str, "%s:%d", s, ntohs(*port));
            as_data->addr_len = 7;
            if(cb(sck, 0, (struct sockaddr *) &addr) != 0)
                return -2;
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
                as_data->addr_len = dlen + 4;
                as_data->port = *port;
                if(as_resolver(sck, addrstr, cb) != 0)
                    return -2;
            }
            sprintf(s,"%d", ntohs(*port));
            memcpy(addr_str, &buf[2], len - 4);
            addr_str[len - 4] = ':';
            memcpy(&addr_str[len - 3], s, strlen(s));
            addr_str[len - 3 + strlen(s)] = '\0';
            return dlen + 4;
        case 0x04:
            //ipv6
            if(len < 19)
                return -1;
            port = (uint16_t *) &buf[17];
            ((struct sockaddr_in6 *) &addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *) &addr)->sin6_port = *port;
            memcpy(&((struct sockaddr_in6 *) &addr)->sin6_addr, (char *) &buf[1], 16);
            inet_ntop(AF_INET6, &buf[1], s, 80);
            sprintf(addr_str, "[%s]:%d", s, ntohs(*port));
            as_data->addr_len = 19;
            if(cb(sck, 0, (struct sockaddr *) &addr) != 0)
                return -2;
            return 19;
        default:
            return -1;
    }
}

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    *data = malloc(sizeof(__as_data_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(__as_data_t));
    *cb = __destroy;
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    int rtn = asp_decrypt(clnt, buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __tcp_client_on_read_decrypt);
    if(rtn == -1)
        return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __tcp_client_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    char addr_str[256];
    as_tcp_t *clnt = (as_tcp_t *) parm;
    if(status != 0)
        return 1;
    __as_data_t *as_data = (__as_data_t *) as_socket_data((as_socket_t *) clnt);
    if(type == 0x01)
    {
        if(as_data->proc == 0)
        {
            as_data->buf_len = len;
            int addr_len = __parse_asp_address((as_socket_t *) clnt, buf, len, addr_str, __tcp_client_dns_resolved);
            if(addr_len < 0)
                return 1;
            LOG_INFO("%s tcp connect to %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), addr_str);
            return 0;
        }
        else
        {
            unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(0));
            size_t dlen;
            if(data == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            asp_encrypt(0x11, 2, NULL, 0, aes_key, data, &dlen);
            as_tcp_write(clnt, data, dlen, __tcp_client_on_wrote);
            free(data);
            return 1;
        }
    }
    else if(type == 0x02 && as_data->proc == 1)
    {
        as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
        as_tcp_write(remote, buf, len, __tcp_remote_on_wrote);
        return 0;
    }
    else
    {
        return 1;
    }
}

static int __tcp_client_on_wrote(as_tcp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    __as_data_t *data = (__as_data_t *) as_socket_data((as_socket_t *) clnt);
    as_tcp_t *remote = (as_tcp_t *) as_socket_map((as_socket_t *) clnt);
    if(data->proc == 0)
    {
        if(data->connect_status == 0)
        {
            data->proc = 1;
            if(as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT) != 0)
                return 1;
        }
        return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
    }
    else
    {
        return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
    }
}

static int __tcp_remote_on_connected(as_tcp_t *remote, char status)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    __as_data_t *as_data = (__as_data_t *) as_socket_data((as_socket_t *) clnt);
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(0));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x11, status, NULL, 0, aes_key, data, &dlen);
    as_data->connect_status = status;
    as_tcp_write(clnt, data, dlen, __tcp_client_on_wrote);
    free(data);
    return 0;
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(len));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x02, 0, buf, len, aes_key, data, &dlen);
    as_tcp_write(clnt, data, dlen, __tcp_client_on_wrote);
    free(data);
    return 0;
}

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    return as_tcp_read_start(clnt, __tcp_client_on_read, AS_READ_ONESHOT);
}

static int __udp_client_on_accepted(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    *data = malloc(sizeof(__as_data_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(*data, 0, sizeof(__as_data_t));
    *cb = __destroy;
    return as_udp_read_start(clnt, __udp_client_on_read, AS_READ_ONESHOT);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    int rtn = asp_decrypt(clnt, buf, len, aes_key, (asp_buffer_t *) as_socket_data((as_socket_t *) clnt), __udp_client_on_read_decrypt);
    if(rtn == -1)
        return as_udp_read_start(clnt, __udp_client_on_read, AS_READ_ONESHOT);
    return rtn;
}

static int __udp_client_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ unsigned char *buf, __const__ size_t len)
{
    char addr_str[256];
    as_udp_t *clnt = (as_udp_t *) parm;
    __as_data_t *as_data = (__as_data_t *) as_socket_data((as_socket_t *) clnt);
    int addr_len;
    if(status != 0)
        return 1;
    if(type == 0x21)
    {
        as_data->buf = (unsigned char *) malloc(len);
        if(as_data->buf == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        memcpy(as_data->buf, buf, len);
        as_data->buf_len = len;
        addr_len = __parse_asp_address((as_socket_t *) clnt, buf, len, addr_str, __udp_client_dns_resolved);
        if(addr_len == -1)
            free(as_data->buf);
        if(addr_len < 0)
            return 1;
        LOG_INFO("%s udp send to %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) clnt)), addr_str);
        return 0;
    }
    else
    {
        return 1;
    }
}

static int __udp_client_on_wrote(as_udp_t *clnt, __const__ unsigned char *buf, __const__ size_t len)
{
    return as_udp_read_start((as_udp_t *) as_socket_map((as_socket_t *) clnt), __udp_remote_on_read, AS_READ_ONESHOT);
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    as_udp_t *clnt = (as_udp_t *) as_socket_map((as_socket_t *) remote);
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(len));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x22, 0, buf, len, aes_key, data, &dlen);
    as_udp_write(clnt, data, dlen, __udp_client_on_wrote);
    free(data);
    return 0;
}
