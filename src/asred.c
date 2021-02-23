#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/socket.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "ascore.h"
#include "log.h"
#include "asprot.h"

unsigned char aes_key[AES_KEY_LEN / 8];

struct sockaddr_storage server_addr;

static int __redirect_destaddr(int fd, struct sockaddr_storage *destaddr);

static int __tproxy_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr);

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
    conf_t conf;
    as_loop_t *loop;
    as_tcp_t *tcp;
    as_udp_t *udp;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;
    if(argc < 2)
        return __usage(argv[0]);
    if(conf_parse(&conf, argv[1], "Redire") != 0)
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

    //bind ipv6 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr6, AS_UDP_IPV6ONLY | AS_UDP_TPROXY) != 0)
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
    if(as_udp_bind(udp, (struct sockaddr *) &addr, AS_UDP_TPROXY) != 0)
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
    as_loop_run(loop);
    return 0;
}

static int __redirect_destaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t len = sizeof(struct sockaddr_storage);
    int en = 0;

    //get ipv6
    en = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &len);
    if(en == 0)
        return 0;

    //get ipv4
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &len);
}

static int __tproxy_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr)
{
    struct cmsghdr *cmsg;
    while((cmsg = CMSG_FIRSTHDR(msg)))
    {
        if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR)
        {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            destaddr->ss_family = AF_INET;
            return 0;
        }
        else if(cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR)
        {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            destaddr->ss_family = AF_INET6;
            return 0;
        }
    }
    return 1;
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
    if(as_tcp_connect(remote, (struct sockaddr*) &server_addr, __tcp_remote_on_connected) != 0)
        return 1;
    return 0;
}

static int __tcp_remote_on_connected(as_tcp_t *remote, char status)
{
    struct sockaddr_storage destaddr;
    as_tcp_t *clnt = (as_tcp_t *) as_socket_map((as_socket_t *) remote);
    if(status != 0)
        return 1;
    if(__redirect_destaddr(as_fd((as_socket_t *) clnt), &destaddr) != 0)
        return 1;
    LOG_INFO("tcp redirect to %s\n", address_str((struct sockaddr *) &destaddr));
    unsigned char buf[19];
    size_t len;
    if(destaddr.ss_family == AF_INET)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *) &destaddr;
        buf[0] = 0x01;
        memcpy(buf + 1, &addr->sin_addr, 4);
        memcpy(buf + 5, &addr->sin_port, 2);
        len = 7;
    }
    else
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &destaddr;
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
    asp_encrypt(0x01, 0, (unsigned char *) buf, len, aes_key, (unsigned char *) sdata, &dlen);
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
    return as_udp_read_start(clnt, __udp_client_on_read, 0);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    struct sockaddr_storage destaddr;
    as_udp_t *remote = (as_udp_t *) as_socket_map((as_socket_t *) clnt);
    if(__tproxy_destaddr((struct msghdr *) msg, &destaddr) != 0)
        return 1;
    LOG_INFO("udp redirect to %s\n", address_str((struct sockaddr *) &destaddr));
    unsigned char addr_buf[19 + len];
    size_t addr_len;
    if(destaddr.ss_family == AF_INET)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *) &destaddr;
        addr_buf[0] = 0x01;
        memcpy(addr_buf + 1, &addr->sin_addr, 4);
        memcpy(addr_buf + 5, &addr->sin_port, 2);
        memcpy(addr_buf + 7, buf, len);
        addr_len = 7 + len;
    }
    else
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &destaddr;
        addr_buf[0] = 0x04;
        memcpy(addr_buf + 1, &addr6->sin6_addr, 16);
        memcpy(addr_buf + 17, &addr6->sin6_port, 2);
        memcpy(addr_buf + 19, buf, len);
        addr_len = 19 + len;
    }
    unsigned char *data = malloc(ASP_MAX_DATA_LENGTH(addr_len));
    size_t dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, (unsigned char *) addr_buf, addr_len, aes_key, (unsigned char *) data, &dlen);
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
