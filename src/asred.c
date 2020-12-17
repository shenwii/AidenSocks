#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
// #include <netinet/ip.h>
// #include <netinet/ip6.h>
// #include <netinet/udp.h>
#include <sys/socket.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "ascore.h"
#include "log.h"
#include "asprot.h"

// typedef struct
// {
//     asp_buffer_t asp_buf;
//     struct sockaddr_storage destaddr;
//     int raw_sck;
//     unsigned char ip_header[40];
// } __udp_proxy_t;

unsigned char aes_key[AES_KEY_LEN / 8];

struct sockaddr_storage server_addr;

// static uint16_t __check_sum(unsigned char *data, int len);

static int __destroy(as_socket_t *sck);

static int __tcp_destaddr(int fd, struct sockaddr_storage *destaddr);

static int __udp_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr);

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len);

static int __tcp_remote_on_read_decrypt(void *parm, __const__ char type, __const__ char status, __const__ char *buf, __const__ int len);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len);

// static int __udp_destroy(as_socket_t *sck);

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
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr, conf.bport);

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

// static uint16_t __check_sum(unsigned char *data, int len) {
//     register long sum = 0;
//     while(len > 1) {
//         sum += *data << 8 | *(data + 1);
//         data += 2;
//         len -= 2;
//     }
//     if(len)
//         sum += *data << 8;
//     while(sum >> 16)
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     return (uint16_t)~sum;
// }

static int __destroy(as_socket_t *sck)
{
    asp_buffer_t *buf = (asp_buffer_t *) as_socket_data(sck);
    if(buf->len != 0)
        free(buf->buf);
    free(buf);
    return 0;
}

static int __tcp_destaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t len = sizeof(struct sockaddr_storage);
    int en = 0;

    //get ipv6
    en = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &len);
    if(en == 0)
        return 0;
    //get ipv4
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &len);;
}

static int __udp_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr)
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

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    struct sockaddr_storage destaddr;
    if(__tcp_destaddr(as_fd((as_socket_t *) clnt), &destaddr) != 0)
        return 1;
    as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
    if(as_tcp_connect(remote, (struct sockaddr*) &server_addr) != 0)
        return 1;
    char buf[19];
    int len;
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
    char *sdata = malloc(ASP_MAX_DATA_LENGTH(len));
    int dlen;
    if(sdata == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x01, 0, (unsigned char *) buf, len, aes_key, (unsigned char *) sdata, &dlen);
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

// static int __udp_destroy(as_socket_t *sck)
// {
//     __udp_proxy_t *udp_proxy = (__udp_proxy_t *) as_socket_data(sck);
//     if(udp_proxy->asp_buf.len != 0)
//         free(udp_proxy->asp_buf.buf);
//     if(udp_proxy->raw_sck > 0)
//         close(udp_proxy->raw_sck);
//     free(udp_proxy);
//     return 0;
// }

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), NULL, NULL);
    if(as_udp_connect(remote, (struct sockaddr *) &server_addr) != 0)
        return 1;
    as_socket_map_bind((as_socket_t *) clnt, (as_socket_t *) remote);
//     *data = malloc(sizeof(__udp_proxy_t));
    *data = malloc(sizeof(asp_buffer_t));
    if(*data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
//     memset(*data, 0, sizeof(__udp_proxy_t));
    memset(*data, 0, sizeof(asp_buffer_t));
//     *cb = __udp_destroy;
    *cb = __destroy;
    return as_udp_read_start(clnt, __udp_client_on_read);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
//     __udp_proxy_t *udp_proxy = (__udp_proxy_t *) as_socket_data((as_socket_t *) clnt);
//     if(__udp_destaddr((struct msghdr *) msg, &udp_proxy->destaddr) != 0)
//         return 1;
    struct sockaddr_storage destaddr;
    if(__udp_destaddr((struct msghdr *) msg, &destaddr) != 0)
        return 1;
//     if(udp_proxy->raw_sck <= 0)
//     {
//         int on = 1;
//         if(udp_proxy->destaddr.ss_family == AF_INET)
//         {
//             udp_proxy->raw_sck = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
//             if(udp_proxy->raw_sck <= 0)
//             {
//                 return 1;
//             }
//             if(setsockopt(udp_proxy->raw_sck, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
//             {
//                 return 1;
//             }
//         }
//         else
//         {
//             udp_proxy->raw_sck = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
//             if(udp_proxy->raw_sck <= 0)
//             {
//                 return 1;
//             }
//             if(setsockopt(udp_proxy->raw_sck, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) != 0)
//             {
//                 return 1;
//             }
//         }
//         if(udp_proxy->destaddr.ss_family == AF_INET)
//         {
//             struct iphdr *iph = (struct iphdr *) udp_proxy->ip_header;
//             iph->ihl = 5;
//             iph->version = 4;
//             iph->tos = 0;
//             iph->id = htons(rand());
//             iph->frag_off = 0;
//             iph->ttl = (uint8_t) 128;
//             iph->protocol = IPPROTO_UDP;
//             iph->check = 0;
//             memcpy(&iph->saddr, &((struct sockaddr_in *) &udp_proxy->destaddr)->sin_addr, 4);
//             memcpy(&iph->daddr, &((struct sockaddr_in *) as_dest_addr((as_socket_t *) clnt))->sin_addr, 4);
//         }
//         else
//         {
//             struct ip6_hdr *ip6h = (struct ip6_hdr *) udp_proxy->ip_header;
//             ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(6 << 28 |  (htons(rand()) >> 12));
//             ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
//             ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
//             memcpy(&ip6h->ip6_src, &((struct sockaddr_in6 *) &udp_proxy->destaddr)->sin6_addr, 16);
//             memcpy(&ip6h->ip6_dst, &((struct sockaddr_in6 *) as_dest_addr((as_socket_t *) clnt))->sin6_addr, 16);
//         }
//     }
    as_udp_t *remote = (as_udp_t *) as_socket_map((as_socket_t *) clnt);
    if(remote == NULL)
        return 1;
    char addr_buf[19 + len];
    int addr_len;
//     if(udp_proxy->destaddr.ss_family == AF_INET)
    if(destaddr.ss_family == AF_INET)
    {
//         struct sockaddr_in *addr = (struct sockaddr_in *) &udp_proxy->destaddr;
        struct sockaddr_in *addr = (struct sockaddr_in *) &destaddr;
        addr_buf[0] = 0x01;
        memcpy(addr_buf + 1, &addr->sin_addr, 4);
        memcpy(addr_buf + 5, &addr->sin_port, 2);
        memcpy(addr_buf + 7, buf, len);
        addr_len = 7 + len;
    }
    else
    {
//         struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &udp_proxy->destaddr;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &destaddr;
        addr_buf[0] = 0x04;
        memcpy(addr_buf + 1, &addr6->sin6_addr, 16);
        memcpy(addr_buf + 17, &addr6->sin6_port, 2);
        memcpy(addr_buf + 19, buf, len);
        addr_len = 19 + len;
    }
    char *data = malloc(ASP_MAX_DATA_LENGTH(addr_len));
    int dlen;
    if(data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    asp_encrypt(0x21, 0, (unsigned char *) addr_buf, addr_len, aes_key, (unsigned char *) data, &dlen);
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
//         __udp_proxy_t *udp_proxy = (__udp_proxy_t *) as_socket_data((as_socket_t *) clnt);
//         struct udphdr udph;
//         memset(&udph, 0, sizeof(struct udphdr));
//         udph.uh_ulen = htons(sizeof(struct udphdr) + len);
//         udph.uh_sum = 0;
//         char *raw_buf;
//         int tot_len;
//         if(udp_proxy->destaddr.ss_family == AF_INET)
//         {
//             struct iphdr *iph = (struct iphdr *) udp_proxy->ip_header;
//             {
//                 unsigned char *chk_buf = (unsigned char *) malloc(12 + sizeof(struct udphdr) + len);
//                 memset(chk_buf, 0, 12 + sizeof(struct udphdr) + len);
//                 memcpy(chk_buf, &iph->saddr, 4);
//                 memcpy(chk_buf + 4, &iph->daddr, 4);
//                 chk_buf[9] = IPPROTO_UDP;
//                 memcpy(chk_buf + 10, &udph.uh_ulen, 2);
//                 memcpy(chk_buf + 12, &udph, sizeof(struct udphdr));
//                 memcpy(chk_buf + 12 + sizeof(struct udphdr), buf, len);
//                 udph.uh_sum = htons(__check_sum(chk_buf, 12 + sizeof(struct udphdr) + len));
//                 free(chk_buf);
//             }
//             udph.uh_sport = ((struct sockaddr_in *) &udp_proxy->destaddr)->sin_port;
//             udph.uh_dport = ((struct sockaddr_in *) as_dest_addr((as_socket_t *) clnt))->sin_port;
//             tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
//             iph->tot_len = htons(tot_len);
//             raw_buf = (char *) malloc(tot_len);
//             if(raw_buf == NULL)
//             {
//                 LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
//                 abort();
//             }
//             memcpy(raw_buf, iph, sizeof(struct iphdr));
//             memcpy(raw_buf + sizeof(struct iphdr), &udph, sizeof(struct udphdr));
//             memcpy(raw_buf + sizeof(struct iphdr) + sizeof(struct udphdr), buf, len);
//         }
//         else
//         {
//             struct ip6_hdr *ip6h = (struct ip6_hdr *) udp_proxy->ip_header;
//             {
//                 unsigned char *chk_buf = (unsigned char *) malloc(36 + sizeof(struct udphdr) + len);
//                 memset(chk_buf, 0, 36 + sizeof(struct udphdr) + len);
//                 memcpy(chk_buf, &ip6h->ip6_src, 16);
//                 memcpy(chk_buf + 16, &ip6h->ip6_dst, 16);
//                 chk_buf[33] = IPPROTO_UDP;
//                 memcpy(chk_buf + 34, &udph.uh_ulen, 2);
//                 memcpy(chk_buf + 36, &udph, sizeof(struct udphdr));
//                 memcpy(chk_buf + 36 + sizeof(struct udphdr), buf, len);
//                 udph.uh_sum = htons(__check_sum(chk_buf, 36 + sizeof(struct udphdr) + len));
//                 free(chk_buf);
//             }
//             udph.uh_sport = ((struct sockaddr_in6 *) &udp_proxy->destaddr)->sin6_port;
//             udph.uh_dport = ((struct sockaddr_in6 *) as_dest_addr((as_socket_t *) clnt))->sin6_port;
//             tot_len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + len;
//             ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct udphdr) + len);
//             raw_buf = (char *) malloc(tot_len);
//             if(raw_buf == NULL)
//             {
//                 LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
//                 abort();
//             }
//             memcpy(raw_buf, ip6h, sizeof(struct ip6_hdr));
//             memcpy(raw_buf + sizeof(struct ip6_hdr), &udph, sizeof(struct udphdr));
//             memcpy(raw_buf + sizeof(struct ip6_hdr) + sizeof(struct udphdr), buf, len);
//         }
//         sendto(udp_proxy->raw_sck, raw_buf, tot_len, 0, (struct sockaddr *) as_dest_addr((as_socket_t *) clnt), sizeof(struct sockaddr_storage));
//         free(raw_buf);
//         as_udp_write(clnt, NULL, 0);
        as_udp_write(clnt, buf, len);
        return 0;
    }
    return 1;
}
