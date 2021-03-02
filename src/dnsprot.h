#ifndef _DNSPROT_H
#define _DNSPROT_H

#include <stdint.h>
#include <stddef.h>

#define DNS_HOST_MAX_LENGTH 256

typedef struct
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    char flag_rd:1;
    char flag_tc:1;
    char flag_aa:1;
    char falg_opcode:4;
    char flag_qr:1;
    char rcode:4;
    char fill:3;
    char flag_ra:1;
#else
    char flag_qr:1;
    char falg_opcode:4;
    char flag_aa:1;
    char flag_tc:1;
    char flag_rd:1;
    char flag_ra:1;
    char fill:3;
    char rcode:4;
#endif
} __attribute__ ((__packed__)) dns_hdr_flag_t;

typedef struct
{
    uint16_t id;
    dns_hdr_flag_t hdr_flag;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} __attribute__ ((__packed__)) dns_hdr_t;

typedef struct
{
    char query[255];
    uint16_t type;
    uint16_t class;
} dns_qstn_t;

typedef struct
{
    char query[255];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    unsigned char data[255];
} dns_resr_t;

typedef struct
{
    dns_hdr_t header;
    dns_qstn_t *question;
    dns_resr_t *answer;
    dns_resr_t *authority;
    dns_resr_t *additional;
} dns_prtcl_t;

int dns_request_data(__const__ uint16_t id, __const__ dns_hdr_flag_t *hdr_flag, char *host, __const__ uint16_t type, __const__ uint16_t _class, unsigned char *data);

int dns_response_parse(__const__ unsigned char *data, __const__ size_t len, dns_prtcl_t *dns_prtcl);

int dns_prtcl_free(dns_prtcl_t *dns_prtcl);

#endif
