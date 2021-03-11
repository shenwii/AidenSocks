#include "dnsprot.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

int __dns_query_parse(__const__ unsigned char *data, __const__ size_t len, int *pos, char *str)
{
    unsigned char *pdata = (unsigned char *) &data[*pos];
    unsigned char strl;
    if(*pos > len)
        return 1;
    if(*pdata == 0)
    {
        if(*pos + 1 > len)
            return 1;
        *pos += 1;
        return 0;
    }
    while((strl = *pdata) != 0)
    {
        if(strl >> 6 == 0x03)
        {
            if(*pos + 2 > len)
                return 1;
            int tpos = *(pdata + 1);
            if(__dns_query_parse(data, len, &tpos, str) != 0)
                return 1;
            pdata += 2;
            *pos += 2;
            return 0;
        }
        else
        {
            memcpy(str, pdata + 1, strl);
            str += strl;
            *str++ = '.';
            pdata += strl + 1;
            *pos += strl + 1;
        }
    }
    *(str - 1) = '\0';
    *pos += 1;
    return 0;
}

int __parse_question(__const__ unsigned char *data, __const__ size_t len, int *pos, uint16_t cnt, dns_qstn_t *question_list)
{
    unsigned char *p;
    for(int i = 0; i < cnt; i++)
    {
        dns_qstn_t *question = question_list + i;
        if(__dns_query_parse(data, len, pos, question->query) != 0)
            return 1;
        p = (unsigned char *) &data[*pos];
        if(*pos + 4 > len)
            return 1;
        question->type = ntohs(*((uint16_t *) p));
        question->class = ntohs(*((uint16_t *) (p + 2)));
        *pos += 4;
    }
    return 0;
}

int __parse_resource(__const__ unsigned char *data, __const__ size_t len, int *pos, uint16_t cnt, dns_resr_t *resource_list)
{
    unsigned char *p;
    for(int i = 0; i < cnt; i++)
    {
        dns_resr_t *resource = resource_list + i;
        if(__dns_query_parse(data, len, pos, resource->query) != 0)
            return 1;
        p = (unsigned char *) &data[*pos];
        if(*pos + 8 > len)
            return 1;
        resource->type = ntohs(*((uint16_t *) p));
        resource->class = ntohs(*((uint16_t *) (p + 2)));
        resource->ttl = ntohl(*((uint32_t *) (p + 4)));
        *pos += 8;
        p = (unsigned char *) &data[*pos];
        if(*pos + 2 > len)
            return 1;
        resource->data_len = ntohs(*((uint16_t *) p));
        if(resource->data_len != 0)
        {
            if(*pos + 2 + resource->data_len > len)
                return 1;
            switch(resource->type)
            {
            case 2:
            case 5:
            {
                int tpos = *pos + 2;
                if(__dns_query_parse(data, len, &tpos, (char *) resource->data) != 0)
                    return 1;
            }
                break;
            default:
                memcpy(resource->data, p + 2, resource->data_len);
                break;
            }
        }
        *pos += 2 + resource->data_len;
    }
    return 0;
}

int dns_request_data(__const__ uint16_t id, __const__ dns_hdr_flag_t *hdr_flag, char *host, __const__ uint16_t type, __const__ uint16_t _class, unsigned char *data)
{
    unsigned char question_data[260];
    int pos = 0;
    unsigned char cnt = 0;
    register char c;
    dns_hdr_t header;
    header.id = htons(id);
    header.hdr_flag = *hdr_flag;
    header.qd_count = htons(1);
    header.an_count = 0;
    header.ns_count = 0;
    header.ar_count = 0;
    while((c = *host++) != '\0')
    {
        if(c == '.')
        {
            question_data[pos] = cnt;
            memcpy(&question_data[pos + 1], host - cnt - 1, cnt);
            pos += cnt + 1;
            cnt = 0;
        }
        else
        {
            cnt++;
        }
    }
    question_data[pos] = cnt;
    if(cnt != 0)
        memcpy(&question_data[pos + 1], host - cnt - 1, cnt);
    pos += cnt + 1;
    question_data[pos++] = 0;
    *((uint16_t *) &question_data[pos]) = htons(type);
    pos += 2;
    *((uint16_t *) &question_data[pos]) = htons(_class);
    pos += 2;
    memcpy(data, &header, sizeof(dns_hdr_t));
    memcpy(data + sizeof(dns_hdr_t), question_data, pos);
    return sizeof(dns_hdr_t) + pos;
}

int dns_response_parse(__const__ unsigned char *data, __const__ size_t len, dns_prtcl_t *dns_prtcl)
{
    int pos = 0;
    if(len < sizeof(dns_hdr_t))
        return 1;
    memcpy(&dns_prtcl->header, data, sizeof(dns_hdr_t));
    dns_prtcl->header.id = ntohs(dns_prtcl->header.id);
    dns_prtcl->header.qd_count = ntohs(dns_prtcl->header.qd_count);
    dns_prtcl->header.an_count = ntohs(dns_prtcl->header.an_count);
    dns_prtcl->header.ns_count = ntohs(dns_prtcl->header.ns_count);
    dns_prtcl->header.ar_count = ntohs(dns_prtcl->header.ar_count);
    pos += sizeof(dns_hdr_t);
    if(dns_prtcl->header.qd_count == 0)
    {
        dns_prtcl->question = NULL;
    }
    else
    {
        dns_prtcl->question = calloc(dns_prtcl->header.qd_count, sizeof(dns_qstn_t));
        if(dns_prtcl->question == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(__parse_question(data, len, &pos, dns_prtcl->header.qd_count, dns_prtcl->question) != 0)
        {
            free(dns_prtcl->question);
            dns_prtcl->header.qd_count = 0;
            return 1;
        }
    }

    if(dns_prtcl->header.an_count == 0)
    {
        dns_prtcl->answer = NULL;
    }
    else
    {
        dns_prtcl->answer = calloc(dns_prtcl->header.an_count, sizeof(dns_resr_t));
        if(dns_prtcl->answer == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(__parse_resource(data, len, &pos, dns_prtcl->header.an_count, dns_prtcl->answer) != 0)
        {
            if(dns_prtcl->header.qd_count != 0)
            {
                free(dns_prtcl->question);
                dns_prtcl->header.qd_count = 0;
            }
            free(dns_prtcl->answer);
            dns_prtcl->header.an_count = 0;
            return 1;
        }
    }

    if(dns_prtcl->header.ns_count == 0)
    {
        dns_prtcl->authority = NULL;
    }
    else
    {
        dns_prtcl->authority = calloc(dns_prtcl->header.ns_count, sizeof(dns_resr_t));
        if(dns_prtcl->authority == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(__parse_resource(data, len, &pos, dns_prtcl->header.ns_count, dns_prtcl->authority) != 0)
        {
            if(dns_prtcl->header.qd_count != 0)
            {
                free(dns_prtcl->question);
                dns_prtcl->header.qd_count = 0;
            }
            if(dns_prtcl->header.an_count != 0)
            {
                free(dns_prtcl->answer);
                dns_prtcl->header.an_count = 0;
            }
            free(dns_prtcl->authority);
            dns_prtcl->header.ns_count = 0;
            return 1;
        }
    }
    if(dns_prtcl->header.ar_count == 0)
    {
        dns_prtcl->additional = NULL;
    }
    else
    {
        dns_prtcl->additional = calloc(dns_prtcl->header.ar_count, sizeof(dns_resr_t));
        if(dns_prtcl->additional == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(__parse_resource(data, len, &pos, dns_prtcl->header.ar_count, dns_prtcl->additional) != 0)
        {
            if(dns_prtcl->header.qd_count != 0)
            {
                free(dns_prtcl->question);
                dns_prtcl->header.qd_count = 0;
            }
            if(dns_prtcl->header.an_count != 0)
            {
                free(dns_prtcl->answer);
                dns_prtcl->header.an_count = 0;
            }
            if(dns_prtcl->header.ns_count != 0)
            {
                free(dns_prtcl->authority);
                dns_prtcl->header.ns_count = 0;
            }
            free(dns_prtcl->additional);
            dns_prtcl->header.ar_count = 0;
            return 1;
        }
    }
    return 0;
}

int dns_prtcl_free(dns_prtcl_t *dns_prtcl)
{
    if(dns_prtcl->header.qd_count != 0)
    {
        free(dns_prtcl->question);
        dns_prtcl->header.qd_count = 0;
    }
    if(dns_prtcl->header.an_count != 0)
    {
        free(dns_prtcl->answer);
        dns_prtcl->header.an_count = 0;
    }
    if(dns_prtcl->header.ns_count != 0)
    {
        free(dns_prtcl->authority);
        dns_prtcl->header.ns_count = 0;
    }
    if(dns_prtcl->header.ar_count != 0)
    {
        free(dns_prtcl->additional);
        dns_prtcl->header.ar_count = 0;
    }
    return 0;
}
