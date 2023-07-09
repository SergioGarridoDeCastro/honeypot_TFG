/* htm_dnsDetection.h
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HT_MODULE_DNSDETECTION_H
#define __HT_MODULE_SSHDOWNLOAD_H 1

#if HAVE_CONFIG_H
# include <config.h>
#include <stdint.h>
#endif

/* DNS header structure */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t num_q;
    uint16_t num_ans;
    uint16_t num_auth;
    uint16_t num_add;
};

/* DNS query structure 
struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
};*/

/* DNS answer structure */
struct dns_answer {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

/* DNS record structure */
struct dns_record {
    char *name;
    struct dns_answer *ans;
};

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
void plugin_register_confopts(void);
int is_dns_query(char* packet);
int cmd_parse_for_dns_query(Attack *attack, struct dns_query *query);
#endif
