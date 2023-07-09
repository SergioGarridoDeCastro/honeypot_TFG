/* htm_sshDownload.h
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

#ifndef __HT_MODULE_SSHDOWNLOAD_H
#define __HT_MODULE_SSHDOWNLOAD_H 1

#if HAVE_CONFIG_H
# include <config.h>
#include <stdint.h>
#endif

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
void plugin_register_confopts(void);
int cmd_parse_for_ssh(Attack *attack);
int get_sshcmd(char *attack_string, uint32_t string_size, Attack *attack);
int get_ssh_resource(const char* user, const char* host, const char* remote_path, const char* local_path, Attack* attack, const char* conn_type, const char* filename, const uint32_t r_addr, const uint16_t r_port);
int get_ssh_resource_by_sftp(const char* user, const char* host, const char* remote_path, const char* local_path, Attack* attack, ssh_session ssh, const char* filename, const uint32_t r_addr, const uint16_t r_port);
int get_ssh_resource_by_scp(const char* user, const char* host, const char* remote_path, const char* local_path, Attack* attack, ssh_session ssh, const char* filename, const uint32_t r_addr, const uint16_t r_port);

#endif
