/* htm_dnsConnection.c
 * Copyright (C) 2006-2015 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * Description:
 *   This honeytrap module parses an attack string for ssh download commands.
 *   It performs the downloads with an own ssh implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <signals.h>
#include <util.h>
#include <md5.h>
#include <tcpip.h>

#include <libssh/libssh.h>
#include "htm_dnsDetection.h"

#define MAX_TRANSMISSION_TRIES  10      /* retransmit 9 times */

const char module_name[]="dnsDetection";
const char module_version[]="1.0.1";

static const char *plugin_config_keywords[] = {
	"dns_host"
};

void plugin_config(void){
	return;
}

void  plugin_init(void){
	plugin_register_hooks();
	return;
}

void plugin_unload(void){
	unhook(PPRIO_ANALYZE, module_name, "cmd_parse_for_dns_query");
	return;
}

void plugin_register_hooks(void){
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "cmd_parse_for_dns_query", (void *) cmd_parse_for_dns_query);
	return;
}

void plugin_register_confopts(void) {
	int i;
	char full_name[264], *confopt;
	
	/* assemble plugin config key */
	memset(full_name, 0, 264);
	strncpy(full_name, "plugin-", 7);
	strncpy(&full_name[7], module_name, 256 < strlen(module_name) ? 256 : strlen(module_name));
	if (add_keyword(&config_keywords_tree, full_name, NULL, 0) == NULL) {
		fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
		exit(EXIT_FAILURE);
	}	

	/* build tree of allowed configuration keywords */
	for (i=0; i<sizeof(config_keywords_tree)/sizeof(char *); i++) {
		/* assemble full config option path */
		if ((confopt = malloc(strlen(full_name)+strlen(plugin_config_keywords[i])+2)) == NULL) {
			fprintf(stderr, "  Error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		memset(confopt, 0, strlen(full_name)+strlen(plugin_config_keywords[i])+2);
		strcat(confopt, full_name);
		strcat(confopt, ".");
		strcat(confopt, plugin_config_keywords[i]);

		/* add config option to tree */
		if (add_keyword(&config_keywords_tree, confopt, NULL, 0) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			exit(EXIT_FAILURE);
		}	
		free(confopt);
	}
	return;
}

int is_dns_query(char* packet){
	//Check if the packet has the minimum size to be a valid DNS packet
	if(packet[2] < 0x01 || packet[2] > 0xff || packet[3] < 0x01 || packet[3] > 0xff){
		return -1;
	}

	//Check the value of the query/response bit
	if((packet[2] & 0x80) == 0x00){
		return 1; //It's a query
	}
	else{
		return 0; //It's a response
	}
}



int cmd_parse_for_dns_query(Attack *attack, struct dns_query *query){
    /*
    Format of DNS query: 
    <dd-mmm-YYYY HH:MM:SS.uuu> <client IP>#<port> query: <query_Domain name> <class name> <type name> <- or +>[SETDC] 
    <(name server ip)>
    */

    char *date = NULL, *hour = NULL, *client_ip = NULL, *port = NULL, *query_str = NULL, *domain_name = NULL,
         *class_name = NULL, *type_name = NULL, *status = NULL, *name_server_ip = NULL;

    size_t payload_size = attack->a_conn.payload.size;

   /* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "DNS connection - No data received.\n");
		return(0);
	}

    logmsg(LOG_DEBUG,1, "DNS connection - Parsing attacking string (%d bytes) for DNS querys", attack->a_conn.payload.size);

   char* string_for_processing = (char *) malloc(attack->a_conn.payload.size + 1);
	memcpy(string_for_processing, attack->a_conn.payload.data, attack->a_conn.payload.size);
	string_for_processing[attack->a_conn.payload.size] = 0;

    /*for(int i = 0; i < attack.a_conn.payload.size; i++){
        parse_string = attack_string +1; 
        *token = strtok(string_for_processing, " ");
        if(token[i])
    }*/

	// extract user and host tokens
  	char* token = strtok(string_for_processing, " ");
  
  	if (token != NULL) {
    	date = token;
    	token = strtok(NULL, " ");
    	if (token != NULL) {
      		hour = token;
      		// extract command token
      		token = strtok(NULL, "");
      		if (token != NULL) {
        		client_ip = token;
				port = strtok(NULL, "#");
      		}
    	}
  	}

	token = strtok(NULL, " ");
	if( token != NULL){
		query_str = token;
		logmsg(LOG_DEBUG, 1, "DNS connection - Query string: %s\n", query_str);
	}
	
	token = strtok(NULL, " ");
	if( token != NULL){
		domain_name = token;
	}

	token = strtok(NULL, " ");
	if( token != NULL){
		class_name = token;
	}

	token = strtok(NULL, " ");
	if( token != NULL){
		type_name = token;
	}

	token = strtok(NULL, " ");
	if( token != NULL){
		status = token;
	}

	token = strtok(NULL, " ");
	if( token != NULL){
		name_server_ip = token; 
	}

	free(string_for_processing);

  	/* add dns connection to attack record */
	size_t total_bytes = payload_size;
	if (total_bytes != 0) {
		logmsg(LOG_DEBUG, 1, "DNS connection - Adding connection to attack record.\n");
		add_query(date, hour, client_ip, (uint16_t) atoi(port), domain_name, class_name, type_name, status, name_server_ip, attack);

		logmsg(LOG_NOTICE, 1, "DNS connection - %s attached to attack record. Client IP:\n", client_ip);
	} else {
		logmsg(LOG_NOISY, 1, "DNS connection - No data received.\n");
	}

  	return 0;
}
