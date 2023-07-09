/* htm_sshConnection.c
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

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <signals.h>
#include <util.h>
#include <md5.h>
#include <tcpip.h>

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libssh/scp.h>
//#include "home/ubuntu/libssh/include/libssh/scp.h"
#include <libssh2.h>
#include "htm_sshDownload.h"

#define MAX_TRANSMISSION_TRIES  10      /* retransmit 9 times */

const char module_name[]="sshDownload";
const char module_version[]="1.0.1";

static const char *plugin_config_keywords[] = {
	"ssh_host"
};

void plugin_config(void){
	return;
}

void  plugin_init(void){
	plugin_register_hooks();
	return;
}

void plugin_unload(void){
	unhook(PPRIO_ANALYZE, module_name, "cmd_parse_for_ssh");
	return;
}

void plugin_register_hooks(void){
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "cmd_parse_for_ssh", (void *) cmd_parse_for_ssh);
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

int cmd_parse_for_ssh(Attack *attack){
	int i=0;
	char *string_for_proccessing;
	char ssh_str[] = "ssh";
	struct in_addr *addr = NULL;

	uint32_t size_payload = attack->a_conn.payload.size;

	/* no data - nothing todo */
	if((size_payload == 0) || (attack->a_conn.payload.data == NULL)){
		logmsg(LOG_DEBUG, 1, "SSH download - No data received, nothing to download.\n");
		return(0);
	}
	logmsg(LOG_DEBUG, 1, "SSH download - Parsing attack string (%d bytes) for ssh commands.\n", size_payload);
	
	string_for_proccessing = (char*) malloc(size_payload + 1);
	memcpy(string_for_proccessing, attack->a_conn.payload.data, size_payload + 1);
	string_for_proccessing[size_payload] = 0;
	
	for(i = 0; i < size_payload; i++){
		if((size_payload - i >= sizeof(ssh_str)) && (memcmp(string_for_proccessing + i, ssh_str, sizeof(ssh_str)) == 0)){
			logmsg(LOG_DEBUG, 1, "SSH download - SSH command found.\n");

			/* do ssh download */
			char r_addr_str[INET_ADDRSTRLEN];
			addr = (struct in_addr *) &(attack->a_conn.l_addr);
			inet_ntop(AF_INET, addr, r_addr_str, INET_ADDRSTRLEN);
			logmsg(LOG_NOTICE, 1, "SSH connection - %s.\n", r_addr_str);
			get_sshcmd(string_for_proccessing, size_payload, attack);
			return(1); //Command ssh found
		}
	}
	logmsg(LOG_DEBUG, 1, "SSH download - No ssh command found.\n");

	free(string_for_proccessing);

	return(0); //Command ssh not found
}

int get_sshcmd(char *attack_string, uint32_t string_size, Attack *attack){
	/*An ssh command looks like this: 
		ssh [options] [user@]host [command]
	*/
		
	char *token, *rest = attack_string, *user = NULL, *host = NULL, *command = NULL, *r_port = NULL;
	// format of remote_path = user@host:/path/to/file 
	// format of local_path = /path/to/file
	char *remote_path = NULL, *local_path = NULL, *conn_type = NULL;
	in_addr_t r_addr = 0;
	
	// skip the 'ssh' command token
	strtok(rest, " ");



	// extract user and host tokens
	token = strtok(rest, "@");
	if (token != NULL) {
    	user = token;
    	token = strtok(NULL, " ");
		if (token != NULL) {
			host = token;

			//get host IP address 
			struct hostent *he;
			struct in_addr **address_list;

			if((he = gethostbyname(host)) == NULL){
				logmsg(LOG_ERR, 1, "Error: could not resolve host %s\n", host);
    			return -1;
			}
			else{
				address_list = (struct in_addr **) he->h_addr_list;
				if(address_list[0] != NULL){
					r_addr = address_list[0]->s_addr;
				}
			}
		}	
  	}

	// extract command token
	token = strtok(NULL, "");
	if (token != NULL) {
		command = token;
		// extract remote and local paths, if present
        char *remote_delim = strstr(command, ":");
        char *local_delim = strrchr(command, '/');

        if (remote_delim != NULL) {
            remote_path = remote_delim + 1;
        }
        if (local_delim != NULL) {
            local_path = local_delim + 1;
        }
	}

	char *filename = NULL;

	if(command != NULL){
		// check if command is scp or sftp
  		if (strstr(command, "scp") != NULL ){
			conn_type = "scp";
			char *c = strstr(command, " ");
			if(c!=NULL){
				c++;
				filename = strrchr(c, '/');
				if(filename != NULL){
					filename++;
				}
				else{
					filename = c;
				}
			}
		}
		else if(strstr(command, "sftp") != NULL) {
			conn_type = "sftp";
			char *c = strstr(command, " ");
			if(c!=NULL){
				c++;
				filename = strrchr(c, '/');
				if(filename != NULL){
					filename++;
				}
				else{
					filename = c;
				}
			}
		}	
	}

// Check the validity of the user parameter
    if (user == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - User parameter is NULL.\n");
            return -1;
    }

    // Check the validity of the host parameter
    if (host == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - Host parameter is NULL.\n");
            return -1;
    }

    // Check the validity of the remote_path parameter
    if (remote_path == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - Remote path parameter is NULL.\n");
            return -1;
    }

    // Check the validity of the local_path parameter
    if (local_path == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - Local path parameter is NULL.\n");
            return -1;
    }

    // Check the validity of the filename parameter
    if (filename == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - Filename parameter is NULL.\n");
            return -1;
    }

    // Check the validity of the r_addr parameter
    if (r_addr < 0) {
            logmsg(LOG_ERR, 1, "SSH download error - Invalid r_addr parameter.\n");
            return -1;
	}

  	return get_ssh_resource(user, host, remote_path, local_path, attack, conn_type, filename, r_addr, atoi(r_port));
}

int get_ssh_resource(const char* user, const char* host, const char* remote_path, const char* local_path, 
	Attack* attack, const char* conn_type, const char* filename, const uint32_t r_addr, const uint16_t r_port){
	ssh_session ssh = ssh_new();

	if(ssh == NULL){
		logmsg(LOG_ERR, 1, "SSH download error - Session cannot be established. \n");
		return -1;
	}


	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);  // establece el host al que se va a conectar
    ssh_options_set(ssh, SSH_OPTIONS_USER, user);  // establece el usuario con el que se va a conectar
    
    int status = ssh_connect(ssh);  // realiza la conexión SSH
    if (status != SSH_OK) {
        logmsg(LOG_ERR, 1, "SSH download error - Connection error with server SSH.\n");
        ssh_free(ssh);
        return -1;
    }

	status = ssh_userauth_publickey_auto(ssh, NULL, NULL);  // autentica la conexión SSH utilizando las claves públicas del usuario
    if (status != SSH_AUTH_SUCCESS) {
        logmsg(LOG_ERR, 1, "SSH download error - Authentication error.\n");
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }

	if (conn_type != NULL && strcmp(conn_type, "SFTP") == 0) {
		get_ssh_resource_by_sftp(user, host, remote_path, local_path, attack, ssh, filename, r_addr, r_port);
	} else if (conn_type != NULL && strcmp(conn_type, "SCP") == 0) {
		get_ssh_resource_by_scp(user, host, remote_path, local_path, attack, ssh, filename, r_addr, r_port);
	} else {
		logmsg(LOG_ERR, 1, "Error: unknown connection type %s\n", conn_type);
		return -1;
	}

	return 1;
}

int get_ssh_resource_by_sftp(const char* user, const char* host, const char* remote_path, const char* local_path, Attack* attack, ssh_session ssh, const char *filename,const uint32_t r_addr, const uint16_t r_port){
	sftp_session sftp = sftp_new(ssh);
	if (sftp == NULL) {
        logmsg(LOG_ERR, 1, "SSH download error - SFTP session cannot be created.\n");
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }
    
    int status = sftp_init(sftp);  // inicializa la sesión SFTP
    if (status != SSH_OK) {
        logmsg(LOG_ERR, 1, "SSH download error - Error initializing SFTP session.\n");
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }
    
    sftp_file file = sftp_open(sftp, remote_path, O_RDONLY, 0);  // abre el archivo remoto en modo lectura
    if (file == NULL) {
        logmsg(LOG_ERR, 1, "SSH download error - Error opening remote file.\n");
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }

	FILE* fp = fopen(local_path, "wb");  // abre el archivo local en modo escritura binaria
    if (fp == NULL) {
        logmsg(LOG_ERR, 1, "SSH download error - Error openng local file.\n");
        sftp_close(file);
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }
    
    char buffer[1024];
	char *data = NULL;
    int nbytes = 0, data_size = 0, total_bytes_read = 0;
	do {
        nbytes = sftp_read(file, buffer, sizeof(buffer));
        if (nbytes > 0) {
			data_size += nbytes;
			data = realloc(data, data_size);
			memcpy(data + total_bytes_read, buffer, nbytes);
            if (fwrite(buffer, 1, nbytes, fp) != nbytes) {
                logmsg(LOG_ERR, 1, "SSH download error - Error writing local file.\n");
                fclose(fp);
                sftp_close(file);
                ssh_disconnect(ssh);
                ssh_free(ssh);
                return -1;
            }
        } else if (nbytes < 0) {
            logmsg(LOG_ERR, 1, "SSH download error - Error reading remote file.\n");
            fclose(fp);
            sftp_close(file);
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return -1;
        }
    } while (nbytes > 0);

	

    // close local file and remote file
    fclose(fp);
    sftp_close(file);

    // disconnect ssh session and free memory
    ssh_disconnect(ssh);
    ssh_free(ssh);
	/* add ssh connection to attack record */
		logmsg(LOG_DEBUG, 1, "SSH connection - Adding connection to attack record.\n");
		status = add_download("SSH", 6, r_addr, r_port, user, NULL, filename, remote_path, NULL, nbytes, attack);
		if(status != 0){
			logmsg(LOG_ERR, 1, "SSH download error - Error adding download to attack record.\n");
		}
		logmsg(LOG_NOTICE, 1, "SSH connection - %s attached to attack record.\n", filename);

    logmsg(LOG_NOTICE, 1, "SSH download - File succesfully download.\n");
    return 0;
}

	
int get_ssh_resource_by_scp(const char* user, const char* host, const char* remote_path, const char* local_path, Attack* attack, ssh_session ssh, const char *filename, const uint32_t r_addr, const uint16_t r_port) {
    ssh_scp scp = ssh_scp_new(ssh, SSH_SCP_READ, remote_path);
    if (scp == NULL || ssh_scp_init(scp) != SSH_OK) {
        logmsg(LOG_ERR, 1, "SSH download error - Failed to create SCP session.\n");
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }

    if (ssh_scp_pull_request(scp) == SSH_SCP_REQUEST_NEWFILE) {
        ssh_scp_accept_request(scp);
        ssh_scp_pull_request(scp);
        ssh_scp_deny_request(scp, "No more files allowed");
    }

    FILE* fp = fopen(local_path, "wb");
    if (fp == NULL) {
        logmsg(LOG_ERR, 1, "SSH download error - Failed to open local file.\n");
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return -1;
    }

    int size = 0, bytesread = 0;

    while (ssh_scp_pull_request(scp) == SSH_SCP_REQUEST_NEWFILE) {
        size = ssh_scp_request_get_size(scp);
        char* buffer = malloc(size);
        if (buffer == NULL) {
            logmsg(LOG_ERR, 1, "SSH download error - Failed to allocate memory.\n");
            fclose(fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return -1;
        }
	// Check if the remote file exists
	if (access(remote_path, F_OK) != 0) {
		logmsg(LOG_ERR, 1, "SSH download error - File does not exist: %s\n", remote_path);
		return -1;
	}

        bytesread = ssh_scp_read(scp, buffer, size);
        if (bytesread <= 0) {
		logmsg(LOG_ERR, 1, "SSH download error - Error reading remote file: %s\n", remote_path);
		return -1;
	}	
	if (bytesread == SSH_ERROR) {
            logmsg(LOG_ERR, 1, "SSH download error - Failed to read remote file.\n");
            fclose(fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return -1;
        }
        if (fwrite(buffer, 1, bytesread, fp) != bytesread) {
            logmsg(LOG_ERR, 1, "SSH download error - Failed to write local file.\n");
            free(buffer);
            fclose(fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return -1;
        }
        free(buffer);
    }

    fclose(fp);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    ssh_disconnect(ssh);
    ssh_free(ssh);

    logmsg(LOG_DEBUG, 1, "SSH connection - Adding connection to attack record.\n");
    int status = add_download("SSH", 6, r_addr, r_port, user, NULL, filename, remote_path, NULL, bytesread, attack);
    if (status != 0) {
        logmsg(LOG_ERR, 1, "SSH download error - Failed to add download to attack record.\n");
    }
    logmsg(LOG_NOTICE, 1, "SSH connection - %s attached to attack record.\n", filename);

    logmsg(LOG_NOTICE, 1, "SSH download - File successfully downloaded.\n");
    return 0;
}

