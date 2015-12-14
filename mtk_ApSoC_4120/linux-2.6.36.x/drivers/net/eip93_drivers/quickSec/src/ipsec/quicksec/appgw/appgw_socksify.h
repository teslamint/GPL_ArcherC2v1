/** 
 
    Application gateway that wraps TCP connections into SOCKSv4
    protocol and redirects them through a SOCKS server.

    <keywords SOCKS application gateway, ALG/SOCKS>

    File: appgw_socksify.h
 
    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved.
 
 */

#ifndef APPGW_SOCKSIFY_H
#define APPGW_SOCKSIFY_H

/* ************************ Types and definitions ***************************/

/** Identification string. */
#define SSH_APPGW_SOCKSIFY_IDENT "alg-socksify@ssh.com"


/* ********************** Initializing SOCKSIFY ALG *************************/

/** Initialize socksify ALG for the policy manager 'pm'. */
void ssh_appgw_socksify_init(SshPm pm);


/* ********************* Handling configuration data ************************/

/** A configuration data object. */
typedef struct SshAppgwSocksifyConfigRec *SshAppgwSocksifyConfig;

/** Create a configuration data object. */
SshAppgwSocksifyConfig ssh_appgw_socksify_config_create(void);

/** Destroy the configuration data object 'config'. */
void ssh_appgw_socksify_config_destroy(SshAppgwSocksifyConfig config);

/** Configure SOCKS server. */
Boolean ssh_appgw_socksify_config_server(SshAppgwSocksifyConfig config,
                                         const unsigned char *address,
                                         const unsigned char *port,
                                         const unsigned char *version,
                                         const unsigned char *user_name,
                                         size_t user_name_len,
                                         const unsigned char *password,
                                         size_t password_len);

/** Configure destination IP address and port to connect to. As a
    default, these are taken from the original session but these can be
    overridden to NAT connections to different locations. */
Boolean ssh_appgw_socksify_config_destination(SshAppgwSocksifyConfig config,
                                              const unsigned char *address,
                                              const unsigned char *port);

/** Marshal configuration data for transporting it to the application
    gateway. */
unsigned char *ssh_appgw_socksify_config_marshal(SshAppgwSocksifyConfig config,
                                                 size_t *data_len_return);

/** Unmarshal configuration data blob 'data', 'data_len' into a
    configuration data structure.  
    
    @return
    The function returns a new configuration data object, or NULL if 
    the unmarshall operation failed. 
    
    */
SshAppgwSocksifyConfig ssh_appgw_socksify_config_unmarshal(
                                                const unsigned char *data,
                                                size_t data_len);

#endif /* not APPGW_SOCKSIFY_H */
