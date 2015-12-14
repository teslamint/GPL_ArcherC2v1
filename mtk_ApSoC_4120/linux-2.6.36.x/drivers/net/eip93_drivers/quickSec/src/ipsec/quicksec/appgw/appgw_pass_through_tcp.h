/**
    Pass-through application gateway for TCP.

    <keywords pass-through TCP application gateway, TCP pass-through 
    application gateway> 
    
    File: appgw_pass_through_tcp.h
 
    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved. 
 
 */

#ifndef APPGW_PASS_THROUGH_TCP_H
#define APPGW_PASS_THROUGH_TCP_H

/* ************************ Types and definitions ***************************/

/** Identification string. */
#define SSH_APPGW_PASS_THROUGH_TCP_IDENT        "alg-pass-through-tcp@ssh.com"


/* ****************** Initializing pass-through TCP ALG *********************/

/** Initialize the pass-through TCP ALG for the policy manager 'pm'. */
void ssh_appgw_pass_through_tcp_init(SshPm pm);


/* ********************* Handling configuration data ************************/

/** A configuration data object. */
typedef struct SshAppgwPassThroughTcpConfigRec *SshAppgwPassThroughTcpConfig;

/** Create a configuration data object. */
SshAppgwPassThroughTcpConfig ssh_appgw_pass_through_tcp_config_create(void);

/** Destroy the configuration data object 'config'. */
void ssh_appgw_pass_through_tcp_config_destroy(
                                        SshAppgwPassThroughTcpConfig config);

/** Configure an IP address and/or a port to which the session is
    redirected.  
    
    @return
    The function returns TRUE if the redirection could be configured, 
    and FALSE otherwise. */
Boolean ssh_appgw_pass_through_tcp_config_redirect(
                                        SshAppgwPassThroughTcpConfig config,
                                        const unsigned char *address,
                                        const unsigned char *port);

/** Marshall configuration data for transporting it to the application
    gateway. */
unsigned char *ssh_appgw_pass_through_tcp_config_marshal(
                                        SshAppgwPassThroughTcpConfig config,
                                        size_t *data_len_return);

/** Unmarshall configuration data blob 'data', 'data_len' into a
    configuration data structure.  
    
    @return
    The function returns a new configuration data object, 
    or NULL if the unmarshall operation failed. 
    
    */
SshAppgwPassThroughTcpConfig ssh_appgw_pass_through_tcp_config_unmarshal(
                                                const unsigned char *data,
                                                size_t data_len);

#endif /* not APPGW_PASS_THROUGH_TCP_H */
