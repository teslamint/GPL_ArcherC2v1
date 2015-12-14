/**
 
    Antivirus application gateway for SMTP.

    <keywords antivirus (AV), AV (antivirus), virus prevention, ALG/antivirus>
   
    File: appgw_av.h
   
    @copyright
    Copyright (c) 2005 - 2007 SFNT Finland Oy, all rights reserved.
 
 */

#ifdef SSHDIST_AV
#ifdef WITH_AV_ALG

#ifndef APPGW_AV_H
#define APPGW_AV_H

/* ************************ Types and definitions ***************************/

/** Identification string. */
#define SSH_APPGW_AV_IDENT  "alg-av@ssh.com"

/* ****************** Initializing the ALG *********************************/

/** Initialize the AV ALG for the policy manager 'pm'. */
void ssh_appgw_av_init(SshPm pm);


/* ********************* Handling configuration data ************************/

/* Parameter offsets. */
#define SSH_APPGW_AV_OFFS_REDIRECT_PORT    0 /** Port to redirect connection.*/
#define SSH_APPGW_AV_OFFS_MAX_CONNECTIONS  1 /** Max of open connections. */
#define SSH_APPGW_AV_OFFS_MAX_CONTENT_SIZE 2 /** Max mail content size. */
#define SSH_APPGW_AV_OFFS_TIMEOUT          3 /** Transaction timeout (sec). */
#define SSH_APPGW_AV_OFFS_ENGINES          4 /** Number of av-engines to use.*/
#define SSH_APPGW_AV_NUM_INT_PARAMS        5 /** Number of integer parameters*/

#define SSH_APPGW_AV_OFFS_REDIRECT_IP      5 /** IP to redirect connection. */
#define SSH_APPGW_AV_OFFS_WORKING_DIR      6 /** Directory for temp files. */
#define SSH_APPGW_AV_OFFS_ENGINE_ADDR      7 /** Engine UNIX or IP socket. */

#define SSH_APPGW_AV_OFFS_OK_ACTION        8 /** OK action (for testing). */
#define SSH_APPGW_AV_OFFS_VIRUS_ACTION     9 /** Virus found action. */
#define SSH_APPGW_AV_OFFS_WARNING_ACTION   10/** Virus warning action. */
#define SSH_APPGW_AV_OFFS_SUSPECT_ACTION   11/** Virus suspect action. */
#define SSH_APPGW_AV_OFFS_PROTECTED_ACTION 12/** Protected file action. */
#define SSH_APPGW_AV_OFFS_CORRUPT_ACTION   13/** Corrupt file action. */
#define SSH_APPGW_AV_OFFS_AV_ERROR_ACTION  14/** AV-check error action. */
#define SSH_APPGW_AV_OFFS_PARTIAL_ACTION   15/** MIME partial action. */
#define SSH_APPGW_AV_NUM_STRING_PARAMS     11/** Number of string parameters.*/

#define SSH_APPGW_AV_NUM_PARAMS \
  (SSH_APPGW_AV_NUM_INT_PARAMS + SSH_APPGW_AV_NUM_STRING_PARAMS)

/** A configuration data object. */
typedef struct SshAppgwAvConfigRec *SshAppgwAvConfig;

/** Create a configuration data object. */
SshAppgwAvConfig ssh_appgw_av_config_create(void);

/** Destroy the configuration data object 'config'. */
void ssh_appgw_av_config_destroy(SshAppgwAvConfig config);

/** Configure parameters. 

    @return 
    Returns an index to an invalid parameter on error. */
int ssh_appgw_av_config(SshAppgwAvConfig config,
                        const unsigned char *(param_tbl[]));

/** Configure an IP address and/or a port to which the session is
    redirected.  
    
    @return
    The function returns TRUE if the redirection could be
    configured, and FALSE otherwise. */
Boolean ssh_appgw_av_config_redirect(SshAppgwAvConfig config,
                                     const unsigned char *address,
                                     const unsigned char *port);

/** Marshall configuration data for transporting it to the application
    gateway. */
unsigned char *ssh_appgw_av_config_marshal(SshAppgwAvConfig config,
                                           size_t *data_len_return);

/** Unmarshall configuration data blob 'data', 'data_len' into a
    configuration data structure.  
    
    @return
    The function returns a new configuration data object, or NULL if 
    the unmarshall operation failed. */
SshAppgwAvConfig ssh_appgw_av_config_unmarshal(const unsigned char *data,
                                               size_t data_len);

#endif /* not APPGW_AV_H */

#endif /* WITH_AV_ALG */
#endif /* SSHDIST_AV */
