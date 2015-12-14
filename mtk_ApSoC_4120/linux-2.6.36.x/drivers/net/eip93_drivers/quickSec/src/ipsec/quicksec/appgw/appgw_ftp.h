/** 
 
    Application gateway for File Transfer Protocol (FTP).
    <keywords File Transfer Protocol (FTP), FTP (File Transfer Protocol), 
    ALG/FTP>
    
    File: appgw_ftp.h
 
    @copyright
    Copyright (c) 2002, 2003 SFNT Finland Oy, all rights reserved. 
 
 */

#ifndef APPGW_FTP_H
#define APPGW_FTP_H

/* ************************ Types and definitions ***************************/

/** Identification string. */
#define SSH_APPGW_FTP_IDENT "alg-ftp@ssh.com"

/* Flags for FTP ALG. */
/** The client can change IP. */
#define SSH_APPGW_FTP_CLIENT_CAN_CHANGE_IP      0x00000001
/** The server can change IP. */
#define SSH_APPGW_FTP_SERVER_CAN_CHANGE_IP      0x00000002


/* ************************* Initializing FTP ALG ***************************/

/** Initialize the FTP ALG for the policy manager 'pm'. */
void ssh_appgw_ftp_init(SshPm pm);


/* ********************* Handling configuration data ************************/

/** A configuration data object. */
typedef struct SshAppgwFtpConfigRec *SshAppgwFtpConfig;

/** Create a configuration data object. */
SshAppgwFtpConfig ssh_appgw_ftp_config_create(void);

/** Destroy the configuration data object 'config'. */
void ssh_appgw_ftp_config_destroy(SshAppgwFtpConfig config);

/** Disable the FTP command 'command' from the configuration data
    'config'.  The function returns TRUE if the command was disabled
    and FALSE if the command was unknown. */
Boolean ssh_appgw_ftp_config_disable_cmd(SshAppgwFtpConfig config,
                                         const char *command);

/** Possible content filters. */
typedef enum
{
  SSH_APPGW_FTP_CONTENT_FILTER_NONE, 	/** No content filters. */
  SSH_APPGW_FTP_CONTENT_FILTER_SIMPLE, 	/** Simple content filter. */
  SSH_APPGW_FTP_CONTENT_FILTER_MD5 	/** MD5-based content filter. */
} SshAppgwFtpContentFilterType;

/** Configure content filter for data streams. */
void ssh_appgw_ftp_config_content_filter(SshAppgwFtpConfig config,
                                         SshAppgwFtpContentFilterType filter);

/** Configure additional flags for the FTP ALG. */
void ssh_appgw_ftp_config_set_flags(SshAppgwFtpConfig config, SshUInt32 flags);

/** Marshall configuration data for transporting it to the application
    gateway. */
unsigned char *ssh_appgw_ftp_config_marshal(SshAppgwFtpConfig config,
                                            size_t *data_len_return);

/** Unmarshall configuration data blob 'data', 'data_len' into a
    configuration data structure.  
    
    @return
    The function returns a new configuration data object, 
    or NULL if the unmarshall operation failed. */
SshAppgwFtpConfig ssh_appgw_ftp_config_unmarshal(const unsigned char *data,
                                                 size_t data_len);

#endif /* not APPGW_FTP_H */
