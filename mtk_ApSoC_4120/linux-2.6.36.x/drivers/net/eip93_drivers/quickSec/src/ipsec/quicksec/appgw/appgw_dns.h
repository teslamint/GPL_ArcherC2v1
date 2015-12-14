/** 
   
    DNS Application Level Gateway configuration. Creating and 
    marshalling.

    <keywords Domain Name System (DNS), DNS (Domain Name System), ALG/DNS>

    File: appgw_dns.h

    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved.
  
*/

#include "sshinet.h"

typedef struct
SshAppgwDNSConfigRec *SshAppgwDNSConfig, SshAppgwDNSConfigStruct;

/** Create configuration. */
SshAppgwDNSConfig ssh_appgw_dns_config_create(void);

/** Add static NAT mapping to configuration. */
void
ssh_appgw_dns_static_nat_map(SshAppgwDNSConfig configuration,
                             const SshIpAddr external,
                             const SshIpAddr internal);

/** Get data from the mapping. */
SshIpAddr
ssh_appgw_dns_static_nat_apply(SshAppgwDNSConfig configuration,
                               SshIpAddr address,
                               Boolean to_external);

/** Free configuration. */
void ssh_appgw_dns_destroy_config(SshAppgwDNSConfig configuration);


/** Marshall and unmarshall (linearize) configuration information for
    transport purposes. */
unsigned char *
ssh_appgw_dns_marshal_config(SshAppgwDNSConfig configuration,
                             size_t *marshalled_len);

SshAppgwDNSConfig
ssh_appgw_dns_unmarshal_config(const unsigned char *data,
                               size_t len);

/* eof */
