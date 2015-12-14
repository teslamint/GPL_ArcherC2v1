/**
 * quicksecpm_xmlconf.h
 *
 * @copyright
 *       Copyright (c) 2002-2006 SFNT Finland Oy -
 *       all rights reserved.
 *
 * XML configuration for QuickSec policy manager.
 *
 */

#ifndef SSHIPSECPM_XMLCONF_H
#define SSHIPSECPM_XMLCONF_H

#include "ipsec_params.h"

#include "quicksec_pm.h"

/*************************** Types and definitions ***************************/

/** Static configuration parameters for the policy manager.  These are
   specified from the command line. */
struct SshIpmParamsRec
{
  /** The name of the policy manager executable. */
  const unsigned char *program;
  unsigned char hostname[256];               /** Hostname. */
  void *machine_context;                     /** -e */
  const unsigned char *config_file;          /** -f */
  unsigned char *http_proxy_url;             /** -H */
  unsigned char *socks_url;                  /** -S */
  const unsigned char *kernel_debug_level;   /** -K */
  unsigned char *debug_level;                /** -D */
  Boolean print_interface_info;              /** -i */
  Boolean pass_unknown_ipsec;                /** -u */
  Boolean no_dns_pass_rule;                
  const unsigned char *appgw_addr;           /** -B */
  unsigned char *ike_addr;                   /** -b */
  SshUInt16 num_ike_ports;
  SshUInt16 local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];       /** --ike-ports */
  SshUInt16 local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];  /** --ike-ports */
  SshUInt16 remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];      /** --ike-ports */
  SshUInt16 remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS]; /** --ike-ports */
  unsigned char *bootstrap_traffic_selector; /** -a */
};

typedef struct SshIpmParamsRec SshIpmParamsStruct;
typedef struct SshIpmParamsRec *SshIpmParams;

/** Context data for policy manager. */
typedef struct SshIpmContextRec *SshIpmContext;

/******************* Public functions for XML configuration ******************/

/** Create a policy manager context for the policy manager object `pm'.
   The function returns a context or NULL if the system run out of
   memory.  The object, pointed by `params' must remain valid as long
   as the returned PM context is valid. */
SshIpmContext ssh_ipm_context_create(SshPm pm, SshIpmParams params);

/** Clear all policy manager objects from the context `ctx'.  The
   function is called when the policy manager is shutting down to
   remove all external references to the policy manager object.  The
   function returns TRUE if the context was shut down and FALSE
   otherwise.  If the function returns FALSE, the caller should call
   this function again after a short timeout.  After this call, the
   policy manager is destroyed. */
Boolean ssh_ipm_context_shutdown(SshIpmContext ctx);

/** Destroy the policy manager context `ctx'. */
void ssh_ipm_context_destroy(SshIpmContext ctx);

/** Configure (or reconfigure) the policy manager `ctx' from the
   current XML configuration stream.  The function either configures
   the policy manager or remains in the current configuration if the
   reconfiguration of the policy manager failed.  The function calls
   the status callback `status_cb' to notify the success of the
   operation. */
SshOperationHandle
ssh_ipm_configure(SshIpmContext ctx, SshPmStatusCB status_cb,
		  void *status_cb_context);

/** Get the <engine-flows refresh timeout from the policy manager 'ctx'.
   The function returns the refresh timeout (in seconds) or 0 if no
   automatic policy refreshing has been configured. */
SshUInt32 ssh_ipm_get_refresh_flows_timeout(SshIpmContext ctx);

/** Get the refresh timeout value from the policy manager `ctx'.  The
   function returns the refresh timeout (in seconds) or 0 if no
   automatic policy refreshing has been configured. */
SshUInt32 ssh_ipm_get_refresh_timeout(SshIpmContext ctx);

#endif /* not SSHIPSECPM_XMLCONF_H */
