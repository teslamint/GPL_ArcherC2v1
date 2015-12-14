/*
  File: sshinet.c

  Description:
        IP related functions and definitions.

  Copyright:
        Copyright (c) 2002, 2003, 2004 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInet"

/* The address string of the SSH_IPADDR_ANY. */
const char *const ssh_ipaddr_any = "*** SSH_IPADDR_ANY ***";
const char *const ssh_ipaddr_any_ipv4 = "0.0.0.0";
const char *const ssh_ipaddr_any_ipv6 = "0::0";


