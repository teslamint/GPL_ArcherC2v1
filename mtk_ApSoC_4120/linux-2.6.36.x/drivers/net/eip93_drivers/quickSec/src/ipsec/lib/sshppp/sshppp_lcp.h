/*
  Author: Lauri Tarkkala <ltarkkal@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All Rights Reserved.
*/

#ifndef SSH_PPP_LCP_H

#define SSH_PPP_LCP_H 1

typedef struct SshLcpLocalRec 
{
  SshPppFlush mux_instance;
  
  SshLcpConfigStruct config_input;
  SshLcpConfigStruct config_output;
  
  SshPppProtocol protocol;
} *SshLcpLocal, SshLcpLocalStruct;

SshPppEvents
ssh_ppp_lcp_get_eventq(SshLcpLocal lcp);

void
ssh_ppp_lcp_disable(SshLcpLocal lcp);

void
ssh_ppp_lcp_destroy(SshLcpLocal lcp);

void*
ssh_ppp_lcp_create(SshPppState gdata, SshPppFlush mux);

#endif /* SSH_PPP_LCP_H */

