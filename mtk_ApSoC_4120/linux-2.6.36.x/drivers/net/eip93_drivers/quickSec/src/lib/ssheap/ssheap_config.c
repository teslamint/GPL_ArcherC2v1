/*
  ssheap_config.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
  All Rights Reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"




#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_config.h"

#include "ssheap_md5.h"
#include "ssheap_sim.h"
#include "ssheap_tls.h"
#include "ssheap_aka.h"









#define SSH_DEBUG_MODULE "SshEapConfig"

/*
  This file contains the configuration related to all protocols
  supported by the SSH EAP library.

  New implementations can be configured here.
*/

const
SshEapProtocolImplStruct ssh_eap_protocols[] = {
  {
    SSH_EAP_TYPE_MD5_CHALLENGE,
    0,
    ssh_eap_md5_create,
    ssh_eap_md5_destroy,
    ssh_eap_md5_signal,
    NULL_FNPTR
  } 
  , {
    SSH_EAP_TYPE_TLS,
    0,
    ssh_eap_tls_create,
    ssh_eap_tls_destroy,
    ssh_eap_tls_signal,
    ssh_eap_tls_key
  }
  , {
    SSH_EAP_TYPE_SIM,
    SSH_EAP_PASS_THROUGH_ONLY,
    ssh_eap_sim_create,
    ssh_eap_sim_destroy,
    ssh_eap_sim_signal,
    ssh_eap_sim_key
  }
  , {
    SSH_EAP_TYPE_AKA,
    SSH_EAP_PASS_THROUGH_ONLY,
    ssh_eap_aka_create,
    ssh_eap_aka_destroy,
    ssh_eap_aka_signal,
    ssh_eap_aka_key
  }
#ifdef SSHDIST_EAP_AKA_DASH  
  , {
    SSH_EAP_TYPE_AKA_DASH,
    SSH_EAP_PASS_THROUGH_ONLY,
    ssh_eap_aka_create,
    ssh_eap_aka_destroy,
    ssh_eap_aka_signal,
    ssh_eap_aka_key
  }
#endif /* SSHDIST_EAP_AKA_DASH */




























};

SshEapProtocolImpl
ssh_eap_config_get_impl_by_type(SshUInt8 type)
{
  int i;

  for (i = 0; i < ssh_eap_config_num_of_impl(); i++)
    {
      if (ssh_eap_protocols[i].id == type)
        {
          return (SshEapProtocolImpl)&ssh_eap_protocols[i];
        }
    }
  return NULL;
}

SshEapProtocolImpl
ssh_eap_config_get_impl_by_idx(int idx)
{
  if (idx >= ssh_eap_config_num_of_impl())
    {
      return NULL;
    }

  return (SshEapProtocolImpl)&ssh_eap_protocols[idx];
}

int
ssh_eap_config_num_of_impl(void)
{
  return sizeof(ssh_eap_protocols) / sizeof(SshEapProtocolImplStruct);
}
