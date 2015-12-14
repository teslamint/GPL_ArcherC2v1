/*
  File: appgw_sip_config.c

  Description:
        Configuration data from SIP application level gateway.

  Copyright:
        Copyright (c) 2003 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "appgw_api.h"
#include "appgw_sip.h"
#include "sshencode.h"
#include "sshinet.h"

#ifdef SSHDIST_IPSEC_FIREWALL

typedef struct SshAppgwSipAddressMappingRec
  *SshAppgwSipAddressMapping, SshAppgwSipAddressMappingStruct;

struct SshAppgwSipConfigRec
{
  SshAppgwSipAddressMapping rules;

  /* Port range where SIP opens holes in the appgw. */
  SshUInt16 baseport;
  SshUInt16 nports;

  /* Internal networks, we do not know it from other sources,
     unfortunately.  Interface tagging would be nice... thank you.  */
  SshIpAddr internal_networks;
  size_t num_internal_networks;
};

struct SshAppgwSipAddressMappingRec
{
  SshAppgwSipAddressMapping next;
  SshIpAddrStruct internal;
  SshIpAddrStruct external;

  SshUInt16 internal_port;
  SshUInt16 external_port;
};

SshAppgwSipConfig
ssh_appgw_sip_config_create(void)
{
  SshAppgwSipConfig c;

  c = ssh_calloc(1, sizeof(*c));
  return c;
}

void
ssh_appgw_sip_add_internal_network(SshAppgwSipConfig configuration,
				   const SshIpAddr intnet)
{
  SshIpAddr tmp;

  tmp = ssh_realloc(configuration->internal_networks,
		    sizeof(SshIpAddrStruct) *
		    (configuration->num_internal_networks + 0),
		    sizeof(SshIpAddrStruct) *
		    (configuration->num_internal_networks + 1));
  if (tmp)
    {
      tmp[configuration->num_internal_networks] = *intnet;
      configuration->num_internal_networks += 1;
      configuration->internal_networks = tmp;
    }
}

SshIpAddr
ssh_appgw_sip_get_internal_networks(SshAppgwSipConfig configuration,
				    size_t *num_internal_networks)
{
  *num_internal_networks = configuration->num_internal_networks;
  return configuration->internal_networks;
}

Boolean
ssh_appgw_sip_get_conduit(SshAppgwSipConfig configuration,
			  SshUInt32 nth,
			  SshIpAddr external, SshUInt16 *external_port,
			  SshIpAddr internal, SshUInt16 *internal_port)
{
  int i;
  SshAppgwSipAddressMapping entry;

  for (entry = configuration->rules, i = 0;
       entry && i < nth;
       entry = entry->next, i++);

  if (entry)
    {
      memcpy(external, &entry->external, sizeof(*external));
      *external_port = entry->external_port;
      memcpy(internal, &entry->internal, sizeof(*internal));
      *internal_port = entry->internal_port;
      return TRUE;
    }
  return FALSE;
}

void
ssh_appgw_sip_add_conduit(SshAppgwSipConfig configuration,
			  const SshIpAddr external,
			  SshUInt16 external_port,
			  const SshIpAddr internal,
			  SshUInt16 internal_port)
{
  SshAppgwSipAddressMapping m;

  if ((m = ssh_calloc(1, sizeof(*m))) != NULL)
    {
      memcpy(&m->internal, internal, sizeof(*internal));
      m->internal_port = internal_port;
      memcpy(&m->external, external, sizeof(*external));
      m->external_port = external_port;

      if (configuration->rules != NULL)
        m->next = configuration->rules;
      else
        m->next = NULL;
    }
  configuration->rules = m;
}

SshIpAddr
ssh_appgw_sip_conduit_apply(SshAppgwSipConfig configuration,
			    SshIpAddr address,
			    Boolean to_external)
{
  SshAppgwSipAddressMapping m;

  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          if (to_external)
            {
              if (SSH_IP_EQUAL(&m->internal, address))
                return ssh_memdup(&m->external, sizeof(m->external));
            }
          else
            {
              if (SSH_IP_EQUAL(&m->external, address))
                return ssh_memdup(&m->internal, sizeof(m->internal));
            }
          m = m->next;
        }
    }
  return NULL;
}

void
ssh_appgw_sip_destroy_config(SshAppgwSipConfig configuration)
{
  SshAppgwSipAddressMapping m, n;

  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          n = m->next;
          ssh_free(m);
          m = n;
        }

      if (configuration->num_internal_networks)
	ssh_free(configuration->internal_networks);
      ssh_free(configuration);
    }
}


#define CFGVERSION "APPGW-Sip-CONFIG-PKT-10"

unsigned char *ssh_appgw_sip_marshal_config(SshAppgwSipConfig configuration,
                                            size_t *marshalled_len)
{
  SshBufferStruct b;
  SshAppgwSipAddressMapping m;
  Boolean errors = FALSE;
  SshUInt32 nrules;
  unsigned char *marshalled_data = NULL;
  int i;

  *marshalled_len = 0;

  ssh_buffer_init(&b);

  if (configuration)
    {
      nrules = 0;
      m = configuration->rules;

      while (m)
        {
          nrules += 1;
          m = m->next;
        }
    }
  else
    return NULL;

  ssh_encode_buffer(&b,
                    SSH_FORMAT_UINT32_STR, CFGVERSION, strlen(CFGVERSION),
                    SSH_FORMAT_UINT32, nrules,
                    SSH_FORMAT_UINT32, configuration->num_internal_networks,
                    SSH_FORMAT_END);

  m = configuration->rules;
  while (m)
    {
      unsigned char external[SSH_IP_ADDR_STRING_SIZE];
      unsigned char internal[SSH_IP_ADDR_STRING_SIZE];

      ssh_ipaddr_print(&m->external, external, sizeof(external));
      ssh_ipaddr_print(&m->internal, internal, sizeof(internal));
      if (ssh_encode_buffer(&b,
			    SSH_FORMAT_UINT32_STR,
			    external, ssh_ustrlen(external),
			    SSH_FORMAT_UINT32, m->external_port,
			    SSH_FORMAT_UINT32_STR,
			    internal, ssh_ustrlen(internal),
			    SSH_FORMAT_UINT32, m->internal_port,
			    SSH_FORMAT_END) == 0)
	{
	  errors = TRUE;
	  break;
	}
      m = m->next;
    }

  for (i = 0; i < configuration->num_internal_networks; i++)
    {
      unsigned char net[SSH_IP_ADDR_STRING_SIZE];

      ssh_ipaddr_print_with_mask(&configuration->internal_networks[i],
				 net, sizeof(net));
      ssh_encode_buffer(&b,
			SSH_FORMAT_UINT32_STR, net, ssh_ustrlen(net),
			SSH_FORMAT_END);

    }

  if (!errors)
    {
      *marshalled_len = ssh_buffer_len(&b);
      marshalled_data = ssh_memdup(ssh_buffer_ptr(&b), ssh_buffer_len(&b));
    }
  ssh_buffer_uninit(&b);
  return marshalled_data;
}

SshAppgwSipConfig
ssh_appgw_sip_unmarshal_config(const unsigned char *data,
                               size_t len)
{
  size_t offset = 0, consumed;
  SshUInt32 n = 0, nrules, nnets;
  SshAppgwSipConfig c;
  unsigned char *id;
  Boolean errors = FALSE;
  SshUInt32 external_port, internal_port;

  offset += ssh_decode_array(data, len,
                             SSH_FORMAT_UINT32_STR_NOCOPY, &id, NULL,
                             SSH_FORMAT_UINT32, &nrules,
                             SSH_FORMAT_UINT32, &nnets,
                             SSH_FORMAT_END);

  c = ssh_appgw_sip_config_create();

  while (offset < len && n < nrules)
    {
      unsigned char *external, *internal;
      SshIpAddrStruct extip, intip;

      if ((consumed =
           ssh_decode_array(data + offset, len - offset,
                            SSH_FORMAT_UINT32_STR_NOCOPY, &external, NULL,
			    SSH_FORMAT_UINT32, &external_port,
                            SSH_FORMAT_UINT32_STR_NOCOPY, &internal, NULL,
			    SSH_FORMAT_UINT32, &internal_port,
                            SSH_FORMAT_END)) == 0)
        {
          errors = TRUE;
          break;
        }
      ssh_ipaddr_parse(&extip, external);
      ssh_ipaddr_parse(&intip, internal);
      ssh_appgw_sip_add_conduit(c,
				&extip, (SshUInt16)external_port,
				&intip, (SshUInt16)internal_port);
      offset += consumed;
      n += 1;
    }

  n = 0;
  while (offset < len && n < nnets)
    {
      unsigned char *netstr;
      SshIpAddrStruct intnet;

      if ((consumed =
	   ssh_decode_array(data + offset, len - offset,
			    SSH_FORMAT_UINT32_STR_NOCOPY, &netstr, NULL,
			    SSH_FORMAT_END)) == 0)
	{
	  errors = TRUE;
	  break;
	}
      ssh_ipaddr_parse_with_mask(&intnet, netstr, NULL);
      ssh_appgw_sip_add_internal_network(c, &intnet);
      n += 1;
    }

  if (errors)
    {
      ssh_appgw_sip_destroy_config(c);
      return NULL;
    }
  else
    return c;
}
#endif /* SSHDIST_IPSEC_FIREWALL */
/* eof */
