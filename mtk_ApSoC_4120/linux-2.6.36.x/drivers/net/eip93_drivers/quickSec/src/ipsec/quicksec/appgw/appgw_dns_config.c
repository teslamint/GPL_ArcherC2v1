/*
  File: appgw_dns_config.c

  Description:
        Configuration data from DNS application level gateway.
        As of 6/2002 this includes static NAT mappings.

  Copyright:
        Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "appgw_dns.h"
#include "sshencode.h"
#include "sshinet.h"

#ifdef SSHDIST_IPSEC_FIREWALL

typedef struct SshAppgwDNSAddressMappingRec
  *SshAppgwDNSAddressMapping, SshAppgwDNSAddressMappingStruct;

struct SshAppgwDNSConfigRec
{
  SshAppgwDNSAddressMapping rules;
};

struct SshAppgwDNSAddressMappingRec
{
  SshAppgwDNSAddressMapping next;
  SshIpAddrStruct internal;
  SshIpAddrStruct external;
};

SshAppgwDNSConfig
ssh_appgw_dns_config_create(void)
{
  SshAppgwDNSConfig c;

  c = ssh_calloc(1, sizeof(*c));
  return c;
}

void
ssh_appgw_dns_static_nat_map(SshAppgwDNSConfig configuration,
                             const SshIpAddr external,
                             const SshIpAddr internal)
{
  SshAppgwDNSAddressMapping m;

  if ((m = ssh_calloc(1, sizeof(*m))) != NULL)
    {
      memcpy(&m->internal, internal, sizeof(*internal));
      memcpy(&m->external, external, sizeof(*external));

      if (configuration->rules != NULL)
        m->next = configuration->rules;
      else
        m->next = NULL;
    }
  configuration->rules = m;
}

SshIpAddr
ssh_appgw_dns_static_nat_apply(SshAppgwDNSConfig configuration,
                               SshIpAddr address,
                               Boolean to_external)
{
  SshAppgwDNSAddressMapping m;

  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          if (to_external)
            {
              if (SSH_IP_EQUAL(&m->internal, address))
                return &m->external;
            }
          else
            {
              if (SSH_IP_EQUAL(&m->external, address))
                return &m->internal;
            }
          m = m->next;
        }
    }
  return NULL;
}

void
ssh_appgw_dns_destroy_config(SshAppgwDNSConfig configuration)
{
  SshAppgwDNSAddressMapping m, n;

  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          n = m->next;
          ssh_free(m);
          m = n;
        }
      ssh_free(configuration);
    }
}

#define CFGVERSION "APPGW-DNS-CONFIG-PKT-10"

unsigned char *ssh_appgw_dns_marshal_config(SshAppgwDNSConfig configuration,
                                            size_t *marshalled_len)
{
  SshBufferStruct b;
  SshAppgwDNSAddressMapping m;
  Boolean errors = FALSE;
  SshUInt32 nentries = 0;
  unsigned char *marshalled_data = NULL;

  *marshalled_len = 0;

  ssh_buffer_init(&b);
  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          nentries += 1;
          m = m->next;
        }
    }
  ssh_encode_buffer(&b,
                    SSH_FORMAT_UINT32_STR, CFGVERSION, strlen(CFGVERSION),
                    SSH_FORMAT_UINT32, nentries,
                    SSH_FORMAT_END);

  if (configuration)
    {
      m = configuration->rules;
      while (m)
        {
          unsigned char external[SSH_IP_ADDR_STRING_SIZE];
	  unsigned char internal[SSH_IP_ADDR_STRING_SIZE];

          ssh_ipaddr_print(&m->internal, internal, sizeof(external));
          ssh_ipaddr_print(&m->external, external, sizeof(external));
          if (ssh_encode_buffer(&b,
                                SSH_FORMAT_UINT32_STR,
                                  external, ssh_ustrlen(external),
                                SSH_FORMAT_UINT32_STR,
                                  internal, ssh_ustrlen(internal),
                                SSH_FORMAT_END) == 0)
            {
              errors = TRUE;
              break;
            }
          m = m->next;
        }
    }
  if (!errors)
    {
      *marshalled_len = ssh_buffer_len(&b);
      marshalled_data = ssh_memdup(ssh_buffer_ptr(&b), ssh_buffer_len(&b));
    }
  ssh_buffer_uninit(&b);
  return marshalled_data;
}

SshAppgwDNSConfig
ssh_appgw_dns_unmarshal_config(const unsigned char *data,
                               size_t len)
{
  size_t offset = 0, consumed;
  SshUInt32 n = 0, nentries;
  SshAppgwDNSConfig c;
  unsigned char *id;
  Boolean errors = FALSE;

  offset += ssh_decode_array(data, len,
                             SSH_FORMAT_UINT32_STR_NOCOPY, &id, NULL,
                             SSH_FORMAT_UINT32, &nentries,
                             SSH_FORMAT_END);

  if (offset > 0)
    c = ssh_appgw_dns_config_create();
  else
    return NULL;

  while (offset < len && n < nentries)
    {
      unsigned char *external, *internal;
      SshIpAddrStruct extip, intip;

      if ((consumed =
           ssh_decode_array(data + offset, len - offset,
                            SSH_FORMAT_UINT32_STR_NOCOPY, &external, NULL,
                            SSH_FORMAT_UINT32_STR_NOCOPY, &internal, NULL,
                            SSH_FORMAT_END)) == 0)
        {
          errors = TRUE;
          break;
        }
      ssh_ipaddr_parse(&extip, external);
      ssh_ipaddr_parse(&intip, internal);
      ssh_appgw_dns_static_nat_map(c, &extip, &intip);
      offset += consumed;
      n += 1;
    }

  if (errors)
    {
      ssh_appgw_dns_destroy_config(c);
      return NULL;
    }
  else
    return c;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
/* eof */
