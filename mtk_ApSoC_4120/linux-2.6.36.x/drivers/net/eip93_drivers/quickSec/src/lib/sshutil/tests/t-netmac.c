/*
  t-netmac.c

  Copyright:
        Copyright (c) 2008 SFNT Finland Oy.
	All rights reserved
  
  Description:
        Tests for sshnetmac API.

*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshnetmac.h"
#include "sshnetconfig.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "TNetmac"

static SshTimeoutStruct send_timer;

static SshNetmacHandle handle = NULL;
static unsigned char local_mac_address[6];
static unsigned char broadcast_mac_address[6] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static struct {
  unsigned char hwspc[2];
  unsigned char ipspc[2];
  unsigned char hwlen[1];
  unsigned char iplen[1];
  unsigned char opcode[2];
  unsigned char sndhw[6];
  unsigned char sndip[4];
  unsigned char tgthw[6];
  unsigned char tgtip[4];
} arp_request = {
  .hwspc = {0x00, 0x01},
  .ipspc = {0x08, 0x00},
  .hwlen = {0x06},
  .iplen = {0x04},
  .opcode = {0x00, 0x01},
  .sndhw = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  .sndip = {0x00, 0x00, 0x00, 0x00},
  .tgthw = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  .tgtip = {0xac, 0x1e, 0x04, 0x01}
};

static void
send_callback(void *context)
{
  if (ssh_netmac_send(handle,
                      broadcast_mac_address,
                      local_mac_address,
                      (void *)&arp_request,
                      sizeof arp_request) != SSH_NETCONFIG_ERROR_OK)
    SSH_DEBUG(SSH_D_ERROR, ("Could not send ARP frame"));
  else
    printf("ARP frame sent\n");

  ssh_register_timeout(&send_timer, 1, 0, send_callback, NULL);
}

static void
receive_callback(const unsigned char *dst,
                 const unsigned char *src,
                 const unsigned char *data_buf,
                 size_t data_len,
                 void *context)
{
  printf("ARP frame received\n");
}

static
void quit_handler(int sig, void *context)
{
  ssh_cancel_timeout(&send_timer);

  if (handle)
    ssh_netmac_unregister(handle);
  handle = NULL;
}

int usage(const char *program_name)
{
  printf("Usage: %s [-i ifname] [-D debug_string] ipv4_addr\n", program_name);
  return -1;
}

int main(int argc, char ** argv)
{
  int status = -1;
#ifdef SSHDIST_PLATFORM_LINUX
#ifdef __linux__
  const char *prg;
  int opt, i;
  SshGetOptDataStruct getopt;
  const char *debug_string = "*=3,*Netmac*=99";
  const char *ifname = "eth0";
  SshUInt32 ifnum, addrc;
  SshNetconfigLinkStruct link;
  SshNetconfigInterfaceAddrStruct addrv[4];
  SshIpAddrStruct remote_ip_buf;
  SshIpAddr local_ip, remote_ip = &remote_ip_buf;

  prg = strrchr(argv[0], '/');
  if (prg)
    prg++;
  else
    prg = argv[0];

  ssh_getopt_init_data(&getopt);
  while ((opt = ssh_getopt(argc, argv, "D:i:h", &getopt)) != EOF)
    {
      switch (opt)
        {
        case 'D':
          debug_string = getopt.arg;
          break;

        case 'i':
          ifname = getopt.arg;
          break;

        case 'h':
        default:
          usage(prg);
          return 0;
          break;
        }
    }

  if (argc != getopt.ind + 1)
    {
      usage(prg);
      return -1;
    }

  if (!ssh_ipaddr_parse(remote_ip, argv[getopt.ind]))
    {
      usage(prg);
      return -1;
    }

  ssh_debug_set_level_string(debug_string);

  ssh_event_loop_initialize();
  ssh_register_signal(SIGINT, quit_handler, NULL);

  if (ssh_netconfig_resolve_ifname(ifname, &ifnum) != SSH_NETCONFIG_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not find interface %s", ifname));
      goto end;
    }
  
  if (ssh_netconfig_get_link(ifnum, &link) != SSH_NETCONFIG_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get info for interface %s", ifname));
      goto end;
    }

  addrc = sizeof addrv / sizeof addrv[0];
  if (ssh_netconfig_get_addresses(ifnum, &addrc, addrv) !=
      SSH_NETCONFIG_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get addrs for interface %s", ifname));
      goto end;
    }

  local_ip = NULL;
  for (i = 0; i < addrc; i++)
    if (SSH_IP_IS4(&addrv[i].address))
      local_ip = &addrv[i].address;

  if (!local_ip)
    {
      SSH_DEBUG(SSH_D_ERROR, ("No IPv4 addresses on interface %s", ifname));
      goto end;
    }

  handle = ssh_netmac_register(ifnum, 0x0806, receive_callback, NULL);
  if (handle == NULL)    
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get MAC handle"));
      goto end;
    }

  memcpy(local_mac_address, link.media_addr, sizeof local_mac_address);
  memcpy(arp_request.sndhw, link.media_addr, sizeof arp_request.sndhw);
  SSH_IP4_ENCODE(local_ip, arp_request.sndip);
  SSH_IP4_ENCODE(remote_ip, arp_request.tgtip);

  ssh_register_timeout(&send_timer, 1, 0, send_callback, NULL);

  printf("Receiving and sending ARP frames. Press ctrl-c to exit.\n");

  ssh_event_loop_run();
  status = 0;

 end:
  ssh_event_loop_uninitialize();
  ssh_debug_uninit();

#endif /* __linux__ */
#endif /* SSHDIST_PLATFORM_LINUX */
  return status;
}
