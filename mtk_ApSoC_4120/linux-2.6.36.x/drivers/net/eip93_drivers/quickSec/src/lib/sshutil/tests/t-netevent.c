/*
  t-netevent.c

  Copyright:
        Copyright (c) 2008 SFNT Finland Oy.
	All rights reserved
  
  Description:
        Tests for sshnetevent API.

*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshnetevent.h"

#define SSH_DEBUG_MODULE "TNetevent"

#define MAX_NUM_ADDRS 64
#define MAX_NUM_ROUTES 64

static SshNetconfigEventHandle handle = NULL;

void event_callback(SshNetconfigEvent event_type,
		    SshUInt32 ifnum,
		    void *context)
{
  unsigned char print_buf[512];
  SshNetconfigError error;

  switch (event_type)
    {
    case SSH_NETCONFIG_EVENT_LINK_CHANGED:
      printf("Link changed, ifnum=%d\n", (int) ifnum);
      if (ifnum != SSH_INVALID_IFNUM)
	{
	  SshNetconfigLinkStruct link;

	  error = ssh_netconfig_get_link(ifnum, &link);
	  if (error != SSH_NETCONFIG_ERROR_OK)
	    {
	      SSH_DEBUG(SSH_D_ERROR, 
			("Could not get link info for ifnum %d: %d",
			 (int) ifnum, (int) error));
	      return;
	    }
	  if (ssh_snprintf(print_buf, sizeof(print_buf),
			   "%@", ssh_netconfig_link_render, &link)
	      <= sizeof(print_buf))
	    printf("%s\n", print_buf);
	}
      break;

    case SSH_NETCONFIG_EVENT_ADDRESS_CHANGED:
      printf("Address changed, ifnum=%d\n", (int) ifnum);
      if (ifnum != SSH_INVALID_IFNUM)
	{
	  SshNetconfigInterfaceAddrStruct addrs[MAX_NUM_ADDRS];
	  SshUInt32 num_addrs = MAX_NUM_ADDRS;
	  int i;
	  unsigned char addr_buf[SSH_IP_ADDR_STRING_SIZE];

	  error = ssh_netconfig_get_addresses(ifnum, &num_addrs, addrs);
	  if (error != SSH_NETCONFIG_ERROR_OK)
	    {
	      SSH_DEBUG(SSH_D_ERROR, 
			("Could not get addresses for ifnum %d: %d",
			 (int) ifnum, (int) error));
	      return;
	    }

	  for (i = 0; i < num_addrs; i++)
	    {
	      ssh_ipaddr_print(&addrs[i].address, addr_buf, sizeof(addr_buf));
	      printf("\t%d: %s/%d", 
		     i, addr_buf, SSH_IP_MASK_LEN(&addrs[i].address));
	      if (addrs[i].flags & SSH_NETCONFIG_ADDR_TENTATIVE)
		printf(" tentative");
	      if (addrs[i].flags & SSH_NETCONFIG_ADDR_BROADCAST)
		{
		  ssh_ipaddr_print(&addrs[i].broadcast, addr_buf,
				   sizeof(addr_buf));
		  printf(" brd %s", addr_buf);
		}
	      printf("\n");
	    }
	}
      break;
    case SSH_NETCONFIG_EVENT_ROUTES_CHANGED:
      {	
	SshNetconfigRouteStruct routes[MAX_NUM_ROUTES];
	SshUInt32 num_routes = MAX_NUM_ROUTES;
	int i;
	
	printf("Routes changed\n");

	memset(routes, 0, sizeof(routes));
	num_routes = MAX_NUM_ROUTES;
	error = ssh_netconfig_get_route(NULL, &num_routes, routes);
	if (error != SSH_NETCONFIG_ERROR_OK)
	  {
	    SSH_DEBUG(SSH_D_ERROR, ("Could not get routes"));
	    return;
	  }
	for (i = 0; i < num_routes; i++)
	  {
	    if (ssh_snprintf(print_buf, sizeof(print_buf),
			     "%@", ssh_netconfig_route_render, &routes[i])
		<= sizeof(print_buf))
	      printf("%d: %s\n", i, print_buf);	    
	  }
      }
      break;
    }
}


void quit_handler(int sig, void *context)
{
  if (handle)
    ssh_netconfig_unregister_event_callback(handle);
  handle = NULL;
}


int main(int argc, char ** argv)
{
  int ret = -1;

  ssh_debug_set_level_string("*=3");

  ssh_event_loop_initialize();
  ssh_register_signal(SIGINT, quit_handler, NULL);
  
  handle = ssh_netconfig_register_event_callback(event_callback, NULL);
  if (handle == NULL)    
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register event callback"));
      goto out;
    }

  printf("Waiting for net events. Press ctrl-c to exit.\n");

  ssh_event_loop_run();
  ret = 0;

 out:
  ssh_event_loop_uninitialize();
  ssh_debug_uninit();

  return ret;
}
