/*
  t-netconfig.c

  Copyright:
        Copyright (c) 2007 SFNT Finland Oy.
	All rights reserved
  
  Description:
        Tests for sshnetconfig.c

*/

#include "sshincludes.h"
#include "sshnetconfig.h"

#define MAX_NUM_ADDRESSES   16
#define MAX_NUM_ROUTES      64

#define DEFAULT_IFNAME       "dummy0"

#define DEFAULT_IPV4_ADDR    "10.0.5.123"
#define DEFAULT_IPV4_BCAST   "10.0.5.123"
#define DEFAULT_IPV4_MASK    "255.255.255.0"
#define DEFAULT_IPV4_NET     "10.0.6.0"
#define DEFAULT_IPV4_NETMASK "255.255.255.0"
#define DEFAULT_IPV4_GW      "10.0.5.125"

#define DEFAULT_IPV6_ADDR    "5000:5::123"
#define DEFAULT_IPV6_MASK    "64"
#define DEFAULT_IPV6_NET     "5000:6::"
#define DEFAULT_IPV6_NETMASK "64"
#define DEFAULT_IPV6_GW      "5000:5::125"

int dump_addresses(SshUInt32 ifnum)
{
  SshNetconfigInterfaceAddrStruct addresses[MAX_NUM_ADDRESSES];
  SshUInt32 num_addresses = MAX_NUM_ADDRESSES;
  int i;
  unsigned char addr_buf[SSH_IP_ADDR_STRING_SIZE];
  SshNetconfigError error;

  memset(addresses, 0, sizeof(addresses));
  num_addresses = MAX_NUM_ADDRESSES;
  error = ssh_netconfig_get_addresses(ifnum, &num_addresses, addresses);
  if (error != SSH_NETCONFIG_ERROR_OK)
    {
      printf("ssh_netconfig_get_addresses: error %d\n", error);
      return -1;
    }  
  for (i = 0; i < num_addresses; i++)
    {
      ssh_ipaddr_print(&addresses[i].address, addr_buf, sizeof(addr_buf));
      printf("\t%d: %s/%d", 
	     i, addr_buf, SSH_IP_MASK_LEN(&addresses[i].address));
      if (addresses[i].flags & SSH_NETCONFIG_ADDR_TENTATIVE)
	printf(" tentative");
      if (addresses[i].flags & SSH_NETCONFIG_ADDR_BROADCAST)
	{
	  ssh_ipaddr_print(&addresses[i].broadcast, addr_buf, 
			   sizeof(addr_buf));
	  printf(" brd %s", addr_buf);
	}
      printf("\n");
    }
  return 0;
}

int dump_routes(SshIpAddr prefix)
{
  SshNetconfigRouteStruct routes[MAX_NUM_ROUTES];
  SshUInt32 num_routes = MAX_NUM_ROUTES;
  SshNetconfigError error;
  int i;
  unsigned char print_buf[512];

  memset(routes, 0, sizeof(routes));
  num_routes = MAX_NUM_ROUTES;
  error = ssh_netconfig_get_route(prefix, &num_routes, routes);
  if (error != SSH_NETCONFIG_ERROR_OK)
    {
      printf("ssh_netconfig_get_route: error %d\n", error);
      return -1;
    }
  for (i = 0; i < num_routes; i++)
    {
      if (ssh_snprintf(print_buf, sizeof(print_buf),
		       "%@", ssh_netconfig_route_render, &routes[i])
	  <= sizeof(print_buf))
	printf("%d: %s\n", i, print_buf);		   
    }
  return 0;
}


int do_tests(unsigned char *ifname, Boolean do_set_tests, Boolean use_ipv6)
{
  unsigned char default_ifname[16] = DEFAULT_IFNAME;
  SshUInt32 ifnum, flags;
  SshNetconfigError error;
  unsigned char addr_buf[64], mask_buf[64];
  SshNetconfigLinkStruct link;
  SshNetconfigInterfaceAddrStruct address;
  SshNetconfigRouteStruct route;  
  Boolean use_any_interface;
  unsigned char print_buf[512];

  if (ifname == NULL)
    {
      use_any_interface = TRUE;
      ifname = default_ifname;
    }
  else
    {
      use_any_interface = FALSE;
    }
  ifnum = SSH_INVALID_IFNUM;

  /* Resolve ifname. */
  printf("Resolving interface \"%s\": ", ifname);
  error = ssh_netconfig_resolve_ifname(ifname, &ifnum);
  if (error != SSH_NETCONFIG_ERROR_OK)
    printf("ssh_netconfig_resolve_ifname: error %d\n", error);
  else
    printf("ifnum %ld\n", ifnum);

  if (ifnum == SSH_INVALID_IFNUM)
    {
      if (use_any_interface)
	{
	  /* Pick another interface. */
	  for (ifnum = 10; ifnum >= 1; ifnum--)
	    {
	      printf("Resolving ifnum %d: ", (int) ifnum);
	      if (ssh_netconfig_resolve_ifnum(ifnum, default_ifname, 
					      sizeof(default_ifname))
		  == SSH_NETCONFIG_ERROR_OK)
		{
		  ifname = default_ifname;
		  printf("\"%s\"\n", ifname);
		  goto interface_found;
		}
	      printf("not found\n");
	    }
	  printf("no usable interfaces found\n");
	}
      return -1;
    }

 interface_found:
  
  /* Get link state. */
  printf("Fetching link state: ");
  error = ssh_netconfig_get_link(ifnum, &link);
  if (error != SSH_NETCONFIG_ERROR_OK)
    {
      printf("ssh_netconfig_get_link: error %d\n", error);
      return -1;
    }
  if (ssh_snprintf(print_buf, sizeof(print_buf),
		   "%@", ssh_netconfig_link_render, &link)
      <= sizeof(print_buf))
    printf("%s\n", print_buf);

  /* Set link state up. */
  if (do_set_tests)
    {
      /* Bring link up, even if it is already up, because this 
	 is a test program. */
      printf("Bringing interface up: ");
      error = ssh_netconfig_set_link_flags(ifnum, SSH_NETCONFIG_LINK_UP, 
					   SSH_NETCONFIG_LINK_UP);
      if (error != SSH_NETCONFIG_ERROR_OK)
	{
	  printf("ssh_netconfig_set_link_flags: error %d\n", error);
	  return -1;
	}
      printf("ok\n");
    }

  /* Dump addresses. */
  printf("Fetching addresses:\n");
  if (dump_addresses(ifnum))
    return -1;


  if (do_set_tests)
    {
      /* Add new IP address. */
      memset(&address, 0, sizeof(address));
      if (!use_ipv6)
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_ADDR);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV4_MASK);
	}
      else
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_ADDR);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV6_MASK);
	}
      printf("Adding address %s/%s ", addr_buf, mask_buf);
      if (!ssh_ipaddr_parse_with_mask(&address.address, addr_buf, mask_buf))
	{
	  printf("ssh_ipaddr_parse: error\n");
	  return -1;
	}
      if (!use_ipv6)
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_BCAST);
	  printf("brd %s: ", addr_buf);
	  if (!ssh_ipaddr_parse(&address.broadcast, addr_buf))
	    {
	      printf("ssh_ipaddr_parse: error\n");
	      return -1;
	    }
	  address.flags = SSH_NETCONFIG_ADDR_BROADCAST;
	}
      error = ssh_netconfig_add_address(ifnum, &address);
      if (error != SSH_NETCONFIG_ERROR_OK)
	{
	  printf("ssh_netconfig_add_address: error %d\n", error);
	  return -1;
	}
      printf("ok\n");

      /* Dump addresses. */
      printf("Fetching addresses:\n");
      if (dump_addresses(ifnum))
	return -1;
    }


  /* Dump routes. */
  printf("Fetching routing table:\n");
  if (dump_routes(NULL))
    return -1;


  if (do_set_tests)
    {
      /* Add new route. */      
      memset(&route, 0, sizeof(route));
      if (!use_ipv6)
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_NET);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV4_NETMASK);
	}
      else
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_NET);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV6_NETMASK);
	}
      ssh_ipaddr_parse_with_mask(&route.prefix, addr_buf, mask_buf);
      printf("Adding route %s/%s", addr_buf, mask_buf);
      if (!use_ipv6)
	ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_GW);
      else
	ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_GW);
      ssh_ipaddr_parse(&route.gateway, addr_buf);
      route.ifnum = ifnum;
      route.metric = 8;
      printf(" via %s dev %ld metric %ld: ", 
	     addr_buf, route.ifnum, route.metric);
      error = ssh_netconfig_add_route(&route);
      if (error != SSH_NETCONFIG_ERROR_OK)
	{
	  printf("ssh_netconfig_add_route: error %d\n", error);
	  return -1;
	}
      printf("ok\n");
      

      /* Dump routes. */
      printf("Fetching routing table:\n");
      if (dump_routes(NULL))
	return -1;

    }

  
  /* Get routes matching prefix. */
  if (!use_ipv6)
    {
      ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_NET);
      ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV4_NETMASK);
    }
  else
    {
      ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_NET);
      ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV6_NETMASK);
    }
  printf("Getting routes matching %s/%s:\n", addr_buf, mask_buf);
  ssh_ipaddr_parse_with_mask(&route.prefix, addr_buf, mask_buf);
  if (dump_routes(&route.prefix))
    return -1;


  if (do_set_tests)
    {
      /* Delete newly added route. */
      memset(&route, 0, sizeof(route));
      if (!use_ipv6)
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_NET);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV4_NETMASK);
	}
      else
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_NET);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV6_NETMASK);
	}
      ssh_ipaddr_parse_with_mask(&route.prefix, addr_buf, mask_buf);
      printf("Deleting route %s/%s", addr_buf, mask_buf);
      if (!use_ipv6)
	ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_GW);
      else
	ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_GW);
      ssh_ipaddr_parse(&route.gateway, addr_buf);
      route.ifnum = ifnum;
      route.metric = 8;
      printf(" via %s dev %ld metric %ld: ", 
	 addr_buf, route.ifnum, route.metric);
      error = ssh_netconfig_del_route(&route);
      if (error != SSH_NETCONFIG_ERROR_OK)
	{
	  printf("ssh_netconfig_del_route: error %d\n", error);
	  return -1;
	}
      printf("ok\n");
  

      /* Dump routes. */
      printf("Fetching routing table:\n");
      if (dump_routes(NULL))
	return -1;


      /* Delete newly added address. */
      memset(&address, 0, sizeof(address));
      if (!use_ipv6)
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV4_ADDR);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV4_MASK);
	}
      else
	{
	  ssh_snprintf(addr_buf, sizeof(addr_buf), DEFAULT_IPV6_ADDR);
	  ssh_snprintf(mask_buf, sizeof(mask_buf), DEFAULT_IPV6_MASK);
	}
      printf("Deleting address %s/%s: ", addr_buf, mask_buf);
      if (!ssh_ipaddr_parse_with_mask(&address.address, addr_buf, mask_buf))
	{
	  printf("ssh_ipaddr_parse: error\n");
	  return -1;
	}
      address.flags = 0;
      error = ssh_netconfig_del_address(ifnum, &address);
      if (error != SSH_NETCONFIG_ERROR_OK)
	{
	  printf("ssh_netconfig_del_address: error %d\n", error);
	  return -1;
	}
      printf("ok\n");
  

      /* Dump addresses. */
      printf("Fetching addresses:\n");
      if (dump_addresses(ifnum))
	return -1;

      /* Restore link state. */
      if ((flags & SSH_NETCONFIG_LINK_UP) == 0)
	{
	  printf("Bringing interface down: ");
	  error =
	    ssh_netconfig_set_link_flags(ifnum, 0, SSH_NETCONFIG_LINK_UP);
	  if (error != SSH_NETCONFIG_ERROR_OK)
	    {
	      printf("ssh_netconfig_set_link_flags: error %d\n", error);
	      return -1;
	    }
	  printf("ok\n");
	}
    }

  return 0;
}

int usage(char *program_name)
{
  printf("%s [-i|--interface ifname] [-s|--do-set-tests] [-6|--ipv6]\n"
	 "\t[-D debug_string]\n", 
	 program_name);
  return -1;
}

int main(int argc, char **argv)
{
  /* Currently sshnetconfig API is implemented on linux. */
#ifdef SSHDIST_PLATFORM_LINUX
#ifdef __linux__
  unsigned char *ifname = NULL;
  Boolean do_set_tests = FALSE, use_ipv6 = FALSE;
  int i;
  unsigned char *debug_str = NULL;

  for (i = 1; i < argc; i++)
    {
      if (strncmp(argv[i], "-i", strlen("-i")) == 0)
	{
	  if (strlen(argv[i] + strlen("-i")) != 0)
	    ifname = argv[i] + strlen("-i");
	  else if (i + 1 < argc)
	    ifname = argv[++i];
	  else
	    usage(argv[0]);
	  continue;
	}
      else if (strncmp(argv[i], "--interface", strlen("--interface")) == 0)
	{
	  if (strlen(argv[i] + strlen("--interface")) != 0)
	    ifname = argv[i] + strlen("--interface");
	  else if (i + 1 < argc)
	    ifname = argv[++i];
	  else
	    usage(argv[0]);
	  continue;
	}
      else if (strncmp(argv[i], "-s", strlen("-s")) == 0
	       || strncmp(argv[i], "--do-set-tests", strlen("--do-set-tests"))
	       == 0)
	do_set_tests = TRUE;
      else if (strncmp(argv[i], "-6", strlen("-6")) == 0
	       || strncmp(argv[i], "--ipv6", strlen("--ipv6")) == 0)
	use_ipv6 = TRUE;
      else if (strncmp(argv[i], "-D", strlen("-D")) == 0)
	{
	  if (strlen(argv[i] + strlen("-D")) != 0)
	    debug_str = argv[i] + strlen("-D");
	  else if (i + 1 < argc)
	    debug_str = argv[++i];
	  else
	    usage(argv[0]);
	  continue;
	}
      else
	return usage(argv[0]);
    }

  if (debug_str != NULL)
    ssh_debug_set_level_string(debug_str);

  return do_tests(ifname, do_set_tests, use_ipv6);
#endif /* __linux__ */
#endif /* SSHDIST_PLATFORM_LINUX */
  return 0;
}
