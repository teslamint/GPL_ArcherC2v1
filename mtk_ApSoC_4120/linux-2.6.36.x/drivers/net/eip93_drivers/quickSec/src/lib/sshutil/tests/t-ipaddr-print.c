/*
 *
 * t-ipaddr-print.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Testing IP address printing.
 *
 */

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "t-ipaddr-print"

struct {
  enum {
    /* Parse `parse' field, compare against `bytes', the render and
       check against `canonical' (or `parse' if `canonical' is NULL).. */
    CHECK,

    /* Like CHECK, but use ssh_ipaddr_print_with_mask and
       ssh_ipaddr_parse_with_mask */
    CHECKMASK,

    /* Like previous, but NB as in "no bytes", eg. pass the `bytes'
       check */
    PARSECHECK,

    /* Check `bytes' rendered against `canonical', `parse' needs to
       have the required ip address version, but is otherwise ignored
       (eg. use `0.0.0.0' for ipv4 and `::' for ipv6) */
    RENDERCHECK,

  } type;

  unsigned char bytes[16];

  const char *parse;
  const char *canonical; /* NULL if same as the parsed version */
} addresses[] = {
  {
    CHECK,
    "\x3f\xfe\x05\x01\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x33",
    "3ffe:501:ffff::33",
    NULL
  },
  {
    CHECK,
    "\x3f\xfe\x05\x01\xff\xff\x00\x00\x02\x00\xe8\xff\xfe\x6f\xc2\xe0",
    "3ffe:501:ffff:0:200:e8ff:fe6f:c2e0",
    NULL
  },
  {
    CHECK,
    "\x3f\xfe\x05\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x33",
    "3ffe:501:0:0:1:0:0:33",
    "3ffe:501::1:0:0:33"
  },
  {
    CHECK,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "::",
    NULL
  },
  {
    CHECK,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "::1",
    NULL
  },
  {
    CHECK,
    "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "1::",
    NULL
  },
  {
    CHECK,
    "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "1::1",
    NULL
  },
  {
    CHECK,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04",
    "::1.2.3.4",
    "::102:304"
  },
  {
    CHECK,
    "\x00\x01\x00\x02\x00\x03\x00\x04\x00\x00\x00\x00\x00\x00\x00\xff",
    "1:2:3:4::ff",
    NULL
  },
  {
    CHECK,
    "\xff\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "ffc0::",
    NULL
  },
  {
    CHECK,
    "\xff\xff\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "ffff:ff::",
    NULL
  },
  {
    CHECKMASK,
    "\xff\xff\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "ffff:ff::/64",
    NULL
  },
  {
    CHECK,
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    NULL,
  },
  {
    CHECKMASK,
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
    NULL
  },
  {
    CHECKMASK,
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff::0",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/64"
  },
  {
    RENDERCHECK,
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    "::",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
  },
  {
    RENDERCHECK,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "::",
    "1:203:405:607:809:a0b:c0d:e0f"
  },
  {
    RENDERCHECK,
    "\x00\x01\x02\x03\x04\x05\x00\x00\x00\x00\x00\x00\x0c\x0d\x0e\x0f",
    "::",
    "1:203:405::c0d:e0f"
  }
};

int
main(int argc, char *argv[])
{
  int i, k, errors;
  SshIpAddrStruct ip;
  char buf[SSH_IP_ADDR_STRING_SIZE], buf2[128];
  const char *correct;

  errors = 0;

  for (i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++)
    {
      if (addresses[i].type == RENDERCHECK)
        {
          /* prime the internal data with `parse' */
          ssh_ipaddr_parse(&ip, addresses[i].parse);
          memcpy(ip.addr_data, addresses[i].bytes, SSH_IP_ADDR_LEN(&ip));
        }
      else if (addresses[i].type == CHECKMASK)
        (void) ssh_ipaddr_parse_with_mask(&ip, addresses[i].parse, NULL);
      else
        (void) ssh_ipaddr_parse(&ip, addresses[i].parse);

      if (addresses[i].type == CHECK)
        {
          for (k = 0; k < SSH_IP_ADDR_LEN(&ip); k++)



            if (addresses[i].bytes[k] != ip.addr_data[k])
              {
                SSH_DEBUG(0, ("ERROR: `%s' differs from expected in byte #%d, "
                              "0x%02x was expected, but parsed as 0x%02x",
                              addresses[i].parse, k,
                              addresses[i].bytes[k], ip.addr_data[k]));

                for (k = 0; k < SSH_IP_ADDR_LEN(&ip); k++)
                  ssh_snprintf(buf + 4 * k, sizeof(buf) - 4 * k,
                               "\\x%02x", addresses[i].bytes[k]);

                SSH_DEBUG(0, ("ERROR: Expected: %s", buf));

                for (k = 0; k < SSH_IP_ADDR_LEN(&ip); k++)
                  ssh_snprintf(buf + 4 * k, sizeof(buf) - 4 * k,
                               "\\x%02x", ip.addr_data[k]);

                SSH_DEBUG(0, ("ERROR: Got:      %s", buf));

                errors++;
                goto next;
              }
        }

      if (addresses[i].type == CHECKMASK)
        ssh_ipaddr_print_with_mask(&ip, buf, sizeof(buf));
      else
        ssh_ipaddr_print(&ip, buf, sizeof(buf));

      if (addresses[i].canonical != NULL)
        correct = addresses[i].canonical;
      else
        correct = addresses[i].parse;

      if (addresses[i].type == RENDERCHECK)
        for (k = 0; k < SSH_IP_ADDR_LEN(&ip); k++)
          ssh_snprintf(buf2 + 4 * k, sizeof(buf2) - 4 * k,
                       "\\x%02x", addresses[i].bytes[k]);
      else
        strcpy(buf2, addresses[i].parse);

      if (strcmp(buf, correct) != 0)
        {
          SSH_DEBUG(0, ("ERROR: `%s' rendered as `%s', when `%s' was expected",
                        buf2, buf, correct));
          errors++;
          goto next;
        }

      SSH_DEBUG(0, ("`%s' rendered `%s', ok.", buf2, buf));

    next:
          ;
    }

  SSH_IP_DECODE(&ip, "\0\0\0\0", 4);
  if (!ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP4_TO_INT(&ip) != 1)
    ssh_fatal("ssh_ipaddr_increment failed not 1 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP4_TO_INT(&ip) != 2)
    ssh_fatal("ssh_ipaddr_increment failed not 2 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP4_TO_INT(&ip) != 1)
    ssh_fatal("ssh_ipaddr_decrement failed not 1 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP4_TO_INT(&ip) != 0)
    ssh_fatal("ssh_ipaddr_decrement failed not 0 %@",
	      ssh_ipaddr_render, &ip);
  if (ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment didn't fail");
  if (SSH_IP4_TO_INT(&ip) != 0xffffffff)
    ssh_fatal("ssh_ipaddr_decrement failed not 0xffffffff %@",
	      ssh_ipaddr_render, &ip);
  if (ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment didn't fail");
  if (SSH_IP4_TO_INT(&ip) != 0)
    ssh_fatal("ssh_ipaddr_increment failed not 0 %@",
	      ssh_ipaddr_render, &ip);

  SSH_IP_DECODE(&ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
  if (!ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD3_TO_INT(&ip) != 1)
    ssh_fatal("ssh_ipaddr_increment failed not 1 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD3_TO_INT(&ip) != 2)
    ssh_fatal("ssh_ipaddr_increment failed not 2 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD3_TO_INT(&ip) != 1)
    ssh_fatal("ssh_ipaddr_decrement failed not 1 %@",
	      ssh_ipaddr_render, &ip);
  if (!ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment failed");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD3_TO_INT(&ip) != 0)
    ssh_fatal("ssh_ipaddr_decrement failed not 0 %@",
	      ssh_ipaddr_render, &ip);
  if (ssh_ipaddr_decrement(&ip))
    ssh_fatal("ssh_ipaddr_increment didn't fail");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0xffffffff ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0xffffffff ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0xffffffff ||
      SSH_IP6_WORD3_TO_INT(&ip) != 0xffffffff)
    ssh_fatal("ssh_ipaddr_decrement failed not 0xffffffff %@",
	      ssh_ipaddr_render, &ip);
  if (ssh_ipaddr_increment(&ip))
    ssh_fatal("ssh_ipaddr_increment didn't fail");
  if (SSH_IP6_WORD0_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD1_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD2_TO_INT(&ip) != 0 ||
      SSH_IP6_WORD3_TO_INT(&ip) != 0)
    ssh_fatal("ssh_ipaddr_increment failed not 0 %@",
	      ssh_ipaddr_render, &ip);

  return errors > 0;
}
