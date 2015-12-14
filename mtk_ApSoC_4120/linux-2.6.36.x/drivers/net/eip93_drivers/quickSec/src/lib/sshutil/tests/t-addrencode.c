/*

  t-addrencode.c

  Author: Santeri Paavolainen <santtu@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

 */

#include "sshincludes.h"
#include "sshinet.h"
#include "sshinetencode.h"
#include "sshrand.h"

#define TEST_ITER       10000

const char * run_test (SshIpAddr orig, int mask_bits, int addr_len)
{
  SshIpAddrStruct addr_decoded;
  int i;
  unsigned char buf[512];
  size_t len;

  /* range is 0 to 32 or 0 to 128! */
  orig->mask_len = (SshUInt8) (ssh_rand() % (mask_bits + 1)); 

  for (i = 0; i < addr_len; i++)
    orig->addr_data[i] = (unsigned char) (ssh_rand() % 0xff);

  if ((len = ssh_encode_ipaddr_array(buf, sizeof(buf), orig)) == 0)
    return "encoding";

  if (ssh_decode_ipaddr_array(buf, len, &addr_decoded) != len)
    return "decoding";

  if (!SSH_IP_EQUAL(orig, &addr_decoded))
    return "address equality";

  if (SSH_IP_MASK_LEN(orig) != SSH_IP_MASK_LEN(&addr_decoded))
    return "mask equality";

  return NULL;
}

int main ()
{
  SshIpAddrStruct addr_orig;
  int i;
  const char * err;

  ssh_rand_seed((SshUInt32)ssh_time());

  /* Run ipv4 address encode/decode tests */
  addr_orig.type = SSH_IP_TYPE_IPV4;

  for (i = 0; i < TEST_ITER; i++) {
    if (i % 1000 == 0)
      fprintf(stderr, ".");

    if ((err = run_test(&addr_orig, 32, 4)) != NULL) {
      fprintf(stderr, "\nipv4: %s\n", err);
      ssh_util_uninit();
      exit(1);
    }
  }

#ifdef WITH_IPV6
  /* Run ipv6 address encode/decode tests */
  addr_orig.type = SSH_IP_TYPE_IPV6;

  for (i = 0; i < TEST_ITER; i++) {
    if (i % 1000 == 0)
      fprintf(stderr, ".");

    if ((err = run_test(&addr_orig,128, 16)) != NULL) {
      fprintf(stderr, "\nipv6: %s\n", err);
      ssh_util_uninit();
      exit(1);
    }
  }
#endif /* WITH_IPV6 */

  fprintf(stderr, "\n");

  ssh_util_uninit();
  exit (0);
}
