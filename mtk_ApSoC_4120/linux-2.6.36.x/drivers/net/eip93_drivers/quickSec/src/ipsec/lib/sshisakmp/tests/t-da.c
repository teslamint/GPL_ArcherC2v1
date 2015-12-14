/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Thu Aug  7 22:14:34 1997 [ttsalo]

  Data Attribute tests for sshisakmp library

  */

/*
 * $Id: //WIFI_SOC/release/SDK_4_1_0_0/source/linux-2.6.36.x/drivers/net/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/t-da.c#1 $
 * $Log: t-da.c,v $
 * Revision 1.1.2.1  2011/01/31 03:29:49  treychen_hc
 * add eip93 drivers
 * * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * $EndLog$
 */

#include "sshincludes.h"
#include "isakmp.h"
#include "sshdebug.h"

void
test_fail(char *msg)
{
  printf(msg);
  printf("\n");
  exit(1);
}

int
main(int argc, char **argv)
{
  /* 16 bit value: 345 type: 12 */
  unsigned char ta1[] = { 0x80, 12, 1, 89 };
  /* 3 byte value: 0x876543 type: 9 */
  unsigned char ta2[] = { 0, 9, 0, 3, 0x87, 0x65, 0x43 };
  /* 4 byte value: 0x9999 type: 0 */
  unsigned char ta3[] = { 0, 0, 0, 4, 0, 0, 0x99, 0x99 };
  unsigned char ta4[] = { 0x30, 0x20, 0, 5, 0x12, 0x34,
                          0x56, 0x78, 0x90 };

  int len;
  Boolean boo;
  size_t used_b;
  SshUInt16 type;
  SshUInt32 value;
  SshBuffer buf = ssh_buffer_allocate();
  
  SshIkeDataAttribute dattr1 =
    ssh_xmalloc(sizeof(struct SshIkeDataAttributeRec));
  SshIkeDataAttribute dattr2 =
    ssh_xmalloc(sizeof(struct SshIkeDataAttributeRec));
  SshIkeDataAttribute dattr3 =
    ssh_xmalloc(sizeof(struct SshIkeDataAttributeRec));
  SshIkeDataAttribute dattr4 =
    ssh_xmalloc(sizeof(struct SshIkeDataAttributeRec));

  if (argc > 1)
    ssh_debug_set_level_string(argv[1]);
  
  /* Testing ssh_ike_decode_data_attribute_size */

  len = ssh_ike_decode_data_attribute_size(ta1, 0);
  if (len != 4)
    test_fail("Test1: invalid size");

  len = ssh_ike_decode_data_attribute_size(ta2, 0);
  if (len != 7)
    test_fail("Test2: invalid size");

  len = ssh_ike_decode_data_attribute_size(ta3, 0);
  if (len != 8)
    test_fail("Test3: invalid size");

  len = ssh_ike_decode_data_attribute_size(ta4, 0);
  if (len != 9)
    test_fail("Test4: invalid size");

  /* Testing ssh_ike_decode_data_attribute */

  boo = ssh_ike_decode_data_attribute(ta1, 4, &used_b, dattr1, 0);
  if (boo != TRUE ||
      (dattr1->attribute_type) != 12 ||
      dattr1->attribute_length != 2 ||
      dattr1->attribute[0] != 1 ||
      dattr1->attribute[1] != 89 ||
      used_b != 4)
    test_fail("Test5: failed");

  boo = ssh_ike_decode_data_attribute(ta2, 7, &used_b, dattr2, 0);
  if (boo != TRUE ||
      (dattr2->attribute_type) != 9 ||
      dattr2->attribute_length != 3 ||
      dattr2->attribute[0] != 0x87 ||
      dattr2->attribute[1] != 0x65 ||
      dattr2->attribute[2] != 0x43 ||
      used_b != 7)
    test_fail("Test6: failed");

  boo = ssh_ike_decode_data_attribute(ta3, 8, &used_b, dattr3, 0);
  if (boo != TRUE ||
      (dattr3->attribute_type) != 0 ||
      dattr3->attribute_length != 4 ||
      dattr3->attribute[0] != 0x0 ||
      dattr3->attribute[1] != 0x0 ||
      dattr3->attribute[2] != 0x99 ||
      dattr3->attribute[3] != 0x99 ||
      used_b != 8)
    test_fail("Test7: failed");

  boo = ssh_ike_decode_data_attribute(ta4, 9, &used_b, dattr4, 0);
  if (boo != TRUE ||
      (dattr4->attribute_type) != 0x3020 ||
      dattr4->attribute_length != 5 ||
      dattr4->attribute[0] != 0x12 ||
      dattr4->attribute[1] != 0x34 ||
      dattr4->attribute[2] != 0x56 ||
      dattr4->attribute[3] != 0x78 ||
      dattr4->attribute[4] != 0x90 ||
      used_b != 9)
    test_fail("Test8: failed");

  /* Testing ssh_ike_decode_data_attribute_int */

  boo = ssh_ike_decode_data_attribute_int(ta1, 4, &type, &value, 0);
  if (boo != TRUE ||
      type != 12 ||
      value != 345)
    test_fail("Test9: failed");

  boo = ssh_ike_decode_data_attribute_int(ta2, 7, &type, &value, 0);
  if (boo != TRUE ||
      type != 9 ||
      value != 0x876543)
    test_fail("Test10: failed");

  boo = ssh_ike_decode_data_attribute_int(ta3, 8, &type, &value, 0);
  if (boo != TRUE ||
      type != 0 ||
      value != 0x9999)
    test_fail("Test11: failed");

  boo = ssh_ike_decode_data_attribute_int(ta4, 9, &type, &value, 0);
  if (boo != FALSE)
    test_fail("Test12: failed");

  /* Testing ssh_ike_encode_data_attribute */
  
  used_b = ssh_ike_encode_data_attribute(buf, dattr1, 0);
  if (used_b != 4 ||
      memcmp(ta1, ssh_buffer_ptr(buf), 4))
    test_fail("Test13: failed");
  ssh_buffer_consume(buf, 4);
  
  used_b = ssh_ike_encode_data_attribute(buf, dattr2, 0);
  if (used_b != 7 ||
      memcmp(ta2, ssh_buffer_ptr(buf), 7))
    test_fail("Test14: failed");
  ssh_buffer_consume(buf, 7);

  used_b = ssh_ike_encode_data_attribute(buf, dattr3, 0);
  if (used_b != 8 ||
      memcmp(ta3, ssh_buffer_ptr(buf), 8))
    test_fail("Test15: failed");
  ssh_buffer_consume(buf, 8);
  
  used_b = ssh_ike_encode_data_attribute(buf, dattr4, 0);
  if (used_b != 9 ||
      memcmp(ta4, ssh_buffer_ptr(buf), 9))
    test_fail("Test16: failed");
  ssh_buffer_consume(buf, 9);

  /* Testing ssh_ike_encode_data_attribute_int */

  used_b = ssh_ike_encode_data_attribute_int(buf, 12, TRUE, 345, 0);
  if (used_b != 4 ||
      memcmp(ta1, ssh_buffer_ptr(buf), 4))
    test_fail("Test17: failed");
  ssh_buffer_consume(buf, 4);
  
  used_b = ssh_ike_encode_data_attribute_int(buf, 0, FALSE, 0x9999, 0);
  if (used_b != 8 ||
      memcmp(ta3, ssh_buffer_ptr(buf), 8))
    test_fail("Test18: failed");
  ssh_buffer_consume(buf, 8);
  ssh_free(dattr1);
  ssh_free(dattr2);
  ssh_free(dattr3);
  ssh_free(dattr4);
  ssh_buffer_free(buf);
  ssh_util_uninit();
  return 0;
}
