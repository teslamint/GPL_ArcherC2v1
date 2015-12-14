/*
  Author: Lauri Tarkkala <ltarkkal@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All Rights Reserved.
*/

#define SSH_DEBUG_MODULE "SshPppPppd"

#include "sshincludes.h"

#include "ssheloop.h"
#include "sshfsm.h"
#include "sshcrypt.h"
#include "sshstream.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "sshglobals.h"

#include "../sshppp_linkpkt.h"
#include "../sshppp_events.h"
#include "../sshppp.h"
#include "../sshppp_config.h"
#include "../sshppp_flush.h"
#include "../sshppp_auth.h"
#include "../sshppp_internal.h"
#include "../sshppp_timer.h"
#include "../sshppp_thread.h"
#include "../sshppp_protocol.h"
#include "../sshppp_chap.h"

static Boolean
test_ntresponse_v1(void)
{
  unsigned  char challenge[] = {
    0x10, 0x2d, 0xb5, 0xdf, 0x08, 0x5d, 0x30,0x41 };
  size_t challenge_length = 8;

  unsigned char ntpw[] = {
    0x4d, 0x00, 0x79, 0x00, 0x50, 0x00, 0x77, 0x00 };
  unsigned char ntpw_length = 8;

  unsigned char correct_response[] = {
    0x4e, 0x9d, 0x3c, 0x8f, 0x9c, 0xfd, 0x38, 0x5d,
    0x5b, 0xf4, 0xd3, 0x24, 0x67, 0x91, 0x95, 0x6c,
    0xa4, 0xc3, 0x51, 0xab, 0x40, 0x9a, 0x3d, 0x61 };

  unsigned char output_buf[24];

  if ( ssh_ppp_chap_generate_ntresponse_v1(ntpw, ntpw_length,
                                           challenge,challenge_length,
                                           output_buf,24) == FALSE )
    return FALSE;

  if (memcmp(output_buf,correct_response,24) == 0)
    return TRUE;

  return FALSE;
}

static Boolean
test_ntresponse(void)
{
  unsigned char output_buf[32];

  unsigned char username[] = { 0x55, 0x73, 0x65, 0x72 };
  size_t username_length = 4;

  unsigned  char secret[] =
    { 0x63, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x65, 0x00, 0x6e, 0x00,
      0x74, 0x00, 0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00 };
  size_t secret_length = 20;

  unsigned char challenge[] =
    { 0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c,
      0x60, 0x21, 0x32, 0x26, 0x26, 0x28 };
  size_t challenge_length = 16;

  unsigned char peer_challenge[] =
    { 0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
      0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e };
  size_t peer_challenge_length = 16;

  unsigned char ntresponse[] =
    { 0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e, 0xa0, 0x8f,
      0xaa, 0x39, 0x81, 0xcd, 0x83, 0x54, 0x42, 0x33, 0x11, 0x4a,
      0x3d, 0x85, 0xd6, 0xdf };


  if ( ssh_ppp_chap_generate_ntresponse(secret,secret_length,
                                        peer_challenge,peer_challenge_length,
                                        challenge, challenge_length,
                                        username, username_length,
                                        output_buf, 32) == FALSE )
    return FALSE;

  if (memcmp(output_buf, ntresponse,24) != 0)
    return FALSE;

  return TRUE;
}

static Boolean
test_des_expand(void)
{
  unsigned char raw_key[] = { 0xfc, 0x15, 0x6a, 0xf7, 0xed, 0xcd, 0x6c };
  unsigned char good_key[8] = { 0xfd, 0x0b, 0x5b, 0x5e,
                                0x7f, 0x6e, 0x34, 0xd9 };
  unsigned char out[8];
  int i;

  for (i = 0; i < 8; i++)
    good_key[i] &= 0xFE;

  ssh_ppp_chap_expand_des_key(out,raw_key);

  if (memcmp(good_key,out,8) == 0)
    return TRUE;
  return FALSE;
}

static Boolean
test_authenticator_response(void)
{
  unsigned char username[] = { 0x55, 0x73, 0x65, 0x72 };
  size_t username_length = 4;

  unsigned  char secret[] =
    { 0x63, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x65, 0x00, 0x6e, 0x00,
      0x74, 0x00, 0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00 };
  size_t secret_length = 20;

  unsigned char challenge[] =
    { 0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c,
      0x60, 0x21, 0x32, 0x26, 0x26, 0x28 };
  size_t challenge_length = 16;

  unsigned char peer_challenge[] =
    { 0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
      0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e };
  size_t peer_challenge_length = 16;

  unsigned char ntresponse[] =
    { 0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e, 0xa0, 0x8f,
      0xaa, 0x39, 0x81, 0xcd, 0x83, 0x54, 0x42, 0x33, 0x11, 0x4a,
      0x3d, 0x85, 0xd6, 0xdf };

  unsigned char good_response[] =
    { 0x40, 0x7a, 0x55, 0x89, 0x11, 0x5f, 0xd0, 0xd6, 0x20, 0x9f,
      0x51, 0x0f, 0xe9, 0xc0, 0x45, 0x66, 0x93, 0x2c, 0xda, 0x56 };



  unsigned char output_buf[32];

  if ( ssh_ppp_chap_generate_authenticator_response(
                                         secret,secret_length,
                                         peer_challenge,peer_challenge_length,
                                         challenge, challenge_length,
                                         username, username_length,
                                         ntresponse, 24,
                                         output_buf, 32) == FALSE )
    return FALSE;

  if (memcmp(output_buf,good_response,20) != 0)
    return FALSE;

  return TRUE;
}

int
main(int argc, char **argv)
{
  ssh_crypto_library_initialize();
  ssh_event_loop_initialize();
  
  if (test_des_expand() == TRUE)
    fprintf(stdout,"test_des_expand() test OK\n");
  else
    fprintf(stdout,"test_des_expand() test FAILED\n");

  if (test_ntresponse_v1() == TRUE)
    fprintf(stdout,"generate_ntresponse_v1() test OK\n");
  else
    fprintf(stdout,"generate_ntresponse_v1() test FAILED\n");

  if (test_ntresponse() == TRUE)
    fprintf(stdout,"generate_ntresponse() test OK\n");
  else
    fprintf(stdout,"generate_ntresponse() test FAILED\n");

  if (test_authenticator_response() == TRUE)
    fprintf(stdout,"generate_authenticator_response() test OK\n");
  else
    fprintf(stdout,"generate_authenticator_response() test FAILED\n");

  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();

  return 0;
}
