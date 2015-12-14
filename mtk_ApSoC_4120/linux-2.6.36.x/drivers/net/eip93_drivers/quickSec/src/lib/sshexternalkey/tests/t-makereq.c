/*

  t-makereq.c

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved


  Created Wed Apr 12 10:38:33 2000.

  This simple utility can be used to create certificate requests for
  public keys that are on hard drive (in the for of SSH public key)
  and the keys that are externalkey provider keys.

*/


#include "sshincludes.h"
#include "sshexternalkey.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshtimeouts.h"
#include "x509.h"
#include "sshfileio.h"

#define SSH_DEBUG_MODULE "MakeEKRequest"

static char *input_file = "pubkey.pem";
static char *initialization_string = "";
static char *provider_type = NULL;
static char *ok_keypath = NULL;
static char *subject_name = "CN = Hardware key";
static char *debug_level_string = "*=4";
static SshPublicKey pubkey = NULL;
static SshUInt32 counter = 0;
static SshExternalKey externalkey;
static char *output_file = ":p:output.req";


void print_usage()
{
  printf("Parameters:\n"
         "-t <type> The externalkey provider type.\n"
         "-i Initialization string for the externalkey provider.\n"
         "-k keypath to use.\n"
         "\t(If not specified, uses the first availeble key.)\n"
         "-s <subject_name> Set the subject name of the request.\n"
         "\t(If not specified, will use 'CN=Hardware key'.)\n"
         "-p <input_file> Input public key file.\n"
         "\t(If not specified, will use pubkey.pem.)\n"
         "-o <output_file> Specify the output file.\n"
         "\t(If not specified, will use output.req.)\n"
         "-d Set the debug level string.\n");

}
#define _PARAMETER_STRING "t:i:k:s:d:o:p:"

void parse_arguments(int argc, char **argv)
{
  char opt;

  while ((opt = ssh_getopt(argc, argv, _PARAMETER_STRING, NULL)) != EOF)
    {
      switch (opt)
        {
        case 't':
          provider_type = ssh_optarg;
          break;
        case 'o':
          output_file = ssh_optarg;
          break;
        case 'i':
          initialization_string = ssh_optarg;
          break;
        case 'k':
          ok_keypath = ssh_optarg;
          break;
        case 's':
          subject_name = ssh_optarg;
          break;
        case 'p':
          input_file = ssh_optarg;
          break;
        case 'd':
          debug_level_string = ssh_optarg;
          break;

        case 'h':
        case '?':
        default:
          /* the Usage. */
          print_usage();
          exit(1);
        }
    }
}



/* Authentication callback is called when a PIN code is needed. This routine
   returns an operation handle, because this is an asynchronic operation.

   If the pending crypto operation is cancelled, then the abort callback of
   the returned handle is called. */
SshOperationHandle authentication_cb(const char *keypath,
                                     const char *label,
                                     SshUInt32 try_number,
                                     SshEkAuthenticationStatus
                                     authentication_status,
                                     SshEkAuthenticationReplyCB
                                     reply_cb,
                                     void *reply_context,
                                     void *context)
{
  unsigned char pin_buffer[100];
  int i = 0;

  SSH_DEBUG(10, ("Authentication callback called.\n"
    "Keypath %s\nLabel %s", keypath, label));
  printf("(Warning: Your PIN will be visible)\n"
    "PIN CODE for %s please:", label);

  scanf("%s", pin_buffer);

  i = strlen(pin_buffer);
  reply_cb(pin_buffer, i, reply_context);
  return NULL;
}

void encode_async_cb(SshX509Status status,
                     const unsigned char *buf_return,
                     size_t buf_return_len,
                     void *context)
{
  if (status != SSH_X509_OK)
    {
      printf("Could not encode the certificate.\n");
      exit(1);
    }

  if (ssh_write_gen_file(output_file,
                     SSH_PEM_CERT_REQ,
                     buf_return,
                     buf_return_len) == FALSE)
    {
      printf("Could not write the file %s.\n", output_file);
      exit(1);
    }

  /* success. */
  printf("Certificate request wrote to %s.\n", output_file);
  ssh_event_loop_abort();
}

void get_private_key_cb(SshEkStatus status,
                        SshPrivateKey key,
                        void *context)
{
  SshX509Certificate c;

  if (status == SSH_EK_OK)
    {
      c = ssh_x509_cert_allocate(SSH_X509_PKCS_10);
      ssh_x509_cert_set_public_key(c, pubkey);
      ssh_x509_cert_set_subject_name(c, subject_name);

      ssh_x509_cert_encode_async(c, key,
                                 encode_async_cb,
                                 NULL);
      return;
    }
  printf("Could not generate the key.\n");
  exit(1);
}


void notify_cb(SshEkEvent event,
               const char *keypath,           
               const char *label,
               SshEkUsageFlags flags,
               void *context)
{
  SshExternalKey externalkey = context;

  SSH_DEBUG(10, ("Notify callback called."
                 "Keypath %s\nLabel %s", keypath, label));


  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      if (ok_keypath == NULL ||
          strcmp(keypath, ok_keypath) == 0)
        ssh_ek_get_private_key(externalkey,
                               keypath,
                               get_private_key_cb,
                               NULL);
    }

  if (event == SSH_EK_EVENT_KEY_UNAVAILABLE)
    {
      SSH_DEBUG(9, ("Key unavailable"));

    }

  return;
}


static void test_ek_add(void)
{
  externalkey = ssh_ek_allocate();
  /* Register authentication and notify callbacks. */
  ssh_ek_register_notify(externalkey, notify_cb, externalkey);

  ssh_ek_register_authentication_callback(externalkey,
                                          authentication_cb,
                                          externalkey);

  ssh_ek_add_provider(externalkey, provider_type,
                      initialization_string, NULL, 0, NULL);
}




/* This will end the test if nothing is happening. */
void end_make(void *context)
{
  if (++counter == 5)
    {
      printf("No suitable key found.\n");
      ssh_event_loop_abort();
    }
  else
    {
      ssh_xregister_timeout(1, 0, end_make, NULL);
      printf(".");
    }
}

int main(int argc, char **argv)
{
  unsigned char *buf;
  size_t len;
  Boolean pub_key_ok = TRUE;

  parse_arguments(argc, argv);

  if (provider_type == NULL)
    {
      printf("You have to specify a provider type.\n");
      exit(1);
    }

  /* try first PEM. */
  if (ssh_read_file_base64(input_file,
                           &buf,
                           &len) == FALSE)
    {
      if (ssh_read_gen_file(input_file,
                            &buf,
                            &len) == FALSE)
        {
          printf("Can not read the input file %s.\n", input_file);
          exit(1);
        }
    }

  printf("Trying to decode the data as pubic key.\n");
  pub_key_ok = ssh_public_key_import(buf, len, &pubkey) == SSH_CRYPTO_OK;
  if (!pub_key_ok)
    {
      SshX509Certificate c;

      printf("Trying to decode the data as certificate.\n");
      c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      pub_key_ok = ssh_x509_cert_decode(buf, len, c) == SSH_X509_OK;
      pub_key_ok = ssh_x509_cert_get_public_key(c, &pubkey) == TRUE;

    }

  if (!pub_key_ok)
    {
      SshX509Certificate c;

      printf("Trying to decode the data as certificate request.\n");
      c = ssh_x509_cert_allocate(SSH_X509_PKCS_10);
      pub_key_ok = ssh_x509_cert_decode(buf, len, c) == SSH_X509_OK;
      pub_key_ok = ssh_x509_cert_get_public_key(c, &pubkey) == SSH_X509_OK;
    }

  if (!pub_key_ok)
    {
      printf("Could not decoe the public key from file %s.", input_file);
      exit(1);
    }

  ssh_event_loop_initialize();
  test_ek_add();

  ssh_xregister_timeout(2, 0, end_make, NULL);
  ssh_event_loop_run();
  ssh_ek_free(externalkey, NULL_FNPTR, NULL); 
  ssh_event_loop_uninitialize();
  return 0;
}
