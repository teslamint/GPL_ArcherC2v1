/*

t-externalcert.c 

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
All rights reserved


Created Wed Apr 12 10:38:33 2000. 

This simple utility can be used to retrieve certificates from an 
external key provider. 

*/


#include "sshincludes.h"
#include "sshexternalkey.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshcrypt.h"
#include "sshtimeouts.h"
#include "x509.h"
#include "sshfileio.h"
#include "sshadt.h"
#include "sshadt_strmap.h"
#define SSH_DEBUG_MODULE "GetEKCert"

static char *initialization_string = "";
static char *provider_type = NULL;
static char *ok_keypath = NULL;
static char *debug_level_string = "*=4";
static SshExternalKey externalkey = NULL;
static int cert_counter = 0;
static SshADTContainer disabled_labels;


void print_usage()
{
  printf("Parameters:\n"
         "-t <type> The externalkey provider type.\n"
         "-T <disable_token_name> Disable Token with name.\n"
         "-i Initialization string for the externalkey provider.\n"
         "-k keypath to use.\n"
         "\t(If not specified, uses the first availeble key.)\n"
         "-d Set the debug level string.\n");

}
#define _PARAMETER_STRING "t:i:k:d:T:"

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
        case 'i':
          initialization_string = ssh_optarg;
          break;
        case 'k':
          ok_keypath = ssh_optarg;
          break;
        case 'T':
          ssh_adt_strmap_add(disabled_labels, ssh_optarg, NULL);
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

Boolean is_disabled(const char *str)
{
  char *key_path = 0;
  SshADTHandle handle;

  if (str == NULL)
    return FALSE;

  for (handle = ssh_adt_enumerate_start(disabled_labels);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(disabled_labels, handle))
    {
      key_path = ssh_adt_get(disabled_labels, handle);
      if (strcmp(str, key_path) == 0)
        return TRUE;
    } 
  return FALSE;
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
                 "Keypath %s\nLabel '%s'", keypath, label));

  if (!is_disabled(label))
    {
      printf("(Warning: Your PIN will be visible)\n"
             "PIN CODE for '%s' please:", label);

      scanf("%s", pin_buffer);

      i = strlen(pin_buffer);
      reply_cb(pin_buffer, i, reply_context);
    }
  else
    {
      if (label)
        printf("Label %s disabled", label);
      (*reply_cb)(NULL, 0, reply_context);
    }
  return NULL;
}

typedef struct SshGetCertRec
{
  int cert_index;
  char *keypath;
} *SshGetCert;

void get_certificate_cb(SshEkStatus status,
                        const unsigned char *data,
                        size_t data_len,
                        void *context)
{

  SshGetCert ctx = context;
  if (status == SSH_EK_OK)
    {
      char fname[100];

      ssh_snprintf(fname, sizeof(fname),
                   "cert-%d.bin", cert_counter++);
      printf("Writing %s.", fname);
      ssh_write_gen_file(fname, SSH_PEM_GENERIC, data, data_len);
      ssh_ek_get_certificate(externalkey,
                             ctx->keypath,
                             ++ctx->cert_index, 
                             get_certificate_cb,
                             ctx);
    }
  else
    {
      ssh_xfree(ctx->keypath);
      ssh_xfree(ctx);
    }
  
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
      SshGetCert context = ssh_xcalloc(1, sizeof(*context));
      context->keypath = ssh_xstrdup(keypath);
      context->cert_index = 0;

      if (ok_keypath == NULL ||
          strcmp(keypath, ok_keypath) == 0)
        ssh_ek_get_certificate(externalkey,
                               keypath,
                               context->cert_index, 
                               get_certificate_cb,
                               context);
    }

  if (event == SSH_EK_EVENT_KEY_UNAVAILABLE)
    {
      SSH_DEBUG(9, ("Key unavailable"));
    }
  if (event == SSH_EK_EVENT_PROVIDER_FAILURE)
    {
      printf("Provider failure: %s\n", label);
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




/* This will end the test when nothing is happening. */
void end_make(void *context)
{
  static int counter = 0;
  if (++counter == 10)
    {
      printf("Test ended.\n");
      ssh_event_loop_abort();
    }
  else
    {
      ssh_xregister_timeout(1, 0, end_make, NULL);
      printf(".");
    }
}

void misc_init()
{
  disabled_labels = ssh_adt_create_strmap();
}

int main(int argc, char **argv)
{
  misc_init();
  
  parse_arguments(argc, argv);

  if (provider_type == NULL)
    {
      printf("You have to specify a provider type.\n");
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

