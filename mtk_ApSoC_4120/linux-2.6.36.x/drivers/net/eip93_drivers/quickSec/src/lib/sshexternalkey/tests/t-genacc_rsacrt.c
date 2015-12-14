
/*
  File: t-rsacrt.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved

  Consistency test program for the RSA CRT operations when used by the 
  genacc externalkey provider.

*/


#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshexternalkey.h"
#include "genaccprov.h"
#include "sshglobals.h"
#include "ssheloop.h"
#include "sshoperation.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshEkTGenaccRSACRT"


/*************************** RSA CRT TEST ***************************/


static SshUInt32 iterations = 100;
static SshUInt32 iteration = 0;
static unsigned int key_size = 1024;

static unsigned char data[512];
static SshPrivateKey crt_key = NULL;
static SshPrivateKey exp_key = NULL;
static SshExternalKey externalkey = NULL;

static unsigned char *crt_sig = NULL;
static unsigned char *exp_sig = NULL;
static size_t crt_sig_len = 0;
static size_t exp_sig_len = 0;

static void do_test(void *context);

void crt_sign_callback(SshCryptoStatus status,
		       const unsigned char *signature_buffer,
		       size_t signature_buffer_len,
		       void *context)
{
  if (status != SSH_CRYPTO_OK)
    ssh_fatal("signature operation failed with status %s",
	      ssh_crypto_status_message(status));

  crt_sig_len = signature_buffer_len;
  crt_sig = ssh_xmemdup(signature_buffer, signature_buffer_len);

  SSH_DEBUG_HEXDUMP(6, ("RSA CRT signature"), crt_sig, crt_sig_len);

  /* Verify the signatures are identical */
  if (exp_sig)
    {
      if ((exp_sig_len != crt_sig_len) ||
	  memcmp(crt_sig, exp_sig, exp_sig_len))
	{
	  SSH_DEBUG_HEXDUMP(0, ("Modexp signature"), exp_sig, exp_sig_len);
	  SSH_DEBUG_HEXDUMP(0, ("RSA CRT signature"), crt_sig, crt_sig_len);
	  ssh_fatal("Test failed on iteration %d", iteration);
	}

      ssh_xfree(crt_sig);
      ssh_xfree(exp_sig);
      crt_sig = NULL;
      exp_sig = NULL;

      ssh_xregister_timeout(0, 0, do_test, NULL);
    }
}


void exp_sign_callback(SshCryptoStatus status,
		   const unsigned char *signature_buffer,
		   size_t signature_buffer_len,
		   void *context)
{
  if (status != SSH_CRYPTO_OK)
    ssh_fatal("signature operation failed with status %s",
	      ssh_crypto_status_message(status));

  exp_sig_len = signature_buffer_len;
  exp_sig = ssh_xmemdup(signature_buffer, signature_buffer_len);

  SSH_DEBUG_HEXDUMP(6, ("Modexp signature"), exp_sig, exp_sig_len);

  if (crt_sig)
    {
      if ((exp_sig_len != crt_sig_len) ||
	  memcmp(crt_sig, exp_sig, exp_sig_len))
	{
	  SSH_DEBUG_HEXDUMP(0, ("Modexp signature"), exp_sig, exp_sig_len);
	  SSH_DEBUG_HEXDUMP(0, ("RSA CRT signature"), crt_sig, crt_sig_len);
	  ssh_fatal("Test failed on iteration %d", iteration);
	}

      ssh_xfree(crt_sig);
      ssh_xfree(exp_sig);
      crt_sig = NULL;
      exp_sig = NULL;

      ssh_xregister_timeout(0, 0, do_test, NULL);
    }
}

static void ek_free_cb(void *context)
{
  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  
  ssh_util_uninit();
  exit(0);
}

static void do_test(void *context)
{
  int i;

  SSH_DEBUG(7, ("On test iteration %d", iteration));

  if (iteration++ == iterations)
    {
      SSH_DEBUG(4, ("Test completed, free data"));
      ssh_private_key_free(exp_key);
      ssh_private_key_free(crt_key);

#ifdef HAVE_THREADS
      ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */
      ssh_ek_free(externalkey, ek_free_cb, NULL);
      return;
    }

  /* Generate random data to be signed */
  for (i = 0; i < sizeof(data); i++)
    data[i] = ssh_random_get_byte();

  SSH_ASSERT(exp_key != NULL);
  SSH_ASSERT(crt_key != NULL);

  /* Sign the same data with the two accelerated keys. One method will use 
     RSA CRT, the other will use plain modexp. Since the signature scheme is
     "rsa-pkcs1-sha1", the output signature is deterministic in terms of the 
     input private key and the data to be signed. The resulting signature 
     can then be compared to check that accelerated RSA CRT is the same as 
     accelerated modexp. */

  SSH_DEBUG(5, ("Sign the data using the modexp accelerated key"));
  ssh_private_key_sign_async(exp_key,
			     data, sizeof(data),
			     exp_sign_callback,
			     NULL);
  SSH_DEBUG(5, ("Sign the data using the rsa crt accelerated key"));
  ssh_private_key_sign_async(crt_key,
			     data, sizeof(data),
			     crt_sign_callback,
			     NULL);

} 


void get_exp_private_key_cb(SshEkStatus status,
			    SshPrivateKey private_key_return,
			    void *context)
{
  SSH_ASSERT(status == SSH_EK_OK);
  SSH_ASSERT(exp_key == NULL);

  /* Save the accelerated key */
  exp_key = private_key_return;

  /* Commence the test both accelerated keys are now derived */
  if (crt_key)
    ssh_xregister_timeout(0, 0, do_test, NULL);
}

void get_crt_private_key_cb(SshEkStatus status,
			    SshPrivateKey private_key_return,
			    void *context)
{
  SSH_ASSERT(status == SSH_EK_OK);
  SSH_ASSERT(crt_key == NULL);

  /* Save the accelerated key */
  crt_key = private_key_return;

  /* Commence the test both accelerated keys are now derived */
  if (exp_key)
    ssh_xregister_timeout(0, 0, do_test, NULL);
}

void usage()
{
  printf("Usage: t-rsacrt [options] device-name\n"
         "-i device info\n"
         "-b key size (in bits) to test with\n"
         "-n test iterations\n"
         "-d debuglevel\n");
}

int main(int ac, char **av)
{
  SshUInt32 num_providers;
  SshEkStatus status;
  SshCryptoStatus stat;
  SshEkProvider provider_array;
  SshPrivateKey prv;
  int opt;
  char *expmod_provider_name, *rsacrt_provider_name, *init_str;
  char *device_name = NULL, *device_info = NULL;

  while ((opt = ssh_getopt(ac, av, "n:d:i:b:", NULL)) != EOF)
    {
      switch (opt)
        {
	case 'b':
	  key_size = atoi(ssh_optarg);
	  break;
        case 'n':
          iterations = atoi(ssh_optarg);
          break;
        case 'i':
          device_info = ssh_optarg;
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        default:
        case 'h':
          usage();
          exit(1);
        }
    }
  ac -= ssh_optind;
  av += ssh_optind;

  device_name = *av;
  
  if (device_name == NULL)
    {
#ifdef DEBUG_LIGHT
      device_name = "dummy";
#else /* DEBUG_LIGHT */
      return 0;
#endif /* DEBUG_LIGHT */
    }
  
  ssh_event_loop_initialize();

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_init();
#endif /* HAVE_THREADS */

  externalkey = ssh_ek_allocate();

  /* Initialize the crypto library. */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");

  ssh_dsprintf((unsigned char **)&init_str, 
	       "name(%s),device-info(%s),rsa-crt(yes)", 
               device_name, device_info);
  
  SSH_DEBUG(4, ("The init string is %s\n", init_str));

  /* Add the provider which performs RSA CRT operations */
  if ((status = ssh_ek_add_provider(externalkey, "genacc",
                                    init_str,
                                    NULL,
                                    SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                    NULL)) != SSH_EK_OK)
    ssh_fatal("Cannot add the provider");
  ssh_free(init_str);

  ssh_dsprintf((unsigned char **)&init_str,
	       "name(%s),device-info(%s),rsa-crt(no)", 
               device_name, device_info);
  
  SSH_DEBUG(4, ("The init string is %s\n", init_str));

   /* Add the provider which will not perform RSA CRT operations */
  if ((status = ssh_ek_add_provider(externalkey, "genacc",
                                    init_str,
                                    NULL,
                                    SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                    NULL)) != SSH_EK_OK)
    ssh_fatal("Cannot add the provider");
  ssh_free(init_str);

  /* Get all the registered providers. */
  if (!ssh_ek_get_providers(externalkey, &provider_array, &num_providers))
    ssh_fatal("Cannot get the providers");

  SSH_ASSERT(num_providers == 2);

  rsacrt_provider_name = (char *) (provider_array[0]).short_name;
  expmod_provider_name = (char *) (provider_array[1]).short_name;

  ssh_free(provider_array);
  
  /* Generate a private key. */
  stat = ssh_private_key_generate(&prv, "if-modn",
				  SSH_PKF_SIZE, key_size,
				  SSH_PKF_SIGN, "rsa-pkcs1-sha1",
				  SSH_PKF_END);
  SSH_ASSERT(stat == SSH_CRYPTO_OK);
  
  /* Get accelerated private keys */

  ssh_ek_generate_accelerated_private_key(externalkey,
					  expmod_provider_name,
					  prv,
					  get_exp_private_key_cb,
					  NULL);
  
  ssh_ek_generate_accelerated_private_key(externalkey,
					  rsacrt_provider_name,
					  prv,
					  get_crt_private_key_cb,
					  NULL);
  
 
  ssh_private_key_free(prv);

  ssh_event_loop_run();

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */

  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  return 0;
}



