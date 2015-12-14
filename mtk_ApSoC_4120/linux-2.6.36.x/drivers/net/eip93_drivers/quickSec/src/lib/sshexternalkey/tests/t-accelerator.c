/*

t-accelerator.c

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
All rights reserved

Created: Mon Oct 25 17:11:56 1999 vsuontam
Last modified: Mon Dec 30 16:12:24 2002 vsuontam

An interactve test for externalkey. The test program adds two
providers to externalkey system and enables all the available
providers.

Authentication and notify callbacks are registered. Keys notified in
authentication callback are stored in a string mapped hash table. They
are fetched asynchronically in get_keys() and data is signed
asynchronically with them.

*/

#include "sshincludes.h"
#include "sshexternalkey.h"
#include "extkeyprov.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshcrypt.h"
#include "sshtimeouts.h"
#include "x509.h"
#include "sshfileio.h"
#include "sshgetopt.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "AcceleratorTest"

static Boolean accelerator_test = TRUE;
static SshUInt32 default_accelerated_encrypts = 100;
static SshUInt32 timeout_ms = 0;
static char *debug_level_string = "*=4";
static Boolean test_only_private_key = FALSE;
static Boolean test_signatures_only = FALSE;
static char *accelerator_init_str = "collect_random(500, 10)";
static Boolean continuous_test = FALSE;
void parse_arguments(int argc, char **argv)
{
  char opt;

  while ((opt = ssh_getopt(argc, argv, "d:ht:n:api:cs", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'c':
          continuous_test = TRUE;
          break;
        case 'n':
          default_accelerated_encrypts = atoi(ssh_optarg);
          break;

        case 'a':
          accelerator_test = FALSE;
          break;

        case 'p':
          test_only_private_key = TRUE;
          break;

        case 's':
          test_signatures_only = TRUE;
          break;

        case 't':
          timeout_ms = atoi(ssh_optarg);
          break;

        case 'd':
          debug_level_string = ssh_optarg;
          break;
        case 'i':
          accelerator_init_str = ssh_optarg;
          break;

        case 'h':
        case '?':
        default:
          /* the Usage. */
          printf("Test for Externalkey. Parameters: \n"
                 "-a Turn accelerator test OFF.\n"
                 "\tEncrypts and decrypts are done using normal "
                 "software keys\n"
                 "-n number of time to test the accelerator\n"
                 "-t set the timeout (in ms) between the encrypts\n"
                 "-i set the initialization string of the accelerator\n"
                 "-s run a signature and signature verification test\n"
                 "\t(default is 'collect_random(500, 10)')\n"
                 "-p Run a private key test only\n"
                 "-c Run continous test. Send USR1 to get statistics\n"
                 "-d set the debug level string");

          printf("\nDefaults are:\n");
          printf("Accelerator test: TRUE\n"
                 "Number of encrypts/decrypt to do: %ld\n"
                 "Timeout (ms) between encrypts: %ld\n",
                 default_accelerated_encrypts,
                 timeout_ms);

          exit(1);
        }
    }
}

SshPrivateKey get_prv_key(const char *name)
{
  unsigned char *buf;
  size_t buf_len;
  SshPrivateKey key;

  if (ssh_read_gen_file(name, &buf, &buf_len) == FALSE)
    {
      fprintf(stderr, "Can not read the private key file %s\n", name);
      exit(1);
    }

  key = ssh_x509_decode_private_key(buf, buf_len);
  if (key == NULL)
    {
      fprintf(stderr, "Could not decode the key from file %s\n", name);
      exit(1);
    }



  return key;
}


/* This is the context for the test. */
typedef struct SshExternalKeyTestCtxRec
{
  unsigned char *big_buf;
  size_t big_buf_len;
  SshExternalKey externalkey;
  size_t cipher_len;
  unsigned char *ciphertext;
  Boolean end_test;
  SshUInt32 signs_completed;
  SshPrivateKey *prv_keys;
  SshPublicKey *pub_keys;
  SshOperationHandle crypto_op;
  SshOperationHandle encrypt_op;
  SshOperationHandle cert_op;
  int num_prv_keys;
  int num_pub_keys;
  Boolean encrypt_ok;
  SshInt32 encrypts;
  SshPublicKey pub_key;
  SshPrivateKey prv_key;
  SshPublicKey acc_pub_key;
  SshPrivateKey acc_prv_key;
  SshUInt32 accelerated_encrypts_left;
  SshUInt32 accelerated_encrypts_pending;
  SshUInt32 accelerated_decrypts_pending;
  SshUInt32 operations_done;
  SshUInt32 operations_failed;
  SshTimeMeasure timer;
} *SshExternalKeyTestCtx;

static SshUInt32 next_op_id = 0;
typedef struct SshEKTestOpRec
{
  SshUInt32 op_id;
  SshExternalKeyTestCtx test_ctx;
  SshTimeMeasure timer;
} *SshEKTestOp;

void print_stats(SshExternalKeyTestCtx ctx)
{
  SshUInt64 s;
  SshUInt32 ms, sec;
  double ratio;

  ssh_time_measure_get_value(ctx->timer, &s, &ms);
  sec = (SshUInt32)s;
  ratio = (double)(ctx->operations_done)/
    ((SshInt64)s + ms / (double)1000000000);

  printf("Time consumed so far %ld secs and %ld ms.\n"
         "%ld operations completed (avg %f ops/sec) "
         "of which %ld have failed.\n",
         sec, ms, ctx->operations_done, ratio, ctx->operations_failed);
}


/* This stores all the keys to mapping in the context. */
void ssh_externalkey_notify_cb(SshEkEvent event,
                               const char *keypath,
                               const char *label,                              
                               SshEkUsageFlags flags,
                               void *context)
{
  SSH_DEBUG(10, ("Notify callback called. Keypath %s\nLabel %s",
                 keypath, label));

  if (event == SSH_EK_EVENT_PROVIDER_ENABLED)
    {
      SSH_DEBUG(9, ("Provider enabled"));
    }

  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      SSH_DEBUG(9, ("Key available"));
    }

  if (event == SSH_EK_EVENT_KEY_UNAVAILABLE)
    {
      SSH_DEBUG(9, ("Key unavailable"));

    }

  return;

}

/* Authentication callback is called when a PIN code is needed. This routine
   returns an operation handle, because this is an asynchronic operation.

   If the pending crypto operation is cancelled, then the abort callback of
   the returned handle is called. */
SshOperationHandle ssh_externalkey_authentication_cb(const char *keypath,
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

  scanf("%s", (char *)pin_buffer);

  i = strlen((char*)pin_buffer);
  reply_cb(pin_buffer, i, reply_context);
  return NULL;
}


void acc_decrypt_done(SshCryptoStatus status,
                      const unsigned char *data,
                      size_t length,
                      void *context)
{
  SshEKTestOp tc = context;
  SshExternalKeyTestCtx ctx = tc->test_ctx;
  ctx->operations_done++;

  SSH_DEBUG(2, ("Completed decrypt %d", tc->op_id));
  ssh_xfree(tc);
  if (status == SSH_CRYPTO_OK)
    {
      SSH_DEBUG_HEXDUMP(7, ("Decrypted data of len %d:",
                            length), data, length);
      if (memcmp(ctx->big_buf, data, length) != 0)
        ssh_fatal("Public encrypt or private decrypt failed, data mismatch");
    }
  else
    {
      SSH_DEBUG(1, ("Could not decrypt with the accelerated private key"));
      ctx->operations_failed++;
    }

  ctx->accelerated_decrypts_pending--;
  if (ctx->accelerated_encrypts_left == 0)
    {
      SSH_DEBUG(2, ("Pending decrypts %d",
                    ctx->accelerated_decrypts_pending));

      if (!continuous_test &&
          ctx->accelerated_decrypts_pending == 0)
        {
          SshUInt64 secs;
          SshUInt32 nanos;
          SshUInt32 s;
          ssh_time_measure_get_value(ctx->timer,
                                     &secs, &nanos);
          s = (SshUInt32)secs;
          SSH_DEBUG(1, ("Whole test completed in %ds and %dns", s, nanos));
          print_stats(ctx);
          exit(0);
        }
    }


}
void acc_encrypt_done(SshCryptoStatus status,
                      const unsigned char *data,
                      size_t length,
                      void *context)
{
  SshEKTestOp tc = context, ntc;
  SshExternalKeyTestCtx ctx = tc->test_ctx;
  SshPrivateKey key;
  SshUInt32 nanos;
  SshUInt64 secs;
  SshUInt32 s;

  ctx->operations_done++;
  ssh_time_measure_get_value(tc->timer,
                             &secs, &nanos);

  s = (SshUInt32)secs;
  key = accelerator_test ? ctx->acc_prv_key : ctx->prv_key;

  ctx->accelerated_encrypts_pending--;
  SSH_DEBUG(2, ("Completed encrypt %d", tc->op_id));
  SSH_DEBUG(3, ("Time %ds %dns", s, nanos));
  ssh_time_measure_free(tc->timer);
  ssh_xfree(tc);
  SSH_DEBUG_HEXDUMP(7, ("Encrypted data of len %d:", length), data, length);


  if (status == SSH_CRYPTO_OK)
    {
      SSH_DEBUG(10, ("Got the data of len %d", length));

      SSH_DEBUG(10, ("Accelerated encrypt succesfull"));
      ctx->accelerated_decrypts_pending++;
      ntc = ssh_xcalloc(1, sizeof(*ntc));

      ntc->op_id = next_op_id++;
      ntc->test_ctx = ctx;
      ssh_private_key_decrypt_async(key,
                                    data, length,
                                    acc_decrypt_done, ntc);
    }
  else
    {
      SSH_DEBUG(1, ("Accelerated encrypt unsuccesfull"));
      ctx->operations_failed++;
    }

}


/* Test to encrypt with the accelerated public key */
void test_acc_public_key(void *context)
{
  SshExternalKeyTestCtx ctx = context;
  SshEKTestOp test_ctx = ssh_xcalloc(1, sizeof(*test_ctx));
  SshPublicKey key;
  unsigned char *data = ctx->big_buf;
  size_t data_len = ctx->big_buf_len;

  key = accelerator_test ? ctx->acc_pub_key : ctx->pub_key;

  test_ctx->op_id = next_op_id++;
  test_ctx->test_ctx = ctx;

  test_ctx->timer = ssh_time_measure_allocate();
  ssh_time_measure_start(test_ctx->timer);
  ctx->accelerated_encrypts_pending++;
  ctx->accelerated_encrypts_left--;
  ssh_public_key_encrypt_async(key,
                               data,
                               data_len,
                               acc_encrypt_done, test_ctx);
  SSH_DEBUG_HEXDUMP(7, ("Encrypting data of len %d:", data_len),
                    data, data_len);

  if (ctx->accelerated_encrypts_left || continuous_test)
    {
      ssh_xregister_timeout(0, timeout_ms * 1000, test_acc_public_key, ctx);
    }
  else
    {
      SSH_DEBUG(2, ("All the encrypts send"));
    }

  SSH_DEBUG(2, ("Encrypts left %d, pending %d",
                ctx->accelerated_encrypts_left,
                ctx->accelerated_encrypts_pending));
}


void acc_prv_decrypt_done(SshCryptoStatus status,
                          const unsigned char *data,
                          size_t length,
                          void *context)
{
  SshExternalKeyTestCtx ctx = context;
  ctx->accelerated_encrypts_pending--;
  ctx->operations_done++;

  if (status == SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Completed private key decrypt succesfully.\n"
                    "Left: %d\n"
                    "Pending: %d",
                    ctx->accelerated_encrypts_left,
                    ctx->accelerated_encrypts_pending));
    }
  else
    {
      SSH_DEBUG(1, ("Decrypt failed."));
      ctx->operations_failed++;
    }
  if (!continuous_test &&
      ctx->accelerated_encrypts_left == 0 &&
      ctx->accelerated_encrypts_pending == 0)
    {
      SshUInt64 secs;
      SshUInt32 nanos;
      SshUInt32 s;
      ssh_time_measure_get_value(ctx->timer,
                                 &secs, &nanos);
      s = (SshUInt32)secs;
      SSH_DEBUG(1, ("Private key test completed in %ds and %dns", s, nanos));
      print_stats(ctx);
      exit(0);
    }
}

void test_acc_private_key(void *context)
{
  SshExternalKeyTestCtx ctx = context;
  SshPrivateKey key;

  key = accelerator_test ? ctx->acc_prv_key : ctx->prv_key;

  ctx->accelerated_encrypts_pending++;
  ctx->accelerated_encrypts_left--;
  SSH_DEBUG(2, ("Doing decrypt with the private key."));
  ssh_private_key_decrypt_async(key,
                                ctx->big_buf,
                                ctx->big_buf_len,
                                acc_prv_decrypt_done,
                                ctx);
  if (ctx->accelerated_encrypts_left || continuous_test)
    {
      ssh_xregister_timeout(0, timeout_ms * 1000,
                            test_acc_private_key,
                            ctx);
    }
}

#define PLAIN_TEXT "'Please sign this.aaaaabbbbbcccccddddd'"

void acc_verify_done(SshCryptoStatus status,
                     void *context)
{
  SshExternalKeyTestCtx ctx = context;

  ctx->accelerated_decrypts_pending--;
  ctx->operations_done++;
  if (status != SSH_CRYPTO_OK)
    ctx->operations_failed++;

  if (!continuous_test &&
      ctx->accelerated_encrypts_left == 0 &&
      ctx->accelerated_decrypts_pending == 0)
    {
      SshUInt64 secs;
      SshUInt32 nanos;
      SshUInt32 s;
      ssh_time_measure_get_value(ctx->timer,
                                 &secs, &nanos);
      s = (SshUInt32)secs;
      SSH_DEBUG(1, ("Signature test completed in %ds and %dns", s, nanos));
      print_stats(ctx);
      exit(0);
    }
}

void acc_prv_sign_done(SshCryptoStatus status,
                       const unsigned char *data,
                       size_t length,
                       void *context)
{
  SshExternalKeyTestCtx ctx = context;
  SshPublicKey key;

  ctx->accelerated_encrypts_pending--;
  ctx->operations_done++;

  key = accelerator_test ? ctx->acc_pub_key : ctx->pub_key;

  if (status == SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Completed private sign succesfully.\n"
                    "Left: %d\n"
                    "Pending: %d",
                    ctx->accelerated_encrypts_left,
                    ctx->accelerated_encrypts_pending));
      ctx->accelerated_decrypts_pending++;
      ssh_public_key_verify_async(key,
                                  data, length,
                                  (unsigned char *)PLAIN_TEXT,
                                  strlen(PLAIN_TEXT) + 1,
                                  acc_verify_done,
                                  ctx);
    }
  else
    {
      SSH_DEBUG(1, ("sign failed."));
      ctx->operations_failed++;
    }

}

void test_acc_private_key_sign(void *context)
{
  SshExternalKeyTestCtx ctx = context;
  SshPrivateKey key;

  key = accelerator_test ? ctx->acc_prv_key : ctx->prv_key;

  ctx->accelerated_encrypts_pending++;
  ctx->accelerated_encrypts_left--;
  SSH_DEBUG(2, ("Doing encrypt with privatekey."));
  ssh_private_key_sign_async(key,
                             (unsigned char *)
                             PLAIN_TEXT,
                             strlen(PLAIN_TEXT) + 1,
                             acc_prv_sign_done,
                             ctx);
  if (ctx->accelerated_encrypts_left || continuous_test)
    {
      ssh_xregister_timeout(0, timeout_ms * 1000,
                            test_acc_private_key_sign,
                            ctx);
    }
}


void test_keys(void *context)
{
  SshExternalKeyTestCtx ctx = context;
  ssh_time_measure_start(ctx->timer);

  if (test_signatures_only)
    {
      test_acc_private_key_sign(context);
    }
  else
    if (test_only_private_key)
      test_acc_private_key(context);
    else
      test_acc_public_key(context);
}


void  get_acc_prv_key_cb(SshEkStatus status,
                         SshPrivateKey key,
                         void *context)
{
  SshExternalKeyTestCtx ctx = context;
  if (status == SSH_EK_OK)
    {
      ctx->acc_prv_key = key;
      SSH_DEBUG(10, ("Got the accelerated private key\n"
                     "Starting the test the accelerated key."));
      ssh_xregister_timeout(0, 1, test_keys, ctx);
    }

}

/* Is called when an accelerated key is got. */
void get_accelerated_pub_key_cb(SshEkStatus status,
                                SshPublicKey key,
                                void *context)
{
  SshExternalKeyTestCtx ctx = context;

  if (status == SSH_EK_OK)
    {
      ctx->acc_pub_key = key;
      SSH_DEBUG(10, ("Got the accelerated public key"));
    }

}

static void test_ek_add(SshExternalKeyTestCtx ctx)
{
  SshExternalKey externalkey;
  SshUInt32 num_providers;
  int i;
  SshEkProvider provider_array;
  const char *accelerator_name = NULL;
  const char *short_name;

  externalkey = ssh_ek_allocate();
  ctx->externalkey = externalkey;

  /* Register authentication and notify callbacks. */
  ssh_ek_register_notify(externalkey, ssh_externalkey_notify_cb, ctx);

  ssh_ek_register_authentication_callback(externalkey,
                                          ssh_externalkey_authentication_cb,
                                          ctx);




  ssh_ek_add_provider(externalkey, "soft-accelerator", accelerator_init_str,
                      NULL, SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR, NULL);


  /* Get the information about installed providers. */
  ssh_ek_get_providers(externalkey,
                       &provider_array,
                       &num_providers);


  /* get all know providers. */
  for (i = 0; i < num_providers; i++)
    {
      short_name = (provider_array[i]).short_name;

      /* Test if we have accelerators. */
      if ((provider_array[i]).provider_flags &
          SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR)
        accelerator_name = short_name;
    }

  ssh_xfree(provider_array);

  if (accelerator_name)
    {
      /* Try_Number to get an accelerated key from an crypto accelerator. */
      ssh_ek_generate_accelerated_public_key(externalkey,
                                             accelerator_name,
                                             ctx->pub_key,
                                             get_accelerated_pub_key_cb,
                                             ctx);
      ssh_ek_generate_accelerated_private_key(externalkey,
                                              accelerator_name,
                                              ctx->prv_key,
                                              get_acc_prv_key_cb,
                                              ctx);
    }
}


void test_signal_handler(int sign, void *context)
{
  SshExternalKeyTestCtx ctx = context;

  printf("Received signal %d.\n", sign);
  print_stats(ctx);
}

int main(int argc, char **argv)
{
  SshExternalKeyTestCtx test_ctx;
  int i;
  SshPrivateKey prv_key;
  SshPublicKey pub_key;
  SshMPInteger n;

  parse_arguments(argc, argv);

  ssh_pk_provider_register(&ssh_pk_if_modn_generator);
  /* Initialize the event loop and the test context. */
  ssh_event_loop_initialize();
  ssh_debug_set_level_string(debug_level_string);

  ssh_global_init();
  /* Initialize the crypto library. */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");

  test_ctx = ssh_xcalloc(1, sizeof(*test_ctx));
  test_ctx->accelerated_encrypts_left = default_accelerated_encrypts;
  test_ctx->timer = ssh_time_measure_allocate();

  SSH_DEBUG(3, ("Reading the test key. Please wait...."));

  prv_key = get_prv_key("accelerator-test.prv");

  if (ssh_private_key_select_scheme(prv_key,
                                    SSH_PKF_ENCRYPT, "rsa-none-none",
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Could not select the scheme for private key");



  if (ssh_private_key_derive_public_key(prv_key, &pub_key)
      != SSH_CRYPTO_OK)
    {
      ssh_fatal("Can not derive a public key from a "
                "stored private key");
    }

  if (ssh_public_key_select_scheme(pub_key,
                                   SSH_PKF_ENCRYPT, "rsa-none-none",
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Could not select the scheme for public key");



  n = ssh_mprz_malloc();

  /* Get information about the RSA key. E and N are needed for nFast. */
  if (ssh_public_key_get_info(pub_key,
                              SSH_PKF_MODULO_N, n,
                              SSH_PKF_END)
      != SSH_CRYPTO_OK)
    {
      return FALSE;
    }


#if 0
  n_bytes = (ssh_mprz_get_size(n, 2) + 7) / 8;
  if (n_bytes == 0 || (n_bytes & 3) != 0)
    n_bytes += (4 - (n_bytes & 3));

  test_ctx->big_buf = ssh_xmalloc(n_bytes);
  test_ctx->big_buf_len = n_bytes;

  ssh_mprz_get_buf(test_ctx->big_buf, test_ctx->big_buf_len, n);
  ssh_mprz_free(n);
  test_ctx->big_buf_len = 128;
  test_ctx->big_buf[0] = 1;
#else
#if 0
  n_bytes = ssh_mprz_get_size(n, 8);
  test_ctx->big_buf = ssh_xmalloc(n_bytes);
  test_ctx->big_buf_len = n_bytes;
  ssh_mprz_init(&r);
  ssh_mprz_rand(&r, n_bytes * 8);
  ssh_mprz_mod(&r, &r, n);
  ssh_mprz_get_buf(test_ctx->big_buf, test_ctx->big_buf_len, &r);
  ssh_mprz_free(n);
  ssh_mprz_clear(&r);
#else
  test_ctx->big_buf = ssh_xmalloc(129);
  test_ctx->big_buf_len = 129;
  memcpy(test_ctx->big_buf,
         "\x00\x50\xe7\x85\x86\x40\xf8\x9b"
         "\xb8\xeb\x19\x64\xd8\x51\x33\xd7"
         "\x4f\xac\x32\x5d\x03\x66\x3d\x0c"
         "\xbe\xfd\x40\x29\x82\xb7\x61\x09"
         "\x15\x37\x4f\xe1\xd0\x57\xb0\x6d"
         "\x16\x49\x73\x25\x20\x3d\xa8\xfa"
         "\xf6\xb4\x72\xec\x75\xc8\x42\xc7"
         "\x99\x64\x63\x23\x29\xe0\x65\xa1"
         "\x2a\xc2\xb7\xf1\x5b\xb4\x9b\x30"
         "\xdb\xc7\x22\xb9\xf9\xde\xb5\x09"
         "\xb5\xe0\x0a\xca\xc5\xf9\xaf\x8f"
         "\x54\xf2\x9a\x06\x2b\xc1\xc2\x65"
         "\x87\xb3\xd5\xec\xd3\x8a\x2f\xa7"
         "\x5f\x69\x34\xe7\x7f\xeb\xaf\x56"
         "\x3c\x3d\x71\x3f\x73\xba\x8b\xa7"
         "\xd3\xe5\x6d\x98\xc8\x01\x6b\x18"
         "\x14",
         129);
#endif
#endif

  test_ctx->pub_key = pub_key;
  test_ctx->prv_key = prv_key;

  test_ek_add(test_ctx);
#ifndef WIN32
  ssh_register_signal(SIGUSR1, test_signal_handler, test_ctx);
#endif
  ssh_event_loop_run();

  /* Uninitialize. */
  for (i = 0; i < test_ctx->num_prv_keys; i++)
    ssh_private_key_free(test_ctx->prv_keys[i]);

  for (i = 0; i < test_ctx->num_pub_keys; i++)
    ssh_public_key_free(test_ctx->pub_keys[i]);


  ssh_xfree(test_ctx->prv_keys);
  ssh_xfree(test_ctx->pub_keys);
  ssh_xfree(test_ctx);
  return 0;
}
