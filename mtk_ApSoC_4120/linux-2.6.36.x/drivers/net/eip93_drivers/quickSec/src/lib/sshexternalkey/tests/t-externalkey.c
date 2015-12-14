/*
t-externalkey.c

  Copyright:
          Copyright (c) 2002-2007 SFNT Finland Oy.
                   All rights reserved

Created: Mon Oct 25 17:11:56 1999 vsuontam
Last modified: Thu Sep 26 10:37:24 2002 vsuontam

An interactve test for externalkey.

Authentication and notify callbacks are registered. Keys notified in
authentication callback are stored in a string mapped hash table. They
are fetched asynchronically in get_keys() and data is signed
asynchronically with them.

*/

#include "sshincludes.h"
#include "sshexternalkey.h"
#include "extkeyprov.h"
#include "ssheloop.h"
#include "sshcrypt.h"
#include "sshtimeouts.h"
#include "x509.h"
#include "sshfileio.h"
#include "sshgetopt.h"
#include "sshadt.h"
#include "sshadt_strmap.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "ExternalKeyTest"

#define TEST_STR "This will be encrypted and decrypted"
static char *debug_level_string = "*=4,SshEKN*=9,ExternalKeyTest*=10,SshPK*=8"
                                  ",SshEKPKCS11=10";
static Boolean test_async_pin = TRUE;
static Boolean abort_operations = FALSE;
static char *initialization_string = "";
static char *provider_type = "smartcard";
static SshUInt32 operations_to_test = 3;
static SshUInt32 timeout_sec = 60;
static Boolean register_sigint = FALSE;
static char *debug_output_file = NULL;
static char *default_pin = NULL;


void print_usage(void)
{
  printf("Parameters:\n"
         "-t <type> The externalkey provider type.\n"
         "\t(e.g 'smartcard')\n"
         "-i <init_str> Itialization string for the externalkey provider.\n"
         "-p <default_pin> Give the default PIN.\n"
         "\t(e.g 'reader(setec, /dev/tty00), card(setec)'"
         "-n <num> Number of signs to perform before ending the test.\n"
         "\t(If not specified, this is 2.)\n"
         "-a Ask PIN synchronously.\n"
         "-m <timeout_sec> Minimum timeout before ending the test.\n"
         "-b Abort crypto operations.\n"
         "-f file direct debug output to a file.\n"
         "-d Set the debug level string.\n");

}


void parse_arguments(int argc, char **argv)
{
  char opt;

  while ((opt = ssh_getopt(argc, argv, "m:t:i:bad:hn:sf:p:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'p':
          default_pin = ssh_optarg;
          break;
        case 'f':
          debug_output_file = ssh_optarg;
          break;
        case 's':
          register_sigint = TRUE;
          break;
        case 'm':
          timeout_sec = atoi(ssh_optarg);
          break;
        case 't':
          provider_type = ssh_optarg;
          break;
        case 'i':
          initialization_string = ssh_optarg;
          break;
        case 'a':
          test_async_pin = FALSE;
          break;
        case 'n':
          operations_to_test = atoi(ssh_optarg);
          break;
        case 'b':
          abort_operations = TRUE;
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


void get_keys(void *context);




/* This is the context for the test. */
typedef struct SshExternalKeyTestCtxRec
{
  SshExternalKey externalkey;
  SshUInt32 operations_completed;
  Boolean end_test;
  SshADTContainer keypaths;
} *SshExternalKeyTestCtx;


/* Key context. */
typedef struct SshEKTestGetKeyRec
{
  SshOperationHandle crypto_op;
  SshOperationHandle encrypt_op;
  char *keypath;
  SshPublicKey public_key;
  SshPrivateKey private_key;
  SshExternalKeyTestCtx test_ctx;
  size_t cipher_len;
  unsigned char *ciphertext;
  size_t digest_len;
  unsigned char *digest;
} *SshEKTestGetKey;


/* This stores all the keys to mapping in the context. */
void ssh_externalkey_notify_cb(SshEkEvent event,
                               const char *keypath,                           
                               const char *label,
                               SshEkUsageFlags flags,
                               void *context)
{
  SshExternalKeyTestCtx ctx = context;
  static Boolean get_keys_issued = FALSE;
  const char *event_str;

  event_str = ssh_ek_get_printable_event(event);
  printf("Event: %s\nKeyPath:%s\n", event_str, keypath);

  if (event == SSH_EK_EVENT_PROVIDER_ENABLED)
    {
      printf("EK provider %s enabled with '%s'\n",
             keypath, (label ? label : ""));
    }

  if (event == SSH_EK_EVENT_PROVIDER_FAILURE)
    {
      printf("EK provider %s failed with '%s'\n",
             keypath, (label ? label : ""));
    }

  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      SshEKTestGetKey key_ctx;
      if (label)
        printf("Label: %s\n", label);
      key_ctx = ssh_xcalloc(1, sizeof(*key_ctx));
      key_ctx->keypath = ssh_xstrdup(keypath);
      key_ctx->test_ctx = ctx;

      if (!ssh_adt_strmap_exists(ctx->keypaths, keypath))
        ssh_adt_strmap_add(ctx->keypaths, keypath, key_ctx);
      /* Start test. We assume all the keys are notified in 1 second. */
      if (!get_keys_issued)
        {
          ssh_xregister_timeout(1, 0, get_keys, ctx);
          get_keys_issued = TRUE;
        }
    }
}



typedef struct AuthContextRec
{
  SshEkAuthenticationReplyCB reply_cb;
  void *reply_context;
  void *context;
  SshOperationHandle handle;
  char *keypath;
  char *label;
  SshUInt32 try_number;
  SshEkAuthenticationStatus authentication_status;
}  *AuthContext;



SshOperationHandle ssh_ek_int_authentication_cb(const char *keypath,
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

  if (authentication_status == SSH_EK_AUTHENTICATION_OK)
    return NULL;


  printf("Authentication callback called. \n"
         "Enter a ten digit PIN to cancel. \n"
    "Keypath %s\nLabel %s", keypath, label);
  printf("(Warning: Your PIN will be visible)\n"
    "PIN CODE for %s please:", label);

  if (default_pin != NULL &&
      ((authentication_status == SSH_EK_AUTHENTICATION_NEEDED_FOR_THE_TOKEN) ||
       (authentication_status == SSH_EK_AUTHENTICATION_CODE_NEEDED)))
    {
      strncpy(pin_buffer, default_pin, sizeof(pin_buffer));
    }
  else
    {
      scanf("%s", pin_buffer);
    }



  i = strlen((char *)pin_buffer);
  if (i == 10)
  {
          /* Length 1 pin equals cancellation. */
          reply_cb(NULL, 0, reply_context);
  }
  else
          reply_cb(pin_buffer, i, reply_context);

  return NULL;
}

/* Forward declaration. */
void ssh_ek_call_async_auth_call(void *context);


/* Is called when the crypto-opration is cancelled when authentication
   operation is pending. */
void ssh_async_auth_call_abort(void *context)
{
  AuthContext auth_context = context;
  ssh_cancel_timeouts(ssh_ek_call_async_auth_call, context);
  ssh_xfree(auth_context->label);
  ssh_xfree(auth_context->keypath);
  ssh_xfree(context);
}

/* Is called by the callback to call the pin query. */
void ssh_ek_call_async_auth_call(void *context)
{
  AuthContext auth_context = context;
  ssh_ek_int_authentication_cb(auth_context->keypath, auth_context->label,
    auth_context->try_number, auth_context->authentication_status,
    auth_context->reply_cb, auth_context->reply_context,
                               auth_context->context);

  ssh_operation_unregister(auth_context->handle);
  ssh_xfree(auth_context->label);
  ssh_xfree(auth_context->keypath);
  ssh_xfree(auth_context);
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
  if (test_async_pin)
  {
    AuthContext auth_context;
    auth_context = ssh_xcalloc(1, sizeof(*auth_context));
    auth_context->reply_cb = reply_cb;
    auth_context->context = context;
    auth_context->reply_context = reply_context;
    auth_context->keypath = ssh_xstrdup(keypath);
    auth_context->label = ssh_xstrdup(label);
    auth_context->try_number = try_number;
    auth_context->authentication_status = authentication_status;
    auth_context->handle = ssh_operation_register(ssh_async_auth_call_abort,
                                                  auth_context);
    ssh_xregister_timeout(1, 0, ssh_ek_call_async_auth_call, auth_context);
    return auth_context->handle;
  }
  else
  {
    return ssh_ek_int_authentication_cb(keypath, label, try_number,
                                        authentication_status, reply_cb,
                                        reply_context, context);
  }
}

#define SIGN_TEXT (unsigned char *)"Please sign this. "
#define SIGN_TEXT_LEN 16


void verify_cb(SshCryptoStatus status, void *context)
{
  if (status == SSH_CRYPTO_OK)
    {
      printf("Signature check success.\n");
    }
  else
    {
      printf("Signature check failed.\n");
    }
}

/* This is called when sign finishes, either succesfully or not. */
void sign_digest_cb(SshCryptoStatus status,
                    const unsigned char *signature_buffer,
                    size_t signature_buffer_len,
                    void *context)
{
  SshEKTestGetKey get_key = context;
  SshExternalKeyTestCtx ctx = get_key->test_ctx;

  ctx->operations_completed++;

  get_key->crypto_op = NULL;
  if (ctx->operations_completed == operations_to_test)
    {
      ctx->end_test = TRUE;
    }

  if (status == SSH_CRYPTO_OK)
    {
      char *key_name;

      printf("Sign Digest successful with the key.\n");
      key_name = ssh_public_key_name(get_key->public_key);

      if (strstr(key_name, "if-modn"))
        {
          /* RSA key */
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "rsa-pkcs1-none",
                                       SSH_PKF_END);
        }
      else if (strstr(key_name, "dl-modp") != NULL)
        {
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "dsa-nist-sha1",
                                       SSH_PKF_END);
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (strstr(key_name, "ec-modp") != NULL)
        {
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "dsa-none-sha1",
                                       SSH_PKF_END);
        }
#endif /* SSHDIST_CRYPT_ECP */
      ssh_xfree(key_name);
      if (get_key->public_key)
        {
          ssh_public_key_verify_digest_async(get_key->public_key,
                                             signature_buffer,
                                             signature_buffer_len,
                                             get_key->digest, 
                                             get_key->digest_len,
                                             verify_cb, NULL);

          ssh_xfree(get_key->digest);
          get_key->digest = NULL;
        }
      else
        {
          SSH_DEBUG(6, ("Could not verify the signature, because there"
                        "is not a proper public key available."));
        }
    }
  else
    {
      printf("Sign digest operation unsuccessful with error code %d!\n",
             status);
    }
}



/* This is called when sign finishes, either succesfully or not. */
void sign_cb(SshCryptoStatus status,
             const unsigned char *signature_buffer,
             size_t signature_buffer_len,
             void *context)
{
  SshEKTestGetKey get_key = context;
  SshExternalKeyTestCtx ctx = get_key->test_ctx;

  ctx->operations_completed++;

  get_key->crypto_op = NULL;
  if (ctx->operations_completed == operations_to_test)
    {
      ctx->end_test = TRUE;
    }

  if (status == SSH_CRYPTO_OK)
    {
      char *key_name;

      printf("Sign successful with the key.\n");
      key_name = ssh_public_key_name(get_key->public_key);

      if (strstr(key_name, "if-modn"))
        {
          /* RSA key */
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "rsa-pkcs1-sha1",
                                       SSH_PKF_END);
        }
      else if (strstr(key_name, "dl-modp") != NULL)
        {
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "dsa-nist-sha1",
                                       SSH_PKF_END);
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (strstr(key_name, "ec-modp") != NULL)
        {
          ssh_public_key_select_scheme(get_key->public_key,
                                       SSH_PKF_SIGN, "dsa-none-sha1",
                                       SSH_PKF_END);
        }
#endif /* SSHDIST_CRYPT_ECP */
      ssh_xfree(key_name);
      if (get_key->public_key)
        {
          ssh_public_key_verify_async(get_key->public_key,
                                      signature_buffer,
                                      signature_buffer_len,
                                      SIGN_TEXT, SIGN_TEXT_LEN,
                                      verify_cb, NULL);
        }
      else
        {
          SSH_DEBUG(6, ("Could not verify the signature, because there"
                        "is not a proper public key available."));
        }
    }
  else
    {
      printf("Sign operation unsuccessful with error code %d.\n", status);
    }
}

/* This is a response callback for decrypt. */
void decrypt_cb(SshCryptoStatus status,
                const unsigned char *plaintext_buffer,
                size_t plaintext_buffer_len,
                void *context)
{
  SshEKTestGetKey get_key = context;
  SshExternalKeyTestCtx ctx = get_key->test_ctx;

  ctx->operations_completed++;
  if (ctx->operations_completed == operations_to_test)
    {
      ctx->end_test = TRUE;
    }

  if (status == SSH_EK_OK)
    {
      if (memcmp(plaintext_buffer, TEST_STR, strlen(TEST_STR) + 1) == 0)
        printf("Encrypt/Decrypt OK.\n");
      else
        printf("Encrypt/Decrypt mismatch!\n");
    }
  else
    {
      printf("Decrypt unsuccesful.\n");
    }
}



/* This is called when asyncronic encryption is ready */
void encrypt_cb(SshCryptoStatus status,
                const unsigned char *ciphertext_buffer,
                size_t ciphertext_buffer_len,
                void *context)
{
  SshEKTestGetKey get_key = context;

  get_key->encrypt_op = NULL;

  if (status == SSH_CRYPTO_OK)
    {
      SshOperationHandle handle;

      SSH_DEBUG(10, ("Crypto operation encrypt successful with "
        "the publickey"));

      get_key->ciphertext = ssh_xmemdup(ciphertext_buffer,
        ciphertext_buffer_len);
      get_key->cipher_len = ciphertext_buffer_len;


      printf("Decrypting data with a '%s' provider.\n", provider_type);
      handle = ssh_private_key_decrypt_async(get_key->private_key,
        get_key->ciphertext, get_key->cipher_len,
        decrypt_cb,
        context);
      if (abort_operations && handle != NULL)
        {
          ssh_operation_abort(handle);
        }
    }
  else
    {
      printf("Crypto operation encrypt unsuccessful with error code %d!\n",
             status);
    }
}


/* This is the reposnse callback for ssh_ek_private_key_get.  It gives
   us the proxy private key. We will sign data with the key. */
void ssh_ek_get_private_key_cb(SshEkStatus status,
                               SshPrivateKey key, void *context)
{
  SshEKTestGetKey get_key = context;
  SshExternalKeyTestCtx ctx = get_key->test_ctx;
  SshHash hash;
  SshCryptoStatus cret;
  const char *hash_name;
  char *key_name;
  unsigned char *digest;
  size_t digest_len;

  if (status == SSH_EK_OK)
    {
      char *key_type;
      SshOperationHandle handle;

      get_key->private_key = key;

      SSH_DEBUG(10, ("Got the private key %s", get_key->keypath));

      /* Do the encryption test only with RSA keys */
      if (ssh_private_key_get_info(key, SSH_PKF_KEY_TYPE,
                                   &key_type, SSH_PKF_END)
          != SSH_CRYPTO_OK)
        {
          ssh_fatal("Could not get the key type");
        }
      if (strstr(key_type, "if-modn"))
        {
          SSH_DEBUG(10, ("Encrypting data assynchronously with "
                         "the public key."));
          if (ssh_private_key_select_scheme(key, SSH_PKF_ENCRYPT,
                                        "rsa-pkcs1-none",
                                        SSH_PKF_SIGN, "rsa-pkcs1-sha1",
                                        SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              printf("Can not select the private key encryption scheme.\n");
            }
          if (ssh_public_key_select_scheme(get_key->public_key,
                                        SSH_PKF_ENCRYPT,
                                        "rsa-pkcs1-none",
                                        SSH_PKF_SIGN, "rsa-pkcs1-sha1",
                                        SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              printf("Can not select the public key encryption scheme.\n");
            }

          handle =
            ssh_public_key_encrypt_async(get_key->public_key,
                                         (const unsigned char *)TEST_STR,
                                         strlen(TEST_STR) + 1,
                                         encrypt_cb, context);
          if (handle)
            get_key->encrypt_op = handle;

        }
      else
        {
          /* Since DSA does not do encryption, increment the number of 
             completed operations immediately. */
          ctx->operations_completed++;
          if (ctx->operations_completed == operations_to_test)
            {
              ctx->end_test = TRUE;
            }
        }

      key_name = ssh_private_key_name(key);

      if (strstr(key_name, "if-modn"))
        {
          /* RSA key */
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "rsa-pkcs1-sha1", SSH_PKF_END);
        }
      else if (strstr(key_name, "dl-modp") != NULL)
        {
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "dsa-nist-sha1", SSH_PKF_END);
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (strstr(key_name, "ec-modp") != NULL)
        {
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "dsa-none-sha1", SSH_PKF_END);
        }
#endif /* SSHDIST_CRYPT_ECP */

      printf("Signing with the proxy private key.\n");
      handle = ssh_private_key_sign_async(key, SIGN_TEXT,
                                          SIGN_TEXT_LEN, sign_cb, get_key);

      if (handle)
        get_key->crypto_op = handle;

      if (abort_operations && get_key->crypto_op != NULL)
        {
          ssh_operation_abort(handle);
          get_key->crypto_op = NULL;
        }

      if (strstr(key_name, "if-modn"))
        {
          /* RSA key */
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "rsa-pkcs1-none", SSH_PKF_END);


        }
      else if (strstr(key_name, "dl-modp") != NULL)
        {
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "dsa-nist-sha1", SSH_PKF_END);
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (strstr(key_name, "ec-modp") != NULL)
        {
          ssh_private_key_select_scheme(key, SSH_PKF_SIGN,
                                        "dsa-none-sha1", SSH_PKF_END);
        }
#endif /* SSHDIST_CRYPT_ECP */

      /* Hash the data to be signed with sign_digest */
      cret = ssh_private_key_derive_signature_hash(key, &hash);

      SSH_ASSERT(cret == SSH_CRYPTO_OK || 
                 (hash == NULL && cret == SSH_CRYPTO_UNSUPPORTED));
      
      /* No hash associated with this signature scheme */
      if (hash == NULL)
        {
          digest_len = SIGN_TEXT_LEN;
          digest = ssh_xmemdup(SIGN_TEXT, SIGN_TEXT_LEN);
        }
      else
        {
          /* There is a valid hash function, hash the data and pass it to
             the sign digest function */
          hash_name = ssh_hash_name(hash);
          digest_len = ssh_hash_digest_length(hash_name);
          digest = ssh_xmalloc(digest_len);
          
          ssh_hash_update(hash, SIGN_TEXT, SIGN_TEXT_LEN);

          cret = ssh_hash_final(hash, digest);

          SSH_DEBUG(6, ("hash_name is %s, digest len is %d, status is %d", 
                        hash_name, digest_len, cret));
          SSH_ASSERT(cret == SSH_CRYPTO_OK);
          
          ssh_hash_free(hash);
        }

      get_key->digest = digest;
      get_key->digest_len = digest_len;

      printf("Signing with the proxy private key, using alternate method.\n");
      handle = ssh_private_key_sign_digest_async(key, digest, digest_len,
                                                 sign_digest_cb, get_key);
      ssh_xfree(key_name);
    }
  else
    {
      SSH_DEBUG(6, ("Get Private key unsuccesful, status is %d", status));
    }

}

/* This is the response callback for ssh_ek_get_public_key. We
   store the keys in to our context. Then we try to retrieve the
   private key. */
void ssh_ek_get_public_key_cb(SshEkStatus status,
                              SshPublicKey key,
                              void *context)
{
  SshEKTestGetKey get_key =  context;
  SshExternalKeyTestCtx ctx = get_key->test_ctx;


  if (status == SSH_EK_OK)
    {
      get_key->public_key = key;
      SSH_DEBUG(10, ("Got the public key %s", get_key->keypath));

      ssh_ek_get_private_key(ctx->externalkey,
                             get_key->keypath,
                             ssh_ek_get_private_key_cb, get_key);
    }
  else
    {
      SSH_DEBUG(6, ("Get public key unsuccesful"));
    }
}


void event_loop_abort(void *context)
{
  ssh_event_loop_abort();
}


static void ssh_ek_test_destroy(void *value,
                                void *context)
{
  SshEKTestGetKey ctx = value;

  if (ctx->public_key)
    ssh_public_key_free(ctx->public_key);
  if (ctx->private_key)
    ssh_private_key_free(ctx->private_key);

  ssh_operation_abort(ctx->crypto_op);
  ssh_operation_abort(ctx->encrypt_op);
  ssh_xfree(ctx->ciphertext);
  ssh_xfree(ctx->keypath);
  ssh_xfree(ctx->digest);
  ssh_xfree(ctx);
}

/* This ends the test if needed. */
void end_test(void *context)
{
  SshExternalKeyTestCtx ctx = context;

  if (ctx->end_test)
    {
      ssh_adt_destroy(ctx->keypaths);

      ssh_ek_free(ctx->externalkey, event_loop_abort, NULL);
    }
  else
    ssh_xregister_timeout(1, 0, end_test, context);
}

typedef struct TestGetCertsRec *TestGetCerts;

typedef void (*TestGetCertCB)(TestGetCerts ctx);

struct TestGetCertsRec
{
  Boolean trusted;
  TestGetCertCB get_next_cb;
  SshUInt32 cert_index;
  SshExternalKey ek;
  char *keypath;
};

static void ssh_test_get_certs_free(TestGetCerts ctx)
{
  ssh_xfree(ctx->keypath);
  ssh_xfree(ctx);
}

void get_cert_cb(SshEkStatus status,
                 const unsigned char *data,
                 size_t data_len,
                 void *context)
{
  TestGetCerts ctx = context;
  if (status == SSH_EK_OK)
    {
      printf("Get %s certificate with index %ld successfully.\n",
             (ctx->trusted ? "trusted" : "user"),
             ctx->cert_index);
      ctx->cert_index++;
      (*ctx->get_next_cb)(ctx);
    }
  else
    {
      if (status == SSH_EK_NO_MORE_CERTIFICATES)
        printf("No %s certificate with index %ld.\n",
               (ctx->trusted ? "trusted" : "user"),
               ctx->cert_index);
      else
        printf("Get %s certificate with index %ld NOT successful!\n",
               (ctx->trusted ? "trusted" : "user"),
               ctx->cert_index);
      ssh_test_get_certs_free(ctx);
    }
}


void get_next_cert(TestGetCerts ctx)
{
  ssh_ek_get_certificate(ctx->ek,
                         ctx->keypath,
                         ctx->cert_index,
                         get_cert_cb,
                         ctx);
}

void get_next_trusted_cert(TestGetCerts ctx)
{
  ssh_ek_get_trusted_cert(ctx->ek,
                          ctx->keypath,
                          ctx->cert_index,
                          get_cert_cb,
                          ctx);
}


void get_certificates(SshExternalKey ek,
                      const char *keypath)
{
  TestGetCerts ctx;

  ctx = ssh_xcalloc(1, sizeof(*ctx));
  ctx->keypath = ssh_xstrdup(keypath);
  ctx->ek = ek;
  ctx->get_next_cb = get_next_cert;
  ctx->trusted = FALSE;
  get_next_cert(ctx);
}

void get_trusted_certificates(SshExternalKey ek,
                             const char *keypath)
{
  TestGetCerts ctx;

  ctx = ssh_xcalloc(1, sizeof(*ctx));
  ctx->ek = ek;
  ctx->keypath = ssh_xstrdup(keypath);
  ctx->get_next_cb = get_next_trusted_cert;
  ctx->trusted = TRUE;
  get_next_trusted_cert(ctx);
}


/* Notify callback will insert keypaths in the string mapping.
   This will get all the keys from the mapping. */
void get_keys(void *context)
{
  SshExternalKeyTestCtx ctx = context;
  SshADTHandle handle;
  char *keypath;
  SshEKTestGetKey key_ctx;


  handle = ssh_adt_enumerate_start(ctx->keypaths);

  /* Iterate through all the keys. */
  while (handle)
    {
      keypath = ssh_adt_get(ctx->keypaths, handle);
      key_ctx = ssh_adt_strmap_get(ctx->keypaths, keypath);

      /* Ignore the returned operation handle, we do not want to
         abort the operation. */
      ssh_ek_get_public_key(ctx->externalkey,
                            keypath, ssh_ek_get_public_key_cb, key_ctx);

      /* Try getting certificates */
      get_certificates(ctx->externalkey, keypath);

      /* Try getting trusted certificates */
      get_trusted_certificates(ctx->externalkey, keypath);
      /* Get the next keypath. */


      handle = ssh_adt_enumerate_next(ctx->keypaths, handle);
    }
}


void kill_test(void *context)
{
  SshExternalKey ek = context;

  ssh_ek_free(ek, NULL_FNPTR, NULL);
}



static void test_add_ek(SshExternalKeyTestCtx ctx)
{
  SshExternalKey externalkey;

  externalkey = ssh_ek_allocate();

  /* test enable and disable of provider using sigint, which is
     defined in both windows and unix. */
  ctx->externalkey = externalkey;

  /* Register authentication and notify callbacks. */
  ssh_ek_register_notify(externalkey, ssh_externalkey_notify_cb, ctx);

  ssh_ek_register_authentication_callback(externalkey,
                                          ssh_externalkey_authentication_cb,
                                          ctx);
  ssh_ek_add_provider(externalkey, provider_type,
                      initialization_string, NULL, 0, NULL);

  ssh_xregister_timeout(timeout_sec, 0, end_test, ctx);
}

static void
t_ek_append_to_file(const char *filename,
                    const char *message)
{
  FILE *f;

  f = fopen(filename, "a+");
  if (f != NULL)
    {
      fwrite(message, strlen(message), 1, f);
      fwrite("\n", 1, 1, f);
      fclose(f);
    }
}


static void
t_externalkey_debug_callback(const char *message,
                             void *context)
{
  if (debug_output_file)
    t_ek_append_to_file(debug_output_file, message);
  printf("%s\n", message);
}

int main(int argc, char **argv)
 {
  SshExternalKeyTestCtx test_ctx;

  ssh_global_init();
  ssh_crypto_library_initialize();

  ssh_x509_library_initialize_framework(NULL);
  ssh_x509_library_register_functions(SSH_X509_PKIX_CERT,
                                      ssh_x509_cert_decode_asn1,
                                      NULL_FNPTR);
#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */
  parse_arguments(argc, argv);

  /* Initialize the event loop and the test context. */
  ssh_event_loop_initialize();
#ifdef HAVE_THREADS
  ssh_threaded_timeouts_init();
#endif /* HAVE_THREADS */
#ifdef DEBUG_LIGHT
  ssh_debug_set_level_string(debug_level_string);
#endif /* DEBUG_LIGHT */
  ssh_debug_register_callbacks(t_externalkey_debug_callback,
                               t_externalkey_debug_callback,
                               t_externalkey_debug_callback,
                               NULL);

  test_ctx = ssh_xcalloc(1, sizeof(*test_ctx));
  test_ctx->keypaths= ssh_adt_xcreate_strmap(NULL,
                                             ssh_ek_test_destroy);

  test_add_ek(test_ctx);

  ssh_event_loop_run();

  /* Uninitialize. */
  ssh_xfree(test_ctx);
#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */
  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
