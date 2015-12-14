/*
  File: t-softprovider.c

  Authors: Vesa Suontama <vsuontam@ssh.fi>

  Description:
        Software provider test functions

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                  All rights reserved.
*/
#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshexternalkey.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"
#include "sshdsprintf.h"
#include "sshsoftkey.h"

#define SSH_DEBUG_MODULE "t-softprovider"

typedef struct SoftProviderTesterRec
{
  SshExternalKey ek;
  const char *provinfo;
  const char *keypath;
  const char *scheme;
  Boolean prv_must_fail;
  SshPublicKey pub_key;
  SshPrivateKey key;
  SshUInt32 provider_num;
  Boolean add_key_tested;
} *SoftProviderTester, SoftProviderTesterStruct;

static void ssh_soft_tester_free(SoftProviderTester tester)
{
  if (tester->key)
    ssh_private_key_free(tester->key);
  if (tester->pub_key)
    ssh_public_key_free(tester->pub_key);
  ssh_ek_free(tester->ek, NULL_FNPTR, NULL);
  ssh_xfree(tester);
}


static void soft_get_pubkey_cb(SshEkStatus status, SshPublicKey key,
                               void *context)
{
  SoftProviderTester tester = context;
  if (status != SSH_EK_OK)
    {
      ssh_fatal("Failed to get the public key in tester %d, status %s", 
		tester->provider_num, ssh_ek_get_printable_status(status));
    }
  else
    {
      tester->pub_key = key;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Got the public key in tester %d",
				   tester->provider_num));


    }
  ssh_soft_tester_free(tester);
}

/* Section 1:
    Code below signs data using keymaterial acquired from keypath set
    up at section 2 from provider set up on section 3. */
static void soft_recv_signature(SshCryptoStatus status,
                                const unsigned char *signature,
                                size_t signature_len,
                                void *context)
{
  SoftProviderTester tester = context;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("EK signature done status %d; len %d",
                               status,
                               signature_len));
  if (status == SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Signed ok with the key in tester %d",
                                  tester->provider_num));
    }
  else
    {
      ssh_fatal("Could not sign with a key");
    }

  ssh_ek_get_public_key(tester->ek, tester->keypath, soft_get_pubkey_cb,
                        tester);

}

#define TESTDATA "sikapantteri ja marsupilami kävelivät kadulla"

static void
tester_continue_after_key(void *context)
{
  SoftProviderTester tester = context;


  if (ssh_private_key_select_scheme(tester->key, SSH_PKF_SIGN, tester->scheme,
       SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("signature scheme change failed. Keypath %s, num %d",
                tester->keypath, tester->provider_num);
    }

  ssh_private_key_sign_async(tester->key,
                             (const unsigned char *)TESTDATA, strlen(TESTDATA),
                             soft_recv_signature, context);
}


/* This tests the key added from ssh_sk_add_key_and_cert. The key must
   be avaialable */
static void
soft_added_prvkey_cb(SshEkStatus status, SshPrivateKey key, void *context)
{
  if (status != SSH_EK_OK)
    ssh_fatal("Added key not available");
  ssh_private_key_free(key);
}


/* Section 2:
    Code below acquires key material from provider using given
    keypath. */


static void
soft_prvkey_cb(SshEkStatus status, SshPrivateKey key, void *context)
{
  SoftProviderTester tester = context;

  if (status == SSH_EK_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("EK provider gave us private key"));
      tester->key = key;

      ssh_xregister_timeout(0L, 0L, tester_continue_after_key, context);
      if (!tester->add_key_tested)
        {
          ssh_sk_add_key_and_cert(tester->ek, NULL, key, "Test key",
                                  NULL, 0);
          tester->add_key_tested = TRUE;
        }

    }
  else
    {
      if (tester->prv_must_fail == TRUE)
        {
          ssh_ek_get_public_key(tester->ek, tester->keypath,
                                soft_get_pubkey_cb, tester);
          return;
        }
      /* This was en error. */
      ssh_fatal("Failed to get the private key");
    }
}


static void get_private_key(void *context)
{
  SoftProviderTester tester = context;

  /* Now the provider is finally up and running. We can get keys
     handles from it using the keypath (constructed at the main
         routine). */
  ssh_ek_get_private_key(tester->ek,
                         tester->keypath, soft_prvkey_cb, tester);

}


static void
soft_notify_cb(SshEkEvent event, const char *keypath,
               const char *label,
               SshEkUsageFlags flags,
               void *context)
{
  SoftProviderTester tester = context;

  if (event == SSH_EK_EVENT_PROVIDER_ENABLED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("EK provider instance enabled"));

      ssh_register_timeout(NULL, 0, 0, get_private_key, tester);
    }
  else
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("EK notification cb for provider %s", keypath));

  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Asking key '%s' with label '%s'",
			      keypath, label));
      ssh_ek_get_private_key(tester->ek,
                             keypath, soft_added_prvkey_cb, tester);
    }
}

static SshOperationHandle
soft_auth_cb(const char *keypath, const char *label,
             SshUInt32 trynumber,
             SshEkAuthenticationStatus status,
             SshEkAuthenticationReplyCB reply,
             void *reply_context,
             void *context)
{
#define PASS "test"
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("EK authentication cb for keypath %s", keypath));

  if (status == SSH_EK_AUTHENTICATION_OK)
    return NULL;

  if (trynumber == 0)
    {
      (*reply)((const unsigned char *)PASS, strlen(PASS), reply_context);
    }
   else
    {
      (*reply)(NULL, 0, reply_context);
    }
  return NULL;
}

/* Section 3:
    Code below is setup code for starting the external key system and
    registering the provider. */
static void
ek_allocate(SoftProviderTester tester)
{
  SshExternalKey ek;

  ek = ssh_ek_allocate();

  if (ek)
    {
      char *short_name;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("EK allocation successful"));
      tester->ek = ek;

      ssh_ek_register_notify(tester->ek, soft_notify_cb, tester);
      ssh_ek_register_authentication_callback(tester->ek, soft_auth_cb,
                                              tester);

      /* Initialize software provider into the external key system. */
      if (ssh_ek_add_provider(ek, "software", tester->provinfo, NULL,
                              0L, &short_name)
          != SSH_EK_OK)
        ssh_fatal("EK add provider FAILED");

      ssh_xfree(short_name);
    }
  else
    SSH_DEBUG(SSH_D_ERROR, ("EK allocation FAILED"));
}

struct SoftTes1tRec
{
  char *keypath;
  char *init;
  char *sign_scheme;
  Boolean prv_key_must_fail;
} keypaths[] =
{
#ifdef SSHDIST_CERT
#ifdef SSHDIST_CRYPT_DES
  /* RSA PKCS8 Shrouded. */
  {"software://0/prvkeydata="
   "MIICoTAbBgkqhkiG9w0BBQowDgQIbiX9a3u8qN8CAgQABIICgGz72hrRrziOPRvr"
   "b6kAWixaKJW51s9+dRi6+je0FBHEELU7n6uoHs4hG71Vksx+LWjmTq8j0Z6bFuDl"
   "8WcJWcVF4iox9zTTeOPLzUFH13kf7aKFxhEBj4tZwqG8XpPyW8bH2NefIvIhHmmF"
   "5LMBzEtILy3ifxo+kKMVz+Qvu2cp7wsaJo8tSr3rqqTUHU4NO8QSsZS0zh9Q5Ygd"
   "+J+6xh8EIRhCnq43U/rOCT9oBozFBkvkqm0T8bZqupsMgz4owH11hJFz6dmEQLVm"
   "JOC4uj14sJ2gAHkbGraiN+F9nIYeJY2wUTJGZJq+yrn5DwizfR1BAuOu7frQuCVJ"
   "OTjFSAO2hoLidrQ8LznhhtNw4E/NL2RYUWmjqjIhucvH6Yt/gQyrTHKoJFwg95I6"
   "L5WLEBVeTgvmg2VZQ9GdtN3zIG0UF7HPOIKAngP5cBpkgmgLQ14WUoIQ1Rdx03Ut"
   "6oSGev97lKxpPqVFz71toSkyee+KFkLr+dhyATbrS1AWQPVJlzg7g+MyKdeziWma"
   "k8J8LPy6FhSL9/AGT9AaOoiXfaA2umfQaN3t3H0HD95BiBjIrJKkmd1DRQh+aC0y"
   "3y0aXOh4/rCTS8nfcXRRfs4nI1CA9bbELrIy7EB3I1mFY1C3oQ5BJMztxlrs790G"
   "cttWOxLkxbWD+J0wt+8CO2WIwufAXQT5yo6yLrGBbWitNb2st16MZ3epH6kLASPb"
   "IXvQ19W656N1yjnwAfxX7Eq53jzNyu+fMpQbNbqEh/FONbw0JFb+V6zmYXnlgPRN"
   "8buY58ElunTx7FxVRj6LhDivhbCZ5KDfzU8XwOEoSEu7hOZ21t1SOO5WEj6/0YRD"
   "DzUEOKQ="
   , "", "rsa-pkcs1-sha1", FALSE},
  /* RSA PKCS8 Shrouded. */
  {"software://0/prvkeydata="
   "MIICoTAbBgkqhkiG9w0BBQowDgQIbiX9a3u8qN8CAgQABIICgGz72hrRrziOPRvr"
   "b6kAWixaKJW51s9+dRi6+je0FBHEELU7n6uoHs4hG71Vksx+LWjmTq8j0Z6bFuDl"
   "8WcJWcVF4iox9zTTeOPLzUFH13kf7aKFxhEBj4tZwqG8XpPyW8bH2NefIvIhHmmF"
   "5LMBzEtILy3ifxo+kKMVz+Qvu2cp7wsaJo8tSr3rqqTUHU4NO8QSsZS0zh9Q5Ygd"
   "+J+6xh8EIRhCnq43U/rOCT9oBozFBkvkqm0T8bZqupsMgz4owH11hJFz6dmEQLVm"
   "JOC4uj14sJ2gAHkbGraiN+F9nIYeJY2wUTJGZJq+yrn5DwizfR1BAuOu7frQuCVJ"
   "OTjFSAO2hoLidrQ8LznhhtNw4E/NL2RYUWmjqjIhucvH6Yt/gQyrTHKoJFwg95I6"
   "L5WLEBVeTgvmg2VZQ9GdtN3zIG0UF7HPOIKAngP5cBpkgmgLQ14WUoIQ1Rdx03Ut"
   "6oSGev97lKxpPqVFz71toSkyee+KFkLr+dhyATbrS1AWQPVJlzg7g+MyKdeziWma"
   "k8J8LPy6FhSL9/AGT9AaOoiXfaA2umfQaN3t3H0HD95BiBjIrJKkmd1DRQh+aC0y"
   "3y0aXOh4/rCTS8nfcXRRfs4nI1CA9bbELrIy7EB3I1mFY1C3oQ5BJMztxlrs790G"
   "cttWOxLkxbWD+J0wt+8CO2WIwufAXQT5yo6yLrGBbWitNb2st16MZ3epH6kLASPb"
   "IXvQ19W656N1yjnwAfxX7Eq53jzNyu+fMpQbNbqEh/FONbw0JFb+V6zmYXnlgPRN"
   "8buY58ElunTx7FxVRj6LhDivhbCZ5KDfzU8XwOEoSEu7hOZ21t1SOO5WEj6/0YRD"
   "DzUEOKQ="
   , "async_time_ms(100)", "rsa-pkcs1-sha1", FALSE},
  /* RSA PKCS8 Shrouded. */
  {"software://0/prvkeydata="
   "MIICoTAbBgkqhkiG9w0BBQowDgQIbiX9a3u8qN8CAgQABIICgGz72hrRrziOPRvr"
   "b6kAWixaKJW51s9+dRi6+je0FBHEELU7n6uoHs4hG71Vksx+LWjmTq8j0Z6bFuDl"
   "8WcJWcVF4iox9zTTeOPLzUFH13kf7aKFxhEBj4tZwqG8XpPyW8bH2NefIvIhHmmF"
   "5LMBzEtILy3ifxo+kKMVz+Qvu2cp7wsaJo8tSr3rqqTUHU4NO8QSsZS0zh9Q5Ygd"
   "+J+6xh8EIRhCnq43U/rOCT9oBozFBkvkqm0T8bZqupsMgz4owH11hJFz6dmEQLVm"
   "JOC4uj14sJ2gAHkbGraiN+F9nIYeJY2wUTJGZJq+yrn5DwizfR1BAuOu7frQuCVJ"
   "OTjFSAO2hoLidrQ8LznhhtNw4E/NL2RYUWmjqjIhucvH6Yt/gQyrTHKoJFwg95I6"
   "L5WLEBVeTgvmg2VZQ9GdtN3zIG0UF7HPOIKAngP5cBpkgmgLQ14WUoIQ1Rdx03Ut"
   "6oSGev97lKxpPqVFz71toSkyee+KFkLr+dhyATbrS1AWQPVJlzg7g+MyKdeziWma"
   "k8J8LPy6FhSL9/AGT9AaOoiXfaA2umfQaN3t3H0HD95BiBjIrJKkmd1DRQh+aC0y"
   "3y0aXOh4/rCTS8nfcXRRfs4nI1CA9bbELrIy7EB3I1mFY1C3oQ5BJMztxlrs790G"
   "cttWOxLkxbWD+J0wt+8CO2WIwufAXQT5yo6yLrGBbWitNb2st16MZ3epH6kLASPb"
   "IXvQ19W656N1yjnwAfxX7Eq53jzNyu+fMpQbNbqEh/FONbw0JFb+V6zmYXnlgPRN"
   "8buY58ElunTx7FxVRj6LhDivhbCZ5KDfzU8XwOEoSEu7hOZ21t1SOO5WEj6/0YRD"
   "DzUEOKQ="
   , "async_time_ms(10) random_async_completion", "rsa-pkcs1-sha1", FALSE},
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_DSA
  /* DSA X509 without passphrase */
  {"software://0/prvkeydata="
   "MIIByjALBgcqhkjOOAQBBQAwggG5AoGBAKTfUfURsFwnWOFUWrjXvNidR7Xc1Ljm"
   "UI9EOauaea5p+zHTd5S34pcxXdHjjWOo7WK/hMXsiyNs/Gwil9J9p/EaIZw1esBn"
   "PO0gjm25ZddHXoCZllaFoss27EvMSDNg6+GT22crZOedZ/VJbz0Lgm8SGDQcxABc"
   "LLfkc3XjQNx/AhUA7Gl/6C74HsH1VmAvuEAUZaZLLMsCgYBvAXjLn56808PMoWK4"
   "dI0PeMHjX3IrtmFIA+YVIgEyQD5tOIM//h5aA++rWZ5bVWuABUyA2jbGuZMORubj"
   "TbDXvWagil3FzUWf8gHSbfLXtiJR734H3IZC41notw3ae2u+HG+0M5x1m0Hj7CS+"
   "0cYwxxrwztFKsIL4UlHwPVgkrwKBgQCf9rBrRE7hOhlHPIQdgmld18cbZkHuL1XQ"
   "GSe+3WKLQDYM/Z41gYBpQzZt7dCily5AC44Hntx4Klje+aZ6cvTR1BxJrRSFz2oU"
   "u6CfqZviaxDLiCW4b8xf1amSn/lJl9xFRg1NKksnQAqOb4ZO9uEvC7al0VyhxJ/E"
   "blF8OjmmGgIVAIBcvZpxSmI8KbJFu2fDkOUCN5QQ", "", "dsa-nist-sha1",
    FALSE},
   /* DSA X509 without passphrase */
  {"software://0/prvkeydata="
   "MIIByjALBgcqhkjOOAQBBQAwggG5AoGBAKTfUfURsFwnWOFUWrjXvNidR7Xc1Ljm"
   "UI9EOauaea5p+zHTd5S34pcxXdHjjWOo7WK/hMXsiyNs/Gwil9J9p/EaIZw1esBn"
   "PO0gjm25ZddHXoCZllaFoss27EvMSDNg6+GT22crZOedZ/VJbz0Lgm8SGDQcxABc"
   "LLfkc3XjQNx/AhUA7Gl/6C74HsH1VmAvuEAUZaZLLMsCgYBvAXjLn56808PMoWK4"
   "dI0PeMHjX3IrtmFIA+YVIgEyQD5tOIM//h5aA++rWZ5bVWuABUyA2jbGuZMORubj"
   "TbDXvWagil3FzUWf8gHSbfLXtiJR734H3IZC41notw3ae2u+HG+0M5x1m0Hj7CS+"
   "0cYwxxrwztFKsIL4UlHwPVgkrwKBgQCf9rBrRE7hOhlHPIQdgmld18cbZkHuL1XQ"
   "GSe+3WKLQDYM/Z41gYBpQzZt7dCily5AC44Hntx4Klje+aZ6cvTR1BxJrRSFz2oU"
   "u6CfqZviaxDLiCW4b8xf1amSn/lJl9xFRg1NKksnQAqOb4ZO9uEvC7al0VyhxJ/E"
   "blF8OjmmGgIVAIBcvZpxSmI8KbJFu2fDkOUCN5QQ", "async_time_ms(10)",
   "dsa-nist-sha1", FALSE },
#endif /* SSHDIST_CRYPT_DSA */
#endif /* SSHDIST_CERT */
   /* Only public key */
  {"software://0/pubkeydata="
   "ZciyigAAAKIAAAAHaWYtbW9kbgAAAIsAAAARAQABAAAEAIZ+O8H8PP6H7jWEhmZu"
   "IgmKKeqq415gDUPZ035ifIKACjKhm2M7u+646OCbg9NqitcjSxI1SB/omDxZG9AQ"
   "H5hpUC9DDE/SlhAZnVEM4DoVMds5y3Oi9GMTNVr8Waal4GrfTcspJ59gi+FmkWaD"
   "EXkYnsM71D9YhQm7hpkHjpk3", "", "", TRUE}
};

#define ARRAY_SIZE(x) sizeof(x) / sizeof(x[0])


/* Section 4: Main. */
int main(int ac, char **av)
{
  SoftProviderTester tester;
  int opt;

  ssh_event_loop_initialize();

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");

  while ((opt = ssh_getopt(ac, av, "hd:", NULL)) != -1)
    {
      switch (opt)
        {
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        default:
        case 'h':
          fprintf(stderr, "usage: t-softprovider [-d debuglevel] prov-init "
                  "keypath\n");
          exit(1);
        }
    }
  ac -= ssh_optind;
  av += ssh_optind;

  if (ac == 2)
    {
      tester = ssh_xcalloc(1, sizeof(*tester));
      tester->provinfo = av[0];
      tester->keypath = av[1];
      ek_allocate(tester);
    }
  else
    {
      int i;
      for (i = 0; i < ARRAY_SIZE(keypaths); i++)
        {
          tester = ssh_xcalloc(1, sizeof(*tester));
          tester->provinfo = keypaths[i].init;
          tester->keypath = keypaths[i].keypath;
          tester->prv_must_fail = keypaths[i].prv_key_must_fail;
          tester->scheme = keypaths[i].sign_scheme;
          tester->provider_num = i;
          ek_allocate(tester);
        }
    }


  ssh_event_loop_run();

  ssh_event_loop_uninitialize();

  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
