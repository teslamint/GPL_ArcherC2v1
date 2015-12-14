/*
  File: t-genacc.c

Copyright:
          Copyright (c) 2002-2008 SFNT Finland Oy.
  All rights reserved

  This test program tests that accelerated keys function in the same
  manner as SSH software keys. This code tests the genacc* files in
  sshexternalkey library and sshproxykey in the crypto library.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshexternalkey.h"
#include "genaccprov.h"
#include "sshglobals.h"
#include "sshfsm.h"
#include "ssheloop.h"
#include "sshoperation.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshEkTGenacc"

static SshUInt32 tests_pending;
static SshUInt32 group_entropy;
static Boolean verbose = FALSE;
static Boolean abort_operations = FALSE;
static SshExternalKey externalkey = NULL;
static char *provider_name = NULL;


void ek_free_cb(void *ctx)
{
#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */
  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  exit(0);
}

void end_test(void *ctx)
{
  if (externalkey != NULL)
    ssh_ek_free(externalkey, ek_free_cb, NULL);
}


/************************************************************************
  The following key generation routine is borrowed from the crypto
  library tests.
*************************************************************************/


typedef struct
{
  char *key_type;
  char *sign;
  char *encrypt;
  unsigned int size;
} PkcsInfo;

PkcsInfo pkcs_info[] = {
  { "if-modn", "rsa-pkcs1-none",  "rsa-pkcs1-none",  1024 },
  { "if-modn", "rsa-pss-md5",  "rsa-pkcs1-none",   1027 },
  { "if-modn", "rsa-pkcs1-none",  "rsa-pkcs1-none",  1025 },
  { "if-modn", "rsa-pkcs1-md5",  "rsa-pkcs1-none",   1319 },
  { "if-modn", "rsa-pkcs1-sha1", NULL, 1025 },
  { "if-modn", "rsa-pkcs1-md5",  "rsa-pkcs1-none",   1024 },
  { "if-modn", "rsa-pkcs1-sha1", NULL, 1024 },
  { "if-modn", "rsa-pss-sha1",  NULL,   1024 },
  { "if-modn", "rsa-pkcs1-sha1", "rsa-pkcs1v2-oaep", 1024 },
#ifdef SSHDIST_CRYPT_DSA
  { "dl-modp", "dsa-nist-sha1",  NULL,               1024 },
#endif /* SSHDIST_CRYPT_DSA */
  { NULL }
};

SshPrivateKey pkcs_make_prvkey(PkcsInfo *info, unsigned int key_size)
{
  unsigned char *buf, *tmp[10], *k;
  unsigned int size;
  SshPrivateKey prv;
  SshCryptoStatus status;
  int i;

  ssh_dsprintf(&buf, "%s{", info->key_type);

  /* Generate the key. */
  i = 0;
  if (info->sign)
    {
      ssh_dsprintf(&tmp[i], "sign{%s}", info->sign);
      i++;
    }
  if (info->encrypt)
    {
      ssh_dsprintf(&tmp[i], "encrypt{%s}", info->encrypt);
      i++;
    }
  tmp[i] = NULL;

  for (i = 0; tmp[i]; i++)
    {
      if (i > 0)
        ssh_dsprintf(&k, "%s,%s", buf, tmp[i]);
      else
        ssh_dsprintf(&k, "%s%s", buf, tmp[i]);
      ssh_xfree(buf);
      ssh_xfree(tmp[i]);
      buf = k;
    }
  ssh_dsprintf(&k, "%s}", buf);
  ssh_xfree(buf);
  buf = k;

  SSH_DEBUG(10, ("Calling prv generate"));

  size = (key_size != 0) ? key_size : info->size;

  status = ssh_private_key_generate(&prv,
                                    buf,
                                    SSH_PKF_SIZE, size,
                                    SSH_PKF_END);

  SSH_DEBUG(10, ("Calling prv generate done"));

  ssh_free(buf);

  if (status != SSH_CRYPTO_OK)
    return NULL;

  return prv;
}



/*************************************************************************/

#ifdef SSHDIST_CRYPT_DH 
typedef struct SshDHGrpRec
{
  char *type;
  char *name;
  SshUInt32 size;
  int group_number;
} *SshDHGrp;

#define no_of_fixed_groups 4
struct SshDHGrpRec group_descr[no_of_fixed_groups] =
  {
    { "dl-modp", "ietf-ike-grp-modp-768",   768, 1 },
    { "dl-modp", "ietf-ike-grp-modp-1024", 1024, 2 },
    { "dl-modp", "ietf-ike-grp-modp-1536", 1536, 5 },
    { "dl-modp", "ietf-ike-grp-modp-2048", 2048, 6 }
  };


/*************************************************************************/

/*************************** GROUP TESTS ********************************/

/*************************************************************************/

SshUInt32 num_group_tests(void)
{
  return no_of_fixed_groups;
}


typedef struct GroupTesterRec
{
  Boolean get_test;
  SshPkGroup unaccel_group;
  SshPkGroup group;
  SshPkGroupDHSecret secret;
  SshPkGroupDHSecret copy_secret;
  char *name;
  char *group_path;
  unsigned char *exchange;
  unsigned char *agreed;
  size_t elen, alen;
  unsigned char *unaccel_agreed;
  size_t unaccel_alen;
  size_t group_entropy;
} *GroupTester;


/************* Consistency tests for DH groups *************************/

/* Forward declarations */
void get_acc_group_cb(SshEkStatus, SshPkGroup, void *);
void dh_setup_cb1(SshCryptoStatus, SshPkGroupDHSecret,
                  const unsigned char *, size_t, void *);
void dh_setup_cb2(SshCryptoStatus, SshPkGroupDHSecret,
                  const unsigned char *, size_t, void *);
void dh_agree_cb1(SshCryptoStatus, const unsigned char *,
                  size_t, void *);
void dh_agree_cb2(SshCryptoStatus, const unsigned char *,
                  size_t, void *);
void dh_agree_cb3(SshCryptoStatus, const unsigned char *,
                  size_t, void *);

/************************************************************************/

/* The structure as used by the crypto library for storing
   Diffie-Hellman secret data. */
typedef struct PkGroupDHSecretRec
{
  /* The length in bytes of the secret data. */
  size_t len;
  /* The secret data. */
  unsigned char *buf;
} PkGroupDHSecretStruct, *PkGroupDHSecret;


void group_test(void *context)
{
  int j;
  SshDHGrp grp;
  SshPkGroup group;
  GroupTester tester;
  SshUInt32 entropy;

  for (j = 0; j < no_of_fixed_groups; j++)
    {
      tester = ssh_xcalloc(1, sizeof(*tester));

      grp = &group_descr[j];

      entropy = (group_entropy < grp->size) ? group_entropy : grp->size;

      /* Generate a software Diffie-Hellman group. */
      if (ssh_pk_group_generate(&group,
                                grp->type,
                                SSH_PKF_PREDEFINED_GROUP, grp->name,
                                SSH_PKF_RANDOMIZER_ENTROPY, entropy,
                                SSH_PKF_DH, "plain",
                                SSH_PKF_END) != SSH_CRYPTO_OK)
        ssh_fatal("setting up group %s", grp->name);

      tester->unaccel_group = group;
      tester->name = ssh_xstrdup(grp->name);

      /* Generate an accelerated Diffie-Hellman group from the
         corresponding software group. */
      ssh_ek_generate_accelerated_group(externalkey, provider_name,
					group, get_acc_group_cb, 
					tester);

    }
}

void get_acc_group_cb(SshEkStatus status,
                      SshPkGroup group,
                      void *context)
{
  GroupTester tester = context;

  tester->group = group;

  /* Do the Diffie-Hellman setup i.e. generate a secret) for
     the unaccelerated group. */
  ssh_pk_group_dh_setup_async(tester->unaccel_group, dh_setup_cb1, tester);
}


void dh_setup_cb1(SshCryptoStatus status,
                  SshPkGroupDHSecret secret,
                  const unsigned char *exchange,
                  size_t elen,
                  void *context)
{
  GroupTester tester = context;
  SshPkGroupDHSecret copy_secret;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The DH setup operation has failed with status %d", status);

  tester->exchange = ssh_xmemdup(exchange, elen);
  tester->elen = elen;

  copy_secret = ssh_pk_group_dup_dh_secret(secret);
  if (copy_secret == NULL)
    ssh_fatal("Out of memory");

  tester->copy_secret = copy_secret;

  ssh_pk_group_dh_agree_async(tester->unaccel_group, secret,
                              tester->exchange, tester->elen,
                              dh_agree_cb1, tester);
}


void dh_agree_cb1(SshCryptoStatus status,
                  const unsigned char *agreed,
                  size_t alen,
                  void *context)
{
  GroupTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("DH agree operation has failed with status %d", status);

  tester->unaccel_alen = alen;
  tester->unaccel_agreed = ssh_xmemdup(agreed, alen);

  /* Check the Diffie-Hellman agree function for the
     accelerated group using the same secret as for the
     unacclerated group gives the same shared secret (the
     comparison between the two shared secrets is done in
     the callback function dh_acc_agree_cb). */
  ssh_pk_group_dh_agree_async(tester->group, tester->copy_secret,
                              tester->exchange, tester->elen,
                              dh_agree_cb2, tester);
}


/* This callback is used when testing that the Diffie-Hellman
   agree function is identical for the software operation and
   the operation done by the accelerated device. */
void dh_agree_cb2(SshCryptoStatus status,
                  const unsigned char *agreed,
                  size_t alen,
                  void *context)
{
  GroupTester tester = context;
  tester->alen = alen;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("DH agree operation has failed, status %d", status);

  if (tester->unaccel_alen != tester->alen)
    ssh_fatal("The agree lengths do not agree, they are %d and %d\n",
              tester->unaccel_alen, tester->alen);

  if (memcmp(tester->unaccel_agreed, agreed, alen))
    { 
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("accel"), agreed, alen);
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("unaccel"), 
			tester->unaccel_agreed, alen);
			
      ssh_fatal("The Diffie-Hellman agree functions are not compatible");
    }

  ssh_xfree(tester->unaccel_agreed);
  ssh_free(tester->exchange);

  ssh_pk_group_dh_setup_async(tester->group, dh_setup_cb2, tester);
}

void dh_setup_cb2(SshCryptoStatus status,
                  SshPkGroupDHSecret secret,
                  const unsigned char *exchange,
                  size_t elen,
                  void *context)
{
  GroupTester tester = context;
  SshOperationHandle handle;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The DH setup operation has failed with status %d", status);

  tester->secret = secret;
  tester->elen = elen;
  tester->exchange = ssh_xmemdup(exchange, elen);

  SSH_DEBUG(SSH_D_MIDOK,("The DH setup function has returned, now calling"
                         " the DH agree function."));

  handle = ssh_pk_group_dh_agree_async(tester->group, tester->secret,
                                       tester->exchange, tester->elen,
                                       dh_agree_cb3, tester);

  if (abort_operations && handle != NULL)
    {
      ssh_operation_abort(handle);

      if (!tester->get_test && verbose)
        printf("Passed the group consistency tests for the group %s\n",
               tester->name);

      ssh_xfree(tester->exchange);
      ssh_pk_group_free(tester->group);
      ssh_pk_group_free(tester->unaccel_group);
      ssh_free(tester->name);
      ssh_free(tester);
    }
}

void dh_agree_cb3(SshCryptoStatus status,
                  const unsigned char *agreed,
                  size_t alen,
                  void *context)
{
  GroupTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("DH agree operation has failed with status %d", status);

  if (tester->get_test)
    SSH_DEBUG(4, ("Passed the first group test with group %s.\n",
                  tester->name));
  else
    SSH_DEBUG(4, ("Passed the second group test with group %s.\n",
                  tester->name));

  if (!tester->get_test && verbose)
    printf("Passed the group consistency tests for the group %s\n",
           tester->name);

  ssh_xfree(tester->exchange);
  ssh_pk_group_free(tester->group);
  ssh_pk_group_free(tester->unaccel_group);
  ssh_free(tester->name);
  ssh_free(tester);

  tests_pending--;
  SSH_DEBUG(4, ("Tests pending is now %d", tests_pending));
  if (tests_pending == 0)
    {
      ssh_xregister_timeout(0, 0, end_test, NULL);
    }
}
#endif /* SSHDIST_CRYPT_DH */

/********************** PUBLIC KEY TESTS ********************************/

typedef struct KeyTesterRec
{
  PkcsInfo *info;

  /* The unaccelerated software keys. */
  SshPrivateKey unaccel_prvkey;
  SshPublicKey unaccel_pubkey;

  /* The accelerated public key. */
  SshPublicKey pubkey;

  /* The accelerated private key. */
  SshPrivateKey prvkey;

  unsigned char *a, *b, *c, *ciphertext;
  size_t a_len, b_len, c_len, len, ciphertextlen;
  size_t ciphertext_len_return;
  size_t plaintext_len_return;

  unsigned char *data;
  size_t datalen;
  unsigned char *signature;
  size_t signaturelen;

  /* Some scheme information. */
  const char *sign_scheme;
  const char *enc_scheme;

  Boolean signature_test;

} *KeyTester;



/************** Consistency tests for public key operations ***************/

void get_prvkey_cb(SshEkStatus, SshPrivateKey, void *);
void get_pubkey_cb(SshEkStatus, SshPublicKey, void *);
void signature_tests(KeyTester tester);
void encryption_tests(KeyTester tester);

void prvkey_decrypt_cb1(SshCryptoStatus, const unsigned char *,
                        size_t, void *);
void prvkey_decrypt_cb2(SshCryptoStatus, const unsigned char *,
                        size_t, void *);
void prvkey_decrypt_cb3(SshCryptoStatus, const unsigned char *,
                        size_t, void *);
void prvkey_decrypt_cb4(SshCryptoStatus, const unsigned char *,
                        size_t, void *);
void pubkey_verify_cb1(SshCryptoStatus, void *);
void pubkey_verify_cb2(SshCryptoStatus, void *);
void pubkey_verify_cb3(SshCryptoStatus, void *);

void prvkey_sign_cb1(SshCryptoStatus, const unsigned char *,
                     size_t, void *);
void prvkey_sign_cb2(SshCryptoStatus, const unsigned char *,
                     size_t, void *);
void pubkey_encrypt_cb1(SshCryptoStatus, const unsigned char *,
                        size_t, void *);
void pubkey_encrypt_cb2(SshCryptoStatus, const unsigned char *,
                        size_t, void *);

/***********************************************************************/

SshUInt32 num_key_tests(void)
{
  SshUInt32 num, idx;

  for (num = 0, idx = 0; pkcs_info[idx].key_type; idx++)
    num++;

  return num;
}


/* The key tests have been adapted from the crypto library tests for check
   for the validity of the accelerated public key operations. They also
   check that the accelerated operations are the same (when possible) with
   the software operations in the crypto library. */
void key_test(void *context)
{
  SshPrivateKey private_key;
  SshPublicKey  public_key;
  KeyTester tester;
  int info_index;

  /* Test all of the key types in the pkcs_info array . */
  for (info_index = 0; pkcs_info[info_index].key_type; info_index++)
    {
      PkcsInfo *info = &pkcs_info[info_index];

      tester = ssh_xcalloc(1, sizeof(*tester));
      tester->sign_scheme =  info->sign;
      tester->enc_scheme =  info->encrypt;
      tester->info =  info;

      /* Generate a private key */
      private_key = pkcs_make_prvkey(info, 0);
      if (private_key == NULL)
        ssh_fatal("error: key generation failed.");

      /* Get the public key */
      if (ssh_private_key_derive_public_key(private_key, &public_key) !=
          SSH_CRYPTO_OK)
        ssh_fatal("error: public key derivation failed.");

      tester->unaccel_prvkey = private_key;
      tester->unaccel_pubkey = public_key;

      /* Generate the accelerated private key from the software key. */
      ssh_ek_generate_accelerated_private_key(externalkey, provider_name,
					      private_key, get_prvkey_cb,
					      tester);
    }
}


void get_prvkey_cb(SshEkStatus status,
                   SshPrivateKey prvkey,
                   void *context)
{
  KeyTester tester = context;
  SshPrivateKey copy_key;

  if (status != SSH_EK_OK)
    ssh_fatal("Failed to generate an accelerated private key");

  tester->prvkey = prvkey;

  /* Set the encryption scheme of the generated key */
  if (tester->enc_scheme &&
      ssh_private_key_select_scheme(tester->prvkey,
                                    SSH_PKF_ENCRYPT, tester->enc_scheme,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Cannot set the scheme");
    }

  /* Set the signature scheme of the generated key */
  if (tester->sign_scheme &&
      ssh_private_key_select_scheme(tester->prvkey,
                                    SSH_PKF_SIGN, tester->sign_scheme,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Cannot set the scheme");
    }

  /* Sanity test: Can we copy the accelerated private key ? */
  if ((status = ssh_private_key_copy(tester->prvkey, &copy_key))
      != SSH_CRYPTO_OK)
    ssh_fatal("Cannot copy the accelerated private key");

  ssh_private_key_free(copy_key);

  /* Generate the accelerated public key from the software key. */
  ssh_ek_generate_accelerated_public_key(externalkey,
					 provider_name,
					 tester->unaccel_pubkey,
					 get_pubkey_cb,
					 tester);
  return;
}


void get_pubkey_cb(SshEkStatus status,
                   SshPublicKey pubkey,
                   void *context)
{
  KeyTester tester = context;
  SshPublicKey copy_key;

  if (status != SSH_EK_OK)
    ssh_fatal("Failed to generate an accelerated group");

  tester->pubkey = pubkey;

  /* Set the encryption scheme of the accelerated public key */
  if (tester->enc_scheme &&
      ssh_public_key_select_scheme(tester->pubkey,
                                   SSH_PKF_ENCRYPT, tester->enc_scheme,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Cannot set the scheme");
    }

  /* Set the signature scheme of the accelerated public key */
  if (tester->sign_scheme &&
      ssh_public_key_select_scheme(tester->pubkey,
                                   SSH_PKF_SIGN, tester->sign_scheme,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Cannot set the scheme");
    }

  /* Sanity test: Can we copy the accelerated public key? */
  if ((status = ssh_public_key_copy(tester->pubkey, &copy_key))
      != SSH_CRYPTO_OK)
    ssh_fatal("Cannot copy the acc. public key");

  ssh_public_key_free(copy_key);

  /* Start the signature tests. */
  signature_tests(tester);
}

void signature_tests(KeyTester tester)
{
  /* Test pointers. */
  unsigned char *a;
  size_t a_len;
  unsigned int i;

  SSH_DEBUG(4, ("Tests pending is now %d", tests_pending));

  a_len = ssh_private_key_max_signature_input_len(tester->unaccel_prvkey);
  if (a_len == 0)
    SSH_DEBUG(3, ("Are not doing any signature tests for this %s key because "
                  "input len is 0\n", tester->info->key_type));

  if (a_len == -1)
    a_len = 1024;

  a = ssh_xmalloc(a_len);

  for (i = 0; i < a_len; i++)
    {
      a[i] = i & 0xf;
    }

  tester->a = a;
  tester->a_len = a_len;

  ssh_private_key_sign_async(tester->unaccel_prvkey, a, a_len,
                             prvkey_sign_cb1, tester);
}


void prvkey_sign_cb1(SshCryptoStatus status,
                     const unsigned char *signature,
                     size_t signaturelen,
                     void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Private key sign has failed, with status %d", status);

  tester->b_len = signaturelen;
  tester->b = ssh_xmemdup(signature, signaturelen);

  tester->len = tester->b_len;

  SSH_DEBUG(SSH_D_MIDOK, ("Are now going to sign"
                          " using the accelerated key"));

  /* Sign the same buffer using the accelerated key. */
  ssh_private_key_sign_async(tester->prvkey, tester->a, tester->a_len,
                             prvkey_sign_cb2, tester);
}


void prvkey_sign_cb2(SshCryptoStatus status,
                     const unsigned char *signature,
                     size_t signaturelen,
                     void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Private key sign has failed, with status %d", status);

  tester->signaturelen = signaturelen;
  tester->signature = ssh_xmemdup(signature, signaturelen);

  if (tester->signaturelen != tester->len)
    ssh_fatal("error: pkcs %s signature lengths do not agree. returned %d"
              " expected %d",
              tester->info->key_type, tester->signaturelen, tester->len);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Are now going to verify the "
             "signature with the accelerated key"));

  /* Verify the signature using the accelerated key. */
  ssh_public_key_verify_async(tester->pubkey,
                              tester->signature,
                              tester->signaturelen,
                              tester->a, tester->a_len,
                              pubkey_verify_cb1, tester);

}

void pubkey_verify_cb1(SshCryptoStatus status,
                       void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The Signature verification op. has failed "
              "with status %s (%d)",
	      ssh_crypto_status_message(status), status);

  /* Check that signing using the accelerated key and verification
     using the software key succeeds. If this test passes we can
     be reasonably confident the accelerated key functions in an
     identical manner to the software key. */
  ssh_public_key_verify_async(tester->unaccel_pubkey,
                              tester->signature,
                              tester->signaturelen,
                              tester->a, tester->a_len,
                              pubkey_verify_cb2, tester);

}


void pubkey_verify_cb2(SshCryptoStatus status,
                       void *context)
{
  KeyTester tester = context;
  SshOperationHandle handle;
  const char *sig_name;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The Signature verification op. has failed "
              "with status %s (%d)",
	      ssh_crypto_status_message(status), status);

  /* For RSA PKCS1 signatures, verify the signature 50% of the time using
     the rsa-pkcs1-implicit scheme. */
  if (ssh_random_get_byte() & 0x1)
    {
      if (ssh_public_key_get_info(tester->pubkey,
				  SSH_PKF_SIGN, &sig_name,
				  SSH_PKF_END) != SSH_CRYPTO_OK)
	{
	  ssh_fatal("error: ssh_public_key_get_info failed");
	}

      if (strstr(sig_name, "rsa-pkcs1-") &&
	  strcmp(sig_name, "rsa-pkcs1-none"))
	{
	  SSH_DEBUG(SSH_D_HIGHOK, ("Selecting RSA PKCS1 implicit scheme, "
				   "original scheme was %s", sig_name));

	  status = ssh_public_key_select_scheme(tester->pubkey,
						SSH_PKF_SIGN,
						"rsa-pkcs1-implicit",
						SSH_PKF_END);
	  SSH_VERIFY(status == SSH_CRYPTO_OK);
	}
    }

  /* Check that signing using the software key and verification
     using the accelerated key succeeds. If this test passes we can
     be reasonably confident the accelerated key functions in an
     identical manner to the software key. */
  handle = ssh_public_key_verify_async(tester->pubkey,
                                       tester->b, tester->b_len,
                                       tester->a, tester->a_len,
                                       pubkey_verify_cb3, tester);

  if (abort_operations && handle != NULL)
    {
      ssh_operation_abort(handle);

      ssh_xfree(tester->signature);
      ssh_xfree(tester->a);
      ssh_xfree(tester->b);

      SSH_DEBUG(3, ("Passed all signature tests for key type %s\n",
                    tester->info->key_type));

      /* Start the Encryption tests. */
      encryption_tests(tester);
    }
}

void pubkey_verify_cb3(SshCryptoStatus status,
                       void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The Signature verification operation has failed "
              "with status %s (%d)",
	      ssh_crypto_status_message(status), status);

  ssh_xfree(tester->signature);
  ssh_xfree(tester->a);
  ssh_xfree(tester->b);

  SSH_DEBUG(3, ("Passed all signature tests for key type %s\n",
                tester->info->key_type));

  /* Start the Encryption tests. */
  encryption_tests(tester);
}

/**********************************************************************/

void encryption_tests(KeyTester tester)

{
  size_t a_len, b_len, c_len, d_len;
  int i;

  a_len = ssh_public_key_max_encrypt_input_len(tester->unaccel_pubkey);
  tester->a_len = ssh_public_key_max_encrypt_input_len(tester->pubkey);

  if (a_len != tester->a_len)
    ssh_warning("The encryption input lengths do not agree, %d got %d\n",
              a_len, tester->a_len);

  if (a_len == 0)
    {
      SSH_DEBUG(3, ("Are not doing any encryption tests for this %s key "
                    "because this is not an encryption key\n",
                    tester->info->key_type));

      if (verbose)
        printf("Passed the key consistency tests for the key {%s,%s}\n",
               tester->sign_scheme, tester->enc_scheme);

      ssh_public_key_free(tester->unaccel_pubkey);
      ssh_private_key_free(tester->unaccel_prvkey);
      ssh_public_key_free(tester->pubkey);
      ssh_private_key_free(tester->prvkey);
      ssh_xfree(tester);

      tests_pending--;
      SSH_DEBUG(4, ("Tests pending is now %d", tests_pending));
      if (tests_pending == 0)
	{
	  ssh_xregister_timeout(0, 0, end_test, NULL);
	}
      return;
    }

  b_len = ssh_public_key_max_encrypt_output_len(tester->unaccel_pubkey);
  tester->b_len = ssh_public_key_max_encrypt_output_len(tester->pubkey);

  if (b_len != tester->b_len)
    ssh_fatal("The encryption output lengths do not agree\n");

  if (a_len == -1)
    a_len = tester->a_len = 1024;

  tester->a = ssh_xmalloc(a_len);

  c_len = ssh_private_key_max_decrypt_input_len(tester->unaccel_prvkey);
  d_len = ssh_private_key_max_decrypt_input_len(tester->prvkey);

  if (c_len != d_len)
    ssh_fatal("The decryption input lengths do not agree\n");

  c_len = ssh_private_key_max_decrypt_output_len(tester->unaccel_prvkey);
  tester->c_len = ssh_private_key_max_decrypt_output_len(tester->prvkey);

  if (c_len != tester->c_len)
    ssh_fatal("The decryption output lengths do not agree\n");

  for (i = 0; i < a_len; i++)
    {
      tester->a[i] = ssh_random_get_byte() & 0xff;
    }

  /* Encrypt with the unaccelerated key. */
  ssh_public_key_encrypt_async(tester->unaccel_pubkey,
                               tester->a, tester->a_len,
                               pubkey_encrypt_cb1, tester);
}


void pubkey_encrypt_cb1(SshCryptoStatus status,
                        const unsigned char *ciphertext,
                        size_t ciphertextlen,
                        void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Public key Encrypt operation failed with status %d", status);

  tester->b_len = ciphertextlen;
  tester->ciphertext_len_return = ciphertextlen;
  tester->b = ssh_xmemdup(ciphertext, ciphertextlen);

  /* Encrypt the same buffer with the accelerated key. */
  ssh_public_key_encrypt_async(tester->pubkey, tester->a, tester->a_len,
                               pubkey_encrypt_cb2, tester);

}



void pubkey_encrypt_cb2(SshCryptoStatus status,
                        const unsigned char *ciphertext,
                        size_t ciphertextlen,
                        void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Public key encrypt operation failed with status %d", status);

  tester->ciphertextlen = ciphertextlen;
  tester->ciphertext = ssh_xmemdup(ciphertext, ciphertextlen);

  /* Check the cipher text lengths are equal */
  if (tester->ciphertextlen != tester->ciphertext_len_return)
    {
      ssh_fatal("Ciphertext lengths do not agree %d %d\n",
                tester->ciphertextlen, tester->ciphertext_len_return);
    }

  /* Decrypt the encrypted buffer with the unaccelerated key. */
  ssh_private_key_decrypt_async(tester->unaccel_prvkey, tester->b,
                                tester->ciphertext_len_return,
                                prvkey_decrypt_cb1,
                                tester);
}

void prvkey_decrypt_cb1(SshCryptoStatus status,
                        const unsigned char *data,
                        size_t datalen, void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The prvkey decrypt operation has failed"
              " with status %d", status);

  tester->plaintext_len_return = datalen;
  tester->c_len = datalen;
  tester->c = ssh_xmemdup(data, datalen);

  /* Decrypt the encrypted buffer with the accelerated key. */
  ssh_private_key_decrypt_async(tester->prvkey, tester->ciphertext,
                                tester->ciphertextlen,
                                prvkey_decrypt_cb2,
                                tester);

}

void prvkey_decrypt_cb2(SshCryptoStatus status,
                        const unsigned char *data,
                        size_t datalen, void *context)
{
  KeyTester tester = context;
  SshOperationHandle handle;
  size_t c_len;
  unsigned int i;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The prvkey decrypt operation has failed"
              " with status %d", status);

  c_len = tester->plaintext_len_return;

  /* Verify that encryption + decryption gives back the same plaintext
     for the software and accelerated keys. */
  for (i = 0; i < c_len; i++)
    {
      if (tester->c[i] != tester->a[i])
        ssh_fatal("error: pkcs %s software decryption failed.",
                  tester->info->key_type);
      if (data[i] != tester->a[i])
        ssh_fatal("error: pkcs %s accelerated decryption failed.",
                  tester->info->key_type);
    }

  /* Check that encryption using the software key and decryption using the
     accelerated key also gives back the same original plaintext. */
  handle = ssh_private_key_decrypt_async(tester->prvkey,
                                         tester->b,
                                         tester->ciphertext_len_return,
                                         prvkey_decrypt_cb3,
                                         tester);

  if (abort_operations && handle != NULL)
    {
      ssh_operation_abort(handle);

      if (verbose)
        printf("Passed the key consistency tests for the key {%s,%s}\n",
               tester->sign_scheme, tester->enc_scheme);

      ssh_xfree(tester->ciphertext);
      ssh_xfree(tester->a);
      ssh_xfree(tester->b);
      ssh_xfree(tester->c);

      ssh_public_key_free(tester->unaccel_pubkey);
      ssh_private_key_free(tester->unaccel_prvkey);
      ssh_public_key_free(tester->pubkey);
      ssh_private_key_free(tester->prvkey);
      ssh_xfree(tester);
      return;
    }

}


void prvkey_decrypt_cb3(SshCryptoStatus status,
                        const unsigned char *data,
                        size_t datalen, void *context)
{
  KeyTester tester = context;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The prvkey decrypt operation has failed"
              " with status %d", status);

  tester->datalen = datalen;
  tester->data = ssh_xmemdup(data, datalen);

  /* Check that encryption using the accelerated key and decryption using
     the software key also gives back the same original plaintext. */
  ssh_private_key_decrypt_async(tester->unaccel_prvkey,
                                tester->ciphertext,
                                tester->ciphertextlen,
                                prvkey_decrypt_cb4,
                                tester);
}


void prvkey_decrypt_cb4(SshCryptoStatus status,
                        const unsigned char *data,
                        size_t datalen,
                        void *context)
{
  KeyTester tester = context;
  unsigned int i;

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("The prvkey decrypt operation has failed"
              " with status %d", status);

  if (tester->datalen != datalen)
    ssh_fatal("The decryption lengths do not match");

  /* If this test passes we can be reasonably confident
     the accelerated key functions in an identical manner
     to the software key. */
  for (i = 0; i < datalen; i++)
    {
      if (data[i] != tester->a[i])
        ssh_fatal("error: pkcs %s decryption failed.",
                  tester->info->key_type);

      if (data[i] != tester->a[i])
        ssh_fatal("error: pkcs %s acc. decryption"
                  " failed.", tester->info->key_type);
    }

  if (verbose)
    printf("Passed the key consistency tests for the key {%s,%s}\n",
           tester->sign_scheme, tester->enc_scheme);

  ssh_xfree(tester->ciphertext);
  ssh_xfree(tester->a);
  ssh_xfree(tester->b);
  ssh_xfree(tester->c);
  ssh_xfree(tester->data);

  ssh_public_key_free(tester->unaccel_pubkey);
  ssh_private_key_free(tester->unaccel_prvkey);
  ssh_public_key_free(tester->pubkey);
  ssh_private_key_free(tester->prvkey);
  ssh_xfree(tester);

  tests_pending--;
  SSH_DEBUG(4, ("Tests pending is now %d", tests_pending));
  if (tests_pending == 0)
    {
      ssh_xregister_timeout(0, 0, end_test, NULL);
    }
}

/*************************** RANDOMNESS TESTS ***************************/

SshUInt32 num_random_tests(void)
{
  return 1;
}

void random_bytes_cb(SshEkStatus status,
                     const unsigned char *random_bytes,
                     size_t random_bytes_len,
                     void *context)
{
  if (status != SSH_EK_OK && status != SSH_EK_OPERATION_NOT_SUPPORTED)
    ssh_fatal("Getting random bytes failed with status %s",
              ssh_ek_get_printable_status(status));

  tests_pending--;
  SSH_DEBUG(4, ("Tests pending is now %d", tests_pending));
  if (tests_pending == 0)
    {
      ssh_xregister_timeout(0, 0, end_test, NULL);
      return;
    }

  if (status == SSH_EK_OPERATION_NOT_SUPPORTED)
    {
      SSH_DEBUG(3, ("This accelerator cannot get random bytes"));
      return;
    }

  SSH_DEBUG(5, ("Obtained %d random bytes\n", random_bytes_len));
}


void random_test(void *context)
{
  size_t bytes_requested;

  bytes_requested = ssh_random_get_byte();

  if (bytes_requested == 0)
    bytes_requested++;

  SSH_DEBUG(3, ("Asking for %d random bytes\n", bytes_requested));

  ssh_ek_get_random_bytes(externalkey, provider_name, bytes_requested,
                          random_bytes_cb, NULL);
}





/*******************************************************************/

void usage()
{
  char *str;
  printf("Usage: t-genacc [options] device-name\n"
         "-i device info\n"
         "-a Abort crypto operations\n"
         "-v Verbose output\n"
         "-d debuglevel\n");

  printf("\nWhen called without any options, the program performs the\n"
         "consistency tests on the specified device.\n");
  str = ssh_acc_device_get_supported();
  printf("\nThe supported device names are %s\n", str);
  ssh_free(str);
}


int main(int ac, char **av)
{
  SshUInt32 num_providers;
  SshEkStatus status;
  SshEkProvider provider_array;
  char *device_name = NULL, *device_info = NULL;
  char *sname, *init_str;
  Boolean rsa_crt = TRUE;
  int opt;

  while ((opt = ssh_getopt(ac, av, "i:ad:vh", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'i':
          device_info = ssh_optarg;
          break;
        case 'a':
          abort_operations = TRUE;
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 'v':
          verbose = TRUE;
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
  
  if (ssh_random_get_byte() & 0x1)
    rsa_crt = FALSE;

  ssh_dsprintf((unsigned char **) &init_str, 
	       "name(%s),device-info(%s),rsa-crt(%s)",
               device_name, device_info, rsa_crt ? "yes" : "no");

  SSH_DEBUG(4, ("The init string is %s\n", init_str));

  /* Add the provider */
  if ((status = ssh_ek_add_provider(externalkey, "genacc",
                                    init_str,
                                    NULL,
                                    SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                    &sname)) != SSH_EK_OK)
    ssh_fatal("Unable to add the provider");

  ssh_free(init_str);
  ssh_free(sname);

  /* Add the software provider */
  if ((status = ssh_ek_add_provider(externalkey, "software",
                                    NULL,
                                    NULL,
                                    SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                    &sname)) != SSH_EK_OK)
    ssh_fatal("Unable to add the soft provider");

  /* Remove the soft provider */
  ssh_ek_remove_provider(externalkey, sname);
  ssh_free(sname);

  SSH_DEBUG(10, (ssh_ek_get_printable_status(status)));

  /* Get all the registered providers. */
  if (!ssh_ek_get_providers(externalkey, &provider_array, &num_providers))
    ssh_fatal("Cannot get the providers");

  provider_name = (char *) (provider_array[0]).short_name;
  ssh_free(provider_array);

  SSH_DEBUG(10, ("Enabling provider %s", provider_name));

  /* Run the consistency group tests. */
  SSH_DEBUG(3, ("Now starting the DH group tests for provider %s\n",
		provider_name));
  
#ifdef SSHDIST_CRYPT_DH
  tests_pending = num_group_tests();
#endif /* SSHDIST_CRYPT_DH */
  tests_pending += num_random_tests();
  tests_pending += num_key_tests();
  
#ifdef SSHDIST_CRYPT_DH
  ssh_xregister_timeout(0, 0, group_test, NULL);
#endif /* SSHDIST_CRYPT_DH */
  ssh_xregister_timeout(0, 0, random_test, NULL);
  ssh_xregister_timeout(0, 0, key_test, NULL);
  
  ssh_event_loop_run();
  return 0;
}
