/*

  t-proxykey.c

  Copyright:
  	Copyright (c) 2002-2005 SFNT Finland Oy.
	All rights reserved.

  A simple test program for proxy keys.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshgetopt.h"
#include "sshcrypt.h"
#include "sshproxykey.h"

#define SSH_DEBUG_MODULE "TestProxyKey"

const char *rsa_scheme = "rsa-pkcs1-sha1";
const char *dsa_scheme = "dsa-nist-sha1";
const char *dh_scheme = "plain";


#define SIG_DATA "Some random data to be signed."
#define ENC_DATA "Encrypt this"

typedef struct ProxyKeyTestContextRec {
  SshPkGroup pk_group;
  Boolean pending;
  char *msg;
} *ProxyKeyTestContext;


void free_op_cb(void *context)
{
  ProxyKeyTestContext ctx = context;

  ssh_xfree(ctx->msg);
  ssh_xfree(ctx);
}


SshOperationHandle key_op_cb(SshProxyOperationId operation_id,
                             SshProxyRGFId rgf_id,
                             SshProxyKeyHandle handle,
                             const unsigned char *input_data,
                             size_t input_data_len,
                             SshProxyReplyCB reply_cb,
                             void *reply_context,
                             void *context)
{
  ProxyKeyTestContext ctx = context;

  SSH_DEBUG(5, ("The message is %s", ctx->msg));

  /* For Diffie Hellman setup we need to return some non NULL data
     to the proxykey library. */
  if (operation_id == SSH_DH_SETUP)
    {
      unsigned char exchange[8], secret[8], *data;
      size_t data_len;

      /* Give some arbitrary values to the DH exchange and secret buffers. */
      memset(exchange, 0x1e, sizeof(exchange));
      memset(secret, 0xe1, sizeof(secret));

      data_len =
	ssh_encode_array_alloc(&data,
			       SSH_ENCODE_UINT32_STR(exchange,
						     sizeof(exchange)),
			       SSH_ENCODE_UINT32_STR(secret,
						     sizeof(secret)),
			       SSH_FORMAT_END);
      if (!data)
        ssh_fatal("No memory.");

      /* Return the data */
      (*reply_cb)(SSH_CRYPTO_OK, data, data_len, reply_context);
      ssh_free(data);
      return NULL;
    }

  /* This suffices for all other operations. */
  (*reply_cb)(SSH_CRYPTO_OK, NULL, 0, reply_context);
  return NULL;
}




/********************   PRIVATE KEY  TEST   *****************************/


void sign_cb(SshCryptoStatus status,
             const unsigned char *signature_buffer,
             size_t signature_buffer_len,
             void *context)
{
  ProxyKeyTestContext ctx = context;

  SSH_ASSERT(status == SSH_CRYPTO_OK);
  ctx->pending = FALSE;
}


Boolean private_key_test(SshProxyKeyTypeId key_type, SshUInt32 key_size)
{
  SshPrivateKey private_key, private_key_copy;
  SshPublicKey public_key;
  ProxyKeyTestContext context;
  SshCryptoStatus status;
  Boolean success = FALSE;
  const char *sig_scheme = NULL;

  context = ssh_xcalloc(1, sizeof(*context));
  context->msg = ssh_xstrdup("'this is a private proxy key'");

  private_key = ssh_private_key_create_proxy(key_type,
                                             key_size,
                                             key_op_cb,
                                             free_op_cb,
                                             context);
  if (!private_key)
    {
      SSH_DEBUG(2, ("Cannot generate a proxy private key"));
      goto fail;
    }

  /* Try to derive a public key, this should fail. */
  status = ssh_private_key_derive_public_key(private_key, &public_key);
  SSH_DEBUG(5, ("Private key derived public key status: %s",
                ssh_crypto_status_message(status)));

  if (status != SSH_CRYPTO_UNSUPPORTED)
     goto fail;

  /* Try to copy the private key, should not fail. */
  if ((status = ssh_private_key_copy(private_key, &private_key_copy))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Private key copy failed with status: %s",
                    ssh_crypto_status_message(status)));
      goto fail;
    }

  ssh_private_key_free(private_key_copy);

  if (key_type == SSH_PROXY_RSA)
    sig_scheme = rsa_scheme;
  else if (key_type == SSH_PROXY_DSA)
    sig_scheme = dsa_scheme;
  else
    SSH_NOTREACHED;

  /* Verify we can set the scheme */
  if ((status = ssh_private_key_select_scheme(private_key,
                                              SSH_PKF_SIGN,
                                              sig_scheme,
                                              SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Private key select scheme failed with status: %s",
                  ssh_crypto_status_message(status)));
      goto fail;
    }

  context->pending = TRUE;

  /* 'Sign' some data */
  ssh_private_key_sign_async(private_key,
                             (unsigned char *)SIG_DATA,
                             strlen(SIG_DATA) + 1,
                             sign_cb, context);

  /* Wait until the operation is finished. */
  while (1)
    {
      if (!context->pending)
        break;
    }

  success = TRUE;

 fail:
  ssh_private_key_free(private_key);
  return success;
}


/********************   PUBLIC KEY TEST   ***************************/


void encrypt_cb(SshCryptoStatus status,
             const unsigned char *ciphertext_buffer,
             size_t ciphertext_buffer_len,
             void *context)
{
  ProxyKeyTestContext ctx = context;

  SSH_ASSERT(status == SSH_CRYPTO_OK);
  ctx->pending = FALSE;
}


Boolean public_key_test(SshProxyKeyTypeId key_type, SshUInt32 key_size)
{
  SshPublicKey public_key, public_key_copy;
  ProxyKeyTestContext context;
  SshCryptoStatus status;
  Boolean success = FALSE;
  const char *enc_scheme = NULL;

  context = ssh_xcalloc(1, sizeof(*context));
  context->msg = ssh_xstrdup("'this is a public proxy key'");

  public_key = ssh_public_key_create_proxy(key_type,
                                           key_size,
                                           key_op_cb,
                                           free_op_cb,
                                           context);
  if (!public_key)
    {
      SSH_DEBUG(2, ("Cannot generate a proxy public key"));
      goto fail;
    }

  /* Try to copy the public key, should not fail. */
  if ((status = ssh_public_key_copy(public_key, &public_key_copy))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Public key copy failed with status: %s",
                    ssh_crypto_status_message(status)));
      goto fail;
    }

  ssh_public_key_free(public_key_copy);

  if (key_type == SSH_PROXY_RSA)
    enc_scheme = "rsa-pkcs1-none";
  else if (key_type == SSH_PROXY_DSA)
    enc_scheme = NULL;
  else
    SSH_NOTREACHED;

  if (!enc_scheme)
    {
      ssh_public_key_free(public_key);
      return TRUE;
    }

  /* Verify we can set the scheme */
  if ((status = ssh_public_key_select_scheme(public_key,
                                             SSH_PKF_ENCRYPT,
                                             enc_scheme,
                                             SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Public key select scheme failed with status: %s",
                    ssh_crypto_status_message(status)));
      goto fail;
    }


  context->pending = TRUE;

  /* 'Encrypt' some data */
  ssh_public_key_encrypt_async(public_key,
                               (unsigned char *)ENC_DATA,
                               strlen(ENC_DATA) + 1,
                               encrypt_cb, context);

  /* Wait until the operation is finished. */
  while (1)
    {
      if (!context->pending)
        break;
    }

  success = TRUE;

 fail:
  ssh_public_key_free(public_key);
  return success;
}

#ifdef SSHDIST_CRYPT_GENPKCS_DH

/**********************   GROUP TEST   *********************************/

void dh_agree_cb(SshCryptoStatus status,
                 const unsigned char *shared_secret_buffer,
                 size_t shared_secret_buffer_len,
                 void *context)
{
  ProxyKeyTestContext ctx = context;

  SSH_ASSERT(status == SSH_CRYPTO_OK);

  ctx->pending = FALSE;
}


void dh_setup_cb(SshCryptoStatus status,
                 SshPkGroupDHSecret secret,
                 const unsigned char *exchange_buffer,
                 size_t exchange_buffer_len,
                 void *context)
{
  ProxyKeyTestContext ctx = context;

  SSH_ASSERT(status == SSH_CRYPTO_OK);

  ssh_pk_group_dh_agree_async(ctx->pk_group,
                              secret,
                              NULL, 0,
                              dh_agree_cb,
                              context);

}

Boolean pk_group_test(SshProxyKeyTypeId key_type, SshUInt32 key_size)
{
  SshPkGroup pk_group, pk_group_copy;
  ProxyKeyTestContext context;
  SshCryptoStatus status;
  Boolean success = FALSE;

  context = ssh_xcalloc(1, sizeof(*context));
  context->msg = ssh_xstrdup("'this is a proxy pk group'");

  pk_group = ssh_dh_group_create_proxy(key_type,
                                       key_size,
                                       key_op_cb,
                                       free_op_cb,
                                       context);
  if (!pk_group)
    {
      SSH_DEBUG(2, ("Cannot generate a proxy dh group"));
      goto fail;
    }

  context->pk_group = pk_group;

  /* Try to copy the group */
  if ((status = ssh_pk_group_copy(pk_group, &pk_group_copy))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Group copy failed with status: %s",
                    ssh_crypto_status_message(status)));
      goto fail;
    }

  ssh_pk_group_free(pk_group_copy);

    /* Verify we can set the scheme */
  if ((status = ssh_pk_group_select_scheme(pk_group,
                                           SSH_PKF_DH,
                                           dh_scheme,
                                           SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Pk group select scheme failed with status: %s",
                    ssh_crypto_status_message(status)));
      goto fail;
    }

  context->pending = TRUE;

  /* Do Diffie-Hellman */
  ssh_pk_group_dh_setup_async(pk_group,
                              dh_setup_cb,
                              context);

  /* Wait until the operation is finished. */
  while (1)
    {
      if (!context->pending)
        break;
    }

  success = TRUE;

 fail:
  ssh_pk_group_free(pk_group);
  return success;
}
#endif /* SSHDIST_CRYPT_GENPKCS_DH */


/***********************************************************************/

int main(int argc, char **argv)
{
  SshUInt32 key_size;
  Boolean failed = FALSE;
  char *debuglevel = NULL;
  int opt;

  while ((opt = ssh_getopt(argc, argv, "d:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'd':
          debuglevel = ssh_optarg;
          break;
        default:
          fprintf(stderr, "usage: t-proxykey [-d debuglevel]\n");
          exit(1);
        }
    }

  if (debuglevel)
    ssh_debug_set_level_string(debuglevel);

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");

  for (key_size = 512; key_size <= 1536; key_size += 512)
    {
      if (!private_key_test(SSH_PROXY_RSA, key_size))
        failed = TRUE;

      if (!private_key_test(SSH_PROXY_DSA, key_size))
        failed = TRUE;

      if (!public_key_test(SSH_PROXY_RSA, key_size))
        failed = TRUE;

      if (!public_key_test(SSH_PROXY_DSA, key_size))
        failed = TRUE;

#ifdef SSHDIST_CRYPT_GENPKCS_DH
      if (!pk_group_test(SSH_PROXY_GROUP, key_size))
        failed = TRUE;
#endif /* SSHDIST_CRYPT_GENPKCS_DH */
    }

  if (!failed)
    printf("All tests passed\n");
  else
    printf("The proxykey test has failed\n\n");

  ssh_crypto_library_uninitialize();
  ssh_debug_uninit();
  ssh_util_uninit();

  exit(0);
}
