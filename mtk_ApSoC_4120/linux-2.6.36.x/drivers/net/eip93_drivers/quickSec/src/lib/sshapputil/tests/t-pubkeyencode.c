/*

  t-pubkeyencode.c

  Author: Markku-Juhani Saarinen <mjos@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved

  Test the pubkeyencode functions.

  */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "ssh2pubkeyencode.h"
#include "sshcipherlist.h"

#ifndef T_PUBKEYENCODE_ITERATIONS
#define T_PUBKEYENCODE_ITERATIONS 1
#endif /* T_PUBKEYENCODE_ITERATIONS */

const char plaintext[] =
  "huuhaa jeejee superjee niks naks super";

void simple_test(char *keytype, int keybits)
{
  SshCryptoStatus code;
  SshPublicKey pubkey, pubkey2;
  SshPrivateKey privkey;
  unsigned char *blob1, *blob2;
  size_t len1, len2;
  unsigned char *signature;
  size_t siglen, siglenr;

  /* generate a private key and a matching public key */

  if (ssh_private_key_generate(&privkey, keytype,
                               SSH_PKF_SIZE, keybits,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("unable to generate %d - bit private key of type :"
              "\n%s\n", keybits, keytype);

  if (ssh_private_key_derive_public_key(privkey, &pubkey) != SSH_CRYPTO_OK)
    ssh_fatal("can't derive public key from private key just generated.");

  /* encode and decode the public key */

  if ((len1 = ssh_encode_pubkeyblob(pubkey, &blob1)) == 0)
    ssh_fatal("ssh_encode_pubkeyblob() failed (1).");

  if ((pubkey2 = ssh_decode_pubkeyblob(blob1, len1)) == NULL)
    ssh_fatal("ssh_decode_pubkeyblob() failed.");

  /* encode again to and compare blobs */
  if ((len2 = ssh_encode_pubkeyblob(pubkey2, &blob2)) == 0)
    ssh_fatal("ssh_encode_pubkeyblob() failed (2).");

  if (len1 != len2)
    ssh_fatal("blob length mismatch.");
  if (memcmp(blob1, blob2, len1) != 0)
    ssh_fatal("blob's don't match.");

  /* sign something */

  siglen = ssh_private_key_max_signature_output_len(privkey);
  signature = ssh_xmalloc(siglen);

  code = ssh_private_key_sign(privkey, (unsigned char *)plaintext,
                              strlen(plaintext),
                              signature, siglen, &siglenr);
  if (code != SSH_CRYPTO_OK)
    ssh_fatal("ssh_private_key_sign() failed (%s).",
              ssh_crypto_status_message(code));

  /* ok, now verify the signature with our decoded public key */

  if (ssh_public_key_verify_signature(pubkey2, signature, siglenr,
                                      (unsigned char *)plaintext,
                                      strlen(plaintext)) != SSH_CRYPTO_OK)
    ssh_fatal("signature verification failed for key %s and keysize %d.",
              keytype, keybits);

  ssh_xfree(blob1);
  ssh_xfree(blob2);
  ssh_xfree(signature);

  ssh_public_key_free(pubkey);
  ssh_public_key_free(pubkey2);
  ssh_private_key_free(privkey);
}


int main(int argc, char **argv)
{
  int i;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    return 1;

  for (i = 0; i < T_PUBKEYENCODE_ITERATIONS; i++)
    {
#ifdef SSHDIST_CRYPT_DSA
      simple_test(SSH_CRYPTO_DSS, 64 * i + 512);
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_RSA
      simple_test(SSH_CRYPTO_RSA, 64 * i + 512);
#endif /* SSHDIST_CRYPT_RSA */
    }

  return 0;
}
