#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshcrypt.h"
#include "sshregression.h"
#include "parser.h"
#include "t-gentest.h"

#define SSH_DEBUG_MODULE "PkcsImportExport"

/************************************************************************/

/* Some key types we generate. */
typedef struct {
  const char *name;
  unsigned int size;
} PkcsKeyInfo;

typedef struct {
  const char *name;
  const unsigned char *key;
  size_t keylen;
} PkcsExportCipherInfo;

PkcsKeyInfo key_types[] = {
  { "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}", 768 },
  { "dl-modp{sign{dsa-nist-sha1},dh{plain}}", 768 },
  { NULL }
};

PkcsExportCipherInfo export_types[] = {
  { "none", NULL, 0 },
  { "3des-cbc", "34567890123456782345678", 24 },
  { "aes-cbc", "0123456701234567", 16 },
  { NULL }
};

#define N_KEYS 16

Boolean
pkcs_import_export_tests_do(const char *filename)
{
  FILE *fp;
  PkcsKeyInfo *key;
  PkcsExportCipherInfo *exp;
  SshPrivateKey private_key;
  SshPublicKey public_key;
  SshPkGroup pk_group;
  SshCryptoStatus status;
  int i, n;
  unsigned char *buf;
  size_t buflen;

  if (!(fp = fopen(filename, "w")))
    {
      fprintf(stderr, "Cannot open '%s' for writing.\n",
              filename);
      return FALSE;
    }

  fprintf(stderr, "Generating import/export test material to file "
          "`%s'\n", filename);

  fprintf(stderr,
          "\n"
          "\tWARNING: Do not indiscriminantly copy the generated over\n"
          "\tthe existing `import-export.tests' file, as the generated\n"
          "\tversion contains exported keys only in the *current* export\n"
          "\tformat, whereas the `import-export.tests' file contains\n"
          "\talso backward-compatibility test vectors. Thus, you must\n"
          "\tdetermine manually how to merge the new generated file\n"
          "\tinto the old test data.\n\n");

  fprintf(stderr,
          "\tFor example, generating verify-...-import-failure test\n"
          "\tvectors requires you to manually corrupt the generated\n"
          "\t*valid* test vectors!\n\n");

  for (key = key_types; key->name; key++)
    {
      for (n = 0; n < N_KEYS; n++)
        {
          status = ssh_private_key_generate(&private_key,
                                            key->name,
                                            SSH_PKF_SIZE, key->size,
                                            SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              fprintf(stderr, "Could not generate `%s' private key: %s\n",
                      key->name, ssh_crypto_status_message(status));

              return FALSE;
            }

          /* Derive public key, print it out for cross-verification */
          status = ssh_private_key_derive_public_key(private_key, &public_key);

          if (status != SSH_CRYPTO_OK)
            {
              fprintf(stderr, "Could not derive public key from `%s' "
                      "private key: %s\n",
                      key->name, ssh_crypto_status_message(status));

              ssh_private_key_free(private_key);
              return FALSE;
            }

          status = ssh_pk_export(&buf, &buflen,
                                 SSH_PKF_PUBLIC_KEY, public_key,
                                 SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              fprintf(stderr, "Could not export `%s' public key: %s\n",
                      key->name, ssh_crypto_status_message(status));

              ssh_public_key_free(public_key);
              ssh_private_key_free(private_key);
              return FALSE;
            }

          fprintf(fp, "paired-public-key ");
          for (i = 0; i < buflen; i++)
            fprintf(fp, "%02x", buf[i]);
          fprintf(fp, "\n");
          ssh_free(buf);

          ssh_public_key_free(public_key);

          status = ssh_pk_group_generate(&pk_group,
                                         "dl-modp",
                                         SSH_PKF_PREDEFINED_GROUP,
                                         "ietf-ike-grp-modp-1024",
                                         SSH_PKF_RANDOMIZER_ENTROPY, 180,
                                         SSH_PKF_DH, "plain",
                                         SSH_PKF_END);

          if (status != SSH_CRYPTO_OK && status != SSH_CRYPTO_UNSUPPORTED)
            {
              fprintf(stderr, "Could not derive group from private "
                      "key `%s': %s\n",
                      key->name, ssh_crypto_status_message(status));
              ssh_private_key_free(private_key);
              return FALSE;
            }

          if (status == SSH_CRYPTO_OK)
            {
              status = ssh_pk_export(&buf, &buflen,
                                     SSH_PKF_PK_GROUP, pk_group,
                                     SSH_PKF_END);

              if (status != SSH_CRYPTO_OK)
                {
                  fprintf(stderr, "Could not export `%s' based group: %s\n",
                          key->name, ssh_crypto_status_message(status));

                  ssh_pk_group_free(pk_group);
                  ssh_private_key_free(private_key);
                  return FALSE;
                }

              fprintf(fp, "paired-pk-group ");
              for (i = 0; i < buflen; i++)
                fprintf(fp, "%02x", buf[i]);
              fprintf(fp, "\n");
              ssh_free(buf);

              /* generate and export randomizer */
              for (i = 0; i < 1000; i++)
                {
                  status = ssh_pk_group_generate_randomizer(pk_group);

                  if (status != SSH_CRYPTO_OK)
                    {
                      fprintf(stderr, "Could not generate "
                              "randomizers for `%s' based group: %s\n",
                              key->name, ssh_crypto_status_message(status));
                      ssh_pk_group_free(pk_group);
                      ssh_private_key_free(private_key);
                      return FALSE;
                    }
                }

                status =
                ssh_pk_export(&buf, &buflen,
                              SSH_PKF_PK_GROUP_RANDOMIZERS, pk_group,
                              SSH_PKF_END);

              if (status != SSH_CRYPTO_OK)
                {
                  fprintf(stderr, "Could not export "
                          "randomizers for `%s' based group: %s\n",
                          key->name, ssh_crypto_status_message(status));
                  ssh_pk_group_free(pk_group);
                  ssh_private_key_free(private_key);
                  return FALSE;
                }

              fprintf(fp, "paired-group-randomizers ");
              for (i = 0; i < buflen; i++)
                fprintf(fp, "%02x", buf[i]);
              fprintf(fp, "\n");
              ssh_free(buf);

              ssh_pk_group_free(pk_group);
              pk_group = NULL;
            }

          for (exp = export_types; exp->name; exp++)
            {
              fprintf(stderr, "#%d: Exporting `%s' with `%s'..\n",
                      n + 1, key->name, exp->name);

              status =
                ssh_pk_export(&buf, &buflen,
                              SSH_PKF_PRIVATE_KEY, private_key,
                              SSH_PKF_CIPHER_NAME, exp->name,
                              SSH_PKF_CIPHER_KEY, exp->key, exp->keylen,
                              SSH_PKF_END);

              if (status != SSH_CRYPTO_OK)
                {
                  fprintf(stderr, "Could not export `%s' with `%s': %s\n",
                          key->name, exp->name,
                          ssh_crypto_status_message(status));

                  ssh_private_key_free(private_key);
                  return FALSE;
                }

              /* We have the exported key. Print out test vector data */
              fprintf(fp, "verify-private-import %s %d ",
                      key->name, key->size);

              if (exp->keylen)
                for (i = 0; i < exp->keylen; i++)
                  fprintf(fp, "%02x", exp->key[i]);
              else
                fprintf(fp,"\"\"");

              fprintf(fp, " ");

              for (i = 0; i < buflen; i++)
                fprintf(fp, "%02x", buf[i]);

              fprintf(fp, "\n");

              /* Now, corrupt the exported key on purpose until it
                 fails to import, then use that for
                 verify-private-import-failure */

              for (i = 0; i < 50; i++)
                {
                  SshUInt32 off;
                  unsigned char byte;
                  SshPrivateKey prv_tmp;

                  off = ssh_random_get_byte() << 24 |
                    ssh_random_get_byte() << 16 |
                    ssh_random_get_byte() << 8 |
                    ssh_random_get_byte();

                  byte = ssh_random_get_byte();

                  /* Corrupt */
                  buf[off % buflen] = byte;

                  status =
                    ssh_pk_import(buf, buflen, NULL,
                                  SSH_PKF_PRIVATE_KEY, &prv_tmp,
                                  SSH_PKF_CIPHER_KEY, exp->key, exp->keylen,
                                  SSH_PKF_END);

                  if (status == SSH_CRYPTO_OK)
                    {
                      ssh_private_key_free(prv_tmp);
                      prv_tmp = NULL;
                      continue;
                    }

                  fprintf(fp, "verify-private-import-failure ");

                  if (exp->keylen)
                    for (i = 0; i < exp->keylen; i++)
                      fprintf(fp, "%02x", exp->key[i]);
                  else
                    fprintf(fp,"\"\"");

                  fprintf(fp, " ");

                  for (i = 0; i < buflen; i++)
                    fprintf(fp, "%02x", buf[i]);

                  fprintf(fp, "\n");
                  break;
                }

              ssh_free(buf);
            }

          ssh_private_key_free(private_key);
          private_key = NULL;
        }
    }

  fclose(fp);

  return TRUE;
}

Boolean
pkcs_import_export_tests(const char *filename)
{
  FILE *fp;
  char *token;
  int lineno;
  Boolean ret;
  SshCryptoStatus status;
  SshPrivateKey private_key;
  SshPublicKey public_key;
  SshPkGroup pk_group;

  /* AES and 3DES cipher functionality are both required for this test */










  if (!(fp = fopen(filename, "r")))
    {
      SSH_DEBUG(0, ("Could not open '%s' for reading.", filename));
      return FALSE;
    }

  lineno = 1;
  ret = TRUE;
  token = NULL;

  private_key = NULL;
  public_key = NULL;
  pk_group = NULL;

  while (1)
    {
      ssh_free(token);
      token = NULL;

      if (!file_parser_get_string(fp, &lineno, &token, FALSE, NULL))
        break;

      if (strcmp(token, "clear") == 0)
        {
          if (public_key)
            {
              ssh_public_key_free(public_key);
              public_key = NULL;
            }

          if (pk_group)
            {
              ssh_pk_group_free(pk_group);
              pk_group = NULL;
            }

          continue;
        }

      if (strcmp(token,"paired-public-key") == 0)
        {
          unsigned char *data;
          size_t datalen;

          if (!file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse public key parameters.",
                         filename, lineno));

              goto failure;
            }

          /* If old public key, free */
          if (public_key)
            {
              ssh_public_key_free(public_key);
              public_key = NULL;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PUBLIC_KEY, &public_key,
                          SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not import public key: %s",
                         filename, lineno,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          ssh_free(data);
          continue;
        }

      if (strcmp(token,"verify-public-import-failure") == 0)
        {
          unsigned char *key, *data;
          size_t keylen, datalen;
          SshPublicKey pub_tmp;

          if (!file_parser_get_data(fp, &lineno, &key, &keylen) ||
              !file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse public key parameters.",
                         filename, lineno));

              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PUBLIC_KEY, &pub_tmp,
                          SSH_PKF_END);

          if (status == SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Succeeded importing "
                         "public key which should have failed.",
                         filename, lineno));

              goto failure;
            }

          ssh_free(key);
          ssh_free(data);
          continue;
        }

      if (strcmp(token,"verify-group-import-failure") == 0)
        {
          unsigned char *key, *data;
          size_t keylen, datalen;
          SshPkGroup grp_tmp;

          if (!file_parser_get_data(fp, &lineno, &key, &keylen) ||
              !file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse group parameters.",
                         filename, lineno));

              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PK_GROUP, &grp_tmp,
                          SSH_PKF_END);

          if (status == SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Succeeded importing "
                         "group which should have failed.",
                         filename, lineno));

              goto failure;
            }

          ssh_free(key);
          ssh_free(data);
          continue;
        }

      if (strcmp(token,"verify-randomizers-import-failure") == 0)
        {
          unsigned char *key, *data;
          size_t keylen, datalen;

          if (!file_parser_get_data(fp, &lineno, &key, &keylen) ||
              !file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse group parameters.",
                         filename, lineno));

              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PK_GROUP_RANDOMIZERS, NULL,
                          SSH_PKF_END);

          if (status == SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Succeeded importing "
                         "group which should have failed.",
                         filename, lineno));

              goto failure;
            }

          ssh_free(key);
          ssh_free(data);
          continue;
        }

      if (strcmp(token, "paired-pk-group") == 0)
        {
          unsigned char *data;
          size_t datalen;

          if (!file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse group parameters.",
                         filename, lineno));

              goto failure;
            }

          /* If old public key, free */
          if (pk_group)
            {
              ssh_pk_group_free(pk_group);
              pk_group = NULL;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PK_GROUP, &pk_group,
                          SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not import group: %s",
                         filename, lineno,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          ssh_free(data);
          continue;
        }

      if (strcmp(token, "paired-group-randomizers") == 0)
        {
          unsigned char *data;
          size_t datalen;

          if (!file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse randomizer parameters.",
                         filename, lineno));

              goto failure;
            }

          if (!pk_group)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Group not defined.", filename, lineno));
              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PK_GROUP_RANDOMIZERS, pk_group,
                          SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not import randomizers: %s",
                         filename, lineno,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          ssh_free(data);
          continue;
        }

      if (strcmp(token, "verify-private-import-failure") == 0)
        {
          unsigned char *key, *data;
          size_t keylen, datalen;

          if (!file_parser_get_data(fp, &lineno, &key, &keylen) ||
              !file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse "
                         "'verify-private-import-failure' parameters.",
                         filename, lineno));
              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PRIVATE_KEY, &private_key,
                          SSH_PKF_CIPHER_KEY, key, keylen,
                          SSH_PKF_END);

          if (status == SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Succeeded in private key import when it "
                         "should have failed!",
                         filename, lineno));

              goto failure;
            }

          ssh_free(key);
          ssh_free(data);

          continue;
        }

      if (strcmp(token, "verify-private-import") == 0)
        {
          char *name;
          unsigned char *key, *data;
          int  size;
          size_t keylen, datalen;
          char *nam;
          unsigned int siz;

          if (!file_parser_get_string(fp, &lineno, &name, FALSE, NULL) ||
              !file_parser_get_int(fp, &lineno, &size) ||
              !file_parser_get_data(fp, &lineno, &key, &keylen) ||
              !file_parser_get_data(fp, &lineno, &data, &datalen))
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not parse 'verify-private-import' "
                         "parameters.",
                         filename, lineno));
              goto failure;
            }

          status =
            ssh_pk_import(data, datalen, NULL,
                          SSH_PKF_PRIVATE_KEY, &private_key,
                          SSH_PKF_CIPHER_KEY, key, keylen,
                          SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not import private key: %s",
                         filename, lineno,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          /* Now get some data out of the key, and compare those
             against size and type data */
          status = ssh_private_key_get_info(private_key,
                                            SSH_PKF_SIZE, &siz,
                                            SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("%s:%d: Could not get info from "
                            "private key: %s",
                            filename, lineno,
                            ssh_crypto_status_message(status)));
              goto failure;
            }

          if (siz != size)
            {
              SSH_DEBUG(0, ("%s:%d: Imported key size (%d bits) "
                            "differs from expected (%d bits).",
                            filename, lineno,
                            siz, size));
              goto failure;
            }

          nam = ssh_private_key_name(private_key);

          if (strncmp(nam, name, strlen(nam)) != 0)
            {
              SSH_DEBUG(0, ("%s:%d: Imported key has different name (%s) "
                            "than expected (%s).",
                            filename, lineno,
                            nam, name));
	      goto failure;
            }

          ssh_free(nam);

          /* If public key available, verify that it and the derived
             match */
          if (public_key)
            {
              SshPublicKey pub_tmp;

              status =
                ssh_private_key_derive_public_key(private_key, &pub_tmp);
              SSH_ASSERT(status == SSH_CRYPTO_OK);

              if (!cmp_public_keys(public_key, pub_tmp))
                {
                  SSH_DEBUG(0, ("%s:%d: Derived and paired public keys "
                                "do not match!", filename, lineno));
                  goto failure;
                }

              /* Yeah, we could do pairwise test here, however we'll
                 skip that for now, because it would be just code
                 duplication: better to extract the pkcs-test pairwise
                 test and use just one implementation of that.. */

              ssh_public_key_free(pub_tmp);
            }

          ssh_private_key_free(private_key);

          ssh_free(name);
          ssh_free(key);
          ssh_free(data);

          continue;
        }

      SSH_DEBUG(0, ("%s:%d: Invalid token '%s' detected.",
                    filename, lineno, token));

    failure:
      ssh_free(token);
      token = NULL;
      ret = FALSE;
      break;
    }

  if (public_key)
    {
      ssh_public_key_free(public_key);
      public_key = NULL;
    }

  if (pk_group)
    {
      ssh_pk_group_free(pk_group);
      pk_group = NULL;
    }


  ssh_free(token);
  fclose(fp);

  return ret;
}
