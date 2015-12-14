/*

ssh-encrypt.c

Author: Timo J. Rinne <tri@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
All rights reserved.

Created:  Mon Nov 23 14:20:12 1998 tri

Encrypt/decrypt data with ciphers in lib/sshcrypto library.

*/

#include "sshincludes.h"

#ifdef SSHDIST_APPS_CRYPTUTILS

#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshgetopt.h"
#include "namelist.h"
#include "sshtimemeasure.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "SshEncrypt"

char *av0; /* Basename of argv[0] */

/* Length of the contiguous memory block given to cipher speed test */
#define CIPHER_TEST_DATA_LEN 0x10000

/* Minimum time of valid speed test (in seconds) */
#define CIPHER_TEST_MIN_TIME 2.0

/* Buffer length in file write operations.  This has to be at least
   two cipher block lengths.  Hope there is no ciphers with more than
   2kB block. */
#define CIPHER_BUFFER_LEN    0x1000

/* Convert single hex character to integer (0-15).  Return negative
   integer if the input character is not a hex digit. */
static int hex_char_to_int(int ch);

/* Convert readable hex string to unsigned char buffer.  If input
   string is of odd length or doesn't consist entirely of hex
   digits, return FALSE, otherwise set the buffer and buffer_len
   to argument pointers (if non NULL) and return TRUE. */
static Boolean hex_string_to_data(char *str,
                                  unsigned char **data,
                                  size_t *data_len);

static void usage(void);
static void help_info(void);

/* Test the speed of the cipher. */
void cipher_speed_test(char *cipher_name,
                       char *passphrase,
                       unsigned char *key, size_t key_len,
                       unsigned char *iv, size_t iv_len,
                       Boolean encrypt_mode);

/* Encrypt data stream with given context */
Boolean cipher_encrypt(SshCipher cipher, FILE *fin, FILE *fout);

/* Decrypt data stream with given context */
Boolean cipher_decrypt(SshCipher cipher, FILE *fin, FILE *fout);

int main(int argc, char **argv)
{
  int c;
  SshCryptoStatus cs;
  SshCipher cipher;
  Boolean all_ciphers = FALSE, speed_test = FALSE, quiet = FALSE;
  unsigned char *iv = NULL, *key = NULL;
  size_t iv_len = 0, key_len = 0;
  char *cipher_name = NULL, *cipher_names, *hlp, *passphrase = NULL;
  Boolean encrypt_mode = TRUE;
  char *input_file = NULL, *output_file = NULL;
  FILE *fin, *fout;
  Boolean r = TRUE;

  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  if (strcasecmp(av0, "ssh-encrypt") == 0)
    encrypt_mode = TRUE;
  else if (strcasecmp(av0, "ssh-decrypt") == 0)
    encrypt_mode = FALSE;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
      fprintf(stderr, "Can't initialize the cryptographic provider.\n");
      exit(1);
    }
  while ((c = ssh_getopt(argc, argv, "thd:ac:i:k:EDp:", NULL)) != -1)
    {
      switch (c)
        {
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 't':
          speed_test = TRUE;
          break;
        case 'a':
          all_ciphers = TRUE;
          break;
        case 'c':
          cipher_name = ssh_xstrdup(ssh_optarg);
          break;
        case 'q':
          quiet = TRUE;
          break;
        case 'i':
          if (iv)
            {
              fprintf(stderr,
                      "%s: No multiple initialization vectors allowed.\n",
                      av0);
              usage();
              exit(-1);
            }
          if (! hex_string_to_data(ssh_optarg, &iv, &iv_len))
            {
              fprintf(stderr, "%s: Bad IV string.\n", av0); 
              exit(-1);
            }
          break;
        case 'k':
          if (key)
            {
              fprintf(stderr, "%s: No multiple keys allowed.\n", av0);
              usage();
              exit(-1);
            }
          if (! hex_string_to_data(ssh_optarg, &key, &key_len))
            {
              fprintf(stderr, "%s: Bad KEY string.\n", av0); 
              exit(-1);
            }
          break;
        case 'p':
          if (passphrase)
            {
              fprintf(stderr, "%s: No multiple passphrases allowed.\n", av0);
              usage();
              exit(-1);
            }
          passphrase = ssh_optarg;
          break;
        case 'E':
          encrypt_mode = TRUE;
          break;
        case 'D':
          encrypt_mode = FALSE;
          break;
        case 'h':
          help_info();
          usage();
          exit(0);
          /*NOTREACHED*/
        default:
          usage();
          exit(-1);
          /*NOTREACHED*/
        }
    }
  argc -= ssh_optind;
  argv += ssh_optind;
  if (speed_test && (argc > 0))
    {
      fprintf(stderr, "%s: Extra parameters.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if (argc > 2)
    {
      fprintf(stderr, "%s: Extra parameters.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if (argc > 1)
    output_file = ssh_xstrdup(argv[1]);
  if (argc > 0)
    input_file = ssh_xstrdup(argv[0]);
  if ((cipher_name != NULL) && all_ciphers)
    {
      fprintf(stderr, "%s: -c and -a can't be used together.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if (all_ciphers && !speed_test)
    {
      fprintf(stderr, "%s: -a can only be used with -t.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if ((cipher_name != NULL) && strchr(cipher_name, ',') && !speed_test)
    {
      fprintf(stderr, "%s: Multiple ciphers only be used with -t.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if (cipher_name == NULL)
    {
      if (speed_test)
        {
          all_ciphers = TRUE; /* Assume `all' if test mode with no ciphers. */
        }
      else
        {
          fprintf(stderr, "Missing -c flag.\n");
          usage();
          exit(-1);
          /*NOTREACHED*/
        }
    }
  if (passphrase && key)
    {
      fprintf(stderr, "%s: Can't use both passphrase and hex key.\n", av0);
      usage();
      exit(-1);
      /*NOTREACHED*/
    }
  if (!key && !passphrase && !speed_test)
    {
      ssh_warning("%s: No key!  Empty passphrase assumed.", av0);
      passphrase = "";
      /*NOTREACHED*/
    }
  if (speed_test)
    {
      fprintf(stderr, "Performing speed tests\n");
      if (all_ciphers)
        {
          cipher_names = ssh_cipher_get_supported();
        }
      else
        {
          /* Steal allocated cipher_name */
          cipher_names = cipher_name;
          cipher_name = NULL;
        }
      hlp = cipher_names;
      while ((cipher_name = ssh_name_list_get_name(hlp)) != NULL)
        {
          hlp += strlen(cipher_name);
          if (*hlp == ',')
            hlp++;
          cipher_speed_test(cipher_name,
                            passphrase,
                            key, key_len,
                            iv, iv_len,
                            encrypt_mode);
          ssh_xfree(cipher_name);

          if (strlen(hlp) == 0)
            break;
        }
      ssh_xfree(cipher_names);
    }
  else
    {
      if (passphrase)
        cs = ssh_cipher_allocate_with_passphrase(cipher_name,
                                                 passphrase,
                                                 encrypt_mode,
                                                 &cipher);
      else
        cs = ssh_cipher_allocate(cipher_name,
                                 key,
                                 key_len,
                                 encrypt_mode,
                                 &cipher);
      if (cs != SSH_CRYPTO_OK)
        {
          switch (cs)
            {
            case SSH_CRYPTO_UNSUPPORTED:
              fprintf(stderr, "%s: Unsupported cipher \"%s\".\n", av0, 
                      cipher_name);
              usage();
              exit(-1);
            case SSH_CRYPTO_KEY_TOO_SHORT:
              fprintf(stderr, "%s: Key too short for \"%s\".\n", av0, 
                      cipher_name);
              usage();
              exit(-1);
            default:
              fprintf(stderr, "%s: Cipher allocate failed.\n", av0);
              exit(-1);
            }
          /*NOTREACHED*/
        }
      if (iv != NULL)
        {
          if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) == iv_len)
            ssh_cipher_set_iv(cipher, iv);
          else
            {
              fprintf(stderr, "%s: Weird IV length.\n", av0);
              exit(-1);
            }
        }
      if (input_file != NULL)
        {
          fin = fopen(input_file, "r");
          if (fin == NULL)
            {
              fprintf(stderr, "%s: Cannot open input file \"%s\".\n", 
                      av0, input_file);
              exit(-1);
            }
        }
      else
        {
          fin = stdin;
        }
      if (output_file != NULL)
        {
          struct stat st;
          if (stat(output_file, &st) >= 0)
            {
              fprintf(stderr, "%s: Output file \"%s\" exists.\n", av0, 
                      output_file);
              exit(-1);
            }
          fout = fopen(output_file, "w");
          if (fout == NULL)
            {    
              fprintf(stderr, "%s: Cannot open output file \"%s\".\n", 
                      av0, output_file);
              exit(-1);
            }
        }
      else
        {
          fout = stdout;
        }
      if (encrypt_mode)
        r = cipher_encrypt(cipher, fin, fout);
      else
        r = cipher_decrypt(cipher, fin, fout);
      if (input_file)
        fclose(fin);
      if (output_file)
        {
          fclose(fout);
          if (! r)
            (void)unlink(output_file);
        }
      ssh_cipher_free(cipher);
      ssh_xfree(cipher_name);
    }

  ssh_xfree(input_file);
  ssh_xfree(output_file);
  ssh_xfree(key);
  ssh_xfree(iv);

  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return((r == TRUE) ? 0 : -1);
}

void cipher_speed_test(char *cipher_name,
                       char *passphrase,
                       unsigned char *key, size_t key_len,
                       unsigned char *iv, size_t iv_len,
                       Boolean encrypt_mode)
{
  SshCryptoStatus cs;
  SshCipher cipher;
  SshTimeMeasure timer;
  unsigned char *data;
  unsigned char *data_dest;
  size_t block_len, data_len, tot, n;
  int i, len_mul;
  double sec;

  if (!passphrase && !key)
    {
      passphrase = "This is a test key!";
    }
  if (passphrase)
    {
      SSH_DEBUG(5, ("Allocating %s context with passphrase.", cipher_name));
      cs = ssh_cipher_allocate_with_passphrase(cipher_name,
                                               passphrase,
                                               encrypt_mode,
                                               &cipher);
    }
  else
    {
      SSH_DEBUG(5, ("Allocating %s context with key vector.", cipher_name));
      cs = ssh_cipher_allocate(cipher_name,
                               key,
                               key_len,
                               encrypt_mode,
                               &cipher);
    }
  if (cs != SSH_CRYPTO_OK)
    {
      switch (cs)
        {
        case SSH_CRYPTO_UNSUPPORTED:
          fprintf(stderr, "%s: Unsupported cipher \"%s\".\n", 
                  av0, cipher_name);
          exit(-1);
        case SSH_CRYPTO_KEY_TOO_SHORT:
          fprintf(stderr, "%s: Key too short for \"%s\".\n", av0, cipher_name);
          exit(-1);
        default:
          fprintf(stderr, "%s: Cipher allocate failed.\n", av0);
          exit(-1);
        }
      /*NOTREACHED*/
    }
  if (iv != NULL)
    {
      if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) == iv_len)
        ssh_cipher_set_iv(cipher, iv);
      else
        {
          fprintf(stderr, "%s: Weird IV length.\n", av0);
          exit(1);
        }
    }
  block_len = ssh_cipher_get_block_length(ssh_cipher_name(cipher));
  data_len = CIPHER_TEST_DATA_LEN;
  while (data_len % block_len != 0)
    {
      SSH_DEBUG(5, ("Growing test data len to match with cipher block size."));
      data_len++;
    }
  data = ssh_xmalloc(data_len);
  data_dest = ssh_xmalloc(data_len);
  for (i = 0; i < data_len; i++)
    data[i] = (unsigned char)(i % 0x100);
  tot = data_len * 2;
  timer = ssh_time_measure_allocate();
 timer_retry:
  n = tot;
  ssh_time_measure_reset(timer);
  ssh_time_measure_start(timer);
  while (n > 0)
    {
      if (n > CIPHER_TEST_DATA_LEN)
        {
          cs = ssh_cipher_transform(cipher,
                                    data_dest,
                                    data,
                                    CIPHER_TEST_DATA_LEN);
          n -= CIPHER_TEST_DATA_LEN;
        }
      else
        {
          cs = ssh_cipher_transform(cipher,
                                    data_dest,
                                    data,
                                    n);
          n = 0;
        }
      if (cs != SSH_CRYPTO_OK)
          ssh_fatal("%s: ssh_cipher_transform failed (%d).", av0, (int)cs);

    }
  ssh_time_measure_stop(timer);
  sec = (double)ssh_time_measure_get(timer, SSH_TIME_GRANULARITY_SECOND);

  if (sec < CIPHER_TEST_MIN_TIME)
    {
      if (sec < 0.1)
        {
          /* This doesn't directly aim to sufficient length.
             Let's retry with 10 times longer data to get
             hash code into the cache for the `real test'. */
          len_mul = 10;
        }
      else
        {
          /* Let's try to heuristically adjust the next test
             loop so that it takes about CIPHER_TEST_MIN_TIME
             seconds to complete. */
          len_mul = (int)((CIPHER_TEST_MIN_TIME + 1.0) / sec) + 1;
        }
      SSH_DEBUG(5, ("Test completes too fast (%.2f sec).", sec));
      SSH_DEBUG(5, ("Multiply test len by %d.", len_mul));
      tot *= len_mul;
      goto timer_retry;
    }
  else
    {
      SSH_DEBUG(5, ("Test completes OK (%.2f sec).", sec));
    }
  printf("Speed[\"%s\"] = %.2f kB (%.2f megabits) / sec\n",
         cipher_name,
         ((((double)tot) / 1024.0) / sec),
         ((((double)tot) / 131072.0) / sec));
  ssh_time_measure_free(timer);
  ssh_cipher_free(cipher);
  ssh_xfree(data);
  ssh_xfree(data_dest);
  return;
}

Boolean cipher_encrypt(SshCipher cipher, FILE *fin, FILE *fout)
{
  const char *cipher_name = NULL;
  size_t block_len, buf_used, buf_len, tr_len;
  unsigned char *buf = NULL;
  size_t len;
  SshCryptoStatus cs;

  cipher_name = ssh_cipher_name(cipher);
  block_len = ssh_cipher_get_block_length(cipher_name);
  buf_len = CIPHER_BUFFER_LEN;
  while (buf_len % block_len != 0)
    {
      SSH_DEBUG(5, ("Growing test data len to match with cipher block size."));
      buf_len++;
    }
  buf = ssh_xmalloc(buf_len);
  buf_used = 0;
  while (1)
    {
      len = fread(buf + buf_used, 1, buf_len - buf_used, fin);
      buf_used += len;
      if (buf_used >= block_len)
        {
          tr_len = buf_used - (buf_used % block_len);
          cs = ssh_cipher_transform(cipher, buf, buf, tr_len);
          if (cs != SSH_CRYPTO_OK)
            {
              ssh_warning("%s: ssh_cipher_transform failed (%d).",
                          av0, (int)cs);
              goto encrypt_failed;
            }
          if (fwrite(buf, 1, tr_len, fout) != tr_len)
            {
              ssh_warning("%s: File write failed.", av0);
              goto encrypt_failed;
            }
          buf_used -= tr_len;
          if (buf_used > 0)
            memcpy(buf, buf + tr_len, buf_used);
        }
      if (feof(fin))
        {
          SSH_ASSERT(block_len > buf_used);
          if (block_len > 1)
            {
              memset(buf + buf_used, buf_used, block_len - buf_used);
              cs = ssh_cipher_transform(cipher,
                                        buf,
                                        buf,
                                        block_len);
              if (cs != SSH_CRYPTO_OK)
                {
                  ssh_warning("%s: ssh_cipher_transform failed (%d).",
                              av0, (int)cs);
                  goto encrypt_failed;
                }
              if (fwrite(buf, 1, block_len, fout) != block_len)
                {
                  ssh_warning("%s: File write failed.", av0);
                  goto encrypt_failed;
                }
            }
          break;
        }
    }
  ssh_xfree(buf);
  return TRUE;

 encrypt_failed:
  ssh_xfree(buf);
  return FALSE;
}

Boolean cipher_decrypt(SshCipher cipher, FILE *fin, FILE *fout)
{
  const char *cipher_name = NULL;
  size_t block_len, buf_used, buf_len;
  unsigned char *buf = NULL;
  size_t len, tr_len;
  SshCryptoStatus cs;
  int i;

  cipher_name = ssh_cipher_name(cipher);
  block_len = ssh_cipher_get_block_length(cipher_name);
  buf_len = CIPHER_BUFFER_LEN;
  while (buf_len % block_len != 0)
    {
      SSH_DEBUG(5, ("Growing test data len to match with cipher block size."));
      buf_len++;
    }
  buf = ssh_xmalloc(buf_len);
  buf_used = 0;
  while (1)
    {
      len = fread(buf + buf_used, 1, buf_len - buf_used, fin);
      buf_used += len;
      if (buf_used >= (2 * block_len))
        {
          if (block_len == 1)
            tr_len = buf_used;
          else
            tr_len = buf_used - (buf_used % block_len) - block_len;
          cs = ssh_cipher_transform(cipher, buf, buf, tr_len);
          if (cs != SSH_CRYPTO_OK)
            {
              ssh_warning("%s: ssh_cipher_transform failed (%d).",
                          av0, (int)cs);
              goto decrypt_failed;
            }
          if (fwrite(buf, 1, tr_len, fout) != tr_len)
            {
              ssh_warning("%s: File write failed.", av0);
              goto decrypt_failed;
            }
          buf_used -= tr_len;
          if (buf_used > 0)
            memcpy(buf, buf + tr_len, buf_used);
        }
      if (feof(fin))
        {
          if (block_len < buf_used)
            {
              ssh_warning("%s: Invalid input file size.", av0);
              goto decrypt_failed;
            }
          if (block_len == 1)
            break;
          if (buf_used < block_len)
            {
              ssh_warning("%s: Truncated input file.", av0);
              goto decrypt_failed;
            }
          cs = ssh_cipher_transform(cipher,
                                    buf,
                                    buf,
                                    block_len);
          if (cs != SSH_CRYPTO_OK)
            {
              ssh_warning("%s: ssh_cipher_transform failed (%d).",
                          av0, (int)cs);
              goto decrypt_failed;
            }
          if (buf[block_len - 1] >= block_len)
            {
              ssh_warning("%s: Malformed input padding.", av0);
              goto decrypt_failed;
            }
          for (i = buf[block_len - 1]; i < block_len - 1; i++)
            {
              if (buf[i] != buf[block_len - 1])
                {
                  ssh_warning("%s: Malformed input padding.", av0);
                  goto decrypt_failed;
                }
            }
          if (buf[block_len - 1] > 0)
            {
              if (fwrite(buf, 1, buf[block_len - 1], fout) !=
                  buf[block_len - 1])
                {
                  ssh_warning("%s: File write failed.", av0);
                  goto decrypt_failed;
                }
            }
          break;
        }
    }

  ssh_xfree(buf);
  return TRUE;

 decrypt_failed:
  ssh_xfree(buf);
  return FALSE;
}

static void help_info(void)
{
  fprintf(stderr, "\n");
  fprintf(stderr,
          "***************************************************************\n");
  fprintf(stderr, "\n");
  fprintf(stderr,
          "The ssh-encrypt program can be used to encrypt/decrypt a file \n"
          "or stream, or alternatively to compare the encryption speeds of \n"
          "different ciphers.\n\n");
  fprintf(stderr,
          "For data encryption, call the program with the flag -E, and for \n"
          "data decryption use the -D flag. The cipher to be used is \n"
          "selected with the -c flag. The input and output files follow \n"
          "the command line options.\n\n");
  fprintf(stderr,
          "For comparision of encryption speeds of different ciphers, use \n"
          "the -t flag. The ciphers to be tested should be a comma separated\n"
          "string of cipher names passed to the -c flag. All ciphers can be \n"
          "tested using -a option. With the -t option it is not necessary \n"
          "to specify an input or output file.\n\n");
  fprintf(stderr,
          "The encryption key is passed as a hexadecimal string to the -k \n"
          "command line option, or alternatively a passphrase (any string) \n"
          "can be passed to the -p option. An optional IV can be passed as a\n"
          "hexadecimal string using the -i option.\n\n");
  fprintf(stderr,
          "***************************************************************\n");
  fprintf(stderr, "\n");
}


static void usage(void)
{
  char *cipher_list;
  fprintf(stderr,
          "Usage:\n");
  fprintf(stderr,
          "ssh-encrypt (-E | -D) -c cipher [-k key | -p passphrase] [-i iv] "
          "input_file output_file\n\n");
  fprintf(stderr,
          "ssh-encrypt -t (-c cipher | -a) [-k key | -p passphrase] [-i iv]"
          "\n");
  cipher_list = ssh_cipher_get_supported();
  fprintf(stderr, "\nThe supported ciphers: %s.\n", cipher_list);
  ssh_xfree(cipher_list);
}

static int hex_char_to_int(int ch)
{
  switch (ch)
    {
    case '0':    return 0;    /*NOTREACHED*/
    case '1':    return 1;    /*NOTREACHED*/
    case '2':    return 2;    /*NOTREACHED*/
    case '3':    return 3;    /*NOTREACHED*/
    case '4':    return 4;    /*NOTREACHED*/
    case '5':    return 5;    /*NOTREACHED*/
    case '6':    return 6;    /*NOTREACHED*/
    case '7':    return 7;    /*NOTREACHED*/
    case '8':    return 8;    /*NOTREACHED*/
    case '9':    return 9;    /*NOTREACHED*/
    case 'A':    return 10;   /*NOTREACHED*/
    case 'a':    return 10;   /*NOTREACHED*/
    case 'B':    return 11;   /*NOTREACHED*/
    case 'b':    return 11;   /*NOTREACHED*/
    case 'C':    return 12;   /*NOTREACHED*/
    case 'c':    return 12;   /*NOTREACHED*/
    case 'D':    return 13;   /*NOTREACHED*/
    case 'd':    return 13;   /*NOTREACHED*/
    case 'E':    return 14;   /*NOTREACHED*/
    case 'e':    return 14;   /*NOTREACHED*/
    case 'F':    return 15;   /*NOTREACHED*/
    case 'f':    return 15;   /*NOTREACHED*/
    default:     return -1;   /*NOTREACHED*/
    }
  /*NOTREACHED*/;
}

static Boolean hex_string_to_data(char *str,
                                  unsigned char **data,
                                  size_t *data_len)
{
  size_t str_len, buf_len;
  unsigned char *buf;
  int i, ch, cl;

  str_len = strlen(str);
  if ((str_len == 0) || ((str_len % 2) != 0))
    return FALSE;
  buf_len = str_len / 2;
  buf = ssh_xmalloc(buf_len);
  for (i = 0; i < buf_len; i++)
    {
      ch = hex_char_to_int(str[i * 2]);
      cl = hex_char_to_int(str[(i * 2) + 1]);
      if ((ch >= 0) && (cl >= 0))
        {
          buf[i] = (unsigned char)(ch * 16 + cl);
        }
      else
        {
          ssh_xfree(buf);
          return FALSE;
        }
    }
  if (data)
    *data = buf;
  else
    ssh_xfree(buf);
  if (data_len)
    *data_len = buf_len;
  return TRUE;
}
#else /* SSHDIST_APPS_CRYPTUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_CRYPTUTILS */
