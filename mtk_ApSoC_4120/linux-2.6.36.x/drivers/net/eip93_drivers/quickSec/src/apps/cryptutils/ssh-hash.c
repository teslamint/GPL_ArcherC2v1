/*

  ssh-hash.c

  Author: Timo J. Rinne <tri@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Wed Oct  7 13:18:44 1998 tri

  Calculate hash values from files or strings using genhash.

*/

#include "sshincludes.h"

#ifdef SSHDIST_APPS_CRYPTUTILS

#include "sshcrypt.h"
#include "sshgetopt.h"
#include "namelist.h"
#include "sshtimemeasure.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "SshHash"

char *av0; /* Basename of argv[0] */

static void help_info(void);
static void usage(void);
static void print_digest(unsigned char *digest, size_t digest_len);

/* Length of the contiguous memory block given to hash speed test */
#define HASH_TEST_DATA_LEN 0x20000

/* Minimum time of valid speed test (in seconds) */
#define HASH_TEST_MIN_TIME 1.0

typedef enum {
  HASH_MODE_STDIN,
  HASH_MODE_STRING,
  HASH_MODE_FILE,
  HASH_MODE_SPEEDTEST
} HashMode;

typedef struct {
  SshHash hash;
  char *name;
  size_t digest_len;
  unsigned char *digest;
} HashEntry;

int main(int argc, char **argv)
{
  char *hash_name;
  int i, j, c, hash_count, hash_space;
  size_t read_cnt;
  unsigned char read_buf[1024];
  FILE *f;
  char *hash_names = NULL, *hash_names_start = NULL;
  SshCryptoStatus cs;
  HashMode hash_mode = HASH_MODE_STDIN;
  Boolean flag_a = FALSE, flag_q = FALSE;
  HashEntry *hash_entry;

  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
      fprintf(stderr, "Can't initialize cryptographic provider.\n");
      exit(2);
    }

  while ((c = ssh_getopt(argc, argv, "fshaqtd:", NULL)) != -1)
    {
      switch (c)
        {
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 'f':
          hash_mode = HASH_MODE_FILE;
          break;
        case 's':
          hash_mode = HASH_MODE_STRING;
          break;
        case 't':
          hash_mode = HASH_MODE_SPEEDTEST;
          break;
        case 'a':
          flag_a = TRUE;
          break;
        case 'q':
          flag_q = TRUE;
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

  argv += ssh_optind;
  argc -= ssh_optind;

  if (flag_a)
    {
      hash_names_start = hash_names = ssh_hash_get_supported();
    }
  else
    {
      if (argc > 0)
        {
          hash_names_start = hash_names = ssh_xstrdup(argv[0]);
          argv++;
          argc--;
        }
      else
        {
          usage();
          exit(-1);
        }
    }

  if ((hash_mode == HASH_MODE_STDIN) || (hash_mode == HASH_MODE_SPEEDTEST))
    {
      if (argc > 0)
        {
          usage();
          exit(1);
        }
    }
  else
    {
      if (argc < 1)
        {
          usage();
          exit(1);
        }
    }

  hash_count = 0;
  hash_space = 10;
  hash_entry = ssh_xmalloc(hash_space * sizeof (*hash_entry));

  while ((hash_name = ssh_name_list_get_name(hash_names)) != NULL)
    {
      hash_count++;
      SSH_ASSERT(hash_count <= hash_space);
      if (hash_count == hash_space)
        {
          hash_space += 10;
          hash_entry = ssh_xrealloc(hash_entry,
                                    hash_space * sizeof (*hash_entry));
        }

      hash_names += strlen(hash_name);
      if (*hash_names == ',')
        hash_names++;

      cs = ssh_hash_allocate(hash_name, &hash_entry[hash_count - 1].hash);
      if (cs != SSH_CRYPTO_OK)
        {
          if (cs == SSH_CRYPTO_UNSUPPORTED)
            {
              fprintf(stderr, "ssh-hash: Hash algorithm \"%s\" unsupported.\n",
                      hash_name);
              fprintf(stderr, "Supported algorithms are: %s\n",
                      ssh_hash_get_supported());
              exit(1);
            }
          else
            {
              ssh_fatal("Failed to allocate hash context (%d)", cs);
            }
        }
      hash_entry[hash_count - 1].name = hash_name;
      hash_entry[hash_count - 1].digest_len =
        ssh_hash_digest_length(ssh_hash_name(hash_entry[hash_count - 1].hash));
      hash_entry[hash_count - 1].digest =
        ssh_xmalloc(hash_entry[hash_count - 1].digest_len);
      if (strlen(hash_names) == 0)
        break;
    }

  if (hash_mode == HASH_MODE_SPEEDTEST)
    {
      unsigned char *data;
      size_t tot, n;
      SshTimeMeasure timer;
      double sec;
      int len_mul;

      fprintf(stderr, "Performing speed tests\n");

      data = ssh_xmalloc(HASH_TEST_DATA_LEN);
      timer = ssh_time_measure_allocate();
      for (i = 0; i < HASH_TEST_DATA_LEN; i++)
        data[i] = i % 0x100;
      for (j = 0; j < hash_count; j++)
        {
          SSH_DEBUG(5, ("Testing %s", hash_entry[j].name));
          tot = HASH_TEST_DATA_LEN * 2;
        timer_retry:
          n = tot;
          SSH_DEBUG(5, ("Test data length is %lu bytes.", (unsigned long)n));
          ssh_time_measure_reset(timer);
          ssh_time_measure_start(timer);
          while (n > 0)
            {
              if (n > HASH_TEST_DATA_LEN)
                {
                  ssh_hash_update(hash_entry[j].hash,
                                  data, HASH_TEST_DATA_LEN);
                  n -= HASH_TEST_DATA_LEN;
                }
              else
                {
                  ssh_hash_update(hash_entry[j].hash, data, n);
                  n = 0;
                }
            }
          ssh_time_measure_stop(timer);
          ssh_hash_final(hash_entry[j].hash, hash_entry[j].digest);
          sec = (double)ssh_time_measure_get(timer,
                                             SSH_TIME_GRANULARITY_SECOND);
          ssh_hash_reset(hash_entry[j].hash);
          if (sec < HASH_TEST_MIN_TIME)
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
                     loop so that it takes about HASH_TEST_MIN_TIME
                     seconds to complete. */
                  len_mul = (int)((HASH_TEST_MIN_TIME + 1.0) / sec) + 1;
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
                 hash_entry[j].name,
                 ((((double)tot) / 1024.0) / sec),
                 ((((double)tot) / 131072.0) / sec));
        }
      ssh_time_measure_free(timer);
      ssh_xfree(data);
    }
  else if (hash_mode == HASH_MODE_STDIN)
    {
      while ((read_cnt = fread(read_buf, 1, sizeof (read_buf), stdin)) > 0)
        {
          for (j = 0; j < hash_count; j++)
            ssh_hash_update(hash_entry[j].hash, read_buf, read_cnt);
        }
      for (j = 0; j < hash_count; j++)
        {
          ssh_hash_final(hash_entry[j].hash, hash_entry[j].digest);
          if (! flag_q)
            printf("%s-hash-file(STDIN) = ", hash_entry[j].name);
          print_digest(hash_entry[j].digest, hash_entry[j].digest_len);
          printf("\n");
          ssh_hash_reset(hash_entry[j].hash);
        }
    }
  else
    {
      for (i = 0; i < argc; i++)
        {
          switch (hash_mode)
            {
            case HASH_MODE_FILE:
              {
                f = fopen(argv[i], "r");
                if (f == NULL)
                  {
                    fprintf(stderr, "ssh-hash: Cannot open \"%s\"\n", argv[i]);
                    continue;
                  }
                else
                  {
                    while ((read_cnt = fread(read_buf,
                                             1,
                                             sizeof (read_buf),
                                             f)) > 0)
                      {
                        for (j = 0; j < hash_count; j++)
                          ssh_hash_update(hash_entry[j].hash,
                                          read_buf,
                                          read_cnt);
                      }
                    fclose(f);
                  }
              }
              break;
            case HASH_MODE_STRING:
              for (j = 0; j < hash_count; j++)
                ssh_hash_update(hash_entry[j].hash,
                                (unsigned char *)argv[i], strlen(argv[i]));
              break;
            default:
              ssh_fatal("Internal error");
            }
          for (j = 0; j < hash_count; j++)
            {
              ssh_hash_final(hash_entry[j].hash, hash_entry[j].digest);
              if (! flag_q)
                {
                  switch (hash_mode)
                    {
                    case HASH_MODE_FILE:
                      printf("%s-hash-file(\"%s\") = ",
                             hash_entry[j].name, argv[i]);
                      break;
                    case HASH_MODE_STRING:
                      printf("%s-hash-string(\"%s\") = ",
                             hash_entry[j].name, argv[i]);
                      break;
                    default:
                      ssh_fatal("Internal error");
                    }
                }
              print_digest(hash_entry[j].digest, hash_entry[j].digest_len);
              printf("\n");
              ssh_hash_reset(hash_entry[j].hash);
            }
        }
    }
  for (j = 0; j < hash_count; j++)
    {
      ssh_hash_free(hash_entry[j].hash);
      ssh_xfree(hash_entry[j].name);
      ssh_xfree(hash_entry[j].digest);
    }
  ssh_xfree(hash_entry);
  ssh_xfree(hash_names_start);

  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;
}


static void help_info(void)
{
  fprintf(stderr, "\n");
  fprintf(stderr,
          "***************************************************************\n");
  fprintf(stderr, "\n");
  fprintf(stderr,
          "The ssh-hash program can be used to hash input files or strings,\n"
          "or alternatively to compare the hashing speeds of different hash\n"
          "algorithms.\n\n");
  fprintf(stderr,
          "To hash input strings, call the program with the -s flag, \n"
          "followed by a comma separated string of hash algorithms followed\n"
          "by the input strings to hash. The ouput hash values are printed \n"
          "to standard error. Input files can be hashed in a similar fashion\n"
          "with the -f flag. Standard input is hashed if -s and -f are \n"
          "both omitted. The -a flag can be used to apply all supported \n"
          "hash algorithms to the input data.\n\n");

  fprintf(stderr,
          "For comparision of the speeds of different hashes, use the -t \n"
          "flag. The hashes to be tested should be a comma separated\n"
          "string of hash names, or -a for all hashes. With the -t flag \n"
          "you should not specify an input file or string.\n\n");
  fprintf(stderr,
          "The -q flag runs the program in quiet mode.\n");
  fprintf(stderr,
          "***************************************************************\n");
  fprintf(stderr, "\n");
}

static void usage()
{
  fprintf(stderr,
          "Usage: %s [-q] -s (hash-algorithm | -a) str1 ... strN\n", av0);
  fprintf(stderr,
          "       %s [-q] -f (hash-algorithm | -a) fn1 ... fnN\n", av0);
  fprintf(stderr,
          "       %s [-q] (hash-algorithm | -a)\n", av0);
  fprintf(stderr,
          "       %s [-q] -t (hash-algorithm | -a)\n", av0);
  fprintf(stderr,
          "Supported hash algorithms are: %s\n",
          ssh_hash_get_supported());
}

static void print_digest(unsigned char *digest, size_t digest_len)
{
  int i;

  for (i = 0; i < (int)digest_len; i++)
    printf("%02x", digest[i]);
  return;
}

#else /* SSHDIST_APPS_CRYPTUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_CRYPTUTILS */
