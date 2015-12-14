/*

t-compress.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

*/

#include "sshincludes.h"
#include "sshrand.h"
#include "bufzip.h"

#define PASSES 1
#define MAX_SIZE 17000
#define STEP     31

void test_compress(SshBuffer b)
{
  unsigned int i, padlen;
  char *method;
  SshBuffer compressed, uncompressed;
  unsigned char ch;
  SshCompression z_compress, z_uncompress;

  compressed = ssh_buffer_allocate();
  uncompressed = ssh_buffer_allocate();

  method = ssh_compress_get_supported();
  method = strtok(method, ",");

  while (method)
    {
      ssh_buffer_clear(compressed);
      ssh_buffer_clear(uncompressed);

      padlen = ssh_rand() % 10;
      ch = (unsigned char)ssh_rand();
      for (i = 0; i < padlen; i++)
        {
          ssh_buffer_append(compressed, &ch, 1);
          ssh_buffer_append(uncompressed, &ch, 1);
        }

      z_compress = ssh_compress_allocate(method, -1, TRUE);
      z_uncompress = ssh_compress_allocate(method, -1, FALSE);

      if (strcmp(method, "none") == 0)
        {
          if (!ssh_compress_is_none(z_compress) ||
              !ssh_compress_is_none(z_uncompress))
            ssh_fatal("ssh_compress_is_none fails for none.");
        }
      else
        {
          if (ssh_compress_is_none(z_compress) ||
              ssh_compress_is_none(z_uncompress))
            ssh_fatal("ssh_compress_is_none fails for !none.");
        }

      /* Test that compression works. */
      ssh_compress_buffer(z_compress, ssh_buffer_ptr(b), ssh_buffer_len(b),
                          compressed);
      ssh_buffer_consume(compressed, padlen);

      ssh_compress_buffer(z_uncompress, ssh_buffer_ptr(compressed),
                          ssh_buffer_len(compressed), uncompressed);
      ssh_buffer_consume(uncompressed, padlen);

      if (ssh_buffer_len(uncompressed) != ssh_buffer_len(b))
        ssh_fatal("SshBuffer length differs after uncompression.");

      if (memcmp(ssh_buffer_ptr(uncompressed),
                 ssh_buffer_ptr(b), ssh_buffer_len(b)) != 0)
        ssh_fatal("SshBuffer data differs after uncompression.");

      /* Now compress again with the same context to check that it works. */
      ssh_buffer_clear(compressed);
      ssh_buffer_clear(uncompressed);
      ssh_compress_buffer(z_compress, ssh_buffer_ptr(b), ssh_buffer_len(b),
                          compressed);
      ssh_compress_buffer(z_uncompress, ssh_buffer_ptr(compressed),
                          ssh_buffer_len(compressed), uncompressed);
      if (ssh_buffer_len(uncompressed) != ssh_buffer_len(b))
        ssh_fatal("SshBuffer length differs after second uncompression.");
      if (memcmp(ssh_buffer_ptr(uncompressed),
                 ssh_buffer_ptr(b), ssh_buffer_len(b)) != 0)
        ssh_fatal("SshBuffer data differs after second uncompression.");

      ssh_compress_free(z_compress);
      ssh_compress_free(z_uncompress);

      method = strtok(NULL, ",");
    }

  ssh_buffer_free(compressed);
  ssh_buffer_free(uncompressed);
  ssh_free(method);
}

int main(int ac, char **av)
{
  int pass, len, i;
  unsigned char ch;
  SshBuffer b;
  char *cp;

  ssh_rand_seed(ssh_time());

  b = ssh_buffer_allocate();

  for (pass = 0; pass < PASSES; pass++)
    {
      printf("pass %d\n", pass);
      cp = ssh_compress_get_supported();

      if (strstr(cp, "none") == NULL)
        ssh_fatal("Required compression method none missing");

#ifdef SSHDIST_ZLIB
      if (strstr(cp, "zlib") == NULL)
        ssh_fatal("Required compression method zlib missing");
#endif /* SSHDIST_ZLIB */

      ssh_free(cp);

      printf("Running compression tests to %d:", MAX_SIZE);
      fflush(stdout);
      for (len = 1; len < MAX_SIZE; len += STEP)
        {
          if (len % 256 == 0)
            {
              printf(" %d", len);
              fflush(stdout);
            }

          /* Test compressing random data. */
          ssh_buffer_clear(b);
          for (i = 0; i < len; i++)
            {
              ch = (unsigned char)ssh_rand();
              ssh_buffer_append(b, &ch, 1);
            }
          test_compress(b);

          /* Test compressing sequentially increasing data. */
          ssh_buffer_clear(b);
          ch = (unsigned char)ssh_rand();
          for (i = 0; i < len; i++)
            {
              ch++;
              ssh_buffer_append(b, &ch, 1);
            }
          test_compress(b);

          /* Test compressing data that is a single character repeated. */
          ssh_buffer_clear(b);
          ch = (unsigned char)ssh_rand();
          for (i = 0; i < len; i++)
            ssh_buffer_append(b, &ch, 1);
          test_compress(b);

          /* Test compressing data with random short segments. */
          ssh_buffer_clear(b);
          ch = (unsigned char)ssh_rand();
          for (i = 0; i < len; i++)
            {
              if (ssh_rand() % 5 == 0)
                ch = (unsigned char)ssh_rand();
              ssh_buffer_append(b, &ch, 1);
            }
          test_compress(b);
        }
      printf("\n");
    }
  ssh_buffer_free(b);
  return 0;
}





