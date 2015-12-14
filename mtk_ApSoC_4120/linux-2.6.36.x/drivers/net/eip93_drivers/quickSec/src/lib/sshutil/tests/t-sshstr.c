/*
  File: t-sshstr.c

  Description:
        Test routines for sshstr.c module.

        Currently very trivial module only trying to utilize iso-latin
        base converted to utf8, and teletext.

  Copyright:
          Copyright (c) 2002, 2003, 2006 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "sshstr.h"
#include "sshrand.h"

static char *test_strings[] = {
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "abcdefghijklmnopqrstuvwxyz0123456789",
  "!@#$%&/()=?+-_.:,;<>'\"*~[]{}\\",
  "åäöÅÄÖ",
  NULL,
};

#define FAIL(msg) do { ssh_warning(msg); return FALSE; } while (0)

static Boolean check_conversion(void)
{
  SshStr s;
  int i;

  for (i = 0; test_strings[i]; i++)
    {
      if ((s =
           ssh_str_make(SSH_CHARSET_ISO_8859_1,
                        ssh_xstrdup(test_strings[i]), strlen(test_strings[i])))
          != NULL)
        {
          SshStr t61, latin, ucs2, ucs4, utf8;

          if ((t61 = ssh_str_charset_convert(s, SSH_CHARSET_T61)) == NULL)
            FAIL("t61");
          if ((ucs2 = ssh_str_charset_convert(t61, SSH_CHARSET_BMP)) == NULL)
            FAIL("ucs2");
          ssh_str_free(t61);

          if ((ucs4 = ssh_str_charset_convert(ucs2, SSH_CHARSET_UNIVERSAL))
              == NULL)
            FAIL("ucs4");
          ssh_str_free(ucs2);

          if ((utf8 = ssh_str_charset_convert(ucs4, SSH_CHARSET_UTF8)) == NULL)
            FAIL("utf8");
          ssh_str_free(ucs4);

          if ((latin = ssh_str_charset_convert(utf8, SSH_CHARSET_ISO_8859_1))
              == NULL)
            FAIL("latin");
          ssh_str_free(utf8);

          {
            unsigned char *b1, *b2;
            size_t b1_len, b2_len;

            if ((b1 = ssh_str_get(s, &b1_len)) != NULL)
              {
                if ((b2 = ssh_str_get(latin, &b2_len)) != NULL)
                  {
                    if (b1_len != b2_len)
		      FAIL("b1_len != b2_len");
                    if (memcmp(b1, b2, b1_len))
		      FAIL("b1 != b2");

                    ssh_xfree(b2);
                  }
                else
                  FAIL("no b2");
                ssh_xfree(b1);
              }
            else
              FAIL("no b1");
          }
          ssh_str_free(latin);
          ssh_str_free(s);
	}
      else
	{
	  FAIL("no core");
	}
    }
  return TRUE;
}

const char *charset[] =
{
  "printable",
  "visible",
  "US ascii",
  "ISO 8859-1:1987",
  "ISO 8859-2:1988",
  "ISO 8859-3:1988",
  "ISO 8859-4:1988",
  "ISO 8859-15:1988",
  "T.61/Teletex",
  "UCS-2",
  "UCS-4",
  "UTF-8"
};

unsigned int bits[] =
{
  0x3f, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void my_hexdump(unsigned char *buf, size_t buf_len)
{
  size_t i;

  if (buf_len > 256)
    {
      buf_len = 256;
      printf(" [ Following is truncated ]\n");
    }

  printf("0000: ");
  for (i = 0; i < buf_len; i++)
    {
      if (i > 0)
        {
          if ((i % 20) == 0)
            printf("\n%04x: ", i);
          else
            printf(" ");
        }

      if (isprint(buf[i]))
        printf(" %c", buf[i]);
      else
        printf("%02x", (unsigned int)buf[i]);
    }
  printf("\n");
}

Boolean check_resistanse(Boolean verbose)
{
  size_t i, j;
  unsigned char *in_buf;
  unsigned char *out_buf;
  size_t in_buf_len, out_buf_len;
  SshCharset in_charset, out_charset;
  SshStr in, out;

  for (i = 0; i < 1000; i++)
    {
      in_charset  = ssh_rand() % (SSH_CHARSET_UTF8+1);
      out_charset = ssh_rand() % (SSH_CHARSET_UTF8+1);

      in_buf_len  = ssh_rand() % 100;
      in_buf      = ssh_xmalloc(in_buf_len);

      for (j = 0; j < in_buf_len; j++)
        in_buf[j] = ssh_rand() & bits[in_charset];

      if (verbose)
        {
          printf(" Input buffer:\n");
          my_hexdump(in_buf, in_buf_len);
        }
      in = ssh_str_make(in_charset, in_buf, in_buf_len);
      if (in == NULL)
        continue;

      out = ssh_str_charset_convert(in, out_charset);
      if (out == NULL)
        {
          /* As the input is random - not neccessary a valid instance
	     of certain character set - we are expected to fail. */
          ;
        }
      else
        {
          out_buf = ssh_str_get(out, &out_buf_len);

          if (out_buf == NULL)
            {
              if (verbose)
                {
                  printf(" %s to %s transform failed for random buffer.\n",
                         charset[in_charset], charset[out_charset]);
                }
            }
          else
            {
              if (verbose)
                {
                  printf(" %s to %s transform success for buf.\n",
                         charset[in_charset], charset[out_charset]);
                  printf("    out buf:\n");
                  my_hexdump(out_buf, out_buf_len);
                }
              ssh_xfree(out_buf);
            }
        }
      ssh_str_free(out);
      ssh_str_free(in);
    }
  return TRUE;
}

int main(int ac, char *av[])
{
  SshTime seed = ssh_time();
  Boolean success = FALSE, verbose = FALSE;

  if (ac > 1)
    {
      if (!strcmp(av[1], "-v"))
        verbose = TRUE;
      else
        seed = atol(av[1]);

      if (ac > 2)
        seed = atol(av[1]);
    }

  ssh_rand_seed(seed);

  if (check_resistanse(verbose) && check_conversion())
    success = TRUE;

  ssh_util_uninit();
  return (success != TRUE);
}

/* eof */
