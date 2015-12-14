/*

  t-base64.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved.

  Created: Wed Oct 22 17:23:38 1997 [mkojo]

  Test program which knows how to convert base64 into and onto.

*/
#include "sshincludes.h"
#include "sshrand.h"
#include "sshbase64.h"
#include "sshfileio.h"

void basic_tests(void)
{
  unsigned char *tmp, *tmp_c, *tmp_o;
  size_t size, tmp_o_len;
  int i, c;

  printf(" -- doing basic base-64 testing.\n");

  for (size = 0; size < 1000; size++)
    {
      printf(" -- size %u\r", size);

      tmp = ssh_xmalloc(size);
      for (i = 0; i < size; i++)
        tmp[i] = ssh_rand() & 0xff;

      tmp_c = ssh_buf_to_base64(tmp, size);
      for (i = 0, c = 0; tmp_c[i] != '\0'; i++)
        {
          if (isprint(tmp_c[i]))
            c++;
        }
      if ((c % 4) != 0)
        {
          printf("warning: octet size = %u and base-64 length "
                 "not divisible by 4.\n", size);
        }

      tmp_o = ssh_base64_to_buf(tmp_c, &tmp_o_len);

      if (tmp_o == NULL)
        printf("warning: conversing back to octet string produces NULL.\n");
      else
        {
          if (tmp_o_len != size)
            printf("warning: conversion size mismatch.\n");
          else
            {
              if (memcmp(tmp_o, tmp, size) != 0)
                printf("warning: conversion failed.\n");
            }
        }
      ssh_xfree(tmp);
      ssh_xfree(tmp_c);
      ssh_xfree(tmp_o);
    }
  printf(" -- done.           \n");
}

void usage(void)
{
  printf("t-base64 [options] -from filename -to filename\n"
         "options: \n"
         " -base64     denotes that the input is in base 64.\n"
         "             Default is from binary to base64.\n");
  exit(1);
}

int main(int ac, char *av[])
{
  int pos, base = 256;
  char *tofile = NULL, *fromfile = NULL;
  unsigned char *buf;
  size_t buf_len;

  basic_tests();

  for (pos = 1; pos < ac; pos++)
    {
      if (strcmp("-to", av[pos]) == 0)
        {
          tofile = av[pos + 1];
          pos++;
          continue;
        }
      if (strcmp("-from", av[pos]) == 0)
        {
          fromfile = av[pos + 1];
          pos++;
          continue;
        }
      if (strcmp("-base64", av[pos]) == 0)
        {
          base = 64;
          continue;
        }
      if (strcmp("-h", av[pos]) == 0 ||
          strcmp("--help", av[pos]) == 0)
        {
          usage();
        }
      printf("Unknown option '%s'.\n", av[pos]);
      exit(1);
    }

  if (tofile == NULL || fromfile == NULL)
    {
      usage();
    }

  if (base == 256)
    {
      if (!ssh_read_file(fromfile, &buf, &buf_len))
        ssh_fatal("Could not read file %s", fromfile);
      if (!ssh_write_file_base64(tofile, "", "", buf, buf_len))
        ssh_fatal("Could not write base64 file %s", tofile);
      ssh_xfree(buf);
    }
  else
    {
      if (base == 64)
        {
          if (!ssh_read_file_base64(fromfile, &buf, &buf_len))
            ssh_fatal("Could not read base64 file %s", fromfile);
          if (!ssh_write_file(tofile, buf, buf_len))
            ssh_fatal("Could not write file %s", tofile);
          ssh_xfree(buf);
        }
      else
        {
          usage();
        }
    }
  return 0;
}
