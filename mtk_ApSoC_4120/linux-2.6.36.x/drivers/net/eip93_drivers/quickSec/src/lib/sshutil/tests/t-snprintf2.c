/*
 * t-snprintf2.c
 *
 * Author: Markus Stenberg <mstenber@ssh.com>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved
 *
 * Created:       Fri Nov 23 18:23:37 2001 mstenber
 * Last modified: Fri Nov 23 20:03:06 2001 mstenber
 * 
 *
 */

/*
  Tatu's t-snprintf original code attempts to verify the saneness of
  snprintf's output; this code, on other hand, attempts to find flaws
  in the buffer overflow handling.

  More than one of those existed in the code tree even fairly long after
  the introduction of the function to the tree, so therefore I considered
  this justified effort.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "foo"

#define MIN_WORKBUFFER_LEN 0
#define MAX_WORKBUFFER_LEN 128

typedef int (*TestCB)(unsigned char *buf, int buf_len, void *context);

/* plaintext */
int
test0(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      " ");
}

/* rendering function */
int
test1(unsigned char *buf, int buf_len, void *context)
{
  SshIpAddr addr = (SshIpAddr) context;
  return ssh_snprintf(buf, buf_len,
                      "%@/%10@[%.5@]",
                      ssh_ipaddr_render, addr,
                      ssh_ipaddr_render, addr,
                      ssh_ipaddr_render, addr);

}

/* %% */
int
test2(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%%");
}

/* number (%i/%d) */
int
test3(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%d", 1234);
}

/* pointer (%p) */
int
test4(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%p", test0);
}

/* hex number (%x) */
int
test5(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%x", 1234);
}

/* octal number (%o) */
int
test6(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%o", 1234);
}

/* unsigned number (%u) */
int
test7(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%u", 1234);
}

/* string (%s) */
int
test8(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%s", "f");
}

int
test9(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%s", "fo");
}

/* float (%f) */
int
test10(unsigned char *buf, int buf_len, void *context)
{
  return ssh_snprintf(buf, buf_len,
                      "%f", 5.6346);
}


void run_test(unsigned char *buf,
              size_t buf_len,
              TestCB callback,
              void *context
              )
{
  int i, ofs, return_value;
  int overflow = 0;
  int len;

  SSH_VERIFY(buf_len >= 2);
  memset(buf, 42, buf_len);
  ofs = 1;
  for (i = 0 ; i < (buf_len+1) ; i++)
    {
      /* printf("iter %d ofs %d\n", i, ofs); */
      return_value = callback(buf+ofs, buf_len-ofs-1, context);
      SSH_ASSERT(return_value >= 0);
      ofs += return_value;
      if (buf_len == 2)
        {

        }
      else
      if (buf_len == 3)
        {
          SSH_ASSERT(buf[1] == 0);
        }
      else
        {
          if (i < (buf_len - 3))
            {
              len = strlen(buf+1);
              SSH_ASSERT(len >= i);
              SSH_ASSERT(len <= buf_len - 3);

            }
        }
      SSH_ASSERT(ofs >= 1);
      SSH_VERIFY(buf[0] == 42);
      SSH_VERIFY(buf[buf_len-1] == 42);
      if (overflow)
        break;
      if (buf_len - ofs - 1 == 0)
        overflow = 1;
    }
}


int
main (int argc, char *argv[])
{
  char buf[1024];
  int i, j, k;
  SshIpAddrStruct addr;
  TestCB foo[] = {
    test0,
    test1,
    test2,
    test3,
    test4,
    test5,
    test6,
    test7,
    test8,
    test9,
    test10,
    NULL_FNPTR
  };
  int start, end, completed=-1;
  Boolean verbose = FALSE;

  ssh_ipaddr_parse_with_mask(&addr,
                             "127.0.0.1",
                             "255.255.255.0");

  if (argc > 1)
    verbose = TRUE;
  for (j = 0 ; foo[j] ; j++)
    {
      if (verbose)
        {
          printf("Running test %3d ", j);
          fflush(stdout);
        }
      start = MIN_WORKBUFFER_LEN + 2;
      end = MAX_WORKBUFFER_LEN + 2;
      completed = -1;
      for (i = start ; i < end ; i ++)
        {
          k = 100 * (i - start) / (end - start + 1);
          if (k != completed)
            {
              if (verbose)
                {
                  if (k%2)
                    printf(".");
                  fflush(stdout);
                }
              completed = k;
            }
          run_test(buf, i, foo[j], &addr);
        }
      if (verbose)
        printf(" OK\n");
    }
  ssh_util_uninit();
  return 0;
}
