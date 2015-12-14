/*

t-icept-attach.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Test program for the cpu-specific attach module.  This module does not exist
on all platforms, and is unix-specific code.

*/

#include "sshincludes.h"
#include "icept_attach.h"

/* On NetBSD 3.0 newer with pfil also on interfaces, we do not need the code
   on this file at all. For 2.0, having pfil, but no on the interfaces
   we attach to the ifioct with old technology. This test is disabled
   for NetBSD 3.0 or newer. */
#if SSH_NetBSD < 300

#include <sys/mman.h>

int pass;
int subst_called;
int orig_called;

/* Test function with few arguments (probably in registers). */

void orig1(int arg)
{
  if (arg != pass)
    {
      printf("orig: arg mismatch\n");
      abort();
    }
  if (orig_called)
    {
      printf("orig: orig already called!\n");
      abort();
    }
  orig_called = 1;
}

/* Test function with many arguments (probably on stack). */

void orig2(int a1, int a2, int a3, int a4, int a5,
           int a6, int a7, int a8, int a9, int a10,
           int a11, int a12)
{
  if (a1 != pass + 1 ||
      a2 != pass + 2 ||
      a3 != pass + 3 ||
      a4 != pass + 4 ||
      a5 != pass + 5 ||
      a6 != pass + 6 ||
      a7 != pass + 7 ||
      a8 != pass + 8 ||
      a9 != pass + 9 ||
      a10 != pass + 10 ||
      a11 != pass + 11 ||
      a12 != pass + 12)
    {
      printf("orig2: arg mismatch\n");
      abort();
    }
  if (orig_called)
    {
      printf("orig2: orig already called!\n");
      abort();
    }
  orig_called = 1;
}

/* Test for replacement. */

void orig3(void)
{
  if (orig_called)
    {
      printf("orig3: orig already called!\n");
      abort();
    }
  orig_called = 1;
}

/* Test for before. */

void substbefore(void)
{
  if (subst_called)
    {
      printf("substbefore called twice!\n");
      abort();
    }
  if (orig_called)
    {
      printf("substbefore called after orig!\n");
      abort();
    }
  subst_called = 1;
}

void substafter(void)
{
  if (subst_called)
    {
      printf("substafter called twice!\n");
      abort();
    }
  if (!orig_called)
    {
      printf("substafter called before orig!\n");
      abort();
    }
  subst_called = 1;
}

void substreplace(void)
{
  if (subst_called)
    {
      printf("substreplace called twice!\n");
      abort();
    }
  if (orig_called)
    {
      printf("substreplace AND orig called!\n");
      abort();
    }
  subst_called = 1;
}

SshAttachRec *substs;

SshAttachRec *ssh_get_substitutions(void)
{
  return substs;
}

SshAttachRec substs_before[] =
{
  { SSH_ATTACH_REPLACE, (void *)orig3, (void *)substreplace },
  { SSH_ATTACH_BEFORE,  (void *)orig1, (void *)substbefore },
  { SSH_ATTACH_BEFORE,  (void *)orig2, (void *)substbefore },
  { SSH_ATTACH_END }
};

SshAttachRec substs_after[] =
{
  { SSH_ATTACH_REPLACE, (void *)orig3, (void *)substreplace },
  { SSH_ATTACH_AFTER,   (void *)orig1, (void *)substafter },
  { SSH_ATTACH_AFTER,   (void *)orig2, (void *)substafter },
  { SSH_ATTACH_END }
};

int orig_retval(int arg)
{
  orig_called = 1;
  if (arg != 3)
    ssh_fatal("orig_retval: argument corrupted");

  return 4;
}

int subst_retval(void)
{
  int i, j = 0;

  subst_called = 1;

  for (i = 0; i < 100; i++)
    j += i;
  return j;
}

SshAttachRec substs_retval[] =
{
  { SSH_ATTACH_AFTER, (void *)orig_retval, (void *)subst_retval },
  { SSH_ATTACH_END }
};

int main(int ac, char **av)
{
  if (strlen(HOSTTYPE) < 4 || strncmp(HOSTTYPE, "i386", 4) != 0)
    /* This is not an `i386' platform.  We can't run this test. */
    return 0;

#ifdef HAVE_MPROTECT
  printf("Making code segment writable.\n");
  if (mprotect((void *)orig1, (long)main - (long)orig1,
               PROT_EXEC|PROT_READ|PROT_WRITE) < 0)
    {
      printf("mprotect failed\n");
      return 0;
    }
#else /* HAVE_MPROTECT */
  printf("No mprotect() found - cannot make code segment writable.\n");
  printf("Trying to run the test anyway, "
         "but this may legitimately fail or dump core.\n");
#endif /* HAVE_MPROTECT */

  printf("Starting attach tests.\n");
  printf("pass: ");
  for (pass = 0; pass < 1000; pass++)
    {
      printf(" %d", pass);
      fflush(stdout);

      /* Attach substitutions.  We do "before" substitutions on even rounds
         and "after" substitutions on odd rounds. */
      substs = (pass & 1) ? substs_after : substs_before;
      
#if SSH_NetBSD == 200
      ssh_attach_ifioctl();
#else /* SSH_NetBSD == 200 */
      ssh_attach_substitutions();
#endif /* SSH_NetBSD == 200 */

      /* Test that the substitutions get called correctly. */

      orig_called = subst_called = 0;
      orig1(pass);
      assert(orig_called && subst_called);

      orig_called = subst_called = 0;
      orig2(pass + 1, pass + 2, pass + 3, pass + 4, pass + 5, pass + 6,
            pass + 7, pass + 8, pass + 9, pass + 10, pass + 11, pass + 12);
      assert(orig_called && subst_called);

      orig_called = subst_called = 0;
      orig3();
      assert(!orig_called && subst_called);

      /* Detach all substitutions. */
#if SSH_NetBSD == 200
      ssh_detach_ifioctl();
#else /* SSH_NetBSD == 200 */
      ssh_detach_substitutions();
#endif /* SSH_NetBSD == 200 */

      /* Check that only the originals get called. */
      orig_called = subst_called = 0;
      orig1(pass);
      assert(orig_called && !subst_called);

      orig_called = subst_called = 0;
      orig2(pass + 1, pass + 2, pass + 3, pass + 4, pass + 5, pass + 6,
            pass + 7, pass + 8, pass + 9, pass + 10, pass + 11, pass + 12);
      assert(orig_called && !subst_called);

      orig_called = subst_called = 0;
      orig3();
      assert(orig_called && !subst_called);

      /* Check that return value from original function is correctly
         retained in after substitution. */
      substs = substs_retval;
      if (orig_retval(3) != 4)
        ssh_fatal("orig_retval returned incorrect value (no subst).");
#if SSH_NetBSD == 200
      ssh_attach_ifioctl();
#else /* SSH_NetBSD == 200 */
      ssh_attach_substitutions();
#endif /* SSH_NetBSD == 200 */
      orig_called = subst_called = 0;
      if (orig_retval(3) != 4)
        ssh_fatal("orig_retval returned incorrect value after substituting.");
      if (!orig_called || !subst_called)
        ssh_fatal("retval: both functions not called");
#if SSH_NetBSD == 200
      ssh_detach_ifioctl();
#else /* SSH_NetBSD == 200 */
      ssh_detach_substitutions();
#endif /* SSH_NetBSD == 200 */
      if (orig_retval(3) != 4)
        ssh_fatal("orig_retval returned incorrect value (after detach).");
    }
  printf("\nAttach tests successful.\n");

  return 0;
}

int splhigh(void)
{
  return 23;
}

void splx(x)
     int x;
{
  assert(x == 23);
}

void notcalled()
{
  /* Force these functions to come from libssh/libc, not interceptor stubs. */
  memcpy(NULL, NULL, 0);
  memcmp(NULL, NULL, 0);
}

#else /* SSH_NetBSD < 300 */
int main(int ac, char **av)
{
  return 0;
}
#endif /* SSH_NetBSD < 300 */
