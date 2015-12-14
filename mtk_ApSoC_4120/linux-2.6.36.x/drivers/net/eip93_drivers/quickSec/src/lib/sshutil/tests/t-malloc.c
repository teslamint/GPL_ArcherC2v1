/*

t-malloc.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Thu Oct 24 22:59:37 1996 ylo
Last modified: 13:19 Feb  5 2009 kivinen

*/

#include "sshincludes.h"
#include "sshrand.h"
#include "ssheloop.h"
#include "sshtimeouts.h"

#ifdef HAVE_SETRLIMIT
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */
#endif /* HAVE_SETRLIMIT */

#define SSH_DEBUG_MODULE "SshMallocTest"

#define BLOCK_SIZE 16000

char *p[10000];
int p_cnt = 0;

void alloc_memory(void *context)
{
  ssh_xregister_timeout(0, 100000, alloc_memory, context);
  printf("Allocating block %d\n", p_cnt);
  p[p_cnt++] = ssh_xmalloc(BLOCK_SIZE);
}

void free_memory(void *context)
{
  ssh_xregister_timeout(1, 0, free_memory, context);
  printf("Freeing block %d\n", p_cnt);
  ssh_xfree(p[--p_cnt]);
}

void signal_memory(SshMallocState state, void *context)
{
  if (state == SSH_MALLOC_STATE_NORMAL)
    {
      printf("State normal, canceling free memory, p_cnt = %d\n", p_cnt);
      ssh_cancel_timeouts(free_memory, SSH_ALL_CONTEXTS);
      return;
    }
  if (state == SSH_MALLOC_STATE_MEMORY_LOW)
    {
      printf("State LOW, continuing, p_cnt = %d\n", p_cnt);
      return;
    }
  if (context)
    {
      printf("State CRITICAL, canceling alloc memory, "
             "starting freeing, p_cnt = %d\n", p_cnt);
      ssh_cancel_timeouts(alloc_memory, SSH_ALL_CONTEXTS);
      ssh_xregister_timeout(0, 10000, free_memory, context);
      return;
    }
  printf("State CRITICAL, continuing, p_cnt = %d\n", p_cnt);
}

int main(int ac, char **av)
{
  int pass;
  int i, j, len;

#ifdef MEMORY_LEAK_CHECKS
  printf("t-malloc does not work with memory leak checks enabled.\n");
  return 0;
#endif

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_DATA)
  {
    pid_t pid;
    int i, j, limit;

    for (i = 0; i < 6; i++)
      {

        printf("Starting test %d\n", i);
        pid = fork();

        if (pid == 0)
          {
            struct rlimit rl;
            ssh_event_loop_initialize();
            getrlimit(RLIMIT_DATA, &rl);
            rl.rlim_cur = 2 * 1024 * 1024;
            setrlimit(RLIMIT_DATA, &rl);
            if (i > 1)
              ssh_malloc_change_spare_buffer_size(128*1024);
	    limit = -1;
            for (j = 0; j < 2048/16; j++)
              {
#undef malloc
#undef free
                p[j] = malloc(BLOCK_SIZE);
                if (p[j] == NULL)
                  {
                    limit = j - 1;
                    break;
                  }
              }
	    if (limit == -1)
	      {
		printf("setrlimit(RLIMT_DATA, 2M) does not work, "
		       "cannot run malloc tests.\n");
		if (i % 2 == 0)
		  exit(0);
		else
		  ssh_fatal("Fail out from test");
	      }
            printf("Total allocatable bytes = %d KiB\n",
                   limit * BLOCK_SIZE / 1024);
            if (i >= 4)
              {
                for (j = limit; j >= 0; j--)
                  {
                    free(p[j]);
                    p[j] = NULL;
                  }
              }
            else
              {
                for (j = limit; j > limit - 16; j--)
                  {
                    free(p[j]);
                    p[j] = NULL;
                  }
              }

            switch (i)
              {
              case 0:
              case 1:
                for (j = 0; j < 16; j++)
                  ssh_xmalloc(BLOCK_SIZE); /* OK */
                if (i == 1)
                  {
                    for (j = 0; j < 2; j++)
                      ssh_xmalloc(BLOCK_SIZE); /* Fail */
                  }
                break;
              case 2:
              case 3:
                for (j = 0; j < 17; j++)
                  ssh_xmalloc(BLOCK_SIZE); /* OK */
                if (ssh_malloc_get_state() != SSH_MALLOC_STATE_NORMAL)
                  ssh_fatal("State not normal in test 2");
                for (j = 0; j < 8; j++)
                  ssh_xmalloc(BLOCK_SIZE); /* OK */
                if (ssh_malloc_get_state() != SSH_MALLOC_STATE_MEMORY_LOW)
                  ssh_fatal("State not low in test 2");
                for (j = 0; j < 4; j++)
                  ssh_xmalloc(BLOCK_SIZE); /* OK */
                if (ssh_malloc_get_state() != SSH_MALLOC_STATE_MEMORY_CRITICAL)
                  ssh_fatal("State not critical in test 2");
                for (j = 0; j < 3; j++)
                  ssh_xmalloc(BLOCK_SIZE); /* OK */
                if (i == 3)
                  for (j = 0; j < 2; j++)
                    ssh_xmalloc(BLOCK_SIZE); /* FAIL */
                break;
              case 4:
              case 5:
                ssh_malloc_signal_function_register(signal_memory,
                                                    (void *) (i == 4));
                ssh_xregister_timeout(1, 0, alloc_memory, (void *) (i == 4));
                ssh_event_loop_run();
                break;
              }
            ssh_event_loop_uninitialize();
            ssh_util_uninit();
            exit(0);
          }
        else
          {
            int status;

            if (wait(&status) != pid)
              {
                ssh_fatal("Wrong pid returned by wait");
              }
            if (i % 2 == 0)
              {
                if (WIFSIGNALED(status))
                  ssh_fatal("Child test %d exited with signal %d, "
                            "should have succeed", i, WTERMSIG(status));
                if (WEXITSTATUS(status) != 0)
                  ssh_fatal("Child test %d exited with status %d, "
                            "should have succeed", i, WEXITSTATUS(status));
              }
            else
              {
                if (WIFSIGNALED(status))
                  {
                    if (WTERMSIG(status) != 6)
                      ssh_fatal("Child test %d exited with signal %d, "
                                "should exit with signal 6",
                                i, WTERMSIG(status));
                  }
                else if (WEXITSTATUS(status) == 0)
                  ssh_fatal("Child test %d exited with status %d, "
                            "should have failed",
                            i, WEXITSTATUS(status));
              }
          }
      }
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_DATA */

  for (pass = 0; pass < 10; pass++)
    {
      for (i = 0; i < 10000; i++)
        {
          len = ssh_rand() % 1000;
          if (ssh_rand() % 256 == 0)
            len += ssh_rand() % 65000;
          if (ssh_rand() % 2)
            p[i] = ssh_xmalloc(len);
          else
            if (ssh_rand() % 2)
              p[i] = ssh_xcalloc(len, 1);
            else
              p[i] = ssh_xcalloc(1, len);
          if (p[i] == NULL)
            {
              printf("ssh_xmalloc %d bytes failed\n", len);
              exit(1);
            }
          memset(p[i], i, len);
        }

      for (i = 0; i < 10000; i++)
        {
          p[i] = ssh_xrealloc(p[i], ssh_rand() % 2000);
          if (p[i] == NULL)
            {
              printf("ssh_xrealloc failed\n");
              exit(1);
            }
        }

      for (i = 0; i < 1000; i++)
        {
          if (p[i])
            {
              ssh_xfree(p[i]);
              p[i] = NULL;
            }
          j = ssh_rand() % 10000;
          if (p[j])
            {
              ssh_xfree(p[j]);
              p[j] = NULL;
            }
        }

      for (i = 0; i < 1000; i++)
        p[i] = ssh_xmalloc(ssh_rand() % 1000);

      for (i = 0; i < 10000; i++)
        if (p[i])
          ssh_xfree(p[i]);

    }

#ifdef SSH_DEBUG_MALLOC
  {
    pid_t pid;
    int i;
    unsigned char *r, *q;
    size_t size;

    size = 0;
    for (i = 0; i < 210; i++)
      {
        pid = fork();
        if (pid == 0)
          {
            switch (i % 10)
              {
              case 0: size = 32; break;
              case 1: size = 31; break;
              case 2: size = 30; break;
              case 3: size = 29; break;
              case 4: size = 28; break;
              case 5: size = 27; break;
              case 6: size = 26; break;
              case 7: size = 25; break;
              case 8: size = 65536; break;
              case 9: size = 65534; break;
              }
            switch (i / 10)
              {
                /* Test overwrite checks in free */
              case 0:
                r = ssh_xmalloc(size);
                r[-1] = 23;
                ssh_xfree(r);   /* This should call fatal */
                break;
              case 1:
                r = ssh_xmalloc(size);
                r[size] = 42;
                ssh_xfree(r);   /* This should call fatal */
                break;

                /* Test overwrite checks in realloc */
              case 2:
                r = ssh_xmalloc(size);
                r[-1] = 23;
                ssh_xrealloc(r, size * 2);      /* This should call fatal */
                break;
              case 3:
                r = ssh_xmalloc(size);
                r[size] = 23;
                ssh_xrealloc(r, size * 2);      /* This should call fatal */
                break;

                /* Test overwrite checks in free after realloc */
              case 4:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[-1] = 23;
                ssh_xfree(r);   /* This should call fatal */
                break;
              case 5:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[size * 2] = 23;
                ssh_xfree(r);   /* This should call fatal */
                break;

                /* Test overwrite checks in realloc after realloc */
              case 6:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[-1] = 23;
                ssh_xrealloc(r, size);  /* This should call fatal */
                break;
              case 7:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[size * 2] = 23;
                ssh_xrealloc(r, size);  /* This should call fatal */
                break;

                /* Test double free */
              case 8:
                r = ssh_xmalloc(size);
                ssh_xfree(r);
                ssh_xfree(r);   /* This should call fatal */
                break;

                /* Test free for previous block assuming realloc moved block */
              case 9:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                ssh_xfree(r);   /* This should call fatal */
                break;

                /* Test overwrite checks in free after realloc, assuming
                   realloc moved block */
              case 10:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[-1] = 23;
                ssh_xfree(q);   /* This should call fatal */
                break;
              case 11:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[size * 10] = 23;
                ssh_xfree(q);   /* This should call fatal */
                break;

                /* Test overwrite checks in realloc after realloc, assuming
                   realloc moved block */
              case 12:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[-1] = 23;
                ssh_xrealloc(q, size);  /* This should call fatal */
                break;
              case 13:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[size * 10] = 23;
                ssh_xrealloc(q, size);  /* This should call fatal */
                break;

                /* Reallocating freed block */
              case 14:
                r = ssh_xmalloc(size);
                ssh_xfree(r);
                ssh_xrealloc(r, size * 2);      /* This should call fatal */
                break;

                /* Freeing unknown block */
              case 15:
                r = ssh_xmalloc(size);
                ssh_xfree(r + 4);       /* This should call fatal */
                break;

                /* Freeing unknown stack block */
              case 16:
                ssh_xfree(&r);  /* This should call fatal */
                break;

                /* Freeing unknown bss block */
              case 17:
                ssh_xfree(p);   /* This should call fatal */
                break;

                /* Reallocating unknown block */
              case 18:
                r = ssh_xmalloc(size);
                ssh_xrealloc(r + 4, size);      /* This should call fatal */
                break;

                /* Reallocating unknown stack block */
              case 19:
                ssh_xrealloc(&r, size); /* This should call fatal */
                break;

                /* Reallocating unknown bss block */
              case 20:
                ssh_xrealloc(p, size);  /* This should call fatal */
                break;
              }
            exit(0);
          }
        else
          {
            int status;

            if (wait(&status) != pid)
              {
                ssh_fatal("Wrong pid returned by wait");
              }
            if (WIFSIGNALED(status))
              {
                if (WTERMSIG(status) != 6)
                  ssh_fatal("Child test %d exited with signal %d, "
                            "should exit with signal 6",
                            i, WTERMSIG(status));
              }
            else if (WEXITSTATUS(status) == 0)
              {
                ssh_fatal("Child test %d exited with status %d, "
                          "should have failed",
                          i, WEXITSTATUS(status));
              }
          }
      }
  }
#endif /* SSH_DEBUG_MALLOC */

  /* This simple test should go through, since realloc must return a
     valid pointer even for 0-byte allocations, and those 0-byte
     allocations can then be further used for realloc and free. Old
     size for 0 allocation will be one. */
  {
    void *a, *b;

    a = NULL;
    b = ssh_realloc(a, 0, 0);
    SSH_ASSERT(b);
    ssh_free(b);

    a = ssh_realloc(a, 0, 0);
    SSH_ASSERT(a);

    b = ssh_realloc(a, 1, 0);
    SSH_ASSERT(b);
    ssh_free(b);
  }

  return 0;
}
