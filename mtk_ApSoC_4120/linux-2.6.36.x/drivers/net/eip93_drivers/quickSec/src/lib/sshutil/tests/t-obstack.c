/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright:
 *       Copyright (c) 2002-2004 SFNT Finland Oy.
 *       All rights reserved.
 *
 */
/*
 *       Program: Obstack test program
 *       Creation          : 12:00 Sep  3 2002 kivinen
 *       Last Modification : 15:57 Oct 29 2008 kivinen
 *       Version           : 1.285
 *       
 *       Description       : Test program obstack
 */

#include "sshincludes.h"
#include "sshobstack.h"
#include "sshrand.h"
#include "sshtimemeasure.h"
#include "sshgetopt.h"

#ifdef HAVE_SETRLIMIT
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */
#endif /* HAVE_SETRLIMIT */

#define TEST_COUNT_SMALL (1024*1024)
#define TEST_COUNT_BIG 1024

int main(int argc, char **argv)
{
  SshObStackContext pool;
  SshObStackContext pools[10];
  SshObStackConfStruct conf;
  unsigned char *buffer;
  unsigned char **ptrs;
  void *p[1024];
  SshTimeMeasureStruct tmit[1];
  SshUInt32 seed;
  size_t len, used;
  int i, j, k, verbose, full, error_printed;
  SshGetOptData getoptdata;


  getoptdata = ssh_xmalloc(sizeof(*getoptdata));
  memset(getoptdata, 0, sizeof(*getoptdata));

  ssh_getopt_init_data(getoptdata);
  verbose = full = 0;
  seed = (SshUInt32) ssh_time() & 0xffffffff;
  while ((i = ssh_getopt(argc, argv, "vf", getoptdata)) != -1)
    {
      switch (i)
        {
        case 'v':
          verbose++;
          break;
        case 'f':
          full++;
          break;
        case '?':
          printf("Usage: %s [-f ] [-v] [-v ...] [seed]\n", argv[0]);
	  exit(1); 
         break;
        }
    }

  if (argc > getoptdata->ind)
    {
      seed = atol(argv[getoptdata->ind]);
    }

  ssh_free(getoptdata);

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rl);
    getrlimit(RLIMIT_DATA, &rl);
    rl.rlim_cur = 0x400000 + 8192;
    if (TEST_COUNT_SMALL * 0x40 >
        TEST_COUNT_BIG * 0x4000 + TEST_COUNT_BIG / 256 * 0x400000)
      rl.rlim_cur += TEST_COUNT_SMALL * 0x40;
    else
      rl.rlim_cur += TEST_COUNT_BIG * 0x4000 + TEST_COUNT_BIG / 256 * 0x400000;
    setrlimit(RLIMIT_DATA, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */

  ptrs = ssh_xcalloc(sizeof(unsigned char *), TEST_COUNT_SMALL);
  buffer = ssh_xcalloc(1, 0x400000);
  for (i = 0; i < 0x400000; i++)
    buffer[i] = (i & 0xff) ^ (i >> 8);

  printf("Seed = %ld\n", seed);

  /* Reset randoms. */
  ssh_rand_seed(seed);

  ssh_time_measure_init(tmit);

  if (verbose)
    printf("Testing small objects...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate small object pool");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      len = (ssh_rand() & 0x3f) + 1;
      if (ssh_rand() & 0x1)
        ptrs[i] = ssh_obstack_alloc(pool, len);
      else
        ptrs[i] = ssh_obstack_alloc_unaligned(pool, len);
      if (ptrs[i] == NULL)
	{
	  if (!error_printed)
	    printf("Alloc %d failed for small objects\n", i);
	  error_printed = TRUE;
	}
      else
        memcpy(ptrs[i], buffer, len);
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)));

  /* Reset randoms. */
  ssh_rand_seed(seed);

  if (verbose > 1)
    printf("Verifying small objects\n");
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      len = (ssh_rand() & 0x3f) + 1;
      if (ssh_rand() & 0x1)
        if ((len >= 8 && ((unsigned long) ptrs[i] & 0x07) != 0) ||
            (len >= 4 && ((unsigned long) ptrs[i] & 0x03) != 0) ||
            (len >= 2 && ((unsigned long) ptrs[i] & 0x01) != 0))
          ssh_fatal("Aligned data not aligned: %d, %p, len = %d", i,
                    ptrs[i], len);
      if (ptrs[i] != NULL && memcmp(ptrs[i], buffer, len) != 0)
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  /* Reset randoms. */
  ssh_rand_seed(seed);

  ssh_time_measure_init(tmit);

  if (verbose)
    printf("Testing memdup objects...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate memdup object pool");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      len = (ssh_rand() & 0xf) + 1;
      if (ssh_rand() & 0x1)
        ptrs[i] = ssh_obstack_memdup(pool, "Kukkuu RESET....", 0);
      else
        ptrs[i] = ssh_obstack_memdup(pool, "Kukkuu RESET....", len);
      if (ptrs[i] == NULL)
	{
	  if (!error_printed)
	    printf("Alloc %d failed for memdup objects\n", i);
	  error_printed = TRUE;
	}
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)));

  /* Reset randoms. */
  ssh_rand_seed(seed);

  if (verbose > 1)
    printf("Verifying memdup objects\n");
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      len = (ssh_rand() & 0xf) + 1;
      if (ssh_rand() & 0x1)
	{
	  if (ptrs[i] != NULL && memcmp(ptrs[i], "Kukkuu RESET....", 17) != 0)
	    ssh_fatal("Memdup buffer overwritten: %d", i);
	}
      else
	{
	  if (ptrs[i] != NULL && memcmp(ptrs[i], "Kukkuu RESET....", len) != 0
	      && ptrs[i][len] != 0)
	    ssh_fatal("Memdup buffer overwritten: %d", i);
	}
    }
  ssh_obstack_destroy(pool);

  /* Reset randoms. */
  ssh_rand_seed(seed);

  if (verbose)
    printf("Testing big objects...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate big object pool");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (i = 0; i < TEST_COUNT_BIG; i++)
    {
      if ((ssh_rand() & 0xff) == 0)
        len = (ssh_rand() & 0x3fffff) + 1;
      else
        len = (ssh_rand() & 0x3fff) + 1;
      if (ssh_rand() & 0x1)
        ptrs[i] = ssh_obstack_alloc(pool, len);
      else
        ptrs[i] = ssh_obstack_alloc_unaligned(pool, len);
      if (ptrs[i] == NULL)
	{
	  if (!error_printed)
	    printf("Alloc %d failed for big objects\n", i);
	  error_printed = TRUE;
	}
      else
        memcpy(ptrs[i], buffer, len);
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_BIG * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)));

  /* Reset randoms. */
  ssh_rand_seed(seed);

  if (verbose > 1)
    printf("Verifying big objects\n");
  for (i = 0; i < TEST_COUNT_BIG; i++)
    {
      if ((ssh_rand() & 0xff) == 0)
        len = (ssh_rand() & 0x3fffff) + 1;
      else
        len = (ssh_rand() & 0x3fff) + 1;
      if (ssh_rand() & 0x1)
        if ((len >= 8 && ((unsigned long) ptrs[i] & 0x07) != 0) ||
            (len >= 4 && ((unsigned long) ptrs[i] & 0x03) != 0) ||
            (len >= 2 && ((unsigned long) ptrs[i] & 0x01) != 0))
          ssh_fatal("Aligned data not aligned: %d, %p, len = %d", i,
                    ptrs[i], len);
      if (ptrs[i] != NULL && memcmp(ptrs[i], buffer, len) != 0)
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (verbose)
    printf("Testing 1 byte aligned objects...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate 1 byte aligned object pool");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      ptrs[i] = ssh_obstack_alloc(pool, 1);
      if (ptrs[i] == NULL)
	{
	  if (!error_printed)
	    printf("Alloc %d failed for 1 byte aligned objects\n", i);
	  error_printed = TRUE;
	}
      else
        ptrs[i][0] = i & 0xff;
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)));
  if (verbose > 1)
    printf("Verifying 1 byte aligned objects\n");
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      if (ptrs[i] != NULL && ptrs[i][0] != (i & 0xff))
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (verbose)
    printf("Testing 1 byte unaligned objects...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate 1 byte unaligned object pool");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      ptrs[i] = ssh_obstack_alloc_unaligned(pool, 1);
      if (ptrs[i] == NULL)
	{
	  if (!error_printed)
	    printf("Alloc %d failed for 1 byte unaligned objects\n", i);
	  error_printed = TRUE;
	}
      else
        ptrs[i][0] = i & 0xff;
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)));
  if (verbose > 1)
    printf("Verifying 1 byte unaligned objects\n");
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      if (ptrs[i] != NULL && ptrs[i][0] != (i & 0xff))
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (verbose)
    printf("Testing 1 byte unaligned objects with pool clear...");
  pool = ssh_obstack_create(NULL);
  if (pool == NULL)
    ssh_fatal("Failed to allocate 1 byte unaligned object pool with clear");
  ssh_time_measure_start(tmit);
  error_printed = FALSE;
  for (j = 0; j < 10; j++)
    {
      ssh_obstack_clear(pool);
      for (i = 0; i < TEST_COUNT_SMALL; i++)
        {
          ptrs[i] = ssh_obstack_alloc_unaligned(pool, 1);
          if (ptrs[i] == NULL)
	    {
	      if (!error_printed)
		printf("Alloc %d failed for 1 byte unaliged objects "
		       "with pool clear\n", i);
	      error_printed = TRUE;
	    }
          else
            ptrs[i][0] = i & 0xff;
        }
      if (verbose)
        printf("%d...", j);
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec)\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            (ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND) /
	     10)));
  if (verbose > 1)
    printf("Verifying 1 byte unaligned objects\n");
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      if (ptrs[i] != NULL && ptrs[i][0] != (i & 0xff))
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (verbose)
    printf("Testing 1 byte unaligned objects with max limit...");
  conf.max_size = TEST_COUNT_SMALL / 2;
  conf.prealloc_size = 0;
  pool = ssh_obstack_create(&conf);
  if (pool == NULL)
    ssh_fatal("Failed to allocate 1 byte unaligned object pool with max");
  ssh_time_measure_start(tmit);
  j = 0;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      ptrs[i] = ssh_obstack_alloc_unaligned(pool, 1);
      if (j == 0)
        {
          if (ptrs[i] == NULL)
            j = i;
          else
            ptrs[i][0] = i & 0xff;
        }
      else
        {
          if (ptrs[i] != NULL)
            ssh_fatal("Alloc %d succeeded, after first failing\n", i);
        }
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec), %d bytes\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)),
           j);
  if (j == 0)
    ssh_fatal("max limit didn't work");
  if (verbose > 1)
    printf("Verifying 1 byte unaligned objects\n");
  for (i = 0; i < j; i++)
    {
      if (ptrs[i] != NULL && ptrs[i][0] != (i & 0xff))
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (verbose)
    printf("Testing 1 byte unaligned objects with max limit and prealloc...");
  conf.max_size = TEST_COUNT_SMALL / 2;
  conf.prealloc_size = TEST_COUNT_SMALL / 2 - 100;
  pool = ssh_obstack_create(&conf);
  if (pool == NULL)
    ssh_fatal("Failed to allocate 1 byte unaligned object pool "
	      "with max and prealloc");
  ssh_time_measure_start(tmit);
  j = 0;
  for (i = 0; i < TEST_COUNT_SMALL; i++)
    {
      ptrs[i] = ssh_obstack_alloc_unaligned(pool, 1);
      if (j == 0)
        {
          if (ptrs[i] == NULL)
            j = i;
          else
            ptrs[i][0] = i & 0xff;
        }
      else
        {
          if (ptrs[i] != NULL)
            ssh_fatal("Alloc %d succeeded, after first failing\n", i);
        }
    }
  ssh_time_measure_stop(tmit);
  if (verbose)
    printf("done (%ld / sec), %d bytes\n", (unsigned long)
           ((unsigned long) TEST_COUNT_SMALL * 1000L /
            ssh_time_measure_stamp(tmit, SSH_TIME_GRANULARITY_MILLISECOND)),
           j);
  if (j == 0)
    ssh_fatal("max limit didn't work");
  if (verbose > 1)
    printf("Verifying 1 byte unaligned objects\n");
  for (i = 0; i < j; i++)
    {
      if (ptrs[i] != NULL && ptrs[i][0] != (i & 0xff))
        ssh_fatal("Buffer overwritten: %d", i);
    }
  ssh_obstack_destroy(pool);

  if (full)
    {
      if (verbose)
	printf("Testing big objects until no more memory\n");
      pool = ssh_obstack_create(NULL);
      if (pool == NULL)
	ssh_fatal("Failed to allocate big objects pool (full test)");
      ssh_time_measure_start(tmit);
      used = 0;
      k = 0;
      for (i = 0; i < TEST_COUNT_SMALL; i++)
	{
	  if ((ssh_rand() & 0xff) == 0)
	    len = (ssh_rand() & 0x3fffff) + 1;
	  else
	    len = (ssh_rand() & 0x3fff) + 1;
	  used += len;
	  if (ssh_rand() & 0x1)
	    ptrs[i] = ssh_obstack_alloc(pool, len);
	  else
	    ptrs[i] = ssh_obstack_alloc_unaligned(pool, len);
	  if (ptrs[i] == NULL)
	    {
	      used -= len;
	      if (verbose > 2)
		printf("Alloc %d failed (%d bytes), memory used = %ld\n",
		       i, len,
		       (unsigned long) used);
	      k++;
	      if (k > 4)
		break;
	    }
	  else
	    {
	      memcpy(ptrs[i], buffer, len);
	      k = 0;
	    }
	}
      ssh_time_measure_stop(tmit);
      if (verbose)
	printf("done (%ld / sec), %ld bytes\n", (unsigned long)
	       ((unsigned long) TEST_COUNT_SMALL * 1000L /
		ssh_time_measure_stamp(tmit,
				       SSH_TIME_GRANULARITY_MILLISECOND)),
	       (unsigned long) used);
      if (i == TEST_COUNT_SMALL)
	ssh_fatal("Couldn't fill up the memory, rlimit problem?");
      ssh_obstack_destroy(pool);
    }

  conf.max_size = 0;
  conf.prealloc_size = (TEST_COUNT_BIG * 0x4000 +
                        TEST_COUNT_BIG / 256 * 0x400000) / 10;
  if (verbose)
    printf("Testing big objects with 10 pools with prealloc size = %ld\n",
           (unsigned long) conf.prealloc_size);
  for (k = 0; k < 10; k++)
    {
      pools[k] = ssh_obstack_create(&conf);
      if (pools[k] == NULL)
	ssh_fatal("Failed to allocate pool %d", k);
    }
  for (k = 0; k < 10; k++)
    {
      if (verbose > 1)
        printf("Filling pool %d\n", k);
      ssh_time_measure_start(tmit);
      used = 0;
      j = 0;
      for (i = 0; i < TEST_COUNT_BIG; i++)
        {
          if ((ssh_rand() & 0xff) == 0)
            len = (ssh_rand() & 0x3fffff) + 1;
          else
            len = (ssh_rand() & 0x3fff) + 1;
          used += len;
          ptrs[i] = ssh_obstack_alloc_unaligned(pools[k], len);
          if (ptrs[i] == NULL)
            {
              used -= len;
              if (verbose > 2)
                printf("Alloc %d failed (%d bytes), memory used = %ld\n",
                       i, len, (unsigned long) used);
              j++;
              if (j > 4)
                break;
            }
          else
            {
              memcpy(ptrs[i], buffer, len);
              j = 0;
            }
        }
      ssh_time_measure_stop(tmit);
      if (verbose > 1)
        printf("done (%ld / sec), %ld bytes\n", (unsigned long)
               ((unsigned long) TEST_COUNT_SMALL * 1000L /
                ssh_time_measure_stamp(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND)),
               (unsigned long) used);
      if (used + len < conf.prealloc_size)
        ssh_fatal("The last alloc should have succeeded, because of prealloc");
    }
  if (verbose)
    printf("Clearing pools\n");
  for (k = 0; k < 10; k++)
    {
      ssh_obstack_clear(pools[k]);
    }

  if (full)
    {
      if (verbose)
	printf("Filling memory with malloc\n");
      len = 1024*1024;
      for (i = 0; i < 1024; i++)
	{
	again:
	  p[i] = ssh_malloc(len);
	  if (p[i] == NULL)
	    {
	      len = len / 2;
	      if (len < 32)
		break;
	      goto again;
	    }
	}
      for (; i < 1024; i++)
	p[i] = NULL;
      
      for (k = 0; k < 10; k++)
	{
	  if (verbose > 1)
	    printf("Filling pools again %d\n", k);
	  ssh_time_measure_start(tmit);
	  used = 0;
	  j = 0;
	  for (i = 0; i < TEST_COUNT_BIG; i++)
	    {
	      if ((ssh_rand() & 0xff) == 0)
		len = (ssh_rand() & 0x3fffff) + 1;
	      else
		len = (ssh_rand() & 0x3fff) + 1;
	      used += len;
	      ptrs[i] = ssh_obstack_alloc_unaligned(pools[k], len);
	      if (ptrs[i] == NULL)
		{
		  used -= len;
		  if (verbose > 2)
		    printf("Alloc %d failed (%d bytes), memory used = %ld\n",
			   i, len, (unsigned long) used);
		  j++;
		  if (j > 4)
		    break;
		}
	      else
		{
		  memcpy(ptrs[i], buffer, len);
		  j = 0;
		}
	    }
	  ssh_time_measure_stop(tmit);
	  if (verbose > 1)
	    printf("done (%ld / sec), %ld bytes\n", (unsigned long)
		   ((unsigned long) TEST_COUNT_SMALL * 1000L /
		    ssh_time_measure_stamp(tmit,
					   SSH_TIME_GRANULARITY_MILLISECOND)),
		   (unsigned long) used);
	  if (used + len < conf.prealloc_size)
	    ssh_fatal("The last alloc should have succeeded, because "
		      "of prealloc");
	}

      for (i = 0; i < 1024; i++)
	ssh_free(p[i]);
    }

  if (verbose)
    printf("Free pools\n");
  for (k = 0; k < 10; k++)
    {
      ssh_obstack_destroy(pools[k]);
    }

  ssh_free(ptrs);
  ssh_free(buffer);
  ssh_util_uninit();
  return 0;
}
