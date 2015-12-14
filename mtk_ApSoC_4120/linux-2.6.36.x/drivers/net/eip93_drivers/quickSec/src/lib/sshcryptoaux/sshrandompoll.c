/*

  sshrandompoll.c

  Author: Patrick Irwin <irwin@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Periodically poll the system for noise and add it to the random number 
  generator.

*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "CryptoRandomPoll"

/* Total number of bits of entropy collected from system environment. */
#define SSH_RANDOM_POLL_SYS_ENV_ENTROPY 2

/* Number of bits of entropy per byte of /dev/random data. */
#define SSH_RANDOM_POLL_DEV_RANDOM_ENTROPY_PER_BYTE 1

/* Number of bits of entropy per byte of MS CSP data. */
#define SSH_RANDOM_POLL_MS_CSP_ENTROPY_PER_BYTE 1

typedef struct SshRandomPollRec {
  Boolean registered;
  SshTime last_collect_time;
} SshRandomPollStruct, *SshRandomPoll;

SSH_GLOBAL_DECLARE(SshRandomPollStruct, ssh_random_poll_state);
#define ssh_random_poll_state SSH_GLOBAL_USE(ssh_random_poll_state)

SSH_GLOBAL_DEFINE(SshRandomPollStruct, ssh_random_poll_state);

/******************* Retrieve noise from operating env ******************/

/* Utility macros */
#define noise_add_byte(B)                                       \
  do {                                                          \
    noise_bytes[noise_index++ % sizeof(noise_bytes)] = (B);     \
  } while (0)

#define noise_add_word(W)                       \
  do {                                          \
    SshUInt32 __w = (W);                        \
    noise_add_byte(__w & 0xff);                 \
    noise_add_byte((__w & 0xff00) >> 8);        \
    noise_add_byte((__w & 0xff0000) >> 16);     \
    noise_add_byte((__w & 0xff000000) >> 24);   \
  } while (0)


void random_poll_add_light_noise(SshRandomPoll state)
{
  unsigned char noise_bytes[512];
  int noise_index = 0;
  size_t entropy_bits = 0;
  SshTime now;
  
  /* First check the time since last noise collection and ignore noise request
     if not enough time has gone. */
  now = ssh_time();
  if (now - state->last_collect_time <= SSH_RANDOM_POLL_MIN_INTERVAL)
    return;

  state->last_collect_time = now;
  
#if !defined(WINDOWS) && !defined(DOS) && \
        !defined(macintosh) && !defined(VXWORKS)
  {
    int f;

    SSH_DEBUG(SSH_D_MIDOK, ("Starting read from /dev/random."));

    /* If /dev/random is available, read some data from there in non-blocking
       mode and mix it into the pool. */
    f = open("/dev/random", O_RDONLY);

    if (f != -1)
      {
        unsigned char *buf;
        size_t len;

	buf = &noise_bytes[noise_index % sizeof(noise_bytes)];
	len = sizeof(noise_bytes) - noise_index;
	if (len > 32)
	  len = 32;

        /* Set the descriptor into non-blocking mode. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
        fcntl(f, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
        fcntl(f, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
        len = read(f, buf, len);
        close(f);

        SSH_DEBUG(SSH_D_NICETOKNOW, ("Read %d bytes from /dev/random.", len));

	if (len > 0)
	  {
	    entropy_bits += len * SSH_RANDOM_POLL_DEV_RANDOM_ENTROPY_PER_BYTE;
	    noise_index = (noise_index + len) % sizeof(noise_bytes);
	  }
      }
    else
      {
        SSH_DEBUG(SSH_D_FAIL, ("Opening /dev/random failed."));
      }
  }
#endif /* !WINDOWS, !DOS, !macintosh, !VXWORKS */

#ifdef WIN32
  /* additional noise on Windows */
  {
    LARGE_INTEGER ticks;
    HCRYPTPROV provider;

    if (CryptAcquireContext(&provider, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_SILENT) || 
                            CryptAcquireContext(&provider, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_SILENT | CRYPT_NEWKEYSET))
      {
        unsigned char *buf;
        size_t len;

	buf = &noise_bytes[noise_index % sizeof(noise_bytes)];
	len = sizeof(noise_bytes) - noise_index;
	if (len > 32)
	  len = 32;
	
        SSH_DEBUG(SSH_D_NICETOKNOW, 
                  ("Using MS RSA CSP's random number generator to "
                   "generate additional random noise"));

        if (CryptGenRandom(provider, len, buf))
	  {
	    entropy_bits += len * SSH_RANDOM_POLL_MS_CSP_ENTROPY_PER_BYTE;
	    noise_index = (noise_index + len) % sizeof(noise_bytes);
	  }

        CryptReleaseContext(provider, 0);
      }
    else
      {
        SSH_DEBUG(SSH_D_NICETOKNOW, 
                  ("Failed to acquire CSP context (error = 0x%08X)",
                  GetLastError()));
      }

    if (QueryPerformanceCounter(&ticks))
      noise_add_word(ticks.LowPart);
    else
      noise_add_word((SshUInt32)GetTickCount());

    noise_add_word((SshUInt32)_getpid());
    noise_add_word((SshUInt32)GetCurrentThreadId());
  }
#endif /* WIN32 */

  /* Get miscellaneous noise from various system parameters and statistics. */
  
  /* Add current time to noise pool. */
  noise_add_word(now);

#ifdef HAVE_CLOCK
  noise_add_word((SshUInt32)clock());
#endif /* HAVE_CLOCK */
#ifdef HAVE_GETTIMEOFDAY
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    noise_add_word((SshUInt32)tv.tv_usec);
    noise_add_word((SshUInt32)tv.tv_sec);
  }
#endif /* HAVE_GETTIMEOFDAY */
#ifdef HAVE_TIMES
  {
    struct tms tm;
    noise_add_word((SshUInt32)times(&tm));
    noise_add_word((SshUInt32)(tm.tms_utime ^
                               (tm.tms_stime << 8) ^
                               (tm.tms_cutime << 16) ^
                               (tm.tms_cstime << 24)));
  }
#endif /* HAVE_TIMES */
#ifdef HAVE_GETRUSAGE
  {
    struct rusage ru, cru;
    getrusage(RUSAGE_SELF, &ru);
    getrusage(RUSAGE_CHILDREN, &cru);

    noise_add_word((SshUInt32)(ru.ru_utime.tv_usec +
                               cru.ru_utime.tv_usec));
    noise_add_word((SshUInt32)(ru.ru_stime.tv_usec +
                               cru.ru_stime.tv_usec));
    noise_add_word((SshUInt32)(ru.ru_maxrss + cru.ru_maxrss));
    noise_add_word((SshUInt32)(ru.ru_ixrss + cru.ru_ixrss));
    noise_add_word((SshUInt32)(ru.ru_idrss + cru.ru_idrss));
    noise_add_word((SshUInt32)(ru.ru_minflt + cru.ru_minflt));
    noise_add_word((SshUInt32)(ru.ru_majflt + cru.ru_majflt));
    noise_add_word((SshUInt32)(ru.ru_nswap + cru.ru_nswap));
    noise_add_word((SshUInt32)(ru.ru_inblock + cru.ru_inblock));
    noise_add_word((SshUInt32)(ru.ru_oublock + cru.ru_oublock));
    noise_add_word((SshUInt32)((ru.ru_msgsnd ^ ru.ru_msgrcv ^
                                ru.ru_nsignals) +
                               (cru.ru_msgsnd ^ cru.ru_msgrcv ^
                                cru.ru_nsignals)));
    noise_add_word((SshUInt32)(ru.ru_nvcsw + cru.ru_nvcsw));
    noise_add_word((SshUInt32)(ru.ru_nivcsw + cru.ru_nivcsw));
  }
#endif /* HAVE_GETRUSAGE */
#if !defined(WINDOWS) && !defined(DOS)
#ifdef HAVE_GETPID
  noise_add_word((SshUInt32)getpid());
#endif /* HAVE_GETPID */
#ifdef HAVE_GETPPID
  noise_add_word((SshUInt32)getppid());
#endif /* HAVE_GETPPID */
#ifdef HAVE_GETUID
  noise_add_word((SshUInt32)getuid());
#endif /* HAVE_GETUID */
#ifdef HAVE_GETGID
  noise_add_word((SshUInt32)(getgid() << 16));
#endif /* HAVE_GETGID */
#ifdef HAVE_GETPGRP
  noise_add_word((SshUInt32)getpgrp());
#endif /* HAVE_GETPGRP */
#endif /* WINDOWS */
#ifdef _POSIX_CHILD_MAX
  noise_add_word((SshUInt32)(_POSIX_CHILD_MAX << 16));
#endif /* _POSIX_CHILD_MAX */
#if defined(CLK_TCK) && !defined(WINDOWS) && !defined(DOS)
  noise_add_word((SshUInt32)(CLK_TCK << 16));
#endif /* CLK_TCK && !WINDOWS */

#ifdef SSH_TICKS_READ64
  {
    SshUInt64 tick;
    SSH_TICKS_READ64(tick);
    noise_add_word((tick >> 32) & 0xfffffff);
    noise_add_word(tick & 0xffffff);
  }
#else /* !SSH_TICKS_READ64 */
#ifdef SSH_TICKS_READ32
  {
    SshUInt32 tick;
    SSH_TICKS_READ32(tick);
    noise_add_word(tick);
  }
#endif /* SSH_TICKS_READ32 */
#endif /* SSH_TICKS_READ64 */

  entropy_bits += SSH_RANDOM_POLL_SYS_ENV_ENTROPY;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adding %d bytes (out of %d collected) of noise to random pool, "
	     "estimated entropy bits %d",
             (noise_index > sizeof(noise_bytes)
	      ? sizeof(noise_bytes) : noise_index),
             (int) noise_index,
	     (int) entropy_bits));

  /* Check if noise pool was filled up. */
  if (noise_index > sizeof(noise_bytes))
    noise_index = sizeof(noise_bytes);

  /* Assume on average no more than 1 bit of entropy per collected byte. */
  if (entropy_bits > noise_index)
    entropy_bits = noise_index;

  /* Add collected entropic (hopefully) bytes */
  ssh_random_add_noise(noise_bytes, noise_index, entropy_bits);
}
#undef noise_add_byte
#undef noise_add_word


/******************* Random noise source provider ***********************/

/* Noise signal callback. Crypto library calls this function whenever it's
   entropy level is low. */
void
random_noise_poll_signal_cb(void *context)
{
  /* Add noise to crypto library. */
  random_poll_add_light_noise(&ssh_random_poll_state);
}

void
ssh_random_noise_polling_init(void)
{
  SshRandomPollStruct poll;
  
  if (SSH_GLOBAL_CHECK(ssh_random_poll_state)
      && ssh_random_poll_state.registered)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Random noise polling is already initialized"));
      return;
    }

  /* Initialize global state. */
  memset(&poll, 0, sizeof(poll));
  SSH_GLOBAL_INIT(ssh_random_poll_state, poll);
  
  /* Register noise source to crypto library. */
  if (ssh_crypto_library_register_noise_request(random_noise_poll_signal_cb,
						&ssh_random_poll_state))
    {
      ssh_random_poll_state.registered = TRUE;
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Registered noise source to crypto library"));
    }
  else
    {
      ssh_random_poll_state.registered = FALSE;
      SSH_DEBUG(SSH_D_FAIL,
		("Failed to register noise source to crypto library"));
    }
}

void
ssh_random_noise_polling_uninit(void)
{
  if (!SSH_GLOBAL_CHECK(ssh_random_poll_state)
      || !ssh_random_poll_state.registered)    
    {
      SSH_DEBUG(SSH_D_FAIL, ("Random noise polling is not initialized"));
      return;
    }

  /* Unregister noise source. */
  if (ssh_crypto_library_unregister_noise_request(random_noise_poll_signal_cb,
						  &ssh_random_poll_state))
    {
      ssh_random_poll_state.registered = FALSE;
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Unregistered noise source from crypto library"));
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Failed to unregister noise source from crypto library"));
    }
}
