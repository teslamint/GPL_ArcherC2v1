/*
  File: crypto_init.c

  Copyright:
        Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved.

  Functions which initialize the crypto library and manipulate its
  global state.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "crypto_tests.h"
#include "sshgetput.h"
#include "sshcipher/sshcipher_i.h"
#ifdef SSHDIST_CRYPTO_MAC
#include "sshmac/sshmac_i.h"
#endif /* SSHDIST_CRYPTO_MAC */

#ifndef KERNEL
#include "sshglobals.h"
#endif /* !KERNEL */
#ifdef SSHDIST_CRYPTO_PK
#ifndef KERNEL
#include "sshglobals.h"
#endif /* !KERNEL */
#endif /* SSHDIST_CRYPTO_PK */








#define SSH_DEBUG_MODULE "SshCryptoInit"

typedef struct SshCryptoNoiseRequestRec {

  SshCryptoNoiseRequestCB callback;
  void *context;
  struct SshCryptoNoiseRequestRec *next;
} SshCryptoNoiseRequestStruct, *SshCryptoNoiseRequest;

typedef struct SshCryptoStateRec
{
  SshCryptoLibraryStatus state;

  /* Current certification mode */
  SshCryptoCertificationMode certification_mode;














  /* Handles (SshCipher, SshHash, SshMac, SshPK, ...) allocated out */
  SshUInt32 handle_count;

  /* Random number generator */
  SshRandomObject rng;

  /* Registered noise request callbacks */
  SshCryptoNoiseRequest noise_requests;

#ifndef KERNEL
  /* Current time settable by ssh_crypto_set_time. If set then ssh_time is not
     used. If zero then ssh_crypto_get_time uses ssh_time to get the current
     time each time. */
  SshTime current_time;
#endif /* !KERNEL */
} SshCryptoStateStruct, *SshCryptoState;

/* SSH Globals cannot be used in kernel mode. */
#ifndef KERNEL
SSH_GLOBAL_DEFINE(SshCryptoStateStruct, ssh_crypto_library_state);
SSH_GLOBAL_DECLARE(SshCryptoStateStruct, ssh_crypto_library_state);
#define ssh_crypto_library_state SSH_GLOBAL_USE(ssh_crypto_library_state)
#else /* !KERNEL */
static SshCryptoStateStruct ssh_crypto_library_state;
#endif /* !KERNEL */




#ifdef WITH_ANSI_RNG
#define DEFAULT_RNG "ansi-x9.62"
#else /* !WITH_ANSI_RNG */
#define DEFAULT_RNG "ssh"
#endif /* WITH_ANSI_RNG */











































































































































/* Forward declaration. */
static SshCryptoStatus ssh_crypto_library_run_self_tests(void);
static void ssh_random_object_add_light_noise(SshRandomObject random);

SshCryptoStatus ssh_crypto_library_initialize(void)
{
  SshCryptoStateStruct s;
#ifndef KERNEL
  SshCryptoStatus status;
#endif /* KERNEL */
  memset(&s, 0, sizeof(s));
  s.state = SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;

  /* Init only possible if in uninit state. */
#ifndef KERNEL
  if (SSH_GLOBAL_CHECK(ssh_crypto_library_state))
#endif /* KERNEL */
  if (ssh_crypto_library_state.state !=
      SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    return SSH_CRYPTO_LIBRARY_ERROR;

#ifdef KERNEL
  ssh_crypto_library_state = s;
#else /* KERNEL */
  SSH_GLOBAL_INIT(ssh_crypto_library_state, s);
#endif /* KERNEL */

#ifndef KERNEL
  /* Register the keys types here. */
#ifdef SSHDIST_CRYPT_RSA
#ifdef WITH_RSA
  status = ssh_pk_provider_register(&ssh_pk_if_modn_generator);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register if-modn key type"));
      return status;
    }
#endif /* WITH_RSA */
#endif /* SSHDIST_CRYPT_RSA */

#ifdef SSHDIST_CRYPT_DL
#ifdef SSHDIST_CRYPT_DL_GENERATE
  status = ssh_pk_provider_register(&ssh_pk_dl_modp_generator);
#else /* SSHDIST_CRYPT_DL_GENERATE */
  status = ssh_pk_provider_register(&ssh_pk_dl_modp);
#endif /* SSHDIST_CRYPT_DL_GENERATE */
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register dl-modp key type"));
      return status;
    }
#endif /* SSHDIST_CRYPT_DL */
#endif /* !KERNEL */





  /* enter self test state for the duration of the tests */
  ssh_crypto_library_state.handle_count = 0;
  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST;













  /* Math library is needed for PK, PK is not available in KERNEL */
#ifdef SSHDIST_MATH
#ifndef KERNEL
  /* Initialize the math library (necessary for public key operations). */
  if (!ssh_math_library_initialize())
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not initialize math library"));
      status = SSH_CRYPTO_MATH_INIT;
      ssh_crypto_library_state.state =
        SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
      goto failed_at_math;
    }
#endif /* !KERNEL */
#endif /* SSHDIST_MATH */

#ifndef KERNEL













  /* Initialize default RNG */
  status = ssh_random_object_allocate(DEFAULT_RNG,
                                      &ssh_crypto_library_state.rng);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate RNG `%s'", DEFAULT_RNG));
      ssh_crypto_library_state.state =
        SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
      goto failed_after_math;
    }















  /* Both the crypto and math library self tests have succeeded (if
     performed). Set the global state to OK. */
  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_OK;









#endif /* !KERNEL */

  ssh_random_object_add_light_noise(ssh_crypto_library_state.rng);
  return SSH_CRYPTO_OK;

#ifndef KERNEL
  /* Failure point, math library has been initialized (if required) */
 failed_after_math:
#ifdef SSHDIST_MATH
  ssh_math_library_uninitialize();

  /* Failure point, when math library failed to initialize */
 failed_at_math:
#endif /* SSHDIST_MATH */







  /* appropriate library state was set already above */
  return status;
#endif /* !KERNEL */
}

/* Uninitialize the library. */
SshCryptoStatus ssh_crypto_library_uninitialize(void)
{
  /* Can't uninit in uninit and self test states. */
  if (ssh_crypto_library_state.state ==
      SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED ||
      ssh_crypto_library_state.state ==
      SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    return SSH_CRYPTO_LIBRARY_ERROR;

#ifndef KERNEL
  /* Free RNG */
  if (ssh_crypto_library_state.rng)
    {
      ssh_random_object_free(ssh_crypto_library_state.rng);
      ssh_crypto_library_state.rng = NULL;
    }
#endif /* !KERNEL */

  if (ssh_crypto_library_state.handle_count > 0)
    {
      ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_ERROR;
      return SSH_CRYPTO_LIBRARY_ERROR;
    }








  ssh_crypto_library_unregister_noise_request(NULL_FNPTR, NULL);

#ifdef SSHDIST_MATH
#ifndef KERNEL
  ssh_math_library_uninitialize();
#endif /* !KERNEL */
#endif /* SSHDIST_MATH */

  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
  return SSH_CRYPTO_OK;
}

/* Just return the status */
SshCryptoLibraryStatus ssh_crypto_library_get_status(void)
{
  return ssh_crypto_library_state.state;
}

void ssh_crypto_library_error(SshCryptoError error)
{
  /* There is no transition to error status from uninitialized state */
  SSH_ASSERT(ssh_crypto_library_state.state
             != SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED);

  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_ERROR;
}

/* Internal */
static SshCryptoStatus ssh_crypto_library_run_self_tests(void)
{













































  /* Run the symmetric crypto self tests. */






























  return SSH_CRYPTO_OK;
}


/* Public */
SshCryptoStatus ssh_crypto_library_self_tests(void)
{
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  status = ssh_crypto_library_run_self_tests();
  if (status != SSH_CRYPTO_OK)
    {
      ssh_crypto_library_error(SSH_CRYPTO_ERROR_OTHER);
      return status;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_crypto_set_certification_mode(SshCryptoCertificationMode mode)
{
  SshCryptoCertificationMode valid_modes[] = {
    SSH_CRYPTO_CERTIFICATION_NONE



  };
  int i;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  /* Well, you can change from current mode to current mode without
     any errors */
  if (ssh_crypto_library_state.certification_mode == mode)
    return SSH_CRYPTO_OK;

  /* Check that handle count is 0 */
  if (ssh_crypto_library_state.handle_count != 0)
    return SSH_CRYPTO_LIBRARY_OBJECTS_EXIST;














  /* Verify that "mode" is one of the approved ones. We are quite
     strict here to prevent someone from setting for example ~0
     mode */
  for (i = 0; i < sizeof(valid_modes) / sizeof(valid_modes[0]); i++)
    if (mode == valid_modes[i])
      {
        ssh_crypto_library_state.certification_mode = mode;
        return SSH_CRYPTO_OK;
      }

  /* Specified certification mode is not supported */
  return SSH_CRYPTO_UNSUPPORTED;
}

SshCryptoCertificationMode
ssh_crypto_get_certification_mode(void)
{
  return ssh_crypto_library_state.certification_mode;
}








































/* Provide a no-operation stub. */
void
ssh_crypto_library_zeroize(void)
{
}


/* Take of reference to crypto object. */
Boolean
ssh_crypto_library_object_use(void *obj, SshCryptoObjectType type)
{




























  ssh_crypto_library_state.handle_count++;

  return TRUE;
}

void
ssh_crypto_library_object_release(void *obj)
{




















  ssh_crypto_library_state.handle_count--;
}

void *ssh_crypto_malloc_i(size_t size)
{
  void *ptr;

  ptr = ssh_malloc(size + sizeof(size_t));

  if (!ptr)
    return NULL;

  ((size_t*) ptr)[0] = size;

  return &(((size_t *) ptr)[1]);
}

void *ssh_crypto_calloc_i(size_t nelems, size_t size)
{
  void *ptr;

  ptr = ssh_crypto_malloc_i(nelems * size);

  if (ptr)
    memset(ptr, 0, nelems * size);

  return ptr;
}

void ssh_crypto_free_i(void *ptr)
{
  size_t size;

  if (!ptr)
    return;

  size = ((size_t *) ptr)[-1];

  memset(ptr, 0, size);

  ssh_free(&((size_t *) ptr)[-01]);
}

#ifdef _MSC_VER
/* turn compiler optimizations off for this func */
#pragma optimize("",off)
#endif /* _MSC_VER */

void ssh_crypto_zeroize(void *ptr, size_t n)
{
  unsigned char *p = (unsigned char *)ptr;
  int i;
  for (i = 0; i < n; i++) p[i] = '\0';
}

#ifdef _MSC_VER
#pragma optimize("",on)
#endif /* _MSC_VER */

unsigned int ssh_random_object_get_byte(void)
{
  unsigned char buf[1];

#ifndef KERNEL
  SshCryptoStatus status;

  status = ssh_random_object_get_bytes(ssh_crypto_library_state.rng,
                                       buf, 1);

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Fatal failure in ssh_random_get_bytes: %s (%d)",
              ssh_crypto_status_message(status), status);
#else /* KERNEL */
  buf[0] = 0;
#endif /* !KERNEL */

  return buf[0];
}

unsigned int ssh_random_get_byte(void)
{
#ifndef KERNEL
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_get_byte called while crypto is uninitialized");
  return ssh_random_object_get_byte();
#else /* KERNEL */
  {
    unsigned char buf[1];

    buf[0] = 0;
    return buf[0];
  }
#endif /* !KERNEL */
}

SshUInt32 ssh_random_get_uint32(void)
{
  SshCryptoStatus status;
  unsigned char buf[4];
#ifndef KERNEL
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_get_byte called while crypto is uninitialized");

  status = ssh_random_object_get_bytes(ssh_crypto_library_state.rng,
                                       buf, 4);
  
  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Fatal failure in ssh_random_get_bytes: %s (%d)",
              ssh_crypto_status_message(status), status);

  return SSH_GET_32BIT(buf);
#else /* KERNEL */
  ssh_fatal("This function is not implemented in kernel");
#endif /* !KERNEL */
}

void
ssh_random_object_add_noise(const unsigned char *buf, size_t bytes,
			    size_t estimated_entropy_bits)
{
#ifndef KERNEL
  ssh_random_object_add_entropy(ssh_crypto_library_state.rng,
                                (const unsigned char *)buf, bytes,
				estimated_entropy_bits);
#endif /* !KERNEL */
}


void
ssh_random_add_noise(const unsigned char *buf, size_t bytes,
		     size_t estimated_entropy_bits)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Adding %d bytes of noise, estimated entropy bits %d",
	     (int) bytes, (int) estimated_entropy_bits));

#ifndef KERNEL
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_add_noise called while crypto is uninitialized");

  ssh_random_object_add_noise(buf, bytes, estimated_entropy_bits);
#endif /* !KERNEL */
}

void ssh_random_stir(void)
{
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_stir called while crypto is uninitialized");

  /* This function has no effect. */
}

/* This routine checks validity of object use/creation within the
   library. It returns TRUE if so, and FALSE otherwise (and sets
   (*status_ret) if not NULL). State is good when it is
   SSH_CRYPTO_LIBRARY_STATE_OK. */

Boolean ssh_crypto_library_object_check_use(SshCryptoStatus *status_ret)
{
  SshCryptoLibraryStatus status;
  SshCryptoStatus dummy;

  if (!status_ret)
    status_ret = &dummy;

  status = ssh_crypto_library_state.state;

  if (status == SSH_CRYPTO_LIBRARY_STATUS_OK)
    {
      *status_ret = SSH_CRYPTO_OK;
      return TRUE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_INITIALIZING;
      return FALSE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_UNINITIALIZED;
      return FALSE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_ERROR)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_ERROR;
      return FALSE;
    }

  *status_ret = SSH_CRYPTO_LIBRARY_ERROR;
  SSH_NOTREACHED;
  return FALSE;
}

/* This routine checks validity of object release within the
   library. It returns TRUE if so, and FALSE otherwise (and sets
   (*status_ret) if not NULL). State is good when it is
   SSH_CRYPTO_LIBRARY_STATE_OK or
   SSH_CRYPTO_LIBRARY_STATE_ERROR. Eg. crypto objects can be freed in
   the error state. */







Boolean ssh_crypto_library_object_check_release(SshCryptoStatus *status_ret)
{
  SshCryptoLibraryStatus status;
  SshCryptoStatus dummy;

  if (!status_ret)
    status_ret = &dummy;

  status = ssh_crypto_library_state.state;

  if (status == SSH_CRYPTO_LIBRARY_STATUS_OK ||
      status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST ||
      status == SSH_CRYPTO_LIBRARY_STATUS_ERROR)
    {
      *status_ret = SSH_CRYPTO_OK;
      return TRUE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_UNINITIALIZED;
      return FALSE;
    }

  SSH_NOTREACHED;
  return FALSE;
}

SshCryptoStatus
ssh_crypto_set_default_rng(SshRandom handle)
{
  SshRandomObject rng;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(rng = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

#ifndef KERNEL








  ssh_random_object_free(ssh_crypto_library_state.rng);
#endif /* !KERNEL */
  ssh_crypto_library_state.rng = rng;

  return SSH_CRYPTO_OK;
}





























void
ssh_crypto_free(void *ptr)
{
  ssh_free(ptr);
}

/* Get current time as 64-bit integer. If time is set in the global state, use
   that (that is used during the static random number tests for random number
   generators which depend on current time), otherwise use ssh_time to get the
   current time. */

#ifndef KERNEL
SshTime ssh_crypto_get_time(void)
{
  if (ssh_crypto_library_state.current_time != -1)
    return ssh_crypto_library_state.current_time;
  return ssh_time();
}

/* Sets the current time used by the crypto library. Setting time to zero
   indicates that crypto library should use ssh_time every time
   ssh_crypto_get_time is called. */

void ssh_crypto_set_time(SshTime t)
{
  ssh_crypto_library_state.current_time = t;
}
#endif /* !KERNEL */


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

/* The kernel and non-kernel version are separated, since they have so
   little in common between them. This helps a little on understanding
   of the routines, since by nature they are heavily
   ifdef-cluttered. */

#ifdef KERNEL
static void
ssh_random_object_add_light_noise(SshRandomObject random)
{
  return;
}

void
ssh_random_add_light_noise(SshRandom handle)
{
  return;
}

#endif /* KERNEL */

#ifndef KERNEL
static void
ssh_random_object_add_light_noise(SshRandomObject random)
{
  unsigned char noise_bytes[512];
  int noise_index = 0;

  if (random == NULL)
    random = ssh_crypto_library_state.rng;

#if !defined(WINDOWS) && !defined(DOS) && \
        !defined(macintosh) && !defined(VXWORKS)
  {
    int f;
    SSH_DEBUG(10, ("Starting read from /dev/random."));
    /* If /dev/random is available, read some data from there in non-blocking
       mode and mix it into the pool. */
    f = open("/dev/random", O_RDONLY);

    if (f != -1)
      {
        unsigned char buf[32];
        int len;
        /* Set the descriptor into non-blocking mode. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
        fcntl(f, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
        fcntl(f, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
        len = read(f, buf, sizeof(buf));
        close(f);
        SSH_DEBUG(10, ("Read %d bytes from /dev/random.", len));
	/* Assume /dev/random provides 1 bit of entropy for each returned 
	   byte (8 bits). */
        if (len > 0)
          ssh_random_object_add_entropy(random, buf, len, len);
      }
    else
      {
        SSH_DEBUG(10, ("Opening /dev/random failed."));
      }
  }
#endif /* !WINDOWS, !DOS, !macintosh, !VXWORKS */

  /* Get miscellaneous noise from various system parameters and statistics. */
  noise_add_word((SshUInt32) ssh_time());
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
#ifdef VXWORKS



#endif /* VXWORKS */

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
        unsigned char buf[32];

        SSH_DEBUG(10, 
                  ("Using MS RSA CSP's random number generator to "
                   "generate additional random noise"));

	/* Assume the MS CSP provides 1 bit of entropy for each returned 
	   byte (8 bits). */
        if (CryptGenRandom(provider, sizeof(buf), buf))
          ssh_random_object_add_entropy(random, buf, sizeof(buf), sizeof(buf));

        CryptReleaseContext(provider, 0);
      }
    else
      {
        SSH_DEBUG(10, 
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

  SSH_DEBUG(9,
            ("Adding %d bytes (out of %d collected) of noise to random pool",
             noise_index > sizeof(noise_bytes)
             ? sizeof(noise_bytes) : noise_index,
             noise_index));

  /* Add collected entropic (hopefully) bytes. This light system noise is 
     by definition pretty weak, so assume we get just 2 random bits in
     total. */
  ssh_random_object_add_entropy(random, noise_bytes,
				noise_index > sizeof(noise_bytes)
				? sizeof(noise_bytes) : noise_index,
				2);
}

void
ssh_random_add_light_noise(SshRandom handle)
{
  SshRandomObject random;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    ssh_fatal("ssh_random_add_light_noise called while crypto is "
              "uninitialized");

  if (handle == NULL)
    {
      ssh_random_object_add_light_noise(NULL);
      return;
    }

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return;

  ssh_random_object_add_light_noise(random);
}


#endif /* !KERNEL */

#undef noise_add_byte
#undef noise_add_word

/******************* End of env noise retrieval *************************/


/************************** Noise sources *******************************/

Boolean
ssh_crypto_library_register_noise_request(SshCryptoNoiseRequestCB request_cb,
					  void *context)
{
  SshCryptoNoiseRequest noise;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Registering noise source request callback %p to crypto library",
	     request_cb));
  
  if (request_cb == NULL_FNPTR)
    return FALSE;
  
  noise = ssh_calloc(1, sizeof(SshCryptoNoiseRequestStruct));
  if (noise == NULL)
    return FALSE;

  noise->callback = request_cb;
  noise->context = context;
  noise->next = ssh_crypto_library_state.noise_requests;
  ssh_crypto_library_state.noise_requests = noise;

  /* Request noise from the newly added noise source. */
  (*request_cb)(context);

  return TRUE;
}

Boolean
ssh_crypto_library_unregister_noise_request(SshCryptoNoiseRequestCB request_cb,
					    void *context)
{
  SshCryptoNoiseRequest curr, prev;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Unregistered noise source request callback %p from "
	     "crypto library", request_cb));

  prev = curr = ssh_crypto_library_state.noise_requests; 

  /* Remove all registered callbacks on NULL input parameters. */
  if (request_cb == NULL_FNPTR && context == NULL)
    {
      while (prev != NULL)
	{
	  curr = prev->next;
	  ssh_free(prev);
	  prev = curr;
	}
      ssh_crypto_library_state.noise_requests = NULL;
      return TRUE;
    }

  while (curr != NULL)
    {
      if (curr->callback == request_cb && curr->context == context)
	{
	  if (curr == ssh_crypto_library_state.noise_requests)
	    ssh_crypto_library_state.noise_requests = curr->next;
	  else
	    prev->next = curr->next;
	  ssh_free(curr);
	  return TRUE;
	}

      prev = curr;      
      curr = curr->next;
    } 
  return FALSE;
}

void  
ssh_crypto_library_request_noise(void)
{
  SshCryptoNoiseRequest request = ssh_crypto_library_state.noise_requests;

  /* Request random noise from all registered sources. */
  while (request != NULL)
    {
      (*request->callback)(request->context);
      request = request->next;
    }
}

