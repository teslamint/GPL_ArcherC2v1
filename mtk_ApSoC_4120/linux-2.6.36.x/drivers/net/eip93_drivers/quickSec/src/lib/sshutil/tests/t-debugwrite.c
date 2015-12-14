/*
 * Shamelessly copied from t-debugwrite.c
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *                  All rights reserved.
 */

/*
 *        Program: Util Lib
 *
 *        Description       : Test to verify that ssh_debug() works with
 *                            non-blocking streams as well.
 *
 */

#define SSH_DEBUG_MODULE "t-debugwrite"

#include "sshincludes.h"
#include "sshsnprintf.h"

#ifdef _XOPEN_SOURCE_EXTENDED
  #undef _XOPEN_SOURCE_EXTENDED
  #define SAVED_XOPEN_SOURCE_EXTENDED
#endif /* _XOPEN_SOURCE_EXTENDED */

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#define SAVED_XOPEN_SOURCE
#endif /* _XOPEN_SOURCE */

#ifdef HAVE_PTHREADS
  #ifndef WIN32
    #include <pthread.h>

    /* We must include strings.h here because otherwise we get
       conflict later */
    #include <strings.h>

    /* The pthread.h also defines try to something, and when we later include
       sshincludes.h we get warning about redefined symbol. */
    #undef try
  #endif /* WIN32 */
#endif /* HAVE_PTHREADS */

#ifndef EWOULDBLOCK
  #define EWOULDBLOCK EAGAIN
#endif /* EWOULDBLOCK */

#ifdef SAVED_XOPEN_SOURCE_EXTENDED
  #undef _XOPEN_SOURCE_EXTENDED
  #define _XOPEN_SOURCE_EXTENDED 1
  #undef SAVED_XOPEN_SOURCE_EXTENDED
#endif /* SAVED_XOPEN_SOURCE_EXTENDED */

#ifdef SAVED_XOPEN_SOURCE
  #undef _XOPEN_SOURCE
  #define _XOPEN_SOURCE 1
  #undef SAVED_XOPEN_SOURCE
#endif /* SAVED_XOPEN_SOURCE */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshmutex.h"
#include "sshgetopt.h"

#define FORMATLEN          5

#define DEBUG_OUTPUT    "test.received"
#define DEBUG_INPUT     "test.sent"

#define NO_TRIP            1

#ifndef SSH_DEBUG_BUFFER_SIZE
  #define SSH_DEBUG_BUFFER_SIZE 1024
#endif /* SSH_DEBUG_BUFFER_SIZE */

typedef void *(*SshForkedFunc)(void *context);
typedef struct SshThreadRec *SshThread;


#ifdef HAVE_THREADS
static SshMutex debug_mutex;
static int      testpipe[2];
static int      retval = 0;
static int      received = 0;
static int      logging = 0;
static int      blocking = 0;
static int      internal = 0;
static int      trip_start = 0;
static int      firsterror = 0;
static FILE    *in = NULL, *out = NULL;

static int      iterations = 3000;
static int      reportinterval = 300;
#endif /* HAVE THREADS */

#ifdef WIN32

#define D(x) \
  (ssh_mutex_lock(debug_mutex), \
  printf x, \
  ssh_mutex_unlock(debug_mutex), 0)

struct SshThreadRec {
  HANDLE handle;
  DWORD thread_id;
  SshForkedFunc func;
  void *func_context;
};

DWORD WINAPI thread_func(LPVOID context)
{
  SshThread thread = (SshThread)context;
  thread->func(thread->func_context);
  return 0;
}

SshThread fork_thread(SshForkedFunc func, void *context)
{
  SshThread t;
  DWORD thread_id;
  HANDLE handle;

  t = (SshThread)ssh_xmalloc(sizeof(*t));
  t->func = func;
  t->func_context = context;
  if (!(handle = CreateThread(NULL, 0, thread_func, t, 0, &thread_id)))
    {
      ssh_xfree(t);
      return NULL;
    }
  t->thread_id = thread_id;
  t->handle = handle;
  return t;
}

void wait_thread(SshThread thread)
{
  WaitForSingleObject(thread->handle, INFINITE);
  CloseHandle(thread->handle);
  ssh_xfree(thread);
}

#endif

#ifdef HAVE_PTHREADS

#define DEBUG_HEAVY
#ifdef DEBUG_HEAVY
#define D(x) \
  (ssh_mutex_lock(debug_mutex), \
  printf x, \
  ssh_mutex_unlock(debug_mutex), 0)
#else /* DEBUG_HEAVY */
#define D(x)
#endif /* DEBUG_HEAVY */

struct SshThreadRec {
  pthread_t thread;
};

SshThread fork_thread(SshForkedFunc func, void *context)
{
  SshThread thread;

  thread = ssh_xcalloc(1, sizeof(*thread));
  if (pthread_create(&thread->thread, NULL, func, context) != 0)
    ssh_fatal("pthread_create failed : %s", strerror(errno));
  return thread;
}

void wait_thread(SshThread thread)
{
  if (pthread_join(thread->thread, NULL) != 0)
    ssh_fatal("pthread_join failed : %s", strerror(errno));
  ssh_xfree(thread);
}

#endif /* HAVE_PTHREADS */

#ifdef HAVE_THREADS

SshMutex mutex1_start, mutex2_start;
SshMutex mutex1, mutex2;
int operations1 = 10;
int operations2 = 10;
SshThread thread1, thread2;
int threads;

char *linearise(char *inp)
{
  static char tmp[2048];
  int i, j, w = strlen(inp);

  for (i = 0, j = 0; i < w; i++)
    {
      if (inp[i] != '\n')
        {
          tmp[j++] = inp[i];
        }
      else
        {
          switch (inp[i])
            {
            case '\n':
              tmp[j++] = '\\';
              tmp[j++] = 'n';
              break;
            default:
              tmp[j++] = '?';
            }
        }
    }
  tmp[j] = (char)0;
  return tmp;
}

void check_for_threads(void *context)
{
  D(("Checking for threads, number of threads = %d\n", threads));
  if (threads == 0)
    {
      D(("No more threads, uninitilizing threaded timeouts\n"));
      ssh_threaded_timeouts_uninit();
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);
      return;
    }
  D(("Still some threads running, reinserting timeout\n"));
  ssh_xregister_timeout(0, 1000000, check_for_threads, NULL);
  return;
}

void call_wait_thread(void *context)
{
  SshThread thread = context;
  D(("C: Call_wait_thread called, number of threads now out %d, thread = %p\n",
     threads, thread));
  D(("C: Waiting for thread\n"));
  wait_thread(thread);
  threads--;
  D(("C: Waited for thread, decrementing threads counter, new value = %d\n",
     threads));
  if (threads == 0)
    ssh_xregister_timeout(0, 0, check_for_threads, NULL);
}

void kill_thread_1(void *context)
{
  retval +=1;

  D(("R: C: Freeing mutex 1\n"));
  ssh_mutex_unlock(mutex1);

  /* close(testpipe[0]); */
}

void kill_thread_2(void *context)
{
  retval +=1;

  D(("W: C: Freeing mutex 2\n"));
  ssh_mutex_unlock(mutex2);

  D(("W: C: Inserting thread wait timeout, thread = %p\n", thread2));
  ssh_xregister_threaded_timeout(0, 0, call_wait_thread, thread2);

  /* close(testpipe[1]); */
}

static void
ssh_debug_set_non_blocking(int fd)
{
#if !defined(WIN32)
#ifdef VXWORKS
  {
    int tmp = 1;
    ioctl(fd, FIONBIO, &tmp);
  }
#else /* VXWORKS */
  /* Make the file descriptor use non-blocking I/O. */
  #if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  #else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NDELAY);
  #endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
#endif  /* VXWORKS */
#endif  /* WIN32 */
}

static int
ssh_debug_wait_fd_writable(unsigned int filedes, unsigned long wait,
                           size_t *reason)
{
  struct timeval tv;
  fd_set fdset;
  int ret;

  /* Initialize the file descriptor set. */
  FD_ZERO(&fdset);
  FD_SET(filedes, &fdset);

  /* set timeout values */
  memset((void *)&tv, 0, sizeof(tv));

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  errno = 0;

  if (wait > 0)
    {
      tv.tv_sec = (long)(wait / 1000000);
      tv.tv_usec = (long)(wait % 1000000);
      ret = select(filedes + 1, NULL, &fdset, NULL, &tv);
    }
  else
    {
      ret = select(filedes + 1, NULL, &fdset, NULL, NULL);
    }

  if (ret > 0)
    {
      SSH_ASSERT(FD_ISSET(filedes, &fdset));
    }
  else
    {
      if (ret < 0 && reason)
        *reason = errno;
    }
  return ret;
}

static int
ssh_debug_wait_fd_readable(unsigned int filedes, unsigned long wait,
                           size_t *reason)
{
  struct timeval tv;
  fd_set fdset;
  int ret;

  /* Initialize the file descriptor set. */
  FD_ZERO(&fdset);
  FD_SET(filedes, &fdset);

  /* set timeout values */
  memset((void *)&tv, 0, sizeof(tv));

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  errno = 0;

  if (wait > 0)
    {
      tv.tv_sec = wait / 1000000;
      tv.tv_usec = wait % 1000000;
      ret = select(filedes + 1, &fdset, NULL, NULL, &tv);
    }
  else
    {
      ret = select(filedes + 1, &fdset, NULL, NULL, NULL);
    }

  if (ret > 0)
    {
      SSH_ASSERT(FD_ISSET(filedes, &fdset));
    }
  else
    {
      if (ret < 0 && reason)
        *reason = errno;
    }
  return ret;
}

void *func1(void *context)
{
  unsigned long val, xval = 0;
  unsigned char tmp[128];
  size_t rd = 0, r;
  size_t reason, result;
  int res;

#ifdef DEBUG_OUTPUT
  if (logging)
    out = fopen(DEBUG_OUTPUT, "w");
#endif /* DEBUG_OUTPUT */

  /* Read end, close write */
  /* close(testpipe[1]); */

  if (!blocking)
    ssh_debug_set_non_blocking(testpipe[0]);

  D(("In thread 1, Locking mutex 1\n"));
  ssh_mutex_lock(mutex1);
  ssh_mutex_lock(mutex1_start);
  ssh_mutex_unlock(mutex1_start);

  D(("R: In thread 1, Activating self-destruction\n"));
  ssh_xregister_threaded_timeout(0, 5000000, kill_thread_1, thread1);

  D(("R: In thread 1, starting\n"));
  r = FORMATLEN + 1;

  for (;;)
    {
      errno = 0;
      res = read(testpipe[0], tmp + rd, r - rd);

      if (res > 0)
        tmp[res + rd] = (char)0;

#ifdef DEBUG_INPUT
      if (logging)
        fprintf(out, "res: %d, err: %d, data: \"%s\"\n",
                res, errno, linearise(tmp + rd));
#endif /* DEBUG_INPUT */

      if (res == 0 && errno == 0)
        break;

      if (res > 0)
        {
          rd +=res;

          if (rd == FORMATLEN + 1)
            {
              rd = 0;
              val = atol(tmp);
              tmp[0] = (char)0;

              if (val != xval + 1)
                {
                  if (firsterror < 2)
                    {
                      D(("R: expected (prev %ld) %ld - %ld received\n",
                         xval, xval + 1, val));
                      if (firsterror == 1)
                        firsterror += 1;
                    }
                  retval += 1;
                }
              else
                {
                  xval = val;
                  received += 1;
                  if ((val % reportinterval) == 0)
                    D(("R: %0*ld\n", FORMATLEN, val));
                }

              if (val == iterations)
                {
                  D(("R: === END === yeah baby!\n"));
                  break;
                }
            }
        }

      if (errno != 0)
        {
          if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
            {
              D(("R: read: %d, error: %d (%s)\n",
                 res, errno, strerror(errno)));
              break;
            }
#ifdef DEBUG_OUTPUT
          if (logging)
            fprintf(out, "Entering select(), stream empty\n");
#endif /* DEBUG_OUTPUT */
          D(("R: Entering select(), current value: '%ld', err:%d (%s)\n",
             val, errno, strerror(errno)));
          do
            {
              result = ssh_debug_wait_fd_readable(testpipe[0], 0, &reason);
            } while (result == -1 && reason == EINTR);
        }
    }

#ifdef DEBUG_OUTPUT
  if (logging && out)
    {
      fclose(out);
      out = NULL;
    }
#endif /* DEBUG_OUTPUT */

  D(("R: In thread 1, All done, inserting thread wait timeout, thread = %p\n",
     thread1));
  ssh_xregister_threaded_timeout(0, 0, call_wait_thread, thread1);

  D(("R: In thread 1, Unlocking mutex 1\n"));
  ssh_mutex_unlock(mutex1);

  D(("R: In thread 1, De-activating self-destruction\n"));
  ssh_cancel_timeouts(kill_thread_1, SSH_ALL_CONTEXTS);

  D(("R: In thread 1, Exiting now\n"));
  close(testpipe[0]);

  return NULL;
}

static void
my_debug_output_i(FILE *stream, char *tmp, int cr)
{
  static int trip = -1;

  int fd = fileno(stream);
  size_t wd = 0, w = strlen(tmp);
  int res;
  size_t reason, result;

  if (trip == -1)
    trip = trip_start;

  for (;;)
    {
      errno = 0;

#ifndef NO_TRIP
      trip = !trip;
#endif

      if (trip)
        {
          res = fwrite(tmp + wd, 1, w - wd, stream);
        }
      else
        {
          res = write(fd, tmp + wd, w - wd);
        }

#ifdef DEBUG_INPUT
      if (logging)
        {
          if (!trip)
#ifdef WIN32
            fprintf(in, "res: %d, err: %d, eof?: %d, data: \"%s\"\n",
                    res, errno, _eof(fd) ? 1 : 0, linearise(tmp + wd));
#else /* WIN32 */
          fprintf(in, "res: %d, err: %d, data: \"%s\"\n",
                  res, errno, linearise(tmp + wd));
#endif /* WIN32 */
          else
            fprintf(in, "res: %d, err: %d, eof?: %d, data: \"%s\"\n",
                    res, errno, feof(stream) ? 1 : 0, linearise(tmp + wd));
        }
#endif /* DEBUG_INPUT */

      if (errno != 0)
        {
          D(("W: write (debug): res: %d, err: %d (%s), data: \"%s\"\n",
             res, errno, strerror(errno), linearise(tmp + wd)));
#ifdef DEBUG_INPUT
          if (logging)
            fprintf(in, "res: %d, err: %d (%s), wd: %d, data: \"%s\"\n",
                    res, errno, strerror(errno), wd, linearise(tmp + wd));
#endif /* DEBUG_INPUT */
        }

      if (res > 0)
        {
          wd +=res;

          if (wd == w)
            {
              if (cr == 0)
                {
                  return;
                }
              cr = 0;
              wd = 0;
              w = 1;
              tmp[0] = '\n';
              tmp[1] = (char)0;
            }
        }

      if (errno != 0)
        {
          if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
            {
              D(("W: write: %d, error: %d (%s)\n",
                 res, errno, strerror(errno)));
              return;
            }

#ifdef DEBUG_OUTPUT
          if (logging)
            fprintf(in, "Entering select(), stream full\n");
#endif /* DEBUG_OUTPUT */
          D(("W: Entering select(), current value: '%s'\n", tmp));

          do
            {
              result = ssh_debug_wait_fd_writable(testpipe[1], 0, &reason);
            } while (result == -1 && reason == EINTR);
        }
    }
}


void my_ssh_debug(const char *fmt, ...)
{
  va_list va;
  char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

#ifndef KERNEL
  my_debug_output_i(stderr, buf, TRUE);
#endif /* KERNEL */
}

void *func2(void *context)
{
  unsigned long val;
  FILE     xstderr, *mystderr;

  /* Write end, close read */
  /* close(testpipe[0]); */

  /* swop */
  mystderr = fdopen(testpipe[1], "a");

  xstderr = *stderr;
  *stderr = *mystderr;

  if (!blocking)
    ssh_debug_set_non_blocking(fileno(stderr));

  D(("In thread 2, Locking mutex 2\n"));
  ssh_mutex_lock(mutex2);
  ssh_mutex_lock(mutex2_start);
  ssh_mutex_unlock(mutex2_start);

  D(("W: In thread 2, Activating self-destruction\n"));
  ssh_xregister_threaded_timeout(0, 10000000, kill_thread_2, thread2);

  D(("W: In thread 2, starting\n"));

#ifdef DEBUG_INPUT
  if (logging)
    in = fopen(DEBUG_INPUT, "w");
#endif /* DEBUG_INPUT */

  for (val = 1; val <= iterations; val++)
    {
      if (internal)
        my_ssh_debug("%05ld", val);
      else
        ssh_debug("%05ld", val);

      if ((val % reportinterval) == 0)
        D(("W: %0*ld\n", FORMATLEN, val));
    }

#ifdef DEBUG_INPUT
  if (logging && in)
    {
      fclose(in);
      in = NULL;
    }
#endif /* DEBUG_INPUT */

  D(("W: Waiting for thread 1 to finish...\n"));
  ssh_mutex_lock(mutex1);
  ssh_mutex_unlock(mutex1);

  *stderr = xstderr;

  D(("W: Closing write end\n"));
  close(testpipe[1]);

  D(("W: In thread 2, All done, inserting thread wait timeout, thread = %p\n",
     thread2));
  ssh_xregister_threaded_timeout(0, 0, call_wait_thread, thread2);

  D(("W: In thread 2, Unlocking mutex 2\n"));
  ssh_mutex_unlock(mutex2);

  D(("W: In thread 2, De-activating self-destruction\n"));
  ssh_cancel_timeouts(kill_thread_2, SSH_ALL_CONTEXTS);

  D(("W: In thread 2, Exiting now\n"));
  /* close(testpipe[1]); */

  return 0;
}

void start_program_r(void *context)
{
  D(("M: Unlocking start mutex 1 (read)\n"));
  ssh_mutex_unlock(mutex1_start);
}

void start_program_w(void *context)
{
  D(("M: Unlocking start mutex 2 (write)\n"));
  ssh_mutex_unlock(mutex2_start);
  ssh_xregister_timeout(0, 3000000, start_program_r, NULL);
}

char *program;

void usage(void)
{
  fprintf(stderr, "Usage: %s [-d debug_level_string] [options]\n"
#ifndef WIN32
          "\t-n  Set file descriptors to blocking mode\n"
#endif /* WIN32 */
          "\t-l  Logging, dump sent and received data into a file\n"
          "\t-i  Use other internal function for writing\n"
          "\t-t  Use fwrite() instead of write()\n"
          "\t-f  Report only first error\n", program);
  exit(0);
}

void describe_situation(void)
{
  D(("\nUsed:\t"));

  if (blocking)
    D(("blocking"));
  else
    D(("non-blocking"));
  D((" streams using "));

  if (internal)
    {
      if (trip_start)
        D(("fwrite()"));
      else
        D(("write()"));

      D((" in my_ssh_debug()"));
    }
  else
    D(("fwrite() in ssh_debug()"));

  D(("\nStats:\t%d/%d received - %4.1f per cent lossage\n", received,
     iterations, (iterations - received) * 100.0 / iterations));
  D(("Result:\t%s\n", (retval != 0 ? "FAIL" : "PASS")));

  D(("\n"));
}

int main(int argc, char **argv)
{
  const char *debug_level = "Sgw*=5";
  SshMutex mutex;
  int option;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((option = ssh_getopt(argc, argv, "as:ld:nitf", NULL)) != -1)
    {
      switch (option)
        {
        case 'a': reportinterval = 1; break;
        case 'd': debug_level = ssh_optarg; break;
        case 's': iterations = atoi(ssh_optarg);
                  reportinterval = iterations / 10; break;
        case 'l': logging = 1; break;
        case 'n': blocking = 1; break;
        case 'i': internal = 1; break;
        case 't': trip_start = 1; break;
        case 'f': firsterror = 1; break;
        case '?':
          usage();
          break;
        }
    }
  if (argc - ssh_optind > 1)
    usage();

  ssh_event_loop_initialize();
  ssh_debug_set_level_string(debug_level);

  if (pipe(testpipe) == -1)
    {
      fprintf(stderr, "Creating pipe(2) failed.\n");
      exit(-1);
    }

  debug_mutex = ssh_mutex_create("Debug", 0);
  if (!debug_mutex)
    ssh_fatal("Cannot create mutex");

  D(("Calling timeout init\n"));
  ssh_threaded_timeouts_init();

  D(("Creating test mutex 1\n"));
  mutex = ssh_mutex_create("Test 1", 0);
  if (!mutex)
    ssh_fatal("Cannot create mutex");

  D(("Locking test mutex 1\n"));
  ssh_mutex_lock(mutex);
  D(("Unlocking test mutex 1\n"));
  ssh_mutex_unlock(mutex);
  D(("Getting name test mutex 1\n"));
  if (strcmp(ssh_mutex_get_name(mutex), "Test 1") != 0)
    ssh_fatal("get name failed");
  D(("Destroying test mutex 1\n"));
  ssh_mutex_destroy(mutex);

  D(("Creating lock 1 and 2\n"));
  mutex1 = ssh_mutex_create("Lock 1", 0);
  mutex1_start = ssh_mutex_create("Start lock 1", 0);
  mutex2 = ssh_mutex_create("Lock 2", 0);
  mutex2_start = ssh_mutex_create("Start lock 2", 0);

  if (!mutex1 || !mutex1_start || !mutex2 || !mutex2_start)
    ssh_fatal("Cannot create mutex");

  D(("Locking start lock 1 and 2\n"));
  ssh_mutex_lock(mutex1_start);
  ssh_mutex_lock(mutex2_start);

  fflush(stdout);
  fflush(stderr);

  if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
    D(("Incorrect type or size of buffer for stdout\n"));
  else
    D(("stdout now has no buffer\n"));

  D(("Forking thread 1\n"));
  thread1 = fork_thread(func1, NULL);
  D(("Forking thread 2\n"));
  thread2 = fork_thread(func2, NULL);
  threads = 2;

  D(("Registering timeouts\n"));
  ssh_xregister_timeout(0, 10000000, check_for_threads, NULL);
  ssh_xregister_timeout(0, 1000000, start_program_w, NULL);

  D(("Staring event loop\n\n"));
  ssh_event_loop_run();
  D(("\nEvent loop run returned\n"));

  ssh_cancel_timeouts(check_for_threads, SSH_ALL_CONTEXTS);

  D(("Destroying mutex 1 and 2\n"));
  ssh_mutex_destroy(mutex1);
  ssh_mutex_destroy(mutex1_start);
  ssh_mutex_destroy(mutex2);
  ssh_mutex_destroy(mutex2_start);

  describe_situation();

  /*
  D(("Closing pipe ends\n"));
  close(testpipe[0]);
  */

  if (logging)
    {
      D(("Closing logs\n"));
      if (in)
        fclose(in);
      if (out)
        fclose(out);
    }

  D(("Cancel timeouts\n"));
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);

  D(("Destroying debug_mutex\n"));
  ssh_mutex_destroy(debug_mutex);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  exit(retval);
}

#else  /* HAVE_THREADS */
int main(int argc, char **argv)
{
  printf("No thread support included, testing ignored\n");
  return 0;
}
#endif /* HAVE_THREADS */
