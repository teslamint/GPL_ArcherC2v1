/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Mon Sep 15 18:49:44 1997 [ttsalo]

  Udp socket wrapper tests

  */

#include "sshincludes.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#ifdef SSHDIST_UTIL_TCP
#include "sshnameserver.h"
#endif /* SSHDIST_UTIL_TCP */

SshUdpListener c_listener, p_listener;
unsigned char c_data[256];
unsigned char p_data[] = "DEADBEEF foobaz";
unsigned char p2_data[256];

void p_timeout_callback(void *context)
{
  ssh_udp_send(p_listener, "127.0.0.1", "54678",
               p_data, strlen((char *) p_data));
}

void p_callback(SshUdpListener listener, void *context)
{
  size_t received;
  char remote_address[256];
  char remote_port[16];
  SshUdpError error;

  error = ssh_udp_read(listener, remote_address, 256,
                       remote_port, 16,
                       p2_data, 256, &received);
  ssh_udp_destroy_listener(listener);

  if (memcmp(p_data, p2_data, strlen((char *) p_data)))
    {
      printf("Test failed (failure to communicate)\n");
      exit(1);
    }
}

void c_callback(SshUdpListener listener, void *context)
{
  char remote_address[256];
  char remote_port[16];
  size_t received;
  SshUdpError error;

  error = ssh_udp_read(listener, remote_address, 256,
                       remote_port, 16,
                       c_data, 256, &received);
  ssh_udp_send(listener, "127.0.0.1", "54321",
               c_data, strlen((char *) c_data));
  ssh_udp_destroy_listener(listener);
}

void c(void)
{
  ssh_event_loop_initialize();
  c_listener = ssh_udp_make_listener("127.0.0.1", "54678", NULL, NULL, NULL,
                                     c_callback, NULL);
  if (c_listener == NULL)
    {
      printf("Listener creation failed.\n");
      exit(1);
    }

  ssh_event_loop_run();
  ssh_debug("child exiting...");
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */
  ssh_event_loop_uninitialize();
}

void p(void)
{
  ssh_event_loop_initialize();

  p_listener = ssh_udp_make_listener(SSH_IPADDR_ANY_IPV4, "54321", NULL, NULL,
                                     NULL, p_callback, NULL);

  if (p_listener == NULL)
    {
      printf("Listener creation failed.\n");
      exit(1);
    }
  ssh_xregister_timeout(2, 0, p_timeout_callback, NULL);
  ssh_event_loop_run();
  ssh_debug("parent exiting...");
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */
  ssh_event_loop_uninitialize();
}

void usage(void)
{
  fprintf(stderr, "Usage: t-udp [-c|-p]\n");
}

int main(int argc, char **argv)
{
  pid_t pid, pid2;

  memset(c_data, 0, 256);
  memset(p2_data, 0, 256);

  /* In the actual test, the parent will send bytes to the
     child, child will mirror them back and parent will check
     that it got the same bytes back. */

  if (argc == 2)
    {
      if (argv[1][0] == '-' && argv[1][1] == 'c')
        {
          c();
          exit(0);
        }
      else if (argv[1][0] == '-' && argv[1][1] == 'p')
        {
          p();
          exit(0);
        }
      else
        {
          usage();
          exit(1);
        }
    }
  if (argc != 1)
    {
      usage();
      exit(1);
    }

  pid = fork();
  if (pid == 0)
    {
      c();
      sleep(2);
      exit(0);
    }
  else
    {
      int status;

      p();
#ifdef HAVE_WAITPID
      while ((pid2 = waitpid(pid, &status, 0)) < 0)
        if (errno != EINTR)
          break;
#else /* HAVE_WAITPID */
      pid2 = wait(&status);
#endif /* HAVE_WAITPID */
      if (pid2 != pid)
        {
          ssh_fatal("Wrong pid returned by wait, %d vs %d", pid, pid2);
        }
      if (WIFSIGNALED(status))
        {
          ssh_fatal("Child exited with signal %d", WTERMSIG(status));
        }
      if (WEXITSTATUS(status) != 0)
        {
          ssh_fatal("Child exited with status %d", WEXITSTATUS(status));
        }
    }

  ssh_util_uninit();
  exit(0);
}
