/*
 *
 * udp-recv.c
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2005 SFNT Finland Oy.
 *               All rights reserved.
 *
 *
 * Receive UDP datagrams from one or many UDP ports.
 *
 */

#include "sshincludes.h"

#ifdef SSHDIST_APPS_PERFUTILS

#include "ssheloop.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshgetopt.h"

static char *program;

static const char *addr = NULL;
static int local_start_port = 6000;
static int local_end_port = 6001;
static int quiet = 0;

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... [LISTEN_ADDRESS]\n\
  -h                    print this help and exit\n\
  -s LOCAL_START_PORT   start of the local port range (inclusive)\n\
  -e LOCAL_END_PORT     end of the local port range (exclusive)\n\
  -q                    be really quiet\n\
",
          program);

  fprintf(stdout, "\nReport bugs to mtr@ssh.fi.\n");
}


static void
udp_callback(SshUdpListener listener, void *context)
{
  char *name = (char *) context;

  while (1)
    {
      unsigned char buf[65536];
      size_t datagram_len;
      SshUdpError error;

      error = ssh_udp_read(listener, NULL, 0, NULL, 0, buf, sizeof(buf),
                           &datagram_len);
      if (error == SSH_UDP_NO_DATA)
        break;
      else if (error == SSH_UDP_OK)
        {
          if (!quiet)
            fprintf(stdout, "%s:%s: %.*s\n", program, name,
                    (int) datagram_len, buf);
        }
      else
        {
          fprintf(stderr, "%s:%s: UDP read failed %s\n",
                  program, name, ssh_udp_error_string(error));
        }
    }

}


int
main(int argc, char *argv[])
{
  int opt;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  while ((opt = ssh_getopt(argc, argv, "hs:e:q", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'h':
          usage();
          exit(0);
          break;

        case 's':
          local_start_port = atoi(ssh_optarg);
          break;

        case 'e':
          local_end_port = atoi(ssh_optarg);
          break;

        case 'q':
          quiet = 1;
          break;
        }
    }

  addr = SSH_IPADDR_ANY;

  if (ssh_optind < argc)
    {
      addr = argv[ssh_optind++];
    }

  /* Sanity checks for arguments. */
  if (ssh_optind < argc)
    {
      fprintf(stderr, "%s: Junk at the end of command line\n",
              program);
      usage();
      exit(1);
    }

  /* Local port range. */
  if (local_end_port <= local_start_port)
    {
      fprintf(stderr, "%s: Local port range is empty: [%d...%d[\n",
              program, local_start_port, local_end_port);
      exit(1);
    }

  ssh_event_loop_initialize();

  /* Create listeners. */
  for (; local_start_port < local_end_port; local_start_port++)
    {
      char buf[256];
      char *name;

      ssh_snprintf(buf, sizeof(buf), "%d", local_start_port);
      name = ssh_xstrdup(buf);

      if (ssh_udp_make_listener(addr, buf, NULL, NULL, NULL, 
				udp_callback, name)
          == NULL)
        {
          fprintf(stderr, "%s: Could not create UDP listener %s:%s\n",
                  program, addr, buf);
          exit(1);
        }
    }

  ssh_event_loop_run();

  return 0;
}
#else /* SSHDIST_APPS_PERFUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_PERFUTILS */
