/*
 *
 * udp-send.c
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2005 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Send UDP datagrams to different addresses and ports.
 *
 */

#include "sshincludes.h"

#ifdef SSHDIST_APPS_PERFUTILS

#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshgetopt.h"

static char *program;

static char *destination = NULL;
static int remote_start_port = 6000;
static int remote_end_port = 6001;
static int remote_port;
static int sleep_microsecs = 50000;
static int quiet = 0;
static int loop = 0;
static size_t data_length = 0;

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... DESTINATION\n\
  -h                    print this help and exit\n\
  -L LENGTH             length of the datagram\n\
  -s REMOTE_START_PORT  start of the remote port range (inclusive)\n\
  -e REMOTE_END_PORT    end of the remote port range (exclusive)\n\
  -t TIMEOUT            timeout (microsecs) between packet sends\n\
  -q                    be really quiet\n\
  -l                    loop infinitely\n\
",
         program);

  fprintf(stdout, "\nReport bugs to mtr@ssh.fi.\n");
}

static void
run(void *context)
{
  char buf[256];
  SshUdpListener listener = (SshUdpListener) context;
  static SshUInt32 packet_count = 0;
  char data[65536];

  if (remote_port >= remote_end_port)
    {
      if (!loop)
        {
          /* All done. */
          if (!quiet)
            printf("\n");

          ssh_udp_destroy_listener(listener);
          return;
        }

      remote_port = remote_start_port;
      if (!quiet)
        printf("\n");
    }

  ssh_snprintf(buf, sizeof(buf), "%d", remote_port++);

  if (data_length)
    {
      size_t i;

      for (i = 0; i < data_length; i++)
        data[i] = (char) i;

      ssh_udp_send(listener, destination, buf, data, data_length);
    }
  else
    {
      ssh_snprintf(data, sizeof(data),
                   "%s %d Hello, world!", buf, packet_count++);
      ssh_udp_send(listener, destination, buf,
                   data, strlen(data));
    }

  if (!quiet)
    {
      printf(".");
      fflush(stdout);
    }

  ssh_xregister_timeout(0, sleep_microsecs, run, listener);
}

int
main(int argc, char *argv[])
{
  SshUdpListener listener;
  int opt;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  while ((opt = ssh_getopt(argc, argv, "hL:s:e:t:ql", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'h':
          usage();
          exit(0);
          break;

        case 'L':
          data_length = atoi(ssh_optarg);
          break;

        case 's':
          remote_start_port = atoi(ssh_optarg);
          break;

        case 'e':
          remote_end_port = atoi(ssh_optarg);
          break;

        case 't':
          sleep_microsecs = atoi(ssh_optarg);
          break;

        case 'q':
          quiet = 1;
          break;

        case 'l':
          loop = 1;
          break;
        }
    }

  /* Sanity checks for arguments. */

  /* Destination address. */
  if (ssh_optind >= argc)
    {
      fprintf(stderr, "%s: No destination IP address specified\n",
              program);
      usage();
      exit(1);
    }
  destination = argv[ssh_optind++];

  /* Sanity check for the remote port range. */
  if (remote_end_port <= remote_start_port)
    {
      fprintf(stderr, "%s: Remote port range is empty: [%d...%d[\n",
              program, remote_start_port, remote_end_port);
      exit(1);
    }
  remote_port = remote_start_port;

  ssh_event_loop_initialize();
  listener = ssh_udp_make_listener(SSH_IPADDR_ANY, "8080", NULL, NULL,
                                   NULL, NULL, NULL);
  ssh_xregister_timeout(0, 0, run, listener);

  ssh_event_loop_run();

  ssh_event_loop_uninitialize();

  return 0;
}
#else /* SSHDIST_APPS_PERFUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_PERFUTILS */
