/*
 *
 * ubenchmark-multiport.c
 *
 *
 *  Copyright:
 *          Copyright (c) 2002-2007 SFNT Finland Oy.
 *               All rights reserved.
 *
 * UDP benchmark with support for sending on multiple ports. This program 
 * does not support autotuning to determine the optimal sending rate.
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshgetopt.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshUBenchmarkMulti"

static char *program;

static int current_port;

static int start_port = 18010;
static char start_port_buf[64];
static int end_port = 18011;
static char end_port_buf[64];
static size_t data_len = 512;
static long timeout = 100;
static SshUInt32 num_packets_per_send = 1;

static Boolean flood = FALSE;
static Boolean receive = FALSE;
static Boolean starting = TRUE;


static SshUdpListener listener;
static unsigned char data[65536];

static SshUInt32 run_time = 0;

/* Send and receive state. */
static SshUInt32 start_time = 0;
static SshUInt32 current_time = 0;
static SshUInt32 sequence_number = 0;

static SshUInt32 num_packets_sent = 0;
static SshUInt32 total_received_packets = 0;
static SshUInt32 total_received_bytes = 0;

static char *source = "0.0.0.0";
static char *destination = { "127.0.0.1" };

static SshUInt32 min_sequence_number = { 0 };
static SshUInt32 max_sequence_number = { 0 };
static SshUInt32 received_packets = { 0 };
static SshUInt32 lost_packets = { 0 };
static SshUInt32 sent_packets = { 0 };

#define MAX_PORTS 2000
static char portbuf[MAX_PORTS][64];

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]...\n\
  -c SOURCE             Local IP address.\n\
  -d DESTINATION        Remote IP addresses.\n\
  -h                    print this help and exit.\n\
  -l LENTH              UDP datagram length excluding headers.\n\
  -f                    flood with as many packets as possible.\n\
  -N NUM_PACKETS        Number of packets per send.\n\
  -s START_PORT         Start of the port range (inclusive).\n\
  -e END_PORT           End of the ort range (exclusive).\n\
  -r                    Receive (the default is to send).\n\
  -D DEBUG              Debug level.\n\
  -T TIME               Run time of the program in seconds.\n\
  -t TIMEOUT            Timeout in microseconds between packet sends.\n", 
	  program);
}


static void
udp_callback(SshUdpListener listener, void *context)
{
  while (1)
    {
      size_t datagram_len;
      SshUdpError error;

      error = ssh_udp_read(listener, NULL, 0, NULL, 0, data, sizeof(data),
                           &datagram_len);
      if (error == SSH_UDP_NO_DATA)
        {
          break;
        }
      else if (error == SSH_UDP_OK)
        {
          SshUInt32 time;

          if (ssh_decode_array(data, datagram_len,
                               SSH_FORMAT_UINT32, &sequence_number,
                               SSH_FORMAT_END) == 0)
            {
              fprintf(stderr, "%s: Truncated datagram", program);
              continue;
            }

          if (starting || sequence_number == 0)
            {
	    starting:
	      starting = FALSE;
	      
              printf("\n");
              printf("Time\tNum of\tPacket\tPacket\t"
                     " Current\n");
              printf("\tpckts\tSize\tloss%%\t10^6 bits/s\n");
              printf("\
----------------------------------------------------------------------\n");

	      /* Wait until a full second has elapsed */
	      start_time = ssh_time();
	      while (ssh_time() == start_time)
		; 

	      /* Reset */
              current_time = start_time = ssh_time();
	      return;
            }

          if (sequence_number < min_sequence_number)
            min_sequence_number = sequence_number;

          if (sequence_number > max_sequence_number)
            max_sequence_number = sequence_number;

	  received_packets++;
	  total_received_packets++;
	  total_received_bytes += datagram_len;

	  time = ssh_time();

          if (time > current_time)
	    {
	      SshUInt32 total_sent_packets = 0;
	      float packet_loss;
	  	      
	      /* If this happens, one of the senders has stopped. */
	      if (min_sequence_number > max_sequence_number)
		{
		  min_sequence_number = max_sequence_number = 0;
		  goto starting;
		}
	      
	      sent_packets = max_sequence_number - 
		min_sequence_number;
	      
	      if (sent_packets < received_packets)
		sent_packets = received_packets;
	      
	      lost_packets = sent_packets - received_packets;
	      total_sent_packets += sent_packets;
	      
	      /* Reset the counters */
	      received_packets = 0;
	      min_sequence_number = max_sequence_number; 
	      max_sequence_number = 0; 
	  
	      packet_loss = total_sent_packets ? 
		((float) (total_sent_packets - total_received_packets)
		/ (float) (total_sent_packets)) * 100.0 : 0.0;

	      /* Current is valid. */
	      printf("%d\t%d\t%d\t%.2f\t%-7.3f\n",
		     (int)(current_time - start_time), 
		     (int)total_received_packets,
		     (int)datagram_len,
		     packet_loss,
		     ((total_received_bytes / 1000.0) * 8 ) / 1000.0);
	      fflush(stdout);

	      /* Reset the counters. */
	      total_received_packets = 0;
	      total_received_bytes = 0;
	      current_time = ssh_time();
	    }
	}
      else
	{
	  fprintf(stderr, "%s: UDP read failed %s\n", program,
		  ssh_udp_error_string(error));
	}
    }
}

static void
send_data(void *context)
{
  SshUdpListener listener = (SshUdpListener) context;
  SshUInt32 time;
  int i, indx;

  SSH_ASSERT(listener != NULL);

  if (current_time == 0) 
    start_time = ssh_time();
  
 start:
  time = ssh_time();
  
  if (time != current_time)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Sent %d packets", num_packets_sent));
      num_packets_sent = 0;
      current_time = time;
    }

  for (i = 0; i < num_packets_per_send; i++)
    {
      ssh_encode_array(data, sizeof(data),
		       SSH_FORMAT_UINT32, sequence_number++,
		       SSH_FORMAT_END);

      indx = current_port - start_port;
      
      ssh_udp_send(listener, destination, portbuf[indx], 
		   data, data_len);

      current_port++;
      if (current_port >= end_port)
	current_port = start_port;

      num_packets_sent++;
    }

  SSH_ASSERT(timeout >= 0);
  
  /* Don't allow the sequence number to wrap. */
  if (sequence_number == 0)
    exit(0);

  if (run_time > 0 && current_time - start_time > run_time) 
    exit(0);

  if (flood)
    goto start; 
  else  
    ssh_xregister_timeout(0, timeout, send_data, listener);
}

#ifdef VXWORKS
#undef main
#define main ubmain
#endif /* VXWORKS */


int
main(int argc, char *argv[])
{
  SshUdpListenerParamsStruct udp_params;
  char buf[256];
  char *remote;
  int port, opt;

  remote = NULL;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  while ((opt = ssh_getopt(argc, argv, "a:D:c:d:hfl:nN:s:e:S:E:rt:u:T:", 
			   NULL)) 
	 != EOF)
    {
      switch (opt)
        {
        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'd':
          remote = ssh_xstrdup(ssh_optarg);
          break;

        case 'c':
          source = ssh_xstrdup(ssh_optarg);
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'f':
          flood = TRUE;
          break;

        case 'l':
          data_len = atoi(ssh_optarg);

	  if (data_len < 8)
	    {
	      fprintf(stderr, 
		      "The datagram length must be at least 8 bytes.\n");
	      usage();
	      exit(1);
	    }

          break;

        case 'N':
          num_packets_per_send = atoi(ssh_optarg);
          break;

        case 's':
          start_port = atoi(ssh_optarg);
          break;

        case 'e':
          end_port = atoi(ssh_optarg);
          break;

        case 'r':
          receive = TRUE;
          break;

        case 't':
          timeout = atoi(ssh_optarg);
          break;

        case 'T':
          run_time = atoi(ssh_optarg);
          break;
        }
    }

  if (ssh_optind < argc)
    {
      fprintf(stderr, "%s: Junk at the end of command line\n",
              program);
      usage();
      exit(1);
    }

  /* Parse the remote IP addresses */
  if (!receive)
    { 
      if (!remote)
	{
	  usage();
	  exit(1);
	}
      if (strchr(remote, ','))
  	ssh_fatal("Only one destination address can be specified for the "
		  "sender (%s)\n", remote);
      else 
	destination = remote;
    }

  ssh_snprintf(start_port_buf, sizeof(start_port_buf), "%d", 
	       start_port);
  ssh_snprintf(end_port_buf, sizeof(end_port_buf), "%d", 
	       end_port);  

#ifndef VXWORKS
  ssh_event_loop_initialize();
#endif /* VXWORKS */

  if (end_port <= start_port)
    {
      fprintf(stderr, "%s: Port range is empty: [%d...%d[\n",
	      program, start_port, end_port);
      exit(1);
    }
  current_port = start_port;  


  if (receive)
    {
      /* Create listeners. */
      for (port = start_port; port < end_port; port++)
	{
	  char *name;
	  
	  ssh_snprintf(buf, sizeof(buf), "%d", port);
	  name = ssh_xstrdup(buf);

	  listener = ssh_udp_make_listener(source, buf, NULL, NULL, NULL, 
					   udp_callback, name);
	  
	  if (listener == NULL)
	    {
	      fprintf(stderr, "%s: Cannot create UDP listener for port %s\n",
		      program, buf);
	      exit(1);
	    }
	}

      printf("%s: Receiver running between ports %d and %d\n", 
	     program, start_port, end_port);
    }
  else
    {
      memset(&udp_params, 0, sizeof(udp_params));
      udp_params.broadcasting = TRUE;

      listener = ssh_udp_make_listener(source, NULL, 
				       NULL, NULL,
				       &udp_params, 
				       NULL, NULL);
      if (listener == NULL)
	{
	  fprintf(stderr, "%s: Could not make UDP listener for %s:%s\n",
		  program, source, start_port_buf);
	  exit(1);
	}
      
      fprintf(stderr, "%s: Sending data traffic from port %d to port %d\n", 
	      program, start_port, end_port);
      
      fflush(stdout);
      start_time = ssh_time();

      if (end_port - start_port > MAX_PORTS)
	{
	  fprintf(stderr, "%s: Too many ports, increase the value of "
		  "MAX_PORTS (%d)\n", program, MAX_PORTS);
	  exit(1);
	}

      for (port = start_port; port < end_port; port++)
	{
	  int i = port - start_port;

	  ssh_snprintf(portbuf[i], sizeof(portbuf[i]), "%d", port);
	}      


      ssh_xregister_timeout(0, 0, send_data, listener);
    }
  
#ifndef VXWORKS
  ssh_event_loop_run();
#endif /* VXWORKS */
  return 0;
}


#ifdef VXWORKS
void ssh_eloop_start(int argc, 
                     int argv, 
                     int arg3, 
                     int arg4, 
                     int arg5, 
                     int arg6, 
                     int arg7, 
                     int arg8, 
                     int arg9, 
                     int arg10)
{
  ssh_event_loop_initialize();
  
  ubmain(argc, (char **)argv);
  
  ssh_event_loop_run();  

  ssh_free((void *)argv);
}

int ubenchmark(char *input, int alone)
{
  char *prog = "ubenchmark-multi ";
  int tblsize = 0, argsize = 0, inputsize = 0, prgsize = 0;
  char *s1;
  char *s2;
  int argc = 0;
  char *argv = NULL;

  /* allocate space for both the table and the arguments */
  if (input)
    inputsize = strlen(input);
  if (prog)
    prgsize = strlen(prog);
  tblsize = ((inputsize >> 1) + 2) * sizeof(char *);
  argsize = prgsize + inputsize + 1;
  argv = ssh_calloc(tblsize + argsize, 1);
  memcpy(argv + tblsize, prog, prgsize);
  memcpy(argv + tblsize + prgsize, input, inputsize);
  
  /* Parse args  */
  s1 = argv + tblsize;

  for (;;)
    {
      while (*s1 == ' ')
        s1++;
      if (!*s1)
        break;
      
      s2 = s1;
      
      while (*s2 != '\0' && *s2 != ' ')
        s2++;
      
      *((char **)argv + argc) = (char *)s1;
      argc++;

      if (!*s2)
        break;
      
      *s2 = '\0';
      s2++;
      s1 = s2;
    }

  if (!alone)
    ubmain(argc, (char **)argv);
  else 
    taskSpawn("tUbenchMulti", 10, 0, 32768,
              (FUNCPTR)ssh_eloop_start, 
              (int)argc, 
              (int)argv, 
              0, 0, 0, 0, 0, 0, 0, 0);

  return 0;
}
#endif /* VXWORKS */


