/*
 *
 * ubenchmark.c
 *
 *
 *  Copyright:
 *          Copyright (c) 2002-2007 SFNT Finland Oy.
 *               All rights reserved.
 *
 * UDP benchmark with autotuning for optimial sending rate.
 *
 */

#include "sshincludes.h"

#ifdef SSHDIST_APPS_PERFUTILS

#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshgetopt.h"
#include "sshencode.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "SshUBenchmark"

char *ubench_program;

SshInt32 run_time = 0;
int ubench_opt_quiet = 0;
SshUInt16 ubench_control_listener_port = 18009;
SshUInt16 ubench_port = 18010;

size_t ubench_data_len = 512;

long ubench_timeout = 100;
long ubench_prev_timeout = 100;
long ubench_last_fail_timeout = 100;
long ubench_last_work_timeout = 100;

SshUInt32 ubench_num_packets_per_send = 1;
SshUInt32 ubench_prev_num_packets_per_send = 1;
SshUInt32 ubench_last_fail_num_packets_per_send = 1;
SshUInt32 ubench_last_work_num_packets_per_send = 1;

double ubench_acceptence = 1.0;
Boolean ubench_flood = FALSE;

SshUdpListener ubench_control_listener;
SshUdpListener ubench_sender_listener;
unsigned char ubench_data[65536];

SshUInt32 ubench_current_sequence_number = 0;

SshIpAddrStruct ubench_destination;

Boolean disable_autotune = FALSE;

typedef enum {
  UBENCH_SEARCHING_N_FAST,
  UBENCH_SEARCHING_N_MEDIUM,
  UBENCH_SEARCHING_N_SLOW,
  UBENCH_SEARCHING_N_VERY_SLOW,
  UBENCH_SEARCHING_T_FAST,
  UBENCH_SEARCHING_T_MEDIUM,
  UBENCH_SEARCHING_T_SLOW,
  UBENCH_SEARCHING_T_VERY_SLOW
} SshUBenchState;

const char *ubench_state_names[] = {
  "fast n", "medium n", "slow n", "very slow n", 
  "fast t", "medium t", "slow t", "very slow t"
};

SshUBenchState ubench_state = UBENCH_SEARCHING_N_FAST;

SshInt64 ubench_max_speed = 0;
SshInt64 ubench_max_pps = 0;

/* Statistics */
SshInt64 ubench_total_received_packets = 0;
SshInt64 ubench_total_received_bytes = 0;
SshTimeMeasureStruct ubench_timer[1];
int ubench_print_header;	/* When this reaches to 0 print header */
long ubench_current_tick;

/* Statistics per sender. */
typedef struct SshUBenchmarkStatsRec {
  SshUdpListener listener;
  SshUInt32 sender;
  SshUInt32 port;
  SshUInt32 min_sequence_number;
  SshUInt32 max_sequence_number;
  SshUInt32 received_packets;
  SshUInt32 datagram_len;
} *SshUBenchmarkStats, SshUBenchmarkStatsStruct;

SshUBenchmarkStatsStruct ubench_stats;

void do_exit(void *context);

void
ubench_usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]...\n\
  -c SOURCE             Local IP address.\n\
  -C CONTROL_PORT       Control listener port.\n\
  -d DESTINATION        Remote IP address. \n\
  -h                    print this help and exit.\n\
  -l LENTH              UDP datagram length excluding headers.\n\
  -f                    flood with as many packets as possible.\n\
  -N NUM_PACKETS        Number of packets per send.\n\
  -p PORT               Port.\n\
  -a ACCEPTENCE LEVEL   Accepted packet loss in percentages.\n\
  -r                    Receive (the default is to send).\n\
  -q                    Quiet, do not print intermediate results\n\
  -D DEBUG              Debug level.\n\
  -T TIME               Run time of the program in seconds, if negative.\n\
                        then it is time run after the done state is reached.\n\
  -t TIMEOUT            Timeout in microseconds between packet sends.\n\
  -A                    Disable autotune.\n",
	  ubench_program);
}

void
ubench_udp_callback(SshUdpListener listener, void *context)
{
  SshUBenchmarkStats stats = context;
  SshUInt32 sequence_number;
  SshIpAddr addr;

  if (!ssh_time_measure_running(ubench_timer))
    ssh_time_measure_start(ubench_timer);

  addr = NULL;
  if (!SSH_IP_DEFINED(&ubench_destination))
    {
      addr = &ubench_destination;
    }

  while (1)
    {
      size_t datagram_len;
      SshUdpError error;

      error = ssh_udp_read_ip(listener,
			      addr, NULL,
			      ubench_data, sizeof(ubench_data),
			      &datagram_len);
      if (error == SSH_UDP_NO_DATA)
        {
          break;
        }
      else if (error == SSH_UDP_OK)
        {
	  if (datagram_len < 4)
	    {
              ssh_warning("%s: Truncated datagram", ubench_program);
              continue;
	    }
	  sequence_number = SSH_GET_32BIT(ubench_data);

          if (sequence_number == 0 || datagram_len != stats->datagram_len)
            {
	      stats->min_sequence_number = sequence_number;
	      stats->max_sequence_number = sequence_number;
	      stats->datagram_len = datagram_len;
	      stats->received_packets = 0;
            }

          if (sequence_number < stats->min_sequence_number)
            stats->min_sequence_number = sequence_number;

          if (sequence_number > stats->max_sequence_number)
            stats->max_sequence_number = sequence_number;

	  stats->received_packets++;
	  ubench_total_received_packets++;
	  ubench_total_received_bytes += datagram_len;
	}
      else
	{
	  ssh_warning("%s: UDP read failed %s", ubench_program,
		      ssh_udp_error_string(error));
	}
    }
}

void ubench_print_statistics(void *context)
{
  SshInt64 total_sent_packets = 0;
  SshUInt32 sent_packets, lost_packets;
  double packet_loss, speed, pps;
  SshUInt32 datagram_len;
  SshTimeT current_time;

  datagram_len = ubench_stats.datagram_len;
  ssh_time_measure_stop(ubench_timer);

  current_time = ssh_time_measure_get(ubench_timer,
				      SSH_TIME_GRANULARITY_MILLISECOND);

  if (ubench_stats.max_sequence_number <
      ubench_stats.min_sequence_number)
    {
      /* Wrapped, restart. */
      ubench_stats.datagram_len = 0;
    }
  else
    {
      sent_packets = ubench_stats.max_sequence_number -
	ubench_stats.min_sequence_number;
      if (sent_packets < ubench_stats.received_packets)
	sent_packets = ubench_stats.received_packets;
      if (datagram_len != ubench_stats.datagram_len)
	datagram_len = 0;
      total_sent_packets += sent_packets;
    }
  
  packet_loss = total_sent_packets ? 
    ((double) (total_sent_packets - ubench_total_received_packets)
     / (double) (total_sent_packets)) * 100.0 : 0.0;
  if (current_time != 0.0)
    {
      speed = (((double) ubench_total_received_bytes /
		current_time / 1000.0) * 8.0);
      pps = (double) ubench_total_received_packets / current_time * 1000.0;
    }
  else
    {
      speed = 0.0;
      pps = 0.0;
    }

  if (!ubench_opt_quiet)
    {
      if (ubench_total_received_packets != 0)
	{
	  if (ubench_print_header == 0)
	    {
	      printf("\n");
	      printf("Time\tNum of\tPacket\tPacket\t"
		     " Current\n");
	      printf("\tpckts\tSize\tloss%%\t10^6 bits/s\n");
	      printf("\
----------------------------------------------------------------------\n");
	      ubench_print_header = 20;
	    }
	  /* Current is valid. */
	  printf("%ld\t%ld\t%ld\t%.2f\t%-7.3f\n",
		 ubench_current_tick++,
		 (long) pps,
		 (long) datagram_len,
		 packet_loss,
		 speed);
	  fflush(stdout);
	  ubench_print_header--;
	}
      else
	{
	  ubench_print_header = 0;
	  ubench_current_tick = 0;
	}
    }

  if (ubench_stats.datagram_len != 0 &&
      ubench_stats.received_packets != 0)
    {
      sent_packets = ubench_stats.max_sequence_number -
	ubench_stats.min_sequence_number;
      if (sent_packets < ubench_stats.received_packets)
	sent_packets = ubench_stats.received_packets;
      lost_packets = sent_packets - ubench_stats.received_packets;
      ssh_encode_array(ubench_data, sizeof(ubench_data),
		       SSH_FORMAT_UINT32,
		       lost_packets,
		       SSH_FORMAT_UINT32,
		       ubench_stats.received_packets,
		       SSH_FORMAT_UINT32,
		       sent_packets,
		       SSH_FORMAT_UINT64,
		       (SshUInt64) current_time,
		       SSH_FORMAT_UINT64,
		       (SshUInt64) pps,
		       SSH_FORMAT_UINT64,
		       (SshUInt64) (packet_loss * 100.0),
		       SSH_FORMAT_UINT64,
		       (SshUInt64) (speed * 1000.0),
		       SSH_FORMAT_UINT32, datagram_len,
		       SSH_FORMAT_END);  
      ssh_udp_send_ip(ubench_control_listener,
		      &ubench_destination,
		      ubench_control_listener_port, ubench_data, 64);
      
      /* Reset the counters */
      ubench_stats.received_packets = 0;
      ubench_stats.min_sequence_number =
	ubench_stats.max_sequence_number; 
    }

  ssh_time_measure_reset(ubench_timer);
  if (ubench_total_received_packets != 0)
    ssh_time_measure_start(ubench_timer);

  /* Reset the counters. */
  ubench_total_received_packets = 0;
  ubench_total_received_bytes = 0;
  ssh_xregister_timeout(1, 0, ubench_print_statistics, NULL);
}

void
ubench_send_data(void *context)
{
  SshUdpListener listener = (SshUdpListener) context;
  int i;

 start:
  for (i = 0; i < ubench_num_packets_per_send; i++)
    {
      SSH_PUT_32BIT(ubench_data, ubench_current_sequence_number);
      ssh_udp_send_ip(listener, &ubench_destination, ubench_port, 
		      ubench_data, ubench_data_len);
      ubench_current_sequence_number++;
    }
  
  /* Don't allow the sequence number to wrap. */
  if (ubench_current_sequence_number == 0)
    exit(0);

  if (ubench_flood)
    goto start; 
  else  
    ssh_xregister_timeout(0, ubench_timeout, ubench_send_data, listener);
}

void ubench_tune_params(double packet_loss, 
			double speed)
{
  /* Currently the search for optimial (N,t) values is done
     by finding a possible (N,t) pair such that the packet
     loss is below 1%. Another option is to search for the
     maximum value of received packets. It may be possible
     that the maximum number of received packets occurs at a
     (N,t) pair where there is significant packet loss. The
     current approach is best if we want to demonstrate
     consistent packet throughput over a (hopefully) long
     period of time with minimal packet loss. The
     alternative (maximizing the number of received packets)
     is better if we just want ubenchmark to emit a single
     number as the maximum packet throughput. */

  if (disable_autotune == TRUE)
    return;
  
  SSH_DEBUG(SSH_D_MIDOK, ("Old values for (N, t) = (%d %d)", 
			  ubench_num_packets_per_send,
			  ubench_timeout));
  if (packet_loss > ubench_acceptence)
    {
      /* Lost too much packets, fall back to prev values,
	 and retry in the next state. */
      ubench_last_fail_num_packets_per_send = ubench_num_packets_per_send;
      ubench_last_fail_timeout = ubench_timeout;

      ubench_num_packets_per_send = ubench_prev_num_packets_per_send;
      ubench_timeout = ubench_prev_timeout;

      ubench_prev_timeout++;
      ubench_state++;
    }
  else
    {
      ubench_last_work_num_packets_per_send = ubench_num_packets_per_send;
      ubench_last_work_timeout = ubench_timeout;

      ubench_prev_timeout = ubench_timeout;
      ubench_prev_num_packets_per_send = ubench_num_packets_per_send;

      switch (ubench_state)
	{
	case  UBENCH_SEARCHING_N_FAST:
	  ubench_num_packets_per_send *= 2;
	  break;
	case UBENCH_SEARCHING_N_MEDIUM:
	  if (ubench_num_packets_per_send > 2)
	    ubench_num_packets_per_send += ubench_num_packets_per_send / 2;
	  else
	    ubench_num_packets_per_send++;
	  break;
	case UBENCH_SEARCHING_N_SLOW:
	  if (ubench_num_packets_per_send > 4)
	    ubench_num_packets_per_send += ubench_num_packets_per_send / 4;
	  else
	    ubench_num_packets_per_send++;
	  break;
	case UBENCH_SEARCHING_N_VERY_SLOW:
	  ubench_num_packets_per_send++;
	  break;
	case UBENCH_SEARCHING_T_FAST:
	  ubench_timeout /= 2;
	  break;
	case UBENCH_SEARCHING_T_MEDIUM:
	  ubench_timeout = ubench_timeout * 3 / 4;
	  if (ubench_timeout == ubench_prev_timeout)
	    ubench_timeout--;
	  break;
	case UBENCH_SEARCHING_T_SLOW:
	  ubench_timeout = ubench_timeout * 9 / 10;
	  if (ubench_timeout == ubench_prev_timeout)
	    ubench_timeout--;
	  break;
	default:
	  /* When we reach the done state, then we install the do_exit
	     timer if the run time value given was negative. */
	  if (run_time < 0)
	    {
	      ssh_xregister_timeout(-run_time, 0, do_exit, NULL);
	      run_time = 0;
	    }
	  /*FALLTHROUGH*/
	case UBENCH_SEARCHING_T_VERY_SLOW:
	  if (ubench_timeout != 0)
	    ubench_timeout--;
	  else
	    {
	      ubench_num_packets_per_send++;
	      ubench_timeout = 100;
	      ubench_state = UBENCH_SEARCHING_N_VERY_SLOW;
	    }
	  break;
	}
      if (ubench_timeout == ubench_last_fail_timeout &&
	  ubench_num_packets_per_send == ubench_last_fail_num_packets_per_send)
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("Trying old failed values again: (N, t) = (%d %d)", 
		     ubench_num_packets_per_send, ubench_timeout));
	}
    }
  SSH_DEBUG(SSH_D_HIGHOK, ("Updated: (N, t) = (%d %d)", 
			   ubench_num_packets_per_send, ubench_timeout));
}


void
ubench_udp_control_callback(SshUdpListener listener, void *context)
{
  SshUInt32 lost_packets, received_packets, sent_packets;
  SshUInt32 received_datagram_len;
  SshInt64 pps, time_ms, packet_loss, speed;

  while (1)
    {
      size_t datagram_len;
      SshUdpError error;

      error = ssh_udp_read_ip(listener, NULL, NULL,
			      ubench_data, sizeof(ubench_data),
			      &datagram_len);
      if (error == SSH_UDP_NO_DATA)
	{
	  return;
	}
      else if (error == SSH_UDP_OK)
	{
	  if (ssh_decode_array(ubench_data, datagram_len,
			       SSH_FORMAT_UINT32, &lost_packets,
			       SSH_FORMAT_UINT32, &received_packets,
			       SSH_FORMAT_UINT32, &sent_packets,
			       SSH_FORMAT_UINT64, &time_ms,
			       SSH_FORMAT_UINT64, &pps,
			       SSH_FORMAT_UINT64, &packet_loss,
			       SSH_FORMAT_UINT64, &speed,
			       SSH_FORMAT_UINT32, &received_datagram_len,
			       SSH_FORMAT_END) == 0)
	    {
	      ssh_warning("%s: Truncated control datagram", ubench_program);
	      continue;
	    }
	  if (!ubench_opt_quiet)
	    {
	      if (ubench_print_header == 0)
		{
		  printf("\n");
		  printf("Time\tNum of\tPacket\tPacket\t"
			 " Current\n");
		  printf("\tpckts\tSize\tloss%%\t10^6 bits/s\tN\tT\tState\n");
		  printf("\
----------------------------------------------------------------------\n");
		  ubench_print_header = 20;
		}
	      /* Current is valid. */
	      printf("%ld\t%ld\t%ld\t%.2f\t%-7.3f\t\t%ld\t%ld\t%s\n",
		     ubench_current_tick++,
		     (long) pps,
		     (long) received_datagram_len,
		     (double) packet_loss / 100.0,
		     (double) speed / 1000.0,
		     (long) ubench_num_packets_per_send,
		     (long) ubench_timeout,
		     (ubench_state > UBENCH_SEARCHING_T_VERY_SLOW ?
		      "done" : ubench_state_names[ubench_state]));
	      fflush(stdout);
	      ubench_print_header--;
	    }
	  if (((double) packet_loss / 100.0) < ubench_acceptence)
	    {
	      if (pps > ubench_max_pps)
		ubench_max_pps = pps;
	      if (speed > ubench_max_speed)
		ubench_max_speed = speed;
	      
	    }
	  ubench_tune_params((double) packet_loss / 100.0,
			     (double) speed / 1000.0);
	}
      else
	{
	  ssh_warning("%s: UDP read failed %s", ubench_program,
		      ssh_udp_error_string(error));
	}
    }
}

#ifdef VXWORKS
#undef main
#define main ubmain
#endif /* VXWORKS */

void do_exit(void *context)
{
  if (ubench_sender_listener)
    ssh_udp_destroy_listener(ubench_sender_listener);
  if (ubench_control_listener)
    ssh_udp_destroy_listener(ubench_control_listener);

  if (ubench_stats.listener)
    ssh_udp_destroy_listener(ubench_stats.listener);
  
  ssh_cancel_timeouts(ubench_send_data, SSH_ALL_CONTEXTS);
  ssh_cancel_timeouts(ubench_print_statistics, SSH_ALL_CONTEXTS);
  printf("%d, %ld, %-7.3f\n",
	 (int)ubench_data_len, (long) ubench_max_pps, 
	 ubench_max_speed / 1000.0);
}

int
main(int argc, char *argv[])
{
  SshUdpListenerParamsStruct udp_params;
  SshIpAddrStruct source[1];
  Boolean receive = FALSE;
  int opt;

  ubench_program = strrchr(argv[0], '/');
  if (ubench_program)
    ubench_program++;
  else
    ubench_program = argv[0];

  SSH_IP_UNDEFINE(source);
  SSH_IP_UNDEFINE(&ubench_destination);

  while ((opt = ssh_getopt(argc, argv, "a:D:C:c:d:hfl:N:p:rt:u:T:qA", 
			   NULL)) 
	 != EOF)
    {
      switch (opt)
        {
        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

	case 'C':
	  ubench_control_listener_port = atoi(ssh_optarg);
	  break;

        case 'd':
	  if (!ssh_ipaddr_parse(&ubench_destination, ssh_optarg))
	    {
	      ssh_warning("Error parsing IP address %s", ssh_optarg);
	      ubench_usage();
	      exit(1);
	    }
          break;

        case 'c':
	  if (!ssh_ipaddr_parse(source, ssh_optarg))
	    {
	      ssh_warning("Error parsing IP address %s", ssh_optarg);
	      ubench_usage();
	      exit(1);
	    }
          break;

        case 'h':
          ubench_usage();
          exit(0);
          break;

        case 'f':
          ubench_flood = TRUE;
          break;

        case 'l':
          ubench_data_len = atoi(ssh_optarg);

	  if (ubench_data_len < 8)
	    {
	      ssh_warning("The datagram length must be at least 8 bytes.");
	      ubench_usage();
	      exit(1);
	    }

          break;

        case 'a':
          ubench_acceptence = atoi(ssh_optarg);
          break;

        case 'N':
          ubench_num_packets_per_send = atoi(ssh_optarg);
          break;

        case 'p':
          ubench_port = atoi(ssh_optarg);
          break;

        case 'r':
          receive = TRUE;
          break;

        case 't':
          ubench_timeout = atoi(ssh_optarg);
          break;

        case 'T':
          run_time = atoi(ssh_optarg);
          break;
	case 'q':
	  ubench_opt_quiet = 1;
	  break;
        case 'A':
          disable_autotune = TRUE;
          break;
        }
    }

  if (ssh_optind < argc)
    {
      ssh_warning("%s: Junk at the end of command line", ubench_program);
      ubench_usage();
      exit(1);
    }

#ifndef VXWORKS
  ssh_event_loop_initialize();
#endif /* VXWORKS */

  if (receive)
    {
      /* Create listener. */
      ubench_stats.sender = 0;
      ubench_stats.port = ubench_port;
      ubench_stats.listener =
	ssh_udp_make_listener_ip(source, ubench_port,
				 &ubench_destination,
				 SSH_IP_DEFINED(&ubench_destination) ?
				 ubench_port : 0,
				 NULL, ubench_udp_callback,
				 &ubench_stats);
      
      if (ubench_stats.listener == NULL)
	{
	  ssh_warning("%s: Cannot create UDP listener for port %d",
		      ubench_program, ubench_port);
	  exit(1);
	}
      
      /* Create a listener for sending control traffic */
      ubench_control_listener =
	ssh_udp_make_listener_ip(source,
				 ubench_control_listener_port,
				 NULL, (SshUInt16) 0,
				 NULL, NULL, NULL);
      if (ubench_control_listener == NULL)
	{
	  ssh_warning("%s: Could not make UDP listener for %@\n",
		      ubench_program, ssh_ipaddr_render, source);
	  exit(1);
	}
      
      if (!ubench_opt_quiet)
	{
	  ssh_debug("%s: Sending control traffic to port %d", 
		    ubench_program, ubench_control_listener_port);
	  
	  ssh_debug("%s: Receiver running on port %d", 
		    ubench_program, ubench_port);
	  fflush(stdout);
	}
      ssh_xregister_timeout(1, 0, ubench_print_statistics, NULL);
    }
  else
    {
      memset(&udp_params, 0, sizeof(udp_params));
      udp_params.broadcasting = TRUE;

      ubench_sender_listener =
	ssh_udp_make_listener_ip(source, ubench_port,
				 NULL, (SshUInt16) 0,
				 &udp_params, NULL, NULL);
      if (ubench_sender_listener == NULL)
	{
	  ssh_warning("%s: Could not make UDP listener for %@\n",
		      ubench_program, ssh_ipaddr_render, source);
	  exit(1);
	}
      
      /* Create a listener for control traffic */
      ubench_control_listener =
	ssh_udp_make_listener_ip(source,
				 ubench_control_listener_port,
				 NULL, (SshUInt16) 0, NULL,
				 ubench_udp_control_callback,
				 NULL);
	  
      if (ubench_control_listener == NULL)
	{
	  ssh_warning("%s: Cannot create UDP listener for port %d",
		      ubench_program, ubench_control_listener_port);
	  exit(1);
	}

      if (!ubench_opt_quiet)
	{
	  ssh_warning("%s: Listening for control traffic on port %d", 
		      ubench_program, ubench_control_listener_port);
	  ssh_warning("%s: Sending data traffic to port %d", 
		      ubench_program, ubench_port);
	  fflush(stdout);
	}

      ssh_xregister_timeout(0, 0, ubench_send_data, ubench_sender_listener);
    }
  if (run_time > 0)
    {
      ssh_xregister_timeout(run_time, 0, do_exit, NULL);
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
  char *prog = "ubenchmark ";
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
    taskSpawn("tUbench", 10, 0, 32768,
              (FUNCPTR)ssh_eloop_start, 
              (int)argc, 
              (int)argv, 
              0, 0, 0, 0, 0, 0, 0, 0);

  return 0;
}
#endif /* VXWORKS */

#else /* SSHDIST_APPS_PERFUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_PERFUTILS */
