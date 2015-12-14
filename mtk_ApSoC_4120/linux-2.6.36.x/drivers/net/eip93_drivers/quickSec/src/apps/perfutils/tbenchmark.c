/*
 *
 * tbenchmark.c
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Elementry benchmark program for TCP. 
 * 
 *
 */

#include "sshincludes.h"

#ifdef SSHDIST_APPS_PERFUTILS

#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshinet.h"
#include "sshtcp.h"
#include "sshgetopt.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshTBenchmark"

static char *program;

static int local_start_port = 8000;
static char local_start_port_buf[64];
static int local_end_port = 8001;
static char local_end_port_buf[64];

static int remote_start_port = 8000;
static char remote_start_port_buf[64];
static int remote_end_port = 8001;
static char remote_end_port_buf[64];

static char *destination = "127.0.0.1";

static int packet_len = 512;
static Boolean receive = FALSE;

/* Send and receive state. */
static SshTime start_time = 0;
static SshTime my_start_time;
static SshTime current_time = 0;
static SshUInt32 sequence_number = 0;
static SshUInt32 last_sequence_number = 0xffffffff;
static SshUInt32 num_packets = 0;
static SshUInt32 num_bytes;
static SshUInt32 num_bytes_total = 0;
static SshUInt32 packets_dropped = 0;

#define MAX_PORTS 30

/* Per-port data */
static unsigned char buf[MAX_PORTS][65536];
static SshUInt32 offset[MAX_PORTS] = {0};
static SshUInt32 remaining[MAX_PORTS] = {0};

static SshUInt32 packets[MAX_PORTS] = {0};


typedef struct PortDataRec {
  int port_idx;
  SshStream stream;
} *PortData;

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]...\n\
  -d DESTINATION        destination IP address\n\
  -h                    print this help and exit\n\
  -D DEBUG LEVEL        debug level\n\
  -s LOCAL_START_PORT   start of the local port range (inclusive)\n\
  -e LOCAL_END_PORT     end of the local port range (exclusive)\n\
  -S REMOTE_START_PORT  start of the remote port range (inclusive)\n\
  -E REMOTE_START_PORT  end of the remote port range (exclusive)\n\
  -r                    receive (default is send)\n\
  -x BACKLOG            tcp listener backlog size\n\
  -y SEND BUFFER        tcp listener send buffer size\n\
  -z RECEVIVE BUFFER    tcp listener recevice buffer size\n\
",
          program);
}

/* Print the packet statistics for the last second, and reset
   the appropiate variables. */
static void reset(SshTime time)
{
  if (current_time != 0)
    {
      SshTime my_time = ssh_time();
      
      if (packets_dropped)
        SSH_DEBUG(SSH_D_FAIL, ("Number of dropped packets is %u", 
			       packets_dropped));
      
      printf("%d\t%.2f\t%-7.3f\t\t%-7.3f\n",
             (int) (current_time - start_time),
             ((float) (packets_dropped) / num_packets * 100),
             (num_bytes * 8) / 1000.0 / 1000.0,
             (num_bytes_total * 8.0 / 1000.0 / 1000.0
              / (my_time - my_start_time)));
 
#ifdef DEBUG_HEAVY
      {
	int indx;
	
	/* Verify that the traffic is resasonably spread over 
	   the port range. */
	for(indx = 0; indx < MAX_PORTS; indx++)
	  printf("%d ", packets[indx]); 
	printf("\n");
      }
#endif /* DEBUG_HEAVY */
    }
  
  memset(packets, 0, sizeof(packets));
  
  num_packets = 0;
  num_bytes = 0;
  packets_dropped = 0;
  current_time = time;
  return;
}


/* Parse the original data we sent from the buffer 'buf' */
static void parse_data(size_t len, int port_idx)
{
  SshTime time;
  SshUInt32 packet_size;
  unsigned char *bufptr = buf[port_idx];

  SSH_DEBUG(SSH_D_LOWOK, ("Parse packets with length %d", len));

  if (len < 12)
    {
      offset[port_idx] = len;
      return;
    }

  /* If this is the first segment, set the packet length. */       
  if (packet_len == 0)
    {
      my_start_time = ssh_time();
      start_time = SSH_GET_32BIT(bufptr);
      current_time = 0;

      packet_len = SSH_GET_32BIT(bufptr + 8);
      SSH_DEBUG(SSH_D_HIGHOK, ("The packet size is %d", packet_len));
    }      
  
  /* Loop through all complete packets contained in  'bufptr' */
  while (1)
    {
      if (len < packet_len)
        break;

      time            =  SSH_GET_32BIT(bufptr);
      sequence_number =  SSH_GET_32BIT(bufptr + 4);
      packet_size     =  SSH_GET_32BIT(bufptr + 8);
      
      SSH_ASSERT(packet_len == packet_size);

      /* This should not happen for TCP */
      if (local_end_port - local_start_port ==  1)
	{
	  if (last_sequence_number && 
	      (sequence_number != last_sequence_number + 1))
	    {
	      SSH_DEBUG(SSH_D_FAIL, 
			("Unexpected sequence number received, (%u %u)", 
			 sequence_number, last_sequence_number));
	      
	      SSH_ASSERT(sequence_number > last_sequence_number);
	      packets_dropped += (sequence_number - last_sequence_number);
	    } 
	}          

      last_sequence_number = sequence_number;
      
      if (time > current_time)
        reset(time);
      
      packets[port_idx]++;
      num_packets++;
      num_bytes += packet_len;
      num_bytes_total += packet_len;

      len -= packet_len;          
      bufptr += packet_len; 
    }
  
  SSH_ASSERT(len < packet_len);
  if (len)
    memmove(buf[port_idx], bufptr, len);

  offset[port_idx] = len;
  return;
}


/* Get data from the stream */
static void listener_callback(SshStreamNotification notification,
                             void *context)
{
  PortData data = context;
  SshStream stream = data->stream;
  int port_idx = data->port_idx;
  int bytes_read;

  SSH_DEBUG(SSH_D_LOWOK, ("In the notify callback, port index %d", port_idx));

  if (notification != SSH_STREAM_INPUT_AVAILABLE)
    return;
  
  /* Read data from the stream for as long as possible */
  while (1)
    {
      /* We don't copy to the first 'offset' bytes of 'buf' since some 
       data may have been saved there from the previous read. */
      bytes_read = ssh_stream_read(stream, buf[port_idx] + offset[port_idx], 
                                   sizeof(buf[port_idx]) - offset[port_idx]);
      
      SSH_DEBUG(SSH_D_MY, ("Read %d bytes from the stream", bytes_read));
      
      /* EOF received */
      if (bytes_read == 0)
        exit(1);
      
      if (bytes_read < 0)
        break;

      /* Parse the TCP data from 'buf' */      
      parse_data(bytes_read + offset[port_idx], port_idx);
    }      
}

static void
tcp_listener_callback(SshTcpError error, SshStream stream, void *context)
{
  PortData data;
  int port_idx = (int)context;

  if (error != SSH_TCP_NEW_CONNECTION)
    exit(1);

  data = ssh_xmalloc(sizeof(*data));
  data->port_idx = port_idx;
  data->stream = stream;
  
  ssh_stream_set_callback(stream, listener_callback, data);

  num_bytes_total = 0;
  last_sequence_number = 0;
  /* We do not yet know what size packets we shall receive. */
  packet_len = 0;
  return;
}

static void send_data(void *context);


static void send_data_loop(void *context) 
{
  send_data(context);
  ssh_xregister_timeout(0, 0, send_data_loop, context);
}


static void send_data(void *context) 
{
  PortData data = context;
  SshStream stream = data->stream;
  int port_idx = data->port_idx;
  int bytes_written = 0, packets = 0;

  /* Send as many packets as we can */  
  while (1)
    {
      SshTime time = ssh_time();

      packets++;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending data to the stream"));

      if (time != current_time)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("number of packets sent at time %d is %d", 
			       time - start_time, num_packets));

          num_packets = 0;
          current_time = time;
        }

      /* If previously we could not send the full packet, send the 
         remainder now. */
      SSH_ASSERT(remaining[port_idx] <= packet_len);
      while (remaining[port_idx])
        {
          bytes_written = 
            ssh_stream_write(stream, buf[port_idx] + 
			     (packet_len - remaining[port_idx]), 
                             remaining[port_idx]);
          
          if (bytes_written >= 0)
            {
              SSH_ASSERT(bytes_written <= remaining[port_idx]);
              remaining[port_idx] -= bytes_written;
            }
        }
      SSH_ASSERT(remaining[port_idx] == 0);
    
      sequence_number++;
      /* Our packet header */
      SSH_PUT_32BIT(buf[port_idx], (SshUInt32) time);
      SSH_PUT_32BIT(buf[port_idx] + 4, sequence_number); 
      SSH_PUT_32BIT(buf[port_idx] + 8, packet_len);
      
      bytes_written = ssh_stream_write(stream, buf[port_idx], packet_len);
      num_packets++;
      
      /* EOF exit from here */
      if (bytes_written == 0)
        exit(1);
      
      /* Stream is full */      
      if (bytes_written < 0)
        {
          remaining[port_idx] = packet_len;
          break;
        }      

      SSH_ASSERT(bytes_written <= packet_len);

      /* If we did not send the full packet, save how bytes we were 
         short, and transmit them later. */
      if (bytes_written != packet_len)
        {
          remaining[port_idx] = packet_len - bytes_written;
          SSH_DEBUG(SSH_D_MIDOK, 
		    ("Could not send the full packet, %d bytes to send", 
		     remaining[port_idx]));
        }
      break;
    }

  return;
}

/* Send data as fast as possible to the stream.  */
static void connect_callback(SshStreamNotification notification,
                             void *context)
{
  SSH_DEBUG(5, ("In the notify callback"));

  if (notification != SSH_STREAM_CAN_OUTPUT)
    return;

  send_data_loop(context);
}


static void
tcp_connect_callback(SshTcpError error, SshStream stream, void *context)
{
  PortData data;
  unsigned char buf[256];
  int port_idx = (int)context;

  fflush(stdout);

  if (error != SSH_TCP_OK)
    exit(1);

  data = ssh_xmalloc(sizeof(*data));
  data->port_idx = port_idx;
  data->stream = stream;

  SSH_DEBUG(SSH_D_HIGHOK, ("Port index is %d", port_idx));

   if (ssh_tcp_get_remote_address(stream, buf, sizeof(buf)))
    SSH_DEBUG(SSH_D_LOWOK, ("Remote address %s", buf));
  if (ssh_tcp_get_remote_port(stream, buf, sizeof(buf)))
    SSH_DEBUG(SSH_D_LOWOK, ("Remote port %s", buf));
  if (ssh_tcp_get_local_address(stream, buf, sizeof(buf)))
    SSH_DEBUG(SSH_D_LOWOK, ("Local address %s", buf));
  if (ssh_tcp_get_local_port(stream, buf, sizeof(buf)))
    SSH_DEBUG(SSH_D_LOWOK, ("Local port %s", buf));

  start_time = ssh_time();
  current_time = start_time;

  ssh_stream_set_callback(stream, connect_callback, data);
}


int
main(int argc, char *argv[])
{
  SshTcpListener listener;
  SshTcpListenerParamsStruct listen_params;
  SshTcpConnectParamsStruct connect_params;
  int opt, port;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  memset(&listen_params, 0, sizeof(listen_params));
  memset(&connect_params, 0, sizeof(connect_params));

  while ((opt = ssh_getopt(argc, argv, "D:d:hnN:s:e:S:E:rt:x:y:z:", NULL)) 
         != EOF)
    {
      switch (opt)
        {
        case 'D':
          ssh_debug_set_level_string(ssh_optarg); 
          break;

       case 'd':
          destination = ssh_xstrdup(ssh_optarg);
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'x':
          listen_params.listen_backlog = atoi(ssh_optarg);
          break;

        case 'y':
          listen_params.send_buffer_size = atoi(ssh_optarg);
          break;

        case 'z':
          listen_params.receive_buffer_size = atoi(ssh_optarg);
          break;

        case 's':
          local_start_port = atoi(ssh_optarg);
          break;

        case 'S':
          remote_start_port = atoi(ssh_optarg);
          break;

        case 'e':
          local_end_port = atoi(ssh_optarg);
          break;

        case 'E':
          remote_end_port = atoi(ssh_optarg);
          break;

        case 'r':
          receive = TRUE;
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

  ssh_snprintf(local_start_port_buf, sizeof(local_start_port_buf), "%d", 
	       local_start_port);
  ssh_snprintf(local_end_port_buf, sizeof(local_end_port_buf), "%d", 
	       local_end_port);  
  ssh_snprintf(remote_start_port_buf, sizeof(remote_start_port_buf), "%d", 
	       remote_start_port);
  ssh_snprintf(remote_end_port_buf, sizeof(remote_end_port_buf), "%d", 
	       remote_end_port);


  ssh_event_loop_initialize();

  /* Create listener. */
  if (receive)
    {
      /* Local port range. */
      if (local_end_port <= local_start_port)
	{
	  fprintf(stderr, "%s: Local port range is empty: [%d...%d[\n",
		  program, local_start_port, local_end_port);
	  exit(1);
	}

      if (local_end_port > local_start_port + MAX_PORTS)
	{
	  fprintf(stderr, "%s: Attempted to open too many ports. "
		  "Maximum allowed is %d\n",
		  program, MAX_PORTS);
	  exit(1);
	}
      
      /* Create listeners. */
      for (port = local_start_port; port < local_end_port; port++)
	{
	  char buf[256];
	  int port_idx = port - local_start_port;	  

	  ssh_snprintf(buf, sizeof(buf), "%d", port);

	  listener = ssh_tcp_make_listener(SSH_IPADDR_ANY, buf, 
					   &listen_params, 
					   tcp_listener_callback, 
					   (void *) port_idx);

	  if (listener == NULL)
	    {
	      fprintf(stderr, "%s: Cannot create TCP listener for port %s\n",
		      program, buf);
	      exit(1);
	    }
	}      
      printf("%s: Receiver running between ports %d and %d\n", 
	     program,  local_start_port, local_end_port);
      printf("\n");
      printf("Time\tPacket\t"
	     "Current\t\tCumulative\n");
      printf("\tloss%%\t10^6bits/s\t10^6bits/s\n");
      printf("\
----------------------------------------------------------------------\n");
    }
  else
    { 
      /* Remote port range. */
      if (remote_end_port <= remote_start_port)
	{
	  fprintf(stderr, "%s: Remote port range is empty: [%d...%d[\n",
		  program, remote_start_port, remote_end_port);
	  exit(1);
	}

      if (remote_end_port > remote_start_port + MAX_PORTS)
	{
	  fprintf(stderr, "%s: Attempted to open too many ports. "
		  "Maximum allowed is %d\n",
		  program, MAX_PORTS);
	  exit(1);
	}

      for (port = remote_start_port; port < remote_end_port; port++)
	{
	  char buf[256];
	  int port_idx = port - remote_start_port;
	  
	  ssh_snprintf(buf, sizeof(buf), "%d", port);

	  ssh_tcp_connect(destination, buf, 
			  &connect_params, tcp_connect_callback, 
			  (void *)port_idx);

	}      
      printf("%s: Sending data to port range %d and %d\n", 
	     program, remote_start_port, remote_end_port);
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
