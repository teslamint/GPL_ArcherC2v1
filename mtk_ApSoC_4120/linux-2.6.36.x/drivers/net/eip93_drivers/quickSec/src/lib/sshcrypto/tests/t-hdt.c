/*
 *
 * t-hdt.c
 *
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test program to transfer data between two peers. Each data segment contains
 * an authentication tag which is checked by the receiver to verify that data
 * corruption has not occured. 
 *
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfdstream.h"
#include "sshudp.h"
#include "sshgetopt.h"
#include "sshgetput.h"
#include "sshencode.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshTHashedDataTransfer"

static char *file = NULL;
static unsigned char *remote = NULL;
static char portbuf[64];
static int max_length = 1024;
static Boolean receiver = FALSE;
static SshUdpListener udp_listener;
static unsigned char data[64024];
static SshHash hash;
static SshUInt32 num_bytes_low = 0;
static SshUInt32 num_bytes_high = 0;
static SshUInt32 num_packets = 0;

static void usage(void)
{
  fprintf(stdout, "\
Usage: t-hdt [OPTION]...\n\
  -d DESTINATION    Remote IP address.\n\
  -p PORT           Port to listen/send to.\n\
  -h                Print this help and exit.\n\
  -f                Input file.\n\
  -l LENTH          Maximum segment/datagram length excluding headers.\n\
  -r                Receive (the default is to send).\n\
  -D DEBUG          Debug level.\n");
}

static void end_test(void)
{
  if (receiver)
    {
      if (num_bytes_high)
	fprintf(stdout, "Received %d packets, %d Gigabytes\n", 
		(int)num_packets, (int)(4 * num_bytes_high));
      else
	fprintf(stdout, "Received %d packets, %d bytes\n", 
		(int)num_packets, (int)num_bytes_low);
    }
  else
    {
      if (num_bytes_high)
	fprintf(stdout, "Sent %d packets, %d Gigabytes\n", 
		(int)num_packets, (int)(4 * num_bytes_high));
      else
	fprintf(stdout, "Sent %d packets, %d bytes\n", 
		(int)num_packets, (int)num_bytes_low);
    }

  ssh_hash_free(hash);
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  exit(0);
}

/* Read data from the listener and verify the hash digests on the packets */
static void
udp_listener_callback(SshUdpListener udp_listener, void *context)
{
  size_t datagram_len, len;
  SshUdpError error;

  while (1)
    {
      error = ssh_udp_read(udp_listener, NULL, 0, NULL, 0, data, sizeof(data),
                           &datagram_len);
      if (error == SSH_UDP_NO_DATA)
        {
          break;
        }
      else if (error == SSH_UDP_OK)
        {
	  len = SSH_GET_32BIT(data);

	  if (len + 24 != datagram_len)
	    {

	      fprintf(stderr, " %d/%d\n", len, datagram_len);
	      fprintf(stderr, "Internal error, corrupt UDP datagram read.\n");
	      end_test();
	    }
	  /* Compute the SHA1 digest */
	  if (ssh_hash_compare_start(hash, data + 4, 20) != SSH_CRYPTO_OK)
	    {
	      fprintf(stderr, "Error, hash compared start failed\n"); 
	      end_test();
	    }
	  ssh_hash_update(hash, data + 24, len);

	  if (ssh_hash_compare_result(hash) != SSH_CRYPTO_OK)
	    {
	      fprintf(stderr, "Error, SHA1 digest does not match!!!\n"); 
	      end_test();
	    }
	  SSH_DEBUG(SSH_D_MY, ("SHA digest ok on payload of length %d", len));
	}
      else
	{
	  fprintf(stderr, "UDP read failed %s\n",
		  ssh_udp_error_string(error));
	}
    }
}

void stream_callback(SshStreamNotification notification,
		     void *context)
{
  int len;
  SshStream stream = context;

  if (notification == SSH_STREAM_DISCONNECTED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Stream Disconnected"));
      exit(1);
    }

  if (notification == SSH_STREAM_CAN_OUTPUT)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Ignoring can output"));
    }

  if (notification == SSH_STREAM_INPUT_AVAILABLE)
    {
      while (1)
	{
	  int read_len;
	  
	  SSH_ASSERT(max_length + 24 <= sizeof(data));
	  
	  read_len = ssh_rand() % max_length;
	  if (read_len == 0)
	    read_len++;
	 
	  /* Read into data at an offset of 24 bytes. The data length 
	     gets encoded to the first 4 bytes, and the SHA1 digest 
	     of the buffer will be placed into the next 20 bytes. */
	  len = ssh_stream_read(stream, data + 24, read_len);
	  
	  if (len == 0)
	    end_test();
	  
	  if (len < 0)
	    break; 

	  SSH_PUT_32BIT(data, len);
	  /* Compute the SHA1 digest */
	  ssh_hash_reset(hash);
	  ssh_hash_update(hash, data + 24, len);
	  SSH_VERIFY(ssh_hash_final(hash, data + 4) == SSH_CRYPTO_OK);
	  
	  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Data"), data, len+24);

	  SSH_DEBUG(SSH_D_LOWOK, ("Sending %d bytes to %s", 24+len, remote));

	  ssh_udp_send(udp_listener, remote, portbuf, data, 24 + len);

          num_packets++;
	  num_bytes_low += len;
	  if (num_bytes_low < len)
	    num_bytes_high++;

	  if (len < read_len)
	    break;
	}
    }
}


int main(int argc, char *argv[])
{
  SshStream stream;
  int opt, port;
  SshIOHandle fd;

  port = 12000;

  if (argc == 1)
    {
      usage();
      exit(1);
    }

  while ((opt = ssh_getopt(argc, argv, "D:d:p:f:l:hr", 
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

        case 'h':
          usage();
          exit(0);
          break;

        case 'p':
          port = atoi(ssh_optarg);
          break;

        case 'l':
          max_length = atoi(ssh_optarg);
          break;

        case 'f':
          file = ssh_optarg;
          break;

        case 'r':
          receiver = TRUE;
          break;
        }
    }

  if (max_length > 64000)
    max_length = 64000;

  if (!receiver && !remote)
    {
      fprintf(stderr, "Please specify a remote destination\n");
      usage();
      exit(1);
    }

  ssh_snprintf(portbuf, sizeof(portbuf), "%d", port);

  ssh_event_loop_initialize();

  SSH_VERIFY(ssh_crypto_library_initialize() == SSH_CRYPTO_OK);
  SSH_VERIFY(ssh_hash_allocate("sha1", &hash) == SSH_CRYPTO_OK);
  SSH_VERIFY(ssh_hash_digest_length("sha1") == 20);

  if (receiver)
    {
      udp_listener = ssh_udp_make_listener(SSH_IPADDR_ANY, portbuf, NULL, 
					   NULL, NULL, 
					   udp_listener_callback, NULL);
      
      if (udp_listener == NULL)
	{
	  fprintf(stderr, "Cannot create UDP listener for port %s\n",
		  portbuf);
	  exit(1);
	}
    }
  else
    {
      udp_listener = ssh_udp_make_listener(SSH_IPADDR_ANY, NULL, 
					   NULL, NULL, NULL, NULL, NULL);
      if (udp_listener == NULL)
	{
	  fprintf(stderr, "Could not make UDP listener");
	  exit(1);
	}

      fd = open(file, O_RDWR);

      stream = ssh_stream_fd_wrap(fd, TRUE);
      ssh_stream_set_callback(stream, stream_callback, stream);
    }
  
  ssh_event_loop_run();
  return 0;
}
