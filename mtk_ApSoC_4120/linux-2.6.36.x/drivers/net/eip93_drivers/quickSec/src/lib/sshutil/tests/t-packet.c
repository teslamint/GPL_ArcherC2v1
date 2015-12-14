/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshdns
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/lib/sshutil/tests/Attic/t-packet.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 11:49 Apr 20 2004 kivinen
 *        Last Modification : 13:58 Aug 25 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.210
 *        
 *
 *        Description       : Test DNS packet encode / decode functions
 *
 *        $Log: t-packet.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:34:48  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshfsm.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshrand.h"

#define SSH_DEBUG_MODULE "Main"

/* Program name */
char *program;

/* Verbose level */
int verbose = 0;

#ifdef SSHDIST_UTIL_DNS_RESOLVER

typedef struct TDNSTestRec {
  int packet_length;
  int return_length;
#define NOT_COMPRESSED 2
  int valid;			/* FALSE = not valid,
				   TRUE = valid
				   NOT_COMPRESSED = valid, but packets do not
				   match (differences in the name
				   compressions) */
  const unsigned char *packet;
} *TDNSTest, TDNSTestStruct;

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     QNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      NAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
TDNSTestStruct t_dns_test[] = {
  /* Following test cases are created by taking the dns packet dumps
     from the net using tcpdump -s 1500 -X -n port 53 and then converting
     them to test cases by perl script. */

#include "t-packet-test1.c"
#include "t-packet-test2.c"
#include "t-packet-test3.c"
#include "t-packet-test4.c"

  /* Some handwritten tests. These are at the end so we can add them later
     without needing to renumber the generated test cases. */
  { 0x20, 0x20, TRUE,
    "\x00\x01\x00\x00"		/* ID, Flags */
    "\x00\x01\x00\x00"		/* qdcount, ancount */
    "\x00\x00\x00\x00"		/* nscount, arcount */
    "\7kivinen\3iki\2fi\0"	/* Name */
    "\x00\x01\x00\x01"		/* qtype, qclass */
  },
  { 0x95, 0x95, TRUE,
    "\x00\x01\x80\x80"		/* ID, Flags */
    "\x00\x01\x00\x00"		/* qdcount, ancount */
    "\x00\x04\x00\x02"		/* nscount, arcount */
    "\7kivinen\3iki\2fi\0"	/* 0x0c -> Name */
    "\x00\x01\x00\x01"		/* qtype, qclass */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns2\xc0\x14"		/* 0x2c -> RDATA of ns2 + ptr to \3iki\2fi */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x14"			/* rdlength */
    "\3ns2\12bbnetworks\3net\0"	/* 0x3e -> RDATA */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x05"			/* rdlength */
    "\2ns\xc0\x14"		/* 0x5e -> RDATA of ns + ptr to \3iki\2fi */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns1\xc0\x14"		/* 0x6f -> RDATA of ns1 +
				   ptr to \12bbnetworks\3net */
    "\xc0\x6f"			/* PTR to \3ns1\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x01"		/* IP = 212.16.96.1 */
    "\xc0\x3e"			/* PTR to \3ns2\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x0b"		/* IP = 212.16.96.11 */
  },
  { 0x95, 0x95, FALSE,
    "\x00\x01\x80\x80"		/* ID, Flags */
    "\x00\x01\x00\x00"		/* qdcount, ancount */
    "\x00\x04\x00\x02"		/* nscount, arcount */
    "\7kivinen\3iki\2fi\0"	/* 0x0c -> Name */
    "\x00\x01\x00\x01"		/* qtype, qclass */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns2\xc0\x2c"		/* 0x2c -> RDATA of ns2 + ptr to ns2 +
				   ptr (loop) */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x14"			/* rdlength */
    "\3ns2\12bbnetworks\3net\0"	/* 0x3e -> RDATA */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x05"			/* rdlength */
    "\2ns\xc0\x14"		/* 0x5e -> RDATA of ns + ptr to \3iki\2fi */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns1\xc0\x14"		/* 0x6f -> RDATA of ns1 +
				   ptr to \12bbnetworks\3net */
    "\xc0\x6f"			/* PTR to \3ns1\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x01"		/* IP = 212.16.96.1 */
    "\xc0\x3e"			/* PTR to \3ns2\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x0b"		/* IP = 212.16.96.11 */
  },
  { 0x95, 0x95, FALSE,
    "\x00\x01\x80\x80"		/* ID, Flags */
    "\x00\x01\x00\x00"		/* qdcount, ancount */
    "\x00\x04\x00\x02"		/* nscount, arcount */
    "\7kivinen\3iki\2fi\0"	/* 0x0c -> Name */
    "\x00\x01\x00\x01"		/* qtype, qclass */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns2\xc0\x30"		/* 0x2c -> RDATA of ns2 + ptr to ptr (loop) */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x14"			/* rdlength */
    "\3ns2\12bbnetworks\3net\0"	/* 0x3e -> RDATA */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x05"			/* rdlength */
    "\2ns\xc0\x14"		/* 0x5e -> RDATA of ns + ptr to \3iki\2fi */
    "\xc0\x14"			/* Ptr to \3iki\2fi */
    "\x00\x02\x00\x01"		/* type, class */
    "\x00\x00\x16\xb6"		/* TTL */
    "\x00\x06"			/* rdlength */
    "\3ns1\xc0\x14"		/* 0x6f -> RDATA of ns1 +
				   ptr to \12bbnetworks\3net */
    "\xc0\x6f"			/* PTR to \3ns1\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x01"		/* IP = 212.16.96.1 */
    "\xc0\x3e"			/* PTR to \3ns2\12bbnetworks\3net */
    "\x00\x01\x00\x01"		/* type, class */
    "\x00\x00\x16\xae"		/* TTL */
    "\x00\x04"			/* rdlength */
    "\xd4\x10\x60\x0b"		/* IP = 212.16.96.11 */
  }
};

int t_dns_test_count = sizeof(t_dns_test) / sizeof(t_dns_test[0]);

void t_dns_test_encode_decode(void)
{
  unsigned char buffer[1024];
  SshDNSPacket packet, packet2;
  int length, i, j;
  if (verbose)
    {
      printf("\nRunning decode/encode/decode tests\n");
      fflush(stdout);
    }

  for(i = 0; i < t_dns_test_count; i++)
    {
      if (verbose > 2)
	{
	  printf("\r    %d", i);
	  fflush(stdout);
	}
      else if (verbose > 1 && (i % 100) == 0)
	{
	  printf("\r    %d", i);
	  fflush(stdout);
	}
      packet = ssh_dns_packet_decode(t_dns_test[i].packet,
				     t_dns_test[i].packet_length);
      if (t_dns_test[i].valid)
	{
	  if (packet == NULL)
	    ssh_fatal("decode %d failed, should have succeeded.", i);
	  length = ssh_dns_packet_encode(packet, buffer,
					 t_dns_test[i].packet_length);
	  if (t_dns_test[i].valid == TRUE)
	    {
	      if (length != t_dns_test[i].return_length)
		{
		  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Original packet"),
				    t_dns_test[i].packet,
				    t_dns_test[i].packet_length);
		  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("New packet"),
				    buffer, length < 0 ? -length : length);
		  ssh_fatal("Encoded %d length does not match %d vs %d",
			    i, length, t_dns_test[i].return_length);
		}
	      if (memcmp(buffer, t_dns_test[i].packet,
			 t_dns_test[i].return_length) != 0)
		{
		  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Original packet"),
				    t_dns_test[i].packet,
				    t_dns_test[i].packet_length);
		  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("New packet"),
				    buffer,
				    length > 0 ? length : -length);
		  ssh_fatal("Encoded and decoded packets %d are different", i);
		}
	    }
	  if (length > 0)
	    {
	      packet2 = ssh_dns_packet_decode(buffer, length);
	      if (packet == NULL)
		ssh_fatal("decode2 %d failed, should have succeeded.", i);
	      SSH_VERIFY(packet->id == packet2->id);
	      SSH_VERIFY(packet->flags == packet2->flags);
	      SSH_VERIFY(packet->op_code == packet2->op_code);
	      SSH_VERIFY(packet->response_code == packet2->response_code);
	      SSH_VERIFY(packet->question_count == packet2->question_count);
	      SSH_VERIFY(packet->answer_count == packet2->answer_count);
	      SSH_VERIFY(packet->authority_count == packet2->authority_count);
	      SSH_VERIFY(packet->additional_count ==
			 packet2->additional_count);
	      for(j = 0; j < packet->question_count; j++)
		{
		  SSH_VERIFY(strcmp(packet->question_array[j].qname,
				    packet2->question_array[j].qname) == 0);
		  SSH_VERIFY(packet->question_array[j].qtype ==
			     packet2->question_array[j].qtype);
		  SSH_VERIFY(packet->question_array[j].qclass ==
			     packet2->question_array[j].qclass);
		}
	      for(j = 0; j < packet->answer_count; j++)
		{
		  SSH_VERIFY(strcmp(packet->answer_array[j].name,
				    packet2->answer_array[j].name) == 0);
		  SSH_VERIFY(packet->answer_array[j].type ==
			     packet2->answer_array[j].type);
		  SSH_VERIFY(packet->answer_array[j].dns_class ==
			     packet2->answer_array[j].dns_class);
		  SSH_VERIFY(packet->answer_array[j].ttl ==
			     packet2->answer_array[j].ttl);
		  SSH_VERIFY(packet->answer_array[j].rdlength ==
			     packet2->answer_array[j].rdlength);
		  SSH_VERIFY(memcmp(packet->answer_array[j].rdata,
				    packet2->answer_array[j].rdata,
				    packet->answer_array[j].rdlength) == 0);
		}
	      for(j = 0; j < packet->authority_count; j++)
		{
		  SSH_VERIFY(strcmp(packet->authority_array[j].name,
				    packet2->authority_array[j].name) == 0);
		  SSH_VERIFY(packet->authority_array[j].type ==
			     packet2->authority_array[j].type);
		  SSH_VERIFY(packet->authority_array[j].dns_class ==
			     packet2->authority_array[j].dns_class);
		  SSH_VERIFY(packet->authority_array[j].ttl ==
			     packet2->authority_array[j].ttl);
		  SSH_VERIFY(packet->authority_array[j].rdlength ==
			     packet2->authority_array[j].rdlength);
		  SSH_VERIFY(memcmp(packet->authority_array[j].rdata,
				    packet2->authority_array[j].rdata,
				    packet->authority_array[j].rdlength) == 0);
		}
	      for(j = 0; j < packet->additional_count; j++)
		{
		  SSH_VERIFY(strcmp(packet->additional_array[j].name,
				    packet2->additional_array[j].name) == 0);
		  SSH_VERIFY(packet->additional_array[j].type ==
			     packet2->additional_array[j].type);
		  SSH_VERIFY(packet->additional_array[j].dns_class ==
			     packet2->additional_array[j].dns_class);
		  SSH_VERIFY(packet->additional_array[j].ttl ==
			     packet2->additional_array[j].ttl);
		  SSH_VERIFY(packet->additional_array[j].rdlength ==
			     packet2->additional_array[j].rdlength);
		  SSH_VERIFY(memcmp(packet->additional_array[j].rdata,
				    packet2->additional_array[j].rdata,
				    packet->additional_array[j].rdlength)
			     == 0);
		}
	      ssh_dns_packet_free(packet2);
	    }
	  ssh_dns_packet_free(packet);
	}
      else
	{
	  if (packet != NULL)
	    {
	      ssh_fatal("Decode %d succeded, should have failed.", i);
	    }
	}
    }
  if (verbose)
    {
      printf("\n");
      fflush(stdout);
    }
}

void t_dns_test_garbage(void)
{
  unsigned char buffer[1024];
  SshDNSPacket packet;
  int i, j, len, start;

  if (verbose)
    {
      printf("Running random garbage tests\n");
      fflush(stdout);
    }

  for(i = 0; i < 1000; i++)
    {
      if (verbose > 2)
	{
	  printf("\r    %d", i);
	  fflush(stdout);
	}
      else if (verbose > 1 && (i % 100) == 0)
	{
	  printf("\r    %d", i);
	  fflush(stdout);
	}

      if (i % 128 == 0)
	{
	  for(j = 0; j < 1024; j++)
	    buffer[j] = ssh_rand();
	}

      if (ssh_rand() % 32 == 0)
	len = ssh_rand() % 1024;
      else
	len = ssh_rand() % 128;
      start = ssh_rand() % 1024;
      if (start + len >= 1024)
	len = 1024 - start;

      packet = ssh_dns_packet_decode(buffer + start, len);
      if (packet != NULL)
	ssh_dns_packet_free(packet);
    }
  if (verbose)
    {
      printf("\n");
      fflush(stdout);
    }
}

#endif /* SSHDIST_UTIL_DNS_RESOLVER */

int main(int argc, char **argv)
{
  const char *debug_string = "Main=9,SshDns*=2";
  int c, errflg = 0;
  SshTime t;

  t = ssh_time();

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "d:r:v", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
        case 'r': t = atol(ssh_optarg); break;
	case 'v': verbose++; break;
	default:
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
	      "Usage: %s [-d debug_flags] [-r random_seed] [-v] [-v]\n",
	      program);
      exit(1);
    }

  printf("seed = %ld\n", (SshUInt32) t);
  ssh_rand_seed((SshUInt32) t);

  ssh_debug_set_level_string(debug_string);

  ssh_event_loop_initialize();

#ifdef SSHDIST_UTIL_DNS_RESOLVER
  t_dns_test_encode_decode();
  t_dns_test_garbage();
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

  ssh_event_loop_uninitialize();
  ssh_debug_uninit();
  ssh_global_uninit();









  return 0;
}
