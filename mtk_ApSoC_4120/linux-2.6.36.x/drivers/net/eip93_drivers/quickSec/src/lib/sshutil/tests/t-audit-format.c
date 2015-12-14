/*
 *
 * t-audit-format.c
 *
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Generate audit events of a given format to an output file.
 * 
 */

#include "sshincludes.h"
#include "sshinet.h"
#include "sshrand.h"
#include "sshaudit.h"
#include "sshaudit_file.h"
#include "sshgetopt.h"


#define SSH_DEBUG_MODULE "TAuditFormat"

/* Audit context and its callback. */
SshAuditContext audit = NULL;
SshAuditFileContext audit_file_context = NULL;

/* snaplength size, this must be less than the full packet size */
#define SSH_SNAPLEN_SIZE 512

/* Data for generating audit events */
static unsigned char packet[1024];


static unsigned char src_addr[4];
static unsigned char dst_addr[4];

static unsigned char *src_addr_txt = (unsigned char *) "172.30.4.66";
static unsigned char *dst_addr_txt = (unsigned char *) "172.30.4.65";
static unsigned char *txt = (unsigned char *) "Hello, world!";
static unsigned char *seq_num = (unsigned char *) "\42\42\42\42";
static size_t seq_num_len = 4;
static unsigned char *spi = (unsigned char *) "abcd";
static size_t spi_len = 4;

/* Types used for certain output formats which require a header preifx 
   appended to the output file. */

#define SSH_SNORT_UNIFIED_MAGIC   0x2dac5ceb
#define SSH_SNORT_MAGIC           0xa1b2c3d4
#define SSH_SNORT_ALERT_MAGIC     0xDEAD4137  
#define SSH_SNORT_LOG_MAGIC       0xDEAD1080  
#define SSH_SNORT_VERSION_MAJOR   1
#define SSH_SNORT_VERSION_MINOR   2

/* From /usr/include/pcpa/net/bpf.h */
#define DLT_NULL        0       /* no link-layer encapsulation */
#define DLT_EN10MB      1       /* Ethernet (10Mb) */
#define DLT_EN3MB       2       /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3       /* Amateur Radio AX.25 */
#define DLT_PRONET      4       /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5       /* Chaos */
#define DLT_IEEE802     6       /* IEEE 802 Networks */
#define DLT_ARCNET      7       /* ARCNET */
#define DLT_SLIP        8       /* Serial Line IP */
#define DLT_PPP         9       /* Point-to-point Protocol */
#define DLT_FDDI        10      /* FDDI */

typedef struct UnifiedLogFileHeaderRec
{
  SshUInt32 magic;
  SshUInt16 version_major;
  SshUInt16 version_minor;
  SshUInt32 timezone;
  SshUInt32 sigfigs;
  SshUInt32 snaplen;
  SshUInt32 linktype;
} UnifiedLogFileHeaderStruct;

typedef struct UnifiedAlertFileHeaderRec
{
  SshUInt32 magic;
  SshUInt32 version_major;
  SshUInt32 version_minor;
  SshUInt32 timezone;
} UnifiedAlertFileHeaderStruct;


typedef struct FileHeaderRec
{
  SshUInt32 magic;
  SshUInt32 flags;
} FileHeaderStruct;


void ssh_audit_cb(SshAuditEvent event,
		  SshUInt32 argc, SshAuditArgument argv,
		  void *context)
{
  ssh_audit_file_cb(event, argc, argv, audit_file_context);
  return;
}

static Boolean generate_audit_events(SshAuditContext audit, 
				     unsigned int num_events)
{
  unsigned char media_type_buf[2], srcport_buf[2], dstport_buf[2];
  unsigned char sig_generator_buf[4], sig_id_buf[4], sig_rev_buf[4];
  unsigned char classification_buf[4], priority_buf[4], event_id_buf[4];
  unsigned char event_ref_buf[4], packet_flags_buf[4], snaplen_buf[4];
  unsigned char media_src[6]; 
  unsigned char media_dst[6];
  char *ifname;
  SshUInt32 sig_generator, sig_id, sig_rev, classification, priority;
  SshUInt32 event_id, event_ref, packet_flags; 
  SshUInt16 srcport, dstport;
  SshUInt8 ipproto;
  int i;

  media_src[0] = 0x00; media_src[1] = 0x07; media_src[2] = 0xE9;
  media_src[3] = 0x4B; media_src[4] = 0x04; media_src[5] = 0x63;
  media_dst[0] = 0x00; media_dst[1] = 0x02; media_dst[2] = 0xB3;
  media_dst[3] = 0x4F; media_dst[4] = 0xF1; media_dst[5] = 0xEA;
  
  SSH_DEBUG_HEXDUMP(4, ("Media src"), media_src, sizeof(media_src));
  SSH_DEBUG_HEXDUMP(4, ("Media dst"), media_dst, sizeof(media_dst));




  SSH_PUT_16BIT(media_type_buf, SSH_ETHERTYPE_IP);

  dstport = ssh_rand();
  SSH_PUT_16BIT(dstport_buf, dstport);

  SSH_DEBUG(SSH_D_MIDOK, ("The destination port is %s (%d)", 
			  dstport_buf, dstport));

  sig_generator = 1;
  sig_rev = 1;
  packet_flags = 0;

  SSH_PUT_32BIT(sig_generator_buf, sig_generator);
  SSH_PUT_32BIT(sig_rev_buf, sig_rev);
  SSH_PUT_32BIT(packet_flags_buf, packet_flags);

  SSH_PUT_32BIT(snaplen_buf, SSH_SNAPLEN_SIZE);



  for (i = 0; i < num_events; i++)
    {
      int j;

      event_id = event_ref = i;
      sig_id = (i + 101) % 2000;
      classification = i % 4;
      priority = i % 5;

      ifname = (i & 1) ? "eth1" : "eth0";
      ipproto = (i & 1) ? SSH_IPPROTO_UDP : SSH_IPPROTO_ICMP;

      SSH_IPH4_SET_PROTO(packet, ipproto);

      for (j = 0; j < sizeof(packet); j++)
	packet[j + 20] = ssh_rand();
      
      SSH_PUT_32BIT(sig_id_buf, sig_id);
      SSH_PUT_32BIT(classification_buf, classification);
      SSH_PUT_32BIT(priority_buf, priority);
      SSH_PUT_32BIT(event_id_buf, event_id);
      SSH_PUT_32BIT(event_ref_buf, event_ref);

      srcport = 100 + i;
      SSH_PUT_16BIT(srcport_buf, srcport);


      SSH_DEBUG_HEXDUMP(4, ("Have medaihdr"), media_src, sizeof(media_src));

      SSH_DEBUG(SSH_D_MIDOK, ("The source port is %s (%d)", 
			      srcport_buf, srcport));

      ssh_audit_event(audit, SSH_AUDIT_NOTICE,
		      SSH_AUDIT_SPI, spi, spi_len, 
		      SSH_AUDIT_SOURCE_INTERFACE, ifname,
		      SSH_AUDIT_ETH_SOURCE_ADDRESS, 
		      media_src, sizeof(media_src),
		      SSH_AUDIT_ETH_DESTINATION_ADDRESS, 
		      media_dst, sizeof(media_dst),
		      SSH_AUDIT_ETH_TYPE, media_type_buf, 2,
#if 0
		      SSH_AUDIT_SOURCE_ADDRESS, src_addr, sizeof(src_addr),
		      SSH_AUDIT_DESTINATION_ADDRESS, dst_addr,sizeof(dst_addr),
#else
		      SSH_AUDIT_SOURCE_ADDRESS_STR, src_addr_txt,
		      SSH_AUDIT_DESTINATION_ADDRESS_STR, dst_addr_txt,
#endif		     
		      SSH_AUDIT_SOURCE_PORT, srcport_buf, 2,
                      SSH_AUDIT_DESTINATION_PORT, dstport_buf, 2,
		      SSH_AUDIT_IPPROTO, &ipproto, 1,
		      SSH_AUDIT_PACKET_DATA, packet, SSH_SNAPLEN_SIZE,
		      SSH_AUDIT_PACKET_LEN, snaplen_buf, 4,
		      SSH_AUDIT_TXT, txt,
		      SSH_AUDIT_SEQUENCE_NUMBER, seq_num, seq_num_len,
		      SSH_AUDIT_SNORT_SIG_GENERATOR, sig_generator_buf, 4,
		      SSH_AUDIT_SNORT_SIG_ID, sig_id_buf, 4,
		      SSH_AUDIT_SNORT_SIG_REV, sig_rev_buf, 4,
#if 1
		      SSH_AUDIT_SNORT_CLASSIFICATION, classification_buf, 4,
#else
		      SSH_AUDIT_SNORT_CLASSIFICATION_STR, "Misc activity",
#endif
		      SSH_AUDIT_TXT, "BAD-TRAFFIC 0 ttl",
		      SSH_AUDIT_SNORT_PRIORITY, priority_buf, 4,
		      SSH_AUDIT_SNORT_EVENT_ID, event_id_buf, 4,
		      SSH_AUDIT_SNORT_EVENT_REFERENCE, event_ref_buf, 4,
		      SSH_AUDIT_SNORT_PACKET_FLAGS, packet_flags_buf, 4,
		      SSH_AUDIT_ARGUMENT_END);
    }

  return TRUE;
}

static SshAuditFormatType format_string_to_type(const char *str)
{
  if (!str)
    return SSH_AUDIT_FORMAT_DEFAULT;
  
  if (!strcmp(str, "default"))
    return SSH_AUDIT_FORMAT_DEFAULT;











  return SSH_AUDIT_FORMAT_DEFAULT;
}


void usage(void)
{
  printf("Usage: ./t-audit-format -f OUTPUT_FILE -t FORMAT_TYPE\n"
	 "\t-n NUM_EVENTS -d DEBUG_LEVEL\n");
  printf("\nThe supported format types are: default,unified-special,"
	 "\nunified-alert,unified-log,syslog\n");
  return;
}





int main(int ac, char **av)
{
  SshAuditFormatType format;
  SshIpAddrStruct ip_src, ip_dst;
  SshTime time;
  FILE *fp = NULL;
  char *format_str = NULL;
  char filename[256];
  char *file = NULL;
  int len, opt;
  unsigned num_events = 100;
  Boolean append_newline = FALSE;
  
  while ((opt = ssh_getopt(ac, av, "d:f:t:n:h", NULL)) != EOF)
    {
      switch (opt)
	{
	case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
	  
	case 'f':
	  file = ssh_optarg;
	  break;

	case 't':
	  format_str = ssh_optarg;
	  break;

	case 'n':
	  num_events = atoi(ssh_optarg);
	  break;

        default:
        case 'h':
          usage();
          exit(1);
	}
    }

  if (file == NULL)
    {
      ssh_warning("No audit file specified");
      usage();
      exit(1);
    }

  /* Get the format type from the input string */
  format = format_string_to_type(format_str);












    {
      strncpy(filename,file, sizeof(filename));
    }

  fp = fopen(filename, "ab");

  if (fp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open audit file `%s': %s",
                             file, strerror(errno)));
      goto error;
    }















































  /* Header prefix is now written, can close the file. */
  fclose(fp);
  
  if (format == SSH_AUDIT_FORMAT_DEFAULT 



      )
    append_newline = TRUE;

  audit_file_context = ssh_audit_file_create(filename, append_newline, format);

  if (audit_file_context == NULL)
    {
      ssh_warning("Could not create audit file `%s'", ssh_optarg);
      exit(1);	
    }        
  
  if ((audit = ssh_audit_create(ssh_audit_cb, NULL_FNPTR, audit_file_context))
      == NULL)
    {
      ssh_warning("Could not create audit context");
      ssh_audit_file_destroy(audit_file_context);
      exit(1);
    }

  /* Build an IP packet */
  SSH_IPH4_SET_VERSION(packet, 4);
  SSH_IPH4_SET_HLEN(packet, 5);
  SSH_IPH4_SET_TOS(packet, 0);
  SSH_IPH4_SET_LEN(packet, sizeof(packet));
  SSH_IPH4_SET_ID(packet, 0);
  SSH_IPH4_SET_FRAGOFF(packet, 0);
  SSH_IPH4_SET_TTL(packet, 64);
  SSH_IPH4_SET_CHECKSUM(packet, 0);

  SSH_VERIFY(ssh_ipaddr_parse(&ip_src, src_addr_txt));
  SSH_VERIFY(ssh_ipaddr_parse(&ip_dst, dst_addr_txt));

  SSH_IP_ENCODE(&ip_src, src_addr, len);
  SSH_ASSERT(len == 4);
  SSH_IP_ENCODE(&ip_dst, dst_addr, len);
  SSH_ASSERT(len == 4);

  SSH_IPH4_SET_SRC(&ip_src, packet);
  SSH_IPH4_SET_DST(&ip_dst, packet);

  /* Generate audit events */
  generate_audit_events(audit, num_events);

  ssh_audit_file_destroy(audit_file_context);
  ssh_audit_destroy(audit);
  ssh_util_uninit();
  return 0;


 error:
  if (fp != NULL)
    fclose(fp);
  exit(1);
}
