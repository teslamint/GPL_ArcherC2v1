/*
 *
 * t-audit.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Regression tests for SSH Audit.
 *
 */

#include "sshincludes.h"
#include "sshaudit.h"

#define SSH_DEBUG_MODULE "t-audit"

static char *context_msg = "Hello, world!";

static SshAuditEvent last_event;
static SshUInt32 last_argc;

Boolean all_arguments = FALSE;

unsigned char *spi = (unsigned char *) "abcd";
size_t spi_len = 4;

unsigned char *src_addr = (unsigned char *) "\0\1\2\3";
size_t src_addr_len = 4;

unsigned char *dst_addr = (unsigned char *) "\3\2\1\0";
size_t dst_addr_len = 4;

unsigned char *src_addr_txt = (unsigned char *) "10.1.48.7";
unsigned char *dst_addr_txt = (unsigned char *) "10.1.48.8";

unsigned char *ipv6_flow_id = (unsigned char *) "\6\6\6\6\6\6";
size_t ipv6_flow_id_len = 6;

unsigned char *seq_num = (unsigned char *) "\42\42\42\42";
size_t seq_num_len = 4;

unsigned char *txt = (unsigned char *) "Hello, world!";

static void
audit_callback(SshAuditEvent event, SshUInt32 argc, SshAuditArgument argv,
               void *context)
{
  SSH_ASSERT(context == context_msg);

  last_event = event;
  last_argc = argc;

  if (all_arguments)
    {
      SshUInt32 i;

      for (i = 0; i < argc; i++)
        {
          switch (argv[i].type)
            {
            case SSH_AUDIT_SPI:
              if (argv[i].data_len != spi_len
                  || memcmp(argv[i].data, spi, spi_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_SPI failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_SOURCE_ADDRESS:
              if (argv[i].data_len != src_addr_len
                  || memcmp(argv[i].data, src_addr, src_addr_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_SOURCE_ADDRESS failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_DESTINATION_ADDRESS:
              if (argv[i].data_len != dst_addr_len
                  || memcmp(argv[i].data, dst_addr, dst_addr_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_DESTINATION_ADDRESS failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_SOURCE_ADDRESS_STR:
              if (argv[i].data_len != strlen((char *) src_addr_txt)
                  || memcmp(argv[i].data, src_addr_txt, argv[i].data_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_SOURCE_ADDRESS_STR failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_DESTINATION_ADDRESS_STR:
              if (argv[i].data_len != strlen((char *) dst_addr_txt)
                  || memcmp(argv[i].data, dst_addr_txt, argv[i].data_len) != 0)
                {
                  fprintf(stderr,
                          "SSH_AUDIT_DESTINATION_ADDRESS_STR failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_IPV6_FLOW_ID:
              if (argv[i].data_len != ipv6_flow_id_len
                  || memcmp(argv[i].data, ipv6_flow_id, ipv6_flow_id_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_IPV6_FLOW_ID failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_SEQUENCE_NUMBER:
              if (argv[i].data_len != seq_num_len
                  || memcmp(argv[i].data, seq_num, seq_num_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_SEQUENCE_NUMBER failed\n");
                  exit(1);
                }
              break;

            case SSH_AUDIT_TXT:
              if (argv[i].data_len != strlen((char *) txt)
                  || memcmp(argv[i].data, txt, argv[i].data_len) != 0)
                {
                  fprintf(stderr, "SSH_AUDIT_TXT failed\n");
                  exit(1);
                }
              break;

            default:
              SSH_NOTREACHED;
              break;
            }
        }
    }
}

int
main(int argc, char *argv[])
{
  SshAuditContext audit;
  int i, j;

  if (argc == 2)
    ssh_debug_set_level_string(argv[1]);

  audit = ssh_audit_create(audit_callback, NULL_FNPTR, context_msg);
  if (audit == NULL)
    {
      fprintf(stderr, "Could not create audit context\n");
      exit(1);
    }

  /* Disable all audit events. */
  for (i = SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW; i < SSH_AUDIT_MAX_VALUE; i++)
    {
      ssh_audit_event_disable(audit, i);
      if (ssh_audit_event_query(audit, i))
        {
          fprintf(stderr, "ssh_audit_event_disable(%d) failed\n", i);
          exit(1);
        }

      /* All other events must be enabled. */
      for (j = SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW; j < SSH_AUDIT_MAX_VALUE;
           j++)
        {
          if (j == i)
            continue;

          if (!ssh_audit_event_query(audit, j))
            {
              fprintf(stderr, "ssh_audit_event_disable(%d) disabled also %d\n",
                      i, j);
              exit(1);
            }
        }

      ssh_audit_event_enable(audit, i);
      if (!ssh_audit_event_query(audit, i))
        {
          fprintf(stderr, "ssh_audit_event_enable(%d) failed\n", i);
          exit(1);
        }
    }

  /* Generate all audit events. */
  for (i = SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW; i < SSH_AUDIT_MAX_VALUE; i++)
    {
      ssh_audit_event(audit, i, SSH_AUDIT_ARGUMENT_END);
      if (last_event != i)
        {
          fprintf(stderr, "ssh_audit_event(%d) failed\n", i);
          exit (1);
        }
      if (last_argc != 0)
        {
          fprintf(stderr, "ssh_audit_event(%d) generated wrong argc\n", i);
          exit(1);
        }
    }

  /* Check that disabled audit events are not generated. */
  last_event = 0;
  for (i = SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW; i < SSH_AUDIT_MAX_VALUE; i++)
    {
      ssh_audit_event_disable(audit, i);
      ssh_audit_event(audit, i, SSH_AUDIT_ARGUMENT_END);
      if (last_event != 0)
        {
          fprintf(stderr, "ssh_audit_event(%d) generated disabled event\n", i);
          exit (1);
        }
      ssh_audit_event_enable(audit, i);
    }

  /* Generate all arguments. */
  all_arguments = TRUE;
  ssh_audit_event(audit, SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW,
                  SSH_AUDIT_SPI, spi, spi_len,
                  SSH_AUDIT_SOURCE_ADDRESS, src_addr, src_addr_len,
                  SSH_AUDIT_DESTINATION_ADDRESS, dst_addr, dst_addr_len,
                  SSH_AUDIT_SOURCE_ADDRESS_STR, src_addr_txt,
                  SSH_AUDIT_DESTINATION_ADDRESS_STR, dst_addr_txt,
                  SSH_AUDIT_IPV6_FLOW_ID, ipv6_flow_id, ipv6_flow_id_len,
                  SSH_AUDIT_SEQUENCE_NUMBER, seq_num, seq_num_len,
                  SSH_AUDIT_TXT, txt,
                  SSH_AUDIT_ARGUMENT_END);

  ssh_audit_destroy(audit);
  ssh_util_uninit();
  return 0;
}
