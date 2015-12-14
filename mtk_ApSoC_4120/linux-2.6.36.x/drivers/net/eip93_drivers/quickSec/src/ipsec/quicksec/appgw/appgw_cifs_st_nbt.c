/*
 *
 * appgw_cifs_st_nbt.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * FSM state functions for NetBIOS over TCP/IP protocol parser.
 *
 */

#include "sshincludes.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifsNbt"


/******************* Prototypes for static help functiona *******************/

static int
ssh_appgw_cifs_netbios_name_decode(unsigned char * output_buffer,
                                   size_t output_buffer_len,
                                   unsigned char * encoded_name_buffer,
                                   size_t name_buffer_len);


/***************** Prototypes for "private" state functions *****************/

SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_decode_header);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_read_packet);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_filter_packet);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_drop_packet);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_reject_session);


/************************** Static help functions ***************************/

static int
ssh_appgw_cifs_netbios_name_decode(unsigned char * output_buffer,
                                   size_t output_buffer_len,
                                   unsigned char * encoded_name_buffer,
                                   size_t name_buffer_len)
{
  SshUInt8 encoded_name_len = encoded_name_buffer[0];

  if ((output_buffer_len >= (encoded_name_len/2 + 1)) &&
      (name_buffer_len >= encoded_name_len - 2))
    {
      unsigned char * cp = &encoded_name_buffer[1];
      SshUInt8 i;

      for (i = 0; i < encoded_name_len/2; i++)
        {
          output_buffer[i] = ((*cp - 'A') << 4) | (*(cp+1) - 'A');

          cp += 2;

          if (output_buffer[i] == ' ')
            break;
        }

      output_buffer[i] = 0x00;

      return (encoded_name_len + 2);
    }
  else
    {
      output_buffer[0] = 0x00;
      return 0;
    }
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_read_header)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  io->cifs_parser.decode_phase = SSH_APPGW_CIFS_READ_TRANSPORT_HEADER;

  io->bytes_to_read = SSH_APPGW_CIFS_NBT_HEADER_LEN;
  io->read_complete_step = ssh_appgw_cifs_nbt_st_decode_header;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_read);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_decode_header)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshUInt8 flags;
  SshUInt8 packet_type;
  SshUInt32 packet_length;

  SSH_ASSERT(io->conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_NBT);
  SSH_ASSERT(io->data_in_buf == SSH_APPGW_CIFS_NBT_HEADER_LEN);

  /* Decode NBT packet header */
  packet_type = io->buf[0];
  flags = io->buf[1];
  packet_length = SSH_GET_16BIT(&(io->buf[2])) |
                                  (((SshUInt32)flags & 0x00000080) << 16);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("NetBIOS over TCP/IP header: packet_type = 0x%02X, length = %d",
             packet_type, (int) packet_length));

  /* Disconnect if this is not a valid NetBIOS over TCP/IP Session
     Service packet header */
  if (((flags & 0x7f) != 0) ||
      ((packet_type != SSH_APPGW_NBT_SESSION_MESSAGE) &&
       (packet_type != SSH_APPGW_NBT_SESSION_KEEP_ALIVE) &&
       (packet_type != SSH_APPGW_NBT_SESSION_REQUEST) &&
       (packet_type != SSH_APPGW_NBT_SESSION_ACK) &&
       (packet_type != SSH_APPGW_NBT_SESSION_NAK) &&
       (packet_type != SSH_APPGW_NBT_SESSION_RETARGET)))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Received packet is not a valid NetBIOS packet!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  io->cifs_parser.transport.nbt.packet_type = packet_type;
  io->cifs_parser.transport.nbt.packet_length = packet_length;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_read_packet);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_read_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  io->cifs_parser.decode_phase = SSH_APPGW_CIFS_READ_PACKET;

  /* Full packet already received? */
  if (io->cifs_parser.transport.nbt.packet_length == 0)
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_filter_packet);
  else
    {
      io->bytes_to_read = io->cifs_parser.transport.nbt.packet_length;
      io->read_complete_step = ssh_appgw_cifs_nbt_st_filter_packet;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_read);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_filter_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwNbtTransport nbt = &(io->conn->transport.nbt);
  SshAppgwCifsConn conn = io->conn;

  unsigned char * cp;
  size_t data_left;
  SshUInt32 encoded_name_len;

  SSH_ASSERT(conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_NBT);

  /* Data read. */
  SSH_DEBUG_HEXDUMP(SSH_D_MY5,
                    ("Read %d bytes:", io->data_in_buf),
                    io->buf, io->data_in_buf);

  switch (io->cifs_parser.transport.nbt.packet_type)
    {
    case SSH_APPGW_NBT_SESSION_REQUEST:
      /* Check the validity of NBT Session Request */
      if ((nbt->session_phase != SSH_APPGW_NBT_SESSION_ESTABLISHMENT)
          || (io->cifs_parser.client == 0))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid NBT session request"));

          /* Reject the session */
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_reject_session);
          return SSH_FSM_CONTINUE;
        }

      /* Resolve NetBIOS names */
      data_left = io->cifs_parser.transport.nbt.packet_length
                    - SSH_APPGW_CIFS_NBT_HEADER_LEN;

      cp = &io->buf[SSH_APPGW_CIFS_NBT_HEADER_LEN];

      encoded_name_len = ssh_appgw_cifs_netbios_name_decode(nbt->called_name,
                                    sizeof(nbt->called_name), cp, data_left);

      cp += encoded_name_len;
      data_left -= encoded_name_len;

      ssh_appgw_cifs_netbios_name_decode(nbt->calling_name,
                                    sizeof(nbt->calling_name), cp, data_left);

      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_NOTICE,
                            SSH_AUDIT_TXT,
                            "NetBIOS over TCP/IP session request",
                            SSH_AUDIT_NBT_SOURCE_HOST,
                            nbt->calling_name,
                            SSH_AUDIT_NBT_DESTINATION_HOST,
                            nbt->called_name,
                            SSH_AUDIT_ARGUMENT_END);

      /* PASS the packet */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      break;

    case SSH_APPGW_NBT_SESSION_ACK:
      /* Check the validity of positive session response */
      if ((nbt->session_phase != SSH_APPGW_NBT_SESSION_ESTABLISHMENT)
          || (io->cifs_parser.client == 1))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Invalid positive NBT session acknowledgement"));

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_NOTICE,
                            SSH_AUDIT_TXT,
                            "NetBIOS over TCP/IP session opened",
                            SSH_AUDIT_NBT_SOURCE_HOST,
                            nbt->calling_name,
                            SSH_AUDIT_NBT_DESTINATION_HOST,
                            nbt->called_name,
                            SSH_AUDIT_ARGUMENT_END);

      /* NBT Session is up and running */
      nbt->session_phase = SSH_APPGW_NBT_SESSION_STEADY;

      /* PASS the packet */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      break;

    case SSH_APPGW_NBT_SESSION_NAK:
      /* Check the validity of positive session response */
      if ((nbt->session_phase != SSH_APPGW_NBT_SESSION_ESTABLISHMENT)
          || (io->cifs_parser.client == 1))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Invalid negative NBT session acknowledgement"));

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_NOTICE,
                            SSH_AUDIT_TXT,
                            "NetBIOS over TCP/IP session rejected",
                            SSH_AUDIT_NBT_SOURCE_HOST,
                            nbt->calling_name,
                            SSH_AUDIT_NBT_DESTINATION_HOST,
                            nbt->called_name,
                            SSH_AUDIT_ARGUMENT_END);

      /* PASS the packet */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      break;

    case SSH_APPGW_NBT_SESSION_RETARGET:
      /* Check the validity of positive session response */
      if ((nbt->session_phase != SSH_APPGW_NBT_SESSION_ESTABLISHMENT)
          || (io->cifs_parser.client == 1))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Invalid negative NBT session retarget response"));

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_NOTICE,
                            SSH_AUDIT_TXT,
                            "NetBIOS over TCP/IP session is being retargeted",
                            SSH_AUDIT_NBT_SOURCE_HOST,
                            nbt->calling_name,
                            SSH_AUDIT_NBT_DESTINATION_HOST,
                            nbt->called_name,
                            SSH_AUDIT_ARGUMENT_END);

      /* PASS the packet */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      break;

    case SSH_APPGW_NBT_SESSION_KEEP_ALIVE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("NetBIOS over TCP/IP: SESSION KEEP ALIVE"));

      if (nbt->session_phase != SSH_APPGW_NBT_SESSION_STEADY)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("Unexpected NBT Session Keep Alive packet"
                     "(session phase = %d)", nbt->session_phase));

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
          return SSH_FSM_CONTINUE;
        }

      /* PASS the packet */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      break;

    case SSH_APPGW_NBT_SESSION_MESSAGE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("NetBIOS over TCP/IP: Session message"));

      if (nbt->session_phase != SSH_APPGW_NBT_SESSION_STEADY)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("Unexpected NBT Session Message (session phase = %d)",
                    nbt->session_phase));

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
          return SSH_FSM_CONTINUE;
        }

      /* Does this look like a CIFS packet? */
      if ((io->cifs_parser.transport.nbt.packet_length >=
                 (SSH_APPGW_CIFS_NBT_HEADER_LEN +
                  SSH_APPGW_CIFS_PROTOCOL_ID_LEN)) &&
          memcmp(&io->buf[SSH_APPGW_CIFS_NBT_HEADER_LEN],
                 SSH_APPGW_CIFS_PROTOCOL_ID,
                 SSH_APPGW_CIFS_PROTOCOL_ID_LEN) == 0)
        {
          io->cifs_parser.packet_ptr =
            &io->buf[SSH_APPGW_CIFS_NBT_HEADER_LEN];
          io->cifs_parser.packet_size =
            io->cifs_parser.transport.nbt.packet_length;

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_decode_header);
          return SSH_FSM_CONTINUE;
        }

      /* Drop the packet because we don't know what it is */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
      break;

    default:
      SSH_DEBUG(SSH_D_NETGARB, ("Unknown packet!"));

      /* Drop the packet to prevent potential denial of service attack */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_drop_packet);
      break;
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_drop_packet)
{
  /* DROP the packet */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_drop);
  return SSH_FSM_CONTINUE;
}


/* Sends the generated CIFS packet to CIFS client */
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_send_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  /* Encode NBT packet header */
  io->buf[0] = SSH_APPGW_NBT_SESSION_MESSAGE;
  io->buf[1] = 0;
  SSH_PUT_16BIT(&(io->buf[2]), io->cifs_parser.packet_size);

  io->bufpos = 0;
  io->data_in_buf = io->cifs_parser.packet_size +
                    SSH_APPGW_CIFS_NBT_HEADER_LEN;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_write_to_src);
  return SSH_FSM_CONTINUE;
}


/* Sends the generated CIFS packet to server */
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_pass_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  /* Encode NBT packet header */
  io->buf[0] = SSH_APPGW_NBT_SESSION_MESSAGE;
  io->buf[1] = 0;
  SSH_PUT_16BIT(&(io->buf[2]), io->cifs_parser.packet_size);

  io->bufpos = 0;
  io->data_in_buf = io->cifs_parser.packet_size +
                    SSH_APPGW_CIFS_NBT_HEADER_LEN;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_reject_session)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Session rejected!"));

  io->bufpos = 0;
  io->buf[0] = SSH_APPGW_NBT_SESSION_NAK;
  io->buf[1] = 0; /* flags */
  SSH_PUT_16BIT(&io->buf[2], 1); /* length */
  io->buf[4] = 0x8F;

  io->data_in_buf = 5;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_write_to_src);
  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
