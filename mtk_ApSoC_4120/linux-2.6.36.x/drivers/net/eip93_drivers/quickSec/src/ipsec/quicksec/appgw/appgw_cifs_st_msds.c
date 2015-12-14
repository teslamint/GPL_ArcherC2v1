/*
 *
 * appgw_cifs_st_msds.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * FSM state functions for Microsoft Direct SMB Service parser.
 *
 */

#include "sshincludes.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifsMsDS"


/***************** Prototypes for "private" state functions *****************/

SSH_FSM_STEP(ssh_appgw_cifs_msds_st_decode_header);
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_read_packet);
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_filter_packet);
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_drop_packet);


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_msds_st_read_header)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  io->cifs_parser.decode_phase = SSH_APPGW_CIFS_READ_TRANSPORT_HEADER;
  io->bytes_to_read = SSH_APPGW_CIFS_MSDS_HEADER_LEN;
  io->read_complete_step = ssh_appgw_cifs_msds_st_decode_header;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_read);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_msds_st_decode_header)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshUInt32 packet_length;

  SSH_ASSERT(io->conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_MSDS);
  SSH_ASSERT(io->data_in_buf == SSH_APPGW_CIFS_MSDS_HEADER_LEN);

  packet_length = SSH_GET_32BIT((const char *)io->buf);
  packet_length &= 0x00FFFFFF;

  /* At least Samba 3.0 sends NetBIOS Session Keep Alive messages also 
     to MS-DS port. */
  if ((io->buf[0] == SSH_APPGW_NBT_SESSION_KEEP_ALIVE) &&
      (packet_length == 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("NetBIOS Session Keep Alive"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
      return SSH_FSM_CONTINUE;
    }

  if ((packet_length + SSH_APPGW_CIFS_MSDS_HEADER_LEN) >
                                          SSH_APPGW_CIFS_MAX_PACKET_SIZE)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid packet length!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("MS-DS header: packet_length = %d",
	     (int) packet_length));

  io->cifs_parser.transport.msds.packet_length = packet_length;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_read_packet);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_msds_st_read_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  SSH_ASSERT(io->conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_MSDS);

  io->cifs_parser.decode_phase = SSH_APPGW_CIFS_READ_PACKET;

  /* Full packet already received? */
  if (io->cifs_parser.transport.msds.packet_length == 0)
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_filter_packet);
  else
    {
      io->bytes_to_read = io->cifs_parser.transport.msds.packet_length;
      io->read_complete_step = ssh_appgw_cifs_msds_st_filter_packet;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_read);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_msds_st_filter_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  SSH_ASSERT(io->conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_MSDS);

  /* Data read. */
  SSH_DEBUG_HEXDUMP(SSH_D_MY5,
                    ("Read %d bytes:", io->data_in_buf),
                    io->buf, io->data_in_buf);

  /* Does this look like a CIFS packet? */
  if ((io->cifs_parser.transport.msds.packet_length >=
             (SSH_APPGW_CIFS_MSDS_HEADER_LEN +
              SSH_APPGW_CIFS_PROTOCOL_ID_LEN)) &&
      memcmp(&io->buf[SSH_APPGW_CIFS_MSDS_HEADER_LEN],
             SSH_APPGW_CIFS_PROTOCOL_ID,
             SSH_APPGW_CIFS_PROTOCOL_ID_LEN) == 0)
    {
      io->cifs_parser.packet_ptr =
        &io->buf[SSH_APPGW_CIFS_MSDS_HEADER_LEN];
      io->cifs_parser.packet_size =
        io->cifs_parser.transport.msds.packet_length;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_decode_header);
      return SSH_FSM_CONTINUE;
    }

  /* Drop the packet because we don't know what it is */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_drop_packet);
  return SSH_FSM_CONTINUE;
}


/* Sends the generated CIFS packet to CIFS client */
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_send_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  /* Encode MS-DS packet header */
  SSH_PUT_16BIT(&(io->buf[0]), 0);
  SSH_PUT_16BIT(&(io->buf[2]), io->cifs_parser.packet_size);

  io->bufpos = 0;
  io->data_in_buf = io->cifs_parser.packet_size +
                    SSH_APPGW_CIFS_MSDS_HEADER_LEN;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_write_to_src);
  return SSH_FSM_CONTINUE;
}


/* Sends the generated CIFS packet to server */
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_pass_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  /* Encode MS-DS packet header */
  SSH_PUT_16BIT(&(io->buf[0]), 0);
  SSH_PUT_16BIT(&(io->buf[2]), io->cifs_parser.packet_size);

  io->bufpos = 0;
  io->data_in_buf = io->cifs_parser.packet_size +
                    SSH_APPGW_CIFS_MSDS_HEADER_LEN;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_pass);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_msds_st_drop_packet)
{
  /* DROP the packet */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_drop);
  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
