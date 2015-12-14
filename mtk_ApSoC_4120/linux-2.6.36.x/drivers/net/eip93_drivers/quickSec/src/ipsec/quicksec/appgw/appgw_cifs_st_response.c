/*
 *
 * appgw_cifs_st_response.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * FSM state functions for filtering CIFS responses.
 *
 */

#include "sshincludes.h"
#include "sshgetput.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifsResponse"


/******************* Prototypes for static help functions *******************/


/***************** Prototypes for "private" state functions *****************/

SSH_FSM_STEP(ssh_appgw_cifs_st_broken_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_pipe_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_rpc_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_trans2_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_nt_transact_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_1st_trans2_response);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_complete);
SSH_FSM_STEP(ssh_appgw_cifs_st_response_filter_complete);

/************************** Static help functions ***************************/

static const unsigned char *
ssh_appgw_cifs_rpc_pdu_to_name(SshDceRpcPDUType pdu_type)
{
  switch (pdu_type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
      return (const unsigned char *)"REQUEST";
    case SSH_DCE_RPC_PDU_RESPONSE:
      return (const unsigned char *)"RESPONSE";
    case SSH_DCE_RPC_PDU_FAULT:
      return (const unsigned char *)"FAULT";
    case SSH_DCE_RPC_PDU_BIND:
      return (const unsigned char *)"BIND";
    case SSH_DCE_RPC_PDU_BIND_ACK:
      return (const unsigned char *)"BIND_ACK";
    case SSH_DCE_RPC_PDU_BIND_NAK:
      return (const unsigned char *)"BIND_NAK";
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
      return (const unsigned char *)"ALTER_CONTEXT";
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
      return (const unsigned char *)"ALTER_CONTEXT_RESPONSE";
    case SSH_DCE_RPC_PDU_AUTH3:
      return (const unsigned char *)"AUTH3";
    case SSH_DCE_RPC_PDU_SHUTDOWN:
      return (const unsigned char *)"SHUTDOWN";
    case SSH_DCE_RPC_PDU_CO_CANCEL:
      return (const unsigned char *)"CO_CANCEL";
    case SSH_DCE_RPC_PDU_ORPHANED:
      return (const unsigned char *)"ORPHANED";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


static const unsigned char *
ssh_appgw_cifs_rpc_uuid_to_name(SshDceRpcUUID uuid)
{
  static const SshDceRpcUUIDStruct srvsvc = SSH_DCE_RPC_UUID_SRVSVC;
  static const SshDceRpcUUIDStruct spoolss = SSH_DCE_RPC_UUID_SPOOLSS;
  static const SshDceRpcUUIDStruct samr = SSH_DCE_RPC_UUID_SAMR;
  static const SshDceRpcUUIDStruct wkssvc = SSH_DCE_RPC_UUID_WKSSVC;
  static const SshDceRpcUUIDStruct winreg = SSH_DCE_RPC_UUID_WINREG;

  if (uuid == NULL)
    return (const unsigned char *)"<NULL>";
  if (memcmp(uuid, &srvsvc, sizeof(*uuid)) == 0)
    return (const unsigned char *)"Microsoft Server Service";
  if (memcmp(uuid, &wkssvc, sizeof(*uuid)) == 0)
    return (const unsigned char *)"Microsoft Workstation Service";
  if (memcmp(uuid, &spoolss, sizeof(*uuid)) == 0)
    return (const unsigned char *)"Microsoft Spool Subsystem";
  if (memcmp(uuid, &samr, sizeof(*uuid)) == 0)
    return (const unsigned char *)"Microsoft Security Account Manager";
  if (memcmp(uuid, &winreg, sizeof(*uuid)) == 0)
    return (const unsigned char *)"Microsoft Registry";

  return (const unsigned char *)"<Unidentified>";
}


static void
ssh_appgw_cifs_log_fopen_event(SshAppgwCifsConn conn,
                               SshAppgwCifsParser cifs,
                               SshAppgwCifsTree tree,
                               SshAppgwCifsFileHandle file)
{
  char tmpbuf[1024];

  /* Currently we log only file/pipe/whatever open or create events having
     either write, delete or execute access. */
  if (file->write_access || file->delete_access || file->execute_access)
    {
      ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                   "file \"%s%s\" opened. Access mask=[%s%s%s%s%s ]",
                   tree->name, file->name,
                   (file->query_access == 1) ? " Query" : "",
                   (file->read_access == 1) ? " Read" : "",
                   (file->write_access == 1) ? " Write" : "",
                   (file->execute_access == 1) ? " Execute" : "",
                   (file->delete_access == 1) ? " Delete" : "");

      ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                            SSH_AUDIT_TXT, tmpbuf,
                            SSH_AUDIT_ARGUMENT_END);
    }
}


static void
ssh_appgw_cifs_log_rpc_response(SshAppgwCifsConn conn,
                                SshDceRpcPDU request,
                                SshDceRpcPDU response,
                                Boolean invalid)
{
  SshUInt8 pdu_type = response->header.packet_type;
  char tmpbuf[512];

  if (invalid)
    {
      ssh_snprintf(tmpbuf, sizeof(tmpbuf), "%s (%u)",
                   ssh_appgw_cifs_rpc_pdu_to_name(pdu_type),
                   pdu_type);

      ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Broken/unexpected DCE/RPC",
                            SSH_AUDIT_TXT,
                            tmpbuf,
                            SSH_AUDIT_ARGUMENT_END);
    }
  else
    {
      switch (pdu_type)
        {
        case SSH_DCE_RPC_PDU_BIND_ACK:
          {
            SshDceRpcBind bind = &request->pdu.bind;
            SshDceRpcUUID uuid = NULL;

            SSH_ASSERT(request->header.packet_type == SSH_DCE_RPC_PDU_BIND);

            if (bind->context_list.items >= 1)
              uuid = &(bind->context_list.list[0].abstract_syntax.if_uuid);

            ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                         "Client successfully bound  \\\\%@\\\"%s\"",
                         ssh_ipaddr_render,
                         &conn->ctx->responder_ip,
                         ssh_appgw_cifs_rpc_uuid_to_name(uuid));

            ssh_appgw_audit_event(conn->ctx,
                                  SSH_AUDIT_NOTICE,
                                  SSH_AUDIT_TXT,
                                  tmpbuf,
                                  SSH_AUDIT_ARGUMENT_END);
          }
          break;

        case SSH_DCE_RPC_PDU_BIND_NAK:
          {
            SshDceRpcBind bind = &request->pdu.bind;
            SshDceRpcUUID uuid = NULL;

            SSH_ASSERT(request->header.packet_type == SSH_DCE_RPC_PDU_BIND);

            if (bind->context_list.items >= 1)
              uuid = &(bind->context_list.list[0].abstract_syntax.if_uuid);

            ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                         "Client failed to bind to \\\\%@\\\"%s\"",
                         ssh_ipaddr_render,
                         &conn->ctx->responder_ip,
                         ssh_appgw_cifs_rpc_uuid_to_name(uuid));

            ssh_appgw_audit_event(conn->ctx,
                                  SSH_AUDIT_NOTICE,
                                  SSH_AUDIT_TXT,
                                  tmpbuf,
                                  SSH_AUDIT_ARGUMENT_END);
          }
          break;

        default:
          break;
        }
    }
}



/* Checks whether the SMB_COM_TRANSACTION2 response is valid */
static SshFSMStepCB
ssh_appgw_cifs_trans2_response_filter(SshAppgwCifsConn conn,
                                      SshAppgwCifsParser cifs,
                                      SshAppgwCifsTransaction trans2)
{
  static SshFSMStepCB continue_st = ssh_appgw_cifs_st_def_response_filter;
  static SshFSMStepCB broken_st = ssh_appgw_cifs_st_invalid_trans2_response;
  char tmpbuf[512];

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- subcommand = %s (0x%02X)",
            ssh_appgw_cifs_transact2_to_name(trans2->subcommand),
            trans2->subcommand));

  if (trans2->first_response)
    {
      switch (trans2->subcommand)
        {
        case SSH_SMB_TRANSACT2_OPEN2:
          if (trans2->server.total_param_count < 30)
            return broken_st;
          break;

        case SSH_SMB_TRANSACT2_FIND_FIRST2:
          if (trans2->server.total_param_count < 10)
            return broken_st;
          break;

        case SSH_SMB_TRANSACT2_FIND_NEXT2:
          if (trans2->server.total_param_count < 8)
            return broken_st;
          break;

        case SSH_SMB_TRANSACT2_CREATE_DIRECTORY:
          if (trans2->server.total_param_count < 2)
            return broken_st;
          break;

        case SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION:
          SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                    ssh_appgw_cifs_fs_info_level_to_name(trans2->info_level),
                    trans2->info_level));

          if (trans2->server.total_param_count != 0)
            return broken_st;

          switch (trans2->info_level)
            {
            case SSH_SMB_INFO_FS_ALLOCATION:
              if (trans2->server.total_data_count != 18)
                return broken_st;
              break;

            case SSH_SMB_INFO_FS_VOLUME:
              if (trans2->server.total_data_count < 5)
                return broken_st;
              break;

            case SSH_SMB_INFO_FS_QUERY_VOLUME_INFO:
              if (trans2->server.total_data_count < 18)
                return broken_st;
              break;

            case SSH_SMB_INFO_FS_QUERY_SIZE_INFO:
              if (trans2->server.total_data_count != 24)
                return broken_st;
              break;

            case SSH_SMB_INFO_FS_QUERY_DEVICE_INFO:
              if (trans2->server.total_data_count != 8)
                return broken_st;
              break;

            case SSH_SMB_INFO_FS_QUERY_ATTRIBUTE_INFO:
              if (trans2->server.total_data_count <= 12)
                return broken_st;
              break;

            default:
              /* Unknown information level */
              break;
            }
          break; /* SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION */

        case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
          SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                  trans2->info_level));

          switch (trans2->info_level)
            {
            case SSH_SMB_INFO_FILE_STANDARD:
            case SSH_SMB_INFO_FILE_QUERY_EA_SIZE:
              if (trans2->server.total_data_count != 26)
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_EAS_FROM_LIST:
            case SSH_SMB_INFO_FILE_QUERY_ALL_EAS:
              if ((trans2->server.total_param_count != 2) ||
                  (trans2->server.total_data_count < 4))
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_IS_NAME_VALID:
              if ((trans2->server.total_param_count != 0) ||
                  (trans2->server.total_data_count != 0))
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO:
            case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO2:
              if (trans2->server.total_data_count < 34)
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO:
            case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO2:
              if (trans2->server.total_data_count < 22)
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_EA_INFO:
            case SSH_SMB_INFO_FILE_QUERY_EA_INFO2:
              if (trans2->server.total_data_count < 4)
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_ALL_INFO:
            case SSH_SMB_INFO_FILE_QUERY_ALL_INFO2:
              if (trans2->server.total_data_count < 100)
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO2:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO2:
              if ((trans2->server.total_param_count != 2) ||
                  ((trans2->server.total_data_count != 0) &&
                   (trans2->server.total_data_count <= 4)))
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO:
            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO2:
              if ((trans2->server.total_param_count != 2) ||
                  ((trans2->server.total_data_count != 0) &&
                   (trans2->server.total_data_count <= 24)))
                return broken_st;
              break;

            case SSH_SMB_INFO_FILE_QUERY_COMPRESSION:
            case SSH_SMB_INFO_FILE_QUERY_COMPRESSION2:
              if (trans2->server.total_data_count < 14)
                return broken_st;
              break;

            default:
              /* Unsupported information_level */
              return continue_st;
            }
          break; /* SSH_SMB_TRANSACT2_QUERY_PATH(/FILE)_INFORMATION */

        case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
          SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                  trans2->info_level));
          /* Not implemented yet */
          break;

        case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
          if (trans2->server.total_data_count < 6)
            return broken_st;
          break;

        case SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY:
          /* No parameters or data bytes */
          break;

        case SSH_SMB_TRANSACT2_SESSION_SETUP:
          /* Not implemented yet */
          break;

        default:
          SSH_NOTREACHED;
          break;
        }
    }

  /* Check the parameter bytes */
  if ((trans2->server.param_count == trans2->server.total_param_count) &&
      (trans2->server.params != NULL) &&
      (trans2->response_params_checked == 0))
    {
      SshAppgwCifsFileHandle file;
      SshAppgwCifsSearchHandle search;
      const unsigned char *param_ptr = trans2->server.params;

      trans2->response_params_checked = 1;

      switch (trans2->subcommand)
        {
        case SSH_SMB_TRANSACT2_OPEN2:
          {
#ifdef DEBUG_LIGHT
            SshUInt16 attributes;
            SshUInt32 file_size;
            SshUInt16 granted_access;
            SshUInt16 file_type;
            SshUInt16 state;
            SshUInt16 action;
            SshUInt16 ea_error_offset;
            SshUInt32 ea_length;
#endif /* DEBUG_LIGHT */

            file = (SshAppgwCifsFileHandle)trans2->context;
            SSH_ASSERT(file != NULL);

            file->id = SSH_GET_16BIT_LSB_FIRST(param_ptr);
#ifdef DEBUG_LIGHT
            attributes = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
            /* skip creation time and date (2+2 bytes) */
            file_size = SSH_GET_32BIT_LSB_FIRST(param_ptr+8);
            granted_access = SSH_GET_16BIT_LSB_FIRST(param_ptr+12);
            file_type = SSH_GET_16BIT_LSB_FIRST(param_ptr+14);
            state = SSH_GET_16BIT_LSB_FIRST(param_ptr+16);
            action = SSH_GET_16BIT_LSB_FIRST(param_ptr+18);
            /* skip four reserved bytes */
            ea_error_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr+24);
            ea_length = SSH_GET_32BIT_LSB_FIRST(param_ptr+26);

            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));
            SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
            SSH_DEBUG(SSH_D_DATADUMP, ("- current_size = %lu", file_size));
            SSH_DEBUG(SSH_D_DATADUMP, ("- granted_access = 0x%04X",
                                      granted_access));
            SSH_DEBUG(SSH_D_DATADUMP, ("- file_type = 0x%04X", file_type));
            SSH_DEBUG(SSH_D_DATADUMP, ("- device_state = 0x%04X", state));
            SSH_DEBUG(SSH_D_DATADUMP, ("- action_taken = 0x%04X", action));
            SSH_DEBUG(SSH_D_DATADUMP, ("- ea_error_offset = %u",
                                      ea_error_offset));
            SSH_DEBUG(SSH_D_DATADUMP, ("- ea_length = %lu", ea_length));
#endif /* DEBUG_LIGHT */

            /* Add the file handle into our bookkeeping */
            ssh_appgw_cifs_file_handle_insert(file);

            /* Clear the context, so the file handle won't be freed when
               transaction context is deleted */
            trans2->context = NULL;

            ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);
          }
          break;

        case SSH_SMB_TRANSACT2_FIND_FIRST2:
          {
            SshUInt16 end_of_search;
#ifdef DEBUG_LIGHT
            SshUInt16 search_count;
            SshUInt16 ea_error_offset;
            SshUInt16 last_name_offset;
#endif /* DEBUG_LIGHT */

            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                ssh_appgw_cifs_search_info_level_to_name(trans2->info_level),
                trans2->info_level));

            search = (SshAppgwCifsSearchHandle)trans2->context;
            SSH_ASSERT(search != NULL);

            search->id = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            end_of_search = SSH_GET_16BIT_LSB_FIRST(param_ptr+4);
#ifdef DEBUG_LIGHT
            search_count = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
            ea_error_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr+6);
            last_name_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr+8);

            SSH_DEBUG(SSH_D_DATADUMP, ("- sid = 0x%04X", search->id));
            SSH_DEBUG(SSH_D_DATADUMP, ("- search_count = %u", search_count));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- end_of_search = %u", end_of_search));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- ea_error_offset = %u", ea_error_offset));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- last_name_offset = %u", last_name_offset));
#endif /* DEBUG_LIGHT */

            /* Add the handle into our bookkeeping */
            if ((search->close_after_request == 0) &&
                ((search->close_when_complete == 0) || (end_of_search == 0)))
              {
                ssh_appgw_cifs_search_handle_insert(search);
                trans2->context = NULL;
              }
          }
          break;

        case SSH_SMB_TRANSACT2_FIND_NEXT2:
          {
            SshUInt16 end_of_search;
#ifdef DEBUG_LIGHT
            SshUInt16 search_count;
            SshUInt16 ea_error_offset;
            SshUInt16 last_name_offset;
#endif /* DEBUG_LIGHT */

            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                ssh_appgw_cifs_search_info_level_to_name(trans2->info_level),
                trans2->info_level));

            search = (SshAppgwCifsSearchHandle)trans2->context;
            SSH_ASSERT(search != NULL);

            end_of_search = SSH_GET_16BIT_LSB_FIRST(param_ptr+4);
#ifdef DEBUG_LIGHT
            search_count = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
            ea_error_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr+6);
            last_name_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr+8);

            SSH_DEBUG(SSH_D_DATADUMP, ("- search_count = %u", search_count));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- end_of_search = %u", end_of_search));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- ea_error_offset = %u", ea_error_offset));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- last_name_offset = %u", last_name_offset));
#endif /* DEBUG_LIGHT */

            /* Add the handle into our bookkeeping */
            if ((search->close_after_request == 0) &&
                ((search->close_when_complete == 0) || (end_of_search == 0)))
              {
                ssh_appgw_cifs_search_handle_insert(search);
                trans2->context = NULL;
              }
          }
          break;

        case SSH_SMB_TRANSACT2_CREATE_DIRECTORY:
          {
#ifdef DEBUG_LIGHT
            SshUInt16 ea_error_offset;

            ea_error_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- ea_error_offset = %u", ea_error_offset));
#endif /* DEBUG_LIGHT */

            SSH_ASSERT(trans2->name != NULL);

            ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                         "Directory \"%s%s\" created",
                         cifs->tree->name, trans2->name);

            ssh_appgw_audit_event(conn->ctx,
                                  SSH_AUDIT_CIFS_OPERATION,
                                  SSH_AUDIT_TXT,
                                  tmpbuf,
                                  SSH_AUDIT_ARGUMENT_END);
          }
          break;

        case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
          /* Not implemented yet */
          break;

        case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
          switch (trans2->info_level)
            {
            case SSH_SMB_INFO_FILE_QUERY_EAS_FROM_LIST:
            case SSH_SMB_INFO_FILE_QUERY_ALL_EAS:
            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO2:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO2:
            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO:
            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO2:
#ifdef DEBUG_LIGHT
              {
                SshUInt16 ea_error_offset;

                ea_error_offset = SSH_GET_16BIT_LSB_FIRST(param_ptr);

                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- ea_error_offset = %u", ea_error_offset));
              }
#endif /* DEBUG_LIGHT */
              break;

            default:
              break;
            }
          break; /* SSH_SMB_TRANSACT2_QUERY_PATH(/FILE)_INFORMATION */

        case SSH_SMB_TRANSACT2_SESSION_SETUP:
          /* Not implemented yet */
          break;

        case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
          /* Not implemented yet */
          break;

        case SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY:
          /* No parameters, so we should not come here */
        default:
          SSH_NOTREACHED;
          break;
        }

      /* If we didn't copy the parameter bytes, we can't safely touch them
         any more */
      if (trans2->response_params_copied == 0)
        trans2->server.params = NULL;
    }

  /* Check the data bytes */
  if ((trans2->server.data_count == trans2->server.total_data_count) &&
      (trans2->server.data != NULL) &&
      (trans2->response_data_checked == 0))
    {
#ifdef DEBUG_LIGHT
      SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx) conn->ctx->user_context;
#endif /* DEBUG_LIGHT */
      const unsigned char *data_ptr = trans2->server.data;
      size_t data_len = trans2->server.data_count;

      trans2->response_data_checked = 1;

      switch (trans2->subcommand)
        {
        case SSH_SMB_TRANSACT2_FIND_FIRST2:
        case SSH_SMB_TRANSACT2_FIND_NEXT2:
          /* Not implemented */
          break;

        case SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION:
          switch (trans2->info_level)
            {
            case SSH_SMB_INFO_FS_ALLOCATION:
#ifdef DEBUG_LIGHT
              {
                SshUInt32 fs_id;
                SshUInt32 sectors;
                SshUInt32 total;
                SshUInt32 available;
                SshUInt32 sector_size;

                fs_id = SSH_GET_32BIT_LSB_FIRST(data_ptr);
                sectors = SSH_GET_32BIT_LSB_FIRST(data_ptr+4);
                total = SSH_GET_32BIT_LSB_FIRST(data_ptr+8);
                available = SSH_GET_32BIT_LSB_FIRST(data_ptr+12);
                sector_size = SSH_GET_32BIT_LSB_FIRST(data_ptr+16);

                SSH_DEBUG(SSH_D_DATADUMP, ("- file_system_id = %lu", fs_id));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- sectors_per_allocation_unit = %lu", sectors));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- total_allocation_units = %lu", total));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- allocation_units_available = %lu", available));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- bytes_per_sector = %u",
			   (unsigned int) sector_size));
              }
#endif /* DEBUG_LIGHT */
              break;

            case SSH_SMB_INFO_FS_VOLUME:
              {
#ifdef DEBUG_LIGHT
                SshUInt32 serial_num;
                char *label;
#endif /* DEBUG_LIGHT */
                SshUInt8 chars_in_label;

#ifdef DEBUG_LIGHT
                serial_num = SSH_GET_32BIT_LSB_FIRST(data_ptr);
#endif /* DEBUG_LIGHT */
                chars_in_label = SSH_GET_8BIT(data_ptr+4);

                data_ptr += 5;
                data_len -= 5;

                if (data_len < chars_in_label)
                  return broken_st;

#ifdef DEBUG_LIGHT
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- volume_serial_number = %lu", serial_num));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- characters_in_label = %u", chars_in_label));

                label = ssh_appgw_cifs_strdup(cifs_alg,
                                              SSH_APPGW_CIFS_DATA_BLOCK,
                                              data_ptr, data_len,
                                              cifs->unicode_strings);
                if (label != NULL)
                  {
                    SSH_DEBUG(SSH_D_DATADUMP, ("- label = \"%s\"", label));
                    ssh_free(label);
                  }
#endif /* DEBUG_LIGHT */
              }
              break;

            case SSH_SMB_INFO_FS_QUERY_VOLUME_INFO:
              {
#ifdef DEBUG_LIGHT
                SshUInt64 created;
                SshUInt32 serial_num;
                char *label;
#endif /* DEBUG_LIGHT */
                SshUInt32 label_len;

#ifdef DEBUG_LIGHT
                created = SSH_GET_64BIT_LSB_FIRST(data_ptr);
                serial_num = SSH_GET_32BIT_LSB_FIRST(data_ptr+8);
#endif /* DEBUG_LIGHT */
                label_len = SSH_GET_32BIT_LSB_FIRST(data_ptr+12);
                /* skip two reserved bytes */

                data_ptr += 18;
                data_len -= 18;

                if (data_len < label_len)
                  return broken_st;

#ifdef DEBUG_LIGHT
                SSH_DEBUG(SSH_D_DATADUMP, ("- creation_time = %qu", created));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- serial_number = %lu", serial_num));
                SSH_DEBUG(SSH_D_DATADUMP, ("- label_len = %lu", label_len));

                label = ssh_appgw_cifs_strdup(cifs_alg,
                                              SSH_APPGW_CIFS_DATA_BLOCK,
                                              data_ptr, data_len,
                                              cifs->unicode_strings);
                if (label != NULL)
                  {
                    SSH_DEBUG(SSH_D_DATADUMP, ("- label = \"%s\"", label));
                    ssh_free(label);
                  }
#endif /* DEBUG_LIGHT */
              }
              break;

            case SSH_SMB_INFO_FS_QUERY_SIZE_INFO:
#ifdef DEBUG_LIGHT
              {
                SshUInt64 total_units;
                SshUInt64 free_units;
                SshUInt32 sectors;
                SshUInt32 bytes;

                total_units = SSH_GET_64BIT_LSB_FIRST(data_ptr);
                free_units = SSH_GET_64BIT_LSB_FIRST(data_ptr+8);
                sectors = SSH_GET_32BIT_LSB_FIRST(data_ptr+16);
                bytes = SSH_GET_32BIT_LSB_FIRST(data_ptr+20);

                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- total_allocation_units = %qu", total_units));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- free_allocation_units = %qu", free_units));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- sectors_per_unit = %lu", sectors));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- bytes_per_sector = %lu", bytes));
              }
#endif /* DEBUG_LIGHT */
              break;

            case SSH_SMB_INFO_FS_QUERY_DEVICE_INFO:
#ifdef DEBUG_LIGHT
              {
                SshUInt32 device_type;
                SshUInt32 characteristics;

                device_type = SSH_GET_32BIT_LSB_FIRST(data_ptr);
                characteristics = SSH_GET_32BIT_LSB_FIRST(data_ptr+4);

                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- device_type = 0x%08lX",
			   (unsigned long) device_type));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- characteristics = 0x%08lX",
			   (unsigned long) characteristics));
              }
#endif /* DEBUG_LIGHT */
              break;

            case SSH_SMB_INFO_FS_QUERY_ATTRIBUTE_INFO:
              {
#ifdef DEBUG_LIGHT
                char * fs_name;
                SshUInt32 fs_attr;
                SshUInt32 max_name_len;
#endif /* DEBUG_LIGHT */
                SshUInt32 fs_name_len;

#ifdef DEBUG_LIGHT
                fs_attr = SSH_GET_32BIT_LSB_FIRST(data_ptr);
                max_name_len = SSH_GET_32BIT_LSB_FIRST(data_ptr+4);
#endif /* DEBUG_LIGHT */
                fs_name_len = SSH_GET_32BIT_LSB_FIRST(data_ptr+8);

                data_ptr += 12;
                data_len -= 12;

                if (fs_name_len > data_len)
                  return broken_st;

#ifdef DEBUG_LIGHT
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- file_system_attributes = 0x%08lX",
			   (unsigned long) fs_attr));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- max_filename_len = %lu", max_name_len));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- file_system_name_len = %lu", fs_name_len));

                fs_name = ssh_appgw_cifs_strdup(cifs_alg,
                                                SSH_APPGW_CIFS_DATA_BLOCK,
                                                data_ptr, data_len,
                                                cifs->unicode_strings);
                if (fs_name != NULL)
                  {
                    SSH_DEBUG(SSH_D_DATADUMP,
                              ("- file_system = \"%s\"", fs_name));

                    ssh_free(fs_name);
                  }
#endif /* DEBUG_LIGHT */
              }
              break;

            default:
              /* Unknown information_level */
              break;
          }
          break; /* SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION */

        case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
          /* Not implemented yet */
          break;

        case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
        case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
          switch (trans2->info_level)
            {
            case SSH_SMB_INFO_FILE_QUERY_EAS_FROM_LIST:
            case SSH_SMB_INFO_FILE_QUERY_ALL_EAS:
              {
                SshUInt32 list_length;

                list_length = SSH_GET_32BIT_LSB_FIRST(data_ptr);

                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- list_length = %u",
			   (unsigned int) list_length));

                if (list_length < trans2->server.total_data_count-4)
                  return broken_st;
              }
              break;

            case SSH_SMB_INFO_FILE_QUERY_EA_INFO:
            case SSH_SMB_INFO_FILE_QUERY_EA_INFO2:
#ifdef DEBUG_LIGHT
              {
                SshUInt32 ea_size;

                ea_size = SSH_GET_32BIT_LSB_FIRST(data_ptr);

                SSH_DEBUG(SSH_D_DATADUMP, ("- ea_size = %lu", ea_size));
              }
#endif /* DEBUG_LIGHT */
              break;

            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_NAME_INFO2:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO:
            case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO2:
              {
                SshUInt32 name_len;
#ifdef DEBUG_LIGHT
                char *name;
#endif /* DEBUG_LIGHT */

                name_len = SSH_GET_32BIT_LSB_FIRST(data_ptr);

                data_ptr += 4;
                data_len -= 4;

                if (name_len > data_len)
                  return broken_st;

#ifdef DEBUG_LIGHT
                SSH_DEBUG(SSH_D_DATADUMP, ("- name_len = %lu", name_len));

                name = ssh_appgw_cifs_strdup(cifs_alg,
                                             SSH_APPGW_CIFS_DATA_BLOCK,
                                             data_ptr, data_len,
                                             cifs->unicode_strings);
                if (name != NULL)
                  {
                    SSH_DEBUG(SSH_D_DATADUMP,
                              ("- file_name: = \"%s\"", name));

                    ssh_free(name);
                  }
#endif /* DEBUG_LIGHT */
              }
              break;

            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO:
            case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO2:
              {
                SshUInt32 name_len;
#ifdef DEBUG_LIGHT
                SshUInt32 next_entry;
                SshUInt64 stream_size;
                SshUInt64 alloc_size;
                char *stream_name;

                next_entry = SSH_GET_32BIT_LSB_FIRST(data_ptr);
#endif /* DEBUG_LIGHT */
                name_len = SSH_GET_32BIT_LSB_FIRST(data_ptr+4);
#ifdef DEBUG_LIGHT
                stream_size = SSH_GET_64BIT_LSB_FIRST(data_ptr+8);
                alloc_size = SSH_GET_64BIT_LSB_FIRST(data_ptr+16);
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- next_entry_offset = %lu", next_entry));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- stream_name_length = %lu", name_len));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- stream_size = %qu", stream_size));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- allocated_size = %qu", alloc_size));
#endif /* DEBUG_LIGHT */

                data_ptr += 24;
                data_len -= 24;

                if (name_len > data_len)
                  return broken_st;

#ifdef DEBUG_LIGHT
                stream_name = ssh_appgw_cifs_strdup(cifs_alg,
                                                SSH_APPGW_CIFS_DATA_BLOCK,
                                                data_ptr, data_len,
                                                cifs->unicode_strings);
                if (stream_name != NULL)
                  {
                    SSH_DEBUG(SSH_D_DATADUMP,
                              ("- stream_name: = \"%s\"", stream_name));

                    ssh_free(stream_name);
                  }
#endif /* DEBUG_LIGHT */
              }
              break;

            case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO:
            case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO2:
              /* Not implemented */
              break;

            case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO:
            case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO2:
              /* Not implemented */
              break;

            case SSH_SMB_INFO_FILE_QUERY_ALL_INFO:
            case SSH_SMB_INFO_FILE_QUERY_ALL_INFO2:
              /* Not implemented */
              break;

            case SSH_SMB_INFO_FILE_QUERY_COMPRESSION:
            case SSH_SMB_INFO_FILE_QUERY_COMPRESSION2:
#ifdef DEBUG_LIGHT
              {
                SshUInt64 size;
                SshUInt16 format;
                SshUInt8 unit_shift;
                SshUInt8 chunk_shift;
                SshUInt8 cluster_shift;

                size = SSH_GET_64BIT_LSB_FIRST(data_ptr);
                format = SSH_GET_16BIT_LSB_FIRST(data_ptr+8);
                unit_shift = SSH_GET_8BIT(data_ptr+10);
                chunk_shift = SSH_GET_8BIT(data_ptr+11);
                cluster_shift = SSH_GET_8BIT(data_ptr+12);
                /* skip 3 reserved bytes */

                SSH_DEBUG(SSH_D_DATADUMP, ("- compressed_size = %qu", size));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- compression_format = %u", format));
                SSH_DEBUG(SSH_D_DATADUMP, ("- unit_shift = %u", unit_shift));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- chunk_shift = %u", chunk_shift));
                SSH_DEBUG(SSH_D_DATADUMP,
                          ("- cluster_shift = %u", cluster_shift));
              }
#endif /* DEBUG_LIGHT */
              break;

            default:  /* Unsupported information_level */
              return broken_st;
            }
          break; /* SSH_SMB_TRANSACT2_QUERY_PATH(/FILE)_INFORMATION */

        case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
#ifdef DEBUG_LIGHT
          {
            SshUInt16 path_consumed;
            SshUInt16 num_referrals;
            SshUInt16 flags;

            path_consumed = SSH_GET_16BIT_LSB_FIRST(data_ptr);
            num_referrals = SSH_GET_16BIT_LSB_FIRST(data_ptr+2);
            flags = SSH_GET_16BIT_LSB_FIRST(data_ptr+4);

            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- path_consumed = %u", path_consumed));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- number_of_referrals = %u", num_referrals));
            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
          }
#endif /* DEBUG_LIGHT */
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      /* If we didn't copy the data bytes, we can't touch them any more */
      if (trans2->response_data_copied == 0)
        trans2->server.data = NULL;
    }

  return continue_st;
}


/* Checks whether the SMB_COM_NT_TRANSACTION response is valid */
static SshFSMStepCB
ssh_appgw_cifs_nt_transact_response_filter(SshAppgwCifsConn conn,
                                           SshAppgwCifsParser cifs,
                                           SshAppgwCifsTransaction transact)
{
  static SshFSMStepCB continue_st = ssh_appgw_cifs_st_def_response_filter;
  static SshFSMStepCB broken_st = ssh_appgw_cifs_st_invalid_nt_transact_resp;
  static SshFSMStepCB invalid_h_st
                        = ssh_appgw_cifs_st_invalid_nt_transact_resp;
  char tmpbuf[512];

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- function = %s (0x%02X)",
            ssh_appgw_cifs_nt_transact_to_name(transact->subcommand),
            transact->subcommand));

  if (transact->first_response)
    {
      SshAppgwCifsFileHandle file;
      SshUInt16 setup_count = cifs->word_count - 18;
      const unsigned char *setup_ptr = NULL;

      if (setup_count)
        setup_ptr = (const unsigned char *)cifs->parameters + 36;

      switch (transact->subcommand)
        {
        case SSH_SMB_NT_TRANSACT_CREATE:
          if (transact->server.total_param_count < 69)
            return broken_st;
          break;

        case SSH_SMB_NT_TRANSACT_IOCTL:
          if ((transact->server.total_param_count != 0) ||
              (ssh_appgw_cifs_file_handle_lookup(conn,
                                                 transact->fid) == NULL))
            return broken_st;

#ifdef DEBUG_LIGHT
          if (setup_count == 1)
            {
              SshUInt16 length;

              length = SSH_GET_16BIT_LSB_FIRST(setup_ptr);

              SSH_DEBUG(SSH_D_DATADUMP, ("- length = %u", length));
            }
#endif /* DEBUG_LIGHT */
          break;

        case SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE:
          if (ssh_appgw_cifs_file_handle_lookup(conn, transact->fid) == NULL)
            return broken_st;
          break;

        case SSH_SMB_NT_TRANSACT_RENAME:
          /* Not implemented */
          break;

        case SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC:
          if (transact->server.total_param_count != 4)
            return broken_st;
          if (ssh_appgw_cifs_file_handle_lookup(conn, transact->fid) == NULL)
            return invalid_h_st;
          break;

        case SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC:
          if ((transact->server.total_param_count != 0) ||
              (transact->server.total_data_count != 0))
            return broken_st;

          file = ssh_appgw_cifs_file_handle_lookup(conn, transact->fid);
          if (file == NULL)
            return invalid_h_st;

          ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                       "Security descriptor of \"%s%s\" modified.",
                       cifs->tree->name, file->name);

          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_CIFS_OPERATION,
                                SSH_AUDIT_TXT,
                                tmpbuf,
                                SSH_AUDIT_ARGUMENT_END);
          break;

        default:
          return broken_st;
        }
    }

  /* Check the parameter bytes */
  if ((transact->server.param_count == transact->server.total_param_count) &&
      (transact->server.params != NULL) &&
      (transact->response_params_checked == 0))
    {
      SshAppgwCifsFileHandle file;
      const unsigned char *param_ptr = transact->server.params;

      transact->response_params_checked = 1;

      switch (transact->subcommand)
        {
        case SSH_SMB_NT_TRANSACT_CREATE:
          {
#ifdef DEBUG_LIGHT
            SshUInt8 oplock_level;
            SshUInt32 create_action;
            SshUInt32 ea_error_offset;
            SshUInt32 attributes;
            SshUInt64 alloc_size;
            SshUInt64 end_of_file;
            SshUInt16 file_type;
            SshUInt16 device_state;
            SshUInt16 is_directory;
#endif /* DEBUG_LIGHT */

            file = transact->context;
            SSH_ASSERT(file != NULL);

#ifdef DEBUG_LIGHT
            oplock_level = SSH_GET_8BIT(param_ptr);
#endif /* DEBUG_LIGHT */
            /* skip one reserved byte */
            file->id = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
#ifdef DEBUG_LIGHT
            create_action = SSH_GET_32BIT_LSB_FIRST(param_ptr+4);
            ea_error_offset = SSH_GET_32BIT_LSB_FIRST(param_ptr+8);
            /* skip creation, access, write and change times (32 bytes) */
            attributes = SSH_GET_32BIT_LSB_FIRST(param_ptr+44);
            alloc_size = SSH_GET_64BIT_LSB_FIRST(param_ptr+48);
            end_of_file = SSH_GET_64BIT_LSB_FIRST(param_ptr+56);
            file_type = SSH_GET_16BIT_LSB_FIRST(param_ptr+64);
            device_state = SSH_GET_16BIT_LSB_FIRST(param_ptr+66);
            is_directory = SSH_GET_16BIT_LSB_FIRST(param_ptr+68);

            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- oplock_level = %u", oplock_level));
            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- create_action = 0x%08lX",
		       (unsigned long) create_action));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- attributes = 0x%08lX",
		       (unsigned long) attributes));
#endif /* DEBUG_LIGHT */

            ssh_appgw_cifs_file_handle_insert(file);

            transact->context = NULL;

            ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);
          }
          break;

        case SSH_SMB_NT_TRANSACT_IOCTL:
          /* No parameters */
          break;

        case SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE:
          /* Not implemented */
          if (ssh_appgw_cifs_file_handle_lookup(conn, transact->fid) == NULL)
            return invalid_h_st;
          break;

        case SSH_SMB_NT_TRANSACT_RENAME:
          /* Not implemented */
          break;

        case SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC:
          if (ssh_appgw_cifs_file_handle_lookup(conn, transact->fid) == NULL)
            {
              return invalid_h_st;
            }
          else
            {
              SshUInt32 sd_len;

              sd_len = SSH_GET_32BIT_LSB_FIRST(param_ptr);

              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- security_descriptor_length = %lu", sd_len));

              if (transact->server.total_data_count < sd_len)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("Invalid Security Descriptor length!"));

                  return broken_st;
                }
            }
          break;

        case SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC:
          /* No parameters */
          break;

        default:
          return broken_st;
        }
    }

  return continue_st;
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_st_response_out_of_mem)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_WARNING,
                        SSH_AUDIT_TXT,
                        "Running low on memory. Sending error response.",
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_out_of_memory);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_broken_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Broken response!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_pipe_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Invalid named pipe response!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Unexpected response!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NEGOTIATE response from server */
SSH_FSM_STEP(ssh_appgw_cifs_st_negotiate_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const unsigned char *params = cifs->parameters;
  const unsigned char *data = cifs->buffer;
  size_t data_len = cifs->byte_count;
  SshAppgwCifsNegotiateCtx negotiate_ctx;
  SshUInt16 selected_dialect;
  SshUInt16 security_mode;
  SshUInt16 max_mpx_count = 1;
  SshUInt16 max_vcs = 0;
  SshUInt32 key_len = 0;
  SshUInt32 max_buffer_size;
#ifdef DEBUG_LIGHT
  SshUInt32 session_key;
#endif /* DEBUG_LIGHT */
  SshUInt16 time_zone = 0;
  SshUInt32 capabilities;

  /* Check whether negotiation succeeded */
  if (cifs->command_failed)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "CIFS dialect negotiation failed!",
                            SSH_AUDIT_ARGUMENT_END);

      conn->session_phase = SSH_APPGW_CIFS_SESSION_CLOSED;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count >= 1);

  negotiate_ctx = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(negotiate_ctx != NULL);

  selected_dialect = SSH_GET_16BIT_LSB_FIRST(params);

  if (selected_dialect >= negotiate_ctx->dialect_count)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Invalid dialect index specified in "
                            "SMB_COM_NEGOTIATE response!",
                            SSH_AUDIT_ARGUMENT_END);

      /* Drop the original response and send a new error response to client */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(negotiate_ctx->dialect_ptrs[selected_dialect] != NULL);

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_NOTICE,
                        SSH_AUDIT_TXT,
                        "CIFS dialect negotiated.",
                        SSH_AUDIT_CIFS_DIALECT,
                        negotiate_ctx->dialect_ptrs[selected_dialect],
                        SSH_AUDIT_ARGUMENT_END);

  switch (cifs->word_count)
    {
    case 1: /* "PC NETWORK PROGRAM 1.0" */
      /* We don't accept connections which do not specify even the minimum
         level of security. Drop the original response and send a new error
         response to client */
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT, "Rejected negotiation of protocol",
                            SSH_AUDIT_CIFS_DIALECT,
                            negotiate_ctx->dialect_ptrs[selected_dialect],
                            SSH_AUDIT_ARGUMENT_END);

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;

    case 13: /* <= "LANMAN2.1" */
      security_mode = SSH_GET_16BIT_LSB_FIRST(params+2);
      max_buffer_size = SSH_GET_16BIT_LSB_FIRST(params+4);
      max_mpx_count = SSH_GET_16BIT_LSB_FIRST(params+6);
      max_vcs = SSH_GET_16BIT_LSB_FIRST(params+8);
      /* skip rawmodes (we'll disable them) */
#ifdef DEBUG_LIGHT
      session_key = SSH_GET_32BIT_LSB_FIRST(params+12);
#endif /* DEBUG_LIGHT */
      /* skip server time (2 bytes) */
      /* skip server date (2 bytes) */
      time_zone = SSH_GET_16BIT_LSB_FIRST(params+20);
      key_len = SSH_GET_16BIT_LSB_FIRST(params+22);

      if (key_len == 0)
        conn->cifs_version = SSH_APPGW_CIFS_VERSION_CORE_PLUS;
      else
        conn->cifs_version = SSH_APPGW_CIFS_VERSION_LANMAN;

      /* Limit the buffer size */
      if (max_buffer_size > conn->max_buffer_size)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Maximum buffer size limited to %u (was %u)",
		     (unsigned int) conn->max_buffer_size,
		     (unsigned int) max_buffer_size));

          max_buffer_size = conn->max_buffer_size;
          SSH_PUT_16BIT_LSB_FIRST(params+4, max_buffer_size);
        }

      /* Disable raw mode (SMB_COM_READ_RAW and SMB_COM_WRITE_RAW) */
      SSH_PUT_32BIT_LSB_FIRST(params+10, 0);
      break;

    case 17: /* "NT LM 0.12" */
      security_mode = SSH_GET_8BIT(params+2);
      max_mpx_count = SSH_GET_16BIT_LSB_FIRST(params+3);
      max_vcs = SSH_GET_16BIT_LSB_FIRST(params+5);
      max_buffer_size = SSH_GET_32BIT_LSB_FIRST(params+7);
      /* skip max_raw_size (4 bytes) */
#ifdef DEBUG_LIGHT
      session_key = SSH_GET_32BIT_LSB_FIRST(params+15);
#endif /* DEBUG_LIGHT */
      capabilities = SSH_GET_32BIT_LSB_FIRST(params+19);
      /* skip UTC time of the server (8 bytes) */
      time_zone = SSH_GET_16BIT_LSB_FIRST(params+31);
      key_len = SSH_GET_8BIT(params+33);

      SSH_DEBUG(SSH_D_DATADUMP,
                ("- capabilities (original) = 0x%08lX",
		 (unsigned long) capabilities));

      /* Disable raw and multiplex modes (SMB_COM_READ_RAW, SMB_COM_WRITE_RAW,
         SMB_COM_READ_MPX and SMB_COM_WRITE_MPX) as well as bulk transfer,
         because our application gateway doesn't currently support these
         features. */
      capabilities &= 0xFFFF3FFC;
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- capabilities (modified) = 0x%08lX",
		 (unsigned long) capabilities));

      SSH_DEBUG(SSH_D_DATADUMP, ("- encryption_key_length = %u",
				 (unsigned int) key_len));

      conn->cifs_version = SSH_APPGW_CIFS_VERSION_NTLM;

      if (capabilities & 0x00000004)
        conn->server_flags.unicode = 1;

      if (capabilities & 0x00000008)
        conn->server_flags.large_files = 1;

      if (capabilities & 0x00000010)
        conn->server_flags.nt_smbs = 1;

      if (capabilities & 0x00000020)
        conn->server_flags.rpc = 1;

      if (capabilities & 0x00000040)
        conn->server_flags.nt_error_codes = 1;

      if (capabilities & 0x80000000)
        conn->server_flags.ext_security = 1;

      /* Limit the maximum buffer size */
      if (max_buffer_size > conn->max_buffer_size)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Maximum buffer size limited to %u (was %u)",
		     (unsigned int) conn->max_buffer_size,
		     (unsigned int) max_buffer_size));

          max_buffer_size = conn->max_buffer_size;
          SSH_PUT_16BIT_LSB_FIRST(params+7, max_buffer_size);
        }

      SSH_PUT_32BIT_LSB_FIRST(params+11, 0); /* max_raw_size */
      SSH_PUT_32BIT_LSB_FIRST(params+19, capabilities);
      break;

    default:
      conn->session_phase = SSH_APPGW_CIFS_SESSION_CLOSED;

      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Unsupported SMB_COM_NEGOTIATE response",
                            SSH_AUDIT_ARGUMENT_END);

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_DATADUMP, ("- session_key = %lu", session_key));
  SSH_DEBUG(SSH_D_DATADUMP, ("- security_mode = 0x%04X", security_mode));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_buffer_size = %lu",
			     (unsigned long) max_buffer_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_multiplex_count = %u",
			     (unsigned int) max_mpx_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_virtual_circuits = %u",
			     (unsigned int) max_vcs));

  /* Check server's time zone */
  if (time_zone == 0)
    SSH_DEBUG(SSH_D_DATADUMP, ("- time_zone = UTC"));
  if (time_zone < (24*60))
    SSH_DEBUG(SSH_D_DATADUMP,
              ("- time_zone = UTC + %d hours", time_zone/60));
  else if ((0x10000-time_zone) < (24*60))
    SSH_DEBUG(SSH_D_DATADUMP,
              ("- time_zone = UTC - %d hours", (0x10000-time_zone)/60));
  else
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Server specified an invalid time zone!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  /* Check the encryption key */
  if ((key_len > 0) &&
      (key_len != data_len)) /* Samba 3.0 interoperabitity fix */
    {
      if (key_len > data_len)
        {
          SshUInt8 tmpbuf[4];

          SSH_PUT_32BIT(tmpbuf, key_len);

          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "CIFS server specified invalid encryption "
                                "key length",
                                SSH_AUDIT_KEY_LENGTH, key_len, 4,
                                SSH_AUDIT_ARGUMENT_END);

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          return SSH_FSM_CONTINUE;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("- encryption_key (%u bytes):",
			 (unsigned int) key_len),
                        data, key_len);

      data += key_len; 
      data_len -= key_len; 
    }

  if (conn->server_flags.ext_security)
    {
#ifdef DEBUG_LIGHT
      SshUInt32 guid_data1;
      SshUInt16 guid_data2;
      SshUInt16 guid_data3;
#endif /* DEBUG_LIGHT */

      /* Check that there is enough bytes for GUID and security BLOB */
      if (data_len < 16)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          return SSH_FSM_CONTINUE;
        }

#ifdef DEBUG_LIGHT
      guid_data1 = SSH_GET_32BIT_LSB_FIRST(data);
      guid_data2 = SSH_GET_16BIT_LSB_FIRST(data+4);
      guid_data3 = SSH_GET_16BIT_LSB_FIRST(data+6);

      SSH_DEBUG(SSH_D_DATADUMP,
                ("- Server_GUID = "
                 "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		 (unsigned long) guid_data1, guid_data2, guid_data3,
		 data[8], data[9],
		 data[10], data[11], data[12], data[13], data[14], data[15]));

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("- Security BLOB (%d bytes)", data_len-16),
                        data+16, data_len-16);
#endif /* DEBUG_LIGHT */
    }
  else
    {
      size_t str_size;

      /* Check the length of OEM domain name */
      if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                                 data, data_len,
                                 cifs->unicode_strings) == FALSE)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          return SSH_FSM_CONTINUE;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("- OEM_domain_name:"), data, data_len);
    }

  if (security_mode & 0x0001)
    {
      conn->user_level_security = 1;

      if (security_mode & 0x0002)
        conn->use_encrypted_passwords = 1;
      else
        {
          /* To block potential SMB downgrade attack, we don't ever accept
             negotiation of CIFS connections using clear text passwords */
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Rejected negotiation of CIFS connection "
                                "because cleartext passwords specified",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          return SSH_FSM_CONTINUE;
        }

      if (security_mode & 0x0004)
        {
          char tmpbuf[256];

          conn->security_signatures_enabled = 1;

          if (security_mode & 0x0008)
            conn->security_signatures_required = 1;

          ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                       "Negotiated user level security with %s passwords"
                       " and %s security signatures.",
                       (conn->use_encrypted_passwords == 1) ?
                       "encrypted" : "clear text",
                       (conn->security_signatures_required == 1) ?
                       "required" : "optional");


          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT,
                                tmpbuf,
                                SSH_AUDIT_ARGUMENT_END);
        }
      else
        {
          char tmpbuf[256];

          ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                       "Negotiated user level security with %s passwords",
                       (conn->use_encrypted_passwords == 1) ?
                       "encrypted" : "clear text");

          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT,
                                tmpbuf,
                                SSH_AUDIT_ARGUMENT_END);
        }
    }
  else
    {
      if (security_mode & 0x0002)
        conn->use_challenge_response = 1;
      else
        {
          /* To block potential SMB downgrade attack, we don't ever accept
             negotiation of CIFS connections using clear text passwords */
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Rejected negotiation of CIFS connection "
                                "because cleartext passwords specified",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          return SSH_FSM_CONTINUE;
        }

      {
        char tmpbuf[256];

        ssh_snprintf(tmpbuf, sizeof(tmpbuf),
                     "Negotiated share level security %s "
                     "challenge/response authentication",
                     (conn->use_challenge_response == 1) ? "with" : "without");



        ssh_appgw_audit_event(conn->ctx,
                              SSH_AUDIT_NOTICE,
                              SSH_AUDIT_TXT,
                              tmpbuf,
                              SSH_AUDIT_ARGUMENT_END);
      }
    }

  if (conn->max_pending_requests < max_mpx_count)
    conn->max_pending_requests = max_mpx_count;

  if (conn->max_sessions < (max_vcs+1))
    conn->max_sessions = max_vcs+1;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing authentication..."));

  conn->session_phase = SSH_APPGW_CIFS_SESSION_AUTHENTICATING;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_SESSION_SETUP_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_session_setup_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsSession session;
  const unsigned char *params = cifs->parameters;
  const unsigned char *ucp;
#ifdef DEBUG_LIGHT
  SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx) conn->ctx->user_context;
  char *domain = NULL;
  char *native_os = NULL;
  char *lan_man = NULL;
#endif /* DEBUG_LIGHT */
  size_t str_size;
  size_t buff_size;
  SshUInt16 action;
  SshUInt16 security_blob_len = 0;

  SSH_ASSERT(cifs->orig_request != NULL);
  cifs->orig_request->more_processing = 0;

  session = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(session != NULL);

  if (cifs->command_failed)
    {
      if ((cifs->nt_error_codes) &&
          (cifs->error.nt.error_code == SSH_APPGW_CIFS_E_MORE_PROCESSING))
        {
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT,
                                "extended authentication required",
                                SSH_AUDIT_ARGUMENT_END);

          session->ext_authentication = 1;
          cifs->orig_request->more_processing = 1;
        }
      else
        {
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT,
                                "session rejected by server!",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
          return SSH_FSM_CONTINUE;
        }
    }

  if (((session->ext_authentication == 1) && (cifs->word_count != 4)) ||
      ((session->ext_authentication == 0) && (cifs->word_count != 3)))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* skip ANDX block (4 bytes) */
  action = SSH_GET_16BIT_LSB_FIRST(params+4);
  SSH_DEBUG(SSH_D_DATADUMP, ("- action = 0x%04X", action));

  ucp = cifs->buffer;
  buff_size = cifs->byte_count;

  if (cifs->word_count == 4)
    {
      security_blob_len = SSH_GET_16BIT_LSB_FIRST(params+6);

      SSH_DEBUG(SSH_D_DATADUMP,
                ("- security_blob_len = 0x%04X", security_blob_len));

      if (security_blob_len > cifs->byte_count)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("- security_blob:"),
                        cifs->buffer, security_blob_len);

      ucp += security_blob_len;
      buff_size -= security_blob_len;
    }

  /* Native OS */
  if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                             ucp, buff_size, cifs->unicode_strings) == FALSE)
    goto session_resp_broken;

  if (str_size > 0)
    {
#ifdef DEBUG_LIGHT
      native_os = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                        ucp, buff_size,
                                        cifs->unicode_strings);
      if (native_os == NULL)
        goto session_resp_out_of_mem;
#endif /* DEBUG_LIGHT */

      ucp += str_size;
      buff_size -= str_size;
    }

  /* Native LAN manager */
  if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                             ucp, buff_size, cifs->unicode_strings) == FALSE)
    goto session_resp_broken;

  if (str_size > 0)
    {
#ifdef DEBUG_LIGHT
      lan_man = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                      ucp, buff_size, cifs->unicode_strings);
      if (lan_man == NULL)
        goto session_resp_out_of_mem;
#endif /* DEBUG_LIGHT */

      ucp += str_size;
      if (buff_size > str_size)
        buff_size -= str_size;
      else
        {
          if (session->ext_authentication)
            buff_size = 0;
          else
            goto session_resp_broken;
        }
    }

  /* Primary domain */
  if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                             ucp, buff_size, cifs->unicode_strings) == FALSE)
    goto session_resp_broken;

#ifdef DEBUG_LIGHT
  if (str_size > 0)
    {
      domain = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                     ucp, buff_size,
                                     cifs->unicode_strings);
      if (domain == NULL)
        goto session_resp_out_of_mem;
    }

  SSH_DEBUG(SSH_D_DATADUMP, ("- Native OS = \"%s\"", native_os));
  SSH_DEBUG(SSH_D_DATADUMP, ("- Native LAN Manager = \"%s\"", lan_man));
  SSH_DEBUG(SSH_D_DATADUMP, ("- Primary domain = \"%s\"", domain));

  ssh_free(native_os);
  ssh_free(lan_man);
  ssh_free(domain);
#endif /* DEBUG_LIGHT */

  if (cifs->orig_request->more_processing == 0)
    {
      session->id = cifs->uid;

      if (ssh_appgw_cifs_session_insert(session) == FALSE)
        {
          if (cifs->nt_error_codes)
            {
              cifs->error.nt.error_code = SSH_APPGW_CIFS_E_TOO_MANY_SESSIONS;
            }
          else
            {
              cifs->error.dos.error_class = SSH_APPGW_CIFS_D_E_CLASS_SERVER;
              cifs->error.dos.error_code = SSH_APPGW_CIFS_D_E_ERROR;
            }

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_generate_error_response);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;

session_resp_broken:

#ifdef DEBUG_LIGHT
  ssh_free(native_os);
  ssh_free(lan_man);
  ssh_free(domain);
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
  return SSH_FSM_CONTINUE;

#ifdef DEBUG_LIGHT
session_resp_out_of_mem:

  ssh_free(native_os);
  ssh_free(lan_man);
  ssh_free(domain);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
  return SSH_FSM_CONTINUE;
#endif /* DEBUG_LIGHT */
}


/* SMB_COM_LOGOFF_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_session_logoff_resp)
{
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CREATE_DIRECTORY response */
SSH_FSM_STEP(ssh_appgw_cifs_st_create_dir_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *directory;
  char tmpbuf[512];

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* Get the directory path */
  directory = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(directory != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "Directory \"%s%s\" created",
               cifs->tree->name, directory);

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT,
                        tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_DELETE_DIRECTORY response */
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_dir_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *directory;
  char tmpbuf[512];

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* Get the directory path */
  directory = ssh_appgw_cifs_cmd_context_get(conn, cifs);

  SSH_ASSERT(directory != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "Directory \"%s%s\" deleted",
               cifs->tree->name, directory);

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT,
                        tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_CONNECT response */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->tree == NULL);
  SSH_ASSERT(cifs->word_count == 2);
  SSH_ASSERT(cifs->byte_count == 0);

  tree = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(tree != NULL);

  tree->tid = cifs->tid;
  ssh_appgw_cifs_tree_insert(tree);

  /* Remember to delete the slot, so tree context won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_CONNECT_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_x_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  tree = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(tree != NULL);

  SSH_ASSERT(cifs->buffer != NULL);
  SSH_ASSERT(cifs->byte_count >= 3);

#ifdef DEBUG_LIGHT
  if (cifs->word_count >= 3)
    {
      unsigned char *params = cifs->parameters;
      SshUInt16 optional_support;

      /* skip ANDX block (4 bytes) */
      optional_support = SSH_GET_16BIT_LSB_FIRST(params+4);
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- optional_support = 0x%04X", optional_support));
    }
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_DATADUMP, ("- service = \"%s\"",
			     (char *) cifs->buffer));

  if ((cifs->byte_count >= 6) && strcmp(cifs->buffer, "IPC") == 0)
    tree->ipc_service = 1;

  tree->tid = cifs->tid;
  ssh_appgw_cifs_tree_insert(tree);

  /* Remember to delete the slot, so tree context won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_DISCONNECT response */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_disconnect_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

  if (tree != NULL)
    ssh_appgw_cifs_tree_remove(tree);
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid tree ID: 0x%04X", cifs->tid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CLOSE_AND_TREE_DISCONNECT response */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_and_tree_disc_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

  if (tree != NULL)
    ssh_appgw_cifs_tree_remove(tree);
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid tree ID: 0x%04X", cifs->tid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TRANSCATION response */
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshUInt16 total_param_count;
  SshUInt16 total_data_count;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 param_displacement;
  SshUInt16 data_count;
  SshUInt16 data_offset;
  SshUInt16 data_displacement;
  SshUInt8 setup_count;
  Boolean buffer_overflow_error = FALSE;

  /* Pick the pending transaction from our bookkeeping */
  transaction = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (transaction == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not find pending transaction!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->command_failed)
    {
      if (cifs->nt_error_codes &&
          (cifs->error.nt.error_code == SSH_APPGW_CIFS_E_BUFFER_OVERFLOW))
        {
          buffer_overflow_error = TRUE;
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
          return SSH_FSM_CONTINUE;
        }
    }

  /* If this is an interim server response, we can pass it without any
     further filtering. */
  if ((cifs->word_count == 0) && (cifs->byte_count == 0) &&
      (transaction->interim_response_received == 0))
    {
      transaction->interim_response_received = 1;
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* All other responses must contain at least 10 parameter words */
  if (cifs->word_count < 10)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  total_param_count = SSH_GET_16BIT_LSB_FIRST(params);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+2);
  /* skip two reserved bytes */
  param_count = SSH_GET_16BIT_LSB_FIRST(params+6);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+8);
  param_displacement = SSH_GET_16BIT_LSB_FIRST(params+10);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+12);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+14);
  data_displacement = SSH_GET_16BIT_LSB_FIRST(params+16);
  setup_count = SSH_GET_8BIT(params+18);

  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_param_count = %u", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- param_displacement = %u", param_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- data_displacement = %u", data_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  /* Check the values */
  if ((setup_count != (cifs->word_count - 10)) ||
      ((transaction->server.data_count == 0) && (data_displacement != 0)) ||
      ((transaction->server.param_count == 0) && (param_displacement != 0)) ||
      (total_param_count > transaction->server.max_param_count) ||
      (total_data_count > transaction->server.max_data_count) ||
      ((param_count + param_displacement) > total_param_count) ||
      ((data_count + data_displacement) > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check that server doesn't try to send more setup, parameter or data
     than the client is expecting */
  if ((setup_count > transaction->server.max_setup_count) ||
      ((param_count + param_displacement) >
                                     transaction->server.max_param_count) ||
      ((data_count + data_displacement) > transaction->server.max_data_count))
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("Transaction response contains more setup, parameter "
                 "or data bytes than the client is expecting"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of parameter and data counts */
  if (transaction->first_response)
    {
      transaction->server.total_param_count = total_param_count;
      transaction->server.total_data_count = total_data_count;
    }

  if ((total_param_count != transaction->server.total_param_count) ||
      (total_data_count != transaction->server.total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  if (transaction->pipe_transaction)
    {
      SshAppgwCifsFileHandle file = NULL;
      unsigned char *pipe_name = transaction->name_ptr;
      Boolean fid_required = FALSE;

      switch (transaction->subcommand)
        {
        case SSH_SMB_PRC_PIPE_SET_STATE:
          if ((param_count != 0) && (data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_QUERY_STATE:
          if (param_count == 2)
            {
#ifdef DEBUG_LIGHT
              SshUInt16 state;
              unsigned char *param_ptr = cifs->packet_ptr + param_offset;

              state = SSH_GET_16BIT_LSB_FIRST(param_ptr);

              ssh_appgw_cifs_dump_pipe_state((SshUInt16)(state & 0xCFFF));
#endif /* DEBUG_LIGHT */
            }
          else
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_QUERY_INFO:
          fid_required = TRUE;
          if (param_count == 0)
            {
#ifdef DEBUG_LIGHT
              SshUInt16 output_buffer_size;
              SshUInt16 input_buffer_size;
              SshUInt8 maximum_instances;
              SshUInt8 current_instances;
              unsigned char *data_ptr = cifs->packet_ptr + data_offset;

              if (data_count < 2)
                break;

              output_buffer_size = SSH_GET_16BIT_LSB_FIRST(data_ptr);
              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- output_buffer_size = %u", output_buffer_size));

              if (data_count < 4)
                break;

              input_buffer_size = SSH_GET_16BIT_LSB_FIRST(data_ptr+2);
              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- input_buffer_size = %u", input_buffer_size));

              if (data_count < 6)
                break;

              maximum_instances = SSH_GET_8BIT(data_ptr+4);
              current_instances = SSH_GET_8BIT(data_ptr+5);
              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- maximum_instances = %u", maximum_instances));
              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- current_instances = %u", current_instances));
#endif /* DEBUG_LIGHT */
            }
          else
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          break;

        case SSH_SMB_RPC_PIPE_TRANSACT:
          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_READ_RAW:
          if (param_count != 0)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_WRITE_RAW:
          if ((param_count == 2) || (data_count == 0))
            {
#ifdef DEBUG_LIGHT
              SshUInt16 bytes_written;
              unsigned char *param_ptr = cifs->packet_ptr + param_offset;

              bytes_written = SSH_GET_16BIT_LSB_FIRST(param_ptr);

              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- bytes_written = %u", bytes_written));
#endif /* DEBUG_LIGHT */
            }
          else
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_CALL:
          if (param_count != 0)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          break;

        case SSH_SMB_RPC_PIPE_WAIT:
          if ((param_count != 0) || (data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          break;

        case SSH_SMB_RPC_PIPE_PEEK:
          if (param_count == 6)
            {
#ifdef DEBUG_LIGHT
              SshUInt16 bytes_available;
              SshUInt16 bytes_remaining;
              SshUInt16 pipe_status;
              unsigned char *param_ptr = cifs->packet_ptr + param_offset;

              bytes_available = SSH_GET_16BIT_LSB_FIRST(param_ptr);
              bytes_remaining = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
              pipe_status = SSH_GET_16BIT_LSB_FIRST(param_ptr+4);

              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- bytes_avalilable = %u", bytes_available));
              SSH_DEBUG(SSH_D_DATADUMP,
                        ("- bytes_remaining = %u", bytes_remaining));

              switch (pipe_status)
                {
                case 1:
                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("- pipe_status = \"Disconnected by server\""));
                  break;

                case 2:
                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("- pipe_status = \"Listening\""));
                  break;

                case 3:
                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("- pipe_status = \"Connection OK\""));
                  break;

                case 4:
                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("- pipe_status = \"Pipe is closed\""));
                  break;

                default:
                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("- pipe_status = 0x%04X", pipe_status));
                  break;
                }
#endif /* DEBUG_LIGHT */
            }
          else
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
          break;

        default:
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("- subcommand = 0x%02X", transaction->subcommand));
          break;
        }

      if (fid_required)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("- fid = 0x%04X", transaction->fid));

          file = ssh_appgw_cifs_file_handle_lookup(conn, transaction->fid);
          if (file != NULL)
            pipe_name = file->name;
          else
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid handle (fid=0x%04X)!", transaction->fid));

              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
              ("- %s pipe transaction response "
               "(pipe=\"%s%s\", command=\"%s\")",
              (transaction->dce_rpc == 1) ? "DCE/RPC" : "",
              cifs->tree->name, pipe_name,
              ssh_appgw_cifs_pipe_transact_to_name(transaction->subcommand)));
    }

  /* Update the fields in transaction context */
  transaction->server.setup_count += setup_count;
  if (param_count > 0)
    transaction->server.param_count = param_count + param_displacement;
  if (data_count > 0)
    transaction->server.data_count = data_count + data_displacement;

  SSH_ASSERT(transaction->server.param_count <= total_param_count);
  SSH_ASSERT(transaction->server.data_count <= total_data_count);

  if (transaction->server.data == NULL)
    {
      if ((buffer_overflow_error == TRUE) ||
          ((data_displacement == 0) && (data_count < total_data_count)))
        {
          transaction->server.data = ssh_malloc(total_data_count);
          if (transaction->server.data == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          transaction->response_data_copied = 1;
        }
    }

  if (transaction->server.data != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Copying server data (%u bytes)", data_count));

      memcpy(transaction->server.data + data_displacement,
             cifs->packet_ptr + data_offset, data_count);

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("%u/%u bytes of server data copied.",
		 (unsigned int)
		 transaction->server.data_count,
		 (unsigned int)
		 total_data_count));
    }

  /* Check whether the transaction is complete */
  if ((transaction->server.param_count == total_param_count) &&
      (transaction->server.data_count == total_data_count))
    {
      if (transaction->dce_rpc)
        {
          unsigned char *buffer;
          SshUInt16 buf_len;
          SshDceRpcPDU req;
          SshDceRpcPDUStruct resp;
          SshUInt16 pdu_len;
          Boolean invalid = FALSE;

          if (transaction->server.data != NULL)
            {
              buffer = transaction->server.data;
              buf_len = transaction->server.data_count;
            }
          else
            {
              buffer = cifs->packet_ptr + data_offset;
              buf_len = data_count;
            }

          req = (SshDceRpcPDU)transaction->context;
          if (req == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_rpc_response);
              return SSH_FSM_CONTINUE;
            }

          if (buffer_overflow_error)
            {
              /* This is a special case when response PDU is longer than the
                 'max_data_count' specified in transaction request.
                 The client can read remaining bytes using "read_andx"
                 requests. */
              SshAppgwCifsFileHandle file;

              file = ssh_appgw_cifs_file_handle_lookup(conn,
                                                       transaction->fid);
              if (file == NULL)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                         ("Invalid handle (fid=0x%04X)!", transaction->fid));
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
                  return SSH_FSM_CONTINUE;
                }

              ssh_dce_rpc_pdu_init(&resp);
              if (ssh_dce_rpc_pdu_header_decode(&(resp.header), buffer,
                                                buf_len, NULL) == TRUE)
                {
                  SshAppgwCifsMultiPartIO read_io;

                  read_io = ssh_appgw_cifs_mp_io_begin(file,
                              SSH_APPGW_CIFS_MULTI_PART_READ,
                              resp.header.frag_length, req,
                              (SshAppgwCifsCtxDeleteCb)ssh_dce_rpc_pdu_free);
                  if (read_io == NULL)
                    {
                      ssh_dce_rpc_pdu_uninit(&resp);
                      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
                      return SSH_FSM_CONTINUE;
                    }

                  /* We "own" the request PDU now, so we must clear the
                     transaction context */
                  transaction->context = NULL;
                  ssh_dce_rpc_pdu_uninit(&resp);

                  SSH_ASSERT(buffer == transaction->server.data);

                  ssh_appgw_cifs_mp_io_append(read_io, buffer, buf_len);
                  ssh_appgw_cifs_mp_io_base_offset_set(read_io, buf_len);

                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
                  return SSH_FSM_CONTINUE;
                }
              else
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("Malformed DCE/RPC PDU header!"));
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
                  return SSH_FSM_CONTINUE;
                }
            }

          ssh_dce_rpc_pdu_init(&resp);
          if (ssh_dce_rpc_pdu_decode(&resp, buffer,
                                     buf_len, &pdu_len) == FALSE)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Malformed DCE/RPC PDU!"));
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_pipe_response);
              return SSH_FSM_CONTINUE;
            }

          switch (resp.header.packet_type)
            {
            case SSH_DCE_RPC_PDU_RESPONSE:
            case SSH_DCE_RPC_PDU_FAULT:
              if ((req->header.packet_type != SSH_DCE_RPC_PDU_REQUEST) ||
                  (req->header.call_id != resp.header.call_id))
                {
                  invalid = TRUE;
                }
              break;

            case SSH_DCE_RPC_PDU_BIND_ACK:
            case SSH_DCE_RPC_PDU_BIND_NAK:
              if ((req->header.packet_type != SSH_DCE_RPC_PDU_BIND) ||
                  (req->header.call_id != resp.header.call_id))
                {
                  invalid = TRUE;
                }
              break;

            case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
              if ((req->header.packet_type !=
                                        SSH_DCE_RPC_PDU_ALTER_CONTEXT) ||
                  (req->header.call_id != resp.header.call_id))
                {
                  invalid = TRUE;
                }
              break;

            default:
              invalid = TRUE;
              break;
            }

          ssh_appgw_cifs_log_rpc_response(conn, req, &resp, invalid);
          ssh_dce_rpc_pdu_uninit(&resp);

          if (invalid)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_rpc_response);
              return SSH_FSM_CONTINUE;
            }

          transaction->context = NULL; /* We'll delete this PDU now */
          ssh_dce_rpc_pdu_free(req);
        }

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  transaction->first_response = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* Unexpected DCE/RPC response received from server */
SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_rpc_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "Invalid/unexpected DCE/RPC response.",
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TRANSCATION2 response */
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction2_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshFSMStepCB next_st;
  SshUInt16 total_param_count;
  SshUInt16 total_data_count;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 param_displacement;
  SshUInt16 data_count;
  SshUInt16 data_offset;
  SshUInt16 data_displacement;
  SshUInt8 setup_count;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  /* If this is an interim server response, we can pass it without any
     further filtering. */
  if ((cifs->word_count == 0) && (cifs->byte_count == 0))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* All other responses must contain at least 10 parameter words */
  if (cifs->word_count < 10)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  total_param_count = SSH_GET_16BIT_LSB_FIRST(params);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+2);
  /* skip two reserved bytes */
  param_count = SSH_GET_16BIT_LSB_FIRST(params+6);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+8);
  param_displacement = SSH_GET_16BIT_LSB_FIRST(params+10);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+12);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+14);
  data_displacement = SSH_GET_16BIT_LSB_FIRST(params+16);
  setup_count = SSH_GET_8BIT(params+18);

  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_param_count = %u", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- param_displacement = %u", param_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- data_displacement = %u", data_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  /* Pick the pending transaction from our bookkeeping */
  transaction = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (transaction == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not find pending transaction!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check the values */
  if ((setup_count != (cifs->word_count - 10)) ||
      ((transaction->server.data_count == 0) && (data_displacement != 0)) ||
      ((transaction->server.param_count == 0) && (param_displacement != 0)) ||
      ((param_count + param_displacement) > total_param_count) ||
      ((data_count + data_displacement) > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check that server doesn't try to send more setup, parameter or data
     than the client is expecting */
  if ((setup_count > transaction->server.max_setup_count) ||
      ((param_count+transaction->server.param_count) >
                                     transaction->server.max_param_count) ||
      ((data_count+transaction->server.data_count) >
                                     transaction->server.max_data_count))
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("Transaction response contains more setup, parameter "
                 "or data bytes than the client is expecting"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of parameter and data counts */
  if (transaction->first_response)
    {
      transaction->server.total_param_count = total_param_count;
      transaction->server.total_data_count = total_data_count;
    }

  if ((total_param_count != transaction->server.total_param_count) ||
      (total_data_count != transaction->server.total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Update the fields in transaction context */
  transaction->server.setup_count += setup_count;
  if (param_count > 0)
    transaction->server.param_count = param_count + param_displacement;
  if (data_count > 0)
    transaction->server.data_count = data_count + data_displacement;

  SSH_ASSERT(transaction->server.param_count <= total_param_count);
  SSH_ASSERT(transaction->server.data_count <= total_data_count);

  /* Copy parameter bytes if only part of them are sent in the first
     transaction2 response */
  if (total_param_count > 0)
    {
      if (param_count < total_param_count)
        {
          if (transaction->first_response)
            {
              transaction->server.params = ssh_malloc(total_param_count);
              if (transaction->server.params == NULL)
                {
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
                  return SSH_FSM_CONTINUE;
                }

              transaction->response_params_copied = 1;
            }

          if (transaction->response_params_checked == 0)
            {
              memcpy(transaction->server.params + param_displacement,
                     cifs->packet_ptr + param_offset, param_count);
            }
        }
      else
        {
          transaction->server.params = cifs->packet_ptr + param_offset;
        }
    }

  if (total_data_count > 0)
    {
      if (data_count < total_data_count)
        {
          if (transaction->first_response)
            {
              transaction->server.data = ssh_malloc(total_data_count);
              if (transaction->server.data == NULL)
                {
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
                  return SSH_FSM_CONTINUE;
                }

              transaction->response_data_copied = 1;
            }

          if (transaction->response_data_checked == 0)
            {
              memcpy(transaction->server.data + data_displacement,
                     cifs->packet_ptr + data_offset, data_count);
            }
        }
      else
        {
          transaction->server.data = cifs->packet_ptr + data_offset;
        }
    }

  next_st = ssh_appgw_cifs_trans2_response_filter(conn, cifs, transaction);
  if (next_st != ssh_appgw_cifs_st_def_response_filter)
    {
      SSH_FSM_SET_NEXT(next_st);
      return SSH_FSM_CONTINUE;
    }

  /* Check whether the transaction is complete */
  if ((transaction->server.param_count == total_param_count) &&
      (transaction->server.data_count == total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  transaction->first_response = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* Invalid transaction2 response received from server */
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_trans2_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsConn conn = io->conn;

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Invalid transaction2 response received.",
                        SSH_AUDIT_ARGUMENT_END);

  cifs->command_failed = 1;

  /* Mark the original request ready so it will be deleted */
  cifs->orig_request->more_processing = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_QUERY_INFORMATION_DISK response */
SSH_FSM_STEP(ssh_appgw_cifs_st_query_info_disk_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
#ifdef DEBUG_LIGHT
  const unsigned char *params = cifs->parameters;
  SshUInt16 total_units;
  SshUInt16 blocks;
  SshUInt16 block_size;
  SshUInt16 free_units;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 5);
  SSH_ASSERT(cifs->byte_count == 0);

#ifdef DEBUG_LIGHT
  total_units = SSH_GET_16BIT_LSB_FIRST(params);
  blocks = SSH_GET_16BIT_LSB_FIRST(params+2);
  block_size = SSH_GET_16BIT_LSB_FIRST(params+4);
  free_units = SSH_GET_16BIT_LSB_FIRST(params+6);
  /* skip two reserved bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("- total_units = %u", total_units));
  SSH_DEBUG(SSH_D_DATADUMP, ("- blocks_per_unit = %u", blocks));
  SSH_DEBUG(SSH_D_DATADUMP, ("- block_size = %u", block_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- free_units = %u", free_units));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_QUERY_INFORMATION response */
SSH_FSM_STEP(ssh_appgw_cifs_st_query_information_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
#ifdef DEBUG_LIGHT
  SshAppgwCifsConn conn = io->conn;
  const unsigned char *params = cifs->parameters;
  const unsigned char *filename;
  SshUInt16 attributes;
  SshUInt32 write_time;
  SshUInt32 file_size;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

#ifdef DEBUG_LIGHT
  filename = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(filename != NULL);

  SSH_DEBUG(SSH_D_DATADUMP, ("Filename: \"%s\"", filename));
#endif /* DEBUG_LIGHT */

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 10);
  SSH_ASSERT(cifs->byte_count == 0);

#ifdef DEBUG_LIGHT
  attributes = SSH_GET_16BIT_LSB_FIRST(params);
  write_time = SSH_GET_32BIT_LSB_FIRST(params+2);
  file_size = SSH_GET_32BIT_LSB_FIRST(params+6);
  /* skip 10 reserved bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- last_write_time = %lu", write_time));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_size = %lu", file_size));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_SET_INFORMATION response */
SSH_FSM_STEP(ssh_appgw_cifs_st_set_information_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsConn conn = io->conn;
  const char *filename;
  char tmpbuf[512];

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  filename = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(filename != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "Attributes of \"%s%s\" modified.",
               cifs->tree->name, filename);

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT, tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CREATE_NEW or SMB_COM_CREATE_TEMPORARY response */
SSH_FSM_STEP(ssh_appgw_cifs_st_create_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count == 0);

  file = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(file != NULL);

  file->id = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));

  ssh_appgw_cifs_file_handle_insert(file);

  /* Remember to delete the slot, so file handle won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_OPEN response */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
#ifdef DEBUG_LIGHT
  SshUInt16 file_attributes;
  SshUInt32 file_size;
  SshUInt16 granted_access;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 7);
  SSH_ASSERT(cifs->byte_count == 0);

  file = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(file != NULL);

  file->id = SSH_GET_16BIT_LSB_FIRST(params);
#ifdef DEBUG_LIGHT
  file_attributes = SSH_GET_16BIT_LSB_FIRST(params+2);
  /* skip last write time (4 bytes) */
  file_size = SSH_GET_32BIT_LSB_FIRST(params+8);
  granted_access = SSH_GET_16BIT_LSB_FIRST(params+12);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_attibutes = 0x%04X", file_attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_size = %lu", file_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- granted_access = 0x%04X", granted_access));
#endif /* DEBUG_LIGHT */

  ssh_appgw_cifs_file_handle_insert(file);

  /* Remember to delete the slot, so file handle won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CLOSE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_DELETE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *filename;
  char tmpbuf[512];

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* Get the filename */
  filename = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(filename != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "\"%s%s\" deleted",
               cifs->tree->name, filename);

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT, tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_RENAME or SMB_COM_NT_RENAME response */
SSH_FSM_STEP(ssh_appgw_cifs_st_rename_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsFileMoveCtx rename_ctx;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  char tmpbuf[512];

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  rename_ctx = ssh_appgw_cifs_cmd_context_get(conn, cifs);

  SSH_ASSERT(rename_ctx != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "\"%s%s\" renamed to \"%s%s\"",
               cifs->tree->name, rename_ctx->original_name,
               cifs->tree->name, rename_ctx->new_name);

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT, tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_COPY response */
SSH_FSM_STEP(ssh_appgw_cifs_st_copy_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileMoveCtx copy_ctx;
  unsigned char *params = cifs->parameters;
  char tmpbuf[512];
#ifdef DEBUG_LIGHT
  SshUInt16 files_copied;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SshUInt8 format;

      /* skip byte_count */
      format = SSH_GET_8BIT(params+4);

      SSH_DEBUG(SSH_D_DATADUMP, ("- format = 0x%02X", format));

      if ((cifs->byte_count < 2) || (format != 0x04))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("- error_filename:"),
                        params+5, cifs->byte_count-1);

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 1);

#ifdef DEBUG_LIGHT
  files_copied = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- files_copied = %u", files_copied));
#endif /* DEBUG_LIGHT */

  copy_ctx = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(copy_ctx != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "\"%s%s\" copied to \"%s%s\"",
               cifs->tree->name, copy_ctx->original_name,
               cifs->tree->name, copy_ctx->new_name);


  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT, tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_MOVE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_move_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsFileMoveCtx move_ctx;
  unsigned char *params = cifs->parameters;
  char tmpbuf[512];
#ifdef DEBUG_LIGHT
  SshUInt16 files_moved;

  files_moved = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- files_moved = %u", files_moved));
#endif /* DEBUG_LIGHT */

  if (cifs->command_failed)
    {
      SshUInt8 format;

      /* skip byte_count */
      format = SSH_GET_8BIT(params+4);

      SSH_DEBUG(SSH_D_DATADUMP, ("- format = 0x%02X", format));

      if ((cifs->byte_count < 2) || (format != 0x04))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("- error_filename:"),
                        params+5, cifs->byte_count-1);
    }

  move_ctx = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(move_ctx != NULL);

  ssh_snprintf(tmpbuf, sizeof(tmpbuf), "\"%s%s\" moved to \"%s%s\"",
               cifs->tree->name, move_ctx->original_name,
               cifs->tree->name, move_ctx->new_name);

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                        SSH_AUDIT_TXT, tmpbuf,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_WRITE_AND_CLOSE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_write_and_close_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 bytes_written;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count == 0);

#ifdef DEBUG_LIGHT
  bytes_written = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- bytes_written = %u", bytes_written));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_OPEN_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_x_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
#ifdef DEBUG_LIGHT
  SshUInt16 file_attributes;
  SshUInt32 file_size;
  SshUInt16 granted_access;
  SshUInt16 file_type;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 15);
  SSH_ASSERT(cifs->byte_count == 0);

  file = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(file != NULL);

  /* Skip ANDX block (4 bytes) */
  file->id = SSH_GET_16BIT_LSB_FIRST(params+4);
#ifdef DEBUG_LIGHT
  file_attributes = SSH_GET_16BIT_LSB_FIRST(params+6);
  /* skip last write time (4 bytes) */
  file_size = SSH_GET_32BIT_LSB_FIRST(params+12);
  granted_access = SSH_GET_16BIT_LSB_FIRST(params+16);
  file_type = SSH_GET_16BIT_LSB_FIRST(params+18);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_attibutes = 0x%04X", file_attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_size = %lu", file_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- granted_access = 0x%04X", granted_access));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_type = 0x%04X", file_type));
#endif /* DEBUG_LIGHT */

  /* Add file_handle into our bookkeeping */
  ssh_appgw_cifs_file_handle_insert(file);

  /* Remember to remove the slot, so file handle won't be freed before we
     actually intend to do free it */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_READ response */
SSH_FSM_STEP(ssh_appgw_cifs_st_read_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  SshAppgwCifsIORequestCtx io_req;
  const unsigned char *params = cifs->parameters;
  const unsigned char *data = cifs->buffer;
  SshUInt16 count;
  SshUInt16 data_len;
  SshUInt8 format;

  SSH_ASSERT(cifs->tree != NULL);

  io_req = ssh_appgw_cifs_cmd_context_get(io->conn, cifs);
  SSH_ASSERT(io_req != NULL);

  file = ssh_appgw_cifs_file_handle_lookup(io->conn, io_req->fid);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 5);

  count = SSH_GET_16BIT_LSB_FIRST(params);
  /* skip eight reserved bytes */
  SSH_DEBUG(SSH_D_DATADUMP, ("- count = %u", count));

  /* Check the validity of 'count' value */
  if (((count + 3) != cifs->byte_count) || (count > io_req->max_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  format = SSH_GET_8BIT(data);
  data_len = SSH_GET_16BIT_LSB_FIRST(data+1);

  SSH_DEBUG(SSH_D_DATADUMP, ("- data_format = %u", format));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_length = %u", data_len));

  /* Check data_format */
  if (format != SSH_APPGW_CIFS_DATA_BLOCK)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid data format (%u)", format));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  if (data_len != count)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid data length: %u (should be %u)",
                data_len, count));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_READ_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_read_x_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  SshAppgwCifsMultiPartIO read_op = NULL;
  SshAppgwCifsIORequestCtx io_req;
  const unsigned char *params = cifs->parameters;
  const unsigned char *data;
  Boolean buffer_overflow_error = FALSE;
  size_t data_length;
  SshUInt16 data_offset;

  SSH_ASSERT(cifs->tree != NULL);

  io_req = ssh_appgw_cifs_cmd_context_get(io->conn, cifs);
  SSH_ASSERT(io_req != NULL);

  file = ssh_appgw_cifs_file_handle_lookup(io->conn, io_req->fid);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  read_op = ssh_appgw_cifs_mp_io_get(file, SSH_APPGW_CIFS_MULTI_PART_READ);

  if (cifs->command_failed)
    {
      if (cifs->nt_error_codes &&
          (cifs->error.nt.error_code == SSH_APPGW_CIFS_E_BUFFER_OVERFLOW))
        {
          buffer_overflow_error = TRUE;
        }
      else
        {
          ssh_appgw_cifs_mp_io_end(read_op);
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
          return SSH_FSM_CONTINUE;
        }
    }

  SSH_ASSERT(cifs->word_count == 12);

  /* skip ANDX block (4 bytes) */
  /* skip 6 bytes */
  data_length = SSH_GET_16BIT_LSB_FIRST(params+10);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+12);

  SSH_DEBUG(SSH_D_DATADUMP, ("- data_length = %u", data_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));

  /* Check the validity of parameters */
  if (((data_offset + data_length) > cifs->packet_size) ||
      (data_length > io_req->max_count))
    {
      ssh_appgw_cifs_mp_io_end(read_op);
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  data = cifs->packet_ptr + data_offset;

  if ((cifs->tree->ipc_service == 1) &&
      (file->file_type == SSH_SMB_FILE_TYPE_MESSAGE_PIPE))
    {
      if (read_op == NULL)
        {
          SshDceRpcPDUHeaderStruct header;

          if (ssh_dce_rpc_pdu_header_decode(&header, data,
                                            (SshUInt16)data_length,
                                            NULL) == TRUE)
            {
              read_op = ssh_appgw_cifs_mp_io_begin(file,
                                             SSH_APPGW_CIFS_MULTI_PART_READ,
                                             header.frag_length,
                                             NULL, NULL_FNPTR);
              if (read_op == NULL)
                {
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
                  return SSH_FSM_CONTINUE;
                }
            }
        }
    }

  if (read_op != NULL)
    {
      Boolean status;

      switch (file->file_type)
        {
        case SSH_SMB_FILE_TYPE_MESSAGE_PIPE:
        case SSH_SMB_FILE_TYPE_PIPE:
          status = ssh_appgw_cifs_mp_io_append(read_op, data, data_length);
          break;

        default:
          status = ssh_appgw_cifs_mp_io_insert(read_op,
                                               (size_t)io_req->offset,
                                               data, data_length);
          break;
        }

      if (status == FALSE)
        {
          read_op = NULL; /* the operation is "dead" already */
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      if (ssh_appgw_cifs_mp_io_is_complete(read_op) == FALSE)
        {
          /* We haven't read the complete PDU yet */
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_cifs_mp_io_data_get(read_op, &data, &data_length);
    }

  /* Filter DCE/RPC response... */
  if ((cifs->tree->ipc_service == 1) &&
      (file->file_type == SSH_SMB_FILE_TYPE_MESSAGE_PIPE))
    {
      SshDceRpcPDUStruct pdu;
      SshUInt16 pdu_len;
      SshUInt8 packet_type;

      ssh_dce_rpc_pdu_init(&pdu);
      if (ssh_dce_rpc_pdu_decode(&pdu, data,
                                 (SshUInt16)data_length, &pdu_len) == FALSE)
        {
          ssh_appgw_cifs_mp_io_end(read_op);
          SSH_DEBUG(SSH_D_NETGARB, ("Malformed DCE/RPC PDU!"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      packet_type = pdu.header.packet_type;
      ssh_dce_rpc_pdu_uninit(&pdu); /* we don't need this PDU any more */

      switch (packet_type)
        {
        case SSH_DCE_RPC_PDU_RESPONSE:
        case SSH_DCE_RPC_PDU_FAULT:
        case SSH_DCE_RPC_PDU_BIND_ACK:
        case SSH_DCE_RPC_PDU_BIND_NAK:
        case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
          break;

        default:
          ssh_appgw_cifs_mp_io_end(read_op);
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_rpc_response);
          return SSH_FSM_CONTINUE;
        }
    }

  ssh_appgw_cifs_mp_io_end(read_op);
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_WRITE_ANDX response */
SSH_FSM_STEP(ssh_appgw_cifs_st_write_x_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshAppgwCifsFileHandle file;
  SshAppgwCifsIORequestCtx io_req;
  SshAppgwCifsMultiPartIO write_op;
  SshUInt16 count;

  SSH_ASSERT(cifs->tree != NULL);

  /* Get I/O request context */
  io_req = ssh_appgw_cifs_cmd_context_get(io->conn, cifs);
  SSH_ASSERT(io_req != NULL);

  /* Get file handle! */
  file = ssh_appgw_cifs_file_handle_lookup(io->conn, io_req->fid);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  write_op = ssh_appgw_cifs_mp_io_get(file, SSH_APPGW_CIFS_MULTI_PART_WRITE);

  if (cifs->command_failed)
    {
      ssh_appgw_cifs_mp_io_end(write_op);
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* skip ANDX block (4 bytes) */
  count = SSH_GET_16BIT_LSB_FIRST(params+4);

  SSH_DEBUG(SSH_D_DATADUMP, ("- bytes_written = %u", count));

  /* Check bytes written! */
  if ((count < io_req->min_count) || (count > io_req->max_count))
    {
      ssh_appgw_cifs_mp_io_end(write_op);
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_IOCTL response */
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction ioctl;
  unsigned char *params = cifs->parameters;
  SshUInt16 total_params;
  SshUInt16 total_data;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 param_displacement;
  SshUInt16 data_count;
  SshUInt16 data_offset;
  SshUInt16 data_displacement;
  Boolean buffer_overflow_error = FALSE;

  /* Pick the pending transaction */
  ioctl = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (ioctl == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not find pending IOCTL transaction!"));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->command_failed)
    {
      if (cifs->nt_error_codes &&
          (cifs->error.nt.error_code == SSH_APPGW_CIFS_E_BUFFER_OVERFLOW))
        {
          buffer_overflow_error = TRUE;
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
          return SSH_FSM_CONTINUE;
        }
    }

  /* If this is an interim server response, we can pass it without any
     further filtering. */
  if ((cifs->word_count == 0) && (cifs->byte_count == 0) &&
      (ioctl->interim_response_received == 0))
    {
      ioctl->interim_response_received = 1;
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* All other responses must contain at least 10 parameter words */
  if (cifs->word_count != 8)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  total_params = SSH_GET_16BIT_LSB_FIRST(params);
  total_data = SSH_GET_16BIT_LSB_FIRST(params+2);
  param_count = SSH_GET_16BIT_LSB_FIRST(params+4);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+6);
  param_displacement = SSH_GET_16BIT_LSB_FIRST(params+8);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+10);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+12);
  data_displacement = SSH_GET_16BIT_LSB_FIRST(params+14);

  SSH_DEBUG(SSH_D_DATADUMP, ("- total_param_count = %u", total_params));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %u", total_data));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- param_displacement = %u", param_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- data_displacement = %u", data_displacement));

  if (((ioctl->server.data_count == 0) && (data_displacement != 0)) ||
      ((ioctl->server.param_count == 0) && (param_displacement != 0)) ||
      ((param_count + param_displacement) > total_params) ||
      ((data_count + data_displacement) > total_data) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

#if 0
  /* Check that server doesn't try to send more parameter or data bytes than
     the client is expecting.

     This check was removed, because e.g. WinME CIFS server doesn't seem to
     respect "max_data_count" limitation set by the CIFS client. */
  if (((param_count+ioctl->server.param_count) >
                                           ioctl->server.max_param_count) ||
      ((data_count+ioctl->server.data_count) > ioctl->server.max_data_count))
    {
      SSH_DEBUG(SSH_D_NETFAULT, ("IOCTL transaction response contains too "
                                 "many parameter or data bytes."));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }
#endif /* 0 */

  /* Check the validity of parameter and data counts */
  if (ioctl->first_response)
    {
      ioctl->server.total_param_count = total_params;
      ioctl->server.total_data_count = total_data;
    }

  if ((total_params != ioctl->server.total_param_count) ||
      (total_data != ioctl->server.total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Update the fields in transaction context */
  if (param_count > 0)
    ioctl->server.param_count = param_count + param_displacement;
  if (data_count > 0)
    ioctl->server.data_count = data_count + data_displacement;

  SSH_ASSERT(ioctl->server.param_count <= total_params);
  SSH_ASSERT(ioctl->server.data_count <= total_data);

  /* Check whether the transaction is complete */
  if ((ioctl->server.param_count == total_params) &&
      (ioctl->server.data_count == total_data))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  ioctl->first_response = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_CREATE_ANDX response from server */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_create_x_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
#ifdef DEBUG_LIGHT
  SshUInt8 oplock_level;
  SshUInt32 create_action;
  SshUInt32 attributes;
  SshUInt64 alloc_size;
  SshUInt64 end_of_file;
  SshUInt16 device_state;
  SshUInt16 status_flags;
  SshUInt16 is_directory;
#endif /* DEBUG_LIGHT */

  file = ssh_appgw_cifs_cmd_context_get(conn, cifs);

  SSH_ASSERT(file != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  /* According to publicly available documents, the word_count should be set
     to 26 in SMB_COM_NT_CREATE_ANDX response. Unfortunately, this is clearly
     wrong information! */

  /* According to our calculations the minimum count of (documented)
     parameter words seem to be 34 */
  if (cifs->word_count < 34)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

#ifdef DEBUG_LIGHT
  /* skip the "ANDX header" */
  oplock_level = SSH_GET_8BIT(params+4);
#endif /* DEBUG_LIGHT */
  file->id = SSH_GET_16BIT_LSB_FIRST(params+5);
#ifdef DEBUG_LIGHT
  create_action = SSH_GET_32BIT_LSB_FIRST(params+7);
  /* skip creation, access, write and change times */
  attributes = SSH_GET_32BIT_LSB_FIRST(params+43);
  alloc_size = SSH_GET_64BIT_LSB_FIRST(params+47);
  end_of_file = SSH_GET_64BIT_LSB_FIRST(params+55);
#endif /* DEBUG_LIGHT */
  file->file_type = SSH_GET_16BIT_LSB_FIRST(params+63);
#ifdef DEBUG_LIGHT
  device_state = SSH_GET_16BIT_LSB_FIRST(params+65);
  status_flags = SSH_GET_16BIT_LSB_FIRST(params+67);

  SSH_DEBUG(SSH_D_DATADUMP, ("- oplock_level = %u", oplock_level));
  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));
  SSH_DEBUG(SSH_D_DATADUMP, ("- create_action = 0x%08lX",
			     (unsigned long) create_action));
  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%08lX",
			     (unsigned long) attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- alloc_size = %qu", alloc_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- end_of_file = %qu", end_of_file));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_type = %u", file->file_type));
  SSH_DEBUG(SSH_D_DATADUMP, ("- device_state = 0x%04X", device_state));
  SSH_DEBUG(SSH_D_DATADUMP, ("- status_flags = 0x%04X", status_flags));

  if (cifs->word_count == 35)
    {
      is_directory = SSH_GET_16BIT_LSB_FIRST(params+69);
      SSH_DEBUG(SSH_D_DATADUMP, ("- is_directory = %u", is_directory));
    }
#endif /* DEBUG_LIGHT */

  /* Add file_handle into our bookkeeping */
  ssh_appgw_cifs_file_handle_insert(file);

  /* Remember to remove the slot, so file handle won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  ssh_appgw_cifs_log_fopen_event(conn, cifs, cifs->tree, file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_TRANSCATION response */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  SshFSMStepCB next_st;
  unsigned char *params = cifs->parameters;
  SshUInt32 total_param_count;
  SshUInt32 total_data_count;
  SshUInt32 param_count;
  SshUInt32 param_offset;
  SshUInt32 param_displacement;
  SshUInt32 data_count;
  SshUInt32 data_offset;
  SshUInt32 data_displacement;
  SshUInt8 setup_count;

  SSH_ASSERT(cifs->tree != NULL);

  transaction = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (transaction == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not find pending transaction!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_response);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  /* Interim response. We can just pass it without any further filtering. */
  if ((cifs->word_count == 0) && (cifs->byte_count == 0) &&
      (transaction->interim_response_received == 0))
    {
      transaction->interim_response_received = 1;
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->word_count < 18) /* must be 18 + setup_count */
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* skip 3 reserved bytes from beginning */
  total_param_count = SSH_GET_32BIT_LSB_FIRST(params+3);
  total_data_count = SSH_GET_32BIT_LSB_FIRST(params+7);
  param_count = SSH_GET_32BIT_LSB_FIRST(params+11);
  param_offset = SSH_GET_32BIT_LSB_FIRST(params+15);
  param_displacement = SSH_GET_32BIT_LSB_FIRST(params+19);
  data_count = SSH_GET_32BIT_LSB_FIRST(params+23);
  data_offset = SSH_GET_32BIT_LSB_FIRST(params+27);
  data_displacement = SSH_GET_32BIT_LSB_FIRST(params+31);
  setup_count = SSH_GET_8BIT(params+35);

  SSH_DEBUG(SSH_D_DATADUMP, ("- total_param_count = %lu", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %lu", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %lu", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %lu", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- param_displacement = %lu", param_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %lu", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %lu", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- data_displacement = %lu", data_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  if ((setup_count == 1) && (cifs->word_count == 18))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Invalid word count, trying to fix..."));

      /* This is one incompatibility issue (i.e. incorrect CIFS server
         implementation), which we try to fix by correcting the wrong
         word count value in SMB header. (Word count should be 18 _plus
         setup_count_, not just 18) */
      cifs->word_count = 19;
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_fix_wc_and_retry);
      return SSH_FSM_CONTINUE;
    }

  if ((setup_count != (cifs->word_count - 18)) ||
      ((transaction->server.data_count == 0) && (data_displacement != 0)) ||
      ((transaction->server.param_count == 0) && (param_displacement != 0)) ||
      (total_param_count > transaction->server.max_param_count) ||
      (total_data_count > transaction->server.max_data_count) ||
      ((param_count + param_displacement) > total_param_count) ||
      ((data_count + data_displacement) > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check that server doesn't try to send more setup, parameter or data
     than the client is expecting */
  if ((setup_count > transaction->server.max_setup_count) ||
      ((param_count + param_displacement) >
                                     transaction->server.max_param_count) ||
      ((data_count + data_displacement) >
                                     transaction->server.max_data_count))
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("Transaction response contains more setup, parameter "
                 "or data bytes than the client is expecting"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of parameter and data counts */
  if (transaction->first_response)
    {
      transaction->server.total_param_count = total_param_count;
      transaction->server.total_data_count = total_data_count;
    }

  if ((total_param_count != transaction->server.total_param_count) ||
      (total_data_count != transaction->server.total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  /* Update the fields in transaction context */
  transaction->server.setup_count += setup_count;
  if (param_count > 0)
    transaction->server.param_count = param_count + param_displacement;
  if (data_count > 0)
    transaction->server.data_count = data_count + data_displacement;

  SSH_ASSERT(transaction->server.param_count <= total_param_count);
  SSH_ASSERT(transaction->server.data_count <= total_data_count);

  /* Copy parameter bytes if only part of them are sent in the first
     NT_TRANSACTION response */
  if (total_param_count > 0)
    {
      if (param_count < total_param_count)
        {
          if (transaction->first_response)
            {
              transaction->server.params = ssh_malloc(total_param_count);
              if (transaction->server.params == NULL)
                {
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_out_of_mem);
                  return SSH_FSM_CONTINUE;
                }

              transaction->request_params_copied = 1;
            }

          if (transaction->response_params_checked == 0)
            {
              memcpy(transaction->server.params + param_displacement,
                     cifs->packet_ptr + param_offset, param_count);
            }
        }
      else
        {
          transaction->server.params = cifs->packet_ptr + param_offset;
        }
    }

  next_st = ssh_appgw_cifs_nt_transact_response_filter(conn, cifs,
                                                       transaction);
  if (next_st != ssh_appgw_cifs_st_def_response_filter)
    {
      SSH_FSM_SET_NEXT(next_st);
      return SSH_FSM_CONTINUE;
    }

  /* Check whether the transaction is complete */
  if ((transaction->server.param_count == total_param_count) &&
      (transaction->server.data_count == total_data_count))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_complete);
      return SSH_FSM_CONTINUE;
    }

  transaction->first_response = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* Invalid NT_TRANSACTION response received from server */
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_nt_transact_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  cifs->command_failed = 1;

  /* Mark the original request ready so it will be deleted */
  cifs->orig_request->more_processing = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
  return SSH_FSM_CONTINUE;
}


/* SMB_OPEN_PRINT_FILE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_print_file_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->tree != NULL);

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count == 0);

  file = ssh_appgw_cifs_cmd_context_get(conn, cifs);
  SSH_ASSERT(file != NULL);

  file->id = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", file->id));

  ssh_appgw_cifs_file_handle_insert(file);

  /* Remember to delete the slot, so file handle won't be freed before we
     actually intend to do so */
  ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_CLOSE_PRINT_FILE response */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_print_file_resp)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->command_failed)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_response_filter);
  return SSH_FSM_CONTINUE;
}


/* Filter embedded commands of ..._ANDX responses */
SSH_FSM_STEP(ssh_appgw_cifs_st_embedded_response_filter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshAppgwCifsAndxCmdCtx andx = cifs->andx_ctx;
  SshUInt8 andx_reserved;
  SshUInt16 prev_andx_offset;
  unsigned char * ucp;
  size_t space_left;
  SshAppgwCifsEmbeddedCmd cmd;

  if (cifs->embedded_cmds == 0)
    {
      /* Filtering complete */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(cifs->embedded_cmds == 1);

  prev_andx_offset = andx->offset;

  if (cifs->is_andx_command == 0)
    {
      /* The currently parsed command is not an "ANDX command". We should
         skip parameter words, byte count field (two bytes) and data
         bytes and continue the checking of next embedded command. (It must
         contain ANDX block, otherwice this packet is malformed) */
      params += cifs->word_count*2 + cifs->byte_count + 2;

      if (params > (cifs->packet_ptr + cifs->packet_size))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }
      else if ((cifs->parameters == NULL) ||
               (params == (cifs->packet_ptr + cifs->packet_size)))
        {
          /* Filtering complete */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("No more embedded commands"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);
          return SSH_FSM_CONTINUE;
        }

      cifs->word_count = SSH_GET_8BIT(params);

      if (cifs->word_count < 2)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
          return SSH_FSM_CONTINUE;
        }

      params++; /* skip the word count field */
    }

  andx_reserved = SSH_GET_8BIT(params+1);
  if (andx_reserved != 0)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  andx->embedded_cmd = SSH_GET_8BIT(params);
  if (andx->embedded_cmd == 0xFF)
    {
      /* Filtering complete */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No more embedded commands"));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);
      return SSH_FSM_CONTINUE;
    }

  andx->offset = SSH_GET_16BIT_LSB_FIRST(params+2);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Embedded %s %s",
            ssh_appgw_cifs_cmd_to_name(andx->embedded_cmd),
            (cifs->response == 0) ? "request" : "response"));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %u", andx->offset));

  /* Check the validity of andx_offset! */

  /* We have a simple protection against malformatted packets having
     "infinite loop" of embedded commands (possible DoS attack). We expect
     that embedded commands are always in a correct order, so the
     currently parsed command must have a bigger andx_offset than the
     previously parsed command had. */
  if ((andx->offset > (cifs->packet_size+SSH_APPGW_SMB_ANDX_MIN_LEN)) ||
      (andx->offset < prev_andx_offset))
    {
      SSH_DEBUG(SSH_D_NETFAULT, ("Invalid 'andx_offset'!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
      return SSH_FSM_CONTINUE;
    }

  /* Pointer to beginning (i.e. the word_count field) of next
     embedded command */
  ucp = cifs->packet_ptr + andx->offset;

  cifs->word_count = SSH_GET_8BIT(ucp);

  /* Check the validity of word_count */
  /* (Three bytes are needed for word_count and byte_count fields) */
  space_left = cifs->packet_size - (andx->offset +
                                    SSH_APPGW_SMB_ANDX_MIN_LEN);

  if (space_left < (cifs->word_count*2))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_response);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->word_count)
    cifs->parameters = (unsigned char *)ucp+1;
  else
    cifs->parameters = NULL;

  /* Skip the parameter words */
  ucp += 1 + (cifs->word_count*2);
  cifs->byte_count = SSH_GET_16BIT_LSB_FIRST(ucp);

  /* Check the validity of byte_count */
  space_left -= cifs->word_count*2;
  if (space_left < cifs->byte_count)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_byte_count);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count == 0)
    cifs->buffer = NULL;
  else
    cifs->buffer = ucp+2;

  SSH_DEBUG(SSH_D_DATADUMP, ("- word_count = %d", cifs->word_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- byte_count = %d", cifs->byte_count));

  SSH_ASSERT(cifs->andx_commands != NULL);

  /* Check whether the client sent this request */
  cmd = cifs->andx_commands;

  while (cmd)
    {
      if (cmd->command == andx->embedded_cmd)
        {
          cifs->cmd_ctx = cmd->context;

          /* Return control to CIFS parser */
          cifs->decode_phase = SSH_APPGW_CIFS_FILTER_ANDX;
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_continue_filtering);
          return SSH_FSM_CONTINUE;
        }

      cmd = cmd->next;
    };

  /* Client did not send this embedded request! */
  SSH_DEBUG(SSH_D_NETFAULT, ("Unexpected embedded %s response!",
            ssh_appgw_cifs_cmd_to_name(andx->embedded_cmd)));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsupported_andx);
  return SSH_FSM_CONTINUE;
}


/* Default filter for CIFS requests */
SSH_FSM_STEP(ssh_appgw_cifs_st_def_response_filter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->embedded_cmds)
    /* Continue filtering embedded commands */
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_embedded_response_filter);
  else
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_complete)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->command_failed)
    {
      if ((cifs->nt_error_codes) &&
          (cifs->error.nt.error_code == SSH_APPGW_CIFS_E_CANCELLED))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("%s: transaction canceled!",
                    ssh_appgw_cifs_cmd_to_name(cifs->command)));
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("%s: transaction failed!",
                    ssh_appgw_cifs_cmd_to_name(cifs->command)));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("%s: transaction complete!",
                ssh_appgw_cifs_cmd_to_name(cifs->command)));
    }

  /* Mark the original request ready so it will be deleted in
     ssh_appgw_cifs_st_response_filter_complete state. */
  cifs->orig_request->more_processing = 0;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_response_filter_complete);
  return SSH_FSM_CONTINUE;
}


/* Passes the requests to client and deletes the pending request entry from
   our bookkeeping. */
SSH_FSM_STEP(ssh_appgw_cifs_st_response_filter_complete)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->command_failed)
    {
      if (cifs->nt_error_codes)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("%s request failed! (error_code = 0x%08lX)",
                     ssh_appgw_cifs_cmd_to_name(cifs->command),
                     (unsigned long) cifs->error.nt.error_code));
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("%s request failed! (class = 0x%02X, code = 0x%04X)",
                     ssh_appgw_cifs_cmd_to_name(cifs->command),
                     cifs->error.dos.error_class,
                     cifs->error.dos.error_code));
        }
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("%s response passed.",
            ssh_appgw_cifs_cmd_to_name(cifs->command)));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_pass_packet);
  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
