/*
 *
 * appgw_cifs_st_request.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * FSM state functions for filtering CIFS requests.
 *
 */

#include "sshincludes.h"
#include "sshgetput.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifsRequest"

/* Opportunistic lock type flags (see SMB_COM_LOCKING_ANDX) */
#define SSH_LOCKING_ANDX_SHARED_LOCK      0x01
#define SSH_LOCKING_ANDX_OPLOCK_RELEASE   0x02
#define SSH_LOCKING_ANDX_CHANGE_LOCKTYPE  0x04
#define SSH_LOCKING_ANDX_CANCEL_LOCK      0x08
#define SSH_LOCKING_ANDX_LARGE_FILES      0x10

/******************* Prototypes for static help function ********************/

/* Allocates and initializes a new "file move context" to be used with
   SMB_COM_MOVE, SMB_COM_RENAME etc. CIFS requests */
static SshAppgwCifsFileMoveCtx
ssh_appgw_cifs_file_move_ctx_allocate(SshAppgwCifsConn conn,
                                      SshAppgwCifsParser cifs,
                                      SshAppgwCifsDataFormat buff_format,
                                      const unsigned char *buffer,
                                      size_t buffer_len,
                                      Boolean unicode);

/* Allocates and initializes a new ASCII filename to be used as a CIFS command
   specific context with SMB_COM_CREATE, SMB_COM_OPEN etc. requests  */
static const char *
ssh_appgw_cifs_filename_ctx_allocate(SshAppgwCifsConn conn,
                                     SshAppgwCifsParser cifs,
                                     SshAppgwCifsDataFormat buff_format,
                                     const unsigned char *buffer,
                                     size_t buffer_len,
                                     Boolean unicode);

/* Callback function for deleting application gateway specific
   SMB_COM_NEGOTIATE context */
static void ssh_appgw_cifs_negotiate_ctx_delete_cb(void *context);

/* Generic context deletion callback function */
static void ssh_appgw_cifs_cmd_ctx_delete_cb(void *context);

/* Access mask decoding function */
static void ssh_appgw_cifs_decode_access_mask(SshAppgwCifsFileHandle file,
                                              SshUInt32 access_mask);

/* Access mode decoding function */
static void ssh_appgw_cifs_decode_access_mode(SshAppgwCifsFileHandle file,
                                              SshUInt16 access_mode);

/***************** Prototypes for "private" state functions *****************/

SSH_FSM_STEP(ssh_appgw_cifs_st_request_filter_complete);
SSH_FSM_STEP(ssh_appgw_cifs_st_broken_request);
SSH_FSM_STEP(ssh_appgw_cifs_st_request_out_of_mem);
SSH_FSM_STEP(ssh_appgw_cifs_st_req_invalid_handle);


/************************** Static help functions ***************************/

static void
ssh_appgw_cifs_cmd_ctx_delete_cb(void *context)
{
  SSH_ASSERT(context != NULL);

  SSH_DEBUG(SSH_D_MY5, ("context deleted [context = %p]", context));

  ssh_free(context);
}


static void
ssh_appgw_cifs_session_delete_cb(void *context)
{
  SshAppgwCifsSession session = (SshAppgwCifsSession) context;

  ssh_free(session->account);
  ssh_free(session->domain);
  ssh_free(session);
}


static void
ssh_appgw_cifs_move_ctx_delete_cb(void *context)
{
  SshAppgwCifsFileMoveCtx move_ctx = (SshAppgwCifsFileMoveCtx) context;

  ssh_free(move_ctx->original_name);
  ssh_free(move_ctx->new_name);
  ssh_free(move_ctx);
}


static SshAppgwCifsFileMoveCtx
ssh_appgw_cifs_file_move_ctx_allocate(SshAppgwCifsConn conn,
                                      SshAppgwCifsParser cifs,
                                      SshAppgwCifsDataFormat buff_format,
                                      const unsigned char *buffer,
                                      size_t buffer_len,
                                      Boolean unicode)
{
  SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx) conn->ctx->user_context;
  SshAppgwCifsFileMoveCtx move_ctx;
  size_t str1_size;
  size_t str2_size;

  /* Check the validity of first filename */
  if (ssh_appgw_cifs_strsize(&str1_size, buff_format,
                             buffer, buffer_len, unicode) == FALSE)
    return NULL;

  /* There must still be enough space for the second filename */
  if (str1_size >= buffer_len)
    return NULL;

  if (ssh_appgw_cifs_strsize(&str2_size, buff_format,
                             &buffer[str1_size], buffer_len - str1_size,
                             unicode) == FALSE)
    return NULL;

  move_ctx = ssh_appgw_cifs_cmd_context_allocate(conn, cifs,
                                          sizeof(*move_ctx),
                                          ssh_appgw_cifs_move_ctx_delete_cb);
  if (move_ctx == NULL)
    return NULL;

  move_ctx->original_name =
    (unsigned char *)ssh_appgw_cifs_strdup(cifs_alg, buff_format,
                                           buffer, str1_size, unicode);

  move_ctx->new_name =
    (unsigned char *)ssh_appgw_cifs_strdup(cifs_alg, buff_format,
                                           &buffer[str1_size], str2_size,
                                           unicode);

  if ((move_ctx->original_name != NULL) && (move_ctx->new_name != NULL))
    return move_ctx;
  else
    return NULL;
}


static const char *
ssh_appgw_cifs_filename_ctx_allocate(SshAppgwCifsConn conn,
                                     SshAppgwCifsParser cifs,
                                     SshAppgwCifsDataFormat buff_format,
                                     const unsigned char *buffer,
                                     size_t buffer_len,
                                     Boolean unicode)
{
  SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx) conn->ctx->user_context;
  SshAppgwCifsCmdCtxSlot slot;
  char *filename;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(buffer != NULL);

  slot = ssh_appgw_cifs_cmd_context_slot_add(conn, cifs);
  if (slot == NULL)
    return NULL;

  filename = ssh_appgw_cifs_strdup(cifs_alg, buff_format,
                                   buffer, buffer_len, unicode);

  ssh_appgw_cifs_cmd_context_set(slot, filename,
                                 ssh_appgw_cifs_cmd_ctx_delete_cb);

  return ((const char *)filename);
}


static SshAppgwCifsFileHandle
ssh_appgw_cifs_file_ctx_allocate(SshAppgwCifsConn conn,
                                 SshAppgwCifsParser cifs,
                                 SshAppgwCifsDataFormat buff_format,
                                 unsigned char *buffer,
                                 size_t buff_len,
                                 Boolean unicode)
{
  SshAppgwCifsCmdCtxSlot slot;
  SshAppgwCifsFileHandle file;

  slot = ssh_appgw_cifs_cmd_context_slot_add(conn, cifs);
  if (slot == NULL)
    return NULL;

  file = ssh_appgw_cifs_file_handle_allocate(conn, buff_format,
                                             buffer, buff_len, unicode);

  ssh_appgw_cifs_cmd_context_set(slot, file,
                                 ssh_appgw_cifs_cmd_ctx_delete_cb);

  return file;
}


static SshAppgwCifsTree
ssh_appgw_cifs_tree_ctx_allocate(SshAppgwCifsConn conn,
                                 SshAppgwCifsParser cifs,
                                 unsigned char *buffer,
                                 size_t buff_len,
                                 Boolean unicode)
{
  SshAppgwCifsCmdCtxSlot slot;
  SshAppgwCifsTree tree;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(buffer != NULL);

  slot = ssh_appgw_cifs_cmd_context_slot_add(conn, cifs);
  if (slot == NULL)
    return NULL;

  tree = ssh_appgw_cifs_tree_allocate(conn, buffer, buff_len, unicode);

  ssh_appgw_cifs_cmd_context_set(slot, tree,
                                 ssh_appgw_cifs_cmd_ctx_delete_cb);

  return tree;
}


static SshAppgwCifsTransaction
ssh_appgw_cifs_transaction_ctx_allocate(SshAppgwCifsConn conn,
                                        SshAppgwCifsParser cifs,
                                        unsigned char *buffer,
                                        size_t buff_len,
                                        Boolean unicode)
{
  SshAppgwCifsCmdCtxSlot slot;
  SshAppgwCifsTransaction transact;

  slot = ssh_appgw_cifs_cmd_context_slot_add(conn, cifs);
  if (slot == NULL)
    return NULL;

  transact = ssh_appgw_cifs_transaction_allocate(conn, buffer, buff_len,
                                                 unicode);
  if (transact == NULL)
    return NULL;

  ssh_appgw_cifs_cmd_context_set(slot, transact,
                    (SshAppgwCifsCtxDeleteCb)ssh_appgw_cifs_transaction_free);

  return transact;
}


static void
ssh_appgw_cifs_negotiate_ctx_delete_cb(void * context)
{
  SshAppgwCifsNegotiateCtx ctx = (SshAppgwCifsNegotiateCtx)context;
  unsigned int i;

  SSH_ASSERT(ctx != NULL);
  SSH_ASSERT(ctx->dialect_count != 0);
  SSH_ASSERT(ctx->dialect_ptrs != NULL);

  SSH_DEBUG(SSH_D_MY5, ("context deleted [context = %p]", context));

  for (i = 0; i < ctx->dialect_count; i++)
    ssh_free(ctx->dialect_ptrs[i]);

  ssh_free(ctx->dialect_ptrs);
  ssh_free(ctx);
}


static void
ssh_appgw_cifs_decode_access_mask(SshAppgwCifsFileHandle file,
                                  SshUInt32 access_mask)
{
  if (access_mask == 0)
    file->query_access = 1;
  else
    {
      if (access_mask & 0x00010000)
        file->delete_access = 1;

      /* Either GENERIC_READ or READ_ACCESS flag set */
      if (access_mask & 0x80000001)
        file->read_access = 1;

      /* Either GENERIC_WRITE or WRITE_ACCESS flag set */
      if (access_mask & 0x40000002)
        file->write_access = 1;

      /* Either GENERIC_EXECUTE or EXECUTE_ACCESS flag set */
      if (access_mask & 0x20000020)
        file->execute_access = 1;

      /* GENERIC_ALL */
      if (access_mask & 0x10000000)
        {
          file->read_access = 1;
          file->write_access = 1;
          file->execute_access = 1;
        }
    }
}


static void
ssh_appgw_cifs_decode_access_mode(SshAppgwCifsFileHandle file,
                                  SshUInt16 access_mode)
{
  switch (access_mode & 0x0007)
    {
    case 0:
      file->read_access = 1;
      break;

    case 1:
      file->write_access = 1;
      break;

    case 2:
      file->read_access = 1;
      file->write_access = 1;
      break;

    case 3:
      file->execute_access = 1;
      break;
    }
}


static void
ssh_appgw_cifs_log_fclose_event(SshAppgwCifsConn conn,
                                SshAppgwCifsParser cifs,
                                SshAppgwCifsTree tree,
                                SshAppgwCifsFileHandle file)
{
  if (file->write_access || file->delete_access || file->execute_access)
    {
      char tmpbuf[512];

      ssh_snprintf(tmpbuf, sizeof(tmpbuf), "\"%s%s\" closed.",
                   tree->name, file->name);

      ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_CIFS_OPERATION,
                            SSH_AUDIT_TXT, tmpbuf,
                            SSH_AUDIT_ARGUMENT_END);
    }
}


static Boolean
ssh_appgw_cifs_rpc_request_decode(SshDceRpcPDU pdu,
                                  unsigned char *buffer,
                                  size_t buffer_len)
{
  SshUInt16 pdu_len;
  unsigned char *orig_buf = buffer;
  Boolean allocated = FALSE;

  if ((unsigned long)pdu % 8)
    {
      buffer = ssh_malloc(buffer_len);
      if (buffer == NULL)
        return FALSE;

      memcpy(buffer, orig_buf, buffer_len);
    }

  if (ssh_dce_rpc_pdu_decode(pdu, buffer,
                             (SshUInt16)buffer_len, &pdu_len) == FALSE)
    {
      if (allocated)
        ssh_free(buffer);

      SSH_DEBUG(SSH_D_NETGARB, ("Malformed DCE/RPC PDU!"));
      return FALSE;
    }

  if (allocated)
    ssh_free(buffer);

  switch (pdu->header.packet_type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
    case SSH_DCE_RPC_PDU_BIND:
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
    case SSH_DCE_RPC_PDU_AUTH3:
      return TRUE;

    default:
      SSH_DEBUG(SSH_D_NETGARB, ("Unexpected DCE/RPC PDU!"));
      return FALSE;
    }
}


/* Checks whether a SMB_COM_TRANSACTION2 request is valid */
static SshFSMStepCB
ssh_appgw_cifs_trans2_request_filter(SshAppgwCifsConn conn,
                                     SshAppgwCifsParser cifs,
                                     SshAppgwCifsTransaction trans2)
{
  static SshFSMStepCB continue_st = ssh_appgw_cifs_st_def_request_filter;
  static SshFSMStepCB broken_st = ssh_appgw_cifs_st_broken_request;
  static SshFSMStepCB no_memory_st = ssh_appgw_cifs_st_request_out_of_mem;
  static SshFSMStepCB invalid_handle_st
                        = ssh_appgw_cifs_st_req_invalid_handle;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- subcommand = %s (0x%02X)",
            ssh_appgw_cifs_transact2_to_name(trans2->subcommand),
            trans2->subcommand));

  if (trans2->first_request)
    {
      SshUInt16 setup_count = (SshUInt16)(cifs->word_count - 14);

      switch (trans2->subcommand)
        {
        case SSH_SMB_TRANSACT2_OPEN2:
          if ((trans2->client.total_param_count <= 24) ||
              (trans2->server.max_param_count < 30) ||
              (trans2->server.max_data_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_FIND_FIRST2:
          if ((trans2->client.total_param_count <= 12) ||
              (trans2->server.max_param_count < 10) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_FIND_NEXT2:
          if ((trans2->client.total_param_count <= 12) ||
              (trans2->server.max_param_count < 8) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION:
          if ((trans2->client.total_param_count < 2) ||
              (trans2->server.max_setup_count != 0) ||
              ((setup_count != 1) && (setup_count != 2)))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
          if ((trans2->client.total_param_count <= 6) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
          if ((trans2->client.total_param_count <= 6) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
          if ((trans2->client.total_param_count < 4) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
          if ((trans2->client.total_param_count < 6) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_CREATE_DIRECTORY:
          if ((trans2->client.total_param_count <= 4) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
          if ((trans2->client.total_param_count <= 2) ||
              (trans2->client.total_data_count != 0) ||
              (trans2->server.max_setup_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY:
          if ((trans2->client.total_param_count <= 2) ||
              (trans2->client.total_data_count != 0) ||
              (trans2->server.max_setup_count != 0) ||
              (trans2->server.max_param_count != 0) ||
              (setup_count != 1))
            {
              return broken_st;
            }
          break;

        case SSH_SMB_TRANSACT2_SESSION_SETUP:
          /* Not implemented yet */
          break;

        default:
          ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "request containing unsupported subcommand "
                                "received",
                                SSH_AUDIT_CIFS_COMMAND,
                                ssh_appgw_cifs_cmd_to_name(cifs->command),
                                SSH_AUDIT_CIFS_SUBCOMMAND,
                                trans2->subcommand,
                                SSH_AUDIT_ARGUMENT_END);
          return broken_st;
        }
    }

  /* Check the contents of parameter bytes */
  if ((trans2->client.param_count == trans2->client.total_param_count) &&
      (trans2->client.params != NULL) &&
      (trans2->request_params_checked == 0))
    {
      const unsigned char *param_ptr = trans2->client.params;
#ifdef DEBUG_LIGHT
      SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
#endif /* DEBUG_LIGHT */

      trans2->request_params_checked = 1;

      switch (trans2->subcommand)
        {
        case SSH_SMB_TRANSACT2_OPEN2:
          {
#ifdef DEBUG_LIGHT
            SshUInt16 flags;
            SshUInt16 desired_access;
            SshUInt16 open_function;
            SshUInt32 alloc_size;
#endif /* DEBUG_LIGHT */
            SshUInt16 attributes;
            SshAppgwCifsFileHandle file;

            SSH_ASSERT(trans2->client.param_count > 24);

#ifdef DEBUG_LIGHT
            flags = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            desired_access = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
#endif /* DEBUG_LIGHT */
            /* skip two reserved bytes */
            attributes = SSH_GET_16BIT_LSB_FIRST(param_ptr+6);
#ifdef DEBUG_LIGHT
            /* skip creation time and date (2+2 bytes) */
            open_function = SSH_GET_16BIT_LSB_FIRST(param_ptr+10);
            alloc_size = SSH_GET_32BIT_LSB_FIRST(param_ptr+12);
            /* skip 10 reserved bytes */

            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
            SSH_DEBUG(SSH_D_DATADUMP, ("- desired_access = 0x%04X",
                                      desired_access));
            SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
            SSH_DEBUG(SSH_D_DATADUMP, ("- open_function = 0x%04X",
                                      open_function));
            SSH_DEBUG(SSH_D_DATADUMP, ("- alloc_size = %lu", alloc_size));
#endif /* DEBUG_LIGHT */

            file = ssh_appgw_cifs_file_handle_allocate(conn,
                                                SSH_APPGW_CIFS_DATA_BLOCK,
                                                param_ptr+24,
                                                trans2->client.param_count-24,
                                                cifs->unicode_strings);
            if (file == NULL)
              return no_memory_st;

            if (attributes & 0x0010)
              file->directory = 1;

#ifdef DEBUG_LIGHT
            ssh_appgw_cifs_decode_access_mode(file, desired_access);

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));
#endif /* DEBUG_LIGHT */

            /* Store the file handle into transaction context */
            trans2->context = file;
          }
          break;

        case SSH_SMB_TRANSACT2_FIND_FIRST2:
          {
#ifdef DEBUG_LIGHT
            SshUInt16 attributes;
            SshUInt16 search_count;
            SshUInt32 storage_type;
#endif /* DEBUG_LIGHT */
            SshUInt16 flags;
            SshAppgwCifsSearchHandle search;

#ifdef DEBUG_LIGHT
            attributes = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            search_count = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
#endif /* DEBUG_LIGHT */
            flags = SSH_GET_16BIT_LSB_FIRST(param_ptr+4);
            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr+6);
#ifdef DEBUG_LIGHT
            storage_type = SSH_GET_32BIT_LSB_FIRST(param_ptr+8);

            SSH_DEBUG(SSH_D_DATADUMP, ("- search_attributes = 0x%04X",
                                      attributes));
            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_search_info_level_to_name(trans2->info_level),
                  trans2->info_level));
            SSH_DEBUG(SSH_D_DATADUMP, ("- search_storage_type = 0x%08lX",
				       (unsigned long) storage_type));
#endif /* DEBUG_LIGHT */

            search = ssh_appgw_cifs_search_handle_allocate(conn,
                                                SSH_APPGW_CIFS_DATA_BLOCK,
                                                param_ptr+12,
                                                trans2->client.param_count-12,
                                                cifs->unicode_strings);
            if (search == NULL)
              return no_memory_st;

            if (flags & 0x0001)
              search->close_after_request = 1;

            if (flags & 0x0002)
              search->close_when_complete = 1;

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", search->name));

            trans2->context = search;
          }
          break;

        case SSH_SMB_TRANSACT2_FIND_NEXT2:
          {
#ifdef DEBUG_LIGHT
            SshUInt16 search_count;
            SshUInt32 resume_key;
#endif /* DEBUG_LIGHT */
            SshUInt16 sid;
            SshUInt16 flags;
            SshAppgwCifsSearchHandle search;

            sid = SSH_GET_16BIT_LSB_FIRST(param_ptr);
#ifdef DEBUG_LIGHT
            search_count = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
#endif /* DEBUG_LIGHT */
            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr+4);
#ifdef DEBUG_LIGHT
            resume_key = SSH_GET_32BIT_LSB_FIRST(param_ptr+6);
#endif /* DEBUG_LIGHT */
            flags = SSH_GET_16BIT_LSB_FIRST(param_ptr+10);

            SSH_DEBUG(SSH_D_DATADUMP, ("- sid = 0x%04X", sid));
            SSH_DEBUG(SSH_D_DATADUMP, ("- search_count = %u", search_count));
            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                ssh_appgw_cifs_search_info_level_to_name(trans2->info_level),
                trans2->info_level));
            SSH_DEBUG(SSH_D_DATADUMP, ("- resume_key = 0x%08lX",
				       (unsigned long) resume_key));
            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));

            search = ssh_appgw_cifs_search_handle_lookup(conn, sid);
            if (search == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Invalid handle (sid=0x%04X)!", sid));
                return invalid_handle_st;
              }

            /* Delete the original handle and create a new one (having updated)
               information */
            ssh_appgw_cifs_search_handle_remove(search);

            search = ssh_appgw_cifs_search_handle_allocate(conn,
                                               SSH_APPGW_CIFS_DATA_BLOCK,
                                               param_ptr+12,
                                               trans2->client.param_count-12,
                                               cifs->unicode_strings);
            if (search == NULL)
              return no_memory_st;

            search->id = sid;

            if (flags & 0x0001)
              search->close_after_request = 1;

            if (flags & 0x0002)
              search->close_when_complete = 1;

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", search->name));

            trans2->context = search;
          }
          break;

        case SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION:
          {
            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr);

            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                    ssh_appgw_cifs_fs_info_level_to_name(trans2->info_level),
                    trans2->info_level));
          }
          break;

        case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
          {
            SshUInt32 mbz;

            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            mbz = SSH_GET_32BIT_LSB_FIRST(param_ptr+2);

            if (mbz != 0)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Reserved field not initialized to zero!"));
                return broken_st;
              }

            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                  trans2->info_level));

            if (ssh_appgw_cifs_transaction_name_set(trans2, param_ptr+6,
                                              trans2->client.param_count-6,
                                              cifs->unicode_strings) == FALSE)
              {
                return no_memory_st;
              }

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"",
                                        trans2->name_ptr));
          }
          break;

        case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
          {
            SshUInt32 mbz;

            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            mbz = SSH_GET_32BIT_LSB_FIRST(param_ptr+2);

            if (mbz != 0)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Reserved field not initialized to zero!"));
                return broken_st;
              }

            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                  trans2->info_level));

            if (ssh_appgw_cifs_transaction_name_set(trans2, param_ptr+6,
                                            trans2->client.param_count-6,
                                            cifs->unicode_strings) == FALSE)
              {
                return no_memory_st;
              }

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"",
                                        trans2->name_ptr));
          }
          break;

        case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
          {
            trans2->fid = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);

            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", trans2->fid));
            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                trans2->info_level));

            if (ssh_appgw_cifs_file_handle_lookup(conn, trans2->fid) == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Invalid handle (fid=0x%04X)!", trans2->fid));
                return invalid_handle_st;
              }
          }
          break;

        case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
          {
            trans2->fid = SSH_GET_16BIT_LSB_FIRST(param_ptr);
            trans2->info_level = SSH_GET_16BIT_LSB_FIRST(param_ptr+2);
            /* skip two reserved bytes */

            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", trans2->fid));
            SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = %s (0x%04X)",
                  ssh_appgw_cifs_file_info_level_to_name(trans2->info_level),
                  trans2->info_level));

            if (ssh_appgw_cifs_file_handle_lookup(conn, trans2->fid) == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Invalid handle (fid=0x%04X)!", trans2->fid));
                return invalid_handle_st;
              }
          }
          break;

        case SSH_SMB_TRANSACT2_CREATE_DIRECTORY:
          {
            SshUInt32 mbz;

            mbz = SSH_GET_32BIT_LSB_FIRST(param_ptr);
            if (mbz != 0)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Reserved field not initialized to zero!"));
                return broken_st;
              }

            if (ssh_appgw_cifs_transaction_name_set(trans2, param_ptr+6,
                                              trans2->client.param_count-6,
                                              cifs->unicode_strings) == FALSE)
              {
                return no_memory_st;
              }

            SSH_DEBUG(SSH_D_NICETOKNOW, ("- directory: \"%s\"",
                                        trans2->name_ptr));
          }
          break;

        case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
#ifdef DEBUG_LIGHT
          {
            SshUInt16 max_level;
            char *dfs_name;

            max_level = SSH_GET_16BIT_LSB_FIRST(param_ptr);

            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- max_referral_level = %u", max_level));

            dfs_name = ssh_appgw_cifs_strdup(cifs_alg,
                                             SSH_APPGW_CIFS_DATA_PATHNAME,
                                             param_ptr+2,
                                             trans2->client.param_count-2,
                                             cifs->unicode_strings);

            if (dfs_name == NULL)
              return no_memory_st;

            SSH_DEBUG(SSH_D_DATADUMP, ("- DFS_name = \"%s\"", dfs_name));

            ssh_free(dfs_name);
          }
#endif /* DEBUG_LIGHT */
          break;

        case SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY:
#ifdef DEBUG_LIGHT
          {
            char *dfs_name = ssh_appgw_cifs_strdup(cifs_alg,
                                                 SSH_APPGW_CIFS_DATA_PATHNAME,
                                                 param_ptr,
                                                 trans2->client.param_count,
                                                 cifs->unicode_strings);
            if (dfs_name == NULL)
              return no_memory_st;

            SSH_DEBUG(SSH_D_DATADUMP, ("- DFS_name = \"%s\"", dfs_name));

            ssh_free(dfs_name);
          }
#endif /* DEBUG_LIGHT */
          break;

        case SSH_SMB_TRANSACT2_SESSION_SETUP:
          /* Not implemented yet */
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      /* If we didn't copy the parameter bytes, we can't touch them any more */
      if (trans2->request_params_copied == 0)
        trans2->client.params = NULL;
    }

  /* If all data bytes sent, check data */
  if ((trans2->client.data_count == trans2->client.total_data_count) &&
      (trans2->client.data != NULL) &&
      (trans2->request_data_checked == 0))
    {
      trans2->request_data_checked = 1;

      /* If we didn't copy the data bytes, we can't touch them any more */
      if (trans2->request_data_copied == 0)
        trans2->client.data = NULL;
    }

  return continue_st;
}


/* Checks whether a SMB_COM_NT_TRANSACTION request is valid */
static SshFSMStepCB
ssh_appgw_cifs_nt_transact_request_filter(SshAppgwCifsConn conn,
                                          SshAppgwCifsParser cifs,
                                          SshAppgwCifsTransaction transact)
{
  static SshFSMStepCB continue_st = ssh_appgw_cifs_st_def_request_filter;
  static SshFSMStepCB broken_st = ssh_appgw_cifs_st_broken_request;
  static SshFSMStepCB invalid_h_st = ssh_appgw_cifs_st_req_invalid_handle;
  static SshFSMStepCB no_mem_st = ssh_appgw_cifs_st_request_out_of_mem;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- function = %s (0x%02X)",
            ssh_appgw_cifs_nt_transact_to_name(transact->subcommand),
            transact->subcommand));

  if (transact->first_request)
    {
      SshUInt16 setup_count = (SshUInt16)(cifs->word_count - 19);
      const unsigned char *setup_ptr = NULL;

      if (setup_count)
        setup_ptr = (const unsigned char *)cifs->parameters + 38;

      switch (transact->subcommand)
        {
        case SSH_SMB_NT_TRANSACT_CREATE:
          if (transact->client.total_param_count < 53)
            return broken_st;
          break;

        case SSH_SMB_NT_TRANSACT_IOCTL:
          {
#ifdef DEBUG_LIGHT
            SshUInt32 fn_code;
            SshUInt8 is_fsctl;
            SshUInt8 flags;
#endif /* DEBUG_LIGHT */

            if ((setup_count != 4) ||
                (transact->client.total_param_count != 0))
              return broken_st;

#ifdef DEBUG_LIGHT
            fn_code = SSH_GET_32BIT_LSB_FIRST(setup_ptr);
#endif /* DEBUG_LIGHT */
            transact->fid = SSH_GET_16BIT_LSB_FIRST(setup_ptr+4);
#ifdef DEBUG_LIGHT
            is_fsctl = SSH_GET_8BIT(setup_ptr+6);
            flags = SSH_GET_8BIT(setup_ptr+7);

            SSH_DEBUG(SSH_D_DATADUMP, ("- function_code = 0x%X",
				       (unsigned int) fn_code));
            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", transact->fid));
            SSH_DEBUG(SSH_D_DATADUMP, ("- is_fsctl = %u", is_fsctl));
            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%02X", flags));
#endif /* DEBUG_LIGHT */

            if (ssh_appgw_cifs_file_handle_lookup(conn,
                                                  transact->fid) == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid handle (fid=0x%04X)!", transact->fid));
                return invalid_h_st;
              }
          }
          break;

        case SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE:
          {
#ifdef DEBUG_LIGHT
            SshUInt32 filter;
            SshUInt8 watch_tree;
#endif /* DEBUG_LIGHT */

            if ((setup_count != 4) ||
                (transact->client.total_param_count != 0))
              return broken_st;

#ifdef DEBUG_LIGHT
            filter = SSH_GET_32BIT_LSB_FIRST(setup_ptr);
#endif /* DEBUG_LIGHT */
            transact->fid = SSH_GET_16BIT_LSB_FIRST(setup_ptr+4);
#ifdef DEBUG_LIGHT
            watch_tree = SSH_GET_8BIT(setup_ptr+6);

            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- completion_filter = 0x%08lX",
		       (unsigned long) filter));
            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", transact->fid));
            SSH_DEBUG(SSH_D_DATADUMP, ("- watch_tree = %u", watch_tree));
#endif /* DEBUG_LIGHT */

            if (ssh_appgw_cifs_file_handle_lookup(conn,
                                                  transact->fid) == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid handle (fid=0x%04X)!", transact->fid));
                return invalid_h_st;
              }

            /* We shouldn't use timeouts for this request, because it can
               stay pending "forever" */
            cifs->no_timeout = 1;
          }
          break;

        case SSH_SMB_NT_TRANSACT_RENAME:
          /* format undocumented */
          break;

        case SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC:
        case SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC:
          if (transact->client.total_param_count != 8)
            return broken_st;
          break;

        default:
          ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "request containing unsupported subcommand "
                                "received",
                                SSH_AUDIT_CIFS_COMMAND,
                                ssh_appgw_cifs_cmd_to_name(cifs->command),
                                SSH_AUDIT_CIFS_SUBCOMMAND,
                                transact->subcommand,
                                SSH_AUDIT_ARGUMENT_END);
          return broken_st;
        }
    }

  /* Check the parameter bytes */
  if ((transact->client.param_count == transact->client.total_param_count) &&
      (transact->client.params != NULL) &&
      (transact->request_params_checked == 0))
    {
      const unsigned char *param_ptr = transact->client.params;

      switch (transact->subcommand)
        {
        case SSH_SMB_NT_TRANSACT_CREATE:
          {
#ifdef DEBUG_LIGHT
            SshUInt32 root_fid;
            SshUInt32 attributes;
            SshUInt32 share_access;
            SshUInt32 disposition;
            SshUInt32 options;
            SshUInt32 sd_len;
            SshUInt32 ea_len;
            SshUInt32 impersonation;
            SshUInt8 security;
#endif /* DEBUG_LIGHT */
            SshUInt32 flags;
            SshUInt32 access_mask;
            SshUInt32 name_len;
            SshAppgwCifsFileHandle file;

            flags = SSH_GET_32BIT_LSB_FIRST(param_ptr);
#ifdef DEBUG_LIGHT
            root_fid = SSH_GET_32BIT_LSB_FIRST(param_ptr+4);
#endif /* DEBUG_LIGHT */
            access_mask = SSH_GET_32BIT_LSB_FIRST(param_ptr+8);
#ifdef DEBUG_LIGHT
            /* skip allocation size (8 bytes) */
            attributes = SSH_GET_32BIT_LSB_FIRST(param_ptr+20);
            share_access = SSH_GET_32BIT_LSB_FIRST(param_ptr+24);
            disposition = SSH_GET_32BIT_LSB_FIRST(param_ptr+28);
            options = SSH_GET_32BIT_LSB_FIRST(param_ptr+32);
            sd_len = SSH_GET_32BIT_LSB_FIRST(param_ptr+36);
            ea_len = SSH_GET_32BIT_LSB_FIRST(param_ptr+40);
#endif /* DEBUG_LIGHT */
            name_len = SSH_GET_32BIT_LSB_FIRST(param_ptr+44);
#ifdef DEBUG_LIGHT
            impersonation = SSH_GET_32BIT_LSB_FIRST(param_ptr+48);
            security = SSH_GET_8BIT(param_ptr+52);

            SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%08lX",
				       (unsigned long) flags));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- root_directory_fid = 0x%08lX",
		       (unsigned long) root_fid));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- desired_access = 0x%08lX",
		       (unsigned long) access_mask));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- ext_file_attributes = 0x%08lX",
		       (unsigned long) attributes));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- share_access = 0x%08lX",
		       (unsigned long) share_access));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- create_disposition = 0x%08lX",
		       (unsigned long) disposition));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- create_options = 0x%08lX",
		       (unsigned long) options));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- security_descriptor_length = %lu",
		       (unsigned long) sd_len));
            SSH_DEBUG(SSH_D_DATADUMP, ("- EA_length = %lu",
				       (unsigned long) ea_len));
            SSH_DEBUG(SSH_D_DATADUMP, ("- name_len = %lu",
				       (unsigned long) name_len));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- impersonation_level = 0x%08lX",
		       (unsigned long) impersonation));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- security_flags = 0x%02X", security));
#endif /* DEBUG_LIGHT */

            /* Allocate new "file handle" */
            file = ssh_appgw_cifs_file_handle_allocate(conn,
                                            SSH_APPGW_CIFS_DATA_BLOCK,
                                            param_ptr+53,
                                            transact->client.param_count-53,
                                            cifs->unicode_strings);
            if (file == NULL)
              return no_mem_st;

            if (name_len)
              {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("- filename: \"%s\"", file->name));
              }

            if (flags & 0x08)
              file->directory = 1;

            ssh_appgw_cifs_decode_access_mask(file, access_mask);

            transact->context = file;
          }
          break;

        case SSH_SMB_NT_TRANSACT_IOCTL:
          /* NT_TRANSACT_IOCTL contains no parameter bytes */
          break;

        case SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE:
          /* NT_TRANSACT_NOTIFY_CHANGE contains no parameter bytes */
          break;

        case SSH_SMB_NT_TRANSACT_RENAME:
          /* format undocumented */
          break;

        case SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC:
        case SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC:
          {
#ifdef DEBUG_LIGHT
            SshUInt32 security_info;
#endif /* DEBUG_LIGHT */

            transact->fid = SSH_GET_16BIT_LSB_FIRST(param_ptr);
#ifdef DEBUG_LIGHT
            /* skip two reserved bytes */
            security_info = SSH_GET_32BIT_LSB_FIRST(param_ptr+4);

            SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", transact->fid));
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("- security_information = 0x%08lX",
		       (unsigned long) security_info));
#endif /* DEBUG_LIGHT */

            if (ssh_appgw_cifs_file_handle_lookup(conn,
                                                  transact->fid) == NULL)
              {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("Invalid handle (fid=0x%04X)!", transact->fid));
                return invalid_h_st;
              }
          }
          break;

        default:
          SSH_NOTREACHED;
          break;
        }
    }

  return continue_st;
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_st_request_out_of_mem)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_WARNING,
                        SSH_AUDIT_TXT,
                        "low on memory. request dropped.",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_out_of_memory);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_broken_request)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "Broken request!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_broken_rpc_request)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "Broken DCE/RPC request!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_req_invalid_handle)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Invalid handle specified in request!",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NEGOTIATE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_negotiate_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsNegotiateCtx negotiate_ctx = NULL;
  SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
  size_t bytes_left;
  const unsigned char *data;
  SshUInt16 dialect_count = 0;
  SshUInt16 i;

  /* Check that nobody has messed up the prefiltering rules */
  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count >= 2);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("CIFS dialects supported by client:"));

  /* Check the validity of CIFS dialects. */
  data = cifs->buffer;
  bytes_left = cifs->byte_count;

  while (bytes_left >= 3)
    {
      size_t dialect_size;

      if ((ssh_appgw_cifs_strsize(&dialect_size, SSH_APPGW_CIFS_DATA_DIALECT,
                                  data, bytes_left, FALSE) == TRUE) &&
          (dialect_size > 0 || dialect_size <= bytes_left))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("- \"%s\"", &(data[1])));

          dialect_count++;
          data += dialect_size;
          bytes_left -= dialect_size;
        }
      else
        {
          goto invalid_negotiate_request;
        }
    }

  if (dialect_count == 0)
    goto invalid_negotiate_request;

  /* Dialects seem to be valid. We can pass this packet if we have enough
     memory to create a context structure */
  negotiate_ctx = ssh_appgw_cifs_cmd_context_allocate(conn, cifs,
                                      sizeof(*negotiate_ctx),
                                      ssh_appgw_cifs_negotiate_ctx_delete_cb);
  if (negotiate_ctx == NULL)
    goto negotiate_req_out_of_memory;

  negotiate_ctx->dialect_count = dialect_count;
  negotiate_ctx->dialect_ptrs = ssh_calloc(dialect_count,
                                           sizeof(unsigned char *));
  if (negotiate_ctx->dialect_ptrs == NULL)
    goto negotiate_req_out_of_memory;

  data = cifs->buffer;
  bytes_left = cifs->byte_count;

  for (i = 0; i < negotiate_ctx->dialect_count; i++)
    {
      size_t dialect_size;

      ssh_appgw_cifs_strsize(&dialect_size, SSH_APPGW_CIFS_DATA_DIALECT,
                             data, bytes_left, FALSE);

      negotiate_ctx->dialect_ptrs[i] =
        (unsigned char*)ssh_appgw_cifs_strdup(cifs_alg,
                                              SSH_APPGW_CIFS_DATA_DIALECT,
                                              data, bytes_left, FALSE);
      if (negotiate_ctx->dialect_ptrs[i] == NULL)
        goto negotiate_req_out_of_memory;

      /* terminating null-character + dialect type -> two extra bytes */
      bytes_left -= dialect_size;
      data += dialect_size;
    }

  conn->session_phase = SSH_APPGW_CIFS_SESSION_NEGOTIATING;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;

negotiate_req_out_of_memory:

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
  return SSH_FSM_CONTINUE;

invalid_negotiate_request:

  /* We send error response if either the request is malformed */
  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Malformed SMB_COM_NEGOTIATE request",
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_SESSION_SETUP_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_session_setup_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsRequest request;
  SshAppgwCifsSession session;
  const unsigned char *params = cifs->parameters;
  const unsigned char *ucp;
  char *account = NULL;
  char *domain = NULL;
  unsigned char *blob = NULL;
#ifdef DEBUG_LIGHT
  char *native_os = NULL;
  char *lan_man = NULL;
#endif /* DEBUG_LIGHT */
  size_t buff_size;
  SshUInt32 session_key;
  SshUInt32 capabilities = 0;
  SshUInt16 max_buffer_size;
  SshUInt16 max_mpx_count;
  SshUInt16 password_len = 0;
  SshUInt16 unicode_pw_len = 0;
  SshUInt16 security_blob_len = 0;
  SshUInt16 vc_number = 0;

  if (conn->cifs_version < SSH_APPGW_CIFS_VERSION_NTLM)
    {
      if (cifs->word_count != 10)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
          return SSH_FSM_CONTINUE;
        }

      max_buffer_size = SSH_GET_16BIT_LSB_FIRST(params+4);
      max_mpx_count = SSH_GET_16BIT_LSB_FIRST(params+6);
      vc_number = SSH_GET_16BIT_LSB_FIRST(params+8);
      session_key = SSH_GET_16BIT_LSB_FIRST(params+10);
      password_len = SSH_GET_16BIT_LSB_FIRST(params+14);

      SSH_DEBUG(SSH_D_DATADUMP, ("- password_len = %u", password_len));
    }
  else
    {
      if (conn->server_flags.ext_security && (cifs->word_count == 12))
        {
          /* Client supports Extended Security */
          max_buffer_size = SSH_GET_16BIT_LSB_FIRST(params+4);
          max_mpx_count = SSH_GET_16BIT_LSB_FIRST(params+6);
          vc_number = SSH_GET_16BIT_LSB_FIRST(params+8);
          session_key = SSH_GET_32BIT_LSB_FIRST(params+10);
          security_blob_len = SSH_GET_16BIT_LSB_FIRST(params+14);
          /* skip reserved field (4 bytes) */
          capabilities = SSH_GET_32BIT_LSB_FIRST(params+20);
        }
      else if (cifs->word_count == 13)
        {
          /* Client does not support Extended Security */
          max_buffer_size = SSH_GET_16BIT_LSB_FIRST(params+4);
          max_mpx_count = SSH_GET_16BIT_LSB_FIRST(params+6);
          vc_number = SSH_GET_16BIT_LSB_FIRST(params+8);
          session_key = SSH_GET_32BIT_LSB_FIRST(params+10);
          password_len = SSH_GET_16BIT_LSB_FIRST(params+14);
          unicode_pw_len = SSH_GET_16BIT_LSB_FIRST(params+16);
          /* skip reserved field (4 bytes) */
          capabilities = SSH_GET_32BIT_LSB_FIRST(params+22);

          SSH_DEBUG(SSH_D_DATADUMP, ("- ascii_pw_len = %u", password_len));
          SSH_DEBUG(SSH_D_DATADUMP, ("- unicode_pw_len = %u", unicode_pw_len));
        }
      else
        {
          goto session_req_broken;
        }

      SSH_DEBUG(SSH_D_DATADUMP, ("- capabilities = 0x%08lX",
				 (unsigned long) capabilities));
    }

  if ((security_blob_len + password_len + unicode_pw_len) > cifs->byte_count)
    goto session_req_broken;

  /* Limit the maximum buffer size */
  if (max_buffer_size > conn->max_buffer_size)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Maximum buffer size limited to %u (was %u)",
		 (unsigned int) conn->max_buffer_size,
		 (unsigned int) max_buffer_size));
      max_buffer_size = conn->max_buffer_size;
      SSH_PUT_16BIT_LSB_FIRST(params+4, max_buffer_size);
    }

  SSH_DEBUG(SSH_D_DATADUMP, ("- max_buffer_size = %u",
			     (unsigned int) max_buffer_size));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_mpx_count = %u",
			     (unsigned int) max_mpx_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- vc_number = %u",
			     (unsigned int) vc_number));
  SSH_DEBUG(SSH_D_DATADUMP, ("- session_key = 0x%08lX",
			     (unsigned long) session_key));

  if (capabilities & 0x0004)
    conn->client_flags.unicode = 0;

  if (capabilities & 0x0008)
    conn->client_flags.large_files = 0;

  if (capabilities & 0x0010)
    conn->client_flags.nt_smbs = 0;

  if (capabilities & 0x0040)
    conn->client_flags.nt_error_codes = 0;

  if (conn->max_pending_requests > max_mpx_count)
    conn->max_pending_requests = max_mpx_count;

  ucp = cifs->buffer;
  buff_size = cifs->byte_count;
  if (password_len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("- Password (ASCII) (%u bytes):", password_len),
                        ucp, password_len);

      ucp += password_len;
      buff_size -= password_len;
    }

  if (unicode_pw_len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("- Password (UNICODE) (%u bytes):", unicode_pw_len),
                        ucp, unicode_pw_len);

      ucp += unicode_pw_len;
      buff_size -= unicode_pw_len;
    }

  if (vc_number == 0)
    {
      size_t str_size;
      SshAppgwCifsCtx cifs_alg;

      cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
      SSH_ASSERT(cifs_alg != NULL);

      if (security_blob_len > 0)
        {
          const char ntlmssp3_id[] =
            {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0, 3, 0, 0, 0};

          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                            ("- Security BLOB (%d bytes):",
                            security_blob_len),
                            cifs->buffer, security_blob_len);

          if ((security_blob_len >= 44) &&
              memcmp(cifs->buffer, ntlmssp3_id, sizeof(ntlmssp3_id)) == 0)
            {
              SshUInt16 dom_len1, dom_len2, acc_len1, acc_len2;
              SshUInt32 dom_offset, acc_offset;

              blob = ssh_malloc(security_blob_len);
              if (blob == NULL)
                goto session_req_out_of_mem;

              memcpy(blob, cifs->buffer, security_blob_len);

              dom_len1 = SSH_GET_16BIT_LSB_FIRST(blob + 28);
              dom_len2 = SSH_GET_16BIT_LSB_FIRST(blob + 30);
              dom_offset = SSH_GET_32BIT_LSB_FIRST(blob + 32);
              acc_len1 = SSH_GET_16BIT_LSB_FIRST(blob + 36);
              acc_len2 = SSH_GET_16BIT_LSB_FIRST(blob + 38);
              acc_offset = SSH_GET_32BIT_LSB_FIRST(blob + 40);

              SSH_DEBUG(SSH_D_MY5, ("domain_len1 = %u", dom_len1));
              SSH_DEBUG(SSH_D_MY5, ("domain_len2 = %u", dom_len2));
              SSH_DEBUG(SSH_D_MY5, ("domain_offset = %u",
				    (unsigned int) dom_offset));
              SSH_DEBUG(SSH_D_MY5, ("account_len1 = %u", acc_len1));
              SSH_DEBUG(SSH_D_MY5, ("account_len2 = %u", acc_len2));
              SSH_DEBUG(SSH_D_MY5, ("account_offset = %u",
				    (unsigned int) acc_offset));

              if ((dom_len1 != dom_len2) ||
                  (acc_len1 != acc_len2) ||
                  ((dom_offset + dom_len1) > security_blob_len) ||
                  ((acc_offset + acc_len1) > security_blob_len))
                goto session_req_broken;

              if (acc_len1)
                {
                  account = ssh_appgw_cifs_strdup(cifs_alg,
                                                  SSH_APPGW_CIFS_DATA_BLOCK,
                                                  blob + acc_offset, acc_len1,
                                                  cifs->unicode_strings);
                  if (account == NULL)
                    goto session_req_out_of_mem;
                }

              if (dom_len1)
                {
                  domain = ssh_appgw_cifs_strdup(cifs_alg,
                                                 SSH_APPGW_CIFS_DATA_BLOCK,
                                                 blob + dom_offset, dom_len1,
                                                 cifs->unicode_strings);
                  if (domain == NULL)
                    goto session_req_out_of_mem;
                }
            }

          ucp += security_blob_len;
          buff_size -= security_blob_len;
        }
      else
        {
          /* Account name */
          if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                                     ucp, buff_size,
                                     cifs->unicode_strings) == FALSE)
            goto session_req_broken;

          account = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                          ucp, buff_size,
                                          cifs->unicode_strings);
          if (account == NULL)
            goto session_req_out_of_mem;

          ucp += str_size;
          buff_size -= str_size;

          /* Domain */
          if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                                     ucp, buff_size,
                                     cifs->unicode_strings) == FALSE)
            goto session_req_broken;

          domain = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                         ucp, buff_size,
                                         cifs->unicode_strings);
          if (domain == NULL)
            goto session_req_out_of_mem;

          ucp += str_size;
          buff_size -= str_size;
        }

      /* Native OS */
      if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                                 ucp, buff_size,
                                 cifs->unicode_strings) == FALSE)
        goto session_req_broken;

#ifdef DEBUG_LIGHT
      native_os = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                        ucp, buff_size,
                                        cifs->unicode_strings);
      if (native_os == NULL)
        goto session_req_out_of_mem;
#endif /* DEBUG_LIGHT */

      ucp += str_size;
      buff_size -= str_size;

      /* Native LAN manager */
      if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_BLOCK,
                                 ucp, buff_size,
                                 cifs->unicode_strings) == FALSE)
        goto session_req_broken;

#ifdef DEBUG_LIGHT
      lan_man = ssh_appgw_cifs_strdup(cifs_alg, SSH_APPGW_CIFS_DATA_BLOCK,
                                      ucp, buff_size,
                                      cifs->unicode_strings);
      if (lan_man == NULL)
        goto session_req_out_of_mem;

      SSH_DEBUG(SSH_D_DATADUMP, ("- Account = \"%s\"", account));
      SSH_DEBUG(SSH_D_DATADUMP, ("- Domain = \"%s\"", domain));
      SSH_DEBUG(SSH_D_DATADUMP, ("- Native OS = \"%s\"", native_os));
      SSH_DEBUG(SSH_D_DATADUMP, ("- LAN manager = \"%s\"", lan_man));

      ssh_free(native_os);
      ssh_free(lan_man);

      native_os = NULL;
      lan_man = NULL;
#endif /* DEBUG_LIGHT */
    }

  /* In case of extended authentication, we update the session context
     associated with the _first_ SESSION_SETUP request. */
  request = ssh_appgw_cifs_pending_request_lookup(conn, cifs);
  if (request != NULL)
    {
      session = request->cmd_ctx->context;

      SSH_ASSERT(session != NULL);

      /* If the 'ext_authentication' flag is not set, we are re-sending
         the request and thus the pending request we just picked is not
         valid any more. Let's delete the old request and allocate a new
         session context. */
      if (session->ext_authentication == 0)
        {
          ssh_appgw_cifs_pending_request_remove(request);
          goto session_allocate;
        }

      if (session->account == NULL)
        session->account = account;
      else
        ssh_free(account);

      if (session->domain == NULL)
        session->domain = domain;
      else
        ssh_free(domain);

      ssh_free(blob);

      SSH_ASSERT(cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND);

      cifs->no_response = 1;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
      return SSH_FSM_CONTINUE;
    }

session_allocate:

  session = ssh_appgw_cifs_cmd_context_allocate(conn, cifs, sizeof(*session),
                                           ssh_appgw_cifs_session_delete_cb);
  if (session == NULL)
    goto session_req_out_of_mem;

  session->conn = conn;
  session->account = account;
  session->domain = domain;
  session->vc_number = vc_number;

  if ((security_blob_len == 0) &&
      ((account == NULL) || (strlen(account) == 0)) &&
      ((domain == NULL) || (strlen(domain) == 0)))
    {
      if (session->vc_number == 0)
        {
          /* Anonymous logon i.e. null session */
          ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Client request a NULL session (anonymous "
                                "logon)",
                                SSH_AUDIT_ARGUMENT_END);

          /* Here we could block and reject primary NULL session requests */
        }

      session->null_session = 1;
    }

  /* Filter the embedded commands */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;

session_req_broken:

  ssh_free(account);
  ssh_free(domain);
  ssh_free(blob);
#ifdef DEBUG_LIGHT
  ssh_free(native_os);
  ssh_free(lan_man);
#endif /* DEBUG_LIGHT */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
  return SSH_FSM_CONTINUE;

session_req_out_of_mem:

  ssh_free(account);
  ssh_free(domain);
  ssh_free(blob);
#ifdef DEBUG_LIGHT
  ssh_free(native_os);
  ssh_free(lan_man);
#endif /* DEBUG_LIGHT */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_LOGOFF_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_session_logoff_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsSession session;

  session = ssh_appgw_cifs_session_lookup(conn, cifs);
  if (session == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Session not found!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_session_remove(session);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CREATE_DIRECTORY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_create_dir_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const char *directory;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count >= 2);

  directory = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                         SSH_APPGW_CIFS_DATA_STRING,
                                         (const unsigned char *)cifs->buffer,
                                         cifs->byte_count,
                                         cifs->unicode_strings);
  if (directory == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- directory = \"%s\"", directory));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_DELETE_DIRECTORY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_dir_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const char * directory;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count >= 2);

  directory = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                         SSH_APPGW_CIFS_DATA_STRING,
                                         (const unsigned char *)cifs->buffer,
                                         cifs->byte_count,
                                         cifs->unicode_strings);
  if (directory == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- directory = \"%s\"", directory));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_CONNECT request */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count >= 4);

  tree = ssh_appgw_cifs_tree_ctx_allocate(conn, cifs, cifs->buffer,
                                          cifs->byte_count,
                                          cifs->unicode_strings);
  if (tree == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- tree = \"%s\"", tree->name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_CONNECT_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTree tree;
  SshUInt16 flags;
  SshUInt16 password_len;
  unsigned char *params = cifs->parameters;
  unsigned char *buffer = cifs->buffer;

  SSH_ASSERT(cifs->word_count == 4);
  SSH_ASSERT(cifs->byte_count >= 3);

  /* skip ANDX block */
  flags = SSH_GET_16BIT_LSB_FIRST(params+4);
  password_len = SSH_GET_16BIT_LSB_FIRST(params+6);

  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- password_len = %u", password_len));

  /* if bit0 is of flags is set, server disconnects the tree specified by
     "tid" in SMB header. */
  if (flags & 0x01)
    {
      /* Client requests the server to disconnect the tree specified by
         SMB header of this packet. We need to update our bookkeeping now,
         because this is the last time we see this tree id. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Deleting old tree 0x%04X", cifs->tid));

      tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

      if (tree)
        ssh_appgw_cifs_tree_remove(tree);
      else
        SSH_DEBUG(SSH_D_ERROR, ("Unknown tree ID: 0x%04X", cifs->tid));
    }

  tree = ssh_appgw_cifs_tree_ctx_allocate(conn, cifs, buffer + password_len,
                                          cifs->byte_count - password_len,
                                          cifs->unicode_strings);
  if (tree == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- tree = \"%s\"", tree->name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TREE_DISCONNECT request */
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_disconnect_req)
{
#ifdef DEBUG_LIGHT
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CLOSE_AND_TREE_DISCONNECT request */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_and_tree_disc_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->word_count == 3);
  SSH_ASSERT(cifs->byte_count == 0);

  SSH_ASSERT(cifs->tree != NULL);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_log_fclose_event(conn, cifs, cifs->tree, file);
  ssh_appgw_cifs_file_handle_remove(file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TRANSACTION request */
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshUInt16 total_param_count;
  SshUInt16 total_data_count;
  SshUInt16 max_param_count;
  SshUInt16 max_data_count;
  SshUInt8 max_setup_count;
  SshUInt16 flags;
  SshUInt32 timeout;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 data_count;
  SshUInt16 data_offset;
  SshUInt8 setup_count;

  /* Ensure that nobody has messed up our pre-filtering rules */
  SSH_ASSERT(cifs->word_count >= 14);

  total_param_count = SSH_GET_16BIT_LSB_FIRST(params);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+2);
  max_param_count = SSH_GET_16BIT_LSB_FIRST(params+4);
  max_data_count = SSH_GET_16BIT_LSB_FIRST(params+6);
  max_setup_count = SSH_GET_8BIT(params+8);
  /* skip reserved byte */
  flags = SSH_GET_16BIT_LSB_FIRST(params+10);
  timeout = SSH_GET_32BIT_LSB_FIRST(params+12);
  /* skip two reserved bytes */
  param_count = SSH_GET_16BIT_LSB_FIRST(params+18);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+20);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+22);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+24);
  setup_count = SSH_GET_8BIT(params+26);
  /* one byte padding */

  SSH_DEBUG(SSH_D_DATADUMP, ("- total_param_count = %u",total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_param_count = %u", max_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_data_count = %u", max_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_setup_count = %u", max_setup_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- timeout = %lu", timeout));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  if ((setup_count != (cifs->word_count - 14)) ||
      (param_count > total_param_count) ||
      (data_count > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  if (flags & 0x01)
    {
      SshAppgwCifsTree tree;

      /* Client requests the server to disconnect the tree specified by
         SMB header of this packet. We need to update our bookkeeping now,
         because this is probably the last time we see this tree id. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Deleting old tree 0x%04X", cifs->tid));

      tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

      if (tree)
        ssh_appgw_cifs_tree_remove(tree);
      else
        SSH_DEBUG(SSH_D_ERROR, ("Unknown tree ID: 0x%04X", cifs->tid));
    }

  transaction = ssh_appgw_cifs_transaction_ctx_allocate(conn, cifs,
                                                      cifs->buffer,
                                                      cifs->byte_count,
                                                      cifs->unicode_strings);
  if (transaction == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  cifs->transaction = 1;

  transaction->client.total_param_count = total_param_count;
  transaction->client.param_count = param_count;
  transaction->client.total_data_count = total_data_count;
  transaction->client.data_count = data_count;

  transaction->server.max_setup_count = max_setup_count;
  transaction->server.setup_count = 0;
  transaction->server.max_param_count = max_param_count;
  transaction->server.total_param_count = 0;
  transaction->server.param_count = 0;
  transaction->server.max_data_count = max_data_count;
  transaction->server.total_data_count = 0;
  transaction->server.data_count = 0;

  /* Note that we should not set the 'no_response' flag if this is an
     embedded SMB_COM_TRANSACTION request */
  if (cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND)
    {
      /* This is one-way transaction. Server doesn't send any response. */
      if (flags & 0x02)
        cifs->no_response = 1;
    }

  if ((setup_count >= 2) &&
      (memcmp(transaction->name_ptr, "\\PIPE\\", 6) == 0))
    {
      unsigned char *pipe_name = transaction->name_ptr;
      Boolean fid_required = FALSE;
      SshUInt16 param_word;

      transaction->pipe_transaction = 1;
      transaction->subcommand = SSH_GET_16BIT_LSB_FIRST(params+28);

      if (strcmp((const char *)transaction->name_ptr,
                 (const char *)"\\PIPE\\") == 0)
        transaction->dce_rpc = 1;

      switch (transaction->subcommand)
        {
        case SSH_SMB_PRC_PIPE_SET_STATE:
          /* Check the parameter and data counts */
          if ((total_param_count != 2) || (total_data_count != 0) ||
              (max_param_count != 0) ||   (max_data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

#ifdef DEBUG_LIGHT
          {
            SshUInt16 state;
            unsigned char *param_ptr = cifs->packet_ptr + param_offset;

            state = SSH_GET_16BIT_LSB_FIRST(param_ptr);

            ssh_appgw_cifs_dump_pipe_state((SshUInt16)(state & 0xCFFF));
          }
#endif /* DEBUG_LIGHT */

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_QUERY_STATE:
          /* Check the parameter and data counts */
          if ((total_param_count != 0) || (total_data_count != 0) ||
              (max_param_count != 2) ||   (max_data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_QUERY_INFO:
          /* Check the parameter and data counts */
          if ((total_param_count != 2) || (total_data_count != 0) ||
              (max_param_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

          /* value of parameter word must be 1 */
          param_word = SSH_GET_16BIT_LSB_FIRST(cifs->packet_ptr+param_offset);
          if (param_word != 1)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_TRANSACT:
          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_READ_RAW:
          /* Check the parameter and data counts */
          if (max_param_count != 0)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_WRITE_RAW:
          /* Check the parameter and data counts */
          if ((total_param_count != 0) ||
              (max_param_count != 2) || (max_data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }

          fid_required = TRUE;
          break;

        case SSH_SMB_RPC_PIPE_CALL:
          /* uses name instead of 'fid' */
          break;

        case SSH_SMB_RPC_PIPE_WAIT:
          /* Check the parameter and data counts */
          if ((total_param_count != 0) || (total_data_count != 0) ||
              (max_param_count != 0) ||   (max_data_count != 0))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }
          /* uses name instead of 'fid' */
          break;

        case SSH_SMB_RPC_PIPE_PEEK:
          /* Check the parameter and data counts */
          if ((total_param_count != 0) || (total_data_count != 0) ||
              (max_param_count != 6))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }
          fid_required = TRUE;
          break;

        default:
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("- subcommand = 0x%02X", transaction->subcommand));
          break;
        }

      if (fid_required)
        {
          SshAppgwCifsFileHandle file;

          transaction->fid = SSH_GET_16BIT_LSB_FIRST(params+30);

          file = ssh_appgw_cifs_file_handle_lookup(conn, transaction->fid);

          if (file != NULL)
            pipe_name = file->name;
          else
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid handle (fid=0x%04X)!", transaction->fid));

              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
              return SSH_FSM_CONTINUE;
            }
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
              ("- %s pipe transaction request "
               "(pipe=\"%s%s\", command=\"%s\")",
              (transaction->dce_rpc == 1) ? "DCE/RPC" : "",
              cifs->tree->name, pipe_name,
              ssh_appgw_cifs_pipe_transact_to_name(transaction->subcommand)));

      if ((transaction->dce_rpc) && (data_count == total_data_count))
        {
          /* The complete DCE/RPC PDU has been received in one transaction
             request, so we can check it now. Otherwise, it will be checked
             when we receive the last SMB_COM_TRANSACTION_SECONDARY packet
             belonging to the same transaction */

          SshDceRpcPDU pdu = ssh_dce_rpc_pdu_allocate();
          if (pdu == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          /* Store DCE/RPC PDU as a transaction context, so it will be
             "automatically" deleted */
          transaction->context = pdu;

          if (ssh_appgw_cifs_rpc_request_decode(pdu,
                                              cifs->packet_ptr + data_offset,
                                              data_count) == FALSE)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_rpc_request);
              return SSH_FSM_CONTINUE;
            }
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("- name = \"%s\"", transaction->name_ptr));
    }

  if (data_count < total_data_count)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Copying client data (%u bytes)", data_count));

      transaction->client.data = ssh_malloc(total_data_count);
      if (transaction->client.data == NULL)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
          return SSH_FSM_CONTINUE;
        }

      memcpy(transaction->client.data,
             cifs->packet_ptr + data_offset, data_count);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("%u/%u bytes of client data copied.",
				   (unsigned int)
				   transaction->client.data_count,
				   (unsigned int)
				   transaction->client.total_data_count));

      transaction->request_data_copied = 1;
    }

  if (cifs->no_response)
    {
      /* Remove the context because this is a one-way transaction */
      ssh_appgw_cifs_transaction_free(transaction);
      ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TRANSACTION2 request */
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction2_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshUInt16 total_param_count;
  SshUInt16 total_data_count;
  SshUInt16 max_param_count;
  SshUInt16 max_data_count;
  SshUInt8 max_setup_count;
  SshUInt16 flags;
  SshUInt32 timeout;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 data_count;
  SshUInt16 data_offset;
  SshUInt8 setup_count;

  SSH_ASSERT(cifs->word_count >= 14);

  total_param_count = SSH_GET_16BIT_LSB_FIRST(params);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+2);
  max_param_count = SSH_GET_16BIT_LSB_FIRST(params+4);
  max_data_count = SSH_GET_16BIT_LSB_FIRST(params+6);
  max_setup_count = SSH_GET_8BIT(params+8);
  /* skip reserved byte */
  flags = SSH_GET_16BIT_LSB_FIRST(params+10);
  timeout = SSH_GET_32BIT_LSB_FIRST(params+12);
  /* skip two reserved bytes */
  param_count = SSH_GET_16BIT_LSB_FIRST(params+18);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+20);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+22);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+24);
  setup_count = SSH_GET_8BIT(params+26);
  /* one byte padding */

  SSH_DEBUG(SSH_D_DATADUMP, ("- total_param_count = %u",total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_param_count = %u", max_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_data_count = %u", max_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_setup_count = %u", max_setup_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- timeout = %lu", timeout));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  if ((setup_count != (cifs->word_count - 14)) ||
      (param_count > total_param_count) ||
      (data_count > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  if (flags & 0x01)
    {
      SshAppgwCifsTree tree;

      /* Client requests the server to disconnect the tree specified by
         SMB header of this packet. We need to update our bookkeeping now,
         because this is probably the last time we see this tree id. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Deleting old tree 0x%04X", cifs->tid));

      tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

      if (tree)
        ssh_appgw_cifs_tree_remove(tree);
      else
        SSH_DEBUG(SSH_D_ERROR, ("Unknown tree ID: 0x%04X", cifs->tid));
    }

  SSH_ASSERT(cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND);

  if (flags & 0x02)
    /* This is one-way transaction. Server doesn't send any response */
    cifs->no_response = 1;

  if (setup_count == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid setup count!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* TRANSACTION2 does not have a name, so we pass NULL as a buffer address
     to allocation function. We will, however, re-use the 'name' field to
     contain path/filename in some specific cases (i.e. when subcommand
     uses path or filename). */
  transaction = ssh_appgw_cifs_transaction_ctx_allocate(conn, cifs, NULL, 0,
                                                        cifs->unicode_strings);
  if (transaction == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  cifs->transaction = 1;

  transaction->client.total_param_count = total_param_count;
  transaction->client.param_count = param_count;
  transaction->client.total_data_count = total_data_count;
  transaction->client.data_count = data_count;

  transaction->server.max_setup_count = max_setup_count;
  transaction->server.setup_count = 0;
  transaction->server.max_param_count = max_param_count;
  transaction->server.total_param_count = 0;
  transaction->server.param_count = 0;
  transaction->server.max_data_count = max_data_count;
  transaction->server.total_data_count = 0;
  transaction->server.data_count = 0;

  /* Setup[0]: */
  transaction->subcommand = SSH_GET_16BIT_LSB_FIRST(params+28);

  transaction->first_request = 1;

  /* Copy parameter bytes if only part of the parameter bytes are sent in
     the first transaction2 request */
  if (total_param_count > 0)
    {
      if (param_count < total_param_count)
        {
          transaction->client.params = ssh_malloc(total_param_count);
          if (transaction->client.params == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          memcpy(transaction->client.params,
                 cifs->packet_ptr + param_offset, param_count);

          transaction->request_params_copied = 1;
        }
      else
        {
          transaction->client.params = cifs->packet_ptr + param_offset;
        }
    }

  /* Copy data bytes if only part of the parameter bytes are sent in
     the first transaction2 request */
  if (total_data_count > 0)
    {
      if (data_count < total_data_count)
        {
          transaction->client.data = ssh_malloc(total_data_count);
          if (transaction->client.data == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          memcpy(transaction->client.data,
                 cifs->packet_ptr + data_offset, data_count);

          transaction->request_data_copied = 1;
        }
      else
        {
          transaction->client.data = cifs->packet_ptr + data_offset;
        }
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_trans2_request_filter(conn, cifs,
                                                        transaction));

  if (cifs->no_response)
    {
      /* Remove the context because this is a one-way transaction */
      ssh_appgw_cifs_transaction_free(transaction);
      ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);
    }

  return SSH_FSM_CONTINUE;
}


/* SMB_COM_TRANSACTION_SECONDARY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_sec_req)
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

  SSH_ASSERT(cifs->word_count == 8);

  total_param_count = SSH_GET_16BIT_LSB_FIRST(params);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+2);
  param_count = SSH_GET_16BIT_LSB_FIRST(params+4);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+6);
  param_displacement = SSH_GET_16BIT_LSB_FIRST(params+8);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+10);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+12);
  data_displacement = SSH_GET_16BIT_LSB_FIRST(params+14);

  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_param_count = %u", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- param_displacement = %u", param_displacement));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- data_displacement = %u", data_displacement));

  /* Pick the pending transaction */
  transaction = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (transaction == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Pending transaction not found!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
    }

  /* Check that the interim response has already been received from server */
  if (transaction->interim_response_received == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("SECONDARY transaction request received "
                                "before an interim response!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
    }

  /* Check the values */
  if (((param_count + param_displacement) > total_param_count) ||
      ((transaction->client.data_count == 0) && (data_displacement != 0)) ||
      ((transaction->client.param_count == 0) && (param_displacement != 0)) ||
      ((data_count + data_displacement) > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of parameter and data counts */
  if ((total_param_count != transaction->client.total_param_count) ||
      (total_data_count != transaction->client.total_data_count))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid transaction"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* Update the fields in transaction context */
  if (param_count > 0)
    transaction->client.param_count = param_count + param_displacement;
  if (data_count > 0)
    transaction->client.data_count = data_count + data_displacement;

  transaction->first_request = 0;

  if ((transaction->client.params != NULL) && (param_count > 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Copying parameters (%u bytes)", param_count));

      memcpy(transaction->client.params + param_displacement,
             cifs->packet_ptr + param_offset, param_count);

      SSH_DEBUG(SSH_D_MY1, ("%u/%u bytes of parameters copied.",
			    (unsigned int)
			    transaction->client.param_count,
			    (unsigned int)
			    transaction->client.total_param_count));
    }

  if ((transaction->client.data != NULL) && (data_count > 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Copying data (%u bytes)", data_count));

      memcpy(transaction->client.data + data_displacement,
             cifs->packet_ptr + data_offset, data_count);

      SSH_DEBUG(SSH_D_MY1, ("%u/%u bytes of data copied.",
			    (unsigned int)
			    transaction->client.data_count,
			    (unsigned int)
			    transaction->client.total_data_count));
    }

  if (transaction->client.data_count ==
      transaction->client.total_data_count)
    {
      if (transaction->dce_rpc)
        {
          /* The complete DCE/RPC request PDU is available now...*/
          SshDceRpcPDU pdu = ssh_dce_rpc_pdu_allocate();
          if (pdu == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          /* Store DCE/RPC PDU as a transaction context, so it will be
             "automatically" deleted */
          transaction->context = pdu;

          if (ssh_appgw_cifs_rpc_request_decode(pdu,
                                    transaction->client.data,
                                    transaction->client.data_count) == FALSE)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_rpc_request);
              return SSH_FSM_CONTINUE;
            }
        }
    }

  /* Server doesn't send any SMB_COM_TRANSACTION_SECONDARY responses */
  cifs->no_response = 1;

  if (cifs->command == SSH_SMB_COM_TRANSACTION2_SECONDARY)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_trans2_request_filter(conn, cifs,
                                                            transaction));
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_QUERY_INFORMATION request */
SSH_FSM_STEP(ssh_appgw_cifs_st_query_information_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const char *filename;

  filename = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                                  SSH_APPGW_CIFS_DATA_STRING,
                                                  cifs->buffer,
                                                  cifs->byte_count,
                                                  cifs->unicode_strings);
  if (filename == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", filename));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_SET_INFORMATION request */
SSH_FSM_STEP(ssh_appgw_cifs_st_set_information_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const char *filename;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 attributes;
  SshUInt32 write_time;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 8);
  SSH_ASSERT(cifs->byte_count >= 2);

#ifdef DEBUG_LIGHT
  attributes = SSH_GET_16BIT_LSB_FIRST(params);
  write_time = SSH_GET_32BIT_LSB_FIRST(params+2);
  /* skip 10 reserved bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- last_write_time = %lu", write_time));
#endif /* DEBUG_LIGHT */

  filename = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                                  SSH_APPGW_CIFS_DATA_STRING,
                                                  cifs->buffer,
                                                  cifs->byte_count,
                                                  cifs->unicode_strings);
  if (filename == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", filename));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CREATE or SMB_COM_CREATE_NEW request */
SSH_FSM_STEP(ssh_appgw_cifs_st_create_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
  SshUInt16 attributes;

  SSH_ASSERT(cifs->word_count == 3);
  SSH_ASSERT(cifs->byte_count >= 2);

  attributes = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_STRING,
                                          cifs->buffer, cifs->byte_count,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));

  if (attributes & 0x0010)
    file->directory = 1;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CHECK_DIRECTORY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_check_directory_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  const char *directory;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count >= 2);

  directory = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                                   SSH_APPGW_CIFS_DATA_STRING,
                                                   cifs->buffer,
                                                   cifs->byte_count,
                                                   cifs->unicode_strings);
  if (directory == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- directory = \"%s\"", directory));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CREATE_TEMPORARY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_create_temp_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;

  SSH_ASSERT(cifs->word_count == 3);
  SSH_ASSERT(cifs->byte_count >= 2);

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_STRING,
                                          cifs->buffer, cifs->byte_count,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_OPEN request */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
  SshUInt16 desired_access;
  SshUInt16 search_attributes;

  /* Ensure that nobody has messed up our pre-filtering rules */
  SSH_ASSERT(cifs->word_count == 2);
  SSH_ASSERT(cifs->byte_count >= 2);

  desired_access = SSH_GET_16BIT_LSB_FIRST(params);
  search_attributes = SSH_GET_16BIT_LSB_FIRST(params+2);

  SSH_DEBUG(SSH_D_DATADUMP, ("- desired_access = 0x%04X", desired_access));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- search_attributes = 0x%04X", search_attributes));

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_STRING,
                                          cifs->buffer, cifs->byte_count,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));

  if (search_attributes & 0x0010)
    file->directory = 1;

  ssh_appgw_cifs_decode_access_mode(file, desired_access);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_CLOSE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->word_count == 3);
  SSH_ASSERT(cifs->byte_count == 0);

  SSH_ASSERT(cifs->tree != NULL);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_log_fclose_event(conn, cifs, cifs->tree, file);
  ssh_appgw_cifs_file_handle_remove(file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_FIND_CLOSE2 request */
SSH_FSM_STEP(ssh_appgw_cifs_st_find_close2_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsSearchHandle search;
  unsigned char *params = cifs->parameters;
  SshUInt16 sid;

  /* Ensure that nobody has messed up our pre-filtering rules */
  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count == 0);

  sid = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- sid = 0x%04X", sid));

  search = ssh_appgw_cifs_search_handle_lookup(conn, sid);
  if (search == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (sid=0x%04X)!", sid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_search_handle_remove(search);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_DELETE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  const char *filename;
  SshUInt16 attributes;

  /* Ensure that nobody has messed up our pre-filtering rules */
  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count >= 2);

  attributes = SSH_GET_16BIT_LSB_FIRST(params);
  /* skip buffer format */

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));

  filename = ssh_appgw_cifs_filename_ctx_allocate(conn, cifs,
                                                  SSH_APPGW_CIFS_DATA_STRING,
                                                  cifs->buffer,
                                                  cifs->byte_count,
                                                  cifs->unicode_strings);
  if (filename == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename = \"%s\"", filename));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}

/* SMB_COM_RENAME request */
SSH_FSM_STEP(ssh_appgw_cifs_st_rename_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileMoveCtx rename_ctx;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 attributes;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count >= 4);

#ifdef DEBUG_LIGHT
  attributes = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
#endif /* DEBUG_LIGHT */

  rename_ctx = ssh_appgw_cifs_file_move_ctx_allocate(io->conn, cifs,
                                                 SSH_APPGW_CIFS_DATA_STRING,
                                                 cifs->buffer,
                                                 cifs->byte_count,
                                                 cifs->unicode_strings);

  if (rename_ctx == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- old_filename = \"%s\"", rename_ctx->original_name));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- new_filename = \"%s\"", rename_ctx->new_name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_RENAME request */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_rename_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileMoveCtx rename_ctx;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 attributes;
  SshUInt16 info_level;
  SshUInt32 cluster_count;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 4);
  SSH_ASSERT(cifs->byte_count >= 4);

#ifdef DEBUG_LIGHT
  attributes = SSH_GET_16BIT_LSB_FIRST(params);
  info_level = SSH_GET_16BIT_LSB_FIRST(params+2);
  cluster_count = SSH_GET_32BIT_LSB_FIRST(params+4);

  SSH_DEBUG(SSH_D_DATADUMP, ("- attributes = 0x%04X", attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- information_level = 0x%04X", info_level));
  SSH_DEBUG(SSH_D_DATADUMP, ("- cluster_count = 0x%04X",
			     (unsigned int) cluster_count));
#endif /* DEBUG_LIGHT */

  rename_ctx = ssh_appgw_cifs_file_move_ctx_allocate(io->conn, cifs,
                                                 SSH_APPGW_CIFS_DATA_STRING,
                                                 cifs->buffer,
                                                 cifs->byte_count,
                                                 cifs->unicode_strings);

  if (rename_ctx == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- old_filename = \"%s\"", rename_ctx->original_name));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- new_filename = \"%s\"", rename_ctx->new_name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_COPY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_copy_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileMoveCtx copy_ctx;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 tid2;
  SshUInt16 open_function;
  SshUInt16 flags;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 3);
  SSH_ASSERT(cifs->byte_count >= 2);

#ifdef DEBUG_LIGHT
  tid2 = SSH_GET_16BIT_LSB_FIRST(params);
  open_function = SSH_GET_16BIT_LSB_FIRST(params+2);
  flags = SSH_GET_16BIT_LSB_FIRST(params+4);
  /* skip byte_count */

  SSH_DEBUG(SSH_D_DATADUMP, ("- tid2 = 0x%04X", tid2));
  SSH_DEBUG(SSH_D_DATADUMP, ("- open_function = 0x%04X", open_function));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
#endif /* DEBUG_LIGHT */

  /* allocate new command specific context */
  copy_ctx = ssh_appgw_cifs_file_move_ctx_allocate(io->conn, cifs,
                                                   SSH_APPGW_CIFS_DATA_STRING,
                                                   cifs->buffer,
                                                   cifs->byte_count,
                                                   cifs->unicode_strings);

  if (copy_ctx == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- old_filename = \"%s\"", copy_ctx->original_name));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- new_filename = \"%s\"", copy_ctx->new_name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_MOVE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_move_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileMoveCtx move_ctx;
#ifdef DEBUG_LIGHT
  unsigned char *params = cifs->parameters;
  SshUInt16 tid2;
  SshUInt16 open_function;
  SshUInt16 flags;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 3);

#ifdef DEBUG_LIGHT
  tid2 = SSH_GET_16BIT_LSB_FIRST(params);
  open_function = SSH_GET_16BIT_LSB_FIRST(params+2);
  flags = SSH_GET_16BIT_LSB_FIRST(params+4);

  SSH_DEBUG(SSH_D_DATADUMP, ("- tid2 = 0x%04X", tid2));
  SSH_DEBUG(SSH_D_DATADUMP, ("- open_function = 0x%04X", open_function));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
#endif /* DEBUG_LIGHT */

  /* allocate new command specific context */
  move_ctx = ssh_appgw_cifs_file_move_ctx_allocate(io->conn, cifs,
                                                   SSH_APPGW_CIFS_DATA_STRING,
                                                   cifs->buffer,
                                                   cifs->byte_count,
                                                   cifs->unicode_strings);
  if (move_ctx == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- old_filename = \"%s\"", move_ctx->original_name));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- new_filename = \"%s\"", move_ctx->new_name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_WRITE_AND_CLOSE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_write_and_close_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
  SshUInt16 count;
  SshUInt32 offset;

  SSH_ASSERT((cifs->word_count >= 6) && (cifs->word_count <= 12));
  SSH_ASSERT(cifs->byte_count >= 2);

  SSH_ASSERT(cifs->tree != NULL);

  /* Word count can be either 6 or 12 */
  if ((cifs->word_count != 6) && (cifs->word_count != 12))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
      return SSH_FSM_CONTINUE;
    }

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);
  count = SSH_GET_16BIT_LSB_FIRST(params+2);
  offset = SSH_GET_32BIT_LSB_FIRST(params+4);
  /* skip other fields */

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- count = %u", count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %u",
			     (unsigned int) offset));

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_log_fclose_event(conn, cifs, cifs->tree, file);
  ssh_appgw_cifs_file_handle_remove(file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_OPEN_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file = NULL;
  unsigned char *params = cifs->parameters;
  SshUInt16 flags;
  SshUInt16 desired_access;
  SshUInt16 search_attributes;
  SshUInt16 file_attributes;
  SshUInt16 open_function;
  SshUInt32 alloc_size;

  SSH_ASSERT(cifs->word_count == 15);
  SSH_ASSERT(cifs->byte_count >= 1);

  /* Skip ANDX block (4 bytes) */
  flags = SSH_GET_16BIT_LSB_FIRST(params+4);
  desired_access = SSH_GET_16BIT_LSB_FIRST(params+6);
  search_attributes = SSH_GET_16BIT_LSB_FIRST(params+8);
  file_attributes = SSH_GET_16BIT_LSB_FIRST(params+10);
  /* skip creation time (4 bytes) */
  open_function = SSH_GET_16BIT_LSB_FIRST(params+16);
  alloc_size = SSH_GET_32BIT_LSB_FIRST(params+18);
  /* skip 8 reserved bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- desired_access = 0x%04X", desired_access));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- search_attributes = 0x%04X", search_attributes));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- file_attributes = 0x%04X", file_attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- open_function = %04X", open_function));
  SSH_DEBUG(SSH_D_DATADUMP, ("- alloc_size = %lu", alloc_size));

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_BLOCK,
                                          cifs->buffer, cifs->byte_count,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));

  if (search_attributes & 0x0010)
    file->directory = 1;

  ssh_appgw_cifs_decode_access_mode(file, desired_access);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_LOCKING_ANDX request.  This request can come either from client
   (in which case we expect to receive server's response) or asynchronously
   from server (in this case, client doesn't send response) */
SSH_FSM_STEP(ssh_appgw_cifs_st_locking_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshUInt8 lock_type;
  SshUInt16 num_oplocks;
#ifdef DEBUG_LIGHT
  SshUInt8 oplock_level;
  SshUInt32 timeout;
  SshUInt16 num_locks;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 8);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params+4);

  if (ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid) == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  /* skip the "ANDX" block (4 bytes) */
  lock_type = SSH_GET_8BIT(params+6);
#ifdef DEBUG_LIGHT
  oplock_level = SSH_GET_8BIT(params+7);
  timeout = SSH_GET_32BIT_LSB_FIRST(params+8);
#endif /* DEBUG_LIGHT */
  num_oplocks = SSH_GET_16BIT_LSB_FIRST(params+12);
#ifdef DEBUG_LIGHT
  num_locks = SSH_GET_16BIT_LSB_FIRST(params+14);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- lock_type = 0x%02X", lock_type));
  SSH_DEBUG(SSH_D_DATADUMP, ("- oplock_level = 0x%02X", oplock_level));
  SSH_DEBUG(SSH_D_DATADUMP, ("- timeout = %lu ms", timeout));
  SSH_DEBUG(SSH_D_DATADUMP, ("- number_of_oplocks = %u", num_oplocks));
  SSH_DEBUG(SSH_D_DATADUMP, ("- number_of_locks = %u", num_locks));
#endif /* DEBUG_LIGHT */

  /* Note that we should not set the 'no_response' flag if this is an
     embedded SMB_COM_TRANSACTION request */
  if (cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND)
    {
      /* We don't expect to see any matching response if this is asynchronous
         request from _server_ */
      if (cifs->client == 0)
        cifs->no_response = 1;

      /* According to available CIFS specifications, this is another special
         case when server doesn't send any response. */
      if ((lock_type & SSH_LOCKING_ANDX_OPLOCK_RELEASE) && (num_oplocks == 0))
        cifs->no_response = 1;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_READ request */
SSH_FSM_STEP(ssh_appgw_cifs_st_read_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshAppgwCifsIORequestCtx io_req;
  SshUInt16 count;
  SshUInt32 offset;
#ifdef DEBUG_LIGHT
  SshUInt16 remaining;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(cifs->word_count == 5);
  SSH_ASSERT(cifs->byte_count == 0);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);
  count = SSH_GET_16BIT_LSB_FIRST(params+2);
  offset = SSH_GET_32BIT_LSB_FIRST(params+4);
#ifdef DEBUG_LIGHT
  remaining = SSH_GET_16BIT_LSB_FIRST(params+8);
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- count = %u", count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %lu", offset));
#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_DATADUMP, ("- remaining = %u", remaining));
#endif /* DEBUG_LIGHT */

  if (ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid) == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  io_req = ssh_appgw_cifs_cmd_context_allocate(conn, cifs, sizeof(*io_req),
                                           ssh_appgw_cifs_cmd_ctx_delete_cb);
  if (io_req == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  io_req->fid = cifs->fid;
  io_req->offset = offset;
  io_req->min_count = count;
  io_req->max_count = count;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_READ_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_read_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshAppgwCifsIORequestCtx io_req;
  SshUInt32 offset;
  SshUInt16 max_count;
  SshUInt16 min_count;

  SSH_ASSERT((cifs->word_count >= 10) && (cifs->word_count <= 12));

  /* parameter word count can be either 12 or 14 */
  if ((cifs->word_count != 10) && (cifs->word_count != 12))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
      return SSH_FSM_CONTINUE;
    }

  /* skip the "ANDX" block (4 bytes) */
  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params+4);
  offset = SSH_GET_32BIT_LSB_FIRST(params+6);
  max_count = SSH_GET_16BIT_LSB_FIRST(params+10);
  min_count = SSH_GET_16BIT_LSB_FIRST(params+12);
  /* skip 6 reserved bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %lu", offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_count = %u", max_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- min_count = %u", min_count));

  if (cifs->word_count == 12)
    {
      SshUInt32 offset_high;

      offset_high = SSH_GET_32BIT_LSB_FIRST(params+20);

      SSH_DEBUG(SSH_D_DATADUMP, ("- offset_high = %lu", offset_high));
    }

  if (ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid) == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  io_req = ssh_appgw_cifs_cmd_context_allocate(conn, cifs, sizeof(*io_req),
                                           ssh_appgw_cifs_cmd_ctx_delete_cb);
  if (io_req == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  io_req->fid = cifs->fid;
  io_req->offset = offset;
  io_req->min_count = min_count;
  io_req->max_count = max_count;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_WRITE_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_write_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  SshAppgwCifsMultiPartIO write_op = NULL;
  SshAppgwCifsIORequestCtx io_req;
  const unsigned char *params = cifs->parameters;
  const unsigned char *data;
  SshUInt32 offset;
  SshUInt16 write_mode;
  SshUInt16 remaining;
  size_t data_length;
  SshUInt16 data_offset;

  SSH_ASSERT(cifs->tree != NULL);
  SSH_ASSERT((cifs->word_count >= 12) && (cifs->word_count <= 14));

  /* parameter word count can be either 12 or 14 */
  if ((cifs->word_count != 12) && (cifs->word_count != 14))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* skip the "ANDX" block (4 bytes) */
  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params+4);
  offset = SSH_GET_32BIT_LSB_FIRST(params+6);
  /* skip four reserved bytes */
  write_mode = SSH_GET_16BIT_LSB_FIRST(params+14);
  remaining = SSH_GET_16BIT_LSB_FIRST(params+16);
  /* skip two reserved bytes */
  data_length = SSH_GET_16BIT_LSB_FIRST(params+20);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+22);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %lu", offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- write_mode = 0x%04X", write_mode));
  SSH_DEBUG(SSH_D_DATADUMP, ("- remaining = %u", remaining));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_length = %u", data_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));

  if ((data_length + data_offset) > cifs->packet_size)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->word_count == 14)
    {
      SshUInt32 offset_high;

      offset_high = SSH_GET_32BIT_LSB_FIRST(params+24);
      SSH_DEBUG(SSH_D_DATADUMP, ("- offset_high = %lu", offset_high));
    }

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  io_req = ssh_appgw_cifs_cmd_context_allocate(conn, cifs, sizeof(*io_req),
                                           ssh_appgw_cifs_cmd_ctx_delete_cb);
  if (io_req == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  io_req->fid = cifs->fid;
  io_req->offset = offset;
  io_req->min_count = data_length;
  io_req->max_count = data_length;

  write_op = ssh_appgw_cifs_mp_io_get(file, SSH_APPGW_CIFS_MULTI_PART_WRITE);

  data = cifs->packet_ptr + data_offset;

  if ((write_op == NULL) &&
      (cifs->tree->ipc_service == 1) &&
      (file->file_type == SSH_SMB_FILE_TYPE_MESSAGE_PIPE) &&
      ((write_mode & 0x000c) == 0x000c))  /* start of message + raw write */
    {
      SshDceRpcPDUHeaderStruct header;
      SshUInt16 pdu_length;

      if (data_length < 2)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
          return SSH_FSM_CONTINUE;
        }

      /* The total length of the PDU  */
      pdu_length = SSH_GET_16BIT_LSB_FIRST(data);
      data += 2;
      data_length -= 2;

      if (ssh_dce_rpc_pdu_header_decode(&header, data,
                                        (SshUInt16)data_length, NULL) == TRUE)
        {
          write_op = ssh_appgw_cifs_mp_io_begin(file,
                                              SSH_APPGW_CIFS_MULTI_PART_WRITE,
                                              header.frag_length,
                                              NULL, NULL_FNPTR);
          if (write_op == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          /* pdu_length should be equal to header.frag_length */
          if (pdu_length != header.frag_length)
            {
              ssh_appgw_cifs_mp_io_end(write_op);
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
              return SSH_FSM_CONTINUE;
            }
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_rpc_request);
          return SSH_FSM_CONTINUE;
        }
    }

  if (write_op != NULL)
    {
      Boolean status;

      switch (file->file_type)
        {
        case SSH_SMB_FILE_TYPE_MESSAGE_PIPE:
        case SSH_SMB_FILE_TYPE_PIPE:
          status = ssh_appgw_cifs_mp_io_append(write_op, data, data_length);
          break;

        default:
          status = ssh_appgw_cifs_mp_io_insert(write_op, offset,
                                               data, data_length);
          break;
        }

      if (status == FALSE)
        {
          write_op = NULL;  /* the operation is "dead" already */
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
          return SSH_FSM_CONTINUE;
        }

      if (ssh_appgw_cifs_mp_io_is_complete(write_op) == FALSE)
        {
          /* Some PDU fragments still missing... */
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
          return SSH_FSM_CONTINUE;
        }

      ssh_appgw_cifs_mp_io_data_get(write_op, &data, &data_length);
    }

  /* Filter DCE/RPC request... */
  if ((cifs->tree->ipc_service == 1) &&
      (file->file_type == SSH_SMB_FILE_TYPE_MESSAGE_PIPE))
    {
      SshDceRpcPDUStruct pdu;
      SshUInt8 packet_type;

      ssh_dce_rpc_pdu_init(&pdu);
      if (ssh_dce_rpc_pdu_decode(&pdu, data,
                                 (SshUInt16)data_length, NULL) == FALSE)
        {
          ssh_appgw_cifs_mp_io_end(write_op);
          SSH_DEBUG(SSH_D_NETGARB, ("Malformed DCE/RPC PDU!"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_rpc_request);
          return SSH_FSM_CONTINUE;
        }

      packet_type = pdu.header.packet_type;
      ssh_dce_rpc_pdu_uninit(&pdu); /* we don't need this PDU any more */

      switch (packet_type)
        {
        case SSH_DCE_RPC_PDU_REQUEST:
        case SSH_DCE_RPC_PDU_BIND:
        case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
        case SSH_DCE_RPC_PDU_CO_CANCEL:
        case SSH_DCE_RPC_PDU_ORPHANED:
        case SSH_DCE_RPC_PDU_AUTH3:
          break;

        default:
          ssh_appgw_cifs_mp_io_end(write_op);
          SSH_DEBUG(SSH_D_NETGARB, ("Unexpected DCE/RPC response!"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_rpc_request);
          return SSH_FSM_CONTINUE;
        }
    }

  ssh_appgw_cifs_mp_io_end(write_op);
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_IOCTL request */
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  SshAppgwCifsTransaction ioctl;
  SshUInt16 function;
  SshUInt16 category;
#ifdef DEBUG_LIGHT
  SshUInt32 timeout;
#endif /* DEBUG_LIGHT */
  SshUInt16 total_param_count;
  SshUInt16 total_data_count;
  SshUInt16 max_param_count;
  SshUInt16 max_data_count;
  SshUInt16 param_count;
  SshUInt16 param_offset;
  SshUInt16 data_count;
  SshUInt16 data_offset;

  SSH_ASSERT(cifs->word_count == 14);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);
  category = SSH_GET_16BIT_LSB_FIRST(params+2);
  function = SSH_GET_16BIT_LSB_FIRST(params+4);
  total_param_count = SSH_GET_16BIT_LSB_FIRST(params+6);
  total_data_count = SSH_GET_16BIT_LSB_FIRST(params+8);
  max_param_count = SSH_GET_16BIT_LSB_FIRST(params+10);
  max_data_count = SSH_GET_16BIT_LSB_FIRST(params+12);
#ifdef DEBUG_LIGHT
  timeout = SSH_GET_32BIT_LSB_FIRST(params+14);
#endif /* DEBUG_LIGHT */
  /* skip two reserved bytes */
  param_count = SSH_GET_16BIT_LSB_FIRST(params+20);
  param_offset = SSH_GET_16BIT_LSB_FIRST(params+22);
  data_count = SSH_GET_16BIT_LSB_FIRST(params+24);
  data_offset = SSH_GET_16BIT_LSB_FIRST(params+26);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- category = %u", category));
  SSH_DEBUG(SSH_D_DATADUMP, ("- function = %u", function));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_param_count = %u", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %u", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_param_count = %u", max_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_data_count = %u", max_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- timeout = %lu ms", timeout));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %u", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %u", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %u", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %u", data_offset));

  if ((param_count > total_param_count) ||
      (data_count > total_data_count) ||
      ((param_offset + param_count) > cifs->packet_size) ||
      ((data_offset + data_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  if (ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid) == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ioctl = ssh_appgw_cifs_transaction_ctx_allocate(conn, cifs, NULL, 0,
                                                  cifs->unicode_strings);
  if (ioctl == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  ioctl->client.total_param_count = total_param_count;
  ioctl->client.param_count = param_count;
  ioctl->client.total_data_count = total_data_count;
  ioctl->client.data_count = data_count;

  ioctl->server.max_param_count = max_param_count;
  ioctl->server.total_param_count = 0;
  ioctl->server.param_count = 0;
  ioctl->server.max_data_count = max_data_count;
  ioctl->server.total_data_count = 0;
  ioctl->server.data_count = 0;

  ioctl->category = category;
  ioctl->subcommand = function;

  ioctl->first_request = 1;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_IOCTL_SECONDARY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_sec_req)
{
  /* Handling os IOCTL_SECONDARY requests is exactly the same than handling
     of TRANSACTION(2)_SECONDARY requests */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_transaction_sec_req);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_CREATE_ANDX request */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_create_x_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file = NULL;
  unsigned char *params = cifs->parameters;
  SshUInt16 name_length;
  SshUInt32 flags;
  SshUInt32 root_fid;
  SshUInt32 access_mask;
  SshUInt32 attributes;
  SshUInt32 share_access;
  SshUInt32 disposition;
  SshUInt32 options;
  SshUInt32 impersonation;
  SshUInt8 security;

  SSH_ASSERT(cifs->word_count == 24);

  /* skip "ANDX header" and one reserved byte */
  name_length = SSH_GET_16BIT_LSB_FIRST(params+5);
  flags = SSH_GET_32BIT_LSB_FIRST(params+7);
  root_fid = SSH_GET_32BIT_LSB_FIRST(params+11);
  access_mask = SSH_GET_32BIT_LSB_FIRST(params+15);
  /* skip alloc_size (8 bytes) */
  attributes = SSH_GET_32BIT_LSB_FIRST(params+27);
  share_access = SSH_GET_32BIT_LSB_FIRST(params+31);
  disposition = SSH_GET_32BIT_LSB_FIRST(params+35);
  options = SSH_GET_32BIT_LSB_FIRST(params+39);
  impersonation = SSH_GET_32BIT_LSB_FIRST(params+43);
  security = SSH_GET_8BIT(params+47);

  SSH_DEBUG(SSH_D_DATADUMP, ("- name_length = %u", name_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%08lX",
			     (unsigned long) flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- root_directory_fid = 0x%08lX",
			     (unsigned long) root_fid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- access_mask = 0x%08lX",
			     (unsigned long) access_mask));
  SSH_DEBUG(SSH_D_DATADUMP, ("- file_attributes = 0x%08lX",
			     (unsigned long) attributes));
  SSH_DEBUG(SSH_D_DATADUMP, ("- share_access = 0x%08lX",
			     (unsigned long) share_access));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- create_disposition = 0x%08lX",
	     (unsigned long) disposition));
  SSH_DEBUG(SSH_D_DATADUMP, ("- create_options = 0x%08lX",
			     (unsigned long) options));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- impersonation_level = 0x%08lX",
	     (unsigned long) impersonation));
  SSH_DEBUG(SSH_D_DATADUMP, ("- security_flags = 0x%02X", security));

  if (name_length > cifs->byte_count)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid name length!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_BLOCK,
                                          cifs->buffer, name_length,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (name_length)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("- filename: \"%s\"", file->name));
    }

  if (flags & 0x08)
    file->directory = 1;

  ssh_appgw_cifs_decode_access_mask(file, access_mask);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_TRANSACTION request */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshUInt8 max_setup_count;
  SshUInt32 total_param_count;
  SshUInt32 total_data_count;
  SshUInt32 max_param_count;
  SshUInt32 max_data_count;
  SshUInt32 param_count;
  SshUInt32 param_offset;
  SshUInt32 data_count;
  SshUInt32 data_offset;
  SshUInt8 setup_count;
  SshUInt16 function;

  SSH_ASSERT(cifs->word_count >= 19);

  max_setup_count = SSH_GET_8BIT(params);
  /* two reserved bytes */
  total_param_count = SSH_GET_32BIT_LSB_FIRST(params+3);
  total_data_count = SSH_GET_32BIT_LSB_FIRST(params+7);
  max_param_count = SSH_GET_32BIT_LSB_FIRST(params+11);
  max_data_count = SSH_GET_32BIT_LSB_FIRST(params+15);
  param_count = SSH_GET_32BIT_LSB_FIRST(params+19);
  param_offset = SSH_GET_32BIT_LSB_FIRST(params+23);
  data_count = SSH_GET_32BIT_LSB_FIRST(params+27);
  data_offset = SSH_GET_32BIT_LSB_FIRST(params+31);
  setup_count = SSH_GET_8BIT(params+35);
  function = SSH_GET_16BIT_LSB_FIRST(params+36);
  /* skip one byte */

  SSH_DEBUG(SSH_D_DATADUMP, ("- max_setup_count = %u", max_setup_count));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- total_param_count = %lu", total_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- total_data_count = %lu", total_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_param_count = %lu", max_param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- max_data_count = %lu", max_data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_count = %lu", param_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- param_offset = %lu", param_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_count = %lu", data_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("- data_offset = %lu", data_offset));
  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_count = %u", setup_count));

  if ((setup_count != (cifs->word_count - 19)) ||
      (param_count > total_param_count) ||
      (data_count > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  transaction = ssh_appgw_cifs_transaction_ctx_allocate(conn, cifs, NULL, 0,
                                                        cifs->unicode_strings);
  if (transaction == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  cifs->transaction = 1;
  transaction->first_request = 1;

  transaction->client.total_param_count = total_param_count;
  transaction->client.param_count = param_count;
  transaction->client.total_data_count = total_data_count;
  transaction->client.data_count = data_count;

  transaction->server.max_setup_count = max_setup_count;
  transaction->server.setup_count = 0;
  transaction->server.max_param_count = max_param_count;
  transaction->server.total_param_count = 0;
  transaction->server.param_count = 0;
  transaction->server.max_data_count = max_data_count;
  transaction->server.total_data_count = 0;
  transaction->server.data_count = 0;

  transaction->subcommand = function;

  /* Copy parameter bytes if only part of them are sent in the first request */
  if (total_param_count > 0)
    {
      if (param_count < total_param_count)
        {
          transaction->client.params = ssh_malloc(total_param_count);
          if (transaction->client.params == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
              return SSH_FSM_CONTINUE;
            }

          memcpy(transaction->client.params,
                 cifs->packet_ptr + param_offset, param_count);

          transaction->request_params_copied = 1;
        }
      else
        {
          transaction->client.params = cifs->packet_ptr + param_offset;
          transaction->request_params_copied = 0;
        }
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_nt_transact_request_filter(conn, cifs,
                                                             transaction));
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_TRANSACTION_SECONDARY request */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_sec_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsTransaction transaction;
  unsigned char *params = cifs->parameters;
  SshUInt32 total_param_count;
  SshUInt32 total_data_count;
  SshUInt32 param_count;
  SshUInt32 param_offset;
  SshUInt32 param_displacement;
  SshUInt32 data_count;
  SshUInt32 data_offset;
  SshUInt32 data_displacement;

  SSH_ASSERT(cifs->word_count == 18);

  /* skip 3 reserved bytes */
  total_param_count = SSH_GET_32BIT_LSB_FIRST(params+3);
  total_data_count = SSH_GET_32BIT_LSB_FIRST(params+7);
  param_count = SSH_GET_32BIT_LSB_FIRST(params+11);
  param_offset = SSH_GET_32BIT_LSB_FIRST(params+15);
  param_displacement = SSH_GET_32BIT_LSB_FIRST(params+19);
  data_count = SSH_GET_32BIT_LSB_FIRST(params+23);
  data_offset = SSH_GET_32BIT_LSB_FIRST(params+27);
  data_displacement = SSH_GET_32BIT_LSB_FIRST(params+31);

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


  /* Pick the pending transaction from our bookkeeping */
  transaction = ssh_appgw_cifs_transaction_lookup(conn, cifs);
  if (transaction == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Pending transaction not found!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
    }

  /* Check that the interim response has already been received from server */
  if (transaction->interim_response_received == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("SECONDARY transaction request received "
                                "before an interim response!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
    }

  /* Check the values */
  if (((param_count + param_displacement) > total_param_count) ||
      ((transaction->client.data_count == 0) && (data_displacement != 0)) ||
      ((transaction->client.param_count == 0) && (param_displacement != 0)) ||
      ((data_count + data_displacement) > total_data_count) ||
      ((data_offset + data_count) > cifs->packet_size) ||
      ((param_offset + param_count) > cifs->packet_size))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of parameter and data counts */
  if ((total_param_count != transaction->client.total_param_count) ||
      (total_data_count != transaction->client.total_data_count))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid transaction"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  /* Update the fields in transaction context */
  if (param_count > 0)
    transaction->client.param_count = param_count + param_displacement;
  if (data_count > 0)
    transaction->client.data_count = data_count + data_displacement;

  transaction->first_request = 0;

  /* Server doesn't send any SMB_COM_NT_TRANSACTION_SECONDARY responses */
  cifs->no_response = 1;

  if ((transaction->client.params != NULL) && (param_count > 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Copying parmaeters (%lu bytes)", param_count));

      memcpy(transaction->client.params + param_displacement,
             cifs->packet_ptr + param_offset, param_count);

      SSH_DEBUG(SSH_D_MY1, ("%lu/%lu of parameter bytes copied.",
                transaction->client.param_count,
                transaction->client.total_param_count));
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_nt_transact_request_filter(conn, cifs,
                                                             transaction));
  return SSH_FSM_CONTINUE;
}


/* SMB_COM_NT_CANCEL request */
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_cancel_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsRequestStruct cancel_req;
  SshAppgwCifsRequest request;

  SSH_ASSERT(cifs->word_count == 0);
  SSH_ASSERT(cifs->byte_count == 0);

  /* Pick canceled request from our bookkeeping and mark it as canceled */
  ssh_appgw_cifs_pending_request_init(&cancel_req, conn, cifs);
  request = ssh_appgw_cifs_canceled_request_lookup(&cancel_req);

  if (request)
    request->canceled = 1;

  /* Server should not send any response to this cancel request */
  cifs->no_response = 1;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_single_block_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsConn conn = io->conn;
#ifdef DEBUG_LIGHT
  SshAppgwCifsCtx cifs_alg = (SshAppgwCifsCtx) conn->ctx->user_context;
  char *originator = NULL;
  char *destination = NULL;
#endif /* DEBUG_LIGHT */

  if (cifs->client)
    {
      const unsigned char *data = cifs->buffer;
      size_t bytes_left = cifs->byte_count;
      SshUInt8  msg_type;
      SshUInt16 msg_len;
      size_t str_size;

      if (cifs->byte_count < 7)
        goto invalid;

      /* Originator name */
      if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_STRING,
                                 data, bytes_left,
                                 cifs->unicode_strings) == FALSE)
        {
          goto invalid;
        }

#ifdef DEBUG_LIGHT
      originator = ssh_appgw_cifs_strdup(cifs_alg,
                                         SSH_APPGW_CIFS_DATA_STRING,
                                         data, str_size,
                                         cifs->unicode_strings);

      SSH_DEBUG(SSH_D_DATADUMP, ("- Originator = %s", originator));
#endif /* DEBUG_LIGHT */

      data += str_size;
      bytes_left -= str_size;

      /* Destination name */
      if (ssh_appgw_cifs_strsize(&str_size, SSH_APPGW_CIFS_DATA_STRING,
                                 data, bytes_left,
                                 cifs->unicode_strings) == FALSE)
        {
          goto invalid;
        }

#ifdef DEBUG_LIGHT
      destination = ssh_appgw_cifs_strdup(cifs_alg,
                                          SSH_APPGW_CIFS_DATA_STRING,
                                          data, str_size,
                                          cifs->unicode_strings);

      SSH_DEBUG(SSH_D_DATADUMP, ("- Destination = %s", destination));
#endif /* DEBUG_LIGHT */

      data += str_size;
      bytes_left -= str_size;

      /* Message */
      if (bytes_left < 3)
        goto invalid;


      msg_type = SSH_GET_8BIT(data);
      msg_len = SSH_GET_16BIT_LSB_FIRST(data+1);

      if ((msg_type != SSH_APPGW_CIFS_DATA_BLOCK) ||
          (msg_len != (bytes_left - 3)))
        {
          goto invalid;
        }

#ifdef DEBUG_LIGHT
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("- Message:"),
                        data+3, bytes_left-3);

      ssh_free(originator);
      ssh_free(destination);
#endif /* DEBUG_LIGHT */

      /* The server acknowledges this request either by sending response
         or another SINGLE_BLOCK request. */
      cifs->response_wait_time = 10;
    }
  else
    {
      SshAppgwCifsRequest request;

      /* "Response" from server should not contain any data */
      if (cifs->byte_count != 0)
        goto invalid;

      /* Pick and delete the corresponding request */
      request = ssh_appgw_cifs_pending_request_lookup(conn, cifs);
      if (request != NULL)
        ssh_appgw_cifs_pending_request_remove(request);

      cifs->no_response = 1;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;

invalid:

#ifdef DEBUG_LIGHT
  ssh_free(originator);
  ssh_free(destination);
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_packet);
  return SSH_FSM_CONTINUE;
}


/* SMB_OPEN_PRINT_FILE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_open_print_file_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;
  SshUInt16 setup_length;
  SshUInt16 mode;

  /* Ensure that nobody has messed up our pre-filtering rules */
  SSH_ASSERT(cifs->word_count == 2);
  SSH_ASSERT(cifs->byte_count >= 2);

  setup_length = SSH_GET_16BIT_LSB_FIRST(params);
  mode = SSH_GET_16BIT_LSB_FIRST(params+2);

  SSH_DEBUG(SSH_D_DATADUMP, ("- setup_length = %u", setup_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("- mode = 0x%04X", mode));

  file = ssh_appgw_cifs_file_ctx_allocate(conn, cifs,
                                          SSH_APPGW_CIFS_DATA_STRING,
                                          cifs->buffer, cifs->byte_count,
                                          cifs->unicode_strings);
  if (file == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("- identifier: \"%s\"", file->name));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* SMB_CLOSE_PRINT_FILE request */
SSH_FSM_STEP(ssh_appgw_cifs_st_close_print_file_req)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->word_count == 1);
  SSH_ASSERT(cifs->byte_count == 0);

  SSH_ASSERT(cifs->tree != NULL);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  ssh_appgw_cifs_file_handle_remove(file);

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* Filter embedded commands of ..._ANDX requests */
SSH_FSM_STEP(ssh_appgw_cifs_st_embedded_request_filter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *params = cifs->parameters;
  unsigned char *ucp;
  SshAppgwCifsAndxCmdCtx andx = cifs->andx_ctx;
  size_t space_left;
  SshAppgwCifsEmbeddedCmd *prev_cmd;
  SshAppgwCifsEmbeddedCmd embedded_cmd;
  SshUInt8 andx_reserved;
  SshUInt16 prev_andx_offset;


  if (cifs->embedded_cmds == 0)
    {
      /* Filtering complete */
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_filter_complete);
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
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
          return SSH_FSM_CONTINUE;
        }
      else if ((cifs->parameters == NULL) ||
               (params == (cifs->packet_ptr + cifs->packet_size)))
        {
          /* Filtering complete */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("No more embedded commands"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_filter_complete);
          return SSH_FSM_CONTINUE;
        }

      cifs->word_count = SSH_GET_8BIT(params);

      if (cifs->word_count < 2)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
          return SSH_FSM_CONTINUE;
        }

      params++; /* skip the word count field */
    }

  SSH_DEBUG(SSH_D_MY2, ("Checking next ANDX block"));

  andx_reserved = SSH_GET_8BIT(params+1);
  if (andx_reserved != 0)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
      return SSH_FSM_CONTINUE;
    }

  andx->embedded_cmd = SSH_GET_8BIT(params);
  if (andx->embedded_cmd == 0xFF)
    {
      /* Filtering complete */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No more embedded commands"));
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_filter_complete);
      return SSH_FSM_CONTINUE;
    }

  andx->offset = SSH_GET_16BIT_LSB_FIRST(params+2);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Embedded %s %s",
            ssh_appgw_cifs_cmd_to_name(andx->embedded_cmd),
            (cifs->response == 0) ? "request" : "response"));
  SSH_DEBUG(SSH_D_DATADUMP, ("- offset = %u", andx->offset));

  /* We have a simple protection against malformatted packets having
     "infinite loop" of embedded commands (possible DoS attack). We expect
     that embedded commands are always in a correct order, so the
     currently parsed command must have a bigger andx_offset than the
     previously parsed command had. */
  if ((andx->offset > (cifs->packet_size+SSH_APPGW_SMB_ANDX_MIN_LEN)) ||
      (andx->offset < prev_andx_offset))
    {
      SSH_DEBUG(SSH_D_NETFAULT, ("Invalid 'andx_offset'!"));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_broken_request);
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
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
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

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- word_count = %d", cifs->word_count));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- byte_count = %d", cifs->byte_count));

  /* Add new command specific context */
  embedded_cmd = ssh_calloc(1, sizeof(*embedded_cmd));
  if (embedded_cmd == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_out_of_mem);
      return SSH_FSM_CONTINUE;
    }

  embedded_cmd->context = NULL;
  embedded_cmd->command = andx->embedded_cmd;

  /* Insert new command at the tail of list of embedded commands */
  if (cifs->andx_commands)
    {
      prev_cmd = &cifs->andx_commands;

      while ((*prev_cmd)->next)
        *prev_cmd = (*prev_cmd)->next;

      (*prev_cmd)->next = embedded_cmd;
    }
  else
    cifs->andx_commands = embedded_cmd;

  /* Return control to CIFS parser */
  cifs->decode_phase = SSH_APPGW_CIFS_FILTER_ANDX;
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_continue_filtering);
  return SSH_FSM_CONTINUE;
}


/* Default filter for file I/O requests. */
SSH_FSM_STEP(ssh_appgw_cifs_st_def_file_io_req_filter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFileHandle file;
  unsigned char *params = cifs->parameters;

  SSH_ASSERT(cifs->word_count >= 1);

  cifs->fid = SSH_GET_16BIT_LSB_FIRST(params);

  SSH_DEBUG(SSH_D_DATADUMP, ("- fid = 0x%04X", cifs->fid));

  file = ssh_appgw_cifs_file_handle_lookup(conn, cifs->fid);
  if (file == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid handle (fid=0x%04X)!", cifs->fid));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_req_invalid_handle);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_def_request_filter);
  return SSH_FSM_CONTINUE;
}


/* Default filter for CIFS requests */
SSH_FSM_STEP(ssh_appgw_cifs_st_def_request_filter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->embedded_cmds)
    /* Continue filtering of embedded commands */
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_embedded_request_filter);
  else
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_request_filter_complete);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_request_filter_complete)
{
#ifdef DEBUG_LIGHT
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("%s request passed.",
            ssh_appgw_cifs_cmd_to_name(cifs->command)));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_pass_packet);
  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
