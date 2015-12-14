/*
 *
 * appgw_cifs.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application level gateway for CIFS (Common Internet File System).
 *
 * This CIFS application gateway supports both of the alternative
 * configurations listed below:
 *
 *    - CIFS over NBT (NetBIOS over TCP/IP)
 *    - CIFS over TCP
 *
 * References:
 *
 *   RFC 1001  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             CONCEPTS AND METHODS
 *   RFC 1002  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             DETAILED SPECIFICATIONS
 *   MSDN Library July 2000:
 *             Common Internet Files System (CIFS/1.0) Protocol
 *             (This document does not contain any unacceptable licensing
 *             terms unlike the updated versions)
 *
 */

#include "sshincludes.h"
#include "sshgetput.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifs"

/* Identification string. */
#define SSH_APPGW_CIFS_IDENT          "alg-cifs@ssh.com"

/* Version. */
#define SSH_APPGW_CIFS_VERSION        1

/* Possible server ports for CIFS */
#define SSH_APPGW_CIFS_NBT_SERVER_PORT  139 /* NetBIOS over TCP/IP */
#define SSH_APPGW_CIFS_MSDS_SERVER_PORT 445 /* Microsoft Direct SMB
                                               Hosting Service */

/* Session specific trees are deleted by application gateway 10 seconds after
   the session has been closed (if CIFS client hasn't deleted them before
   that). */
#define SSH_APPGW_CIFS_TREE_TIMEOUT     10


/* Context data for "multi part" I/O requests. (i.e. requests containing
   several CIFS packets) */
struct SshAppgwCifsMultiPartIORec
{
  SshAppgwCifsMultiPartIOType type;
  SshAppgwCifsFileHandle file;

  /* Un-aligned begin address of the buffer. */
  unsigned char *_buff_begin;
  unsigned char *buffer;
  size_t base_offset;
  size_t total_size;
  size_t bytes_in_buffer;

  /* Optional context and a delete callback */
  void * context;
  SshAppgwCifsCtxDeleteCb delete_cb;
};

typedef struct SshAppgwCifsMultiPartIORec SshAppgwCifsMultiPartIOStruct;


/******************* Prototypes for static help function ********************/

/* A stream notification callback. */
static void ssh_appgw_cifs_stream_cb(SshStreamNotification notification,
                                       void *context);

/* A timeout function to terminate the CIFS connection `context'. */
static void ssh_appgw_cifs_connection_terminate(void *context);

/* Destroy and optionally unregister Common Internet File System application
   gateway instance `ctx'. */
static void ssh_appgw_cifs_destroy(SshAppgwCifsCtx ctx);

/* Timeout function for deleting unresponded requests */
static void
ssh_appgw_cifs_pending_request_timeout(void * context);

/* Timeout function for deleting "zombie" trees */
static void
ssh_appgw_cifs_tree_delete_timeout(void * context);


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_appgw_cifs_io_st_terminate);
SSH_FSM_STEP(ssh_appgw_cifs_io_st_write);


/************************** ADT bag for session IDs *************************/

static SshUInt32
ssh_appgw_cifs_session_hash(void *ptr, void *ctx)
{
  SshAppgwCifsSession session = (SshAppgwCifsSession) ptr;

  return session->id;
}


static int
ssh_appgw_cifs_session_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwCifsSession session1 = (SshAppgwCifsSession) ptr1;
  SshAppgwCifsSession session2 = (SshAppgwCifsSession) ptr2;

  if (session1->id != session2->id)
    return -1;

  return 0;
}


static void
ssh_appgw_cifs_session_destroy(void *ptr, void *ctx)
{
  SshAppgwCifsSession session = (SshAppgwCifsSession) ptr;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Session (uid=0x%04X) deleted", session->id));

  ssh_free(session->account);
  ssh_free(session->domain);
  ssh_free(session);
}


/************************** ADT bag for CIFS trees **************************/

static SshUInt32
ssh_appgw_cifs_tree_hash(void *ptr, void *ctx)
{
  SshAppgwCifsTree tree = (SshAppgwCifsTree) ptr;

  return tree->tid;
}


static int
ssh_appgw_cifs_tree_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwCifsTree tree1 = (SshAppgwCifsTree) ptr1;
  SshAppgwCifsTree tree2 = (SshAppgwCifsTree) ptr2;

  if (tree1->tid != tree2->tid)
    return -1;

  return 0;
}


static void
ssh_appgw_cifs_tree_destroy(void *ptr, void *ctx)
{
  SshAppgwCifsTree tree = (SshAppgwCifsTree) ptr;

  ssh_cancel_timeouts(ssh_appgw_cifs_tree_delete_timeout, tree);
  ssh_free(tree);
}


/*************************** ADT bag for handles ****************************/

static SshUInt32
ssh_appgw_cifs_handle_hash(void *ptr, void *ctx)
{
  SshAppgwCifsHandle handle = (SshAppgwCifsHandle) ptr;

  return ((handle->handle_type << 16) || handle->id);
}


static int
ssh_appgw_cifs_handle_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwCifsHandle h1 = (SshAppgwCifsHandle) ptr1;
  SshAppgwCifsHandle h2 = (SshAppgwCifsHandle) ptr2;

  if (h1->handle_type != h2->handle_type)
    return -1;

  if (h1->id != h2->id)
    return -1;

  return 0;
}


static void
ssh_appgw_cifs_handle_destroy(void *ptr, void *ctx)
{
  SshAppgwCifsHandle handle = (SshAppgwCifsHandle) ptr;

  SSH_DEBUG(SSH_D_MY5, ("Deleting handle [%p]", handle));

  if (handle->read_op != NULL)
    ssh_appgw_cifs_mp_io_end(handle->read_op);

  ssh_free(handle);

  SSH_DEBUG(SSH_D_MY5, ("Handle deleted [%p]", handle));
}


/********************* ADT bag for pending CIFS requests ********************/

static SshUInt32
ssh_appgw_cifs_request_hash(void *ptr, void *ctx)
{
  SshAppgwCifsRequest req = (SshAppgwCifsRequest) ptr;

  return (((req->command << 16) | req->uid) ^ ((req->tid << 16) | req->mid));
}


static int
ssh_appgw_cifs_request_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwCifsRequest req1 = (SshAppgwCifsRequest) ptr1;
  SshAppgwCifsRequest req2 = (SshAppgwCifsRequest) ptr2;

  if (req1->command != req2->command)
    return -1;

  if (req1->uid != req2->uid)
    return -1;

  if (req1->tid != req2->tid)
    return -1;

  if (req1->mid != req2->mid)
    return -1;

  /* 'pid' fields are not compared, because they are normally host specific
     values (i.e. not the same values in both requests and responses) */

  return 0;
}


static void
ssh_appgw_cifs_request_destroy(void *ptr, void *ctx)
{
  SshAppgwCifsRequest req = (SshAppgwCifsRequest) ptr;
  SshAppgwCifsCtx cifs_alg;

  SSH_ASSERT(req != NULL);

  cifs_alg = (SshAppgwCifsCtx)req->conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  if ((req->timeout_disabled == 0) && (req->timeout == 0))
    ssh_cancel_timeouts(ssh_appgw_cifs_pending_request_timeout, req);

  if (req->cmd_ctx != NULL)
    ssh_appgw_cifs_cmd_contexts_delete(req->conn, req->cmd_ctx);

  if (req->andx_commands != NULL)
    ssh_appgw_cifs_andx_commands_delete(req->conn, req->andx_commands);

  if (req->pre_allocated)
    {
      req->next = cifs_alg->free_requests;
      cifs_alg->free_requests = req;
    }
  else
    ssh_free(req);

  cifs_alg->num_requests--;

  SSH_DEBUG(SSH_D_MY5, ("Request destroyed (%lu remaining)",
            cifs_alg->num_requests));
}


static Boolean
ssh_appgw_cifs_strlen(size_t *len_return,
                      SshUInt8 *padding_return,
                      SshAppgwCifsDataFormat buff_format,
                      const unsigned char *buffer,
                      size_t buffer_len,
                      Boolean unicode)
{
  size_t string_len;
  SshUInt8 extra_padding = 0;

  SSH_ASSERT(len_return != NULL);
  SSH_ASSERT((buffer != NULL) || (buffer_len == 0));

  *len_return = 0;

  if (padding_return != NULL)
    *padding_return = 0;

  if (buffer_len == 0)
    return TRUE;

  switch (buff_format)
    {
    /* If buffer type is either "dialect" or "ASCII" the first byte of the
       buffer must contain the type. (The actual string begins from the
       second byte. */
    case SSH_APPGW_CIFS_DATA_DIALECT:
    case SSH_APPGW_CIFS_DATA_STRING:
      if (buffer[0] != buff_format)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Buffer does not contain valid string!"));
          return FALSE;
        }
      buffer++;
      buffer_len--;
      extra_padding = 1;
      break;

    default:
      break;
    }

  if (unicode)
    {
      SshUInt32 ptr = *(SshUInt32 *) buffer;
      
      /* If buffer is not 16-bit aligned, there is one byte of padding before
         the string begins */
      if (ptr & 0x00000001)
        {
          buffer++;

          if (padding_return != NULL)
            *padding_return = 1;
        }

      for (string_len = 0; string_len < buffer_len-1; string_len += 2)
        {
          SshUInt16 uchar = SSH_GET_16BIT(buffer);

          if (uchar == 0x0000)
            break;

          buffer += 2;
        }

      /* UNICODE string without terminating NULL character */
    }
  else
    {
      /* ASCII/ANSI string */
      for (string_len = 0; string_len < buffer_len; string_len++)
        {
          if (*buffer == 0x00)
            break;

          buffer++;
        }
    }

  *len_return = string_len;

  if ((padding_return != NULL) && (extra_padding))
    *padding_return += extra_padding;

  return TRUE;
}


/************************* Exported help functions **************************/

Boolean
ssh_appgw_cifs_strsize(size_t *size_ptr,
                       SshAppgwCifsDataFormat buff_format,
                       const unsigned char *buffer,
                       size_t buffer_len,
                       Boolean unicode)
{
  SshUInt8 padding;
  size_t str_len;

  SSH_ASSERT(size_ptr != NULL);
  SSH_ASSERT((buffer != NULL) || (buffer_len == 0));

  *size_ptr = 0;

  if (buffer_len == 0)
    return TRUE;

  if (ssh_appgw_cifs_strlen(&str_len, &padding, buff_format,
                            buffer, buffer_len, unicode))
    {
      size_t total_size;

      if (unicode)
        total_size = padding + str_len + 2;
      else
        total_size = padding + str_len + 1;

      *size_ptr = total_size;

      return TRUE;
    }

  return FALSE;
}


char *
ssh_appgw_cifs_strdup(SshAppgwCifsCtx cifs_alg,
                      SshAppgwCifsDataFormat buff_format,
                      const unsigned char *buffer,
                      size_t buff_len,
                      Boolean original_is_unicode)
{
  SshUInt8 padding;
  size_t str_len;
  char *ascii_copy;

  if (ssh_appgw_cifs_strlen(&str_len, &padding, buff_format,
                            buffer, buff_len, original_is_unicode))
    {
      size_t str_size;
      size_t total_size = str_len + padding;

      if (original_is_unicode)
        {
          str_size = (str_len/2) + 1;

          /* Last string in buffer is not necessary NULL terminated */
          if (buff_len > 1 && total_size < (buff_len - 2))
            total_size += 2;
          else
            total_size = buff_len;
        }
      else
        {
          str_size = str_len + 1;

          /* Last string in buffer is not necessary NULL terminated */
          if (buff_len > 0 && total_size < (buff_len - 1))
            total_size += 1;
          else
            total_size = buff_len;
        }

      if (total_size > buff_len)
        return NULL;

      ascii_copy = ssh_calloc(1, str_size);
      if (ascii_copy == NULL)
        return NULL;

      if (original_is_unicode)
        ssh_charset_convert(cifs_alg->unicode_to_ascii,
                            (char *)buffer+padding, str_len,
                            ascii_copy, str_size);
      else
        memcpy(ascii_copy, buffer+padding, str_size);

      return ascii_copy;
    }

  return NULL;
}


/* Add a new slot for storing CIFS command specific context. */
SshAppgwCifsCmdCtxSlot
ssh_appgw_cifs_cmd_context_slot_add(SshAppgwCifsConn conn,
                                    SshAppgwCifsParser cifs)
{
  SshAppgwCifsCmdCtxSlot slot;
  SshAppgwCifsCtx cifs_alg;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(conn->ctx != NULL);
  SSH_ASSERT(cifs != NULL);

  cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  if (cifs_alg->free_cmd_ctxs != NULL)
    {
      slot = cifs_alg->free_cmd_ctxs;
      cifs_alg->free_cmd_ctxs = slot->next;
    }
  else
    {
      slot = ssh_calloc(1, sizeof(*slot));

      if (slot != NULL)
        slot->pre_allocated = FALSE;
    }

  if (slot != NULL)
    {
      slot->context = NULL;
      slot->delete_cb = NULL_FNPTR;
      slot->next = NULL;
      slot->andx_context = 0;

      if (cifs->first_cmd_ctx == NULL)
        {
          cifs->first_cmd_ctx = slot;
        }
      else
        {
          SshAppgwCifsCmdCtxSlot prev_slot = cifs->first_cmd_ctx;

          while (prev_slot->next != NULL)
            prev_slot = prev_slot->next;

          prev_slot->next = slot;
        }

      cifs->cmd_ctx = slot;

      if (cifs->andx_commands != NULL)
        {
          slot->andx_context = 1;
          cifs->andx_commands->context = slot;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate a slot for command specific context!"));
    }

  return slot;
}


void *
ssh_appgw_cifs_cmd_context_allocate(SshAppgwCifsConn conn,
                                    SshAppgwCifsParser cifs,
                                    size_t size_of_context,
                                    SshAppgwCifsCtxDeleteCb delete_cb)
{
  void * context;

  if (ssh_appgw_cifs_cmd_context_slot_add(conn, cifs) == NULL)
    return NULL;

  context = ssh_calloc(1, size_of_context);
  if (context == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate command specific context"));

      ssh_appgw_cifs_cmd_context_slot_remove(conn, cifs);

      return NULL;
    }

  /* Store the context into CIFS parser structure */
  cifs->cmd_ctx->context = context;
  cifs->cmd_ctx->delete_cb = delete_cb;

  return context;
}


void
ssh_appgw_cifs_cmd_context_slot_remove(SshAppgwCifsConn conn,
                                       SshAppgwCifsParser cifs)
{
  SshAppgwCifsCmdCtxSlot deleted_slot = cifs->cmd_ctx;

  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(deleted_slot != NULL);

  SSH_DEBUG(SSH_D_MY5, ("Context detached [Slot=%p, Context=%p]",
                        deleted_slot, deleted_slot->context));

  /* Update the cached information in CIFS parser context */
  cifs->cmd_ctx = cifs->cmd_ctx->next;

  if (cifs->first_cmd_ctx == deleted_slot)
   cifs->first_cmd_ctx = cifs->cmd_ctx;

  /* If (and when) we are currently filtering a response, we need to
     remove the same context also from the original request */
  if (cifs->response)
    {
      SSH_ASSERT(cifs->orig_request != NULL);
      SSH_ASSERT(cifs->orig_request->cmd_ctx != NULL);

      if (deleted_slot == cifs->orig_request->cmd_ctx)
        {
          /* First slot deleted */
          cifs->orig_request->cmd_ctx = deleted_slot->next;
        }
      else
        {
          SshAppgwCifsCmdCtxSlot prev = cifs->orig_request->cmd_ctx;
          SshAppgwCifsCmdCtxSlot slot;

          for (slot = prev->next; slot != NULL; slot = slot->next)
            {
              if (slot == deleted_slot)
                {
                  prev->next = slot->next;
                  break;
                }
            }
        }
    }

  /* Remove the link so this context can't be referenced from
     embedded command's context any more */
  if (deleted_slot->andx_context)
    {
      SshAppgwCifsEmbeddedCmd embedded_cmd;

      embedded_cmd = cifs->andx_commands;

      while (embedded_cmd)
        {
          if (deleted_slot == embedded_cmd->context)
            {
              embedded_cmd->context = NULL;
              break;
            }

          embedded_cmd = embedded_cmd->next;
        }
    }

  /* Finally we need to delete the slot holding the context */
  if (deleted_slot->pre_allocated)
    {
      SshAppgwCifsCtx cifs_alg;

      cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;

      deleted_slot->next = cifs_alg->free_cmd_ctxs;
      cifs_alg->free_cmd_ctxs = deleted_slot;
    }
  else
    ssh_free(deleted_slot);
}


void ssh_appgw_cifs_cmd_contexts_delete(SshAppgwCifsConn conn,
                                        SshAppgwCifsCmdCtxSlot first_slot)
{
  SshAppgwCifsCmdCtxSlot cmd_ctx;
  SshAppgwCifsCmdCtxSlot next_ctx;
  SshAppgwCifsCtx cifs_alg;

  SSH_ASSERT(conn != NULL);

  cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  for (cmd_ctx = first_slot; cmd_ctx != NULL; cmd_ctx = next_ctx)
    {
      next_ctx = cmd_ctx->next;

      if ((cmd_ctx->context != NULL) && (cmd_ctx->delete_cb != NULL_FNPTR))
        cmd_ctx->delete_cb(cmd_ctx->context);

      if (cmd_ctx->pre_allocated)
        {
          cmd_ctx->next = cifs_alg->free_cmd_ctxs;
          cifs_alg->free_cmd_ctxs = cmd_ctx;
        }
      else
        ssh_free(cmd_ctx);
    }
}


void *
ssh_appgw_cifs_cmd_context_get(SshAppgwCifsConn conn,
                               SshAppgwCifsParser cifs)
{
  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(cifs->cmd_ctx != NULL);

  return cifs->cmd_ctx->context;
}


void
ssh_appgw_cifs_cmd_context_set(SshAppgwCifsCmdCtxSlot slot,
                               void * context,
                               SshAppgwCifsCtxDeleteCb delete_cb)
{
  SSH_ASSERT(slot != NULL);

  /* Check that this is a free slot */
  SSH_ASSERT(slot->context == NULL);
  SSH_ASSERT(slot->delete_cb == NULL_FNPTR);

  /* It's allowed to set a NULL context */
  slot->context = context;
  slot->delete_cb = delete_cb;
}


void
ssh_appgw_cifs_andx_commands_delete(SshAppgwCifsConn conn,
                                    SshAppgwCifsEmbeddedCmd andx_cmd)
{
  SSH_ASSERT(conn != NULL);

  while (andx_cmd != NULL)
    {
      SshAppgwCifsEmbeddedCmd next = andx_cmd->next;

      ssh_free(andx_cmd);

      andx_cmd = next;
    }
}


SshAppgwCifsMultiPartIO
ssh_appgw_cifs_mp_io_begin(SshAppgwCifsFileHandle file,
                           SshAppgwCifsMultiPartIOType type,
                           size_t total_length,
                           void *context,
                           SshAppgwCifsCtxDeleteCb ctx_delete_cb)
{
  SshAppgwCifsMultiPartIO *iop = NULL;
  SSH_ASSERT(file != NULL);
  SSH_ASSERT(total_length != 0);

  if (total_length > SSH_APPGW_CIFS_MAX_MULTI_PART_IO_SIZE)
    return NULL;

  switch (type)
    {
    case SSH_APPGW_CIFS_MULTI_PART_READ:
      iop = &(file->read_op);
      break;

    case SSH_APPGW_CIFS_MULTI_PART_WRITE:
      iop = &(file->write_op);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  if (*iop != NULL)
    ssh_appgw_cifs_mp_io_end(*iop);

  *iop = ssh_calloc(1, sizeof(SshAppgwCifsMultiPartIOStruct));
  if (*iop == NULL)
    return NULL;

  (*iop)->_buff_begin = ssh_calloc(1, total_length + 8);
  if ((*iop)->_buff_begin == NULL)
    {
      ssh_free(*iop);
      return NULL;
    }

  (*iop)->buffer = (*iop)->_buff_begin;
  while ((unsigned long)(*iop)->buffer % 8)
    ((*iop)->buffer)++;

  (*iop)->file = file;
  (*iop)->type = type;
  (*iop)->total_size = (size_t)total_length;
  (*iop)->context = context;
  (*iop)->delete_cb = ctx_delete_cb;

  SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O operation allocated"));

  return (*iop);
}


SshAppgwCifsMultiPartIO
ssh_appgw_cifs_mp_io_get(SshAppgwCifsFileHandle file,
                         SshAppgwCifsMultiPartIOType type)
{
  SSH_ASSERT(file != NULL);

  switch (type)
    {
    case SSH_APPGW_CIFS_MULTI_PART_READ:
      return (file->read_op);

    case SSH_APPGW_CIFS_MULTI_PART_WRITE:
      return (file->write_op);

    default:
      SSH_NOTREACHED;
      return NULL;
    }
}


Boolean
ssh_appgw_cifs_mp_io_append(SshAppgwCifsMultiPartIO io,
                            const unsigned char *buffer,
                            size_t buffer_len)
{
  if ((io->bytes_in_buffer + buffer_len) > io->total_size)
    {
      ssh_appgw_cifs_mp_io_end(io);
      return FALSE;
    }

  memcpy(io->buffer + io->bytes_in_buffer, buffer, buffer_len);
  io->bytes_in_buffer += buffer_len;

  SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O: %zu/%zu bytes copied",
			io->bytes_in_buffer, io->total_size));

  if (io->bytes_in_buffer == io->total_size)
    {
      SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O operation complete"));
    }

  return TRUE;
}


void
ssh_appgw_cifs_mp_io_base_offset_set(SshAppgwCifsMultiPartIO io,
                                     size_t base_offset)
{
  if (base_offset <= io->total_size)
    {
      SSH_DEBUG(SSH_D_MY1,
                ("Multi-part I/O: base offset set to %zu", base_offset));

      io->base_offset = base_offset;
    }
}


Boolean
ssh_appgw_cifs_mp_io_insert(SshAppgwCifsMultiPartIO io,
                            size_t offset,
                            const unsigned char *buffer,
                            size_t buffer_len)
{
  offset += io->base_offset;

  if ((offset + buffer_len) > io->total_size)
    {
      ssh_appgw_cifs_mp_io_end(io);
      return FALSE;
    }

  SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O: inserting bytes %zu...%zu",
            offset, offset + buffer_len));

  memcpy(io->buffer + offset, buffer, buffer_len);

  if (io->bytes_in_buffer < (offset + buffer_len))
    io->bytes_in_buffer = offset + buffer_len;

  SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O: %zu/%zu bytes copied",
            io->bytes_in_buffer, io->total_size));

  if (io->bytes_in_buffer == io->total_size)
    {
      SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O operation complete"));
    }

  return TRUE;
}


Boolean
ssh_appgw_cifs_mp_io_is_complete(SshAppgwCifsMultiPartIO io)
{
  if (io->bytes_in_buffer == io->total_size)
    return TRUE;
  else
    return FALSE;
}


void
ssh_appgw_cifs_mp_io_data_get(SshAppgwCifsMultiPartIO io,
                              const unsigned char **buffer_return,
                              size_t *length_return)
{
  SSH_ASSERT(buffer_return != NULL);
  SSH_ASSERT(length_return != NULL);

  *buffer_return = io->buffer;
  *length_return = io->bytes_in_buffer;
}


void
ssh_appgw_cifs_mp_io_end(SshAppgwCifsMultiPartIO io)
{
  SshAppgwCifsMultiPartIO *iop = NULL;

  if (io == NULL)
    return;

  if (io->context)
    {
      SSH_ASSERT(io->delete_cb != NULL_FNPTR);

      io->delete_cb(io->context);
    }

  if (io->_buff_begin)
    ssh_free(io->_buff_begin);

  switch (io->type)
    {
    case SSH_APPGW_CIFS_MULTI_PART_READ:
      iop = &(io->file->read_op);
      break;

    case SSH_APPGW_CIFS_MULTI_PART_WRITE:
      iop = &(io->file->write_op);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_free(io);

  *iop = NULL;

  SSH_DEBUG(SSH_D_MY1, ("Multi-part I/O operation deleted"));
}


/************************** Static help functions ***************************/

static void
ssh_appgw_cifs_tree_delete_timeout(void * context)
{
  SshAppgwCifsTree tree = (SshAppgwCifsTree)context;

  SSH_ASSERT(tree != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Timeout! (connected tree, tid=0x%04X)", tree->tid));

  ssh_appgw_cifs_tree_remove(tree);
}


static void
ssh_appgw_cifs_pending_request_timeout(void * context)
{
  SshAppgwCifsRequest req = (SshAppgwCifsRequest) context;

  SSH_ASSERT(req != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Timeout! (%s, uid=0x%04X, pid=0x%04X, tid=0x%04X, mid=0x%04X)",
             ssh_appgw_cifs_cmd_to_name(req->command),
             req->uid, req->pid, req->tid, req->mid));

  req->timeout = 1;

  if (req->busy == 0)
    ssh_appgw_cifs_pending_request_remove(req);
}


/******************************** CIFS trees ********************************/

SshAppgwCifsTree
ssh_appgw_cifs_tree_allocate(SshAppgwCifsConn conn,
                             const unsigned char *name_buffer,
                             size_t buffer_len,
                             Boolean unicode_format)
{
  SshAppgwCifsTree tree;
  size_t name_len;
  SshUInt8 padding;

  SSH_ASSERT(name_buffer != NULL);

  if (ssh_appgw_cifs_strlen(&name_len, &padding, SSH_APPGW_CIFS_DATA_PATHNAME,
                            name_buffer, buffer_len, unicode_format) == FALSE)
    return NULL;

  if (unicode_format)
    name_len = name_len/2;

  /* SshAppgwCifsTreeStruct already reserves space for terminating NULL
     character. */
  tree = ssh_calloc(1, (sizeof(*tree) + name_len));
  if (tree)
    {
      if (unicode_format)
        {
          SshAppgwCifsCtx cifs_ctx;

          cifs_ctx = (SshAppgwCifsCtx)conn->ctx->user_context;

          name_len = ssh_charset_convert(cifs_ctx->unicode_to_ascii,
                                     (unsigned char *)(name_buffer + padding),
                                     name_len * 2, tree->name, name_len);
        }
      else
        {
          memcpy(tree->name, name_buffer, name_len);
        }

      /* Ensure that the filename is always null-terminated */
      tree->name[name_len] = 0x00;
      tree->conn = conn;
      tree->tid = 0;
      tree->ipc_service = 0;
    }

  return tree;
}


void
ssh_appgw_cifs_tree_insert(SshAppgwCifsTree tree)
{
  SSH_ASSERT(tree != NULL);
  SSH_ASSERT(tree->conn != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Tree \"%s\" added (tid=0x%04X)", tree->name, tree->tid));

  ssh_adt_insert(tree->conn->connected_trees, tree);
}


void
ssh_appgw_cifs_tree_remove(SshAppgwCifsTree tree)
{
  SshADTHandle h;
  SshADTHandle hnext;

  SSH_ASSERT(tree != NULL);
  SSH_ASSERT(tree->conn != NULL);

  /* Delete all tree specific pending requests */
  for (h = ssh_adt_enumerate_start(tree->conn->pending_requests);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwCifsRequest request;

      hnext = ssh_adt_enumerate_next(tree->conn->pending_requests, h);

      request = ssh_adt_get(tree->conn->pending_requests, h);
      SSH_ASSERT(request != NULL);

      if ((request->busy == 0) &&
          (request->tid == tree->tid))
        ssh_appgw_cifs_pending_request_remove(request);
    }

  /* Delete all tree-specific handles */
  for (h = ssh_adt_enumerate_start(tree->conn->open_handles);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwCifsHandle cifs_handle;

      hnext = ssh_adt_enumerate_next(tree->conn->open_handles, h);

      cifs_handle = ssh_adt_get(tree->conn->open_handles, h);
      SSH_ASSERT(cifs_handle != NULL);

      if (cifs_handle->tree == tree)
        ssh_appgw_cifs_file_handle_remove(cifs_handle);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Tree \"%s\" removed (tid=0x%04X)", tree->name, tree->tid));

  ssh_adt_delete_object(tree->conn->connected_trees, tree);
}


SshAppgwCifsTree
ssh_appgw_cifs_tree_lookup(SshAppgwCifsConn conn,
                           SshAppgwCifsParser cifs)
{
  SshADTHandle h;
  SshAppgwCifsTreeStruct  tree_struct;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(conn->connected_trees != NULL);

  tree_struct.tid = cifs->tid;

  h = ssh_adt_get_handle_to_equal(conn->connected_trees, &tree_struct);

  if (h != SSH_ADT_INVALID)
    return ssh_adt_get(conn->connected_trees, h);
  else
    return NULL;
}


/****************************** CIFS sessions *******************************/

Boolean
ssh_appgw_cifs_session_insert(SshAppgwCifsSession session)
{
  SshAppgwCifsConn conn;

  SSH_ASSERT(session != NULL);
  SSH_ASSERT(session->conn != NULL);

  conn = session->conn;

  if (session->vc_number == 0)
    {
      if (session->null_session)
        {
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "NULL CIFS session (anonymous logon) opened",
                                SSH_AUDIT_ARGUMENT_END);
        }
      else
        {
          if (ssh_adt_num_objects(conn->active_sessions) > 0)
            {
              SshADTHandle h;

              SSH_DEBUG(SSH_D_FAIL, ("Primary session re-opened"));

              if (session->id == 0x0000) /* Win9X compatibility kludge... */
                {
                  h = ssh_adt_get_handle_to_equal(conn->active_sessions,
                                                  session);
                  if (h != SSH_ADT_INVALID)
                    {
                      ssh_appgw_cifs_session_destroy(session, NULL);
                      return TRUE;
                    }
                  else
                    {
                      /* Remove all virtual circuits if - and only if - the
                         session ID changes. */
                      ssh_appgw_cifs_remove_all_sessions(conn);
                    }
                }
              else
                {
                  ssh_appgw_cifs_remove_all_sessions(conn);
                }
            }

          if ((session->domain != NULL) && strlen(session->domain) &&
              (session->account != NULL) && strlen(session->account))
            {

              ssh_appgw_audit_event(conn->ctx,
                                    SSH_AUDIT_CIFS_SESSION_START,
                                    SSH_AUDIT_CIFS_DOMAIN, session->domain,
                                    SSH_AUDIT_CIFS_ACCOUNT, session->account,
                                    SSH_AUDIT_ARGUMENT_END);
            }
          else
            {
              ssh_appgw_audit_event(conn->ctx,
                                    SSH_AUDIT_CIFS_SESSION_START,
                                    SSH_AUDIT_ARGUMENT_END);
            }
        }
    }
  else if (ssh_adt_num_objects(conn->active_sessions) >= conn->max_sessions)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "session rejected: too many virtual circuits.",
                            SSH_AUDIT_ARGUMENT_END);
      return FALSE;
    }

  ssh_adt_insert(session->conn->active_sessions, session);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Session (uid=0x%04X) added", session->id));

  conn->session_phase = SSH_APPGW_CIFS_SESSION_STEADY;

  return TRUE;
}


void
ssh_appgw_cifs_session_remove(SshAppgwCifsSession session)
{
  SshADTHandle h;
  SshAppgwCifsConn conn;

  SSH_ASSERT(session != NULL);
  SSH_ASSERT(session->conn != NULL);

  conn = session->conn;

  SSH_ASSERT(conn->active_sessions != NULL);

  ssh_adt_delete_object(conn->active_sessions, session);

  if (ssh_adt_num_objects(conn->active_sessions) == 0)
    {
      SshADTHandle hnext;
      SshAppgwCifsTree tree;

      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_CIFS_SESSION_STOP,
                            SSH_AUDIT_ARGUMENT_END);

      /* If this was the last session, we must also register timeouts for
         deleting connected trees */
      for (h = ssh_adt_enumerate_start(conn->connected_trees);
           h != SSH_ADT_INVALID;
           h = hnext)
        {
          hnext = ssh_adt_enumerate_next(conn->connected_trees, h);

          tree = ssh_adt_get(conn->connected_trees, h);
          SSH_ASSERT(tree != NULL);

          ssh_xregister_timeout(SSH_APPGW_CIFS_TREE_TIMEOUT, 0,
                               ssh_appgw_cifs_tree_delete_timeout, tree);
        }

      conn->session_phase = SSH_APPGW_CIFS_SESSION_AUTHENTICATING;
    }
}


void
ssh_appgw_cifs_remove_all_sessions(SshAppgwCifsConn conn)
{
  SshADTHandle h;
  SshADTHandle hnext;

  /* Delete all specific of the specified connection */
  for (h = ssh_adt_enumerate_start(conn->active_sessions);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwCifsSession session;

      hnext = ssh_adt_enumerate_next(conn->active_sessions, h);

      session = ssh_adt_get(conn->active_sessions, h);
      SSH_ASSERT(session != NULL);

      ssh_appgw_cifs_session_remove(session);
    }
}


SshAppgwCifsSession
ssh_appgw_cifs_session_lookup(SshAppgwCifsConn conn,
                              SshAppgwCifsParser cifs)
{
  SshADTHandle h;
  SshAppgwCifsSessionStruct  id_struct;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(conn->active_sessions != NULL);

  id_struct.id = cifs->uid;

  h = ssh_adt_get_handle_to_equal(conn->active_sessions, &id_struct);

  if (h != SSH_ADT_INVALID)
    return ssh_adt_get(conn->active_sessions, h);
  else
    return NULL;
}


/************************* File and search handles **************************/

static SshAppgwCifsHandle
ssh_appgw_cifs_handle_allocate(SshAppgwCifsConn conn,
                               SshAppgwCifsDataFormat buff_format,
                               const unsigned char *name_buffer,
                               size_t buffer_len,
                               Boolean unicode_format)
{
  SshAppgwCifsHandle handle;
  size_t name_len;
  SshUInt8 padding;

  SSH_ASSERT(name_buffer != NULL);

  if (ssh_appgw_cifs_strlen(&name_len, &padding, buff_format,
                            name_buffer, buffer_len, unicode_format) == FALSE)
    return NULL;

  if (unicode_format)
    name_len = name_len/2;

  /* SshAppgwCifsHandleStruct reserves space for terminating NULL
     character. */
  handle = ssh_calloc(1, (sizeof(*handle) + name_len));
  if (handle)
    {
      if (unicode_format)
        {
          SshAppgwCifsCtx cifs_ctx;

          cifs_ctx = (SshAppgwCifsCtx)conn->ctx->user_context;

          name_len = ssh_charset_convert(cifs_ctx->unicode_to_ascii,
                                         (char *)name_buffer + padding,
                                         name_len * 2,
                                         handle->name, name_len);
        }
      else
        {
          memcpy(handle->name, name_buffer+padding, name_len);
        }

      /* Ensure that the filename is always null-terminated */
      handle->name[name_len] = 0x00;
      handle->id = 0;
      handle->directory = 0;
      handle->delete_access = 0;
      handle->execute_access = 0;
      handle->write_access = 0;
      handle->read_access = 0;
      handle->query_access = 0;
      handle->close_after_request = 0;
      handle->close_when_complete = 0;
      handle->conn = conn;
      handle->tree = NULL;
      handle->file_type = SSH_SMB_FILE_TYPE_FILE_OR_DIR;
      handle->read_op = NULL;
      handle->write_op = NULL;
    }

  return handle;
}


static void
ssh_appgw_cifs_handle_insert(SshAppgwCifsHandle handle)
{
  SSH_ASSERT(handle != NULL);
  SSH_ASSERT(handle->conn != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Handle added (%p, type=%u, id=0x%04X)",
                               handle, handle->handle_type, handle->id));

  ssh_adt_insert(handle->conn->open_handles, handle);
}


static void
ssh_appgw_cifs_handle_remove(SshAppgwCifsHandle handle)
{
  SSH_ASSERT(handle != NULL);
  SSH_ASSERT(handle->conn != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Handle removed (%p, type=%u, id=0x%04X)",
                               handle, handle->handle_type, handle->id));

  ssh_adt_delete_object(handle->conn->open_handles, handle);
}


static SshAppgwCifsHandle
ssh_appgw_cifs_handle_lookup(SshAppgwCifsConn conn,
                             SshAppgwCifsHandleType type,
                             SshUInt16 id)
{
  SshADTHandle h;
  SshAppgwCifsHandleStruct handle;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(conn->open_handles != NULL);

  handle.handle_type = type;
  handle.id = id;

  h = ssh_adt_get_handle_to_equal(conn->open_handles, &handle);

  if (h != SSH_ADT_INVALID)
    return ssh_adt_get(conn->open_handles, h);
  else
    return NULL;
}

/****************************** File handles ********************************/

SshAppgwCifsFileHandle
ssh_appgw_cifs_file_handle_allocate(SshAppgwCifsConn conn,
                                    SshAppgwCifsDataFormat buff_format,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format)
{
  SshAppgwCifsFileHandle file;

  file = ssh_appgw_cifs_handle_allocate(conn, buff_format, name_buffer,
                                        buffer_len, unicode_format);

  if (file)
    file->handle_type = SSH_APPGW_CIFS_FILE_HANDLE;

  return file;
}


void
ssh_appgw_cifs_file_handle_insert(SshAppgwCifsFileHandle file)
{
  SSH_ASSERT(file != NULL);

  ssh_appgw_cifs_handle_insert(file);
}


void
ssh_appgw_cifs_file_handle_remove(SshAppgwCifsFileHandle file)
{
  SshADTHandle h, hnext;

  SSH_ASSERT(file != NULL);
  SSH_ASSERT(file->conn != NULL);

  /* Delete pending file requests */
  for (h = ssh_adt_enumerate_start(file->conn->pending_requests);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwCifsRequest request;

      hnext = ssh_adt_enumerate_next(file->conn->pending_requests, h);

      request = ssh_adt_get(file->conn->pending_requests, h);
      SSH_ASSERT(request != NULL);

      if ((request->busy == 0) && (request->fid == file->id))
        ssh_appgw_cifs_pending_request_remove(request);
    }

  ssh_appgw_cifs_handle_remove(file);
}


SshAppgwCifsFileHandle
ssh_appgw_cifs_file_handle_lookup(SshAppgwCifsConn conn,
                                  SshUInt16 fid)
{
  return ssh_appgw_cifs_handle_lookup(conn, SSH_APPGW_CIFS_FILE_HANDLE, fid);
}


/**************************** Search handles ********************************/

SshAppgwCifsSearchHandle
ssh_appgw_cifs_search_handle_allocate(SshAppgwCifsConn conn,
                                      SshAppgwCifsDataFormat buff_format,
                                      const unsigned char *name_buffer,
                                      size_t buffer_len,
                                      Boolean unicode_format)
{
  SshAppgwCifsSearchHandle search;

  search = ssh_appgw_cifs_handle_allocate(conn, buff_format, name_buffer,
                                          buffer_len, unicode_format);
  if (search)
    search->handle_type = SSH_APPGW_CIFS_SEARCH_HANDLE;

  return search;
}


void
ssh_appgw_cifs_search_handle_insert(SshAppgwCifsSearchHandle search)
{
  ssh_appgw_cifs_handle_insert(search);
}


void
ssh_appgw_cifs_search_handle_remove(SshAppgwCifsSearchHandle search)
{
  ssh_appgw_cifs_handle_remove(search);
}


SshAppgwCifsSearchHandle
ssh_appgw_cifs_search_handle_lookup(SshAppgwCifsConn conn,
                                    SshUInt16 sid)
{
  return ssh_appgw_cifs_handle_lookup(conn,
                                      SSH_APPGW_CIFS_SEARCH_HANDLE, sid);
}


/************************* Pending CIFS requests ****************************/
void
ssh_appgw_cifs_pending_request_init(SshAppgwCifsRequest req,
                                    SshAppgwCifsConn conn,
                                    SshAppgwCifsParser cifs)
{
  SSH_ASSERT(req != NULL);
  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);

  req->more_processing = 0;
  req->timeout = 0;
  req->canceled = 0;
  req->busy = 0;
  req->andx_commands = NULL;
  req->cmd_ctx = NULL;

  req->conn = conn;
  req->command = cifs->command;
  req->mid = cifs->mid;
  req->pid = cifs->pid;
  req->fid = cifs->fid;
  req->response_timeout = cifs->response_wait_time;
  req->timeout_disabled = cifs->no_timeout;

  switch (req->command)
    {
    case SSH_SMB_COM_NEGOTIATE:
    case SSH_SMB_COM_SESSION_SETUP_ANDX:
    case SSH_SMB_COM_ECHO:
      req->uid = SSH_APPGW_CIFS_ID_DONT_CARE;
      req->mid = SSH_APPGW_CIFS_ID_DONT_CARE;
      req->tid = SSH_APPGW_CIFS_ID_DONT_CARE;
      break;

    case SSH_SMB_COM_LOGOFF_ANDX:
    case SSH_SMB_COM_TREE_CONNECT:
    case SSH_SMB_COM_TREE_CONNECT_ANDX:
      req->uid = SSH_APPGW_CIFS_ID_DONT_CARE;
      req->tid = SSH_APPGW_CIFS_ID_DONT_CARE;
      break;

    default:
      req->uid = cifs->uid;
      req->tid = cifs->tid;
      break;
    }

  if (cifs->transaction)
    req->more_processing = 1;
}


SshAppgwCifsRequest
ssh_appgw_cifs_pending_request_add(SshAppgwCifsConn conn,
                                   SshAppgwCifsParser cifs)
{
  SshAppgwCifsRequest req;
  SshAppgwCifsCtx cifs_alg;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);
  SSH_ASSERT(cifs->response == 0);

  cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  /* Check whether we already know this request (i.e. the client is
     resending it) */
  req = ssh_appgw_cifs_pending_request_lookup(conn, cifs);
  if (req != NULL)
    {
      /* Yes, this is re-send operation. We need to delete the (duplicated)
         command specific contents and re-schedule a timeout. */
      ssh_appgw_cifs_cmd_contexts_delete(conn, cifs->first_cmd_ctx);
      ssh_appgw_cifs_andx_commands_delete(conn, cifs->andx_commands);

      if (req->timeout_disabled == 0)
        {
          SSH_DEBUG(SSH_D_MY5,
                    ("Re-scheduling timeout (%s, uid=0x%04X, pid=0x%04X, "
                     "tid=0x%04X, mid=0x%04X)",
                     ssh_appgw_cifs_cmd_to_name(req->command),
                     req->uid, req->pid, req->tid, req->mid));

          ssh_cancel_timeouts(ssh_appgw_cifs_pending_request_timeout, req);
        }

      goto succeeded;
    }

  /* This is a new request */
  if (cifs_alg->num_requests >= SSH_APPGW_CIFS_MAX_REQUESTS)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "resource limit reached",
                            SSH_AUDIT_TXT,
                            ssh_appgw_cifs_cmd_to_name(cifs->command),
                            SSH_AUDIT_ARGUMENT_END);
      goto failed;
    }

  if (ssh_adt_num_objects(conn->pending_requests) >=
                                                conn->max_pending_requests)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Maximum number of pending requests exceeded!"));
      goto failed;
    }

  if (cifs_alg->free_requests != NULL)
    {
      req = cifs_alg->free_requests;
      cifs_alg->free_requests = req->next;
    }
  else
    {
      req = ssh_calloc(1, sizeof(*req));
      if (req == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Couldn't allocate new request context!"));
          goto failed;
        }

      req->pre_allocated = FALSE;
    }

  ssh_appgw_cifs_pending_request_init(req, conn, cifs);

  req->cmd_ctx = cifs->first_cmd_ctx;
  req->andx_commands = cifs->andx_commands;

  SSH_DEBUG(SSH_D_MY5,
            ("Pending request added (%s, uid=0x%04X, pid=0x%04X, "
             "tid=0x%04X, mid=0x%04X)",
             ssh_appgw_cifs_cmd_to_name(req->command),
             req->uid, req->pid, req->tid, req->mid));

#ifdef DEBUG_LIGHT
  if (req->cmd_ctx)
    {
      SshAppgwCifsCmdCtxSlot cmd_ctx = req->cmd_ctx;

      while (cmd_ctx != NULL)
        {
          SSH_DEBUG(SSH_D_MY5, ("[Context = %p]", cmd_ctx->context));

          cmd_ctx = cmd_ctx->next;
        }
    }
#endif /* DEBUG_LIGHT */

  ssh_adt_insert(conn->pending_requests, req);

  cifs_alg->num_requests++;
  SSH_DEBUG(SSH_D_MY5, ("%lu requests pending", cifs_alg->num_requests));

succeeded:

  cifs->cmd_ctx = NULL;
  cifs->first_cmd_ctx = NULL;
  cifs->andx_commands = NULL;

  if (req->timeout_disabled == 0)
    {
      /* Schedule timeout, after which the pending request will be
         deleted if the CIFS/SMB server doesn't respond */
      ssh_xregister_timeout(req->response_timeout, 0,
                            ssh_appgw_cifs_pending_request_timeout, req);
    }

  return req;

failed:

  /* We must delete the command specific contexts, if any. */
  ssh_appgw_cifs_cmd_contexts_delete(conn, cifs->first_cmd_ctx);
  ssh_appgw_cifs_andx_commands_delete(conn, cifs->andx_commands);

  return NULL;
}


void
ssh_appgw_cifs_pending_request_remove(SshAppgwCifsRequest req)
{
  SSH_ASSERT(req != NULL);
  SSH_ASSERT(req->conn != NULL);

  SSH_DEBUG(SSH_D_MY5,
          ("Pending request removed (%s, uid=0x%04X, pid=0x%04X, "
           "tid=0x%04X, mid=0x%04X)",
           ssh_appgw_cifs_cmd_to_name(req->command),
           req->uid, req->pid, req->tid, req->mid));

#ifdef DEBUG_LIGHT
  if (req->cmd_ctx)
    {
      SshAppgwCifsCmdCtxSlot cmd_ctx = req->cmd_ctx;

      while (cmd_ctx != NULL)
        {
          SSH_DEBUG(SSH_D_MY5, ("[Context = %p]", cmd_ctx->context));

          cmd_ctx = cmd_ctx->next;
        }
    }
#endif /* DEBUG_LIGHT */

  ssh_adt_delete_object(req->conn->pending_requests, req);
}


SshAppgwCifsRequest
ssh_appgw_cifs_canceled_request_lookup(SshAppgwCifsRequest cancel_req)
{
  SshAppgwCifsConn conn;
  SshADTHandle h;
  SshADTHandle hnext;

  SSH_ASSERT(cancel_req != NULL);
  SSH_ASSERT(cancel_req->conn != NULL);

  conn = cancel_req->conn;

  for (h = ssh_adt_enumerate_start(conn->pending_requests);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwCifsRequest request;

      hnext = ssh_adt_enumerate_next(conn->pending_requests, h);

      request = ssh_adt_get(conn->pending_requests, h);
      SSH_ASSERT(request != NULL);

      /* We have found the correct request if all of uid, tid, pid and mid
         fields are equal. (Except that we shouldn't remove the pending
         _cancel_ request itself) */
      if ((request != cancel_req) &&
          (request->uid == cancel_req->uid) &&
          (request->tid == cancel_req->tid) &&
          (request->pid == cancel_req->pid) &&
          (request->mid == cancel_req->mid))
        {
          return request;
        }
    }

  SSH_DEBUG(SSH_D_ERROR, ("Canceled request not found!"));

  return NULL;
}


SshAppgwCifsRequest
ssh_appgw_cifs_pending_request_lookup(SshAppgwCifsConn conn,
                                      SshAppgwCifsParser cifs)
{
  SshADTHandle h;
  SshAppgwCifsRequestStruct  req_struct;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(conn->pending_requests != NULL);
  SSH_ASSERT(cifs != NULL);

  ssh_appgw_cifs_pending_request_init(&req_struct, conn, cifs);

  h = ssh_adt_get_handle_to_equal(conn->pending_requests, &req_struct);

  if (h != SSH_ADT_INVALID)
    return ssh_adt_get(conn->pending_requests, h);
  else
    return NULL;
}


/************************** Pending transactions ****************************/

SshAppgwCifsTransaction
ssh_appgw_cifs_transaction_allocate(SshAppgwCifsConn conn,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format)
{
  SshAppgwCifsCtx cifs_alg;
  SshAppgwCifsTransaction transaction;

  SSH_ASSERT(conn != NULL);

  cifs_alg = (SshAppgwCifsCtx)conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  if (cifs_alg->num_transactions >= SSH_APPGW_CIFS_MAX_TRANSACTIONS)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Resource limit reached. Transaction request "
                            "rejected.",
                            SSH_AUDIT_ARGUMENT_END);
      return NULL;
    }

  /* Use a pre-allocated transaction context or allocate a new one */
  if (cifs_alg->free_transactions != NULL)
    {
      transaction = cifs_alg->free_transactions;
      cifs_alg->free_transactions = transaction->next;
    }
  else
    {
      transaction = ssh_calloc(1, sizeof(*transaction));

      if (transaction != NULL)
        transaction->pre_allocated = FALSE;
    }

  if (transaction == NULL)
    return NULL;

  cifs_alg->num_transactions++;

  SSH_DEBUG(SSH_D_MY5,
            ("%lu transactions pending", cifs_alg->num_transactions));

  transaction->conn = conn;
  transaction->pipe_transaction = 0;
  transaction->dce_rpc = 0;
  transaction->first_request = 1;
  transaction->request_params_copied = 0;
  transaction->request_params_checked = 0;
  transaction->request_data_copied = 0;
  transaction->request_data_checked = 0;
  transaction->first_response = 1;
  transaction->response_params_copied = 0;
  transaction->response_params_checked = 0;
  transaction->response_data_copied = 0;
  transaction->response_data_checked = 0;
  transaction->interim_response_received = 0;
  transaction->category = 0;
  transaction->subcommand = 0;
  transaction->fid = 0;
  transaction->name_ptr = NULL;
  transaction->context = NULL;
  transaction->client.params = NULL;
  transaction->client.data = NULL;
  transaction->server.params = NULL;
  transaction->server.data = NULL;

  if (buffer_len > 0)
    {
      if (ssh_appgw_cifs_transaction_name_set(transaction,
                                              name_buffer, buffer_len,
                                              unicode_format) == FALSE)
        {
          ssh_appgw_cifs_transaction_free(transaction);
          return NULL;
        }
    }

  return transaction;
}


Boolean
ssh_appgw_cifs_transaction_name_set(SshAppgwCifsTransaction transaction,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format)
{
  size_t name_len = 0;
  SshUInt8 padding = 0;

  SSH_ASSERT(transaction != NULL);
  SSH_ASSERT(transaction->name_ptr == NULL);

  if (buffer_len > 0)
    {
      if (ssh_appgw_cifs_strlen(&name_len, &padding,
                                SSH_APPGW_CIFS_DATA_PATHNAME,
                                name_buffer, buffer_len,
                                unicode_format) == FALSE)
        return FALSE;
    }

  if (unicode_format)
    name_len = name_len/2;

  if (name_len < sizeof(transaction->name))
    transaction->name_ptr = transaction->name;
  else
    {
      transaction->name_ptr = ssh_calloc(1, name_len+1);

      if (transaction->name_ptr == NULL)
        return FALSE;
    }

  if (name_len > 0)
    {
      if (unicode_format)
        {
          SshAppgwCifsCtx cifs_ctx;

          cifs_ctx = (SshAppgwCifsCtx)transaction->conn->ctx->user_context;

          name_len = ssh_charset_convert(cifs_ctx->unicode_to_ascii,
                                         (char *)name_buffer + padding,
                                         name_len * 2,
                                         transaction->name_ptr, name_len);
        }
      else
        {
          memcpy(transaction->name_ptr, name_buffer, name_len);
        }
    }

  transaction->name_ptr[name_len] = 0x00;

  return TRUE;
}


SshAppgwCifsTransaction
ssh_appgw_cifs_transaction_lookup(SshAppgwCifsConn conn,
                                  SshAppgwCifsParser cifs)
{
  SshAppgwCifsRequest request;

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(cifs != NULL);

  if (cifs->response)
    request = cifs->orig_request;
  else
    {
      SshAppgwCifsCmdType cmd = cifs->command;

      /* If this is secondary transaction request, we have to find the
         pending request, which began the transaction */
      switch (cifs->command)
        {
        case SSH_SMB_COM_TRANSACTION_SECONDARY:
          cifs->command = SSH_SMB_COM_TRANSACTION;
          break;

        case SSH_SMB_COM_TRANSACTION2_SECONDARY:
          cifs->command = SSH_SMB_COM_TRANSACTION2;
          break;

        case SSH_SMB_COM_NT_TRANSACTION_SECONDARY:
          cifs->command = SSH_SMB_COM_NT_TRANSACTION;
          break;

        default:
          break;
        }

      request = ssh_appgw_cifs_pending_request_lookup(conn, cifs);

      cifs->command = cmd;
    }

  if (request)
    {
      SSH_ASSERT(request->cmd_ctx != NULL);

      return ((SshAppgwCifsTransaction)request->cmd_ctx->context);
    }
  else
    return NULL;
}


void
ssh_appgw_cifs_transaction_free(SshAppgwCifsTransaction transaction)
{
  SshAppgwCifsCtx cifs_alg;

  SSH_ASSERT(transaction != NULL);
  SSH_ASSERT(transaction->conn != NULL);
  SSH_ASSERT(transaction->conn->ctx != NULL);

  cifs_alg = (SshAppgwCifsCtx)transaction->conn->ctx->user_context;
  SSH_ASSERT(cifs_alg != NULL);

  if (transaction->dce_rpc)
    {
      SshDceRpcPDU pdu = transaction->context;

      if (pdu != NULL)
        ssh_dce_rpc_pdu_free(pdu);

      transaction->context = NULL;
    }

  if (transaction->request_params_copied)
    ssh_free(transaction->client.params);
  transaction->client.params = NULL;

  if (transaction->request_data_copied)
    ssh_free(transaction->client.data);
  transaction->client.data = NULL;

  if (transaction->response_params_copied)
    ssh_free(transaction->server.params);
  transaction->server.params = NULL;

  if (transaction->response_data_copied)
    ssh_free(transaction->server.data);
  transaction->server.data = NULL;

  if ((transaction->name_ptr != NULL) &&
      (transaction->name_ptr != transaction->name))
    {
      ssh_free(transaction->name_ptr);
      transaction->name_ptr = NULL;
    }

  if (transaction->context != NULL)
    {
      ssh_free(transaction->context);
      transaction->context = NULL;
    }

  if (transaction->pre_allocated)
    {
      transaction->next = cifs_alg->free_transactions;
      cifs_alg->free_transactions = transaction;
    }
  else
    ssh_free(transaction);

  cifs_alg->num_transactions--;

  SSH_DEBUG(SSH_D_MY5, ("Transaction destroyed (%lu remaining)",
            cifs_alg->num_transactions));
}


static void
ssh_appgw_cifs_io_buffer_align(SshAppgwCifsIO io)
{
  SSH_ASSERT(io->header_len <= 8);

  io->buf = io->_unaligned_buffer;

  /* This forces the beginning of SMB header to be aligned at 8 byte
     boundary */
  while ((unsigned long)(io->buf + io->header_len) % 8)
    io->buf++;
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_io_st_read)
{
  SshAppgwCifsCtx cifs_ctx = (SshAppgwCifsCtx) fsm_context;
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  int read;

  /* Check whether this thread should terminate. */
  if ((cifs_ctx->shutdown) || (io->terminate))
    {
      ssh_stream_output_eof(io->dst);
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Check that this is a valid read request */
  SSH_ASSERT((io->bytes_to_read + io->data_in_buf)
                                          <= SSH_APPGW_CIFS_MAX_PACKET_SIZE);

  while (io->bytes_to_read)
    {
      /* Read some data. */
      read = ssh_stream_read(io->src, io->buf + io->data_in_buf,
                             io->bytes_to_read);

      if (read < 0)
        {
          /* We would block.  Check if we should terminate. */
          if (io->terminate)
            {
              /** Connection closed. */
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_terminate);
              return SSH_FSM_CONTINUE;
            }

          /* Wait for more input. */
          return SSH_FSM_SUSPENDED;
        }
      else if (read == 0)
        {
          /** EOF. */
          /* Signal that we won't write any more data. */
          ssh_stream_output_eof(io->dst);
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          io->data_in_buf += read;
          io->bytes_to_read -= read;
        }
    }

  SSH_FSM_SET_NEXT(io->read_complete_step);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_io_st_drop)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                    ("Packet dropped! (size = %u bytes)", io->data_in_buf),
                    io->buf, io->data_in_buf);

  io->bufpos = 0;
  io->data_in_buf = 0;

  SSH_FSM_SET_NEXT(io->first_step);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_io_st_pass)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Packet passed!"));

  io->target_stream = io->dst;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_write);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_io_st_write_to_src)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;

  io->target_stream = io->src;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet injected!"));

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_write);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_io_st_write)
{
  SshAppgwCifsCtx cifs_ctx = (SshAppgwCifsCtx) fsm_context;
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  int wrote;

  SSH_ASSERT(io->data_in_buf);
  SSH_ASSERT(io->bufpos < io->data_in_buf);

  /* First, check whether this thread should terminate. */
  if (cifs_ctx->shutdown || io->terminate)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Write as much as possible. */
  while (io->bufpos < io->data_in_buf)
    {
      wrote = ssh_stream_write(io->target_stream, io->buf + io->bufpos,
                               io->data_in_buf - io->bufpos);
      if (wrote < 0)
        {
          /* We would block.  Wait until we can write more data. */
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          /** Write failed. */
          SSH_DEBUG(SSH_D_LOWOK,("write failed.. pipe closed"));
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          io->bufpos += wrote;
        }
    }

  SSH_ASSERT(io->bufpos >= io->data_in_buf);
  io->bufpos = 0;
  io->data_in_buf = 0;

  SSH_FSM_SET_NEXT(io->first_step);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_io_st_terminate)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;

  /* This thread is finished. */
  io->active = 0;

  /* Check if we were the last thread in the connection. */
  if (!conn->io_i.active && !conn->io_r.active)
    {
      /* Yes we were.  Let's register a timeout to destroy the
         connection object. */
      ssh_xregister_timeout(0, 0,
                            ssh_appgw_cifs_connection_terminate,
                            conn);
    }
  else
    {
      /* Let's notify our peer thread. */
      conn->io_i.terminate = 1;
      conn->io_r.terminate = 1;

      if (conn->io_i.active)
        ssh_fsm_continue(&conn->thread_i);
      if (conn->io_r.active)
        ssh_fsm_continue(&conn->thread_r);
    }

  /* Terminate this thread. */
  return SSH_FSM_FINISH;
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_cifs_conn_cb(SshAppgwContext ctx,
                       SshAppgwAction action,
                       const unsigned char *udp_data,
                       size_t udp_len,
                       void *context)
{
  SshAppgwCifsCtx cifs_ctx = (SshAppgwCifsCtx) context;
  SshAppgwCifsConn conn;

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("New configuration data for service %u:",
                         (unsigned int) ctx->service_id),
                        ctx->config_data, ctx->config_data_len);
      break;

    case SSH_APPGW_SHUTDOWN:
      cifs_ctx->shutdown = 1;

      if (cifs_ctx->connections)
        {
          /* We have active connections so let's notify them about the
              shutdown.  They will terminate after they receive the
              notification. */
          for (conn = cifs_ctx->connections; conn; conn = conn->next)
            {
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      else
        {
          /* Shutdown immediately. */
          ssh_appgw_cifs_destroy(cifs_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      /* Create a new connection. */
      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate Common Internet File System "
                     "connection"));
          ssh_appgw_done(ctx);
          return;
        }

      conn->pending_requests = ssh_adt_create_generic(
                SSH_ADT_BAG,

                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshAppgwCifsRequestStruct, adt_header),

                SSH_ADT_HASH,    ssh_appgw_cifs_request_hash,
                SSH_ADT_COMPARE, ssh_appgw_cifs_request_compare,
                SSH_ADT_DESTROY, ssh_appgw_cifs_request_destroy,

                SSH_ADT_ARGS_END);

      conn->open_handles = ssh_adt_create_generic(
                SSH_ADT_BAG,

                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshAppgwCifsHandleStruct, adt_header),

                SSH_ADT_HASH,    ssh_appgw_cifs_handle_hash,
                SSH_ADT_COMPARE, ssh_appgw_cifs_handle_compare,
                SSH_ADT_DESTROY, ssh_appgw_cifs_handle_destroy,
                SSH_ADT_CONTEXT, conn,

                SSH_ADT_ARGS_END);

      conn->connected_trees = ssh_adt_create_generic(
                SSH_ADT_BAG,

                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshAppgwCifsTreeStruct, adt_header),

                SSH_ADT_HASH,    ssh_appgw_cifs_tree_hash,
                SSH_ADT_COMPARE, ssh_appgw_cifs_tree_compare,
                SSH_ADT_DESTROY, ssh_appgw_cifs_tree_destroy,
                SSH_ADT_CONTEXT, conn,

                SSH_ADT_ARGS_END);

      conn->active_sessions = ssh_adt_create_generic(
                SSH_ADT_BAG,

                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshAppgwCifsSessionStruct, adt_header),

                SSH_ADT_HASH,    ssh_appgw_cifs_session_hash,
                SSH_ADT_COMPARE, ssh_appgw_cifs_session_compare,
                SSH_ADT_DESTROY, ssh_appgw_cifs_session_destroy,
                SSH_ADT_CONTEXT, conn,

                SSH_ADT_ARGS_END);

      if ((conn->pending_requests == NULL) ||
          (conn->connected_trees == NULL) ||
          (conn->active_sessions == NULL))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not create ADT bag"));

          if (conn->pending_requests)
            ssh_adt_destroy(conn->pending_requests);

          if (conn->connected_trees)
            ssh_adt_destroy(conn->connected_trees);

          if (conn->active_sessions)
            ssh_adt_destroy(conn->active_sessions);

          ssh_free(conn);
          ssh_appgw_done(ctx);
          return;
        }

      switch (ctx->responder_port)
        {
        case SSH_APPGW_CIFS_NBT_SERVER_PORT:
          conn->transport_type = SSH_APPGW_CIFS_TRANSPORT_NBT;
          conn->transport_name
            = (const unsigned char *)"NetBIOS over TCP/IP Session Service";
          conn->io_i.header_len = SSH_APPGW_CIFS_NBT_HEADER_LEN;
          conn->io_i.cifs_parser.transport.nbt.packet_length = 0;
          conn->io_i.first_step = ssh_appgw_cifs_nbt_st_read_header;

          conn->transport.nbt.session_phase
            = SSH_APPGW_NBT_SESSION_ESTABLISHMENT;
          break;

        case SSH_APPGW_CIFS_MSDS_SERVER_PORT:
          conn->transport_type = SSH_APPGW_CIFS_TRANSPORT_MSDS;
          conn->transport_name = (const unsigned char *)"MS-DS";
          conn->io_i.header_len = SSH_APPGW_CIFS_MSDS_HEADER_LEN;
          conn->io_i.cifs_parser.transport.msds.packet_length = 0;
          conn->io_i.first_step = ssh_appgw_cifs_msds_st_read_header;
          break;

        default:
          SSH_DEBUG(SSH_D_ERROR,
                    ("CIFS: Unsupported server port %d!",
                    ctx->responder_port));

          ssh_adt_destroy(conn->pending_requests);
          ssh_adt_destroy(conn->open_handles);
          ssh_adt_destroy(conn->connected_trees);
          ssh_adt_destroy(conn->active_sessions);
          ssh_free(conn);
          ssh_appgw_done(ctx);
          return;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &ctx->initiator_ip_after_nat,
                 ctx->initiator_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &ctx->responder_ip_after_nat,
                 ctx->responder_port));

      conn->max_buffer_size
        = (SshUInt16)(SSH_APPGW_CIFS_MAX_PACKET_SIZE - conn->io_i.header_len);
      conn->max_pending_requests = 1;
      conn->max_sessions = 1;
      conn->cifs_version = SSH_APPGW_CIFS_VERSION_PC_NW;
      conn->session_phase = SSH_APPGW_CIFS_SESSION_CLOSED;
      conn->user_level_security = 0;
      conn->use_challenge_response = 0;
      conn->use_encrypted_passwords = 1;
      conn->security_signatures_enabled = 0;
      conn->security_signatures_required = 0;

      conn->client_flags.nt_smbs = 0;
      conn->client_flags.large_files = 0;
      conn->client_flags.nt_error_codes = 0;
      conn->client_flags.unicode = 0;

      conn->server_flags.nt_smbs = 0;
      conn->server_flags.large_files = 0;
      conn->server_flags.rpc = 0;
      conn->server_flags.ext_security = 0;
      conn->server_flags.nt_error_codes = 0;
      conn->server_flags.unicode = 0;
      conn->server_flags.caseless_pahtnames = 0;
      conn->server_flags.long_filenames = 0;

      /* Link connection to the gateway's list of active
         connections. */
      conn->next = cifs_ctx->connections;
      if (cifs_ctx->connections)
        cifs_ctx->connections->prev = conn;
      cifs_ctx->connections = conn;

      /* Store application level gateway framework's context. */
      conn->ctx = ctx;

      /* Store application gateway context into SshAppgwContext's
         `user_context'. */
      ctx->user_context = cifs_ctx;

      /* Set stream callbacks. */
      ssh_stream_set_callback(conn->ctx->initiator_stream,
                              ssh_appgw_cifs_stream_cb, conn);
      ssh_stream_set_callback(conn->ctx->responder_stream,
                              ssh_appgw_cifs_stream_cb, conn);

      /* Setup I/O threads. */
      conn->io_r = conn->io_i;

      ssh_appgw_cifs_io_buffer_align(&conn->io_i);
      conn->io_i.active = 1;
      conn->io_i.cifs_parser.client = 1;
      conn->io_i.src = conn->ctx->initiator_stream;
      conn->io_i.dst = conn->ctx->responder_stream;
      conn->io_i.conn = conn;

      ssh_fsm_thread_init(&cifs_ctx->fsm, &conn->thread_i,
                          conn->io_i.first_step,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_i);

      ssh_appgw_cifs_io_buffer_align(&conn->io_r);
      conn->io_r.active = 1;
      conn->io_r.cifs_parser.client = 0;
      conn->io_r.src = conn->ctx->responder_stream;
      conn->io_r.dst = conn->ctx->initiator_stream;
      conn->io_r.conn = conn;

      ssh_fsm_thread_init(&cifs_ctx->fsm, &conn->thread_r,
                          conn->io_r.first_step,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_r);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_FLOW_INVALID:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow invalid"));
      break;
    }
}

static void
ssh_appgw_cifs_stream_cb(SshStreamNotification notification,
                         void *context)
{
  SshAppgwCifsConn conn = (SshAppgwCifsConn) context;

  /* Simply continue all active threads. */
  if (conn->io_i.active)
    ssh_fsm_continue(&conn->thread_i);
  if (conn->io_r.active)
    ssh_fsm_continue(&conn->thread_r);
}

static void
ssh_appgw_cifs_connection_terminate(void *context)
{
  SshAppgwCifsConn conn = (SshAppgwCifsConn) context;
  SshAppgwCifsCtx cifs_ctx;

  ssh_stream_set_callback(conn->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(conn->ctx->responder_stream, NULL_FNPTR, NULL);

  ssh_adt_destroy(conn->pending_requests);
  ssh_adt_destroy(conn->open_handles);
  ssh_adt_destroy(conn->connected_trees);
  ssh_adt_destroy(conn->active_sessions);

  /* Get application gateway context. */
  cifs_ctx = (SshAppgwCifsCtx) conn->ctx->user_context;
  conn->ctx->user_context = NULL;

  ssh_appgw_done(conn->ctx);

  /* Remove us from the application gateway's list of connections. */

  if (conn->next)
    conn->next->prev = conn->prev;

  if (conn->prev)
    conn->prev->next = conn->next;
  else
    cifs_ctx->connections = conn->next;

  /* Free our connection structure. */
  ssh_free(conn);

  if (cifs_ctx->shutdown && cifs_ctx->connections == NULL)
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway. */
    ssh_appgw_cifs_destroy(cifs_ctx);
}


static void
ssh_appgw_cifs_destroy_cb(void *context)
{
  SshAppgwCifsCtx ctx = (SshAppgwCifsCtx) context;

  ssh_fsm_uninit(&ctx->fsm);

  if (ctx->registered)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_CIFS_NAME);

      ssh_appgw_unregister_local(ctx->pm,
                                 SSH_APPGW_CIFS_IDENT,
                                 SSH_APPGW_CIFS_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  ssh_charset_free(ctx->unicode_to_ascii);
  ssh_free(ctx);
}


static void
ssh_appgw_cifs_destroy(SshAppgwCifsCtx ctx)
{
  /* Register a zero-timeout to destroy the application gateway instance.
     This is needed since this function is called also from thread
     destructors and the FSM library needs to access the FSM context that
     will be destroyed when the context is freed. */
  ssh_xregister_timeout(0, 0, ssh_appgw_cifs_destroy_cb, ctx);
}


static void
ssh_appgw_cifs_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwCifsCtx ctx = (SshAppgwCifsCtx) context;

  if (error != SSH_APPGW_ERROR_OK)
    {
      char *why;

      switch (error)
        {
        case SSH_APPGW_ERROR_OK:
          why = "ok";
          break;

        case SSH_APPGW_ERROR_TOOMANY:
          why = "too many";
          break;

        case SSH_APPGW_ERROR_NOTFOUND:
          why = "not found";
          break;

        case SSH_APPGW_ERROR_VERSION:
          why = "invalid version";
          break;

        case SSH_APPGW_ERROR_PROTOVERSION:
          why = "invalid protocol version";
          break;

        default:
          why = "unknown reason";
          break;
        }

      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not start application gateway: "
                    "registration failed: %s.",
                    SSH_APPGW_CIFS_NAME, why);

      ssh_appgw_cifs_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.",
                SSH_APPGW_CIFS_NAME);

  ctx->registered = 1;
}


void
ssh_appgw_cifs_init(SshPm pm)
{
  SshAppgwCifsCtx ctx;
  unsigned int i;
  SshAppgwParamsStruct params;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not create application gateway: "
                    "out of memory.",
                    SSH_APPGW_CIFS_NAME);
      return;
    }

  ctx->unicode_to_ascii = ssh_charset_init(SSH_CHARSET_UNICODE16_LBO,
                                           SSH_CHARSET_ISO_LATIN_1);
  if (ctx->unicode_to_ascii == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not create application gateway: "
                    "initialization failed.",
                    SSH_APPGW_CIFS_NAME);

      ssh_free(ctx);
      return;
    }

  /* Initialize pre-allocated contexts */
  ctx->free_requests = NULL;
  for (i = 0; i < SSH_APPGW_CIFS_PREALLOC_REQUESTS; i++)
    {
      ctx->preallocated_requests[i].pre_allocated = 1;
      ctx->preallocated_requests[i].next = ctx->free_requests;

      ctx->free_requests = &ctx->preallocated_requests[i];
    }

  ctx->free_transactions = NULL;
  for (i = 0; i < SSH_APPGW_CIFS_PREALLOC_TRANSACTIONS; i++)
    {
      ctx->preallocated_transactions[i].pre_allocated = 1;
      ctx->preallocated_transactions[i].next = ctx->free_transactions;

      ctx->free_transactions = &ctx->preallocated_transactions[i];
    }

  ctx->free_cmd_ctxs = NULL;
  for (i = 0; i < SSH_APPGW_CIFS_PREALLOC_REQUESTS; i++)
    {
      ctx->preallocated_ctx_slots[i].pre_allocated = 1;
      ctx->preallocated_ctx_slots[i].next = ctx->free_cmd_ctxs;

      ctx->free_cmd_ctxs = &ctx->preallocated_ctx_slots[i];
    }

  ctx->pm = pm;
  ctx->num_requests = 0;
  ctx->num_transactions = 0;
  ssh_fsm_init(&ctx->fsm, ctx);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_CIFS_IDENT;
  params.printable_name = "Common Internet File System";
  params.version = SSH_APPGW_CIFS_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;

  ssh_appgw_register_local(ctx->pm,
                           &params,
                           0,
                           ssh_appgw_cifs_conn_cb, ctx,
                           ssh_appgw_cifs_reg_cb, ctx);
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
