/*
 *
 * dce_rpc_pdu.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Decoding of DCE/RPC protocol data units (PDUs). Currently only the
 * connection-oriented PDUs are supported.
 *
 *
 * References:
 *
 *   Open Group: DCE 1.1: Remote Procedure Call (Document Number C706)
 *   (www.opengroup.org/onlinepubs/9629399)
 *
 *
 */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshgetput.h"
#include "dce_rpc_pdu.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshDCERPC"

/* All connection-oriented DCE/RPC PDUs have 16 byte header */
#define SSH_DCE_RPC_CO_FIXED_HEADER_LEN   16

/* Eight byte header exists before the actual authentication data */
#define SSH_DCE_RPC_AUTH_HEADER_LEN       8

/* Checks whether the memory allocation succeeded */
#define SSH_DCE_RPC_DECODE_ALLOC_CHECK(ptr)                                 \
do                                                                          \
{                                                                           \
  if (ptr == NULL)                                                          \
    {                                                                       \
      SSH_DEBUG(SSH_D_FAIL, ("Not enough memory to decode DCE/RPC PDU!"));  \
      return FALSE;                                                         \
    }                                                                       \
}                                                                           \
while (0);


/* Restores the correct alignement by skipping padding bytes when needed */
#define SSH_DCE_RPC_BUFF_ALIGN_RESTORE(buf,alignment)                    \
do                                                                       \
{                                                                        \
  unsigned long __ptr = (unsigned long) ((buf)->buffer);                 \
  SshUInt8 __pad = (SshUInt8) (__ptr % (alignment));                     \
  if (__pad != 0)                                                        \
    {                                                                    \
      __pad = (SshUInt8)((alignment) - __pad);                           \
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, __pad);                            \
      SSH_DCE_RPC_BUFF_CONSUME(buf, __pad);                              \
    }                                                                    \
}                                                                        \
while (0);


/* Checks that the buffer contains enough data */
#define SSH_DCE_RPC_BUFF_LEN_CHECK(buf,required)                      \
do                                                                    \
{                                                                     \
  if ((buf)->size < (required))                                       \
    {                                                                 \
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid (too short) DCE/RPC PDU!")); \
      return FALSE;                                                   \
    }                                                                 \
}                                                                     \
while (0);

#define SSH_DCE_RPC_BUFF_CONSUME(buf,bytes)       \
do                                                \
{                                                 \
  (buf)->buffer += (bytes);                       \
  (buf)->size -= (bytes);                         \
}                                                 \
while (0);


#define SSH_DCE_RPC_BUFF_GET_8BIT(ptr, buf)       \
do                                                \
{                                                 \
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, 1);             \
  *(ptr) = SSH_GET_8BIT((buf)->buffer);           \
  SSH_DCE_RPC_BUFF_CONSUME(buf, 1);               \
}                                                 \
while (0);


#define SSH_DCE_RPC_BUFF_GET_16BIT(ptr, buf, byte_order)    \
do                                                          \
{                                                           \
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, 2);                       \
  if ((byte_order) == SSH_DCE_RPC_LITTLE_ENDIAN)            \
    *(ptr) = SSH_GET_16BIT_LSB_FIRST((buf)->buffer);        \
  else                                                      \
    *(ptr) = SSH_GET_16BIT((buf)->buffer);                  \
  SSH_DCE_RPC_BUFF_CONSUME(buf, 2);                         \
}                                                           \
while (0);


#define SSH_DCE_RPC_BUFF_GET_32BIT(ptr, buf, byte_order)           \
do                                                                 \
{                                                                  \
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, 4);                              \
  if ((byte_order) == SSH_DCE_RPC_LITTLE_ENDIAN)                   \
    *(ptr) = SSH_GET_32BIT_LSB_FIRST((const char *)(buf)->buffer); \
  else                                                             \
    *(ptr) = SSH_GET_32BIT((const char *)(buf)->buffer);           \
  SSH_DCE_RPC_BUFF_CONSUME(buf, 4);                                \
}                                                                  \
while (0);


/*************************** Static help functions **************************/

#ifdef DEBUG_LIGHT
static const char *
ssh_dce_rpc_packet_type_to_str(SshDceRpcPDUType type)
{
  switch (type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
      return (const char *)"REQUEST";
    case SSH_DCE_RPC_PDU_PING:
      return (const char *)"PING";
    case SSH_DCE_RPC_PDU_RESPONSE:
      return (const char *)"RESPONSE";
    case SSH_DCE_RPC_PDU_FAULT:
      return (const char *)"FAULT";
    case SSH_DCE_RPC_PDU_WORKING:
      return (const char *)"WORKING";
    case SSH_DCE_RPC_PDU_NOCALL:
      return (const char *)"NOCALL";
    case SSH_DCE_RPC_PDU_REJECT:
      return (const char *)"REJECT";
    case SSH_DCE_RPC_PDU_ACK:
      return (const char *)"ACK";
    case SSH_DCE_RPC_PDU_CL_CANCEL:
      return (const char *)"CL_CANCEL";
    case SSH_DCE_RPC_PDU_FACK:
      return (const char *)"FACK";
    case SSH_DCE_RPC_PDU_CANCEL_ACK:
      return (const char *)"CANCEL_ACK";
    case SSH_DCE_RPC_PDU_BIND:
      return (const char *)"BIND";
    case SSH_DCE_RPC_PDU_BIND_ACK:
      return (const char *)"BIND_ACK";
    case SSH_DCE_RPC_PDU_BIND_NAK:
      return (const char *)"BIND_NAK";
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
      return (const char *)"ALTER_CONTEXT";
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
      return (const char *)"ALTER_CONTEXT_RESP";
    case SSH_DCE_RPC_PDU_AUTH3:
      return (const char *)"AUTH3";
    case SSH_DCE_RPC_PDU_SHUTDOWN:
      return (const char *)"SHUTDOWN";
    case SSH_DCE_RPC_PDU_CO_CANCEL:
      return (const char *)"CO_CANCEL";
    case SSH_DCE_RPC_PDU_ORPHANED:
      return (const char *)"ORPHANED";
    default:
      return (const char *)"<Unknown>";
    }
}
#endif /* DEBUG_LIGHT */


/* Decodes an UUID (Universally Unique IDentifier) field */
static Boolean
ssh_dce_rpc_uuid_decode(SshDceRpcUUID id,
                        SshDceRpcDataBuffer buf,
                        SshUInt8 byte_order)
{
  SSH_ASSERT(id != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DCE_RPC_BUFF_GET_32BIT(&(id->data1), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(id->data2), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(id->data3), buf, byte_order);
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, 8);
  memcpy(id->data4, buf->buffer, 8);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 8);

  SSH_DEBUG(SSH_D_DATADUMP,
            ("UUID = %08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
	     (unsigned long) id->data1,
	     id->data2, id->data3,
	     id->data4[0], id->data4[1],
	     id->data4[2], id->data4[3], id->data4[4],
	     id->data4[5], id->data4[6], id->data4[7]));

  return TRUE;
}



/* Decodes a DCE/RPC syntax ID */
static Boolean
ssh_dce_rpc_syntax_id_decode(SshDceRpcSyntaxID syntax,
                             SshDceRpcDataBuffer buf,
                             SshUInt8 byte_order)
{
#ifdef DEBUG_LIGHT
  SshUInt16 major;
  SshUInt16 minor;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(syntax != NULL);
  SSH_ASSERT(buf != NULL);

  if (ssh_dce_rpc_uuid_decode(&(syntax->if_uuid),
                              buf, byte_order) == FALSE)
    return FALSE;

  SSH_DCE_RPC_BUFF_GET_32BIT(&(syntax->if_version), buf, byte_order);

#ifdef DEBUG_LIGHT
  major = (SshUInt16)(syntax->if_version & 0x0000FFFF);
  minor = (SshUInt16)(syntax->if_version >> 16);

  SSH_DEBUG(SSH_D_DATADUMP,
            ("if_version: [major=%u, minor=%u]", major, minor));
#endif /* DEBUG_LIGHT */

  return TRUE;
}


/* Decodes a negotiation context list */
static Boolean
ssh_dce_rpc_context_list_decode(SshDceRpcContextList list,
                                SshDceRpcDataBuffer buf,
                                SshUInt8 byte_order)
{
  SshDceRpcContext prev = NULL;
  SshUInt8 i;

  SSH_ASSERT(list != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DCE_RPC_BUFF_ALIGN_RESTORE(buf, 4);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(list->items), buf);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 3); /* skip three bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("number of contexts = %u", list->items));

  /* We have an empty list */
  if (list->items == 0)
    return TRUE;

  for (i = 0; i < list->items; i++)
    {
      SshDceRpcContext context;
      SshUInt16 context_id;
      SshUInt8  items;
      SshUInt16 buff_needed;
      SshUInt8 j;

      SSH_DCE_RPC_BUFF_GET_16BIT(&context_id, buf, byte_order);
      SSH_DCE_RPC_BUFF_GET_8BIT(&items, buf);
      SSH_DCE_RPC_BUFF_CONSUME(buf, 1); /* skip one byte */

      SSH_DEBUG(SSH_D_DATADUMP, ("context_id = %u", context_id));
      SSH_DEBUG(SSH_D_DATADUMP, ("transfer_syntaxes = %u", items));

      /* There must be one "abstract_syntax" and specified number of
         transfer syntaxes */
      buff_needed = (SshUInt16)((items + 1) * (16 + 4));
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, buff_needed);

      context = ssh_calloc(1, sizeof(*context));
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(context);

      if (prev == NULL)
        list->list = context;
      else
        prev->next = context;

      context->context_id = context_id;
      context->number_of_syntaxes = items;

      context->transfer_syntaxes
        = ssh_calloc(items, sizeof(*(context->transfer_syntaxes)));
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(context->transfer_syntaxes);

      for (j = 0; j <= items; j++)
        {
          SshDceRpcSyntaxID syntax;

          if (j == 0)
            {
              SSH_DEBUG(SSH_D_DATADUMP, ("Abstract syntax:"));

              syntax = &(context->abstract_syntax);
            }
          else
            {
              SSH_DEBUG(SSH_D_DATADUMP, ("Transfer syntax %u:", j));

              syntax = &(context->transfer_syntaxes[j-1]);
            }

          if (ssh_dce_rpc_syntax_id_decode(syntax, buf,
                                           byte_order) == FALSE)
            return FALSE;
        }

      prev = context;
    }

  return TRUE;
}


/* Decodes a context negotiation result list */
static Boolean
ssh_dce_rpc_result_list_decode(SshDceRpcResultList list,
                               SshDceRpcDataBuffer buf,
                               SshUInt8 byte_order)
{
  SshUInt8 i;

  SSH_DCE_RPC_BUFF_ALIGN_RESTORE(buf, 4);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(list->items), buf);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 3); /* skip three bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("number of results = %u", list->items));

  /* We have an empty list */
  if (list->items == 0)
    return TRUE;

  list->list = ssh_calloc(list->items, sizeof(*list->list));
  SSH_DCE_RPC_DECODE_ALLOC_CHECK(list->list);

  for (i = 0; i < list->items; i++)
    {
      SSH_DCE_RPC_BUFF_GET_16BIT(&(list->list[i].result), buf, byte_order);
      SSH_DCE_RPC_BUFF_GET_16BIT(&(list->list[i].reason), buf, byte_order);

      if (ssh_dce_rpc_syntax_id_decode(&list->list[i].transfer_syntax,
                                       buf, byte_order) == FALSE)
        return FALSE;
    }

  return TRUE;
}



/* Decodes the DCE/RPC protocol version list */
static Boolean
ssh_dce_rpc_version_list_decode(SshDceRpcVersionList list,
                                SshDceRpcDataBuffer buf,
                                SshUInt8 byte_order)
{
  SSH_DCE_RPC_BUFF_ALIGN_RESTORE(buf, 4);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(list->items), buf);

  if (list->items > 0)
    {
      SshUInt8 i;

      list->list = ssh_calloc(list->items, sizeof(*list->list));
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(list->list);

      for (i = 0; i < list->items; i++)
        {
          SSH_DCE_RPC_BUFF_GET_8BIT(&(list->list[i].major_version), buf);
          SSH_DCE_RPC_BUFF_GET_8BIT(&(list->list[i].minor_version), buf);
        }
    }

  return TRUE;
}


/* Decodes the DCE/RPC secondary address field */
static Boolean
ssh_dce_rpc_sec_addr_decode(SshDceRpcDataBuffer addr,
                            SshDceRpcDataBuffer buf,
                            SshUInt8 byte_order)
{
  SSH_DCE_RPC_BUFF_GET_16BIT(&(addr->size), buf, byte_order);

  SSH_DEBUG(SSH_D_DATADUMP, ("size of secondary address = %u", addr->size));

  if (addr->size > 0)
    {
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, addr->size);

      addr->buffer = ssh_calloc(1, addr->size);
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(addr->buffer);

      memcpy(addr->buffer, buf->buffer, addr->size);
      SSH_DCE_RPC_BUFF_CONSUME(buf, addr->size);

      if (addr->buffer[addr->size-1] != 0)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Secondary address not NULL-terminated!"));
          return FALSE;
        }

      SSH_DEBUG(SSH_D_DATADUMP, ("secondary address = \"%s\"", addr->buffer));
    }

  return TRUE;
}


/* Copies the "payload" of DCE/RPC PDU */
static Boolean
ssh_dce_rpc_pdu_payload_copy(SshDceRpcDataBuffer payload,
                             SshDceRpcPDU pdu,
                             SshDceRpcDataBuffer buf)
{
  payload->size = buf->size;

  if (pdu->header.auth_length != 0)
    {
      const unsigned char *auth_hdr;
      SshUInt8 padding;
      SshUInt16 total_auth_size = (SshUInt16)(pdu->header.auth_length +
                                  SSH_DCE_RPC_AUTH_HEADER_LEN);

      /* Check that we still have enough buffer left... */
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, total_auth_size);

      /* Calculate the begin address of authentication verifier */
      auth_hdr = (buf->buffer + buf->size) - total_auth_size;

      /* Now we still need to check whether there are some extra padding
         between payload and authentication verifier */
      padding = SSH_GET_8BIT(&(auth_hdr[2]));

      /* Now we can calculate the actual size of payload */
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, total_auth_size + padding);
      payload->size -= (total_auth_size + padding);
    }

  if (payload->size > 0)
    {
      SSH_DCE_RPC_BUFF_ALIGN_RESTORE(buf, 4);

      payload->buffer = ssh_malloc(payload->size);
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(payload->buffer);

      memcpy(payload->buffer, buf->buffer, payload->size);
      SSH_DCE_RPC_BUFF_CONSUME(buf, payload->size);

      SSH_DEBUG_HEXDUMP(SSH_D_MY1, ("PDU payload (%u bytes):", payload->size),
                        payload->buffer, payload->size);
    }

  return TRUE;
}


/* Decodes the DCE/RPC authentication verifier field */
static Boolean
ssh_dce_rpc_auth_verifier_decode(SshDceRpcAuthVerifier verifier,
                                 SshDceRpcDataBuffer buf,
                                 SshUInt8 byte_order)
{
  const unsigned char *orig_ptr = buf->buffer;
  const unsigned char *auth_hdr;
  SshUInt16 total_auth_size;
  SshUInt8 offset;
  SshUInt8 pad_len;

  /* Check whether this PDU contains authentication verifier. */
  if (verifier->length == 0)
    return TRUE;

  total_auth_size = (SshUInt16)(verifier->length +
                                SSH_DCE_RPC_AUTH_HEADER_LEN);

  /* Check that we still have enough buffer left... */
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, total_auth_size);

  /* Calculate the begin address of authentication verifier */
  auth_hdr = (buf->buffer + buf->size) - total_auth_size;

  /* Now we still need to check whether there are some extra padding
     between payload and authentication verifier */
  pad_len = SSH_GET_8BIT(&(auth_hdr[2]));

  SSH_DCE_RPC_BUFF_CONSUME(buf, pad_len);
  offset = (SshUInt8)(buf->buffer - orig_ptr);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(verifier->type), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(verifier->level), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&pad_len, buf);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 1); /* Skip one byte */
  SSH_DCE_RPC_BUFF_GET_32BIT(&verifier->context_id, buf, byte_order);

  SSH_DEBUG(SSH_D_DATADUMP, ("auth_type = %u", verifier->type));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_level = %u", verifier->level));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_pad_length = %u", pad_len));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_context_id = %lu", verifier->context_id));

  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, verifier->length);

  verifier->credentials = ssh_malloc(verifier->length);
  SSH_DCE_RPC_DECODE_ALLOC_CHECK(verifier->credentials);

  memcpy(verifier->credentials, buf->buffer, verifier->length);
  SSH_DCE_RPC_BUFF_CONSUME(buf, verifier->length);

  return TRUE;
}


/* Decodes the common header of a connection-oriented DCE/RPC PDU */
static Boolean
ssh_dce_rpc_co_pdu_header_decode(SshDceRpcPDUHeader hdr,
                                 SshDceRpcDataBuffer buf)
{
  SshUInt32 data_rep;

  SSH_ASSERT(hdr != NULL);
  SSH_ASSERT(buf != NULL);

  /* Decode common header */
  SSH_DCE_RPC_BUFF_GET_8BIT(&(hdr->major_version), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(hdr->minor_version), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(hdr->packet_type), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(hdr->pfc_flags), buf);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(data_rep), buf, SSH_DCE_RPC_BIG_ENDIAN);

  hdr->byte_order = (SshUInt8)(data_rep >> 28);
  hdr->char_set = (SshUInt8)((data_rep & 0x0F000000) >> 24);
  hdr->float_type = (SshUInt8)((data_rep & 0x00FF0000) >> 16);

  SSH_DCE_RPC_BUFF_GET_16BIT(&(hdr->frag_length), buf, hdr->byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(hdr->auth_length), buf, hdr->byte_order);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(hdr->call_id), buf, hdr->byte_order);

  SSH_DEBUG(SSH_D_DATADUMP, ("major_version = %d", hdr->major_version));
  SSH_DEBUG(SSH_D_DATADUMP, ("minor_version = %d", hdr->minor_version));
  SSH_DEBUG(SSH_D_DATADUMP, ("packet_type = %s (%d)",
            ssh_dce_rpc_packet_type_to_str(hdr->packet_type),
            hdr->packet_type));
  SSH_DEBUG(SSH_D_DATADUMP, ("pfc_flags = 0x%02X", hdr->pfc_flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("data_representation = 0x%08lX",
			     (unsigned long) data_rep));
  SSH_DEBUG(SSH_D_DATADUMP, ("length of fragment = %d", hdr->frag_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("length of auth_value = %d", hdr->auth_length));
  SSH_DEBUG(SSH_D_DATADUMP, ("call_id = %lu", hdr->call_id));

  /* Check the PDU type (accept only connection-oriented ones) */
  switch (hdr->packet_type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
    case SSH_DCE_RPC_PDU_FAULT:
    case SSH_DCE_RPC_PDU_RESPONSE:
    case SSH_DCE_RPC_PDU_BIND:
    case SSH_DCE_RPC_PDU_BIND_ACK:
    case SSH_DCE_RPC_PDU_BIND_NAK:
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
    case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
    case SSH_DCE_RPC_PDU_AUTH3:
    case SSH_DCE_RPC_PDU_SHUTDOWN:
    case SSH_DCE_RPC_PDU_CO_CANCEL:
    case SSH_DCE_RPC_PDU_ORPHANED:
      break;

    default:
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid PDU type (%d)", hdr->packet_type));
      return FALSE;
    }

  return TRUE;
}


/* Decodes PDU type specific fields of connection-oriented "REQUEST" packet */
static Boolean
ssh_dce_rpc_co_request_decode(SshDceRpcPDU pdu,
                              SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcRequest request;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  request = &(pdu->pdu.request);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_32BIT(&(request->alloc_hint), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(request->context_id), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(request->opnum), buf, byte_order);

  SSH_DEBUG(SSH_D_DATADUMP, ("alloc_hint = %lu", request->alloc_hint));
  SSH_DEBUG(SSH_D_DATADUMP, ("context_id = %u", request->context_id));
  SSH_DEBUG(SSH_D_DATADUMP, ("opnum = %u", request->opnum));

  if (pdu->header.pfc_flags & SSH_DCE_PFC_OBJECT_UUID)
    {
      request->object = ssh_calloc(1, sizeof(*(request->object)));
      if (request->object == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not decode UUID field; Out of memory"));
          return FALSE;
        }

      if (ssh_dce_rpc_uuid_decode(request->object,
                                  buf, byte_order) == FALSE)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Could not decode UUID field"));
          return FALSE;
        }
    }

  if (ssh_dce_rpc_pdu_payload_copy(&(request->data), pdu, buf) == FALSE)
    return FALSE;

  request->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(request->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of connection-oriented "RESPONSE"
   packet */
static Boolean
ssh_dce_rpc_co_response_decode(SshDceRpcPDU pdu,
                               SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcResponse response;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  response = &(pdu->pdu.response);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_32BIT(&(response->alloc_hint), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(response->context_id), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(response->cancel_count), buf);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 1); /* skip one byte */

  SSH_DEBUG(SSH_D_DATADUMP, ("alloc_hint = %lu", response->alloc_hint));
  SSH_DEBUG(SSH_D_DATADUMP, ("context_id = %u", response->context_id));
  SSH_DEBUG(SSH_D_DATADUMP, ("cancel_count = %u", response->cancel_count));

  if (ssh_dce_rpc_pdu_payload_copy(&(response->data), pdu, buf) == FALSE)
    return FALSE;

  response->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(response->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of connection-oriented "FAULT" packet */
static Boolean
ssh_dce_rpc_co_fault_decode(SshDceRpcPDU pdu,
                            SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcFault fault;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  fault = &(pdu->pdu.fault);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_32BIT(&(fault->alloc_hint), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(fault->context_id), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(fault->cancel_count), buf);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 1); /* skip one byte */
  SSH_DCE_RPC_BUFF_GET_32BIT(&(fault->status), buf, byte_order);
  SSH_DCE_RPC_BUFF_CONSUME(buf, 4); /* skip four bytes */

  SSH_DEBUG(SSH_D_DATADUMP, ("alloc_hint = %lu", fault->alloc_hint));
  SSH_DEBUG(SSH_D_DATADUMP, ("context_id = %u", fault->context_id));
  SSH_DEBUG(SSH_D_DATADUMP, ("cancel_count = %u", fault->cancel_count));
  SSH_DEBUG(SSH_D_DATADUMP, ("status = 0x%08lX",
			     (unsigned long) fault->status));

  if (ssh_dce_rpc_pdu_payload_copy(&(fault->data), pdu, buf) == FALSE)
    return FALSE;

  fault->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(fault->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of "BIND" packet */
static Boolean
ssh_dce_rpc_bind_decode(SshDceRpcPDU pdu,
                        SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcBind bind;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  bind = &(pdu->pdu.bind);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_16BIT(&(bind->max_xmit_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(bind->max_recv_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(bind->group_id), buf, byte_order);

  if (ssh_dce_rpc_context_list_decode(&(bind->context_list),
                                      buf, byte_order) == FALSE)
    return FALSE;

  bind->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(bind->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of "BIND_ACK" packet */
static Boolean
ssh_dce_rpc_bind_ack_decode(SshDceRpcPDU pdu,
                            SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcBindAck bind_ack;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  bind_ack = &(pdu->pdu.bind_ack);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_16BIT(&(bind_ack->max_xmit_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(bind_ack->max_recv_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(bind_ack->group_id), buf, byte_order);

  if (ssh_dce_rpc_sec_addr_decode(&(bind_ack->sec_addr),
                                  buf, byte_order) == FALSE)
    return FALSE;

  if (ssh_dce_rpc_result_list_decode(&(bind_ack->result_list),
                                     buf, byte_order) == FALSE)
    return FALSE;

  bind_ack->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(bind_ack->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of "BIND_NAK" packet */
static Boolean
ssh_dce_rpc_bind_nak_decode(SshDceRpcPDU pdu,
                            SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcBindNak bind_nak;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  bind_nak = &(pdu->pdu.bind_nak);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_16BIT(&(bind_nak->reject_reason), buf, byte_order);

  if (ssh_dce_rpc_version_list_decode(&(bind_nak->supported_versions),
                                      buf, byte_order))
    return TRUE;
  else
    return FALSE;
}


/* Decodes PDU type specific fields of "ALTER_CONTEXT" packet */
static Boolean
ssh_dce_rpc_alter_context_decode(SshDceRpcPDU pdu,
                                 SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcAlterCtx alter_ctx;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  alter_ctx = &(pdu->pdu.alter_ctx);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_16BIT(&(alter_ctx->max_xmit_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(alter_ctx->max_recv_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(alter_ctx->group_id), buf, byte_order);

  alter_ctx->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_context_list_decode(&(alter_ctx->context_list),
                                      buf, byte_order) == FALSE)
    return FALSE;

  alter_ctx->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(alter_ctx->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of "ALTER_CONTEXT_RESP" packet */
static Boolean
ssh_dce_rpc_alter_context_resp_decode(SshDceRpcPDU pdu,
                                      SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcAlterCtxResp ctx_resp;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  ctx_resp = &(pdu->pdu.alter_ctx_resp);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_16BIT(&(ctx_resp->max_xmit_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_16BIT(&(ctx_resp->max_recv_frag), buf, byte_order);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(ctx_resp->group_id), buf, byte_order);

  if (ssh_dce_rpc_sec_addr_decode(&(ctx_resp->sec_addr),
                                  buf, byte_order) == FALSE)
    return FALSE;

  if (ssh_dce_rpc_result_list_decode(&(ctx_resp->result_list),
                                     buf, byte_order) == FALSE)
    return FALSE;

  ctx_resp->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(ctx_resp->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes PDU type specific fields of AUTH3 packet (i.e. response to
   NTLMSSP challenges) */
static Boolean
ssh_dce_rpc_auth3_decode(SshDceRpcPDU pdu,
                         SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcAuth3 auth3;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  auth3 = &(pdu->pdu.auth3);
  byte_order = pdu->header.byte_order;

  SSH_DCE_RPC_BUFF_GET_32BIT(&(auth3->magic_number), buf, byte_order);

  SSH_DCE_RPC_BUFF_GET_8BIT(&(auth3->auth_type), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(auth3->auth_level), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(auth3->auth_pad_len), buf);
  SSH_DCE_RPC_BUFF_GET_8BIT(&(auth3->auth_reserved), buf);
  SSH_DCE_RPC_BUFF_GET_32BIT(&(auth3->auth_context_id), buf, byte_order);

  SSH_DEBUG(SSH_D_DATADUMP, ("magic_number = 0x%08lX",
			     (unsigned long) auth3->magic_number));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_type = %u", auth3->auth_type));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_level = %u", auth3->auth_level));
  SSH_DEBUG(SSH_D_DATADUMP, ("auth_pad_len = %u", auth3->auth_pad_len));
  SSH_DEBUG(SSH_D_DATADUMP, 
            ("auth_context_id = %lu", auth3->auth_context_id));

  /* Skip the padding bytes */
  SSH_DCE_RPC_BUFF_LEN_CHECK(buf, auth3->auth_pad_len);
  SSH_DCE_RPC_BUFF_CONSUME(buf, auth3->auth_pad_len);

  /* Verify and copy the authentication data */
  auth3->data.size = pdu->header.auth_length;
  if (auth3->data.size > 0)
    {
      SSH_DCE_RPC_BUFF_LEN_CHECK(buf, auth3->data.size);

      auth3->data.buffer = ssh_malloc(auth3->data.size);
      SSH_DCE_RPC_DECODE_ALLOC_CHECK(auth3->data.buffer);

      memcpy(auth3->data.buffer, buf->buffer, auth3->data.size);
      SSH_DCE_RPC_BUFF_CONSUME(buf, auth3->data.size);

      SSH_DEBUG_HEXDUMP(SSH_D_MY1, 
                        ("Authentication data (%u bytes):", auth3->data.size),
                        auth3->data.buffer, auth3->data.size);
    }

  return TRUE;
}


/* Decodes PDU type specific fields of connection-oriented "CANCEL" packet */
static Boolean
ssh_dce_rpc_co_cancel_decode(SshDceRpcPDU pdu,
                             SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcCancel cancel;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  cancel = &(pdu->pdu.cancel);
  byte_order = pdu->header.byte_order;

  cancel->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(cancel->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}



/* Decodes PDU type specific fields of "ORPHANED" packet */
static Boolean
ssh_dce_rpc_orphaned_decode(SshDceRpcPDU pdu,
                            SshDceRpcDataBuffer buf)
{
  SshUInt8 byte_order;
  SshDceRpcOrphaned orphaned;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  orphaned = &(pdu->pdu.orphaned);
  byte_order = pdu->header.byte_order;

  orphaned->verifier.length = pdu->header.auth_length;

  if (ssh_dce_rpc_auth_verifier_decode(&(orphaned->verifier),
                                       buf, byte_order) == FALSE)
    return FALSE;

  return TRUE;
}


/* Decodes connection-oriented DCE/RPC PDU */
static Boolean
ssh_dce_rpc_co_pdu_decode(SshDceRpcPDU pdu,
                          SshDceRpcDataBuffer buf)
{
  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buf != NULL);

  if (ssh_dce_rpc_co_pdu_header_decode(&pdu->header, buf) == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Could not decode DCE/RPC PDU header!"));
      return FALSE;
    }

  /* Check fragment_length */
  if (pdu->header.frag_length > (buf->size + SSH_DCE_RPC_CO_FIXED_HEADER_LEN))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Invalid fragment length %d specified in PDU header!",
		 pdu->header.frag_length));
      return FALSE;
    }

  /* Check auth_length */
  if (pdu->header.auth_length >
                 (pdu->header.frag_length - SSH_DCE_RPC_CO_FIXED_HEADER_LEN))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Invalid authentication verifier length %d specified in PDU"
                " header!", pdu->header.auth_length));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Decoding \"%s\" DCE/RPC PDU",
            ssh_dce_rpc_packet_type_to_str(pdu->header.packet_type)));

  switch (pdu->header.packet_type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
      return ssh_dce_rpc_co_request_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_RESPONSE:
      return ssh_dce_rpc_co_response_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_FAULT:
      return ssh_dce_rpc_co_fault_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_BIND:
      return ssh_dce_rpc_bind_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_BIND_ACK:
      return ssh_dce_rpc_bind_ack_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_BIND_NAK:
      return ssh_dce_rpc_bind_nak_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
      return ssh_dce_rpc_alter_context_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
      return ssh_dce_rpc_alter_context_resp_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_AUTH3:
      return ssh_dce_rpc_auth3_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_SHUTDOWN:
      /* Doesn't contain any PDU specific fields */
      return TRUE;

    case SSH_DCE_RPC_PDU_CO_CANCEL:
      return ssh_dce_rpc_co_cancel_decode(pdu, buf);

    case SSH_DCE_RPC_PDU_ORPHANED:
      return ssh_dce_rpc_orphaned_decode(pdu, buf);

    default:
      return FALSE;
    }
}


/***************** Exported DCE/RPC PDU decoding functions ******************/

/* Allocates and initializes a new (empty) DCE/RPC PDU context. */
SshDceRpcPDU
ssh_dce_rpc_pdu_allocate(void)
{
  SshDceRpcPDU pdu = ssh_malloc(sizeof(*pdu));

  if (pdu)
    ssh_dce_rpc_pdu_init(pdu);

  return pdu;
}


/* Frees a dynamically allocated DCE/RPC PDU context. */
void
ssh_dce_rpc_pdu_free(SshDceRpcPDU pdu)
{
  if (pdu == NULL)
    return;

  ssh_dce_rpc_pdu_uninit(pdu);
  ssh_free(pdu);
}


/* Initializes the given (pre-allocated) DCE/RPC PDU context */
void
ssh_dce_rpc_pdu_init(SshDceRpcPDU pdu)
{
  memset(pdu, 0x00, sizeof(*pdu));
}


/* Un-initializes the given DCE/RPC PDU context. (i.e. frees all attached
   items, but doesn't free the PDU context) */
void
ssh_dce_rpc_pdu_uninit(SshDceRpcPDU pdu)
{
  SshDceRpcContextList ctx_list = NULL;

  SSH_ASSERT(pdu != NULL);

  switch (pdu->header.packet_type)
    {
    case SSH_DCE_RPC_PDU_REQUEST:
      ssh_free(pdu->pdu.request.object);
      ssh_free(pdu->pdu.request.data.buffer);
      ssh_free(pdu->pdu.request.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_RESPONSE:
      ssh_free(pdu->pdu.response.data.buffer);
      ssh_free(pdu->pdu.response.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_FAULT:
      ssh_free(pdu->pdu.fault.data.buffer);
      ssh_free(pdu->pdu.fault.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_BIND:
      ctx_list = &(pdu->pdu.bind.context_list);
      ssh_free(pdu->pdu.bind.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_BIND_ACK:
      ssh_free(pdu->pdu.bind_ack.sec_addr.buffer);
      ssh_free(pdu->pdu.bind_ack.result_list.list);
      ssh_free(pdu->pdu.bind_ack.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_BIND_NAK:
      ssh_free(pdu->pdu.bind_nak.supported_versions.list);
      break;

    case SSH_DCE_RPC_PDU_ALTER_CONTEXT:
      ctx_list = &(pdu->pdu.alter_ctx.context_list);
      ssh_free(pdu->pdu.alter_ctx.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP:
      ssh_free(pdu->pdu.alter_ctx_resp.sec_addr.buffer);
      ssh_free(pdu->pdu.alter_ctx_resp.result_list.list);
      ssh_free(pdu->pdu.alter_ctx_resp.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_AUTH3:
      ssh_free(pdu->pdu.auth3.data.buffer);
      break;

    case SSH_DCE_RPC_PDU_CO_CANCEL:
      ssh_free(pdu->pdu.cancel.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_ORPHANED:
      ssh_free(pdu->pdu.orphaned.verifier.credentials);
      break;

    case SSH_DCE_RPC_PDU_SHUTDOWN:
    default:
      /* No specific cleanup required */
      break;
    }

  if (ctx_list != NULL)
    {
      SshUInt8 i;

      for (i = 0; (i < ctx_list->items) && (ctx_list->list != NULL); i++)
        {
          SshDceRpcContext next = ctx_list->list->next;

          ssh_free(ctx_list->list->transfer_syntaxes);
          ssh_free(ctx_list->list);

          ctx_list->list = next;
        }
    }

  /* clear the context */
  ssh_dce_rpc_pdu_init(pdu);
}


Boolean
ssh_dce_rpc_pdu_header_decode(SshDceRpcPDUHeader hdr,
                              const unsigned char *buffer,
                              SshUInt16 buffer_len,
                              SshUInt16 *bytes_read)
{
  SshDceRpcDataBufferStruct buff;
  SshUInt8 major_version;

  SSH_ASSERT(hdr != NULL);
  SSH_ASSERT(buffer != NULL);

  if (buffer_len == 0)
    return FALSE;

  buff.buffer = (unsigned char *)buffer;
  buff.size = buffer_len;

  if (bytes_read != NULL)
    *bytes_read = 0;

  /* Check the type of PDU */
  SSH_DCE_RPC_BUFF_LEN_CHECK(&buff, 1);
  major_version = SSH_GET_8BIT(buff.buffer);

  switch (major_version)
    {
    case SSH_DCE_RPC_CO_MAJOR_VERSION:
      if (ssh_dce_rpc_co_pdu_header_decode(hdr, &buff) == FALSE)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Could not decode \"%s\" DCE/RPC header!",
                    ssh_dce_rpc_packet_type_to_str(hdr->packet_type)));
          return FALSE;
        }
      break;

    case SSH_DCE_RPC_CL_MAJOR_VERSION:
      SSH_DEBUG(SSH_D_ERROR, ("Connectionless DCE/RPC PDUs not supported!"));
      return FALSE;

    default:
      SSH_DEBUG(SSH_D_ERROR,
                ("DCE/RPC PDU header contains invalid major version!"));
      return FALSE;
    }

  if (bytes_read != NULL)
    *bytes_read = (SshUInt16)(buffer_len - buff.size);

  return TRUE;
}


/* Decodes the DCE/RPC PDU indicated by `buffer' of size of `buffer_len'
   bytes into a memory block pointed to by `pdu'. The encoded length (in
   bytes) of PDU is optionally returned in `bytes_read'.

   If the `buffer' does not contain an 8-byte aligned memory address, this
   function expects that there are extra padding bytes at the head of buffer.
   Possible alignment bytes are included to the 'bytes_read' returned by this
   function.

   Returns FALSE if the PDU is malformed.

   NOTICE! This function supports currently only connection-oriented DCE/RPC
           PDUs */
Boolean
ssh_dce_rpc_pdu_decode(SshDceRpcPDU pdu,
                       const unsigned char *buffer,
                       SshUInt16 buffer_len,
                       SshUInt16 *bytes_read)
{
  SshDceRpcDataBufferStruct buff;
  SshUInt8 major_version;

  SSH_ASSERT(pdu != NULL);
  SSH_ASSERT(buffer != NULL);

  if (buffer_len == 0)
    return FALSE;

  buff.buffer = (unsigned char *)buffer;
  buff.size = buffer_len;

  SSH_DEBUG(SSH_D_HIGHOK, ("Decoding DCE/RPC Protocol Data Unit"));

  SSH_DEBUG_HEXDUMP(SSH_D_MY5, ("DCE/RPC PDU (length %d bytes)", buffer_len),
                    buffer, buffer_len);

  if (bytes_read != NULL)
    *bytes_read = 0;

  SSH_DCE_RPC_BUFF_ALIGN_RESTORE(&buff, 4);

  /* Check the type of PDU */
  SSH_DCE_RPC_BUFF_LEN_CHECK(&buff, 1);
  major_version = SSH_GET_8BIT(buff.buffer);

  switch (major_version)
    {
    case SSH_DCE_RPC_CO_MAJOR_VERSION:
      if (ssh_dce_rpc_co_pdu_decode(pdu, &buff) == FALSE)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Could not decode \"%s\" DCE/RPC PDU!",
                    ssh_dce_rpc_packet_type_to_str(pdu->header.packet_type)));

          ssh_dce_rpc_pdu_uninit(pdu);

          return FALSE;
        }
      break;

    case SSH_DCE_RPC_CL_MAJOR_VERSION:
      SSH_DEBUG(SSH_D_ERROR, ("Connectionless DCE/RPC PDUs not supported!"));
      return FALSE;

    default:
      SSH_DEBUG(SSH_D_ERROR, ("DCE/RPC PDU contains invalid major version!"));
      return FALSE;
    }

  if (bytes_read != NULL)
    *bytes_read = (SshUInt16)(buffer_len - buff.size);

  return TRUE;
}
