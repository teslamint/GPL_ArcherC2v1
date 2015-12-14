/*
 * wins_packet.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Encoding and decoding of NBNS/WINS packets
 *
 * References:
 *
 *   RFC 1002  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             DETAILED SPECIFICATIONS
 *
 */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "wins_packet.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshWINSPacket"

#define SSH_WINS_HEADER_LEN    12

#define SSH_WINS_OPCODE_MASK   (0xf << SSH_WINS_OPCODE_SHIFT)
#define SSH_WINS_OPCODE_SHIFT  11

#define SSH_WINS_ZERO_MASK     (0x6 << 4)
#define SSH_WINS_RCODE_MASK    0xf


struct SshWINSPhantomBufferRec
{
  const unsigned char *data;
  size_t total_len;
  const unsigned char *ptr;
};

typedef struct SshWINSPhantomBufferRec SshWINSPhantomBufferStruct;
typedef struct SshWINSPhantomBufferRec *SshWINSPhantomBuffer;


struct SshWINSCompressionMapRec
{
  struct SshWINSCompressionMapRec *next;
  size_t offset;
  unsigned char *encoded_name;
};

typedef struct SshWINSCompressionMapRec SshWINSCompressionMapStruct;
typedef struct SshWINSCompressionMapRec *SshWINSCompressionMap;



/* Marks the packet as "broken" */
#define SSH_WINS_PARSE_FAIL(header, why)   \
do                                         \
{                                          \
  SSH_DEBUG(SSH_D_NETGARB, why);           \
  (header)->flags |= SSH_WINS_FLAG_BROKEN; \
  return FALSE;                            \
}                                          \
while (0)


#define SSH_WINS_ENCODE_FAIL()                  \
do                                              \
{                                               \
  SSH_DEBUG(SSH_D_FAIL, ("Not enough memory")); \
  return FALSE;                                 \
}                                               \
while (0)


/* Return if broken */
#define SSH_WINS_RIB(packet)                         \
  if ((packet)->header.flags & SSH_WINS_FLAG_BROKEN) \
    return FALSE;


/*************************** Static help functions **************************/

static Boolean
ssh_wins_netbios_name_decode(SshWINSPacket p,
                             SshNetBIOSName name,
                             SshWINSPhantomBuffer buf);

/*************************** Static help functions **************************/

static const unsigned char *
ssh_wins_phantom_buf_ptr(SshWINSPhantomBuffer buffer)
{
  return (buffer->ptr);
}

static size_t
ssh_wins_phantom_buf_len(SshWINSPhantomBuffer buffer)
{
  return (buffer->total_len - (buffer->ptr - buffer->data));
}


static void
ssh_wins_phantom_buf_consume(SshWINSPhantomBuffer buffer,
                             size_t len)
{
  buffer->ptr += len;
}


/*** Help functions for NetBIOS names ***/

static SshWINSCompressionMap
ssh_wins_add_to_map(SshWINSCompressionMap map,
                    const unsigned char *encoded_name,
                    size_t offset)
{
  SshWINSCompressionMap m;

  if ((m = ssh_calloc(1, sizeof(*m))) != NULL)
    {
      m->encoded_name = ssh_strdup(encoded_name);
      if (m->encoded_name == NULL)
        {
          ssh_free(m);
          return NULL;
        }

      m->offset = offset;
      m->next = map;
    }
  return m;
}

static void
ssh_wins_delete_map(SshWINSCompressionMap map)
{
  if (map == NULL)
    return;

  ssh_wins_delete_map(map->next);
  ssh_free(map->encoded_name);
  ssh_free(map);
}


static Boolean
ssh_wins_try_forward_map(SshWINSCompressionMap map,
                         const unsigned char *encoded_name,
                         size_t *offset)
{
  while (map != NULL)
    {
      if (ssh_ustrcmp(map->encoded_name, encoded_name) == 0)
        {
          *offset = map->offset;
            return TRUE;
        }
      map = map->next;
    }
  return FALSE;
}


static Boolean
ssh_wins_netbios_name_decode(SshWINSPacket p,
                             SshNetBIOSName name,
                             SshWINSPhantomBuffer buf)
{
  unsigned char nb_temp[SSH_WINS_MAX_NAME_LEN + 1];
  unsigned char *name_ptr;
  unsigned char length;
  const unsigned char *ptr = NULL;
  SshUInt16 offset;
  int redirected = 0;

  SSH_ASSERT(p != NULL);
  SSH_ASSERT(name != NULL);
  SSH_ASSERT(buf != NULL);

  name_ptr = nb_temp;

  while (1)
    {
      if (!redirected)
        ptr = ssh_wins_phantom_buf_ptr(buf);

      SSH_DEBUG(SSH_D_MIDSTART,
                ("Parsing NetBIOS name: offset = %d", ptr - buf->data));

      if (redirected)
        {
          if (ptr >= buf->data + buf->total_len)
            SSH_WINS_PARSE_FAIL(&(p->header),
                                ("Redirected pointer out of bounds."));
        }
      else
        {
          if (ssh_wins_phantom_buf_len(buf) == 0)
            SSH_WINS_PARSE_FAIL(&(p->header),
                                ("Buffer empty when parsing NetBIOS name."));
        }

      length = *ptr;

      if (length > 63)
        {
          /* Compressed field. */
          if (redirected)
            {
              if (ptr >= buf->data + buf->total_len - 2)
                SSH_WINS_PARSE_FAIL(&(p->header),
                                   ("Can't read compressed field when "
                                    "redirected."));
            }
          else
            {
              if (ssh_wins_phantom_buf_len(buf) < 2)
                SSH_WINS_PARSE_FAIL(&(p->header),
                                    ("Can't read compressed field."));
            }

          offset = SSH_GET_16BIT(ptr) & ~0xc000;

          if (offset >= buf->total_len)
            SSH_WINS_PARSE_FAIL(&(p->header),
                                ("Compressed field offset out of bounds."));


          if (!redirected)
            ssh_wins_phantom_buf_consume(buf, 2);

          ptr = &buf->data[offset];
          redirected++;
          if (redirected > 20)
            SSH_WINS_PARSE_FAIL(&(p->header), ("Over 20 redirections."));
        }
      else /* length less than 64 */
        {
          if (length + (name_ptr - nb_temp) > SSH_WINS_MAX_NAME_LEN)
            SSH_WINS_PARSE_FAIL(&(p->header), ("Too long NetBIOS name."));

          if (redirected)
            {
              if (ptr + length + 1 >
                  buf->data + buf->total_len)
                SSH_WINS_PARSE_FAIL(&(p->header),
                                   ("Too long NetBIOS name when redirected."));
            }
          else
            {
              if (ssh_wins_phantom_buf_len(buf) < length + 1)
                SSH_WINS_PARSE_FAIL(&(p->header),
                                    ("Too long NetBIOS name field."));
            }

          if (name_ptr > nb_temp && length > 0)
            *name_ptr++ = '.';

          memcpy(name_ptr, ptr + 1, length);
          name_ptr += length;

          if (!redirected)
            ssh_wins_phantom_buf_consume(buf, (size_t)length + 1);
          else
            ptr += length + 1;

          if (length == 0)
            {
              *name_ptr = '\0';

              if (name_ptr - nb_temp >= SSH_WINS_ENCODED_NB_NAME_LEN)
                {
                  SshInt8 i;

                  name->scope_id =
                    ssh_strdup(&(nb_temp[SSH_WINS_ENCODED_NB_NAME_LEN]));

                  if (name->scope_id == NULL)
                    SSH_WINS_PARSE_FAIL(&(p->header),
                                        ("Out of memory."));

                  /* Perform conversion! */
                  for (i = 0; i < 16; i++)
                    {
                      nb_temp[i] = ((nb_temp[i*2] - 'A') << 4) |
                                   (nb_temp[i*2+1] - 'A');
                    }

                  name->type = nb_temp[15];

                  /* Remove extre space characters */
                  i = 15;
                  while (nb_temp[i-1] == ' ')
                    i--;
                  nb_temp[i] = 0x00;

                  name->name_len = i;
                  name->name = ssh_calloc(1, name->name_len+1);

                  if (name->name == NULL)
                    SSH_WINS_PARSE_FAIL(&(p->header),
                                        ("Out of memory."));

                  memcpy(name->name, nb_temp, name->name_len);

                  SSH_DEBUG(SSH_D_DATADUMP,
                            ("Decoded NetBIOS name: \"%s%s\" (type = 0x%02X)",
                            name->name, name->scope_id, name->type));
                }
              else
                SSH_WINS_PARSE_FAIL(&(p->header), ("Invalid NetBIOS name."));

              return TRUE;
            }
        }
    }
}


static Boolean
ssh_wins_netbios_name_encode(SshWINSPacket p,
                             SshNetBIOSName name,
                             SshWINSCompressionMap *map_ptr,
                             SshBuffer buf)
{
  unsigned char nb_temp[SSH_WINS_MAX_NAME_LEN + 1];
  unsigned char *ptr;
  unsigned char *buf_ptr;
  unsigned char *netbios_name = nb_temp;
  size_t offset;
  SshUInt16 i;
  size_t start_offset = 0;

  if (name->name_len > 15)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid NetBIOS name."));
      return FALSE;
    }

  buf_ptr = &nb_temp[SSH_WINS_ENCODED_NB_NAME_LEN];

  memcpy(buf_ptr, name->name, name->name_len);
  memset(buf_ptr + name->name_len, ' ', 15 - name->name_len);
  SSH_PUT_8BIT(buf_ptr + 15, name->type);

  /* encode NetBIOS name and type */
  for (i = 0; i < 16; i++)
    {
      nb_temp[i*2]   = ((buf_ptr[i] & 0xF0) >> 4) + 'A';
      nb_temp[i*2+1] = (buf_ptr[i] & 0x0F) + 'A';
    }

  if (strlen((const char *)name->scope_id) >=
                            (sizeof(nb_temp) - SSH_WINS_ENCODED_NB_NAME_LEN))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid NetBIOS scope ID."));
      return FALSE;
    }

  /* append NetBIOS scope ID (if any) */
  memcpy(&nb_temp[SSH_WINS_ENCODED_NB_NAME_LEN],
         name->scope_id, strlen((const char *)name->scope_id) + 1);

  while (1)
    {
      if (*netbios_name == '\0')
        {
          if (ssh_buffer_append(buf,
                                (const unsigned char *)"\0",
                                1) != SSH_BUFFER_OK)
            SSH_WINS_ENCODE_FAIL();

          return TRUE;
        }

      if (ssh_wins_try_forward_map(*map_ptr, netbios_name, &offset))
        {
          /* Set the two highest bits to denote a compressed name. */
          offset |= 0xc000;

          if (ssh_buffer_append_space(buf, &ptr, 2) != SSH_BUFFER_OK)
            SSH_WINS_ENCODE_FAIL();

          SSH_PUT_16BIT(ptr, offset);
          return TRUE;
        }

      /* Otherwise find the next dot or end-of-string. */
      ptr = (unsigned char *)strchr((const char *)netbios_name, '.');

      offset = start_offset + ssh_buffer_len(buf);

      if (ptr)
        {
          SshUInt32 len = (SshUInt32)(ptr - netbios_name);
          if (len > 0)
            {
              if (ssh_buffer_append_space(buf, &buf_ptr,
                                          len + 1) != SSH_BUFFER_OK)
                SSH_WINS_ENCODE_FAIL();

              *buf_ptr = len;
              memcpy(buf_ptr + 1, netbios_name, len);

              *map_ptr = ssh_wins_add_to_map(*map_ptr, netbios_name, offset);
              if (*map_ptr == NULL)
                SSH_WINS_ENCODE_FAIL();
            }

          netbios_name = ptr + 1;
        }
      else
        {
          int len = ssh_ustrlen(netbios_name);
          if (len > 0)
            {
              if (ssh_buffer_append_space(buf, &buf_ptr, len + 1)
                  != SSH_BUFFER_OK)
                SSH_WINS_ENCODE_FAIL();

              *buf_ptr = len;
              memcpy(buf_ptr + 1, netbios_name, len);

              *map_ptr = ssh_wins_add_to_map(*map_ptr, netbios_name, offset);
              if (*map_ptr == NULL)
                SSH_WINS_ENCODE_FAIL();
            }

          netbios_name += len;
          SSH_ASSERT(*netbios_name == '\0');
        }
    }
}


/*** Help functions for question records ***/

static SshWINSQuestion
ssh_wins_question_allocate(void)
{
  SshWINSQuestion question;

  question = ssh_calloc(1, sizeof(*question));

  return question;
}


static void
ssh_wins_question_free(SshWINSQuestion q)
{
  if (q == NULL)
    return;

  ssh_free(q->name.name);
  ssh_free(q->name.scope_id);
  ssh_free(q);
}


static Boolean
ssh_wins_question_decode(SshWINSPacket p,
                         SshWINSPhantomBuffer buf)
{
  const unsigned char *ptr;

  p->question = ssh_wins_question_allocate();
  if (p->question == NULL)
    SSH_WINS_PARSE_FAIL(&(p->header),
                        ("Can't allocate new question: Out of memory."));

  SSH_WINS_RIB(p);
  ssh_wins_netbios_name_decode(p, &(p->question->name), buf);
  SSH_WINS_RIB(p);

  if (ssh_wins_phantom_buf_len(buf) < 4)
    SSH_WINS_PARSE_FAIL(&(p->header), ("Truncated question."));
  SSH_WINS_RIB(p);

  ptr = ssh_wins_phantom_buf_ptr(buf);
  p->question->query = SSH_GET_16BIT(ptr);
  p->question->protocol_class = SSH_GET_16BIT(ptr + 2);
  ssh_wins_phantom_buf_consume(buf, 4);

  return TRUE;
}


static Boolean
ssh_wins_question_encode(SshWINSPacket p,
                         SshWINSQuestion q,
                         SshWINSCompressionMap *map_ptr,
                         SshBuffer buf)
{
  unsigned char *ptr;

  if (q == NULL)
    return TRUE;

  if (ssh_wins_netbios_name_encode(p, &(q->name), map_ptr, buf) == FALSE)
    SSH_WINS_ENCODE_FAIL();

  if (ssh_buffer_append_space(buf, &ptr, 4) != SSH_BUFFER_OK)
    SSH_WINS_ENCODE_FAIL();

  SSH_PUT_16BIT(ptr, q->query);
  SSH_PUT_16BIT(ptr+2, q->protocol_class);

  return TRUE;
}


/*** Help functions for resource records ***/

static SshWINSRecord
ssh_wins_record_allocate(void)
{
  SshWINSRecord record;

  record = ssh_calloc(1, sizeof(*record));

  return record;
}


static void
ssh_wins_record_free(SshWINSRecord r)
{
  if (r == NULL)
    return;

  ssh_free(r->name.name);
  ssh_free(r->name.scope_id);
  ssh_free(r->data);
  ssh_free(r);
}


static Boolean
ssh_wins_record_decode(SshWINSPacket p,
                       SshWINSRecord *rptr,
                       SshWINSPhantomBuffer buf)
{
  SshWINSRecord record;
  const unsigned char *ptr;

  *rptr = ssh_wins_record_allocate();
  if (*rptr == NULL)
    SSH_WINS_PARSE_FAIL(&(p->header),
                        ("Can't allocate new record: Out of memory."));
  record = *rptr;

  ssh_wins_netbios_name_decode(p, &(record->name), buf);
  SSH_WINS_RIB(p);

  if (ssh_wins_phantom_buf_len(buf) < 10)
    SSH_WINS_PARSE_FAIL(&(p->header), ("Truncated resource record."));

  ptr = ssh_wins_phantom_buf_ptr(buf);
  record->resource = SSH_GET_16BIT(ptr);
  record->protocol_class = SSH_GET_16BIT(ptr + 2);
  record->ttl = SSH_GET_32BIT(ptr + 4);
  record->data_len = SSH_GET_16BIT(ptr + 8);
  ssh_wins_phantom_buf_consume(buf, 10);

  SSH_DEBUG(SSH_D_DATADUMP, ("Resource record:"));
  SSH_DEBUG(SSH_D_DATADUMP, ("- resource = 0x%04X", record->resource));
  SSH_DEBUG(SSH_D_DATADUMP, ("- class = 0x%04X", record->protocol_class));
  SSH_DEBUG(SSH_D_DATADUMP, ("- TTL = %lu", record->ttl));
  SSH_DEBUG(SSH_D_DATADUMP, ("- RDLENGTH = %u", record->data_len));

  if (ssh_wins_phantom_buf_len(buf) < record->data_len)
    SSH_WINS_PARSE_FAIL(&(p->header),
                        ("Truncated resource record (data lost)."));

  if ((record->resource == SSH_WINS_RESOURCE_NB) &&
      (p->header.op_code != SSH_WINS_WACK))
    {
      SshUInt16 num_addr = record->data_len / 6;
      SshUInt16 i;
      SshWINSAddress addr;

      record->data = ssh_calloc(num_addr, sizeof(SshWINSAddressStruct));

      addr = record->data;

      for (i = 0; i < num_addr; i++, addr++)
        {
          ptr = ssh_wins_phantom_buf_ptr(buf);

          if (ssh_wins_phantom_buf_len(buf) < 6)
            SSH_WINS_PARSE_FAIL(&(p->header),
                                ("Truncated resource record (data lost)."));

          addr->flags = SSH_GET_16BIT(ptr);
          SSH_IP4_DECODE(&addr->ip_addr, (ptr+2));

          SSH_DEBUG(SSH_D_DATADUMP, ("Address entry %d:", i+1));
          SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", addr->flags));
          SSH_DEBUG(SSH_D_DATADUMP, ("- IP address = %@",
                    ssh_ipaddr_render, &addr->ip_addr));

          ssh_wins_phantom_buf_consume(buf, 6);
        }
    }
  else
    {
      record->data = ssh_malloc(record->data_len);
      if (record->data == NULL)
        SSH_WINS_PARSE_FAIL(&(p->header), ("Out of memory."));

      memcpy(record->data, ptr+10, record->data_len);
      ssh_wins_phantom_buf_consume(buf, record->data_len);
    }

  return TRUE;
}


static Boolean
ssh_wins_record_encode(SshWINSPacket p,
                       SshWINSRecord r,
                       SshWINSCompressionMap *map_ptr,
                       SshBuffer buf)
{
  unsigned char *ptr;
  size_t offset;

  if (r == NULL)
    return TRUE;

  if (ssh_wins_netbios_name_encode(p, &(r->name), map_ptr, buf) == FALSE)
    SSH_WINS_ENCODE_FAIL();

  if (ssh_buffer_append_space(buf, &ptr, 8) != SSH_BUFFER_OK)
    SSH_WINS_ENCODE_FAIL();

  SSH_PUT_16BIT(ptr, r->resource);
  SSH_PUT_16BIT(ptr + 2, r->protocol_class);
  SSH_PUT_32BIT(ptr + 4, r->ttl);

  /* Reserve space for length octets, then pack the record's data. */
  offset = ssh_buffer_len(buf);

  if (ssh_buffer_append_space(buf, &ptr, r->data_len+2) != SSH_BUFFER_OK)
    SSH_WINS_ENCODE_FAIL();

  SSH_PUT_16BIT(ptr, r->data_len);
  ptr += 2;

  if ((r->resource == SSH_WINS_RESOURCE_NB) &&
      (p->header.op_code != SSH_WINS_WACK))
    {
      SshUInt16 num_addr = r->data_len / 6;
      SshUInt16 i;
      SshWINSAddress addr = r->data;

      for (i = 0; i < num_addr; i++, addr++, ptr += 6)
        {
          SSH_DEBUG(SSH_D_DATADUMP, ("Address entry %d:", i+1));
          SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%04X", addr->flags));
          SSH_DEBUG(SSH_D_DATADUMP, ("- IP address = %@",
                    ssh_ipaddr_render, &addr->ip_addr));

          SSH_PUT_16BIT(ptr, addr->flags);
          SSH_IP4_ENCODE(&addr->ip_addr, (ptr+2));
        }
    }
  else
    {
      memcpy(ptr, r->data, r->data_len);
    }

  return TRUE;
}


/************* Exported WINS packet decoding/encoding functions *************/

/* Allocates a new (empty) WINS packet structure. */
SshWINSPacket
ssh_wins_packet_allocate(void)
{
  SshWINSPacket packet;

  packet = ssh_calloc(1, sizeof(*packet));
  return packet;
}


/* Frees a WINS packet structure and all attached records */
void
ssh_wins_packet_free(SshWINSPacket p)
{
  if (p == NULL)
    return;

  ssh_wins_question_free(p->question);
  ssh_wins_record_free(p->answer);
  ssh_wins_record_free(p->additional_rec);
  ssh_free(p);
}


/* Decode the NBNS/WINS packet `packet' from the buffer `buf'. Sets the
   `BROKEN' flag in `packet->flags' if parsing encounters an error. */
Boolean
ssh_wins_packet_decode(SshWINSPacket p,
                       const unsigned char *buf,
                       SshUInt16 msg_len,
                       Boolean decode_header)
{
  SshWINSPhantomBufferStruct phantom_buf;

  SSH_ASSERT(p != NULL);
  SSH_ASSERT(buf != NULL);

  phantom_buf.data = buf;
  phantom_buf.total_len = msg_len;
  phantom_buf.ptr = phantom_buf.data;

  SSH_DEBUG(SSH_D_LOWOK, ("Parsing a WINS packet."));

  if (decode_header)
    ssh_wins_header_decode(&p->header, buf, msg_len);
  SSH_WINS_RIB(p);

  ssh_wins_phantom_buf_consume(&phantom_buf, 12);

  if (p->header.flags & SSH_WINS_FLAG_IS_RESPONSE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Parsing an answer."));
      SSH_DEBUG_INDENT;
      /* The "answer" record exists also in negative name query responses! */
      ssh_wins_record_decode(p, &(p->answer), &phantom_buf);
      SSH_DEBUG_UNINDENT;
      SSH_WINS_RIB(p);
    }
  else
    {
      /* Parse question */
      SSH_DEBUG(SSH_D_LOWOK, ("Parsing a question."));
      SSH_DEBUG_INDENT;
      ssh_wins_question_decode(p, &phantom_buf);
      SSH_DEBUG_UNINDENT;
      SSH_WINS_RIB(p);
    }

  if (p->header.num_additional_recs == 1)
    {
      /* Parse additional record (if any) */
      SSH_DEBUG(SSH_D_LOWOK, ("Parsing an additional record."));
      SSH_DEBUG_INDENT;
      ssh_wins_record_decode(p, &(p->additional_rec), &phantom_buf);
      SSH_DEBUG_UNINDENT;
      SSH_WINS_RIB(p);
    }

  if (ssh_wins_phantom_buf_len(&phantom_buf) != 0)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NETGARB, ("Extraneous data: "),
                        ssh_wins_phantom_buf_ptr(&phantom_buf),
                        ssh_wins_phantom_buf_len(&phantom_buf));
/*
      Windows 2000 host seem to send 18 extra more or less "random" bytes at
      the tail of every NetBIOS node status response. For Win2K compatibility,
      we don't mark the whole datagram as broken (even though it is). We just
      silently drop the extra bytes away.

      SSH_WINS_PARSE_FAIL(&(p->header),
                          ("Extraneous data at the end of the packet, "
                          "%d bytes.",
                          ssh_wins_phantom_buf_len(&phantom_buf)));
*/
    }

  return TRUE;
}


/* Decode the NBNS/WINS packet `packet' from the buffer `buf'. Sets the
   `BROKEN' flag in `packet->flags' if parsing encounters an error. */
Boolean
ssh_wins_header_decode(SshWINSPacketHeader header,
                       const unsigned char *buf,
                       SshUInt16 buf_len)
{
  SshUInt16 w;
  SshUInt16 num_authority_recs;

  SSH_ASSERT(header != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("Parsing a WINS header."));

  if (buf_len < SSH_WINS_HEADER_LEN)
    SSH_WINS_PARSE_FAIL(header, ("WINS packet header truncated."));

  header->xid = SSH_GET_16BIT(buf);
  w = SSH_GET_16BIT(buf + 2);
  header->flags = (w & SSH_WINS_FLAG_MASK);
  header->op_code = (w & SSH_WINS_OPCODE_MASK) >> SSH_WINS_OPCODE_SHIFT;
  header->response_code = (w & SSH_WINS_RCODE_MASK);

  /* Check that the `Z' field is really zeroed. */
  if (w & SSH_WINS_ZERO_MASK)
    SSH_DEBUG(SSH_D_NETGARB,
              ("WINS header Z is not zero, but %x.",
               (w & SSH_WINS_ZERO_MASK)));

  header->num_questions = SSH_GET_16BIT(buf + 4);
  header->num_answers = SSH_GET_16BIT(buf + 6);
  num_authority_recs = SSH_GET_16BIT(buf + 8);
  header->num_additional_recs = SSH_GET_16BIT(buf + 10);

  SSH_DEBUG_INDENT;
  SSH_DEBUG(SSH_D_DATADUMP, ("Transaction ID = 0x%04X", header->xid));
  SSH_DEBUG(SSH_D_DATADUMP, ("Flags = 0x%04X", w));
  SSH_DEBUG_INDENT;
  SSH_DEBUG(SSH_D_DATADUMP, ("NM_FLAGS = 0x%04X", header->flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("OPCODE = 0x%04X", header->op_code));
  SSH_DEBUG(SSH_D_DATADUMP, ("RCODE = 0x%04X", header->response_code));
  SSH_DEBUG_UNINDENT;
  SSH_DEBUG(SSH_D_DATADUMP,
            ("Number of questions = %d", header->num_questions));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("Number of answers = %d", header->num_answers));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("Number of authority records = %d", num_authority_recs));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("Number of additional records = %d",
            header->num_additional_recs));
  SSH_DEBUG_UNINDENT;

  /* Currently we don't support redirect name query responses, so number of
     authority records must always be zero */
  if (num_authority_recs)
    SSH_WINS_PARSE_FAIL(header,
                        ("WINS packet containing authority records!"));

  if (header->flags & SSH_WINS_FLAG_IS_RESPONSE)
    {
      if (header->num_questions) /* num_questions must be zero */
        SSH_WINS_PARSE_FAIL(header,
                            ("WINS response containing question records!"));

      switch (header->op_code)
        {
        case SSH_WINS_QUERY:
          if (header->response_code != SSH_WINS_OK)
            {
              if (header->num_answers == 0)
                break;

              SSH_WINS_PARSE_FAIL(header,
                                  ("WINS request containing invalid "
                                  "number (%d) of answer records!",
                                  header->num_answers));
            }
        case SSH_WINS_REGISTRATION:
        case SSH_WINS_MULTIHOMED_REGISTRATION:
        case SSH_WINS_REFRESH:
        case SSH_WINS_RELEASE:
        case SSH_WINS_WACK:
          if (header->num_answers != 1) /* num_answers must be 1 */
            SSH_WINS_PARSE_FAIL(header,
                                ("WINS request containing invalid number "
                                "(%d) of answer records!",
                                header->num_answers));
          break;

        default:
          SSH_WINS_PARSE_FAIL(header, ("Unknown WINS response (%d)!",
                              header->op_code));
          break;
        }

      if (header->num_additional_recs != 0) /* must be 0 */
        SSH_WINS_PARSE_FAIL(header,
                            ("WINS response containing invalid number (%d) "
                             "of additional records!",
                            header->num_additional_recs));
    }
  else
    {
      if (header->num_answers) /* num_answers must be zero */
        SSH_WINS_PARSE_FAIL(header,
                            ("WINS request containing answer records!"));

      switch (header->op_code)
        {
        case SSH_WINS_QUERY:
          if (header->num_additional_recs != 0) /* must be 0 */
            SSH_WINS_PARSE_FAIL(header,
                                ("WINS request containing invalid number "
                                "(%d) of additional records!",
                                header->num_additional_recs));
          break;

        case SSH_WINS_REGISTRATION:
        case SSH_WINS_MULTIHOMED_REGISTRATION:
        case SSH_WINS_REFRESH:
        case SSH_WINS_RELEASE:
          if (header->num_additional_recs != 1) /* must be 1 */
            SSH_WINS_PARSE_FAIL(header,
                                ("WINS request containing invalid number "
                                 "(%d) of additional records!",
                                header->num_additional_recs));
          break;

        default:
          SSH_WINS_PARSE_FAIL(header, ("Unknown WINS request (%d)!",
                              header->op_code));
          break;
        }

      if (header->num_questions != 1) /* num_questions must be 1 */
        SSH_WINS_PARSE_FAIL(header,
                            ("WINS request containing invalid number (%d) "
                            "of question records!",
                            header->num_questions));
    }

  return TRUE;
}


/* Encode the WINS packet `packet' to the buffer `buf'. */
Boolean
ssh_wins_packet_encode(SshWINSPacket packet,
                       SshBuffer buf)
{
  Boolean stat = TRUE;
  SshWINSCompressionMap map = NULL;
  unsigned char *ptr;

  if (ssh_buffer_append_space(buf, &ptr, 12) != SSH_BUFFER_OK)
    SSH_WINS_ENCODE_FAIL();

  SSH_PUT_16BIT(ptr, packet->header.xid);
  SSH_PUT_16BIT(ptr+2, (SshUInt16) (packet->header.flags |
                        (packet->header.op_code << SSH_WINS_OPCODE_SHIFT) |
                        (packet->header.response_code)));
  SSH_PUT_16BIT(ptr+4, packet->header.num_questions);
  SSH_PUT_16BIT(ptr+6, packet->header.num_answers);
  SSH_PUT_16BIT(ptr+8, 0);
  SSH_PUT_16BIT(ptr+10, packet->header.num_additional_recs);

  stat &= ssh_wins_question_encode(packet, packet->question, &map, buf);
  stat &= ssh_wins_record_encode(packet, packet->answer, &map, buf);
  stat &= ssh_wins_record_encode(packet, packet->additional_rec, &map, buf);

  ssh_wins_delete_map(map);

  return stat;
}
