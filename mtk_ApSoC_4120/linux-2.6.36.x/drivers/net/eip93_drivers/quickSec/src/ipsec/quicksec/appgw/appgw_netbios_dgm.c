/*
 *
 * appgw_netbios_dgm.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application level gateway for NetBIOS Datagram Services.
 *
 *
 * References:
 *
 *   RFC 1001  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             CONCEPTS AND METHODS
 *   RFC 1002  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             DETAILED SPECIFICATIONS
 *
 */

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "appgw_api.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE  "SshAppgwNetBIOSDgm"

/* Identification string. */
#define SSH_APPGW_IDENT     "alg-netbios-dgm@ssh.com"
#define SSH_APPGW_VERSION   1
#define SSH_APPGW_NAME      "NBDGMALG"

/* Flow and operations ageing timer. */
#define SSH_APPGW_NBDGM_TIMER      10

/* Number of timer ticks a flow is kept alive if it does not receive
   any packets. When the flow receives packets, it will get this
   much lifetime. */
#define SSH_APPGW_NBDGM_KEEPALIVE  (8/*hours*/*60/*minutes*/*6/*ticks*/)

/* Number of timer ticks an operation is kept alive if we don't receive
   response from name server */
#define SSH_APPGW_OPERATION_TTL     2

/* Length of NetBIOS datagram header (RFC 1001: 17.1.2) */
#define SSH_APPGW_NBDGM_HEADER_LEN   14

/* Maximum length of NetBIOS Datagram data section (RFC 1001: 17.1.2) */
#define SSH_APPGW_NBDGM_MAX_DATA_LEN 1022

/* Maximum UDP data length of NetBIOS Datagram */
#define SSH_APPGW_NBDGM_MAX_DATAGRAM_LEN (SSH_APPGW_NBDGM_HEADER_LEN +  \
                                          SSH_APPGW_NBDGM_MAX_DATA_LEN)

/* Length of shortest possible NetBIOS datagram from client */
#define SSH_APPGW_NBDGM_MIN_CALL_LEN   SSH_APPGW_NBDGM_HEADER_LEN

/* Length of shortest possible NetBIOS datagram (Error Packet) from server. */
#define SSH_APPGW_NBDGM_MIN_REPLY_LEN  11

/* Field offsets in NetBIOS datagram */
#define SSH_APPGW_NBDGM_TYPE_OFFSET    0
#define SSH_APPGW_NBDGM_FLAGS_OFFSET   1
#define SSH_APPGW_NBDGM_ID_OFFSET      2
#define SSH_APPGW_NBDGM_ADDR_OFFSET    4
#define SSH_APPGW_NBDGM_PORT_OFFSET    8
#define SSH_APPGW_NBDGM_LENGTH_OFFSET  10
#define SSH_APPGW_NBDGM_ERROR_OFFSET   10
#define SSH_APPGW_NBDGM_PKTOFFS_OFFSET 12


/* Message types for NetBIOS datagrams (RFC 1002: 4.4.1) */
typedef enum
{
  SSH_NBDS_DIRECT_UNIQUE_DATAGRAM = 0x10,
  SSH_NBDS_DIRECT_GROUP_DATAGRAM,
  SSH_NBDS_DROADCAST_DATAGRAM,
  SSH_NBDS_DATAGRAM_ERROR,
  SSH_NBDS_QUERY_REQUEST,
  SSH_NBDS_POSITIVE_RESPONSE,
  SSH_NBDS_NEGATIVE_RESPONSE
} SshAppgwNbDgmMsgType;


/* Error code values (RFC 1002: 4.4.3) */
typedef enum
{
  SSH_NBDS_E_DESTINATION_NOT_PRESENT = 0x82,
  SSH_NBDS_E_INVALID_SOURCE_NAME,
  SSH_NBDS_E_INVALID_DESTINATION_NAME
} SshAppgwNbDgmErrorCode;


/* NetBIOS end-node types: (RFC 1001: 10, 11.2) */
typedef enum
{
  SSH_NETBIOS_NODE_TYPE_B = 0,    /* Broadcast */
  SSH_NETBIOS_NODE_TYPE_P,        /* Point-to-point */
  SSH_NETBIOS_NODE_TYPE_M,        /* Mixed node */
  SSH_NETBIOS_NODE_TYPE_NBDD,     /* Datagram distribution server */
  SSH_NETBIOS_NODE_TYPE_H = 0x06  /* Microsoft specific; Hybrid node */
} SshAppgwNetbiosNodeType;


struct SshNetBIOSNameRec
{
  /* Link field */
  struct SshNetBIOSNameRec *next;

  /* up to 15 characters long NetBIOS name */
  unsigned char name[16];

  /* optional NetBIOS scope ID */
  unsigned char *scope_id;

  /* NetBIOS name type */
  SshUInt8 type;

  /* Length of NetBIOS name (can also be '*' with 14 NULLs) */
  SshUInt8 name_len;
};

typedef struct SshNetBIOSNameRec SshNetBIOSNameStruct;
typedef struct SshNetBIOSNameRec *SshNetBIOSName;


/* A NetBIOS Datagram Service connection. */
struct SshAppgwNbDgmConnectionRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwNbDgmConnectionRec *next;
  struct SshAppgwNbDgmConnectionRec *prev;

  /* An unique ID for this connection. */
  SshUInt32 unique_id;

  /* TTL, number of SSH_APPGW_WINS_TIMER ticks this flow is kept alive. */
  SshUInt16 ttl;

  /* Source name(s). (Normally one NetBIOS name only) */
  SshNetBIOSName source_names;

  /* The application gateway context. */
  SshAppgwContext instance;

  /* Application gateway instance context. */
  struct SshAppgwNbDgmCtxRec *nbdgm_alg;
};

typedef struct SshAppgwNbDgmConnectionRec SshAppgwNbDgmConnectionStruct;
typedef struct SshAppgwNbDgmConnectionRec *SshAppgwNbDgmConnection;


/* Decoded NetBIOS datagram structure */
struct SshAppgwNetbiosDatagramRec
{
  /* Type of datagram */
  SshAppgwNbDgmMsgType msg_type;

  /* Source IP */
  SshIpAddrStruct src_ip;

  /* Source port */
  SshUInt16 src_port;

  /* Datagram ID */
  SshUInt16 datagram_id;

  /* Flags: */
  unsigned int more_fragments : 1;
  unsigned int first_fragment : 1;

  /* Source end-node type */
  SshAppgwNetbiosNodeType node_type;

  /* Datagram length */
  SshUInt16 datagram_length;

  /* Packet offset */
  SshUInt16 packet_offset;

  /* Error code */
  SshUInt8 error_code;

  /* NetBIOS names */
  SshNetBIOSNameStruct src_name;
  SshNetBIOSNameStruct dest_name;

  /* User data */
  unsigned char *user_data;
  size_t user_data_size;
};

typedef struct SshAppgwNetbiosDatagramRec SshAppgwNetbiosDatagramStruct;
typedef struct SshAppgwNetbiosDatagramRec *SshAppgwNetbiosDatagram;


/* Context data for NetBIOS Datagram Service application gateways. */
struct SshAppgwNbDgmCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* Flow and operations ageing timer. */
  SshTimeoutStruct timeout;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */

  /* Next unique ID for connections. */
  SshUInt32 next_unique_id;

  /* Active connections. */
  SshAppgwNbDgmConnection connections;
};

typedef struct SshAppgwNbDgmCtxRec SshAppgwNbDgmCtxStruct;
typedef struct SshAppgwNbDgmCtxRec *SshAppgwNbDgmCtx;


struct SshAppgwNbDgmFilterRuleRec
{
  /* Type of datagram */
  SshAppgwNbDgmMsgType msg_type;

  /* Human-readable name for debugging porposes */
  const char *name;

  /* Minimum length */
  SshUInt16  min_length;

  /* Maximum length */
  SshUInt16  max_length;

  /* Flags: */
  SshUInt16  flags;
};

typedef struct SshAppgwNbDgmFilterRuleRec SshAppgwNbDgmFilterRuleStruct;
typedef struct SshAppgwNbDgmFilterRuleRec *SshAppgwNbDgmFilterRule;


/* Definitions for SshAppgwNbDgmFilterRuleRec.flags */
#define SSH_APPGW_NBDGM_DROP                   0x8000
#define SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR  0x0800
#define SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER  0x0400
#define SSH_APPGW_NBDGM_HAS_LENGTH_FIELD       0x0080
#define SSH_APPGW_NBDGM_HAS_OFFSET_FIELD       0x0040
#define SSH_APPGW_NBDGM_HAS_ERROR_FIELD        0x0020
#define SSH_APPGW_NBDGM_HAS_SOURCE_NAME        0x0008
#define SSH_APPGW_NBDGM_HAS_DESTINATION_NAME   0x0004
#define SSH_APPGW_NBDGM_HAS_USER_DATA          0x0002

static const SshAppgwNbDgmFilterRuleStruct ssh_appgw_nbds_filter_rules[] = {

  {SSH_NBDS_DIRECT_UNIQUE_DATAGRAM, (const char *)"DIRECT_UNIQUE_DATAGRAM",
   SSH_APPGW_NBDGM_HEADER_LEN, SSH_APPGW_NBDGM_MAX_DATAGRAM_LEN,
   SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR |
   SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER |
   SSH_APPGW_NBDGM_HAS_LENGTH_FIELD |
   SSH_APPGW_NBDGM_HAS_OFFSET_FIELD |
   SSH_APPGW_NBDGM_HAS_SOURCE_NAME |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME |
   SSH_APPGW_NBDGM_HAS_USER_DATA},

  {SSH_NBDS_DIRECT_GROUP_DATAGRAM, (const char *)"DIRECT_GROUP_DATAGRAM",
   SSH_APPGW_NBDGM_HEADER_LEN, SSH_APPGW_NBDGM_MAX_DATAGRAM_LEN,
   SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR |
   SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER |
   SSH_APPGW_NBDGM_HAS_LENGTH_FIELD |
   SSH_APPGW_NBDGM_HAS_OFFSET_FIELD |
   SSH_APPGW_NBDGM_HAS_SOURCE_NAME |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME |
   SSH_APPGW_NBDGM_HAS_USER_DATA},

  {SSH_NBDS_DROADCAST_DATAGRAM, (const char *)"BROADCAST_DATAGRAM",
   SSH_APPGW_NBDGM_HEADER_LEN, SSH_APPGW_NBDGM_MAX_DATAGRAM_LEN,
   SSH_APPGW_NBDGM_DROP |
   SSH_APPGW_NBDGM_HAS_LENGTH_FIELD |
   SSH_APPGW_NBDGM_HAS_OFFSET_FIELD |
   SSH_APPGW_NBDGM_HAS_SOURCE_NAME |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME |
   SSH_APPGW_NBDGM_HAS_USER_DATA},

  {SSH_NBDS_DATAGRAM_ERROR, (const char *)"DATAGRAM_ERROR",
   11, 11,
   SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER |
   SSH_APPGW_NBDGM_HAS_ERROR_FIELD},

  {SSH_NBDS_QUERY_REQUEST, (const char *)"QUERY_REQUEST",
   12, 265,
   SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME},

  {SSH_NBDS_POSITIVE_RESPONSE, (const char *)"POSITIVE_RESPONSE",
   12, 265,
   SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME},

  {SSH_NBDS_NEGATIVE_RESPONSE, (const char *)"NEGATIVE_RESPONSE",
   12, 265,
   SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER |
   SSH_APPGW_NBDGM_HAS_DESTINATION_NAME}
};

/************************** Static help functions ***************************/

static void ssh_appgw_nbdgm_done(SshAppgwNbDgmConnection conn);

/************************ ADT bag for WINS operations ***********************/


/************************** Static help functions ***************************/

static Boolean
ssh_netbios_name_decode(SshNetBIOSName name,
                        const unsigned char * encoded_name_buffer,
                        size_t name_buffer_len)
{
  const unsigned char * cp = encoded_name_buffer;
  size_t buffer_left = name_buffer_len;
  SshUInt8 i;

  SSH_ASSERT(name->scope_id == NULL);
  SSH_ASSERT(encoded_name_buffer != NULL);

  if (name_buffer_len < 34)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid buffer!"));
      return FALSE;
    }

  if (*cp != 32)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid length!"));
      return FALSE;
    }

  cp++;

  /* Convert the NetBIOS name_buffer */
  for (i = 0; i < 16; i++, cp += 2)
    name->name[i] = (unsigned char)(((*cp - 'A') << 4) | (*(cp+1) - 'A'));

  name->type = name->name[15];

  /* Remove extre space characters and append a terminating null character */
  i = 15;
  while (name->name[i-1] == ' ')
    i--;

  name->name_len = i;
  name->name[name->name_len] = 0x00;

  /* Parse NetBIOS scope ID (if any) */
  if (*cp != 0)
    {
      size_t scope_len = *cp;

      buffer_left -= 34;

      if (scope_len >= buffer_left)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid NetBIOS scope ID!"));
          return FALSE;
        }

      cp++;

      name->scope_id = ssh_calloc(1, scope_len+1);
      if (name->scope_id == NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                        "%s: Can't copy NetBIOS scope ID; reason: "
                        "Out of memory.", SSH_APPGW_NAME);
          return FALSE;
        }

      memcpy(name->scope_id, cp, scope_len);
      cp += scope_len;
    }

  if (*cp != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid NetBIOS name!"));
      return FALSE;
    }

  return TRUE;
}


static size_t
ssh_netbios_name_encoded_len(SshNetBIOSName name)
{
  size_t length;

  length = 32 + 2; /* length of encoded NetBIOS name + two length fields */

  if (name->scope_id)
    length += 1 + (2 * strlen((const char *)name->scope_id));

  return length;
}


static void
ssh_netbios_name_encode(SshNetBIOSName name,
                        unsigned char * buffer,
                        size_t buffer_len)
{
  unsigned char * cp = buffer;
  SshUInt8 i;

  if (buffer_len < ssh_netbios_name_encoded_len(name))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid buffer!"));
      return;
    }

  *cp = 32; /* length */

  if (name->name_len < 15)
    {
      if (name->name[name->name_len] == 0x00)
        name->name[name->name_len] = ' ';
    }

  /* encode NetBIOS name and type */
  name->name[15] = name->type;
  for (i = 0, cp++; i < 16; i++, cp += 2)
    {
      *cp    = (unsigned char)(((name->name[i] & 0xF0) >> 4) + 'A');
      *(cp+1) = (unsigned char)((name->name[i] & 0x0F) + 'A');
    }
  name->name[15] = 0x00;

  if (name->scope_id != NULL)
    {
      size_t name_len = strlen((const char *)name->scope_id);

      *cp = (unsigned char)name_len;
      memcpy(cp+1, name->scope_id, name_len);

      cp += name_len + 1;
    }

  *cp = 0; /* Length of next string (always zero) */
}


static const SshAppgwNbDgmFilterRuleStruct *
ssh_appgw_nbds_filter_rule_lookup(SshAppgwNbDgmMsgType msg_type)
{
  if ((msg_type >= SSH_NBDS_DIRECT_UNIQUE_DATAGRAM) &&
      (msg_type <= SSH_NBDS_NEGATIVE_RESPONSE))
    {
      return &ssh_appgw_nbds_filter_rules[msg_type -
					  SSH_NBDS_DIRECT_UNIQUE_DATAGRAM];
    }
  
  return NULL;
}


static void
ssh_netbios_datagram_init(SshAppgwNetbiosDatagram datagram)
{
  datagram->more_fragments = 0;
  datagram->first_fragment = 0;
  datagram->datagram_length = 0;
  datagram->error_code = 0;
  datagram->packet_offset = 0;
  datagram->src_name.next = NULL;
  datagram->src_name.scope_id = NULL;
  datagram->dest_name.next = NULL;
  datagram->dest_name.scope_id = NULL;
  datagram->user_data = NULL;
  datagram->user_data_size = 0;
}


static void
ssh_netbios_datagram_uninit(SshAppgwNetbiosDatagram datagram)
{
  if (datagram->src_name.scope_id)
    ssh_free(datagram->src_name.scope_id);

  if (datagram->dest_name.scope_id)
    ssh_free(datagram->dest_name.scope_id);

  if (datagram->user_data)
    ssh_free(datagram->user_data);
}


static Boolean
ssh_netbios_datagram_decode(SshAppgwNbDgmConnection conn,
                            SshAppgwNetbiosDatagram datagram,
                            const unsigned char *data,
                            size_t data_len,
                            Boolean initiator)
{
  const SshAppgwNbDgmFilterRuleStruct *rule;
  size_t name_offset = SSH_APPGW_NBDGM_PORT_OFFSET+2;
  SshUInt8 flags;

  if ((data == NULL) || (data_len == 0))
    return FALSE;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Original NetBIOS datagram:"),
                    data, data_len);

  datagram->msg_type = SSH_GET_8BIT(data+SSH_APPGW_NBDGM_TYPE_OFFSET);

  rule = ssh_appgw_nbds_filter_rule_lookup(datagram->msg_type);
  if (rule == NULL)
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Failed to decode NetBIOS datagram; reason: "
                            "invalid type.",
                            SSH_AUDIT_ARGUMENT_END);
      return FALSE;
    }
  
  if (rule->flags & SSH_APPGW_NBDGM_DROP)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NetBIOS datagram (type = %d) dropped!",
                datagram->msg_type));
      return FALSE;
    }

  if (((initiator == TRUE) &&
       (rule->flags & SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR) == 0) ||
      ((initiator == FALSE) &&
       (rule->flags & SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER) == 0))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NetBIOS datagram (type = %d) dropped!",
                datagram->msg_type));
      return FALSE;
    }

  /* Check the length of packet! */
  if ((data_len < rule->min_length) || (data_len > rule->max_length))
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Failed to decode NetBIOS datagram; reason: "
                            "invalid length.",
                            SSH_AUDIT_ARGUMENT_END);
      return FALSE;
    }

  SSH_ASSERT(data_len >= SSH_APPGW_NBDGM_MIN_REPLY_LEN);

  flags = SSH_GET_8BIT(data+SSH_APPGW_NBDGM_FLAGS_OFFSET);

  /* According to NetBIOS RFCs four most significant bits must be zero, but
     Microsoft has made some additions... (i.e. 'hybrid' node) */
  if (flags & 0xE0)
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Failed to decode NetBIOS datagram; reason: "
                            "invalid flags.",
                            SSH_AUDIT_ARGUMENT_END);
      return FALSE;
    }

  if (flags & 0x01)
    datagram->more_fragments = 1;
  if (flags & 0x02)
    datagram->first_fragment = 1;

  datagram->node_type = (flags >> 2);

  datagram->datagram_id = SSH_GET_16BIT(data+SSH_APPGW_NBDGM_ID_OFFSET);

  SSH_IP_DECODE(&datagram->src_ip,
                data+SSH_APPGW_NBDGM_ADDR_OFFSET, SSH_IPH4_ADDRLEN);

  datagram->src_port = SSH_GET_16BIT(data+SSH_APPGW_NBDGM_PORT_OFFSET);

  if (rule->flags & SSH_APPGW_NBDGM_HAS_LENGTH_FIELD)
    {
      datagram->datagram_length =
        SSH_GET_16BIT(data+SSH_APPGW_NBDGM_LENGTH_OFFSET);

      if (datagram->datagram_length + 14 != data_len)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Failed to decode NetBIOS datagram; reason: "
                                "invalid user data length.",
                                SSH_AUDIT_ARGUMENT_END);
          return FALSE;
        }

      datagram->user_data_size = datagram->datagram_length;

      name_offset += 2;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_ERROR_FIELD)
    {
      datagram->error_code =
        SSH_GET_8BIT(data+SSH_APPGW_NBDGM_ERROR_OFFSET);

      name_offset += 1;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_OFFSET_FIELD)
    {
      datagram->packet_offset =
        SSH_GET_16BIT(data+SSH_APPGW_NBDGM_PKTOFFS_OFFSET);

      if ((datagram->first_fragment == 0) && (datagram->packet_offset > 0))
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Failed to decode NetBIOS datagram; reason: "
                                "invalid offset.",
                                SSH_AUDIT_ARGUMENT_END);
          return FALSE;
        }

      name_offset += 2;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_SOURCE_NAME)
    {
      size_t name_len;

      if (ssh_netbios_name_decode(&datagram->src_name, data + name_offset,
                                  data_len - name_offset) == FALSE)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Failed to decode NetBIOS datagram; reason: "
                                "invalid NetBIOS source name.",
                                SSH_AUDIT_ARGUMENT_END);
          return FALSE;
        }

      name_len = ssh_netbios_name_encoded_len(&datagram->src_name);
      name_offset += name_len;
      datagram->user_data_size -= name_len;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_DESTINATION_NAME)
    {
      size_t name_len;

      if (ssh_netbios_name_decode(&datagram->dest_name, data + name_offset,
                                  data_len - name_offset) == FALSE)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Failed to decode NetBIOS datagram; reason: "
                                "invalid NetBIOS destination name.",
                                SSH_AUDIT_ARGUMENT_END);
          return FALSE;
        }

      name_len = ssh_netbios_name_encoded_len(&datagram->dest_name);
      name_offset += name_len;
      datagram->user_data_size -= name_len;
    }

  /* Copy the appended user data */
  if (rule->flags & SSH_APPGW_NBDGM_HAS_USER_DATA)
    {
      datagram->user_data = ssh_malloc(datagram->user_data_size);
      if (datagram->user_data == NULL)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Running low on memory. NetBIOS datagram "
                                "dropped.",
                                SSH_AUDIT_ARGUMENT_END);
          return FALSE;
        }

      memcpy(datagram->user_data, data + name_offset,
             datagram->user_data_size);
    }

#ifdef DEBUG_LIGHT

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Decoded NetBIOS Datagram (type = 0x%X)", datagram->msg_type));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- source_ip = %@", ssh_ipaddr_render, &datagram->src_ip));
  SSH_DEBUG(SSH_D_DATADUMP, ("- source_port = %u", datagram->src_port));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- datagram_id = 0x%04X", datagram->datagram_id));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- first_fragment = %u", datagram->first_fragment));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- more_fragments = %u", datagram->more_fragments));
  SSH_DEBUG(SSH_D_DATADUMP, ("- node_type = %u", datagram->node_type));

  if (rule->flags & SSH_APPGW_NBDGM_HAS_LENGTH_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- datagram_length = %u", datagram->datagram_length));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_OFFSET_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- packet_offset = %u", datagram->packet_offset));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_ERROR_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- error_code = %u", datagram->error_code));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_SOURCE_NAME)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- source_name = \"%s\"", datagram->src_name.name));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_DESTINATION_NAME)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- destination_name = \"%s\"", datagram->dest_name.name));
    }
#endif /* DEBUG_LIGHT */

  return TRUE;
}


static unsigned char *
ssh_netbios_datagram_encode(SshAppgwNbDgmConnection conn,
                            SshAppgwNetbiosDatagram datagram,
                            size_t *buffer_size,
                            Boolean initiator)
{
  const SshAppgwNbDgmFilterRuleStruct *rule;
  SshUInt8 flags = 0;
  size_t datagram_size = 0;
  unsigned char *buffer;
  unsigned char *cp;

  rule = ssh_appgw_nbds_filter_rule_lookup(datagram->msg_type);
  SSH_ASSERT(rule != NULL);

  /* Calculate the total size of datagram */
  datagram_size = 10;

  if (rule->flags & SSH_APPGW_NBDGM_HAS_LENGTH_FIELD)
    datagram_size += 2;

  if (rule->flags & SSH_APPGW_NBDGM_HAS_OFFSET_FIELD)
    datagram_size += 2;

  if (rule->flags & SSH_APPGW_NBDGM_HAS_ERROR_FIELD)
    datagram_size += 1;

  if (rule->flags & SSH_APPGW_NBDGM_HAS_SOURCE_NAME)
    datagram_size += ssh_netbios_name_encoded_len(&datagram->src_name);

  if (rule->flags & SSH_APPGW_NBDGM_HAS_DESTINATION_NAME)
    datagram_size += ssh_netbios_name_encoded_len(&datagram->dest_name);

  if (rule->flags & SSH_APPGW_NBDGM_HAS_USER_DATA)
    datagram_size += datagram->user_data_size;

  /* Check maximum_length */
  if (datagram_size > rule->max_length)
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Failed to encode NetBIOS datagram.",
                            SSH_AUDIT_ARGUMENT_END);
      return NULL;
    }

  buffer = ssh_calloc(1, datagram_size);
  if (buffer == NULL)
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Running low on memory. NetBIOS datagram "
                            "dropped.",
                            SSH_AUDIT_ARGUMENT_END);
      return NULL;
    }

  cp = buffer;

#ifdef DEBUG_LIGHT

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Encoding NetBIOS Datagram (type = 0x%X)", datagram->msg_type));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- source_ip = %@", ssh_ipaddr_render, &datagram->src_ip));
  SSH_DEBUG(SSH_D_DATADUMP, ("- source_port = %u", datagram->src_port));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- datagram_id = 0x%04X", datagram->datagram_id));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- first_fragment = %u", datagram->first_fragment));
  SSH_DEBUG(SSH_D_DATADUMP,
            ("- more_fragments = %u", datagram->more_fragments));
  SSH_DEBUG(SSH_D_DATADUMP, ("- node_type = %u", datagram->node_type));

  if (rule->flags & SSH_APPGW_NBDGM_HAS_LENGTH_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- datagram_length = %u", datagram->datagram_length));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_OFFSET_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- packet_offset = %u", datagram->packet_offset));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_ERROR_FIELD)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- error_code = %u", datagram->error_code));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_SOURCE_NAME)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- source_name = \"%s\"", datagram->src_name.name));
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_DESTINATION_NAME)
    {
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- destination_name = \"%s\"", datagram->dest_name.name));
    }

#endif /* DEBUG_LIGHT */

  if (((initiator == TRUE) &&
       (rule->flags & SSH_APPGW_NBDGM_ALLOWED_FOR_INITIATOR) == 0) ||
      ((initiator == FALSE) &&
       (rule->flags & SSH_APPGW_NBDGM_ALLOWED_FOR_RESPONDER) == 0))
    {
      return NULL;
    }

  if (datagram->more_fragments)
    flags |= 0x01;
  if (datagram->first_fragment)
    flags |= 0x02;

  flags |= (datagram->node_type << 2);

  SSH_PUT_8BIT(cp+SSH_APPGW_NBDGM_TYPE_OFFSET, datagram->msg_type);
  SSH_PUT_8BIT(cp+SSH_APPGW_NBDGM_FLAGS_OFFSET, flags);
  SSH_PUT_16BIT(cp+SSH_APPGW_NBDGM_ID_OFFSET, datagram->datagram_id);
  SSH_IP4_ENCODE(&datagram->src_ip, cp+SSH_APPGW_NBDGM_ADDR_OFFSET);
  SSH_PUT_16BIT(cp+SSH_APPGW_NBDGM_PORT_OFFSET, datagram->src_port);

  cp += 10;
  /* */
  if (rule->flags & SSH_APPGW_NBDGM_HAS_LENGTH_FIELD)
    {
      SSH_PUT_16BIT(cp, datagram->datagram_length);
      cp += 2;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_ERROR_FIELD)
    {
      SSH_PUT_8BIT(cp, datagram->error_code);
      cp++;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_OFFSET_FIELD)
    {
      SSH_PUT_16BIT(cp, datagram->packet_offset);
      cp += 2;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_SOURCE_NAME)
    {
      size_t name_len = ssh_netbios_name_encoded_len(&datagram->src_name);

      ssh_netbios_name_encode(&datagram->src_name, cp, name_len);
      cp += name_len;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_DESTINATION_NAME)
    {
      size_t name_len = ssh_netbios_name_encoded_len(&datagram->dest_name);

      ssh_netbios_name_encode(&datagram->dest_name, cp, name_len);
      cp += name_len;
    }

  if (rule->flags & SSH_APPGW_NBDGM_HAS_USER_DATA)
    {
      memcpy(cp, datagram->user_data, datagram->user_data_size);
    }

  if (buffer_size)
    *buffer_size = datagram_size;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Encoded NetBIOS datagram:"),
                    buffer, datagram_size);

  return buffer;
}


static Boolean
ssh_appgw_netbios_name_lookup(SshAppgwNbDgmConnection conn,
                              SshNetBIOSName nb_name)
{
  SshNetBIOSName name = conn->source_names;

  while (name != NULL)
    {
      if ((name->type == nb_name->type) &&
          (name->name_len == nb_name->name_len) &&
          (strcmp((char *)name->name, (char *)nb_name->name) == 0) &&
          (((name->scope_id == NULL) && (nb_name->scope_id == NULL)) ||
           (strcmp((char *)name->scope_id, (char *)nb_name->scope_id) == 0)))
        {
          /* Name found */
          return TRUE;
        }

      name = name->next;
    }

  return FALSE;
}


static void
ssh_appgw_netbios_name_add(SshAppgwNbDgmConnection conn,
                           SshNetBIOSName source_name)
{
  SshNetBIOSName name;

  if (ssh_appgw_netbios_name_lookup(conn, source_name))
    return;

  name = ssh_calloc(1, sizeof(*name));
  if (name == NULL)
    return;

  *name = *source_name;
  name->next = conn->source_names;
  if (source_name->scope_id)
    name->scope_id = ssh_strdup(source_name->scope_id);

  conn->source_names = name;
}


/**************************** Decoding messages *****************************/

static void
ssh_appgw_netbios_dgm_call(SshAppgwNbDgmCtx nbdgm_alg,
                           SshAppgwNbDgmConnection conn,
                           const unsigned char *data, size_t data_len)
{
  SshAppgwNetbiosDatagramStruct datagram;

  ssh_netbios_datagram_init(&datagram);

  if (ssh_netbios_datagram_decode(conn, &datagram, data, data_len, TRUE))
    {
      unsigned char * buffer;
      size_t buffer_len;

      /* Replace source IP address and UDP port */
      datagram.src_ip = conn->instance->initiator_ip_after_nat;
      datagram.src_port = conn->instance->initiator_port_after_nat;

      ssh_appgw_netbios_name_add(conn, &datagram.src_name);

      buffer = ssh_netbios_datagram_encode(conn, &datagram,
                                           &buffer_len, TRUE);

      ssh_udp_send(conn->instance->responder_listener,
                   NULL, NULL, buffer, buffer_len);

      ssh_netbios_datagram_uninit(&datagram);
      ssh_free(buffer);
    }
}


static void
ssh_appgw_netbios_dgm_reply(SshAppgwNbDgmCtx nbdgm_alg,
                            SshAppgwNbDgmConnection conn,
                            const unsigned char *data, size_t data_len)
{
  SshAppgwNetbiosDatagramStruct datagram;

  ssh_netbios_datagram_init(&datagram);

  if (ssh_netbios_datagram_decode(conn, &datagram, data, data_len, TRUE))
    {
      /* Find correct connection. It's probably the current one, but we
         must check it because we share the the same UDP port (138) for all
         connections. */
      if (ssh_appgw_netbios_name_lookup(conn, &datagram.dest_name) == FALSE)
        {
          SshAppgwNbDgmConnection orig = conn;

          conn = nbdgm_alg->connections;
          while (conn)
            {
              if ((conn != orig) &&
                  ssh_appgw_netbios_name_lookup(conn, &datagram.dest_name))
                {
                  break;
                }

              conn = conn->next;
            }
        }

      if (conn)
        {
          unsigned char * buffer;
          size_t buffer_len;

          /* Replace source IP address and UDP port */
          datagram.src_ip = conn->instance->responder_ip_after_nat;
          datagram.src_port = conn->instance->responder_port_after_nat;

          buffer = ssh_netbios_datagram_encode(conn, &datagram,
                                               &buffer_len, FALSE);

          ssh_udp_send(conn->instance->initiator_listener,
                       NULL, NULL, buffer, buffer_len);

          ssh_free(buffer);
        }

      ssh_netbios_datagram_uninit(&datagram);
    }
}


static void
ssh_appgw_nbdgm_operation_timeout(void *context)
{
  SshAppgwNbDgmCtx nbdgm_alg = (SshAppgwNbDgmCtx) context;
  SshAppgwNbDgmConnection conn, next;

  conn = nbdgm_alg->connections;
  while (conn)
    {
      next = conn->next;

      if (--(conn->ttl) == 0)
        ssh_appgw_nbdgm_done(conn);

      conn = next;
    }

  ssh_register_timeout(&(nbdgm_alg->timeout), SSH_APPGW_NBDGM_TIMER, 0L,
                       ssh_appgw_nbdgm_operation_timeout, nbdgm_alg);
}


static void
ssh_appgw_nbdgm_connection_destroy(SshAppgwNbDgmConnection conn)
{
  SshNetBIOSName name;

  ssh_appgw_done(conn->instance);

  /* Free source name(s) */
  name = conn->source_names;
  while (name)
    {
      SshNetBIOSName next = name->next;

      ssh_free(name->scope_id);
      ssh_free(name);

      name = next;
    }

  ssh_free(conn);
}


static void
ssh_appgw_nbdgm_done(SshAppgwNbDgmConnection conn)
{
  SshAppgwNbDgmConnection p, prev;
  SshAppgwNbDgmCtx nbdgm_alg = (SshAppgwNbDgmCtx) conn->nbdgm_alg;

  prev = p = nbdgm_alg->connections;
  while (p)
    {
      if (p == conn)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Destroying connection %p", conn));
          if (p == nbdgm_alg->connections)
            {
              nbdgm_alg->connections = nbdgm_alg->connections->next;
              if (nbdgm_alg->connections)
                nbdgm_alg->connections->prev = NULL;
            }
          else
            {
              prev->next = p->next;
              if (prev->next)
                prev->next->prev = prev;
            }
          break;
        }
      prev = p;
      p = p->next;
    }

  ssh_appgw_nbdgm_connection_destroy(conn);
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_nbdgm_destroy(SshAppgwNbDgmCtx nbdgm_alg)
{
  ssh_cancel_timeouts(ssh_appgw_nbdgm_operation_timeout, nbdgm_alg);

  /* Free all connections. */
  while (nbdgm_alg->connections)
    {
      SshAppgwNbDgmConnection conn = nbdgm_alg->connections;
      nbdgm_alg->connections = conn->next;

      ssh_appgw_nbdgm_connection_destroy(conn);
    }

  if (nbdgm_alg->registered)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Unregistering from firewall"));
      ssh_appgw_unregister_local(nbdgm_alg->pm,
                                 SSH_APPGW_IDENT,
                                 SSH_APPGW_VERSION,
                                 SSH_IPPROTO_UDP);
    }

  ssh_free(nbdgm_alg);
}


static void
ssh_appgw_netbios_dgm_conn_cb(SshAppgwContext instance,
                             SshAppgwAction action,
                             const unsigned char *udp_data,
                             size_t udp_len,
                             void *context)
{
  SshAppgwNbDgmCtx nbdgm_alg = (SshAppgwNbDgmCtx) context;
  SshAppgwNbDgmConnection conn;

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("New configuration data for service %u:",
                         (unsigned int) instance->service_id),
                        instance->config_data, instance->config_data_len);
      break;

    case SSH_APPGW_SHUTDOWN:
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);

      /* Destroy the application gateway instance. */
      ssh_appgw_nbdgm_destroy(nbdgm_alg);
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New NetBIOS Datagram Service connection %@.%d > %@.%d",
                 ssh_ipaddr_render, &instance->initiator_ip,
                 instance->initiator_port,
                 ssh_ipaddr_render, &instance->responder_ip,
                 instance->responder_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &instance->initiator_ip_after_nat,
                 instance->initiator_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &instance->responder_ip_after_nat,
                 instance->responder_port));

      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Can't serve connection; reason: no space.",
                                SSH_AUDIT_ARGUMENT_END);

          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                        "%s: Can't serve connection; reason: no space.",
                        SSH_APPGW_NAME);
          ssh_appgw_done(instance);
          return;
        }

      /* Link it to the gateway's list of active connections. */
      conn->next = nbdgm_alg->connections;
      if (nbdgm_alg->connections)
        nbdgm_alg->connections->prev = conn;
      nbdgm_alg->connections = conn;

      conn->instance = instance;
      conn->nbdgm_alg = nbdgm_alg;
      instance->user_context = conn;

      conn->unique_id = nbdgm_alg->next_unique_id++;

      conn->ttl = SSH_APPGW_NBDGM_KEEPALIVE;
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet from initiator"));
      ssh_appgw_netbios_dgm_call(nbdgm_alg, instance->user_context,
                                 udp_data, udp_len);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet from responder"));
      ssh_appgw_netbios_dgm_reply(nbdgm_alg, instance->user_context,
                                  udp_data, udp_len);
      break;

    case SSH_APPGW_FLOW_INVALID:
      /* Framework destroyed flow, remove resources associated. */
      ssh_appgw_nbdgm_done(instance->user_context);
      break;
    }
}


static void
ssh_appgw_netbios_dgm_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwNbDgmCtx nbdgm_alg = (SshAppgwNbDgmCtx) context;

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
                    "%s: Can't start application gateway: "
                    "registration failed; reason %s.", SSH_APPGW_NAME, why);
      ssh_appgw_nbdgm_destroy(nbdgm_alg);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  nbdgm_alg->registered = 1;

  ssh_register_timeout(&(nbdgm_alg->timeout), SSH_APPGW_NBDGM_TIMER, 0L,
                       ssh_appgw_nbdgm_operation_timeout, nbdgm_alg);
}


void
ssh_appgw_netbios_dgm_init(SshPm pm)
{
  SshAppgwNbDgmCtx nbdgm_alg;
  SshAppgwParamsStruct params;

  nbdgm_alg = ssh_calloc(1, sizeof(*nbdgm_alg));
  if (nbdgm_alg == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      return;
    }
  nbdgm_alg->pm = pm;

  nbdgm_alg->next_unique_id = 1;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_IDENT;
  params.printable_name = "NetBIOS Datagram Service";
  params.version = SSH_APPGW_VERSION;
  params.ipproto = SSH_IPPROTO_UDP;
  params.flow_idle_timeout = 10;

  ssh_appgw_register_local(pm,
                           &params,
                           SSH_APPGW_F_NAT_KEEP_PORT
                           | SSH_APPGW_F_NAT_SHARE_PORT,
                           ssh_appgw_netbios_dgm_conn_cb, nbdgm_alg,
                           ssh_appgw_netbios_dgm_reg_cb, nbdgm_alg);
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
