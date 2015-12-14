/**

    Encoding and decoding of NBNS/WINS packets. 
    
    <keywords NBNS/WINS, WINS (Windows Internet Naming Service), 
    Windows Internet Naming Service (WINS), NetBIOS>
 
    File: wins_packet.h
 
    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved.
 
 */

#ifndef SSH_WINS_PACKET_H
#define SSH_WINS_PACKET_H

#include "sshincludes.h"
#include "sshinet.h"

/* ************************ Types and definitions ***************************/

#define SSH_WINS_MAX_PACKET_SIZE      512 	/** Maximum packet size. */
#define SSH_WINS_MAX_NAME_LEN         255 	/** Maximum name length. */
/** The length of the encoded NetBIOS name.*/
#define SSH_WINS_ENCODED_NB_NAME_LEN  32 	


typedef enum {
  SSH_WINS_QUERY = 0,
  SSH_WINS_REGISTRATION = 5,
  SSH_WINS_RELEASE = 6,
  SSH_WINS_WACK = 7,
  SSH_WINS_REFRESH = 8,
  SSH_WINS_MULTIHOMED_REGISTRATION = 15
} SshWINSOpCode;


typedef enum {
  SSH_WINS_OK = 0,
  SSH_WINS_FORMAT_ERROR = 1,
  SSH_WINS_SERVER_FAILURE = 2,
  SSH_WINS_UNIMPLEMENTED = 4,
  SSH_WINS_QUERY_REFUSED = 5,
  SSH_WINS_NAME_ACTIVE = 6,
  SSH_WINS_NAME_CONFLICT = 7
} SshWINSResponseCode;


typedef enum {
  SSH_WINS_CLASS_IN = 1
} SshWINSProtocolClass;


/** WINS resource definitions. */
typedef enum {
  SSH_WINS_RESOURCE_A = 0x01,         /** IP address. */
  SSH_WINS_RESOURCE_NS = 0x02,        /** Name server. */
  SSH_WINS_RESOURCE_NULL = 0x0A,      /** Null resource record. */
  SSH_WINS_RESOURCE_NB = 0x20,        /** Name service. */
  SSH_WINS_RESOURCE_NBSTAT = 0x21     /** Node status. */
} SshWINSResource;

typedef SshWINSResource SshWINSQuery;

/* These values orrespond directly to RFC 1002. */
#define SSH_WINS_FLAG_IS_RESPONSE           0x8000 	/** Response. */
#define SSH_WINS_FLAG_AUTHORITATIVE         0x0400 	/** Authoritative. */
#define SSH_WINS_FLAG_TRUNCATED             0x0200 	/** Truncated. */
/** Recursion desired.*/
#define SSH_WINS_FLAG_RECURSION_DESIRED     0x0100 	
/** Recursion available.*/
#define SSH_WINS_FLAG_RECURSION_AVAILABLE   0x0080 	
#define SSH_WINS_FLAG_BROADCAST             0x0010 	/** Broadcast. */

/* This flag is internal to the implementation. */
#define SSH_WINS_FLAG_BROKEN                0x0001

#define SSH_WINS_FLAG_MASK            \
(SSH_WINS_FLAG_IS_RESPONSE |          \
 SSH_WINS_FLAG_AUTHORITATIVE |        \
 SSH_WINS_FLAG_TRUNCATED |            \
 SSH_WINS_FLAG_RECURSION_DESIRED |    \
 SSH_WINS_FLAG_RECURSION_AVAILABLE |  \
 SSH_WINS_FLAG_BROADCAST)


/** NetBIOS name. */
struct SshNetBIOSNameRec
{
  /** Up to 15 characters long NetBIOS name. */
  unsigned char *name;

  /** Optional NetBIOS scope ID. */
  unsigned char *scope_id;

  /** NetBIOS name type. */
  SshUInt8 type;

  /** The length of NetBIOS name (can also be '*' with 14 NULLs). */
  SshUInt8 name_len;
};

typedef struct SshNetBIOSNameRec SshNetBIOSNameStruct;
typedef struct SshNetBIOSNameRec *SshNetBIOSName;


struct SshWINSQuestionRec
{
  SshNetBIOSNameStruct name;
  SshWINSQuery query;
  SshWINSProtocolClass protocol_class;
};

typedef struct SshWINSQuestionRec SshWINSQuestionStruct;
typedef struct SshWINSQuestionRec *SshWINSQuestion;


struct SshWINSAddressRec
{
  SshUInt16 flags;
  SshIpAddrStruct ip_addr;
};

typedef struct SshWINSAddressRec SshWINSAddressStruct;
typedef struct SshWINSAddressRec *SshWINSAddress;


struct SshWINSRecordRec
{
  SshNetBIOSNameStruct name;
  SshWINSResource resource;
  SshWINSProtocolClass protocol_class;
  SshUInt32 ttl;

  /** Either the length (in bytes) of the appended data or the number of
      appended address structures. */
  SshUInt16 data_len;

  void *data;
};

typedef struct SshWINSRecordRec SshWINSRecordStruct;
typedef struct SshWINSRecordRec *SshWINSRecord;


/** A NBNS/WINS packet header. */
struct SshWINSPacketHeaderRec
{
  SshUInt16 xid;
  SshUInt16 flags;
  SshWINSOpCode op_code;
  SshWINSResponseCode response_code;
  SshUInt16 num_questions;
  SshUInt16 num_answers;
  SshUInt16 num_additional_recs;
};

typedef struct SshWINSPacketHeaderRec SshWINSPacketHeaderStruct;
typedef struct SshWINSPacketHeaderRec *SshWINSPacketHeader;

/** A NBNS/WINS packet. */
struct SshWINSPacketRec
{
  SshWINSPacketHeaderStruct header;
  SshWINSQuestion question;
  SshWINSRecord answer;
  SshWINSRecord additional_rec;
};

typedef struct SshWINSPacketRec SshWINSPacketStruct;
typedef struct SshWINSPacketRec *SshWINSPacket;


/** Allocate a new (empty) WINS packet structure. */
SshWINSPacket ssh_wins_packet_allocate(void);


/** Free a WINS packet structure and all attached records. */
void ssh_wins_packet_free(SshWINSPacket packet);


/** Decode the header of WINS packet indicated by 'data' of size of 'data_len'
    bytes into the memory block pointed to by 'header'.

    @return
    Returns FALSE if the WINS header is malformed. */
Boolean ssh_wins_header_decode(SshWINSPacketHeader header,
                               const unsigned char *data,
                               SshUInt16 data_len);


/** Decode the WINS packet indicated by 'data' of size of 'data_len' bytes
    into the memory block pointed to by 'packet'. 
    
    @param decode_header
    Specifies whether the WINS header should also be decoded (if
    'decode_header' is FALSE, only the appended records are decoded).

    @return
    Returns FALSE if the message is malformed. */
Boolean ssh_wins_packet_decode(SshWINSPacket packet,
                               const unsigned char *data,
                               SshUInt16 data_len,
                               Boolean decode_header);


/** Encode the WINS packet indicated by 'message' into 'buffer'.

    @return
    Return FALSE if encoding can't be successfully performed. */
Boolean ssh_wins_packet_encode(SshWINSPacket packet,
                               SshBuffer buffer);


#endif /* not SSH_WINS_PACKET_H */
