/** 
    Decoding of DCE/RPC Protocol Data Units (PDUs). 
    
    <keywords DCE/RPC (Distributed Computing Environment / Remote 
    Procedure Calls), Distributed Computing Environment / Remote 
    Procedure Calls (DCE/RPC), RPC (Remote Procedure Call), Remote 
    Procedure Call (RPC), PDU (Protocol Data Unit), 
    Protocol Data Unit (PDU)>
 
    File: dce_rpc_pdu.h
 
    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved. 
 
 */

#ifndef SSH_DCE_RPC_PDU_H
#define SSH_DCE_RPC_PDU_H

#include "sshincludes.h"

/* ************************ Types and definitions ***************************/

/* ********************* Some well known object UUIDs ***********************/

/** Microsoft Security Account Manager. */
#define SSH_DCE_RPC_UUID_SAMR \
{0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}}

/** Microsoft Spool Subsystem. */
#define SSH_DCE_RPC_UUID_SPOOLSS  \
{0x12345678, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}}

/** Microsoft Server Service. */
#define SSH_DCE_RPC_UUID_SRVSVC \
{0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}}

/** Microsoft Registry. */
#define SSH_DCE_RPC_UUID_WINREG \
{0x338cd001, 0x2244, 0x31f1, {0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03}}

/** Microsoft Workstation Service. */
#define SSH_DCE_RPC_UUID_WKSSVC \
{0x6bffd098, 0xa112, 0x3610, {0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a}}


/** Definitions for 'pfc_flags' field of DCE/RPC PDUs. */
#define SSH_DCE_PFC_FIRST_FRAG      0x01
#define SSH_DCE_PFC_LAST_FRAG       0x02
#define SSH_DCE_PFC_PENDING_CANCEL  0x04
#define SSH_DCE_PFC_CONCURRENT_MPX  0x10
#define SSH_DCE_PFC_DID_NOT_EXECUTE 0x20
#define SSH_DCE_PFC_MAYBE           0x40
#define SSH_DCE_PFC_OBJECT_UUID     0x80

#define SSH_DCE_RPC_PDU_IS_FRAGMENTED(pdu)  \
  ((((pdu)->header.pfc_flags & 0x03) == 0x03) ? FALSE : TRUE)

/** Major version numbers of encoded DCE/RPC PDUs. */
typedef enum
{
  SSH_DCE_RPC_CL_MAJOR_VERSION = 4,   /** Connectionless PDUs. */
  SSH_DCE_RPC_CO_MAJOR_VERSION = 5    /** Connection-oriented PDUs. */
} SshDceRpcMajorVersion;


/** DCE/RPC PDU types. */
typedef enum
{
  SSH_DCE_RPC_PDU_REQUEST = 0, 	/** Request. */
  SSH_DCE_RPC_PDU_PING,       	/** Ping, connectionless. */
  SSH_DCE_RPC_PDU_RESPONSE, 	/** Response. */
  SSH_DCE_RPC_PDU_FAULT, 	/** Fault. */
  SSH_DCE_RPC_PDU_WORKING,    	/** Working, connectionless. */
  SSH_DCE_RPC_PDU_NOCALL,     	/** No call, connectionless. */
  SSH_DCE_RPC_PDU_REJECT,     	/** Reject, connectionless. */
  SSH_DCE_RPC_PDU_ACK,        	/** Acknowledge, connectionless. */
  SSH_DCE_RPC_PDU_CL_CANCEL,  	/** Cancel, connectionless. */
  SSH_DCE_RPC_PDU_FACK,       	/** Fragment ACK, connectionless. */
  SSH_DCE_RPC_PDU_CANCEL_ACK, 	/** Cancel ACK, connectionless. */
  SSH_DCE_RPC_PDU_BIND, 	/** Bind. */
  SSH_DCE_RPC_PDU_BIND_ACK, 	/** Bind ACK. */
  SSH_DCE_RPC_PDU_BIND_NAK, 	/** No acknowledgement. */
  SSH_DCE_RPC_PDU_ALTER_CONTEXT, 	/** Alter context. */
  SSH_DCE_RPC_PDU_ALTER_CONTEXT_RESP, 	/** Alter context response. */
  SSH_DCE_RPC_PDU_AUTH3, 	/** Auth3. */
  SSH_DCE_RPC_PDU_SHUTDOWN = 17, 	/** Shutdown. */
  SSH_DCE_RPC_PDU_CO_CANCEL, 	/** CO cancel. */
  SSH_DCE_RPC_PDU_ORPHANED 	/** Orphaned. */
} SshDceRpcPDUType;


/** Generic DCE/RPC data buffer. */
struct SshDceRpcDataBufferRec
{
  unsigned char *buffer;
  SshUInt16 size;
};

typedef struct SshDceRpcDataBufferRec SshDceRpcDataBufferStruct;
typedef struct SshDceRpcDataBufferRec *SshDceRpcDataBuffer;


/** DCE/RPC UUID. */
struct SshDceRpcUUIDRec
{
  SshUInt32 data1;
  SshUInt16 data2;
  SshUInt16 data3;
  SshUInt8  data4[8];
};

typedef struct SshDceRpcUUIDRec SshDceRpcUUIDStruct;
typedef struct SshDceRpcUUIDRec *SshDceRpcUUID;


/** DCE/RPC syntax ID. */
struct SshDceRpcSyntaxIDRec
{
  SshDceRpcUUIDStruct if_uuid;
  SshUInt32 if_version;
};

typedef struct SshDceRpcSyntaxIDRec SshDceRpcSyntaxIDStruct;
typedef struct SshDceRpcSyntaxIDRec *SshDceRpcSyntaxID;


/** DCE/RPC protocol version information. */
struct SshDceRpcVersionRec
{
  SshUInt8  major_version;
  SshUInt8  minor_version;
};

typedef struct SshDceRpcVersionRec SshDceRpcVersionStruct;
typedef struct SshDceRpcVersionRec *SshDceRpcVersion;

/** DCE/RPC protocol version list. */
struct SshDceRpcVersionListRec
{
  SshDceRpcVersion list;
  SshUInt8 items;
};

typedef struct SshDceRpcVersionListRec SshDceRpcVersionListStruct;
typedef struct SshDceRpcVersionListRec *SshDceRpcVersionList;


/** DCE/RPC presentation context. */
struct SshDceRpcContextRec
{
  struct SshDceRpcContextRec *next;
  SshDceRpcSyntaxIDStruct abstract_syntax;
  SshDceRpcSyntaxID transfer_syntaxes;
  SshUInt16 context_id;
  SshUInt8  number_of_syntaxes;
};

typedef struct SshDceRpcContextRec SshDceRpcContextStruct;
typedef struct SshDceRpcContextRec *SshDceRpcContext;


/** DCE/RPC presentation context list. */
struct SshDceRpcContextListRec
{
  SshDceRpcContext list;
  SshUInt8 items;
};

typedef struct SshDceRpcContextListRec SshDceRpcContextListStruct;
typedef struct SshDceRpcContextListRec *SshDceRpcContextList;


/** DCE/RPC context negotiation result. */
struct SshDceRpcResultRec
{
  SshUInt16 result;
  SshUInt16 reason;
  SshDceRpcSyntaxIDStruct transfer_syntax;
};

typedef struct SshDceRpcResultRec SshDceRpcResultStruct;
typedef struct SshDceRpcResultRec *SshDceRpcResult;


/** DCE/RPC context negotiation result list. */
struct SshDceRpcResultListRec
{
  SshDceRpcResult list;
  SshUInt8 items;
};

typedef struct SshDceRpcResultListRec SshDceRpcResultListStruct;
typedef struct SshDceRpcResultListRec *SshDceRpcResultList;


/** DCE/RPC authentication verifier. */
struct SshDceRpcAuthVerifierRec
{
  SshUInt16 length; 	/** The length specified in PDU header. */
  SshUInt8  type; 	/** Type. */
  SshUInt8  level; 	/** Level. */
  SshUInt32 context_id; 	/** Context ID. */
  unsigned char *credentials; 	/** Credentials. */
};

typedef struct SshDceRpcAuthVerifierRec SshDceRpcAuthVerifierStruct;
typedef struct SshDceRpcAuthVerifierRec *SshDceRpcAuthVerifier;


/** Common header of DCE/RPC PDU. */
struct SshDceRpcPDUHeaderRec
{
  SshUInt8 major_version;
  SshUInt8 minor_version;
  SshUInt8 packet_type;
  SshUInt8 pfc_flags;
  SshUInt16 frag_length;
  SshUInt16 auth_length;
  SshUInt32 call_id;

  SshUInt8  byte_order;
#define SSH_DCE_RPC_BIG_ENDIAN        0
#define SSH_DCE_RPC_LITTLE_ENDIAN     1

  SshUInt8  char_set;
#define SSH_DCE_RPC_CHAR_SET_ASCII    0
#define SSH_DCE_RPC_CHAR_SET_EBCDIC   1

  SshUInt8  float_type;
#define SSH_DCE_RPC_FLOAT_TYPE_IEEE   0
#define SSH_DCE_RPC_FLOAT_TYPE_VAX    1
#define SSH_DCE_RPC_FLOAT_TYPE_CRAY   2
#define SSH_DCE_RPC_FLOAT_TYPE_IBM    3
};

typedef struct SshDceRpcPDUHeaderRec SshDceRpcPDUHeaderStruct;
typedef struct SshDceRpcPDUHeaderRec *SshDceRpcPDUHeader;


/** "ALTER_CONTEXT" and "BIND" PDU specific fields. */
struct SshDceRpcAlterCtxRec
{
  SshUInt16 max_xmit_frag;
  SshUInt16 max_recv_frag;
  SshUInt32 group_id;

  /** Presentation context list. */
  SshDceRpcContextListStruct context_list;

  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcAlterCtxRec SshDceRpcAlterCtxStruct;
typedef struct SshDceRpcAlterCtxRec *SshDceRpcAlterCtx;
typedef struct SshDceRpcAlterCtxRec SshDceRpcBindStruct;
typedef struct SshDceRpcAlterCtxRec *SshDceRpcBind;


/** "ALTER_CONTEXT_RESP" and "BIND_ACK" PDU specific fields. */
struct SshDceRpcAlterCtxRespRec
{
  SshUInt16 max_xmit_frag;
  SshUInt16 max_recv_frag;
  SshUInt32 group_id;

  /** Secondary address. */
  SshDceRpcDataBufferStruct sec_addr;

  /** Presentation context result list. */
  SshDceRpcResultListStruct result_list;

  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcAlterCtxRespRec SshDceRpcAlterCtxRespStruct;
typedef struct SshDceRpcAlterCtxRespRec *SshDceRpcAlterCtxResp;
typedef struct SshDceRpcAlterCtxRespRec SshDceRpcBindAckStruct;
typedef struct SshDceRpcAlterCtxRespRec *SshDceRpcBindAck;


/** "BIND_NAK" PDU specific fields. */
struct SshDceRpcBindNakRec
{
  SshUInt16 reject_reason;

  /** Supported protocol versions. */
  SshDceRpcVersionListStruct supported_versions;
};

typedef struct SshDceRpcBindNakRec SshDceRpcBindNakStruct;
typedef struct SshDceRpcBindNakRec *SshDceRpcBindNak;


/** "CANCEL" and "ORPHANED" PDU specific fields. */
struct SshDceRpcCancelRec
{
  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcCancelRec SshDceRpcCancelStruct;
typedef struct SshDceRpcCancelRec *SshDceRpcCancel;
typedef struct SshDceRpcCancelRec SshDceRpcOrphanedStruct;
typedef struct SshDceRpcCancelRec *SshDceRpcOrphaned;


/** "FAULT" PDU specific fields. */
struct SshDceRpcFaultRec
{
  SshUInt32 alloc_hint;
  SshUInt16 context_id;
  SshUInt8 cancel_count;
  SshUInt32 status;

  /** Payload carried by this PDU. */
  SshDceRpcDataBufferStruct data;

  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcFaultRec SshDceRpcFaultStruct;
typedef struct SshDceRpcFaultRec *SshDceRpcFault;


/** "REQUEST" PDU specific fields. */
struct SshDceRpcRequestRec
{
  SshUInt32 alloc_hint;
  SshUInt16 context_id;
  SshUInt16 opnum;

  SshDceRpcUUID object;

  /** Payload carried by this PDU. */
  SshDceRpcDataBufferStruct data;

  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcRequestRec SshDceRpcRequestStruct;
typedef struct SshDceRpcRequestRec *SshDceRpcRequest;



/** "RESPONSE" PDU specific fields. */
struct SshDceRpcResponseRec
{
  SshUInt32 alloc_hint;
  SshUInt16 context_id;
  SshUInt8 cancel_count;

  /** Payload carried by this PDU. */
  SshDceRpcDataBufferStruct data;

  /** Authentication verifier. */
  SshDceRpcAuthVerifierStruct verifier;
};

typedef struct SshDceRpcResponseRec SshDceRpcResponseStruct;
typedef struct SshDceRpcResponseRec *SshDceRpcResponse;


/** "AUTH3" PDU specific fields (Microsoft's custom PDU). */
struct SshDceRpcAuth3Rec
{
  SshUInt32 magic_number;

  SshUInt8  auth_type;
  SshUInt8  auth_level;
  SshUInt8  auth_pad_len;
  SshUInt8  auth_reserved;
  SshUInt32 auth_context_id;

  /** Authentication data. */
  SshDceRpcDataBufferStruct data;
};

typedef struct SshDceRpcAuth3Rec SshDceRpcAuth3Struct;
typedef struct SshDceRpcAuth3Rec *SshDceRpcAuth3;


/** Connection-oriented DCE/RPC PDU. */
struct SshDceRpcPDURec
{
  SshDceRpcPDUHeaderStruct header;

  /** PDU-type specific fields. */
  union
  {
    SshDceRpcAlterCtxStruct alter_ctx;
    SshDceRpcAlterCtxRespStruct alter_ctx_resp;

    SshDceRpcBindStruct bind;
    SshDceRpcBindAckStruct bind_ack;
    SshDceRpcBindNakStruct bind_nak;

    SshDceRpcCancelStruct cancel;

    SshDceRpcFaultStruct fault;

    SshDceRpcOrphanedStruct orphaned;

    SshDceRpcRequestStruct request;
    SshDceRpcResponseStruct response;

    /** "SHUTDOWN" PDU does not contain any PDU specific fields. */

    SshDceRpcAuth3Struct auth3;
  } pdu;
};

typedef struct SshDceRpcPDURec SshDceRpcPDUStruct;
typedef struct SshDceRpcPDURec *SshDceRpcPDU;

/** Allocate and initialize a new (empty) DCE/RPC PDU context. */
SshDceRpcPDU ssh_dce_rpc_pdu_allocate(void);


/** Free a dynamically allocated DCE/RPC PDU context. */
void ssh_dce_rpc_pdu_free(SshDceRpcPDU pdu);


/** Initialize the given (pre-allocated) DCE/RPC PDU context. */
void ssh_dce_rpc_pdu_init(SshDceRpcPDU pdu);


/** Un-initialize the given DCE/RPC PDU context (frees all attached
    items, but doesn't free the PDU context). */
void ssh_dce_rpc_pdu_uninit(SshDceRpcPDU pdu);


/** Decode the specified DCE/RPC PDU into a memory block pointed to by
    'pdu_hdr'. 
    
    Unlike ssh_dce_rpc_pdu_decode(), this function does not make any 
    alignment assumptions (i.e. 'buffer' specifies the exact address 
    of header). 

    NOTE: This function currently supports only connection-oriented 
    DCE/RPC PDUs. 
         
    @return
    The encoded length (in bytes) of the header is optionally returned 
    in 'bytes_read'. Returns FALSE if the PDU header is malformed.

   */
Boolean ssh_dce_rpc_pdu_header_decode(SshDceRpcPDUHeader pdu_hdr,
                                      const unsigned char *buffer,
                                      SshUInt16 buffer_len,
                                      SshUInt16 *bytes_read);


/** Decode the DCE/RPC PDU indicated by 'buffer' of size of 'buffer_len'
    bytes into a memory block pointed to by 'pdu'. 

    If the 'buffer' does not contain an 8-byte aligned memory address, 
    this function expects that there are extra padding bytes at the 
    head of buffer. Possible alignment bytes are included to the 
    'bytes_read' returned by this function.

    NOTE: This function currently supports only connection-oriented 
    DCE/RPC PDUs. 

    @return
    The encoded length (in bytes) of PDU is optionally returned in 
    'bytes_read'. Returns FALSE if the PDU is malformed.
    
    */

Boolean ssh_dce_rpc_pdu_decode(SshDceRpcPDU pdu,
                               const unsigned char *buffer,
                               SshUInt16 buffer_len,
                               SshUInt16 *bytes_read);

#endif /* not SSH_DCE_RPC_PDU_H */
