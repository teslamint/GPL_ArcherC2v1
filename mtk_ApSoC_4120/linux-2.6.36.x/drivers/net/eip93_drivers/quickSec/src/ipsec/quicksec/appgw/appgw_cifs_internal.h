/**
 
   Internal definitions for the CIFS application gateway.
 
   File: appgw_cifs_internal.h
 
   @copyright
   Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved. 
 
 */

#ifndef APPGW_CIFS_INTERNAL_H
#define APPGW_CIFS_INTERNAL_H

#include "appgw_api.h"
#include "sshstream.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshfsm.h"
#include "sshutf8.h"
#include "dce_rpc_pdu.h"

/* ************************ Types and definitions ***************************/

/* The name of the application gateway as shown in syslog events. */
#define SSH_APPGW_CIFS_NAME   "CIFSALG"

/* Some error codes needed by this application gateway */
/*-- "NT" format --*/
#define SSH_APPGW_CIFS_E_BUFFER_OVERFLOW      0x80000005
#define SSH_APPGW_CIFS_E_UNSUCCESSFUL         0xC0000002
#define SSH_APPGW_CIFS_E_MORE_PROCESSING      0xC0000016
#define SSH_APPGW_CIFS_E_NO_MEMORY            0xC0000017
#define SSH_APPGW_CIFS_E_TOO_MANY_SESSIONS    0xC00000CE
#define SSH_APPGW_CIFS_E_CANCELLED            0xC0000120

/*-- "DOS" format --*/
#define SSH_APPGW_CIFS_D_E_CLASS_DOS          0x01
#define SSH_APPGW_CIFS_D_E_CLASS_SERVER       0x02
#define SSH_APPGW_CIFS_D_E_CLASS_HW           0x03
#define SSH_APPGW_CIFS_D_E_CLASS_CMD          0xFF
/* error codes for "DOS" class */
#define SSH_APPGW_CIFS_D_E_NO_MEMORY          0x0008
/* error codes for "SERVER" class */
#define SSH_APPGW_CIFS_D_E_ERROR              0x0001

/* Length of CIFS protocol ID */
#define SSH_APPGW_CIFS_PROTOCOL_ID_LEN        4
#define SSH_APPGW_CIFS_PROTOCOL_ID            "\xffSMB"

/* Minimum length of an embedded command */
/*   - number of parameter words (8 bit field) */
/*   - number of byte values (16 bit field) */
#define SSH_APPGW_SMB_ANDX_MIN_LEN            3

/* Maximum number of nested ANDX commands */
/* If this value is, for example 2, it means that the "major ANDX command"
   can contain an embedded ANDX command(s) having embedded "non-ANDX"
   commands */
#define SSH_APPGW_CIFS_MAX_NESTED_ANDX        2

/* Length of NetBIOS over TCP/IP packet header */
#define SSH_APPGW_CIFS_NBT_HEADER_LEN         4

/* Length of MS-DS packet header */
#define SSH_APPGW_CIFS_MSDS_HEADER_LEN        4

/* Maximum CIFS packet size (including transport header) */
/*   Samba 3.0 does not seem to always respect the negotiated maximum buffer
     size. (Sends too long response messages to transaction requests)
#define SSH_APPGW_CIFS_MAX_PACKET_SIZE        4100 
*/
#define SSH_APPGW_CIFS_MAX_PACKET_SIZE        20480 

/* Number of pre-allocated pending request contexts */
#define SSH_APPGW_CIFS_PREALLOC_REQUESTS      50

/* Number of pre-allocated transaction contexts */
#define SSH_APPGW_CIFS_PREALLOC_TRANSACTIONS  10

/* Maximum number of simultaneously pending requests */
#define SSH_APPGW_CIFS_MAX_REQUESTS           1000

/* Maximum number of simultaneously pending transactions */
#define SSH_APPGW_CIFS_MAX_TRANSACTIONS       200

/* Maximum size of "multi-part" I/0 request the application gateway accepts.
   (Bigger ones are considered as potential DoS attacks) */
#define SSH_APPGW_CIFS_MAX_MULTI_PART_IO_SIZE   65536

/* Application gateway waits max. 120 seconds for server's response */
#define SSH_APPGW_CIFS_REQUEST_TIMEOUT  120

/* "Don't care" value for CIFS 'uid', 'tid', 'mid', 'pid' and 'fid' */
#define SSH_APPGW_CIFS_ID_DONT_CARE     0xFFFF


/* Possible packet types of NetBIOS Session Service */
typedef enum
{
  SSH_APPGW_NBT_SESSION_MESSAGE = 0x00,
  SSH_APPGW_NBT_SESSION_REQUEST = 0x81,
  SSH_APPGW_NBT_SESSION_ACK = 0x82,
  SSH_APPGW_NBT_SESSION_NAK = 0x83,
  SSH_APPGW_NBT_SESSION_RETARGET = 0x84,
  SSH_APPGW_NBT_SESSION_KEEP_ALIVE = 0x85
} SshAppgwNbtSessionPacketType;


/* CIFS Version information */
typedef enum
{
  SSH_APPGW_CIFS_VERSION_PC_NW, /* "PC Network Program 1.0" */
  SSH_APPGW_CIFS_VERSION_CORE_PLUS,
  SSH_APPGW_CIFS_VERSION_LANMAN,  /* "LANMAN2.1" */
  SSH_APPGW_CIFS_VERSION_NTLM     /* "NT LM 0.12" */
} SshAppgwCifsVersion;


/* Well known CIFS/SMB commands */
typedef enum
{
  SSH_SMB_COM_CREATE_DIRECTORY = 0x00,
  SSH_SMB_COM_DELETE_DIRECTORY,
  SSH_SMB_COM_OPEN,
  SSH_SMB_COM_CREATE,
  SSH_SMB_COM_CLOSE,
  SSH_SMB_COM_FLUSH,
  SSH_SMB_COM_DELETE,
  SSH_SMB_COM_RENAME,
  SSH_SMB_COM_QUERY_INFORMATION,
  SSH_SMB_COM_SET_INFORMATION,
  SSH_SMB_COM_READ,
  SSH_SMB_COM_WRITE,
  SSH_SMB_COM_LOCK_BYTE_RANGE,
  SSH_SMB_COM_UNLOCK_BYTE_RANGE,
  SSH_SMB_COM_CREATE_TEMPORARY,
  SSH_SMB_COM_CREATE_NEW,
  SSH_SMB_COM_CHECK_DIRECTORY,
  SSH_SMB_COM_PROCESS_EXIT,
  SSH_SMB_COM_SEEK,
  SSH_SMB_COM_LOCK_AND_READ,
  SSH_SMB_COM_WRITE_AND_UNLOCK,
  SSH_SMB_COM_READ_RAW = 0x1A,
  SSH_SMB_COM_READ_MPX,
  SSH_SMB_COM_READ_MPX_SECONDARY,
  SSH_SMB_COM_WRITE_RAW,
  SSH_SMB_COM_WRITE_MPX,
  SSH_SMB_COM_WRITE_COMPLETE = 0x20,
  SSH_SMB_COM_SET_INFORMATION2 = 0x22,
  SSH_SMB_COM_QUERY_INFORMATION2,
  SSH_SMB_COM_LOCKING_ANDX,
  SSH_SMB_COM_TRANSACTION,
  SSH_SMB_COM_TRANSACTION_SECONDARY,
  SSH_SMB_COM_IOCTL,
  SSH_SMB_COM_IOCTL_SECONDARY,
  SSH_SMB_COM_COPY,
  SSH_SMB_COM_MOVE,
  SSH_SMB_COM_ECHO,
  SSH_SMB_COM_WRITE_AND_CLOSE,
  SSH_SMB_COM_OPEN_ANDX,
  SSH_SMB_COM_READ_ANDX,
  SSH_SMB_COM_WRITE_ANDX,
  SSH_SMB_COM_CLOSE_AND_TREE_DISC = 0x31,
  SSH_SMB_COM_TRANSACTION2,
  SSH_SMB_COM_TRANSACTION2_SECONDARY,
  SSH_SMB_COM_FIND_CLOSE2,
  SSH_SMB_COM_FIND_NOTIFY_CLOSE,
  SSH_SMB_COM_TREE_CONNECT = 0x70,
  SSH_SMB_COM_TREE_DISCONNECT,
  SSH_SMB_COM_NEGOTIATE,
  SSH_SMB_COM_SESSION_SETUP_ANDX,
  SSH_SMB_COM_LOGOFF_ANDX,
  SSH_SMB_COM_TREE_CONNECT_ANDX,
  SSH_SMB_COM_QUERY_INFORMATION_DISK = 0x80,
  SSH_SMB_COM_SEARCH,
  SSH_SMB_COM_FIND,
  SSH_SMB_COM_FIND_UNIQUE,
  SSH_SMB_COM_NT_TRANSACTION = 0xA0,
  SSH_SMB_COM_NT_TRANSACTION_SECONDARY,
  SSH_SMB_COM_NT_CREATE_ANDX,
  SSH_SMB_COM_NT_CANCEL = 0xA4,
  SSH_SMB_COM_NT_RENAME,
  SSH_SMB_OPEN_PRINT_FILE = 0xC0,
  SSH_SMB_WRITE_PRINT_FILE,
  SSH_SMB_CLOSE_PRINT_FILE,
  SSH_SMB_GET_PRINT_QUEUE,
  SSH_SMB_SEND_SINGLE_BLOCK = 0xD0
} SshAppgwCifsCmdType;


/* Named pipe transaction subcommand codes */
typedef enum
{
  SSH_SMB_PRC_PIPE_SET_STATE = 0x01,
  SSH_SMB_RPC_PIPE_READ_RAW = 0x11,
  SSH_SMB_RPC_PIPE_QUERY_STATE = 0x21,
  SSH_SMB_RPC_PIPE_QUERY_INFO,
  SSH_SMB_RPC_PIPE_PEEK,
  SSH_SMB_RPC_PIPE_TRANSACT = 0x26,
  SSH_SMB_RPC_PIPE_WRITE_RAW = 0x31,
  SSH_SMB_RPC_PIPE_WAIT = 0x53,
  SSH_SMB_RPC_PIPE_CALL,
} SshAppgwCifsPipeCommand;


/* SMB_COM_TRANSACTION2 subcommand codes */
typedef enum
{
  SSH_SMB_TRANSACT2_OPEN2,
  SSH_SMB_TRANSACT2_FIND_FIRST2,
  SSH_SMB_TRANSACT2_FIND_NEXT2,
  SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION,
  SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION = 0x05,
  SSH_SMB_TRANSACT2_SET_PATH_INFORMATION,
  SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION,
  SSH_SMB_TRANSACT2_SET_FILE_INFORMATION,
  SSH_SMB_TRANSACT2_CREATE_DIRECTORY = 0x0D,
  SSH_SMB_TRANSACT2_SESSION_SETUP,
  SSH_SMB_TRANSACT2_GET_DFS_REFERRAL = 0x10,
  SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY
} SshAppgwCifsTransact2Code;


/* Well-known file system information levels */
typedef enum
{
  SSH_SMB_INFO_FS_ALLOCATION = 1,
  SSH_SMB_INFO_FS_VOLUME = 2,
  SSH_SMB_INFO_FS_QUERY_VOLUME_INFO = 0x102,
  SSH_SMB_INFO_FS_QUERY_SIZE_INFO,
  SSH_SMB_INFO_FS_QUERY_DEVICE_INFO,
  SSH_SMB_INFO_FS_QUERY_ATTRIBUTE_INFO
} SshAppgwCifsFsInfoLevel;


/* Well-known file information levels */
typedef enum
{
  SSH_SMB_INFO_FILE_STANDARD = 1,
  SSH_SMB_INFO_FILE_QUERY_EA_SIZE,
  SSH_SMB_INFO_FILE_QUERY_EAS_FROM_LIST,
  SSH_SMB_INFO_FILE_QUERY_ALL_EAS,
  SSH_SMB_INFO_FILE_IS_NAME_VALID = 6,
  SSH_SMB_INFO_FILE_QUERY_BASIC_INFO = 0x101,
  SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO,
  SSH_SMB_INFO_FILE_QUERY_EA_INFO,
  SSH_SMB_INFO_FILE_QUERY_NAME_INFO,
  SSH_SMB_INFO_FILE_QUERY_ALL_INFO = 0x107,
  SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO,
  SSH_SMB_INFO_FILE_QUERY_STREAM_INFO,
  SSH_SMB_INFO_FILE_QUERY_COMPRESSION = 0x10B,
  SSH_SMB_INFO_FILE_QUERY_BASIC_INFO2 = 0x3EC,
  SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO2 = 0x3ED,
  SSH_SMB_INFO_FILE_QUERY_EA_INFO2,
  SSH_SMB_INFO_FILE_QUERY_NAME_INFO2 = 0x3F1,
  SSH_SMB_INFO_FILE_QUERY_ALL_INFO2 = 0x3FA,
  SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO2 = 0x3FD,
  SSH_SMB_INFO_FILE_QUERY_STREAM_INFO2,
  SSH_SMB_INFO_FILE_QUERY_COMPRESSION2 = 0x404
} SshAppgwCifsFileInfoLevel;


/* Well-known find/search information levels */
typedef enum
{
  SSH_SMB_INFO_SEARCH_STANDARD = 1,
  SSH_SMB_INFO_SEARCH_QUERY_EA_SIZE,
  SSH_SMB_INFO_SEARCH_QUERY_EAS_FROM_LIST,
  SSH_SMB_INFO_SEARCH_DIRECTORY_INFO = 0x101,
  SSH_SMB_INFO_SEARCH_FULL_DIRECTORY_INFO,
  SSH_SMB_INFO_SEARCH_NAMES_INFO,
  SSH_SMB_INFO_SEARCH_BOTH_DIRECTORY_INFO
} SshAppgwCifsSearchInfoLevel;


/* SMB_COM_NT_TRANSACTION subcommand codes */
typedef enum
{
  SSH_SMB_NT_TRANSACT_CREATE = 1,
  SSH_SMB_NT_TRANSACT_IOCTL,
  SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC,
  SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE,
  SSH_SMB_NT_TRANSACT_RENAME,
  SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC,
} SshAppgwCifsNtTransactCode;


/* CIFS/SMB data buffer formats */
typedef enum
{
  /* "Raw data" */
  SSH_APPGW_CIFS_DATA_BLOCK = 1,

  /* 0x02 followed by NULL-terminated ASCII string */
  SSH_APPGW_CIFS_DATA_DIALECT,

  /* "Raw data" */
  SSH_APPGW_CIFS_DATA_PATHNAME,

  /* 0x04 followed by either UNICODE or ASCII string */
  SSH_APPGW_CIFS_DATA_STRING,

  /* "Raw data" */
  SSH_APPGW_CIFS_DATA_VARIABLE_BLOCK
} SshAppgwCifsDataFormat;


/* Status of CIFS Session */
typedef enum
{
  SSH_APPGW_CIFS_SESSION_NEGOTIATING,
  SSH_APPGW_CIFS_SESSION_AUTHENTICATING,
  SSH_APPGW_CIFS_SESSION_STEADY,
  SSH_APPGW_CIFS_SESSION_CLOSED
} SshAppgwCifsSessionStatus;


/* Possible transport layers for CIFS connections */
typedef enum
{
  SSH_APPGW_CIFS_TRANSPORT_NBT, /* NetBIOS over TCP/IP */
  SSH_APPGW_CIFS_TRANSPORT_MSDS /* TCP (Microsoft Direct SMB Service) */
} SshAppgwCifsTransportType;


/* Phases of NetBIOS Session Service (RFC 1001) */
typedef enum
{
  SSH_APPGW_NBT_SESSION_ESTABLISHMENT,
  SSH_APPGW_NBT_SESSION_STEADY,
  SSH_APPGW_NBT_SESSION_CLOSED
} SshAppgwNbtSessionPhase;


/* CIFS packet decoding phases */
typedef enum
{
  SSH_APPGW_CIFS_READ_TRANSPORT_HEADER,
  SSH_APPGW_CIFS_DECODE_TRANSPORT_HEADER,
  SSH_APPGW_CIFS_READ_PACKET,
  SSH_APPGW_CIFS_DECODE_HEADER,
  SSH_APPGW_CIFS_FILTER_COMMAND,
  SSH_APPGW_CIFS_FILTER_ANDX
} SshAppgwCifsDecodePhase;


/* Types of handles internally used by CIFS application level gateway */
typedef enum
{
  SSH_APPGW_CIFS_FILE_HANDLE,
  SSH_APPGW_CIFS_SEARCH_HANDLE
} SshAppgwCifsHandleType;


/* NetBIOS over TCP/IP transport layer specific context data */
struct SshAppgwNbtTransportRec
{
  /* RFC 1001: 16.1 */
  SshAppgwNbtSessionPhase session_phase;

  /* Decoded NetBIOS names */
  unsigned char called_name[17];
  unsigned char calling_name[17];
};

typedef struct SshAppgwNbtTransportRec SshAppgwNbtTransportStruct;
typedef struct SshAppgwNbtTransportRec *SshAppgwNbtTransport;


/* Prototype of callback funtion for deleting CIFS command specific context
   data. */
typedef void (*SshAppgwCifsCtxDeleteCb)(void * context);


/* Context data for embedded CIFS ("ANDX") commands */
struct SshAppgwCifsEmbeddedCmdRec
{
  /* Type of command */
  SshAppgwCifsCmdType command;

  /* Pointer to next chained command */
  struct SshAppgwCifsEmbeddedCmdRec *next;

  /* Pointer to context structure */
  struct SshAppgwCifsCmdCtxSlotRec *context;
};

typedef struct SshAppgwCifsEmbeddedCmdRec SshAppgwCifsEmbeddedCmdStruct;
typedef struct SshAppgwCifsEmbeddedCmdRec *SshAppgwCifsEmbeddedCmd;


/* CIFS/SMB command specific context data */
struct SshAppgwCifsCmdCtxSlotRec
{
  /* Pointer to next chained structure */
  struct SshAppgwCifsCmdCtxSlotRec *next;

  /* Context and delete callback */
  void * context;
  SshAppgwCifsCtxDeleteCb delete_cb;

  /* Flags */
  unsigned int pre_allocated : 1;
  unsigned int andx_context : 1;  /* This context is used by embedded
                                     command */
};

typedef struct SshAppgwCifsCmdCtxSlotRec SshAppgwCifsCmdCtxSlotStruct;
typedef struct SshAppgwCifsCmdCtxSlotRec *SshAppgwCifsCmdCtxSlot;


/* Context data for pending CIFS/SMB requests */
struct SshAppgwCifsRequestRec
{
  SshADTBagHeaderStruct adt_header;

  /* Pointer to connection context */
  struct SshAppgwCifsConnRec *conn;

  /* Pointer to next request */
  struct SshAppgwCifsRequestRec *next;

  SshAppgwCifsCmdType command;
  SshUInt16 uid;  /* User ID */
  SshUInt16 pid;  /* Process ID */
  SshUInt16 tid;  /* Tree ID */
  SshUInt16 mid;  /* Multiplex ID */

  SshUInt16 fid;  /* Optional file ID */

  SshUInt16 response_timeout;  /* Maximum waiting time (in seconds) for
                                  the response */

  /* flags */
  unsigned int pre_allocated : 1; /* Specifies whether this structure is a
                                     pre-allocated one that should not be
                                     freed after use */
  unsigned int timeout_disabled : 1;  /* If set, this request won't be
                                         deleted after a timeout period. */
  unsigned int timeout : 1; /* No response from server before timeout */
  unsigned int more_processing : 1; /* The transaction is not complete
                                       yet, Request should not be deleted. */
  unsigned int canceled : 1;  /* Request has been canceled by client */
  unsigned int busy : 1;      /* Request can't be deleted before this flag
                                 is cleared */

  /* optional context structures */
  SshAppgwCifsCmdCtxSlot cmd_ctx;

  /* List of embedded commands */
  SshAppgwCifsEmbeddedCmd andx_commands;
};

typedef struct SshAppgwCifsRequestRec SshAppgwCifsRequestStruct;
typedef struct SshAppgwCifsRequestRec *SshAppgwCifsRequest;


/* Context data for CIFS/SMB transactions and IOCTL requests */
struct SshAppgwCifsTransactionRec
{
  /* Pointer to connection context */
  struct SshAppgwCifsConnRec *conn;

  /* Pointer to next transaction */
  struct SshAppgwCifsTransactionRec *next;

  struct
  {
    /* Total nummber of parameter and data bytes client will send */
    SshUInt32 total_param_count;
    SshUInt32 total_data_count;

    /* Number of parameter and data bytes sent so far */
    SshUInt32 param_count;
    SshUInt32 data_count;

    /* Buffers containing parameter and data bytes */
    unsigned char *params;
    unsigned char *data;
  } client;

  struct
  {
    /* Client specified maximum total numbers of parameter and data bytes
       the server may send. */
    SshUInt32 max_param_count;
    SshUInt32 max_data_count;

    /* Server specified total numbers of parameter and data bytes */
    SshUInt32 total_param_count;
    SshUInt32 total_data_count;

    /* Number of parameter and data bytes received so far */
    SshUInt32 param_count;
    SshUInt32 data_count;

    /* Maximum number of setup words the server may sent */
    SshUInt8 max_setup_count;

    /* Total number of setup words received */
    SshUInt8 setup_count;

    /* Buffers containing parameter and data bytes */
    unsigned char *params;
    unsigned char *data;
  } server;

  /* Flags: */
  unsigned int pre_allocated : 1;   /* Set if this is a pre-allocated
                                       transaction context */
  unsigned int pipe_transaction : 1;  /* Set if this is a pipe trnasaction */
  unsigned int dce_rpc : 1;           /* Set if this is DCE/RPC transaction */
  unsigned int interim_response_received : 1; /* Interim response received
                                                 from server */

  unsigned int first_request : 1;   /* We are filtering the first transaction
                                       request */
  unsigned int request_params_copied : 1;
  unsigned int request_params_checked : 1;

  unsigned int request_data_copied : 1;
  unsigned int request_data_checked : 1;

  unsigned int first_response : 1;  /* We are filtering the first transaction
                                       response */
  unsigned int response_params_copied : 1;
  unsigned int response_params_checked : 1;

  unsigned int response_data_copied : 1;
  unsigned int response_data_checked : 1;

  /* Associated file ID */
  SshUInt16 fid;

  /* Device category (used only with IOCTL commands) */
  SshUInt16 category;

  /* Subcommand code of the transaction */
  SshUInt16 subcommand;

  /* Additional information level code used with some subcommands */
  SshUInt16 info_level;

  /* Additional context, which can be used when some subcommand specific
     information must be stored */
  void *context;

  /* Pointer to name of transaction or path or filename associated with the
     transaction subcommand. This points either to appended 'name' buffer or
     dynamically allocated block */
  unsigned char *name_ptr;

  /* Preallocated block for name. This block is used, if the name is short
     enough to fit in this buffer */
  unsigned char name[16];
};

typedef struct SshAppgwCifsTransactionRec SshAppgwCifsTransactionStruct;
typedef struct SshAppgwCifsTransactionRec *SshAppgwCifsTransaction;


/* Context data for ANDX commands having embedded SMB commands */
struct SshAppgwCifsAndxCmdCtxRec
{
  /* Type of the command carrying embedded SMB commands */
  SshAppgwCifsCmdType carrier_cmd;

  /* Type of currently parsed embedded command */
  SshAppgwCifsCmdType embedded_cmd;

  /* Offset to next command */
  SshUInt16 offset;
};

typedef struct SshAppgwCifsAndxCmdCtxRec SshAppgwCifsAndxCmdCtxStruct;
typedef struct SshAppgwCifsAndxCmdCtxRec *SshAppgwCifsAndxCmdCtx;


/* Context data for CIFS/SMB parser */
struct SshAppgwCifsParserRec
{
  /* Decoding phase */
  SshAppgwCifsDecodePhase decode_phase;

  /* Transport layer (NetBIOS over TCP/IP / Microsoft-DS) specific
     information */
  union
  {
    /* NetBIOS over TCP/IP */
    struct
    {
      size_t packet_length;
      SshUInt8 packet_type;
    } nbt;

    /* TCP (Microsoft Direct SMB Service) */
    struct
    {
      size_t packet_length;
    } msds;
  } transport;

  /* Size (in bytes) of SMB/CIFS packet (excluding transport headers) */
  size_t packet_size;

  /* Pointer to beginning of SMB/CIFS packet */
  unsigned char * packet_ptr;

  SshAppgwCifsCmdType command;

  /* Error code either in NT or DOS format. Flag "nt_error_codes" specifies
     which one is in use */
  union
  {
    struct
    {
      SshUInt32 error_code;
    } nt;

    struct
    {
      SshUInt8  error_class;
      SshUInt16 error_code;
    } dos;
  } error;

  SshUInt16 tid;  /* tree identifier */
  SshUInt16 pid;  /* process identifier */
  SshUInt16 uid;  /* unauthenticated user id */
  SshUInt16 mid;  /* multiplex id */
  SshUInt16 fid;  /* Optional file ID */
  SshUInt8 word_count;
  void *parameters;
  SshUInt16 byte_count; /* number of bytes in buffer */
  void *buffer;


  /* Interpreted flags */
  unsigned int client : 1;  /* Specifies whether source is client */
  unsigned int embedded_cmds : 1;  /* Packet contains appended commands */
  unsigned int is_andx_command : 1; /* Set if the currently parsed command
                                       is an "ANDX" command */
  unsigned int transaction : 1;    /* This is transaction command */
  unsigned int response : 1;  /* This is a command response */
  unsigned int command_failed : 1;  /* Command failed */
  unsigned int nt_error_codes : 1;  /* DOS or NT style error codes? */
  unsigned int unicode_strings : 1; /* Strings are in UNICODE format */
  unsigned int no_response : 1;     /* We don't expect response from server
                                       (one-way transaction) */
  unsigned int no_timeout : 1;      /* We should not register timeout for
                                       this request. */

  /* Timeout (in seconds) for response */
  SshUInt16 response_wait_time;

  /* CIFS application gateway specific tree context */
  struct SshAppgwCifsTreeRec *tree;

  /* Contains the information of next embedded command (when embedded_cmds
     flag is set) */
  unsigned int andx_depth_level;
  SshAppgwCifsAndxCmdCtx andx_ctx;
  SshAppgwCifsAndxCmdCtxStruct andx[SSH_APPGW_CIFS_MAX_NESTED_ANDX];

  /* Original request (used only when parsing CIFS responses) */
  SshAppgwCifsRequest orig_request;

  /* List of slots holding additional SMB/CIFS request/response
     specific contexts */
  SshAppgwCifsCmdCtxSlot cmd_ctx;
  SshAppgwCifsCmdCtxSlot first_cmd_ctx;

  /* List of embedded commands */
  SshAppgwCifsEmbeddedCmd andx_commands;
};

typedef struct SshAppgwCifsParserRec SshAppgwCifsParserStruct;
typedef struct SshAppgwCifsParserRec *SshAppgwCifsParser;

/* An I/O structure for unidirectional communication. */
struct SshAppgwCifsIORec
{
  /* Flags. */
  unsigned int active : 1;      /* Thread active. */
  unsigned int terminate : 1;   /* Terminate when already read data
                                   has been flushed. */

  /* Source stream. */
  SshStream src;

  /* Destination stream. */
  SshStream dst;

  /* Current target stream for write operation (src or dst) */
  SshStream target_stream;

  /* Buffer for data being copied. */

  /* Unaligned buffer */
  unsigned char _unaligned_buffer[SSH_APPGW_CIFS_MAX_PACKET_SIZE+8];

  /* Correctly aligned buffer */
  unsigned char *buf;
  size_t header_len;
  size_t data_in_buf;
  size_t bytes_to_read;
  size_t bufpos;

  /* State functions depending from transport layer */
  SshFSMStepCB first_step;
  SshFSMStepCB read_complete_step;

  /* Pointer to the connection structure. */
  struct SshAppgwCifsConnRec *conn;

  /* CIFS parser specific context data */
  SshAppgwCifsParserStruct cifs_parser;
};

typedef struct SshAppgwCifsIORec SshAppgwCifsIOStruct;
typedef struct SshAppgwCifsIORec *SshAppgwCifsIO;


/* A Common Internet File System connection through the gateway. */
struct SshAppgwCifsConnRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwCifsConnRec *next;
  struct SshAppgwCifsConnRec *prev;

  /* Flags. */
  unsigned int user_level_security : 1;     /* Negotiated security for */
  unsigned int use_challenge_response : 1;  /* this connection */
  unsigned int use_encrypted_passwords : 1;
  unsigned int security_signatures_enabled : 1;
  unsigned int security_signatures_required : 1;

  /* The application gateway context. */
  SshAppgwContext ctx;

  /* Thread handling the initiator->responder communication. */
  SshFSMThreadStruct thread_i;
  SshAppgwCifsIOStruct io_i;

  /* Thread handling the responder->initiator communication. */
  SshFSMThreadStruct thread_r;
  SshAppgwCifsIOStruct io_r;

  /* SMB/CIFS session phase */
  SshAppgwCifsSessionStatus session_phase;

  /* Currently active sessions */
  SshADTContainer active_sessions;

  /* Currently connected trees on server */
  SshADTContainer connected_trees;

  /* Open handles */
  SshADTContainer open_handles;

  /* Currently pending requests */
  SshADTContainer pending_requests;

  /* Negotiated CIFS/SMB version */
  SshAppgwCifsVersion cifs_version;

  /* Negotiated maximum number of concurrently pending requests */
  SshUInt16 max_pending_requests;

  /* Negotiated maximum number of concurrent sessions */
  SshUInt16 max_sessions;

  /* Negotiated mamimum buffer size */
  SshUInt16 max_buffer_size;

  /* Client capability flags */
  struct
  {
    unsigned int nt_smbs : 1; /* Supports "NT LM 0.12" specific commands */
    unsigned int large_files : 1; /* Supports files with 64-bit offsets */
    unsigned int nt_error_codes : 1; /* Supports NT style error codes */
    unsigned int unicode : 1; /* Can use UNICODE strings */
  } client_flags;

  /* Server capability flags */
  struct
  {
    unsigned int nt_smbs : 1; /* Supports "NT LM 0.12" specific commands */
    unsigned int rpc: 1;      /* Supports RPC remote APIs */
    unsigned int large_files : 1; /* Supports files with 64-bit offsets */
    unsigned int ext_security : 1;  /* Supports extended security */
    unsigned int caseless_pahtnames : 1; /* Doesn't support case-sensitive
                                            path and filenames */
    unsigned int long_filenames : 1; /* Supports long filenames */
    unsigned int nt_error_codes : 1; /* can use NT style error codes */
    unsigned int unicode : 1;        /* can use UNICODE strings */
  } server_flags;

  /* Type and human readable name of CIFS transport */
  SshAppgwCifsTransportType transport_type;
  const unsigned char *transport_name;

  /* Transport layer specific information */
  union
  {
    /* NetBIOS over TCP/IP */
    SshAppgwNbtTransportStruct nbt;

  } transport;
};

typedef struct SshAppgwCifsConnRec SshAppgwCifsConnStruct;
typedef struct SshAppgwCifsConnRec *SshAppgwCifsConn;


/* Context data for Common Internet File System gateways. */
struct SshAppgwCifsCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* FSM controlling the gateway. */
  SshFSMStruct fsm;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */
  unsigned int shutdown : 1;    /* The system is shutting down. */

  /* Active NBT Session Service connections through this gateway. */
  SshAppgwCifsConn connections;

  /* For UNICODE -> ASCII character set conversion */
  SshChrConv unicode_to_ascii;

  /* Current amount of simultaneously pending reguests and transactions */
  SshUInt32 num_requests;
  SshUInt32 num_transactions;

  /* Some pre-allocated contexts to reduce the amount of dynamic memory
     allocations. */
  struct SshAppgwCifsRequestRec *free_requests;

  struct SshAppgwCifsRequestRec
    preallocated_requests[SSH_APPGW_CIFS_PREALLOC_REQUESTS];

  /* Some pre-allocated transaction contexts to reduce the amount of
     dynamic memory allocations */
  struct SshAppgwCifsTransactionRec *free_transactions;

  struct SshAppgwCifsTransactionRec
    preallocated_transactions[SSH_APPGW_CIFS_PREALLOC_TRANSACTIONS];

  /* Some pre-allocated CIFS command contexts to reduce the amount of
     dynamic memory allocations */
  struct SshAppgwCifsCmdCtxSlotRec *free_cmd_ctxs;

  struct SshAppgwCifsCmdCtxSlotRec
    preallocated_ctx_slots[SSH_APPGW_CIFS_PREALLOC_REQUESTS];
};

typedef struct SshAppgwCifsCtxRec SshAppgwCifsCtxStruct;
typedef struct SshAppgwCifsCtxRec *SshAppgwCifsCtx;


/* Context data for CIFS sessions and virtual circuits */
struct SshAppgwCifsSessionRec
{
  SshADTBagHeaderStruct adt_header;

  /* Pointer to connection context */
  SshAppgwCifsConn conn;

  SshUInt16 id;  /* Session ID */

  SshUInt16 vc_number;  /* Virtual circuit #; zero if primary session */

  /* Account information */
  char *account;
  char *domain;

  unsigned int null_session : 1;  /* This is a NULL session (i.e. anonymous
                                  logon) */
  unsigned int ext_authentication : 1;  /* Extended authentication used in
                                           session setup */
};

typedef struct SshAppgwCifsSessionRec SshAppgwCifsSessionStruct;
typedef struct SshAppgwCifsSessionRec *SshAppgwCifsSession;


/* Context data for connected trees */
struct SshAppgwCifsTreeRec
{
  SshADTBagHeaderStruct adt_header;

  /* Pointer to connection context */
  SshAppgwCifsConn conn;

  SshUInt16 tid;  /* Tree ID */

  /* flags */
  unsigned int ipc_service : 1; /* Set if service type is "IPC" */

  /* The tree name is appended here in ASCII format, so the actual length of
     this structure depends from the length of the name. */
  unsigned char name[1];
  /* ***** Don't add anything here! *******/
};


typedef struct SshAppgwCifsTreeRec SshAppgwCifsTreeStruct;
typedef struct SshAppgwCifsTreeRec *SshAppgwCifsTree;


typedef struct SshAppgwCifsMultiPartIORec *SshAppgwCifsMultiPartIO;

typedef enum
{
  SSH_APPGW_CIFS_MULTI_PART_READ,
  SSH_APPGW_CIFS_MULTI_PART_WRITE
} SshAppgwCifsMultiPartIOType;


/* Context data for "file handles" and "search handles" */
struct SshAppgwCifsHandleRec
{
  SshADTBagHeaderStruct adt_header;

  /* Pointer to connection context */
  struct SshAppgwCifsConnRec *conn;

  /* Type of handle */
  SshAppgwCifsHandleType handle_type;

  /* CIFS/SMB handle */
  SshUInt16 id;

  /* Pointer to the context of connected tree "owning" this handle */
  SshAppgwCifsTree tree;

  /* Type of file */
  SshUInt16 file_type;
#define SSH_SMB_FILE_TYPE_FILE_OR_DIR   0 /* disk file or directory */
#define SSH_SMB_FILE_TYPE_PIPE          1 /* named pipe in byte mode */
#define SSH_SMB_FILE_TYPE_MESSAGE_PIPE  2 /* named pipe in message mode */
#define SSH_SMB_FILE_TYPE_PRINTER       3 /* spooled printer */

  /* Pending "multi-part" I/O operations */
  SshAppgwCifsMultiPartIO read_op;
  SshAppgwCifsMultiPartIO write_op;

  /* Flags */
  unsigned int directory : 1; /* Set if this is directory instead of file */
  unsigned int execute_access : 1;
  unsigned int write_access : 1;
  unsigned int read_access : 1;
  unsigned int query_access : 1;
  unsigned int delete_access : 1;
  unsigned int close_after_request : 1; /* Handle is closed automatically
                                           after this request */
  unsigned int close_when_complete : 1; /* Handle is closed automatically if
                                           the end of action (e.g. search)
                                           reached */

  /* The filename is appended here in ASCII format, so the actual length of
     this structure depends from the length of filename. */
  unsigned char name[1];
  /* ***** Don't add anything here! *******/
};

typedef struct SshAppgwCifsHandleRec SshAppgwCifsHandleStruct;
typedef struct SshAppgwCifsHandleRec *SshAppgwCifsHandle;
typedef struct SshAppgwCifsHandleRec *SshAppgwCifsFileHandle;
typedef struct SshAppgwCifsHandleRec *SshAppgwCifsSearchHandle;


/* Application gateway specific context data for SMB_COM_NEGOTIATE request */
struct SshAppgwCifsNegotiateCtxRec
{
  /* Total number of supported dialects specified in SMB_COM_NEGOTIATE
     request */
  SshUInt16 dialect_count;

  /* Variable length array of pointers to dialect strings (in plain ASCII
     format) */
  unsigned char **dialect_ptrs;
};

typedef struct SshAppgwCifsNegotiateCtxRec SshAppgwCifsNegotiateCtxStruct;
typedef struct SshAppgwCifsNegotiateCtxRec *SshAppgwCifsNegotiateCtx;


/* Application gateway specific context for SMB_COM_COPY, SMB_COM_MOVE
   and SMB_COM_RENAME requests */
struct SshAppgwCifsFileMoveCtxRec
{
  /* Original filename in ASCII format (can contain wild card characters) */
  unsigned char *original_name;

  /* New filename in ASCII format (can contain wild card characters) */
  unsigned char *new_name;
};

typedef struct SshAppgwCifsFileMoveCtxRec SshAppgwCifsFileMoveCtxStruct;
typedef struct SshAppgwCifsFileMoveCtxRec *SshAppgwCifsFileMoveCtx;


/* Application gateway specific (optionally used) context for read and write
   requests */
struct SshAppgwCifsIORequestCtxRec
{
  /* File handle */
  SshUInt16 fid;

  SshUInt64 offset;
  SshUInt64 min_count;
  SshUInt64 max_count;
};

typedef struct SshAppgwCifsIORequestCtxRec SshAppgwCifsIORequestCtxStruct;
typedef struct SshAppgwCifsIORequestCtxRec *SshAppgwCifsIORequestCtx;


/* ********************* Prototypes for help functions **********************/

/* Checks the validity and the total length of a string without risk of
   access violations (which could occur if the string doesn't have
   terminating null-character). Returns FALSE if the string is malformed.

   This function works with both ASCII/ANSI and UNICODE strings. The argument
   'is_unicode' must be set to TRUE if the caller assumes that the given
   buffer contains an UNICODE string. The length returned in 'size_return'
   is the total length - in bytes - of the string. All padding byte(s)
   potentially preceeding the actual string as well as the size of
   terminating NULL character are included into the returned length, This
   function assumes that UNICODE strings are aligned to an even memory
   address, so there can be 0...2 padding bytes (maximum of one buffer type
   identifier byte and one padding byte for UNICODE string) preceding the
   actual string.

   In addition to "normal" ASCII/UNICODE strings this function understands
   also the special buffer formats defined in CIFS protocol specification.
   (For example, buffer type "DIALECT" contains a type identifier 0x02
   followed by a NULL terminated string.) The format of data buffer 'buffer'
   is specified by argument 'buff_format'.

   The length of input buffer 'buffer' is specified by argument
   'buffer_len'. */
Boolean ssh_appgw_cifs_strsize(size_t *size_return,
                               SshAppgwCifsDataFormat buff_format,
                               const unsigned char *buffer,
                               size_t buffer_len,
                               Boolean is_unicode);

/* Makes an ASCII copy of either ASCII or UNICODE string specified by
   "buffer". Returns FALSE if the buffer does not contain a valid (NULL
   terminated) string or if the memory allocation fails.

   In addition to "normal" ASCII/UNICODE strings this function understands
   also the special buffer formats defined in CIFS protocol specification.
   (For example, buffer type "DIALECT" contains a type identifier 0x02
   followed by a NULL terminated string.) The format of data buffer 'buffer'
   is specified by argument 'buff_format'. */
char * ssh_appgw_cifs_strdup(SshAppgwCifsCtx cifs_alg,
                             SshAppgwCifsDataFormat buff_format,
                             const unsigned char *buffer,
                             size_t buff_len,
                             Boolean original_is_unicode);


/* Allocates a new slot for storing CIFS command specific context. This
   function must be called before ssh_appgw_cifs_cmd_context_set(). */
SshAppgwCifsCmdCtxSlot ssh_appgw_cifs_cmd_context_slot_add(
                                            SshAppgwCifsConn conn,
                                            SshAppgwCifsParser cifs);

/* Removes the slot storing the current CIFS command context. This
   function does not delete the context! */
void ssh_appgw_cifs_cmd_context_slot_remove(SshAppgwCifsConn conn,
                                            SshAppgwCifsParser cifs);

/* Allocates a new CIFS command specific context */
void * ssh_appgw_cifs_cmd_context_allocate(SshAppgwCifsConn conn,
                                           SshAppgwCifsParser cifs,
                                           size_t size_of_context,
                                           SshAppgwCifsCtxDeleteCb delete_cb);

/* Returns the CIFS command specific context */
void * ssh_appgw_cifs_cmd_context_get(SshAppgwCifsConn conn,
                                      SshAppgwCifsParser cifs);

/* Stores the given context as the CIFS command specific context. Use
   ssh_appgw_cifs_cmd_context_slot_add() to allocate a new slot before
   you call this function. */
void ssh_appgw_cifs_cmd_context_set(SshAppgwCifsCmdCtxSlot slot,
                                    void *context,
                                    SshAppgwCifsCtxDeleteCb delete_cb);

/* Deletes CIFS command specific contexts */
void ssh_appgw_cifs_cmd_contexts_delete(SshAppgwCifsConn conn,
                                        SshAppgwCifsCmdCtxSlot first_slot);

/* Deletes "ANDX contexts" from CIFS parser structure */
void ssh_appgw_cifs_andx_commands_delete(SshAppgwCifsConn conn,
                                         SshAppgwCifsEmbeddedCmd context);

/* ********* Prototypes for "CIFS filtering rule" lookup functions **********/

/* Checks whether a CIFS request/response can contain the specified
   embedded command */
Boolean ssh_appgw_cifs_is_embedded_cmd_allowed(SshAppgwCifsCmdType major,
                                               SshAppgwCifsCmdType embedded);

/* Help function for resolving CIFS commands codes into a human readable
   ASCII strings. Can be used either in event logging or as a debugging
   help. */
const unsigned char * ssh_appgw_cifs_cmd_to_name(SshAppgwCifsCmdType cmd);


/* ************* Prototypes for some debugging help functions **************/

#ifdef DEBUG_LIGHT
/* Debug help function for resolving PIPE transaction subcommand codes
   into ASCII names */
const unsigned char *
ssh_appgw_cifs_pipe_transact_to_name(SshAppgwCifsPipeCommand cmd);

/* Debug help function for resolving TRANSACTION2 subcommand codes
   into ASCII names */
const unsigned char *
ssh_appgw_cifs_transact2_to_name(SshAppgwCifsTransact2Code code);

/* Debug help function for resolving file system information levels
   into ASCII names */
const unsigned char *
ssh_appgw_cifs_fs_info_level_to_name(SshAppgwCifsFsInfoLevel info_level);

/* Debug help function for resolving file information levels into ASCII
   names. */
const unsigned char *
ssh_appgw_cifs_file_info_level_to_name(SshAppgwCifsFileInfoLevel info_level);

/* Debug help function for resolving search information levels into ASCII
   names */
const unsigned char *
ssh_appgw_cifs_search_info_level_to_name(SshAppgwCifsSearchInfoLevel level);

/* Debug help function for resolving NT_TRANSACTION subcommand codes
   into ASCII names */
const unsigned char *
ssh_appgw_cifs_nt_transact_to_name(SshAppgwCifsNtTransactCode code);

void
ssh_appgw_cifs_dump_pipe_state(SshUInt16 pipe_state);

#endif /* DEBUG_LIGHT */

/* ***************** Prototypes for bookkeeping functions *******************/

/*----------------------------- CIFS sessions ------------------------------*/

/* Adds a new CIFS session entry */
Boolean ssh_appgw_cifs_session_insert(SshAppgwCifsSession session);

/* Removes existing CIFS session entry */
void ssh_appgw_cifs_session_remove(SshAppgwCifsSession session);

/* Removes all existing sessions of the specified connection */
void ssh_appgw_cifs_remove_all_sessions(SshAppgwCifsConn conn);

/* Searches for a matching CIFS session entry */
SshAppgwCifsSession ssh_appgw_cifs_session_lookup(SshAppgwCifsConn conn,
                                                  SshAppgwCifsParser cifs);

/*------------------------------- CIFS trees -------------------------------*/

/* Allocates a new application gateway specific tree context */
SshAppgwCifsTree ssh_appgw_cifs_tree_allocate(SshAppgwCifsConn conn,
                                              const unsigned char *name_buffer,
                                              size_t buffer_len,
                                              Boolean unicode_format);

/* Inserts a new CIFS tree context entry */
void ssh_appgw_cifs_tree_insert(SshAppgwCifsTree tree);

/* Removes existing CIFS tree entry */
void ssh_appgw_cifs_tree_remove(SshAppgwCifsTree tree);

/* Searches for a matching CIFS tree entry */
SshAppgwCifsTree ssh_appgw_cifs_tree_lookup(SshAppgwCifsConn conn,
                                            SshAppgwCifsParser cifs);

/*------------------------------ File handles ------------------------------*/

/* Allocates a new application gateway specific "file handle" context */
SshAppgwCifsFileHandle
ssh_appgw_cifs_file_handle_allocate(SshAppgwCifsConn conn,
                                    SshAppgwCifsDataFormat buff_format,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format);

/* Inserts a new file handle entry */
void ssh_appgw_cifs_file_handle_insert(SshAppgwCifsFileHandle file);

/* Removes existing file handle entry */
void ssh_appgw_cifs_file_handle_remove(SshAppgwCifsFileHandle file);

/* Searched for a matching file handle entry */
SshAppgwCifsFileHandle ssh_appgw_cifs_file_handle_lookup(
                                                SshAppgwCifsConn conn,
                                                SshUInt16 fid);

/* Allocates a new "multi-part" I/O operation. */
SshAppgwCifsMultiPartIO
ssh_appgw_cifs_mp_io_begin(SshAppgwCifsFileHandle file,
                           SshAppgwCifsMultiPartIOType type,
                           size_t total_length,
                           void *context,
                           SshAppgwCifsCtxDeleteCb ctx_delete_cb);

/* Appends a new buffer to pending "multi-part" I/O operation. If this
   function fails, the pending operation will be terminated (so "io" will
   also be freed) */
Boolean
ssh_appgw_cifs_mp_io_append(SshAppgwCifsMultiPartIO io,
                            const unsigned char *buffer,
                            size_t buffer_len);

/* Inserts a new buffer to pending "multi-part" I/O operation. The location
   of insertion is specified by "offset". If this function fails, the pending
   operation will be terminated (so "io" will also be freed) */
Boolean
ssh_appgw_cifs_mp_io_insert(SshAppgwCifsMultiPartIO io,
                            size_t offset,
                            const unsigned char *buffer,
                            size_t buffer_len);

/* Sets the "base offset" for a multi-part I/O operation. During insertion,
   the base_offset is added to the offset value given to
   ssh_appgw_cifs_mp_io_insert(). */
void
ssh_appgw_cifs_mp_io_base_offset_set(SshAppgwCifsMultiPartIO io,
                                     size_t base_offset);

/* Returns a pending "multi-part" I/O operation, if available. */
SshAppgwCifsMultiPartIO
ssh_appgw_cifs_mp_io_get(SshAppgwCifsFileHandle file,
                         SshAppgwCifsMultiPartIOType type);

/* Checks whether the "multi-part" I/O operation is complete */
Boolean
ssh_appgw_cifs_mp_io_is_complete(SshAppgwCifsMultiPartIO io);

/* Returns the "results" (i.e. the buffer containing the data and the length
   of data) of a "multi-part" I/O operation. The results can either be
   intermediate or final ones. Use ssh_appgw_cifs_is_mp_io_complete() if you
   need to know whether the I/O is complete. */
void
ssh_appgw_cifs_mp_io_data_get(SshAppgwCifsMultiPartIO io,
                              const unsigned char **buffer_return,
                              size_t *length_return);

/* Terminates and frees pending "multi-part" read operation */
void
ssh_appgw_cifs_mp_io_end(SshAppgwCifsMultiPartIO io);

/*----------------------------- Search handles -----------------------------*/

/* Allocates a new application gateway specific "search handle" context */
SshAppgwCifsSearchHandle
ssh_appgw_cifs_search_handle_allocate(SshAppgwCifsConn conn,
                                      SshAppgwCifsDataFormat buff_format,
                                      const unsigned char *name_buffer,
                                      size_t buffer_len,
                                      Boolean unicode_format);

/* Inserts a new search handle entry */
void ssh_appgw_cifs_search_handle_insert(SshAppgwCifsSearchHandle search);

/* Removes existing search handle entry */
void ssh_appgw_cifs_search_handle_remove(SshAppgwCifsSearchHandle search);

/* Searched for a matching file handle entry */
SshAppgwCifsSearchHandle ssh_appgw_cifs_search_handle_lookup(
                                                SshAppgwCifsConn conn,
                                                SshUInt16 sid);

/*---------------------------- Pending requests ----------------------------*/

/* Initializes a request context */
void ssh_appgw_cifs_pending_request_init(SshAppgwCifsRequest req,
                                         SshAppgwCifsConn conn,
                                         SshAppgwCifsParser cifs);

/* Adds a new pending request entry */
SshAppgwCifsRequest ssh_appgw_cifs_pending_request_add(SshAppgwCifsConn conn,
                                                     SshAppgwCifsParser cifs);

/* Removes existing pending request entry */
void ssh_appgw_cifs_pending_request_remove(SshAppgwCifsRequest request);

/* Searches for a pending request entry */
SshAppgwCifsRequest ssh_appgw_cifs_pending_request_lookup(
                                                  SshAppgwCifsConn conn,
                                                  SshAppgwCifsParser cifs);

/* Searches for a pending request corresponding with the given cancel
   request */
SshAppgwCifsRequest ssh_appgw_cifs_canceled_request_lookup(
                                          SshAppgwCifsRequest cancel_req);

/*-------------------------- Pending transactions --------------------------*/

/* Allocates a new transaction context */
SshAppgwCifsTransaction
ssh_appgw_cifs_transaction_allocate(SshAppgwCifsConn conn,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format);

/* Adds a name to transaction context. This function can be used if the name
   buffer was not given at the time the transaction context was allocated.
   It's an error to call this function if the name has already been set. */
Boolean
ssh_appgw_cifs_transaction_name_set(SshAppgwCifsTransaction transaction,
                                    const unsigned char *name_buffer,
                                    size_t buffer_len,
                                    Boolean unicode_format);

/* Searches for a pending transaction */
SshAppgwCifsTransaction
ssh_appgw_cifs_transaction_lookup(SshAppgwCifsConn conn,
                                  SshAppgwCifsParser cifs);

/* Frees a transaction context */
void ssh_appgw_cifs_transaction_free(SshAppgwCifsTransaction transaction);

/* ******************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_appgw_cifs_io_st_read);
SSH_FSM_STEP(ssh_appgw_cifs_io_st_drop);
SSH_FSM_STEP(ssh_appgw_cifs_io_st_pass);
SSH_FSM_STEP(ssh_appgw_cifs_io_st_write_to_src);

  /*-- State functions for CIFS over NBT protocol parser --*/
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_read_header);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_send_response);
SSH_FSM_STEP(ssh_appgw_cifs_nbt_st_pass_packet);

  /*--- State functions for CIFS over MSDS parser ---*/
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_read_header);
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_send_response);
SSH_FSM_STEP(ssh_appgw_cifs_msds_st_pass_packet);

  /*--- State functions common for both requests and responses ---*/
SSH_FSM_STEP(ssh_appgw_cifs_st_fix_wc_and_retry);
SSH_FSM_STEP(ssh_appgw_cifs_st_decode_header);
SSH_FSM_STEP(ssh_appgw_cifs_st_continue_filtering);
SSH_FSM_STEP(ssh_appgw_cifs_st_pass_packet);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_version);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_word_count);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_byte_count);
SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_packet);
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_packet);
SSH_FSM_STEP(ssh_appgw_cifs_st_unsupported_andx);
SSH_FSM_STEP(ssh_appgw_cifs_st_unsuccessful);
SSH_FSM_STEP(ssh_appgw_cifs_st_out_of_memory);
SSH_FSM_STEP(ssh_appgw_cifs_st_generate_error_response);

 /*--- State functions for filtering CIFS requests ----*/
SSH_FSM_STEP(ssh_appgw_cifs_st_negotiate_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_session_setup_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_session_logoff_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_create_dir_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_dir_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_disconnect_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_and_tree_disc_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_sec_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction2_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_sec_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_query_information_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_set_information_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_create_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_check_directory_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_create_temp_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_find_close2_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_rename_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_rename_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_copy_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_move_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_write_and_close_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_locking_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_read_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_read_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_write_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_sec_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_create_x_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_cancel_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_print_file_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_print_file_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_single_block_req);
SSH_FSM_STEP(ssh_appgw_cifs_st_def_file_io_req_filter);
SSH_FSM_STEP(ssh_appgw_cifs_st_def_request_filter);


 /*--- State functions for filtering CIFS responses ----*/
SSH_FSM_STEP(ssh_appgw_cifs_st_negotiate_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_session_setup_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_session_logoff_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_create_dir_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_dir_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_connect_x_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_tree_disconnect_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_and_tree_disc_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_transaction2_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_transaction_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_query_info_disk_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_query_information_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_set_information_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_create_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_delete_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_rename_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_copy_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_move_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_write_and_close_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_x_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_read_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_read_x_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_write_x_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_ioctl_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_nt_create_x_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_open_print_file_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_close_print_file_resp);
SSH_FSM_STEP(ssh_appgw_cifs_st_def_response_filter);


#endif /* not APPGW_CIFS_INTERNAL_H */
