/*
 *
 * appgw_cifs_st_parser.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * FSM state functions for CIFS (Common Internet File System) protocol
 * parser.
 *
 */

#include "sshincludes.h"
#include "sshgetput.h"
#include "appgw_cifs_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwCifsParser"

/* Minimum length of SMB/CIFS header */
#define SSH_APPGW_SMB_HEADER_LEN      35

#define SSH_APPGW_SMB_CMD_COUNT       66
#define SSH_APPGW_SMB_INDEX_MAX       (SSH_APPGW_SMB_CMD_COUNT-1)
#define SSH_APPGW_SMB_INDEX_INVALID   (SSH_APPGW_SMB_INDEX_MAX+1)

/* Flag specifying that a SMB command can contain embedded commands */
#define SSH_APPGW_CIFS_ANDX_COMMAND           0x80000000

/* Flag specifying that also server can send this request to client */
#define SSH_APPGW_CIFS_ALLOW_SERVER_REQUEST   0x40000000

/* Flags specifying that we must have a valid tree context, otherwice the
   request/response will be dropped */
#define SSH_APPGW_CIFS_MUST_HAVE_TREE         0x08000000

/* Flag specifying that parser does not perform session lookup when filtering
   this SMB command */
#define SSH_APPGW_CIFS_NO_SESSION_CHECK       0x00008000

/* Flag specifying that parser accepts response having zero UID */
#define SSH_APPGW_CIFS_ALLOW_0_UID_RESPONSE   0x00004000

/* Flag specifying that request is allowed without CIFS session setup */
#define SSH_APPGW_CIFS_ALLOW_REQUEST_WHEN_CLOSED  0x00000001

/* Flag specifying that response is allowed without CIFS session setup */
#define SSH_APPGW_CIFS_ALLOW_RESPONSE_WHEN_CLOSED 0x00000002

/* */
#define SSH_APPGW_CIFS_WORD_COUNT_NO_MIN  0
#define SSH_APPGW_CIFS_WORD_COUNT_NO_MAX  0xFF

#define SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN  0
#define SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX  0xFFFF


struct SshAppgwCifsFilterRulesRec
{
  struct
  {
    SshAppgwCifsCmdType command;
    const unsigned char *name;
  } cmd;

  SshUInt32 flags;

  struct
  {
    SshFSMStepCB filter;

    SshUInt8  word_count_min;
    SshUInt8  word_count_max;
    SshUInt16 byte_count_min;
    SshUInt16 byte_count_max;
  } request;

  struct
  {
    SshFSMStepCB filter;

    SshUInt8  word_count_min;
    SshUInt8  word_count_max;
    SshUInt16 byte_count_min;
    SshUInt16 byte_count_max;
  } response;

  const SshUInt8 *allowed_embedded_cmds;
};

typedef struct SshAppgwCifsFilterRulesRec SshAppgwCifsFilterRulesStruct;
typedef struct SshAppgwCifsFilterRulesRec *SshAppgwCifsFilterRules;

/* Macro for CIFS command filtering rule lookup */
#define SSH_APPGW_CIFS_FILTER_RULES_GET(cmd)  \
  (SshAppgwCifsFilterRules) \
    &ssh_appgw_cifs_filter_rules[SSH_APPGW_CIFS_TO_INDEX(cmd)];


/* Lookup table for converting CIFS command codes to application gateway
   specific indexes. */
static const unsigned char
ssh_appgw_smb_to_index_table[256] =
{
  /*-------------------- 0x00 --------------------*/
  0,  /* SMB_COM_CREATE_DIRECTORY */
  1,  /* SMB_COM_DELETE_DIRECTORY */
  2,  /* SMB_COM_OPEN */
  3,  /* SMB_COM_CREATE */
  4,  /* SMB_COM_CLOSE */
  5,  /* SMB_COM_FLUSH */
  6,  /* SSH_SMB_COM_DELETE */
  7,  /* SMB_COM_RENAME */
  8,  /* SMB_COM_QUERY_INFORMATION */
  9,  /* SMB_COM_SET_INFORMATION */
  10, /* SSH_SMB_COM_READ */
  11, /* SMB_COM_WRITE */
  12, /* SMB_COM_LOCK_BYTE_RANGE */
  13, /* SMB_COM_UNLOCK_BYTE_RANGE */
  14, /* SMB_COM_CREATE_TEMPORARY */
  15, /* SMB_COM_CREATE_NEW */
  /*-------------------- 0x10 --------------------*/
  16, /* SMB_COM_CHECK_DIRECTORY */
  17, /* SMB_COM_PROCESS_EXIT */
  18, /* SMB_COM_SEEK */
  19, /* SMB_COM_LOCK_AND_READ */
  20, /* SMB_COM_WRITE_AND_UNLOCK */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x15 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x16 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x17 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x18 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x19 */
  21, /* SMB_COM_READ_RAW */
  22, /* SMB_COM_READ_MPX */
  23, /* SMB_COM_READ_MPX_SECONDARY */
  24, /* SMB_COM_WRITE_RAW */
  25, /* SMB_COM_WRITE_MPX */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x1F */
  /*-------------------- 0x20 --------------------*/
  26, /* SMB_COM_WRITE_COMPLETE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x21 */
  27, /* SMB_COM_SET_INFORMATION2 */
  28, /* SMB_COM_QUERY_INFORMATION2 */
  29, /* SMB_COM_LOCKING_ANDX */
  30, /* SMB_COM_TRANSACTION */
  31, /* SMB_COM_TRANSACTION_SECONDARY */
  32, /* SSH_SMB_COM_IOCTL */
  33, /* SMB_COM_IOCTL_SECONDARY */
  34, /* SMB_COM_COPY */
  35, /* SMB_COM_MOVE */
  36, /* SMB_COM_ECHO */
  37, /* SMB_COM_WRITE_AND_CLOSE */
  38, /* SMB_COM_OPEN_ANDX */
  39, /* SMB_COM_READ_ANDX */
  40, /* SMB_COM_WRITE_ANDX */
  /*-------------------- 0x30 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x30 */
  41, /* SMB_COM_CLOSE_AND_TREE_DISC */
  42, /* SMB_COM_TRANSACTION2 */
  43, /* SMB_COM_TRANSACTION2_SECONDARY */
  44, /* SMB_COM_FIND_CLOSE2 */
  45, /* SMB_COM_FIND_NOTIFY_CLOSE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x36 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x37 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x38 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x39 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x3F */
  /*-------------------- 0x40 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x40 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x41 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x42 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x43 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x44 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x45 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x46 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x47 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x48 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x49 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x4F */
  /*-------------------- 0x50 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x50 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x51 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x52 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x53 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x54 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x55 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x56 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x57 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x58 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x59 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x5F */
  /*-------------------- 0x60 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x60 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x61 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x62 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x63 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x64 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x65 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x66 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x67 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x68 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x69 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x6F */
  /*-------------------- 0x70 --------------------*/
  46, /* SMB_COM_TREE_CONNECT */
  47, /* SMB_COM_TREE_DISCONNECT */
  48, /* SMB_COM_NEGOTIATE */
  49, /* SMB_COM_SESSION_SETUP_ANDX */
  50, /* SMB_COM_LOGOFF_ANDX */
  51, /* SMB_COM_TREE_CONNECT_ANDX */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x76 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x77 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x78 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x79 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x7F */
  /*-------------------- 0x80 --------------------*/
  52, /* SMB_COM_QUERY_INFORMATION_DISK */
  53, /* SMB_COM_SEARCH */
  54, /* SMB_COM_FIND */
  55, /* SMB_COM_FIND_UNIQUE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x84 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x85 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x86 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x87 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x88 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x89 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x8F */
  /*-------------------- 0x90 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x90 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x91 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x92 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x93 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x94 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x95 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x96 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x97 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x98 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x99 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9A */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9B */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9C */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9D */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9E */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0x9F */
  /*-------------------- 0xA0 --------------------*/
  56, /* SMB_COM_NT_TRANSACT */
  57, /* SMB_COM_NT_TRANSACT_SECONDARY */
  58, /* SMB_COM_NT_CREATE_ANDX */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xA3 */
  59, /* SMB_COM_NT_CANCEL */
  60, /* SMB_COM_NT_RENAME */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xA6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xA7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xA8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xA9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAD */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xAF */
  /*-------------------- 0xB0 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB0 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB1 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB2 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB3 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB4 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB5 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xB9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBD */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xBF */
  /*-------------------- 0xC0 --------------------*/
  61, /* SMB_OPEN_PRINT_FILE */
  62, /* SMB_WRITE_PRINT_FILE */
  63, /* SMB_CLOSE_PRINT_FILE */
  64, /* SMB_GET_PRINT_QUEUE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC4 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC5 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xC9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCD */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xCF */
  /*-------------------- 0xD0 --------------------*/
  65, /* SMB_SEND_SINGLE_BLOCK */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD1 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD2 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD3 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD4 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD5 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xD9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDD */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xDF */
  /*-------------------- 0xE0 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE0 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE1 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE2 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE3 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE4 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE5 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xE9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xEA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xEB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xEC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xED */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xEE */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xEF */
  /*-------------------- 0xF0 --------------------*/
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF0 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF1 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF2 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF3 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF4 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF5 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF6 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF7 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF8 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xF9 */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xFA */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xFB */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xFC */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xFD */
  SSH_APPGW_SMB_INDEX_INVALID, /* 0xFE */
  SSH_APPGW_SMB_INDEX_INVALID  /* 0xFF */
};


/* By default, our application gateway doesn't accept any embedded
   commands */
static const SshUInt8
SSH_APPGW_CIFS_NO_EMBEDDED_CMDS[] = {0xFF};

/* Allowed embedded commands for SMB_COM_SESSION_SETUP_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_SESSION_SETUP_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_TREE_CONNECT_ANDX,
  SSH_SMB_COM_OPEN,
  SSH_SMB_COM_OPEN_ANDX,
  SSH_SMB_COM_CREATE,
  SSH_SMB_COM_CREATE_NEW,
  SSH_SMB_COM_CREATE_DIRECTORY,
  SSH_SMB_COM_DELETE,
  SSH_SMB_COM_DELETE_DIRECTORY,
  SSH_SMB_COM_FIND,
  SSH_SMB_COM_FIND_UNIQUE,
  SSH_SMB_COM_COPY,
  SSH_SMB_COM_RENAME,
  SSH_SMB_COM_NT_RENAME,
  SSH_SMB_COM_CHECK_DIRECTORY,
  SSH_SMB_COM_QUERY_INFORMATION,
  SSH_SMB_COM_SET_INFORMATION,
  SSH_SMB_OPEN_PRINT_FILE,
  SSH_SMB_GET_PRINT_QUEUE,
  SSH_SMB_COM_TRANSACTION,
  0xFF};

/* Allowed embedded commands for SMB_COM_LOGOFF_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_LOGOFF_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_SESSION_SETUP_ANDX,
  0xFF};

/* Allowed embedded commands for SMB_COM_TREE_CONNECT_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_TREE_CONNECT_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_OPEN,
  SSH_SMB_COM_OPEN_ANDX,
  SSH_SMB_COM_CREATE,
  SSH_SMB_COM_CREATE_NEW,
  SSH_SMB_COM_CREATE_DIRECTORY,
  SSH_SMB_COM_DELETE,
  SSH_SMB_COM_DELETE_DIRECTORY,
  SSH_SMB_COM_FIND,
  SSH_SMB_COM_FIND_UNIQUE,
  SSH_SMB_COM_COPY,
  SSH_SMB_COM_RENAME,
  SSH_SMB_COM_NT_RENAME,
  SSH_SMB_COM_CHECK_DIRECTORY,
  SSH_SMB_COM_QUERY_INFORMATION,
  SSH_SMB_COM_SET_INFORMATION,
  SSH_SMB_OPEN_PRINT_FILE,
  SSH_SMB_GET_PRINT_QUEUE,
  SSH_SMB_COM_TRANSACTION,
  0xFF};

/* Allowed embedded commands for SMB_COM_NT_CREATE_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_NT_CREATE_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_READ,
  SSH_SMB_COM_READ_ANDX,
  SSH_SMB_COM_IOCTL,
  0xFF};

/* Allowed embedded commands for SMB_COM_READ_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_READ_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_CLOSE,
  0xFF};

/* Allowed embedded commands for SMB_COM_WRITE_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_WRITE_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_READ,
  SSH_SMB_COM_READ_ANDX,
  SSH_SMB_COM_LOCK_AND_READ,
  SSH_SMB_COM_WRITE_ANDX,
  SSH_SMB_COM_CLOSE,
  0xFF};

/* Allowed embedded commands for SMB_COM_COCKING_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_LOCKING_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_READ,
  SSH_SMB_COM_READ_ANDX,
  SSH_SMB_COM_WRITE,
  SSH_SMB_COM_WRITE_ANDX,
  SSH_SMB_COM_FLUSH,
  SSH_SMB_COM_LOCKING_ANDX,
  SSH_SMB_COM_CLOSE,
  0xFF};

/* Allowed embedded commands for SMB_COM_OPEN_ANDX */
static const SshUInt8
SSH_APPGW_CIFS_OPEN_X_EMBEDDED_CMDS[] = {
  SSH_SMB_COM_READ,
  SSH_SMB_COM_READ_ANDX,
  SSH_SMB_COM_IOCTL,
  0xFF};


#define SSH_CIFS_SMB_DEBUG_INFO(name)  \
  { SSH_##name, (const unsigned char *)#name }

static const SshAppgwCifsFilterRulesStruct
ssh_appgw_cifs_filter_rules[SSH_APPGW_SMB_CMD_COUNT+1] =
{
  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CREATE_DIRECTORY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_create_dir_req,
    0, 0,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_create_dir_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_DELETE_DIRECTORY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_delete_dir_req,
    0, 0,
    1, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_delete_dir_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_OPEN),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_open_req,
    2, 2,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_open_resp,
    7, 7,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CREATE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_create_req,
    3, 3,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_create_resp,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CLOSE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_close_req,
    3, 3,
    0, 0},
   {ssh_appgw_cifs_st_close_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_FLUSH),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    1, 1,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_DELETE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_delete_req,
    1, 1,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_delete_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_RENAME),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_rename_req,
    1, 1,
    4, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_rename_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_QUERY_INFORMATION),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_query_information_req,
    0, 0,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_query_information_resp,
    10, 10,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_SET_INFORMATION),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_set_information_req,
    8, 8,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_set_information_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_READ),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_read_req,
    5, 5,
    0, 0},
   {ssh_appgw_cifs_st_read_resp,
    5, 5,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    5, 5,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_LOCK_BYTE_RANGE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    5, 5,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_UNLOCK_BYTE_RANGE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    5, 5,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CREATE_TEMPORARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_create_temp_req,
    3, 3,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_create_resp,
    1, 1,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CREATE_NEW),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_create_req,
    3, 3,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_create_resp,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CHECK_DIRECTORY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_check_directory_req,
    0, 0,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_PROCESS_EXIT),
   0, /* flags */
   {ssh_appgw_cifs_st_def_request_filter,
    0, 0,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_SEEK),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    4, 4,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    2, 2,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_LOCK_AND_READ),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    5, 5,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    5, 5,
    1, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_AND_UNLOCK),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    5, 5,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_READ_RAW),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {/* We don't accept raw reads */
    ssh_appgw_cifs_st_unexpected_packet,
    8, 8,
    0, 0},
   {/* No SMB_COM_READ_RAW responses! */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_READ_MPX),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {/* We don't accept MPX reads */
    ssh_appgw_cifs_st_unexpected_packet,
    8, 8,
    0, 0},
   {ssh_appgw_cifs_st_unexpected_packet,
    8, 8,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_READ_MPX_SECONDARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {/* We don't accept MPX reads */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   {ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_RAW),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {/* We don't accept raw writes */
    ssh_appgw_cifs_st_unexpected_packet,
    12, 14,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {/* No SMB_COM_WRITE_RAW responses! */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_MPX),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {/* We don't accept MPX write requests */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   {ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_COMPLETE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_SET_INFORMATION2),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    7, 7,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_QUERY_INFORMATION2),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_file_io_req_filter,
    1, 1,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    11, 11,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_LOCKING_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND |
   SSH_APPGW_CIFS_MUST_HAVE_TREE |
   SSH_APPGW_CIFS_ALLOW_SERVER_REQUEST |
   SSH_APPGW_CIFS_NO_SESSION_CHECK,
   {ssh_appgw_cifs_st_locking_x_req,
    8, 8,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    2, 2,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_LOCKING_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TRANSACTION),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_transaction_req,
    14, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_transaction_resp,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TRANSACTION_SECONDARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_transaction_sec_req,
    8, 8, /* word_count must be 8 */
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {/* No SMB_COM_TRANSACTION_SECONDARY responses! */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_IOCTL),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_ioctl_req,
    14, 14,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_ioctl_resp,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, 8,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_IOCTL_SECONDARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_ioctl_sec_req,
    8, 8,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {/* No SMB_COM_IOCTL_SECONDARY responses! */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_COPY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_copy_req,
    3, 3,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_copy_resp,
    1, 1,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_MOVE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_move_req,
    3, 3,
    2, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_move_resp,
    1, 1,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_ECHO),
   SSH_APPGW_CIFS_NO_SESSION_CHECK, /* flags */
   {ssh_appgw_cifs_st_def_request_filter,
    1, 1,
    1, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    1, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_AND_CLOSE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_write_and_close_req,
    6, 12,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_write_and_close_resp,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_OPEN_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND |
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_open_x_req,
    15, 15,
    1, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_open_x_resp,
    15, 15,
    0, 0},
   SSH_APPGW_CIFS_OPEN_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_READ_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND |
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_read_x_req,
    10, 12, /* word_count */
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_read_x_resp,
    12, 12,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_READ_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_WRITE_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND |
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_write_x_req,
    12, 14, /* word_count */
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_write_x_resp,
    6, 6,
    0, 0},
   SSH_APPGW_CIFS_WRITE_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_CLOSE_AND_TREE_DISC),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_close_and_tree_disc_req,
    3, 3,
    0, 0},
   {ssh_appgw_cifs_st_close_and_tree_disc_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TRANSACTION2),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_transaction2_req,
    14, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_transaction2_resp,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TRANSACTION2_SECONDARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_transaction_sec_req,
    9, 9,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {/* Server shouldn't send SMB_COM_TRANSACTION2_SECONDARY responses */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_FIND_CLOSE2),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_find_close2_req,
    1, 1,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_FIND_NOTIFY_CLOSE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TREE_CONNECT),
   0,
   {ssh_appgw_cifs_st_tree_connect_req,
    0, 0,
    4, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_tree_connect_resp,
    2, 2,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TREE_DISCONNECT),
   SSH_APPGW_CIFS_MUST_HAVE_TREE |
   SSH_APPGW_CIFS_NO_SESSION_CHECK, /* flags */
   {ssh_appgw_cifs_st_tree_disconnect_req,
    0, 0,
    0, 0},
   {ssh_appgw_cifs_st_tree_disconnect_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NEGOTIATE),
   SSH_APPGW_CIFS_ALLOW_REQUEST_WHEN_CLOSED, /* flags */
   {ssh_appgw_cifs_st_negotiate_req,
    0, 0,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_negotiate_resp,
    1, 17,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_SESSION_SETUP_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND | /* flags */
   SSH_APPGW_CIFS_NO_SESSION_CHECK,
   {ssh_appgw_cifs_st_session_setup_req,
    10, 13,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_session_setup_resp,
    3, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_SESSION_SETUP_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_LOGOFF_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND | /* flags */
   SSH_APPGW_CIFS_NO_SESSION_CHECK |
   SSH_APPGW_CIFS_ALLOW_0_UID_RESPONSE,
   {ssh_appgw_cifs_st_session_logoff_req,
    2, 2,
    0, 0},
   {ssh_appgw_cifs_st_session_logoff_resp,
    2, 2,
    0, 0},
   SSH_APPGW_CIFS_LOGOFF_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_TREE_CONNECT_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND | /* flags */
   SSH_APPGW_CIFS_ALLOW_0_UID_RESPONSE,
   {ssh_appgw_cifs_st_tree_connect_x_req,
    4, 4,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_tree_connect_x_resp,
    2, 7,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_TREE_CONNECT_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_QUERY_INFORMATION_DISK),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    0, 0,
    0, 0},
   {ssh_appgw_cifs_st_query_info_disk_resp,
    5, 5,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_SEARCH),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    2, 2,
    5, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_FIND),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    2, 2,
    5, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_FIND_UNIQUE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    2, 2,
    5, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    1, 1,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NT_TRANSACTION),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_nt_transaction_req,
    19, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_nt_transaction_resp,
    SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NT_TRANSACTION_SECONDARY),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_nt_transaction_sec_req,
    18, 18,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {/* Server shouldn't send SMB_COM_NT_TRANSACTION_SECONDARY responses */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NT_CREATE_ANDX),
   SSH_APPGW_CIFS_ANDX_COMMAND |
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_nt_create_x_req,
    24, 24,
    SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_nt_create_x_resp,
    34, 35,
    0, 0},
   SSH_APPGW_CIFS_NT_CREATE_X_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NT_CANCEL),
   0, /* flags */
   {ssh_appgw_cifs_st_nt_cancel_req,
    0, 0,
    0, 0},
   {/* Server should not send SMB_COM_NT_CANCEL response */
    ssh_appgw_cifs_st_unexpected_packet,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_COM_NT_RENAME),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_nt_rename_req,
    4, 4,
    4, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_rename_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_OPEN_PRINT_FILE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_open_print_file_req,
    2, 2,
    2, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_open_print_file_resp,
    1, 1,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_WRITE_PRINT_FILE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    1, 1,
    4, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_CLOSE_PRINT_FILE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_close_print_file_req,
    1, 1,
    0, 0},
   {ssh_appgw_cifs_st_close_print_file_resp,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_GET_PRINT_QUEUE),
   SSH_APPGW_CIFS_MUST_HAVE_TREE,
   {ssh_appgw_cifs_st_def_request_filter,
    2, 2,
    0, 0},
   {ssh_appgw_cifs_st_def_response_filter,
    2, 2,
    3, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {SSH_CIFS_SMB_DEBUG_INFO(SMB_SEND_SINGLE_BLOCK),
   SSH_APPGW_CIFS_ALLOW_REQUEST_WHEN_CLOSED | /* Flags */
   SSH_APPGW_CIFS_ALLOW_RESPONSE_WHEN_CLOSED |
   SSH_APPGW_CIFS_ALLOW_SERVER_REQUEST,
   {ssh_appgw_cifs_st_single_block_req,
    0, 0,
    0, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX},
   {ssh_appgw_cifs_st_def_response_filter,
    0, 0,
    0, 0},
   SSH_APPGW_CIFS_NO_EMBEDDED_CMDS},

  {
   {0xFF, (const unsigned char *)"<Unknown>"},
    0, /* flags */
    {ssh_appgw_cifs_st_invalid_packet,
     SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
     SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
    {ssh_appgw_cifs_st_invalid_packet,
     SSH_APPGW_CIFS_WORD_COUNT_NO_MIN, SSH_APPGW_CIFS_WORD_COUNT_NO_MAX,
     SSH_APPGW_CIFS_BYTE_COUNT_NO_MIN, SSH_APPGW_CIFS_BYTE_COUNT_NO_MAX},
    SSH_APPGW_CIFS_NO_EMBEDDED_CMDS
  }
};


/* Macros/functions for table lookups */
#ifdef DEBUG_LIGHT

/* This is implemented as a function when DEBUG_LIGHT is defined */
static SshUInt8
SSH_APPGW_CIFS_TO_INDEX(SshAppgwCifsCmdType cmd)
{
  SshUInt8 index;

  SSH_ASSERT(cmd < 256);

  index = ssh_appgw_smb_to_index_table[cmd];

  SSH_DEBUG(99, ("Index lookup: 0x%02X -> %u", cmd, index));

  /* Check that we found the correct index (i.e. nobody has messed up the
     lookup table)! */
  SSH_ASSERT((ssh_appgw_cifs_filter_rules[index].cmd.command == 0xFF) ||
             (ssh_appgw_cifs_filter_rules[index].cmd.command == cmd));

  return index;
}


const unsigned char *
ssh_appgw_cifs_pipe_transact_to_name(SshAppgwCifsPipeCommand cmd)
{
  switch (cmd)
    {
    case SSH_SMB_PRC_PIPE_SET_STATE:
      return (const unsigned char *)"SetNamedPipeHandleState";
    case SSH_SMB_RPC_PIPE_QUERY_STATE:
      return (const unsigned char *)"GetNamedPipeHandleState";
    case SSH_SMB_RPC_PIPE_QUERY_INFO:
      return (const unsigned char *)"GetNamedPipeInfo";
    case SSH_SMB_RPC_PIPE_TRANSACT:
      return (const unsigned char *)"TransactNamedPipe";
    case SSH_SMB_RPC_PIPE_READ_RAW:
      return (const unsigned char *)"RawReadNamedPipe";
    case SSH_SMB_RPC_PIPE_WRITE_RAW:
      return (const unsigned char *)"RawWriteNamedPipe";
    case SSH_SMB_RPC_PIPE_CALL:
      return (const unsigned char *)"CallNamedPipe";
    case SSH_SMB_RPC_PIPE_WAIT:
      return (const unsigned char *)"WaitNamedPipe";
    case SSH_SMB_RPC_PIPE_PEEK:
      return (const unsigned char *)"PeekNamedPipe";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


const unsigned char *
ssh_appgw_cifs_transact2_to_name(SshAppgwCifsTransact2Code code)
{
  switch (code)
    {
    case SSH_SMB_TRANSACT2_OPEN2:
      return (const unsigned char *)"TRANS2_OPEN2";
    case SSH_SMB_TRANSACT2_FIND_FIRST2:
      return (const unsigned char *)"TRANS2_FIND_FIRST2";
    case SSH_SMB_TRANSACT2_FIND_NEXT2:
      return (const unsigned char *)"TRANS2_FIND_NEXT2";
    case SSH_SMB_TRANSACT2_QUERY_FS_INFORMATION:
      return (const unsigned char *)"TRANS2_QUERY_FS_INFORMATION";
    case SSH_SMB_TRANSACT2_QUERY_PATH_INFORMATION:
      return (const unsigned char *)"TRANS2_QUERY_PATH_INFORMATION";
    case SSH_SMB_TRANSACT2_SET_PATH_INFORMATION:
      return (const unsigned char *)"TRANS2_SET_PATH_INFORMATION";
    case SSH_SMB_TRANSACT2_QUERY_FILE_INFORMATION:
      return (const unsigned char *)"TRANS2_QUERY_FILE_INFORMATION";
    case SSH_SMB_TRANSACT2_SET_FILE_INFORMATION:
      return (const unsigned char *)"TRANS2_SET_FILE_INFORMATION";
    case SSH_SMB_TRANSACT2_CREATE_DIRECTORY:
      return (const unsigned char *)"TRANS2_CREATE_DIRECTORY";
    case SSH_SMB_TRANSACT2_SESSION_SETUP:
      return (const unsigned char *)"TRANS2_SESSION_SETUP";
    case SSH_SMB_TRANSACT2_GET_DFS_REFERRAL:
      return (const unsigned char *)"TRANS2_GET_DFS_REFERRAL";
    case SSH_SMB_TRANSACT2_REPORT_DFS_INCONSINTENCY:
      return (const unsigned char *)"TRANS2_REPORT_DFS_INCONSINTENCY";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


const unsigned char *
ssh_appgw_cifs_fs_info_level_to_name(SshAppgwCifsFsInfoLevel info_level)
{
  switch (info_level)
    {
    case SSH_SMB_INFO_FS_ALLOCATION:
      return (const unsigned char *)"SMB_INFO_ALLOCATION";
    case SSH_SMB_INFO_FS_VOLUME:
      return (const unsigned char *)"SMB_INFO_VLOUME";
    case SSH_SMB_INFO_FS_QUERY_VOLUME_INFO:
      return (const unsigned char *)"SMB_QUERY_FS_VOLUME_INFO";
    case SSH_SMB_INFO_FS_QUERY_SIZE_INFO:
      return (const unsigned char *)"SMB_QUERY_FS_SIZE_INFO";
    case SSH_SMB_INFO_FS_QUERY_DEVICE_INFO:
      return (const unsigned char *)"SMB_QUERY_FS_DEVICE_INFO";
    case SSH_SMB_INFO_FS_QUERY_ATTRIBUTE_INFO:
      return (const unsigned char *)"SMB_QUERY_FS_ATTRIBUTE_INFO";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


const unsigned char *
ssh_appgw_cifs_file_info_level_to_name(SshAppgwCifsFileInfoLevel info_level)
{
  switch (info_level)
    {
    case SSH_SMB_INFO_FILE_STANDARD:
      return (const unsigned char *)"SMB_INFO_STANDARD";
    case SSH_SMB_INFO_FILE_QUERY_EA_SIZE:
      return (const unsigned char *)"SMB_INFO_QUERY_EA_SIZE";
    case SSH_SMB_INFO_FILE_QUERY_EAS_FROM_LIST:
      return (const unsigned char *)"SMB_INFO_QUERY_EAS_FROM_LIST";
    case SSH_SMB_INFO_FILE_QUERY_ALL_EAS:
      return (const unsigned char *)"SMB_INFO_QUERY_ALL_EAS";
    case SSH_SMB_INFO_FILE_IS_NAME_VALID:
      return (const unsigned char *)"SMB_INFO_IS_NAME_VALID";
    case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO:
    case SSH_SMB_INFO_FILE_QUERY_BASIC_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_BASIC_INFO";
    case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO:
    case SSH_SMB_INFO_FILE_QUERY_STANDARD_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_STANDARD_INFO";
    case SSH_SMB_INFO_FILE_QUERY_EA_INFO:
    case SSH_SMB_INFO_FILE_QUERY_EA_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_EA_INFO";
    case SSH_SMB_INFO_FILE_QUERY_NAME_INFO:
    case SSH_SMB_INFO_FILE_QUERY_NAME_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_NAME_INFO";
    case SSH_SMB_INFO_FILE_QUERY_ALL_INFO:
    case SSH_SMB_INFO_FILE_QUERY_ALL_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_ALL_INFO";
    case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO:
    case SSH_SMB_INFO_FILE_QUERY_ALT_NAME_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_ALT_NAME_INFO";
    case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO:
    case SSH_SMB_INFO_FILE_QUERY_STREAM_INFO2:
      return (const unsigned char *)"SMB_QUERY_FILE_STREAM_INFO";
    case SSH_SMB_INFO_FILE_QUERY_COMPRESSION:
    case SSH_SMB_INFO_FILE_QUERY_COMPRESSION2:
      return (const unsigned char *)"SMB_QUERY_FILE_COMPRESSION_INFO";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


const unsigned char *
ssh_appgw_cifs_search_info_level_to_name(SshAppgwCifsSearchInfoLevel level)
{
  switch (level)
    {
    case SSH_SMB_INFO_SEARCH_STANDARD:
      return (const unsigned char *)"SMB_INFO_STANDARD";
    case SSH_SMB_INFO_SEARCH_QUERY_EA_SIZE:
      return (const unsigned char *)"SMB_INFO_QUERY_EA_SIZE";
    case SSH_SMB_INFO_SEARCH_QUERY_EAS_FROM_LIST:
      return (const unsigned char *)"SMB_INFO_QUERY_EAS_FROM_LIST";
    case SSH_SMB_INFO_SEARCH_DIRECTORY_INFO:
      return (const unsigned char *)"SMB_FIND_FILE_DIRECTORY_INFO";
    case SSH_SMB_INFO_SEARCH_FULL_DIRECTORY_INFO:
      return (const unsigned char *)"SMB_FIND_FILE_FULL_DIRECTORY_INFO";
    case SSH_SMB_INFO_SEARCH_NAMES_INFO:
      return (const unsigned char *)"SMB_FIND_FILE_NAMES_INFO";
    case SSH_SMB_INFO_SEARCH_BOTH_DIRECTORY_INFO:
      return (const unsigned char *)"SMB_FIND_FILE_BOTH_DIRECTORY_INFO";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


const unsigned char *
ssh_appgw_cifs_nt_transact_to_name(SshAppgwCifsNtTransactCode code)
{
  switch (code)
    {
    case SSH_SMB_NT_TRANSACT_CREATE:
      return (const unsigned char *)"NT_TRANSACT_CREATE";
    case SSH_SMB_NT_TRANSACT_IOCTL:
      return (const unsigned char *)"NT_TRANSACT_IOCTL";
    case SSH_SMB_NT_TRANSACT_SET_SECURITY_DESC:
      return (const unsigned char *)"NT_TRANSACT_SET_SECURITY_DESC";
    case SSH_SMB_NT_TRANSACT_NOTIFY_CHANGE:
      return (const unsigned char *)"NT_TRANSACT_NOTIFY_CHANGE";
    case SSH_SMB_NT_TRANSACT_RENAME:
      return (const unsigned char *)"NT_TRANSACT_RENAME";
    case SSH_SMB_NT_TRANSACT_QUERY_SECURITY_DESC:
      return (const unsigned char *)"NT_TRANSACT_QUERY_SECURITY_DESC";
    default:
      return (const unsigned char *)"<Unknown>";
    }
}


void
ssh_appgw_cifs_dump_pipe_state(SshUInt16 pipe_state)
{
  SSH_DEBUG(SSH_D_DATADUMP, ("- %s reads/writes",
            ((pipe_state & 0x8000) == 0x8000) ? "Blocking" : "Nonblocking"));

  SSH_DEBUG(SSH_D_DATADUMP, ("- endpoint = %s end of pipe",
            ((pipe_state & 0x4000) == 0x4000) ? "Server" : "Client"));

  switch ((pipe_state >> 10) & 0x0003)
    {
    case 0x00:
      SSH_DEBUG(SSH_D_DATADUMP, ("- type = byte stream pipe"));
      break;
    case 0x01:
      SSH_DEBUG(SSH_D_DATADUMP, ("- type = message pipe"));
      break;
    default:
      SSH_DEBUG(SSH_D_DATADUMP, ("- type = <unknown>"));
      break;
    }

  switch ((pipe_state >> 8) & 0x0003)
    {
    case 0x00:
      SSH_DEBUG(SSH_D_DATADUMP, ("- read_mode = byte stream"));
      break;
    case 0x01:
      SSH_DEBUG(SSH_D_DATADUMP, ("- read_mode = messages"));
      break;
    default:
      SSH_DEBUG(SSH_D_DATADUMP, ("- read_mode = <unknown>"));
      break;
    }

  SSH_DEBUG(SSH_D_DATADUMP, ("- Icount = %u", pipe_state & 0x00FF));
}


#else /* not DEBUG_LIGHT */

#define SSH_APPGW_CIFS_TO_INDEX(cmd) ssh_appgw_smb_to_index_table[cmd]

#endif /* DEBUG_LIGHT */


const unsigned char *
ssh_appgw_cifs_cmd_to_name(SshAppgwCifsCmdType cmd)
{
  return (ssh_appgw_cifs_filter_rules[SSH_APPGW_CIFS_TO_INDEX(cmd)].cmd.name);
}


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_appgw_cifs_st_prefilter);
SSH_FSM_STEP(ssh_appgw_cifs_st_drop_packet);


/************************** Static help functions ***************************/

/* Checks whether the specified "major" SMB command can contain given
   embedded command. */
Boolean
ssh_appgw_cifs_is_embedded_cmd_allowed(SshAppgwCifsCmdType major,
                                       SshAppgwCifsCmdType embedded)
{
  SshAppgwCifsFilterRules rules;
  unsigned int i;

  rules = SSH_APPGW_CIFS_FILTER_RULES_GET(major);

  for (i = 0; rules->allowed_embedded_cmds[i] != 0xFF; i++)
    {
      if (rules->allowed_embedded_cmds[i] == embedded)
        return TRUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("%s can't contain embedded %s!",
            ssh_appgw_cifs_cmd_to_name(major),
            ssh_appgw_cifs_cmd_to_name(embedded)));

  return FALSE;
}


static Boolean
ssh_appgw_cifs_st_wc_interop_fix(SshAppgwCifsParser cifs)
{
  if (cifs->response == 1)
    {
      switch (cifs->command)
        {
        /* Windows 2000 sometimes sends broken SMB_COM_NT_CREATE_ANDX
           responses (wrong word_count specified in SMB header). */
        case SSH_SMB_COM_NT_CREATE_ANDX:
          if (cifs->word_count == 42)
            {
              cifs->word_count = 35;
              return TRUE;
            }
          break;

        /* Some CIFS servers seem to send SMB_COM_LOGOFF_ANDX responses
           without "ANDX block" */
        case SSH_SMB_COM_LOGOFF_ANDX:
          if (cifs->word_count < 2)
            {
              cifs->word_count = 2;
              return TRUE;
            }
          break;

        default:
          break;
        }
    }

  return FALSE;
}


static Boolean
ssh_appgw_cifs_st_bc_interop_fix(SshAppgwCifsParser cifs)
{
  if (cifs->response == 1)
    {
      switch (cifs->command)
        {
        case SSH_SMB_COM_NT_CREATE_ANDX:
        case SSH_SMB_COM_LOGOFF_ANDX:
          if (cifs->byte_count != 0)
            {
              cifs->byte_count = 0;
              return TRUE;
            }
          break;

        default:
          break;
        }
    }

  return FALSE;
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_cifs_st_fix_wc_and_retry)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *ucp = cifs->packet_ptr + 32;
  SshAppgwCifsFilterRules rules;
  SshUInt8 old_value;

  if ((cifs->decode_phase != SSH_APPGW_CIFS_DECODE_HEADER) &&
      (cifs->decode_phase != SSH_APPGW_CIFS_FILTER_COMMAND))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
      return SSH_FSM_CONTINUE;
    }

  rules = SSH_APPGW_CIFS_FILTER_RULES_GET(cifs->command);

  SSH_DEBUG(SSH_D_MY5, ("Correcting word count..."));

  old_value = SSH_GET_8BIT(ucp);

  SSH_PUT_8BIT(ucp, cifs->word_count);

  /* Construct a new ANDX block */
  if ((rules->flags & SSH_APPGW_CIFS_ANDX_COMMAND) &&
      (old_value < 2))
    {
      cifs->byte_count = 0;

      SSH_PUT_8BIT(ucp+1, 0xFF);  /* Command */
      SSH_PUT_8BIT(ucp+2, 0x00);  /* MBZ */
      SSH_PUT_16BIT(ucp+3, 0);    /* ANDX-offset */
      SSH_PUT_16BIT(ucp+5, cifs->byte_count);

      /* Re-calculate the packet length */
      cifs->packet_size = SSH_APPGW_SMB_HEADER_LEN +
                          cifs->word_count * 2 +
                          cifs->byte_count;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_decode_header);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_fix_bc_and_retry)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFilterRules rules;
  unsigned char *ucp = cifs->packet_ptr + 33;

  if (cifs->decode_phase != SSH_APPGW_CIFS_DECODE_HEADER)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_byte_count);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_MY5, ("Correcting byte count..."));

  ucp += cifs->word_count * 2;

  SSH_ASSERT((ucp - (unsigned char *)cifs->packet_ptr) <
                                      (SSH_APPGW_CIFS_MAX_PACKET_SIZE - 2));

  SSH_PUT_16BIT_LSB_FIRST(ucp, cifs->byte_count);

  rules = SSH_APPGW_CIFS_FILTER_RULES_GET(cifs->command);

  /* Correct also the ANDX-block */
  if (rules->flags & SSH_APPGW_CIFS_ANDX_COMMAND)
    {
      ucp = cifs->parameters;

      /* Re-calculate the packet-size */
      cifs->packet_size = SSH_APPGW_SMB_HEADER_LEN +
                          cifs->word_count * 2 +
                          cifs->byte_count;

      SSH_PUT_8BIT(ucp+1, 0x00);
      /* Correct the 'andx_offset' */
      SSH_PUT_16BIT_LSB_FIRST(ucp+2, cifs->packet_size);
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_decode_header);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_decode_header)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char * ucp = cifs->packet_ptr;
  SshUInt8 dos_error_class;
  SshUInt16 dos_error_code;
  SshUInt8 flags;
  SshUInt16 flags2;
  SshUInt32 error_code;
  SshUInt8 andx_command;
  SshAppgwCifsFilterRules cmd_rules;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Decoding CIFS/SMB header."));

  cifs->decode_phase = SSH_APPGW_CIFS_DECODE_HEADER;

  cifs->fid = SSH_APPGW_CIFS_ID_DONT_CARE;
  cifs->andx_depth_level = 0;
  cifs->andx_ctx = &cifs->andx[0];
  cifs->andx_ctx->carrier_cmd = 0xFF;
  cifs->andx_ctx->embedded_cmd = 0xFF;
  cifs->andx_ctx->offset = 0;
  cifs->cmd_ctx = NULL;
  cifs->first_cmd_ctx = NULL;
  cifs->orig_request = NULL;
  cifs->andx_commands = NULL;
  cifs->transaction = 0;
  cifs->response = 0;
  cifs->command_failed = 0;
  cifs->unicode_strings = 0;
  cifs->nt_error_codes = 0;
  cifs->embedded_cmds = 0;
  cifs->buffer = NULL;
  cifs->parameters = NULL;
  cifs->no_response = 0;
  cifs->no_timeout = 0;
  cifs->response_wait_time = SSH_APPGW_CIFS_REQUEST_TIMEOUT;
  cifs->tree = NULL;

  /* Check the header length */
  if (cifs->packet_size < SSH_APPGW_SMB_HEADER_LEN)
    {
      ssh_appgw_audit_event(conn->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Broken (too short) CIFS/SMB packet.",
                            SSH_AUDIT_ARGUMENT_END);

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  /* Skip the protocol ID (already checked) */
  ucp += SSH_APPGW_CIFS_PROTOCOL_ID_LEN;

  /* Decode the header (important fields only) */
  cifs->command = SSH_GET_8BIT(ucp);
  dos_error_class = SSH_GET_8BIT(ucp+1);
  dos_error_code = SSH_GET_16BIT_LSB_FIRST(ucp+3);
  error_code = SSH_GET_32BIT_LSB_FIRST(ucp+1);
  flags = SSH_GET_8BIT(ucp+5);
  flags2 = SSH_GET_16BIT_LSB_FIRST(ucp+6);
  /* Skip some "not so interesting"/unknown fields... */
  ucp = cifs->packet_ptr + 24;
  cifs->tid = SSH_GET_16BIT_LSB_FIRST(ucp);
  cifs->pid = SSH_GET_16BIT_LSB_FIRST(ucp+2);
  cifs->uid = SSH_GET_16BIT_LSB_FIRST(ucp+4);
  cifs->mid = SSH_GET_16BIT_LSB_FIRST(ucp+6);

  /* Interpret some useful flags (for easier usage) */
  if (flags & 0x80)
    cifs->response = 1;

  if (flags2 & 0x0041)
    conn->server_flags.long_filenames = 1;

  if (flags2 & 0x8000)
    cifs->unicode_strings = 1;

  /* Does the header use NT style error codes? */
  if (flags2 & 0x4000)
    {
      cifs->nt_error_codes = 1;

      if (error_code)
        {
          cifs->command_failed = 1;
          cifs->error.nt.error_code = error_code;
        }

      SSH_DEBUG(SSH_D_DATADUMP, ("- error_code = 0x%08X",
				 (unsigned int) error_code));
    }
  else
    {
      /* DOS style error codes */
      if (dos_error_class != 0x00)
        {
          cifs->command_failed = 1;
          cifs->error.dos.error_class = dos_error_class;
          cifs->error.dos.error_code = dos_error_code;
        }

      SSH_DEBUG(SSH_D_DATADUMP,
                ("- error_class = 0x%02X", dos_error_class));
      SSH_DEBUG(SSH_D_DATADUMP,
                ("- error_code = 0x%04X", dos_error_code));
    }

  cifs->word_count = SSH_GET_8BIT(ucp+8);

  SSH_DEBUG(SSH_D_DATADUMP, ("- flags = 0x%02X", flags));
  SSH_DEBUG(SSH_D_DATADUMP, ("- flags2 = 0x%04X", flags2));
  SSH_DEBUG(SSH_D_DATADUMP, ("- tid = 0x%04X", cifs->tid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- pid = 0x%04X", cifs->pid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- uid = 0x%04X", cifs->uid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- mid = 0x%04X", cifs->mid));
  SSH_DEBUG(SSH_D_DATADUMP, ("- word_count = %d", cifs->word_count));

  if (ssh_appgw_cifs_st_wc_interop_fix(cifs))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_fix_wc_and_retry);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of word_count value */
  if ((SSH_APPGW_SMB_HEADER_LEN + cifs->word_count*2) > cifs->packet_size)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Invalid word count value (%d) in SMB/CIFS header!",
                 cifs->word_count));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->word_count)
    cifs->parameters = (unsigned char *)ucp+9;

  /* Skip the parameter words */
  ucp += 9 + (cifs->word_count * 2);

  cifs->byte_count = SSH_GET_16BIT_LSB_FIRST(ucp);

  SSH_DEBUG(SSH_D_DATADUMP, ("- byte_count = %d", cifs->byte_count));

  if (ssh_appgw_cifs_st_bc_interop_fix(cifs))
    {
      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_fix_bc_and_retry);
      return SSH_FSM_CONTINUE;
    }

  /* Check the validity of byte_count value */
  if (cifs->packet_size < (SSH_APPGW_SMB_HEADER_LEN +
                           cifs->word_count*2 + cifs->byte_count))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Invalid byte count (%d) value in SMB/CIFS header!",
                 cifs->byte_count));

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  if (cifs->byte_count > 0)
    cifs->buffer = ucp+2;

  if (cifs->client)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("CIFS: %s %s %@ > %@",
                 ssh_appgw_cifs_cmd_to_name(cifs->command),
                 (cifs->response == 0) ? "request" : "response",
                 ssh_ipaddr_render, &conn->ctx->initiator_ip,
                 ssh_ipaddr_render, &conn->ctx->responder_ip));
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("CIFS: %s %s %@ > %@",
                 ssh_appgw_cifs_cmd_to_name(cifs->command),
                 (cifs->response == 0) ? "request" : "response",
                 ssh_ipaddr_render, &conn->ctx->responder_ip,
                 ssh_ipaddr_render, &conn->ctx->initiator_ip));
    }

  /* Check whether packet contains appended secondary command(s) */
  cmd_rules = SSH_APPGW_CIFS_FILTER_RULES_GET(cifs->command);

  if (cmd_rules->flags & SSH_APPGW_CIFS_ANDX_COMMAND)
    {
      if (cifs->command_failed == 0)
        {
          /* There must be at least two parameter words (because this is
             "andx" command) */
          if (cifs->word_count < 2)
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_packet);
              return SSH_FSM_CONTINUE;
            }

          andx_command = SSH_GET_8BIT((unsigned char *)cifs->parameters);

          if (andx_command != 0xFF)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Packet contains embedded commands"));

              cifs->embedded_cmds = 1;
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("No embedded commands"));
            }
        }
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_prefilter);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_prefilter)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFilterRules rules;

  SSH_DEBUG(SSH_D_MY5, ("Pre-filtering CIFS/SMB message [step 1]."));

  /* Step1: Filter messages according the version of CIFS/SMB protocol */
  switch (cifs->command)
    {
    /* NT LM 0.12 */
    case SSH_SMB_COM_NT_TRANSACTION:
    case SSH_SMB_COM_NT_TRANSACTION_SECONDARY:
    case SSH_SMB_COM_NT_CREATE_ANDX:
    case SSH_SMB_COM_NT_CANCEL:
    case SSH_SMB_COM_NT_RENAME:
      if (conn->server_flags.nt_smbs == 0)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_version);
          return SSH_FSM_CONTINUE;
        }
      break;

    /* PC NETWORK PROGRAM 1.0 Only! */
    case SSH_SMB_COM_PROCESS_EXIT:
      if (conn->cifs_version != SSH_APPGW_CIFS_VERSION_PC_NW)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_version);
          return SSH_FSM_CONTINUE;
        }
      break;

    /* "LANMAN 1.0" */
    case SSH_SMB_COM_SESSION_SETUP_ANDX:
    case SSH_SMB_COM_LOCK_AND_READ:
    case SSH_SMB_COM_WRITE_AND_UNLOCK:
    case SSH_SMB_COM_READ_RAW:
    case SSH_SMB_COM_READ_MPX:
    case SSH_SMB_COM_WRITE_RAW:
    case SSH_SMB_COM_WRITE_MPX:
    case SSH_SMB_COM_WRITE_COMPLETE:
    case SSH_SMB_COM_READ_MPX_SECONDARY:
    case SSH_SMB_COM_SET_INFORMATION2:
    case SSH_SMB_COM_QUERY_INFORMATION2:
    case SSH_SMB_COM_LOCKING_ANDX:
    case SSH_SMB_COM_TRANSACTION:
    case SSH_SMB_COM_TRANSACTION_SECONDARY:
    case SSH_SMB_COM_IOCTL:
    case SSH_SMB_COM_IOCTL_SECONDARY:
    case SSH_SMB_COM_COPY:
    case SSH_SMB_COM_MOVE:
    case SSH_SMB_COM_ECHO:
    case SSH_SMB_COM_WRITE_AND_CLOSE:
    case SSH_SMB_COM_OPEN_ANDX:
    case SSH_SMB_COM_READ_ANDX:
    case SSH_SMB_COM_WRITE_ANDX:
    case SSH_SMB_COM_CLOSE_AND_TREE_DISC:
    case SSH_SMB_COM_FIND_NOTIFY_CLOSE:
    case SSH_SMB_COM_TREE_CONNECT_ANDX:
    case SSH_SMB_COM_FIND:
    case SSH_SMB_COM_FIND_UNIQUE:
    /* "LM1.2X002" */
    case SSH_SMB_COM_TRANSACTION2:
    case SSH_SMB_COM_TRANSACTION2_SECONDARY:
    case SSH_SMB_COM_FIND_CLOSE2:
    case SSH_SMB_COM_LOGOFF_ANDX:
      if (conn->cifs_version < SSH_APPGW_CIFS_VERSION_CORE_PLUS)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_version);
          return SSH_FSM_CONTINUE;
        }
      break;

    /* PC NETWORK PROGRAM 1.0 or later */
    case SSH_SMB_COM_NEGOTIATE:
    case SSH_SMB_COM_CREATE_DIRECTORY:
    case SSH_SMB_COM_DELETE_DIRECTORY:
    case SSH_SMB_COM_OPEN:
    case SSH_SMB_COM_CREATE:
    case SSH_SMB_COM_CLOSE:
    case SSH_SMB_COM_FLUSH:
    case SSH_SMB_COM_DELETE:
    case SSH_SMB_COM_RENAME:
    case SSH_SMB_COM_QUERY_INFORMATION:
    case SSH_SMB_COM_SET_INFORMATION:
    case SSH_SMB_COM_READ:
    case SSH_SMB_COM_WRITE:
    case SSH_SMB_COM_LOCK_BYTE_RANGE:
    case SSH_SMB_COM_UNLOCK_BYTE_RANGE:
    case SSH_SMB_COM_CREATE_TEMPORARY:
    case SSH_SMB_COM_CREATE_NEW:
    case SSH_SMB_COM_CHECK_DIRECTORY:
    case SSH_SMB_COM_SEEK:
    case SSH_SMB_COM_TREE_CONNECT:
    case SSH_SMB_COM_TREE_DISCONNECT:
    case SSH_SMB_COM_QUERY_INFORMATION_DISK:
    case SSH_SMB_COM_SEARCH:
    case SSH_SMB_OPEN_PRINT_FILE:
    case SSH_SMB_WRITE_PRINT_FILE:
    case SSH_SMB_CLOSE_PRINT_FILE:
    case SSH_SMB_GET_PRINT_QUEUE:
    case SSH_SMB_SEND_SINGLE_BLOCK:
      /* These commands are allowed for all CIFS versions */
      break;

    default:
      {
        char tmpbuf[32];
        ssh_snprintf(tmpbuf, sizeof(tmpbuf), "type=%u", cifs->command);

        ssh_appgw_audit_event(conn->ctx,
                              SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                              SSH_AUDIT_TXT, "unknown CIFS/SMB packet dropped",
                              SSH_AUDIT_TXT, tmpbuf,
                              SSH_AUDIT_ARGUMENT_END);
      }

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_MY5, ("Pre-filtering CIFS/SMB message [step 2]."));

  rules = SSH_APPGW_CIFS_FILTER_RULES_GET(cifs->command);

  /* Step2: Filter messages according the session phase */
  switch (conn->session_phase)
    {
    case SSH_APPGW_CIFS_SESSION_CLOSED:
      if ((rules->flags & SSH_APPGW_CIFS_ALLOW_REQUEST_WHEN_CLOSED) &&
          (cifs->response == 0))
        break;

      if ((rules->flags & SSH_APPGW_CIFS_ALLOW_RESPONSE_WHEN_CLOSED) &&
          (cifs->response == 1))
        break;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
      return SSH_FSM_CONTINUE;
      break;

    case SSH_APPGW_CIFS_SESSION_NEGOTIATING:
      /* only SMB_COM_NEGOTIATE response allowed */
      if ((cifs->command != SSH_SMB_COM_NEGOTIATE) ||
          (cifs->response == 0))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_APPGW_CIFS_SESSION_AUTHENTICATING:
      if ((cifs->command != SSH_SMB_COM_SESSION_SETUP_ANDX) &&
          (cifs->command != SSH_SMB_COM_TREE_CONNECT_ANDX) &&
          (cifs->command != SSH_SMB_COM_TREE_DISCONNECT) &&
          (cifs->command != SSH_SMB_COM_LOGOFF_ANDX))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_APPGW_CIFS_SESSION_STEADY:
      {
        Boolean check_session = TRUE;

        /* Should we perform session check */
        if (rules->flags & SSH_APPGW_CIFS_NO_SESSION_CHECK)
          check_session = FALSE;

        if ((rules->flags & SSH_APPGW_CIFS_ALLOW_0_UID_RESPONSE) &&
            (cifs->response == 1) &&
            (cifs->uid == 0))
          check_session = FALSE;

        /* Do we have a valid session? */
        if ((check_session == TRUE) &&
            (ssh_appgw_cifs_session_lookup(conn, cifs) == NULL))
          {
            SSH_DEBUG(SSH_D_NETFAULT, ("Invalid session!"));

            SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
            return SSH_FSM_CONTINUE;
          }
      }
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  /* Step3: Forward for further filtering */
  cifs->decode_phase = SSH_APPGW_CIFS_FILTER_COMMAND;

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_continue_filtering);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_continue_filtering)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshAppgwCifsFilterRules rules = NULL;


  switch (cifs->decode_phase)
    {
    case SSH_APPGW_CIFS_FILTER_COMMAND:
      rules = SSH_APPGW_CIFS_FILTER_RULES_GET(cifs->command);

      cifs->andx_ctx->carrier_cmd = cifs->command;
      break;

    case SSH_APPGW_CIFS_FILTER_ANDX:
      /* Check whether this embedded command is allowed for the "major"
         command */
      if (ssh_appgw_cifs_is_embedded_cmd_allowed(cifs->andx_ctx->carrier_cmd,
                                                cifs->andx_ctx->embedded_cmd))
        {
          rules = SSH_APPGW_CIFS_FILTER_RULES_GET(
                                                cifs->andx_ctx->embedded_cmd);

          if (rules->flags & SSH_APPGW_CIFS_ANDX_COMMAND)
            {
              SshAppgwCifsAndxCmdCtx prev = cifs->andx_ctx;

              cifs->andx_depth_level++;

              if (cifs->andx_depth_level >= SSH_APPGW_CIFS_MAX_NESTED_ANDX)
                {
                  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsupported_andx);
                  return SSH_FSM_CONTINUE;
                }

              cifs->andx_ctx++;

              cifs->andx_ctx->carrier_cmd = prev->embedded_cmd;
              cifs->andx_ctx->offset = prev->offset;
            }
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsupported_andx);
          return SSH_FSM_CONTINUE;
        }
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  SSH_ASSERT(rules != NULL);

  if (rules->flags & SSH_APPGW_CIFS_ANDX_COMMAND)
    cifs->is_andx_command = TRUE;
  else
    cifs->is_andx_command = FALSE;

  if ((cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND) &&
      (rules->flags & SSH_APPGW_CIFS_MUST_HAVE_TREE))
    {
      cifs->tree = ssh_appgw_cifs_tree_lookup(conn, cifs);

      if (cifs->tree == NULL)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Could not find tree context!"));

          if (cifs->response == 0)
            SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
          else
            SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);

          return SSH_FSM_CONTINUE;
        }
    }

  if (cifs->client)
    {
      if (cifs->response)
        {
          if (rules->flags & SSH_APPGW_CIFS_ALLOW_SERVER_REQUEST)
            {
              /* Some SMB requests can also be originated asynchronously
                 by the _server_! */
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Response from _CLIENT_!"));
              goto check_and_filter_response;
            }
          else
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
              return SSH_FSM_CONTINUE;
            }
        }

check_and_filter_request:

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Filtering %s request.",
                ssh_appgw_cifs_cmd_to_name(rules->cmd.command)));

      if ((cifs->word_count < rules->request.word_count_min) ||
          (cifs->word_count > rules->request.word_count_max))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
          return SSH_FSM_CONTINUE;
        }

      if ((cifs->byte_count < rules->request.byte_count_min) ||
          (cifs->byte_count > rules->request.byte_count_max))
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_byte_count);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(rules->request.filter);
    }
  else
    {
      if (cifs->response == 0)
        {
          if (rules->flags & SSH_APPGW_CIFS_ALLOW_SERVER_REQUEST)
            {
              /* Some SMB requests can also be originated asynchronously
                 by the _server_! */
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Request from _SERVER_!"));
              goto check_and_filter_request;
            }

          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
          return SSH_FSM_CONTINUE;
        }

check_and_filter_response:

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Filtering %s response.",
                ssh_appgw_cifs_cmd_to_name(rules->cmd.command)));

      /* Check whether this is a response to a pending command or cancel
         request */
      cifs->orig_request = ssh_appgw_cifs_pending_request_lookup(conn, cifs);
      if (cifs->orig_request == NULL)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unexpected_packet);
          return SSH_FSM_CONTINUE;
        }

      if (cifs->decode_phase == SSH_APPGW_CIFS_FILTER_COMMAND)
        {
          cifs->cmd_ctx = cifs->orig_request->cmd_ctx;
          cifs->first_cmd_ctx = cifs->cmd_ctx;
          cifs->andx_commands = cifs->orig_request->andx_commands;
        }

      /* Prevent the deletion of this request */
      cifs->orig_request->busy = 1;

      /* If the error flag is on, we don't check word_count and byte_count
         values here */
      if (cifs->command_failed == 0)
        {
          if ((cifs->word_count < rules->response.word_count_min) ||
              (cifs->word_count > rules->response.word_count_max))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_word_count);
              return SSH_FSM_CONTINUE;
            }

          if ((cifs->byte_count < rules->response.byte_count_min) ||
              (cifs->byte_count > rules->response.byte_count_max))
            {
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_invalid_byte_count);
              return SSH_FSM_CONTINUE;
            }
        }

      SSH_FSM_SET_NEXT(rules->response.filter);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_version)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  SSH_DEBUG(SSH_D_NETFAULT,
            ("Command %s not supported by the negotiated CIFS version!",
             ssh_appgw_cifs_cmd_to_name(cifs->command)));

  if (cifs->client)
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
  else
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);

  return SSH_FSM_CONTINUE;
}


/* Unexpected packet received wither from client or server */
SSH_FSM_STEP(ssh_appgw_cifs_st_unexpected_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshIpAddr ip_addr;

  if (cifs->client)
    {
      ip_addr = &conn->ctx->initiator_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
    }
  else
    {
      ip_addr = &conn->ctx->responder_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
    }

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        (cifs->response == 0
                         ? "Unexpected request received"
                         : "Unexpected response received"),
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  return SSH_FSM_CONTINUE;
}


/* Invalid number of data bytes */
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_byte_count)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshIpAddr ip_addr;

  if (cifs->client)
    {
      ip_addr = &conn->ctx->initiator_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
    }
  else
    {
      ip_addr = &conn->ctx->responder_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
    }

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        (cifs->response == 0
                         ? "request containing invalid number of data bytes "
                         "received"
                         : "response containing invalid number of data bytes "
                         "received"),
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  return SSH_FSM_CONTINUE;
}


/* Invalid number of parameter words */
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_word_count)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshIpAddr ip_addr;

  if (cifs->client)
    {
      ip_addr = &conn->ctx->initiator_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
    }
  else
    {
      ip_addr = &conn->ctx->responder_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
    }

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        (cifs->response == 0
                         ? "request containing invalid number of parameter "
                         "words received"
                         : "response containing invalid number of parameter "
                         "words received"),
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  return SSH_FSM_CONTINUE;
}


/* Invalid (broken or illegal) packet from client or server */
SSH_FSM_STEP(ssh_appgw_cifs_st_invalid_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshIpAddr ip_addr;

  if (cifs->client)
    {
      ip_addr = &conn->ctx->initiator_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
    }
  else
    {
      ip_addr = &conn->ctx->responder_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
    }

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        (cifs->response == 0
                         ? "broken request received"
                         : "broken response received"),
                        SSH_AUDIT_ARGUMENT_END);

  return SSH_FSM_CONTINUE;
}


/* Unsupported secondary command */
SSH_FSM_STEP(ssh_appgw_cifs_st_unsupported_andx)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  SshIpAddr ip_addr;

  if (cifs->client)
    {
      ip_addr = &conn->ctx->initiator_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_unsuccessful);
    }
  else
    {
      ip_addr = &conn->ctx->responder_ip;

      SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_drop_packet);
    }

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        (cifs->response == 0
                         ? "request containing illegal/unsupported embedded "
                         "command(s) received"
                         : "response containing illegal/unsupported embedded "
                         "command(s) received"),
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  return SSH_FSM_CONTINUE;
}


/* Generates error response */
SSH_FSM_STEP(ssh_appgw_cifs_st_generate_error_response)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;
  unsigned char *ucp = cifs->packet_ptr;
  SshUInt8 flags = 0x80;  /* Response flag set */
  SshUInt16 flags2 = 0;

  /* Dump the dropped packet */
  SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON, ("CIFS packet dropped!"),
                    cifs->packet_ptr, cifs->packet_size);

  if (conn->server_flags.caseless_pahtnames)
    flags |= 0x08;

  if (conn->server_flags.long_filenames)
    flags2 |= 0x0041;

  if (conn->server_flags.unicode && conn->client_flags.unicode)
    flags2 |= 0x8000;

  if (cifs->nt_error_codes)
    flags2 |= 0x4000;  /* NT style error codes */

  cifs->word_count = 0;
  cifs->byte_count = 0;

  /* Skip the protocol ID (it's correctly set already) */
  SSH_PUT_8BIT(ucp+4, cifs->command);
  if (cifs->nt_error_codes)
    SSH_PUT_32BIT_LSB_FIRST(ucp+5, cifs->error.nt.error_code);
  else
    {
      SSH_PUT_8BIT(ucp+5, cifs->error.dos.error_class);
      SSH_PUT_8BIT(ucp+6, 0);
      SSH_PUT_16BIT_LSB_FIRST(ucp+7, cifs->error.dos.error_code);
    }

  SSH_PUT_8BIT(ucp+9, flags);
  SSH_PUT_16BIT_LSB_FIRST(ucp+10, flags2);
  /* Skip 12 bytes of padding */
  SSH_PUT_16BIT_LSB_FIRST(ucp+24, cifs->tid);
  SSH_PUT_16BIT_LSB_FIRST(ucp+26, cifs->pid);
  SSH_PUT_16BIT_LSB_FIRST(ucp+28, cifs->uid);
  SSH_PUT_16BIT_LSB_FIRST(ucp+30, cifs->mid);
  SSH_PUT_8BIT(ucp+32, cifs->word_count);
  SSH_PUT_16BIT_LSB_FIRST(ucp+33, cifs->byte_count);

  if (cifs->response == 0)
    {
      /* Perform clean-up */
      ssh_appgw_cifs_cmd_contexts_delete(io->conn, cifs->first_cmd_ctx);
      ssh_appgw_cifs_andx_commands_delete(io->conn, cifs->andx_commands);
    }
  else
    {
      if (cifs->orig_request)
        {
          /* delete the pending request (wíthour sending response) */
          cifs->orig_request->busy = 0;
          ssh_appgw_cifs_pending_request_remove(cifs->orig_request);
        }
    }

  cifs->packet_size = SSH_APPGW_SMB_HEADER_LEN;

  ssh_appgw_audit_event(conn->ctx, SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "response injected",
                        SSH_AUDIT_CIFS_COMMAND,
                        ssh_appgw_cifs_cmd_to_name(cifs->command),
                        SSH_AUDIT_ARGUMENT_END);

  /* Dump the injected response */
  SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON, ("CIFS response injected!"),
                    cifs->packet_ptr, cifs->packet_size);

  if (cifs->client)
    {
      if (conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_NBT)
        SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_send_response);
      else
        SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_send_response);
    }
  else
    {
      if (conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_NBT)
        SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_pass_packet);
      else
        SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_pass_packet);
    }

  return SSH_FSM_CONTINUE;
}


/* Drops the original packet and sends "unsuccessful" response to client */
SSH_FSM_STEP(ssh_appgw_cifs_st_unsuccessful)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->nt_error_codes)
    {
      cifs->error.nt.error_code = SSH_APPGW_CIFS_E_UNSUCCESSFUL;
    }
  else
    {
      cifs->error.dos.error_class = SSH_APPGW_CIFS_D_E_CLASS_SERVER;
      cifs->error.dos.error_code = SSH_APPGW_CIFS_D_E_ERROR;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_generate_error_response);
  return SSH_FSM_CONTINUE;
}


/* Drops the original packet and sends "no memory" response to client */
SSH_FSM_STEP(ssh_appgw_cifs_st_out_of_memory)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->nt_error_codes)
    {
      cifs->error.nt.error_code = SSH_APPGW_CIFS_E_NO_MEMORY;
    }
  else
    {
      cifs->error.dos.error_class = SSH_APPGW_CIFS_D_E_CLASS_DOS;
      cifs->error.dos.error_code = SSH_APPGW_CIFS_D_E_NO_MEMORY;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_generate_error_response);
  return SSH_FSM_CONTINUE;
}


/* Performs needed clean up before packet is dropped */
SSH_FSM_STEP(ssh_appgw_cifs_st_drop_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->response == 0)
    {
      /* Perform clean-up */
      ssh_appgw_cifs_cmd_contexts_delete(io->conn, cifs->first_cmd_ctx);
      ssh_appgw_cifs_andx_commands_delete(io->conn, cifs->andx_commands);
    }
  else
    {
      if (cifs->orig_request)
        {
          /* delete the pending request (wíthour sending response) */
          cifs->orig_request->busy = 0;
          ssh_appgw_cifs_pending_request_remove(cifs->orig_request);
        }
    }

  /* DROP the packet */
  SSH_FSM_SET_NEXT(ssh_appgw_cifs_io_st_drop);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_cifs_st_pass_packet)
{
  SshAppgwCifsIO io = (SshAppgwCifsIO) thread_context;
  SshAppgwCifsConn conn = io->conn;
  SshAppgwCifsParser cifs = &io->cifs_parser;

  if (cifs->response)
    {
      if (cifs->orig_request)
        {
          cifs->orig_request->busy = 0;

          /* We shouldn't remove pending transaction requests before they
             have been completed (except when timeout occurs). */
          if (cifs->orig_request->more_processing == 0)
            ssh_appgw_cifs_pending_request_remove(cifs->orig_request);
          else
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("'more_processing' flag set; request not deleted"));
        }
    }
  else /* Request */
    {
      SshAppgwCifsRequest request;

      /* If no_response flag is set, it means that the client is sending
         one-way transaction request (i.e. there won't be any response
         from server). */
      if (cifs->no_response == 0)
        {
          request = ssh_appgw_cifs_pending_request_add(conn, cifs);
          if (request == NULL)
            {
              /* Not enough memory, so it's better to just drop this packet
                 and send error response to client */
              SSH_FSM_SET_NEXT(ssh_appgw_cifs_st_out_of_memory);
              return SSH_FSM_CONTINUE;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("'no_response' flag set; possible "
                                       "response will be dropped"));

#ifdef DEBUG_LIGHT
          if (cifs->cmd_ctx != NULL)
            {
              /* Dump the packet which triggered the invalid state. */
              SSH_DEBUG_HEXDUMP(SSH_D_ERROR, ("Internal error!"),
                                cifs->packet_ptr, cifs->packet_size);
            }

          SSH_ASSERT(cifs->cmd_ctx == NULL);
#endif /* DEBUG_LIGHT */
        }
    }

  if (conn->transport_type == SSH_APPGW_CIFS_TRANSPORT_NBT)
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_nbt_st_pass_packet);
  else
    SSH_FSM_SET_NEXT(ssh_appgw_cifs_msds_st_pass_packet);

  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
