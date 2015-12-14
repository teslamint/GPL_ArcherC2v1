/*
 *
 * appgw_av.c
 *
 * Copyright:
 *  Copyright (c) 2005 SFNT Finland Oy.
 *  All rights reserved.
 *
 * Anti-Virus application layer gateway for SMTP.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "appgw_api.h"
#include "appgw_av.h"
#include "sshfsm.h"
#include "sshencode.h"
#include "sshinetencode.h"
#include "sshfdstream.h"
#include "sshdatastream.h"
#include "sshdsprintf.h"
#include "ssheloop.h"

#ifdef SSHDIST_AV
#ifdef WITH_AV_ALG
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
#ifndef VXWORKS

/* There is a file name conflict between Quicksec and Kaspersky. Both have a
   file named md5.h. Edit file kldclient.h by removing #include "md5.h"
   statement from it. */

#include "anti-virus/md5.h"
#include "anti-virus/kldclient.h"
#include "anti-virus/kaverr.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwAv"

/* Version */
#define AVALG_VERSION 1

/* The name of the application gateway as shown in syslog events */
#define SSH_APPGW_NAME  "av-alg"

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif

#define AVALG_MAX_LINE      1024  /* max. line accepted */
#define SMTP_CMD_LEN        4     /* SMTP commands are 4 bytes */

/* Timeout interval, seconds */
#define AVALG_TIMEOUT_INTERVAL  10

/* Debug print levels */
#define AVALG_D_STATE_CHG (SSH_D_LOWOK + 1)
#define AVALG_D_SMTP      (SSH_D_LOWOK + 2)
#define AVALG_D_CONTENT   (SSH_D_LOWOK + 3)
#define AVALG_D_AV_ENG    (SSH_D_LOWOK + 4)
#define AVALG_D_INJECT    (SSH_D_LOWOK + 5)
#define AVALG_D_STATE     (SSH_D_LOWOK + 6)

/* SMTP reply code ranges */
#define SMTP_REPLY_PREMILINARY_POSITIVE   100
#define SMTP_REPLY_POSITIVE               200
#define SMTP_REPLY_INTERMEDIATE_POSITIVE  300
#define SMTP_REPLY_TRANSIENT_NEGATIVE     400
#define SMTP_REPLY_PERMANENT_NEGATIVE     500

/* Return values for ssh_avalg_get_reply_code() */
#define SMTP_REPLY_CONTINUES  -1  /* reply continues into next line */
#define SMTP_REPLY_FILTER     -2  /* reply continues, filter out this line */

/* SMTP commands, bitmap */
typedef enum
{
  SMTP_CMD_NOOP = 0x0001, SMTP_CMD_HELO = 0x0002, SMTP_CMD_EHLO = 0x0004,
  SMTP_CMD_MAIL = 0x0008, SMTP_CMD_RCPT = 0x0010, SMTP_CMD_DATA = 0x0020,
  SMTP_CMD_RSET = 0x0040, SMTP_CMD_VRFY = 0x0080, SMTP_CMD_EXPN = 0x0100,
  SMTP_CMD_HELP = 0x0200, SMTP_CMD_QUIT = 0x0400, SMTP_CMD_SEND = 0x0800,
  SMTP_CMD_SOML = 0x1000, SMTP_CMD_SAML = 0x2000, SMTP_CMD_TURN = 0x4000,
  SMTP_CMD_BDAT = 0x8000, SMTP_CMD_NONE = 0x10000
} SmtpCommand;

/* Data read/write result */
typedef enum
{
  AV_IO_READY, AV_IO_BLOCK, AV_IO_EOF
} AvIoState;

/* Anti-Virus ALG state machine states */
typedef enum
{
  AV_ST_START, AV_ST_ENVELOPE, AV_ST_TURN, AV_ST_WAIT_REPLY,
  AV_ST_RECEIVE_CONTENT, AV_ST_CONTENT_END, AV_ST_WAIT_ENGINE,
  AV_ST_CHECK, AV_ST_SEND_CONTENT, AV_ST_SEND_END, AV_ST_ERROR,
  AV_ST_LAST
} AvState;

/* Virus check outcomes */
typedef enum
{
  AV_CHECK_RESULT_CLEAN, AV_CHECK_RESULT_VIRUS, AV_CHECK_RESULT_WARNING,
  AV_CHECK_RESULT_SUSPECT, AV_CHECK_RESULT_PROTECTED,
  AV_CHECK_RESULT_CORRUPT, AV_CHECK_RESULT_ERROR, AV_CHECK_RESULT_PARTIAL,
  AV_CHECK_RESULT_LAST
} AvCheckResult;

/* Virus check result actions */
typedef enum
{
  AV_ACTION_PASS, AV_ACTION_REPLACE, AV_ACTION_REPLACE_AND_REPLY,
  AV_ACTION_ADD, AV_ACTION_ADD_AND_REPLY, AV_ACTION_DROP,
  AV_ACTION_LAST
} AvAction;

/* Error codes */
typedef enum
{
  AV_ERROR_NONE, AV_ERROR_LONG_LINE, AV_ERROR_TIMEOUT, AV_ERROR_IO_WRITE,
  AV_ERROR_IO_READ, AV_ERROR_ENGINE_NA, AV_ERROR_ENGINE, AV_ERROR_INPUT_FULL,
  AV_ERROR_OUT_OF_SYNC, AV_ERROR_CONN_CLOSE, AV_ERROR_SHUTDOWN,
  AV_ERROR_RESOURCES, AV_ERROR_TOO_MANY_CONN, AV_ERROR_STORAGE,
  AV_ERROR_BDAT, AV_ERROR_DROP_MAIL, AV_ERROR_CONTENT,
  AV_ERROR_LAST
} AvError;

/* Command pending at AV-server */
typedef enum
{
  AV_COMMAND_NONE, AV_COMMAND_PING, AV_COMMAND_SCAN, AV_COMMAND_GET_KEY_INFO
} AvCommand;

/* Replies to send to SMTP client */
typedef enum
{
  AV_REPLY_NONE, AV_REPLY_502_TURN, AV_REPLY_421_TOO_MANY_CONN,
  AV_REPLY_421_AV_ENGINE_NA, AV_REPLY_421_SHUTDOWN, AV_REPLY_451_TIMEOUT,
  AV_REPLY_451_IO_ERROR, AV_REPLY_451_AV_ENGINE_NA, AV_REPLY_451_AV_ERROR,
  AV_REPLY_451_RESOURCES, AV_REPLY_552_CONTENT, AV_REPLY_552_STORAGE,
  AV_REPLY_500_LONG_LINE, AV_REPLY_500_INPUT_FULL, AV_REPLY_503_BAD_SEQUENCE,
  AV_REPLY_500_BDAT, AV_REPLY_500_CONTENT, AV_REPLY_LAST
} AvReply;

/* Email content parts, bitmap */
typedef enum
{
  CONTENT_NONE, CONTENT_HDR_SUBJECT = 0x01, CONTENT_HDR_FROM = 0x02,
  CONTENT_HDR_TO = 0x04, CONTENT_HDR_CC = 0x08, CONTENT_HDR_DATE = 0x10,
  CONTENT_HDR_MESSAGE_ID = 0x20, CONTENT_HDR_PASS = 0x3f,
  CONTENT_HDR_CONTENT_TYPE = 0x40, CONTENT_HDR_OTHER = 0x80,
  CONTENT_HDR_END = 0x100,
  CONTENT_BODY = 0x200, CONTENT_ALL = 0x3ff
} ContentPart;

/* MIME content types, bitmap */
typedef enum
{
  MIME_CONTENT_TYPE_NONE, MIME_CONTENT_TYPE_PARTIAL = 0x01,
  MIME_CONTENT_TYPE_ENCRYPTED = 0x02, MIME_CONTENT_TYPE_OTHER = 0x04
} MimeContentType;


/* Double linked list implementation */
typedef struct SshListItemRec
{
  struct SshListItemRec *next;
  struct SshListItemRec *prev;
} *SshListItem;

#define SSH_LIST_ADD(list, item) \
{\
  (item)->next = (list);\
  (item)->prev = (list)->prev;\
  (list)->prev->next = item;\
  (list)->prev = item;\
}

#define SSH_LIST_REMOVE(item) \
{\
  (item)->next->prev = (item)->prev;\
  (item)->prev->next = (item)->next;\
}

#define SSH_LIST_IS_EMPTY(list) ((list)->next == list)
#define SSH_LIST_INIT(list) (list)->next = (list)->prev = list

/* Data buffer */
typedef struct AvAlgBuffRec
{
  unsigned char data[AVALG_MAX_LINE];
  size_t pos;
} *AvAlgBuff;

#define ALG_BUFF_BYTES(buff)  (buff)->pos
#define ALG_BUFF_ROOM(buff)   (sizeof((buff)->data) - (buff)->pos)

/* Stream and buffer to read/write data into a file */
typedef struct AvAlgMailContentRec
{
  char name[PATH_MAX];  /* file name */
  struct AvAlgBuffRec buff;
  Boolean is_input; /* TRUE if input stream */
  SshStream stream;
  SshUInt64 size; /* content size */
} *AvAlgMailContent;

/* Extra content inject into mail content header or body */
typedef struct AvAlgInjectRec
{
  SshUInt32 size; /* size of inject */
  SshUInt32 pos;
  ContentPart content_part; /* mail part to inject into */
  char *buff; /* data to inject */
} *AvAlgInject;

/* Mail content filter */
typedef struct AvAlgContentFilterRec
{
  ContentPart part; /* content part */
  int pass;         /* content to pass */
  ContentPart prev_part;
  int prev_pass;
} *AvAlgContentFilter;

/* MIME parser */
typedef struct AvAlgMimeParserRec
{
  ContentPart part; /* content part */
  int parts_parsed; /* content parts parsed */
  MimeContentType content_type; /* content type */
  struct {  /* buffer to unfold header fields */
    int len;
    char buff[AVALG_MAX_LINE]; /* must be at least AVALG_MAX_LINE */
  } unfolded_line;
} *AvAlgMimeParser;

/* Configuration data object */
struct SshAppgwAvConfigRec
{
  /* This has to be first field of the structure */
  struct SshListItemRec link;

  /* Service ID of this configuration data */
  SshUInt32 service_id;

  /* Redirection IP */
  SshIpAddrStruct redirect_ip;

  SshUInt32 redirect_port;    /* port to re-direct connection */
  SshUInt32 max_connections;  /* max. of open connections */
  SshUInt32 max_content_size; /* max. mail content size */
  SshUInt32 timeout;          /* transaction timeout (sec) */
  SshUInt32 engines;          /* number of av-engines to use */

  char *redir_ip;             /* IP to re-direct connection */
  char *working_dir;          /* directory for temp files */
  char *engine_addr;          /* engine unix or IP socket */

  char *ok_action;            /* virus check OK action (for testing) */
  char *virus_action;         /* virus found action */
  char *warning_action;       /* virus warning action */
  char *suspect_action;       /* virus suspect action */
  char *protected_action;     /* protected file action */
  char *corrupt_action;       /* corrupt file action */
  char *error_action;         /* av-check error action */
  char *partial_action;       /* mime partial message action */

  SshUInt32 strings_size; /* sizeof strings buffer */
  char *strings_buff; /* buffer for above config strings */
};

/* An I/O structure for unidirectional communication */
typedef struct AvAlgIoRec
{
  /* Flags */
  unsigned int active : 1;    /* Thread active */
  unsigned int terminate : 1; /* Terminate when already read data has
                                 been flushed */
  unsigned int dst_eof : 1;   /* Destination stream write has returned eof */
  unsigned int initiator: 1;  /* TRUE if connection initiator */

  /* Source stream */
  SshStream src;

  /* Destination stream */
  SshStream dst;

  /* Buffer for input data */
  struct AvAlgBuffRec in_buf;

  /* Buffer for output data */
  struct AvAlgBuffRec out_buf;

  /* Pointer to the connection structure */
  struct AvAlgConnRec *conn;
} *AvAlgIo;

/* A TCP connection through the gateway */
typedef struct AvAlgConnRec
{
  /* Link for list of active connections */
  /* This has to be first field of the structure */
  struct SshListItemRec link;

  /* Anti-Virus check state */
  AvState av_state;

  /* Error */
  AvError error;

  /* Number of SMTP commands to server outstanding */
  int cmds_out;

  /* Unique tag for each connection */
  SshUInt32 tag;

  /* Transaction start time */
  SshTime start_time;

  /* Time error state was entred */
  SshTime error_time;

  /* Reply to send to client from error state */
  AvReply error_reply;

  /* Reply to send to client on content end */
  AvReply content_end_reply;

  /* Initiator and responder IP addresses */
  SshIpAddrStruct initiator_ip;
  SshIpAddrStruct responder_ip;

  /* Mail content stream */
  struct AvAlgMailContentRec content;

  /* Data to inject into mail content */
  struct AvAlgInjectRec inject;

  /* MIME parser */
  struct AvAlgMimeParserRec mime_parser;

  /* Mail content out filter */
  struct AvAlgContentFilterRec filter;

  /* Virus scan result */
  struct {
    Boolean ready;  /* scan ready */
    AvCheckResult result; /* scan result */
    char *infect_list; /* list of viruses and files from engine */
  } scan_result;

  /* The application gateway context */
  SshAppgwContext ctx;

  /* Thread handling the initiator->responder communication */
  SshFSMThreadStruct thread_i;
  struct AvAlgIoRec io_i;

  /* Thread handling the responder->initiator communication */
  SshFSMThreadStruct thread_r;
  struct AvAlgIoRec io_r;

  /* Configuration data for the connection */
  SshAppgwAvConfig config;
} *AvAlgConn;

/* AV-engine interface */
typedef struct AvAlgEngRec
{
  kld_session_t *session;
  kav_check_result_t result;
  Boolean connected;  /* TRUE if connected to AV-server */
  Boolean registered; /* TRUE if file handle is registered to event loop */
  AvCommand command;  /* current command processed by AV-server */
  SshUInt32 user_tag; /* tag of connection that is using the engine */
  char address[PATH_MAX]; /* Engine socket address, Unix domain or IP */
} *AvAlgEng;

/* Context data for AV gateways */
typedef struct AvAlgCtxRec
{
  /* Policy manager */
  SshPm pm;

  /* FSM controlling the gateway */
  SshFSMStruct fsm;

  /* Flags */
  unsigned int registered : 1;  /* Successfully registered with firewall */
  unsigned int shutdown : 1;    /* The system is shutting down */

  /* Running count of connections created */
  SshUInt32 conn_count;

  /* Count of active connections */
  int conn_act;

  /* Active TCP connections through this gateway */
  struct SshListItemRec conn_list;

  /* Known configuration data objects */
  struct SshListItemRec config_list;

  /* AV-engine(s) interface */
  struct AvAlgEngRec av_eng;

  /* Timeout */
  struct SshTimeoutRec timeout;
} *AvAlgCtx;

/******************* Prototypes for static help function ********************/

/* A timeout function to terminate connection */
static void ssh_avalg_connection_terminate(void *context);

/********************** Prototypes for FSM lib state functions **************/

SSH_FSM_STEP(ssh_avalg_st_client);
SSH_FSM_STEP(ssh_avalg_st_server);
SSH_FSM_STEP(ssh_avalg_st_terminate);

/********************** Static data *****************************************/
static AvAlgCtx appgw_av_ctx;

/***************************** Helper functions *****************************/

#ifdef DEBUG_LIGHT
/* Print input line */
static void ssh_avalg_print_input_line(AvAlgIo io, int len)
{
  char buff[AVALG_MAX_LINE];
  char *src = io->initiator ? "C":"S";

  len -= 2; /* cr,lf off */
  memcpy(buff, io->in_buf.data, len);
  buff[len] = '\0';
  SSH_DEBUG(AVALG_D_SMTP, ("%s:\n%s", src, buff));
}

/* Dump Kaspersky av-engine license info */
static void ssh_avalg_dump_key(kld_session_t *session)
{
  const char *contype[]={"local", "network"};
  kld_key_info_t *cur;
  for(cur = session->keys; cur !=0 ; cur = cur->next)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("-------------------------------------------"));
      SSH_DEBUG(SSH_D_NICETOKNOW,("Serial : %04X-%06X-%08X",
        cur->serial[0], cur->serial[1], cur->serial[2]));
      SSH_DEBUG(SSH_D_NICETOKNOW,("Expire : %02d-%02d-%04d",
        cur->expire.day,cur->expire.month, cur->expire.year));
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Days left : %d", cur->daysleft));
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Connection type : %s",
        contype[cur->conn_type]));
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Connection count : %d", cur->count));
      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("-------------------------------------------"));
    }
}

/* Get content part string from code */
static const char *ssh_avalg_content_part_string(ContentPart part)
{
  const struct{
    const ContentPart part;
    const char *string;
  } parts[] = {
    {CONTENT_NONE, "CONTENT_NONE"},
    {CONTENT_HDR_SUBJECT, "CONTENT_HDR_SUBJECT"},
    {CONTENT_HDR_FROM, "CONTENT_HDR_FROM"},
    {CONTENT_HDR_TO, "CONTENT_HDR_TO"},
    {CONTENT_HDR_CC, "CONTENT_HDR_CC"},
    {CONTENT_HDR_DATE, "CONTENT_HDR_DATE"},
    {CONTENT_HDR_MESSAGE_ID, "CONTENT_HDR_MESSAGE_ID"},
    {CONTENT_HDR_CONTENT_TYPE, "CONTENT_HDR_CONTENT_TYPE"},
    {CONTENT_HDR_OTHER, "CONTENT_HDR_OTHER"},
    {CONTENT_HDR_END, "CONTENT_HDR_END"},
    {CONTENT_BODY, "CONTENT_BODY"}
  };
  int i;

  for(i = 0; i < sizeof(parts)/sizeof(parts[0]); i++)
    {
      if (parts[i].part == part)
        return parts[i].string;
    }
  return "CONTENT ?";
}

#endif /* DEBUG_LIGHT */

/* Get string from AvState code */
static const char *ssh_avalg_state_string(AvState state)
{
  const char * const states[AV_ST_LAST] = {
    "start", "envelope", "turn", "wait reply",
    "receive content", "content end", "wait engine",
    "check", "send content", "send end", "error"
  };

  SSH_ASSERT(states[AV_ST_LAST - 1]);

  return states[state];
}

/* Log error into system log */
static void ssh_avalg_log_error(AvAlgConn conn)
{
  const char * const error_strings[AV_ERROR_LAST] = {
    "",                     /* AV_ERROR_NONE */
    "long smtp line",       /* AV_ERROR_LONG_LINE */
    "timeout",              /* AV_ERROR_TIMEOUT */
    "i/o write",            /* AV_ERROR_IO_WRITE */
    "i/o read",             /* AV_ERROR_IO_READ */
    "av-engine n/a",        /* AV_ERROR_ENGINE_NA */
    "av-engine error",      /* AV_ERROR_ENGINE */
    "unexpected input",     /* AV_ERROR_INPUT_FULL */
    "unexpected smtp command",/* AV_ERROR_OUT_OF_SYNC */
    "connection closed",    /* AV_ERROR_CONN_CLOSE */
    "alg shutdown",         /* AV_ERROR_SHUTDOWN */
    "out resources",        /* AV_ERROR_RESOURCES */
    "too many connections", /* AV_ERROR_TOO_MANY_CONN */
    "exceeded storage allocation",/* ERROR_STORAGE */
    "smtp bdat command",    /* AV_ERROR_BDAT */
    "",                     /* AV_ERROR_DROP_MAIL */
    "content parse error",  /* AV_ERROR_CONTENT */
  };

  SSH_ASSERT(error_strings[AV_ERROR_LAST - 1]);

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
    "%s: %@ -> %@; error %d, %s; state: %s",
    SSH_APPGW_NAME, 
    ssh_ipaddr_render, &conn->initiator_ip,
    ssh_ipaddr_render, &conn->responder_ip,
    conn->error, error_strings[conn->error],
    ssh_avalg_state_string(conn->av_state));
}

/* Log scan result into system log */
static void ssh_avalg_log_scan_result(AvAlgConn conn, AvAction action)
{
    const char * const results[AV_CHECK_RESULT_LAST] = {
      "clean",    /* AV_CHECK_RESULT_CLEAN */
      "infected", /* AV_CHECK_RESULT_VIRUS */
      "warning",  /* AV_CHECK_RESULT_WARNING */
      "suspect",  /* AV_CHECK_RESULT_SUSPECT */
      "protected",/* AV_CHECK_RESULT_PROTECTED */
      "corrupt",  /* AV_CHECK_RESULT_CORRUPT */
      "error",    /* AV_CHECK_RESULT_ERROR */
      "partial",  /* AV_CHECK_RESULT_PARTIAL */
    };
    const char * const actions[AV_ACTION_LAST] = {
      "pass",     /* AV_ACTION_PASS */
      "replace",  /* AV_ACTION_REPLACE */
      "replace and reply",/* AV_ACTION_REPLACE_AND_REPLY */
      "add",      /* AV_ACTION_ADD */
      "add and reply", /* AV_ACTION_ADD_AND_REPLY */
      "drop",     /* AV_ACTION_DROP */
    };

  SSH_ASSERT(results[AV_CHECK_RESULT_LAST - 1]);
  SSH_ASSERT(actions[AV_ACTION_LAST - 1]);


  SSH_DEBUG(SSH_D_NICETOKNOW,
    ("%s: %@ -> %@; scan result: %s; action: %s; virus: %s",
    SSH_APPGW_NAME, 
    ssh_ipaddr_render, &conn->initiator_ip,
    ssh_ipaddr_render, &conn->responder_ip,
    results[conn->scan_result.result],
    actions[action],
    conn->scan_result.infect_list ? conn->scan_result.infect_list : "none"));

  if (conn->scan_result.result == AV_CHECK_RESULT_CLEAN)
    {
      ssh_log_event(SSH_LOGFACILITY_MAIL, SSH_LOG_INFORMATIONAL,
        "%s: %@ -> %@; scan result: clean; action: %s",
        SSH_APPGW_NAME, 
        ssh_ipaddr_render, &conn->initiator_ip,
        ssh_ipaddr_render, &conn->responder_ip,
        actions[action]);
    }
  else
    {
      char *infect_list = conn->scan_result.infect_list;
      if (!infect_list)
        infect_list = "n/a";

      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
        "%s: %@ -> %@; scan result: %s; action: %s; virus: %s",
        SSH_APPGW_NAME, 
        ssh_ipaddr_render, &conn->initiator_ip,
        ssh_ipaddr_render, &conn->responder_ip,
        results[conn->scan_result.result],
        actions[action], infect_list);
  }
}

/* Stream callback */
static void
ssh_avalg_stream_cb(SshStreamNotification notification, void *context)
{
  AvAlgConn conn = (AvAlgConn) context;

  /* Simply continue all active threads */
  if (conn->io_i.active)
    ssh_fsm_continue(&conn->thread_i);
  if (conn->io_r.active)
    ssh_fsm_continue(&conn->thread_r);
}

/* Open content stream */
static Boolean ssh_avalg_open_content(AvAlgConn conn, Boolean rd)
{
  SshStream stream;
  int flags = rd ? O_BINARY|O_RDONLY : O_BINARY|O_CREAT|O_WRONLY|O_TRUNC;
  SshIOHandle fd = open(conn->content.name, flags, 0644);
  if (fd == -1)
    return FALSE;

  stream = ssh_stream_fd_wrap(fd, TRUE);
  if (!stream)
    {
      close(fd);
      return FALSE;
    }

  conn->content.is_input = rd;
  conn->content.stream = stream;

  ssh_stream_set_callback(stream, ssh_avalg_stream_cb, conn);

  return TRUE;
}

/* Close content stream */
static void ssh_avalg_close_content(AvAlgConn conn)
{
  if (conn->content.stream)
    {
      ssh_stream_set_callback(conn->content.stream, NULL_FNPTR, NULL);
      ssh_stream_destroy(conn->content.stream);
      conn->content.stream = NULL;
    }
}

/* Free extra content */
static void ssh_avalg_free_inject(AvAlgInject inject)
{
  if (inject->buff)
    ssh_free(inject->buff);

  memset(inject, 0, sizeof(*inject));
}

/* Convert characters to upper case */
static void ssh_avalg_to_upper(char *pc, int len)
{
  while (len--)
    {
      *pc = toupper(*pc);
      pc++;
    }
}

/* Search buffer for a max. 4-character token. Return pointer to last
   character of the token. */
static const char *
ssh_avalg_has_token(const char *buff, int len, int token_bytes, char *token)
{
  long i;
  SshUInt32 mask = 0xffffffff;
  union{
    struct{
      unsigned char c[4];
    } as_byte;
    SshUInt32 as_int;
  } tmp, tok;

  tmp.as_int = tok.as_int = 0;

  memcpy(&tok.as_byte.c[sizeof(tok.as_byte) - token_bytes], token,
    token_bytes);

#ifdef WORDS_BIGENDIAN
  mask >>= token_bytes * 8;
#else
  mask <<= token_bytes * 8;
#endif

  for(i = 0; i < len; i++)
  {
#ifdef WORDS_BIGENDIAN
    tmp.as_int <<= 8;
#else
    tmp.as_int >>= 8;
#endif
    tmp.as_byte.c[3] = *(buff + i);

    if ((tmp.as_int & mask) == tok.as_int)
      return buff + i;
  }
  return NULL;
}

/* Check if input buffer contains cr,lf pair. Return pointer to lf. */
static const char *ssh_avalg_has_line(const char *buff, int len)
{
  char tmp[2] = {'\r','\n'};
  return ssh_avalg_has_token(buff, len, sizeof(tmp), tmp);
}

/* Skip space and tab characters in buffer */
static const char *ssh_avalg_skip_space(const char *buff, int len)
{
  int i;
  for(i = 0; i < len; i++, buff++)
    {
      if (*buff != ' ' && *buff != '\t')
        break;
    }
  return buff;
}

/* Parse mail content. Returns mail content part the line belongs to and
   whether content part changed */
static ContentPart
ssh_avalg_parse_content(Boolean *is_new_part, ContentPart current, char *line,
                        int line_len)
{
  char c;
  int i;
  int copy_bytes;
  int name_len;
  ContentPart part;
  const struct{
    const ContentPart part;
    const char *name;
  } field_names[] = {
    {CONTENT_HDR_SUBJECT, "SUBJECT"},
    {CONTENT_HDR_FROM, "FROM"},
    {CONTENT_HDR_TO, "TO"},
    {CONTENT_HDR_CC, "CC"},
    {CONTENT_HDR_DATE, "DATE"},
    {CONTENT_HDR_MESSAGE_ID, "MESSAGE-ID"},
    {CONTENT_HDR_CONTENT_TYPE, "CONTENT-TYPE"},
  };
  const int MAX_FIELD_NAME = 16;
  char buff[MAX_FIELD_NAME];

  /* Check if header has ended */
  if (current == CONTENT_BODY)
    {
      *is_new_part = FALSE;
      return CONTENT_BODY;
    }

  *is_new_part = TRUE;

  if (current == CONTENT_HDR_END)
    return CONTENT_BODY;

  /* Check if empty line, end of header */
  if (line_len == 2)
    return CONTENT_HDR_END;

  /* Check if folded line, field is continuing */
  c = *line;
  if (current != CONTENT_NONE && (c == ' ' || c == '\t'))
    {
      *is_new_part = FALSE;
      return current;
    }

  /* Check appearance of valid field name. If not found,
     assume header has ended */
  if (!isalnum(c) || !memchr(line, ':', line_len))
    return CONTENT_HDR_END;

  current = CONTENT_HDR_OTHER;

  line_len -= 2;  /* cr,lf off */

  /* Search for field name */
  copy_bytes = sizeof(buff) < line_len ? sizeof(buff) : line_len;
  for(i = 0; i < sizeof(field_names)/sizeof(field_names[0]); i++)
    {
      name_len = strlen(field_names[i].name);
      if (name_len + 1> copy_bytes)
        continue;
      memcpy(buff, line, name_len);
      ssh_avalg_to_upper(buff, name_len);
      if (memcmp(buff, field_names[i].name, name_len) == 0)
        break;
    }

  if (i >= sizeof(field_names)/sizeof(field_names[0]))
    return current;

  part = field_names[i].part;

  /* Found field name, check for colon after it */
  for(i = name_len; i < line_len; i++)
    {
      c = *(line + i);
      if (c == ' ' || c == '\t')
        continue;
      if (c == ':')
        {
          current = part;
          break;
        }
    }
  return current;
}

/* Initialize mail content filter */
static void ssh_avalg_init_filter(AvAlgContentFilter filter, int to_pass)
{
  filter->part = filter->prev_part = CONTENT_NONE;
  filter->pass = filter->prev_pass = to_pass;
}

/* Backtrack mail content filter to previous state */
static inline void ssh_avalg_backtrack_filter(AvAlgContentFilter filter)
{
  filter->part = filter->prev_part;
  filter->pass = filter->prev_pass;
}

/* Filter mail content. Returns number of bytes to pass (positive) or
   drop (negative) */
static int
ssh_avalg_filter_content(AvAlgContentFilter filter, char *buff, int len)
{
  const char *line_end;
  int line_len;
  ContentPart part;
  int pass;
  Boolean is_new_part;

  if (filter->part == CONTENT_BODY)
    return (filter->pass & CONTENT_BODY) ? len : -len;

  line_end = ssh_avalg_has_line(buff, len);

  if (!line_end)
    return 0; /* need more data */

  line_len = line_end - buff + 1;

#ifdef DEBUG_LIGHT
  {
    char debug_buff[AVALG_MAX_LINE + 1];
    memcpy(debug_buff, buff, line_len);
    debug_buff[line_len - 2] = '\0';
    SSH_DEBUG(AVALG_D_CONTENT, ("Line:\n%s", debug_buff));
  }
#endif

  part = ssh_avalg_parse_content(&is_new_part, filter->part, buff, line_len);
  pass = filter->pass;

  if (is_new_part)
    {
      /* Filter out if field repeats in header */
      if (filter->part & CONTENT_HDR_PASS)
        pass &= ~filter->part;

      SSH_DEBUG(AVALG_D_CONTENT, ("%s, %s",
        ssh_avalg_content_part_string(part),
        (part & pass) ? "pass" : "filter out"));
    }

  /* Save previous state to be able to backtrack */
  filter->prev_part = filter->part;
  filter->prev_pass = filter->pass;

  filter->part = part;
  filter->pass = pass;

  if (!(part & pass))
    line_len = -line_len;

  return line_len;
}

/* Initialize mime parser */
static void ssh_avalg_init_mime_parser(AvAlgMimeParser parser)
{
  parser->part = CONTENT_NONE;
  parser->parts_parsed = 0;
  parser->content_type = MIME_CONTENT_TYPE_NONE;
  parser->unfolded_line.len = 0;
}

/* Parse MIME content type field. Return FALSE on parse error. */
static Boolean
ssh_avalg_parse_mime_content_type(AvAlgMimeParser parser)
{
  int i;
  const char *pc;
  int copy_bytes;
  int type_len;
  char *line = parser->unfolded_line.buff;
  int line_len = parser->unfolded_line.len;
  const struct{
    const MimeContentType type;
    const char *name;
  } content_types[] = {
    {MIME_CONTENT_TYPE_PARTIAL, "MESSAGE/PARTIAL"},
    {MIME_CONTENT_TYPE_ENCRYPTED, "MULTIPART/ENCRYPTED"}
  };
  const int MAX_FIELD = 20;
  char buff[MAX_FIELD];

  if (line_len <= 2)
    return TRUE;

  /* We are intrested only in MIME content type field in content header. And
     only content types message/partial and multipart/encrypted */

  parser->content_type = MIME_CONTENT_TYPE_OTHER;

  /* Find semicolon after field name */
  pc = (char *)memchr(line + 12, ':', line_len - 12);
  if (!pc)
    return FALSE;

  pc++;
  pc = ssh_avalg_skip_space(pc, line_len - (pc - line)); /* skip white space */

  line_len -= pc - line;
  line_len -= 2;  /* cr,lf off */

  /* Search for field name */
  copy_bytes = sizeof(buff) < line_len ? sizeof(buff) : line_len;
  for(i = 0; i < sizeof(content_types)/sizeof(content_types[0]); i++)
    {
      type_len = strlen(content_types[i].name);
      if (type_len > copy_bytes)
        continue;
      memcpy(buff, pc, type_len);
      ssh_avalg_to_upper(buff, type_len);
      if (memcmp(buff, content_types[i].name, type_len) == 0)
        {
          parser->content_type = content_types[i].type;
          break;
        }
    }
  return TRUE;
}

/* Parse MIME fields from content header. Return FALSE on parse error. */
static Boolean
ssh_avalg_parse_mime(AvAlgMimeParser parser, char *line, int line_len)
{
  Boolean is_new_part;
  ContentPart content_part;
  Boolean ret_val = TRUE;
  const char *pc;

  /* Parse email content */
  content_part = ssh_avalg_parse_content(&is_new_part, parser->part,
    line, line_len);

  /* We parse only header, not individual parts of multipart mime */
  if (content_part != CONTENT_BODY)
    {
      /* Unfold header fields */
      if (!is_new_part)
        {
          int unfolded_len = parser->unfolded_line.len;
          int len = line_len;
          if (unfolded_len + len > sizeof(parser->unfolded_line.buff))
            return FALSE;
          pc = ssh_avalg_skip_space(line, len);
          len -= pc - line;
          unfolded_len -= 2; /* cr, lf off */
          memcpy(&parser->unfolded_line.buff[unfolded_len], pc, len);
          parser->unfolded_line.len = unfolded_len + len;
        }
      else
        {
          if (parser->part == CONTENT_HDR_CONTENT_TYPE)
            {
              /* Check that content type field does not repeat */
              if (parser->parts_parsed & parser->part)
                ret_val = FALSE;
              else
                ret_val = ssh_avalg_parse_mime_content_type(parser);
            }
          parser->parts_parsed |= parser->part;
          memcpy(parser->unfolded_line.buff, line, line_len);
          parser->unfolded_line.len = line_len;
        }
    }

  parser->part = content_part;

  return ret_val;
}

/* Count number of new lines in a string. Return number of new lines. */
static int
ssh_avalg_count_nl(const char *str, const char **plast, int *max_line)
{
  int nl_cnt = 0;
  int line_len;
  char *pc;

  *plast = NULL;
  *max_line = 0;
  while ((pc = strchr(str, '\n')) != NULL)
    {
      nl_cnt++;
      line_len = (pc - str) + 1;
      if (line_len > *max_line)
        *max_line = line_len;
        str = pc + 1;
    }
  if (nl_cnt)
    *plast = str - 1;

  return nl_cnt;
}

/* Copy src string to dst. Expand nl characters to cr,nl pairs. Literal
   '\''n' character sequences are replaced with cr,nl pairs */
static char *ssh_avalg_copy_string(char *dst, const char *src)
{
  Boolean has_back_slash = FALSE;

  while (*src)
    {
      char c = *src++;
      if (c == '\n')
        *dst++ = '\r';
      *dst++ = c;
      if (c == 'n' && has_back_slash)
        {
          *(dst - 2) = '\r';
          *(dst - 1) = '\n';
        }
      has_back_slash = c == '\\' ? TRUE : FALSE;
    }
    *dst++ = '\0';

    return dst;
}

/* Add folding to a string. After each cr,lf pair, add a tab. Return pointer
   to next free byte in buffer. Assumes buffer has room. */
static char *ssh_avalg_add_folding(char *src, int len)
{
  Boolean has_cr = FALSE;

  while (len)
    {
      char c = *src++;
      len--;
      if (c == '\n' && has_cr)
        {
          memmove(src + 1, src, len);
          *src++ = '\t';
        }
      has_cr = c == '\r' ? TRUE : FALSE;
    }
    return src;
}

/* Find item on a list with a tag at offset */
static SshListItem
ssh_avalg_find_list_item(SshListItem list, int offset, SshUInt32 tag)
{
  SshListItem list_item = list->next;
  while (list_item != list)
    {
      if (*((SshUInt32 *)(((char *)list_item) + offset)) == tag)
        return list_item;
      list_item = list_item->next;
    }
  return NULL;
}

/* Give asynchronous command to av-engine. Return TRUE on success. */
static Boolean
ssh_avalg_command_eng(AvAlgEng av_eng, AvCommand command, char *file_name)
{
  tERROR kld_error = errUNEXPECTED;

  av_eng->command = command;
  switch(command)
    {
      case AV_COMMAND_NONE:
        break;
      case AV_COMMAND_PING:
        kld_error = KldPing(av_eng->session);
        break;
      case AV_COMMAND_SCAN:
        kld_error = KldScanFile(av_eng->session, file_name, &av_eng->result,
                                SF_STOPAFTERFIRST | SF_ARCHIVED | SF_PACKED |
                                SF_SFXARCHIVED | SF_MAILBASES |
                                SF_MAILPLAIN | SF_CODEANALYZER | SF_WARNINGS |
                                SF_SHOW_ALL, NULL);
        break;
      case AV_COMMAND_GET_KEY_INFO:
        kld_error = KldGetKeyInfo(av_eng->session);
        break;
    }

  if (kld_error == errIN_PROGRESS)
    {
      SSH_DEBUG(AVALG_D_AV_ENG, ("av-server command started"));
      ssh_io_set_fd_request(av_eng->session->socket,
        av_eng->session->read_state ? SSH_IO_READ : SSH_IO_WRITE);
      return TRUE;
    }

  av_eng->command = AV_COMMAND_NONE;
  SSH_DEBUG(SSH_D_ERROR,("av-server command error: ERROR 0x%x",kld_error));
  return FALSE;
}

/* Wake-up all connections in wait engine state */
static void ssh_avalg_wake_wait_engine(AvAlgCtx ctx)
{
  AvAlgConn conn;
  SshListItem list_item;

  /* Wake up all threads in wait engine state to give a chance to start
     a scan. Do the wake up in priority order, longest waiters first.
     This relies in a fact that threads in wait-engine state are put
     into end of execute ring by ssh_fsm_continue() and executed in a
     round robin fashion. Connections in the connections list are
     longest waiter first.
  */
  list_item = ctx->conn_list.next;
  while (list_item != &ctx->conn_list)
    {
      conn = (AvAlgConn)list_item;
      if (conn->av_state == AV_ST_WAIT_ENGINE && conn->io_i.active)
        ssh_fsm_continue(&conn->thread_i);
      list_item = list_item->next;
    }
}

/* Handle AV-scan completion */
static void
ssh_avalg_event_scan_done(AvAlgCtx ctx, unsigned int kld_error)
{
  AvAlgConn conn;
  AvCheckResult result;
  char *info = NULL;

  /* Find the connection that requested the scan */
  conn = (AvAlgConn)ssh_avalg_find_list_item(&ctx->conn_list,
    offsetof(struct AvAlgConnRec, tag), ctx->av_eng.user_tag);

  /* If connection is waiting at AV-check state. Copy result for it and
     wake it up */
  if (conn && conn->av_state == AV_ST_CHECK)
    {
      /* If there was an error in performing scan, set result to error */
      result = AV_CHECK_RESULT_ERROR;
      if (kld_error == errOK)
        switch(ctx->av_eng.result.result)
          {
            case KAV_RESULT_OK:
              result = AV_CHECK_RESULT_CLEAN;
              break;
            case KAV_RESULT_INFECTED:
              result = AV_CHECK_RESULT_VIRUS;
              info = (char *)ssh_strdup(ctx->av_eng.result.szVirusList);
              break;
            case KAV_RESULT_WARNING:
              result = AV_CHECK_RESULT_WARNING;
              info = (char *)ssh_strdup(ctx->av_eng.result.szWarningsList);
              break;
            case KAV_RESULT_SUSPICION:
              result = AV_CHECK_RESULT_SUSPECT;
              info = (char *)ssh_strdup(ctx->av_eng.result.szSuspiciosList);
              break;
            case KAV_RESULT_PROTECTED:
              result = AV_CHECK_RESULT_PROTECTED;
              break;
            case KAV_RESULT_CORRUPTED:
              result = AV_CHECK_RESULT_CORRUPT;
              break;
            case KAV_RESULT_ERROR:
              result = AV_CHECK_RESULT_ERROR;
              break;
            default:
              result = AV_CHECK_RESULT_ERROR;
              SSH_DEBUG(SSH_D_ERROR,
                ("Ill scan result %d", ctx->av_eng.result));
              break;
          }

      conn->scan_result.result = result;
      conn->scan_result.infect_list = info;
      conn->scan_result.ready = TRUE;

      if (conn->io_i.active)
        ssh_fsm_continue(&conn->thread_i);
    }

  KldCleanupResult(&ctx->av_eng.result);
}

/* Close av-engine connection */
static void ssh_appgw_conn_close_engine(AvAlgEng av_eng)
{
  if (av_eng->registered)
    {
      ssh_io_unregister_fd(av_eng->session->socket, TRUE);
      av_eng->registered = FALSE;
    }

  if (av_eng->connected)
    {
      KldSessionClose(av_eng->session);
      av_eng->connected = FALSE;
    }
}

/* Close av-engine connection and destroy session */
static void ssh_appgw_conn_destroy_engine(AvAlgEng av_eng)
{
  ssh_appgw_conn_close_engine(av_eng);

  if (av_eng->session)
    KldSessionDestroy(av_eng->session);

  av_eng->session = NULL;
}

/* Callback for av-engine socket events */
static void ssh_avalg_engine_io_cb(unsigned int events, void *context)
{
  AvAlgCtx ctx = (AvAlgCtx)context;
  AvAlgEng av_eng = (AvAlgEng)&ctx->av_eng;
  int read_state = av_eng->session->read_state;

  KldSessionProcess(av_eng->session);

  SSH_DEBUG(AVALG_D_AV_ENG, ("ev %x, busy %d, read_state %d,%d",
    events, SESSION_BUSY(av_eng->session), read_state,
    av_eng->session->read_state));

  if (SESSION_BUSY(av_eng->session))
    {
      /* Engine command is still in progress, let event loop wait for file
         handle to become ready again */
      if (read_state != av_eng->session->read_state)
        ssh_io_set_fd_request(av_eng->session->socket,
          av_eng->session->read_state ? SSH_IO_READ : SSH_IO_WRITE);
    }
  else
    {
      unsigned int kld_error = av_eng->session->last_error;

      /* Engine command is complete */

      ssh_io_set_fd_request(av_eng->session->socket, 0);

      if (kld_error == errOK)
          SSH_DEBUG(AVALG_D_AV_ENG, ("av-engine command complete OK"));
      else
        {
          ssh_appgw_conn_close_engine(av_eng);
          SSH_DEBUG(SSH_D_ERROR,
            ("av-server command error: ERROR 0x%x", kld_error));
        }

      switch(av_eng->command)
        {
          case AV_COMMAND_SCAN:
            ssh_avalg_event_scan_done(ctx, kld_error);
            break;
          case AV_COMMAND_GET_KEY_INFO:
            if (kld_error == errOK)
              {
#ifdef DEBUG_LIGHT
                ssh_avalg_dump_key(av_eng->session);
#endif
                KldKeyCleanupResult(av_eng->session);
              }
            break;
          case AV_COMMAND_PING:
          default:
            break;
        }

      av_eng->command = AV_COMMAND_NONE;

      /* Wake up all threads in wait engine state */
      ssh_avalg_wake_wait_engine(ctx);
    }
}

/* Connect to av-engine. Return TRUE on success. */
static Boolean ssh_appgw_conn_to_engine(AvAlgCtx ctx)
{
  const int CONNECT_TIMEOUT = 5;
  AvAlgEng av_eng = &ctx->av_eng;
  tERROR kld_error;

  /* Create session to AVESERVER if not already created */
  if (!av_eng->session)
    {
      const unsigned int SESSION_BUFF_SIZE = 8192;
      const unsigned int SESSION_RD_TIMEOUT = 5*60;
      const unsigned int SESSION_WR_TIMEOUT = SESSION_RD_TIMEOUT;
      unsigned int flags = KLD_SESSION_ASYNC;

      /* Engine address may be unix domain socket for local engine or ip
         address or host name for remote engine */
      if (av_eng->address[0] != '/')
        flags |= KLD_SESSION_NETWORK;

      av_eng->session =
        KldCreateSession(SESSION_BUFF_SIZE, SESSION_RD_TIMEOUT,
                         SESSION_WR_TIMEOUT, KLD_SESSION_ASYNC);
      if (!av_eng->session)
      {
        SSH_DEBUG(SSH_D_ERROR,("Cannot create session to AV-server"));
        return FALSE;
      }
    }

  if (!av_eng->connected)
    {
      kld_error =
        KldConnect(av_eng->address, CONNECT_TIMEOUT, av_eng->session);
      if (kld_error != errOK)
        {
          SSH_DEBUG(SSH_D_ERROR,
            ("Cannot connect to  AV-server: ERROR %x",kld_error));
          ssh_appgw_conn_close_engine(av_eng);
          return FALSE;
        }
      av_eng->connected = TRUE;
    }

  if (!av_eng->registered)
    av_eng->registered =
      ssh_io_register_fd(av_eng->session->socket, ssh_avalg_engine_io_cb, ctx);

  if (!av_eng->registered)
    {
      SSH_DEBUG(SSH_D_ERROR,("Cannot register fd"));
      ssh_appgw_conn_close_engine(av_eng);
    }
  return av_eng->registered;
}

/* Free memory allocated for scan results */
void ssh_avalg_free_scan_result(AvAlgConn conn)
{
  if (conn->scan_result.infect_list)
    ssh_free(conn->scan_result.infect_list);

  memset(&conn->scan_result, 0, sizeof(conn->scan_result));
}

/* Copy data into buffer. Return TRUE if data copied. */
static Boolean
ssh_avalg_copy_data(AvAlgBuff dst, const void *src, int len)
{
  if (dst->pos + len > sizeof(dst->data))
    return FALSE;

  memcpy(&dst->data[dst->pos], src, len);
  dst->pos += len;

  return TRUE;
}

/* Delete data from buffer */
static void ssh_avalg_delete_data(AvAlgBuff dst, int len)
{
  dst->pos -= len;
  if (dst->pos)
    memcpy(dst->data, &dst->data[len], dst->pos);
}

/* Move data between buffers. Return TRUE if data was moved. */
static Boolean ssh_avalg_move(AvAlgBuff dst, AvAlgBuff src, int len)
{
  if (len == 0)
    return FALSE;

  if (len + dst->pos > sizeof(dst->data))
    return FALSE;

  ssh_avalg_copy_data(dst, src->data, len);
  ssh_avalg_delete_data(src, len);

  return TRUE;
}

/* Write SMTP reply to output buffer. Returns TRUE if buffer had room. */
static Boolean 
ssh_avalg_wr_reply(AvAlgBuff out_buff, AvReply reply_code)
{
  const struct{
    Boolean add_domain;
    const char *reply;
  } replies[AV_REPLY_LAST] = {
    {FALSE, "552 5.5.0 Requested mail action aborted\r\n"},
    {FALSE, "502 5.5.1 Command not implemented: \"TURN\"\r\n"},
    {TRUE, "421  4.4.5 Too many connections, "
      "closing transmission channel\r\n"},
    {TRUE, "421  4.3.0 Antivirus engine not available, "
      "closing transmission channel\r\n"},
    {TRUE, "421  4.3.2 System shutting down, "
      "closing transmission channel\r\n"},
    {FALSE, "451 4.5.0 Requested action aborted: Transaction timeout\r\n"},
    {FALSE, "451 4.5.0 Requested action aborted: I/O error\r\n"},
    {FALSE, "451 4.5.0 Requested action aborted: "
      "Antivirus engine not available\r\n"},
    {FALSE, "451 4.5.0 Requested action aborted: Antivirus engine error\r\n"},
    {FALSE, "451 4.5.0 Requested action aborted: Out of memory\r\n"},
    {FALSE, "552 5.6.0 Requested mail action aborted: "
      "Mail content unacceptable\r\n"},
    {FALSE, "552 5.3.4 Requested mail action aborted: "
      "Exceeded storage allocation\r\n"},
    {FALSE, "500 5.5.1 Syntax error, long line\r\n"},
    {FALSE, "500 5.5.1 Syntax error, input buffer full\r\n"},
    {FALSE, "503 5.5.1 Bad sequence of commands\r\n"},
    {FALSE, "500 5.5.1 Command unrecognized: BDAT\r\n"},
    {FALSE, "500 5.6.0 Syntax error: MIME parser error\r\n"},
  };
  const int DOMAIN_OFFS = 4;
  char buff[AVALG_MAX_LINE];
  int domain_len = 0;
  const char *reply = replies[reply_code].reply;
  int reply_len = strlen(reply);

  SSH_ASSERT(replies[AV_REPLY_LAST - 1].reply);

  if (replies[reply_code].add_domain)
    {
      if (getdomainname(&buff[DOMAIN_OFFS], sizeof(buff) - DOMAIN_OFFS) == 0)
        domain_len = strlen(&buff[DOMAIN_OFFS]);
      if (domain_len + reply_len > sizeof(buff))
        domain_len = 0;
    }

  memcpy(buff, reply, DOMAIN_OFFS);
  memcpy(&buff[DOMAIN_OFFS + domain_len], reply + DOMAIN_OFFS,
    reply_len - DOMAIN_OFFS);

  /* If buffer has room, copy response into it */
  return ssh_avalg_copy_data(out_buff, buff, reply_len + domain_len);
}

/* Move state machine to a new state */
static AvIoState
ssh_avalg_new_state(AvAlgConn conn, AvState new_state)
{
  AvState old_state = conn->av_state;

  if (old_state == new_state)
    return AV_IO_READY;

  SSH_DEBUG(AVALG_D_STATE_CHG,
    ("%d, %s -> %s", conn->tag, ssh_avalg_state_string(old_state),
    ssh_avalg_state_string(new_state)));

  conn->av_state = new_state;

  ssh_fsm_continue(&conn->thread_i);
  ssh_fsm_continue(&conn->thread_r);

  return AV_IO_READY;
}

/* Move state machine to error state */
static AvIoState
ssh_avalg_to_error_state(AvAlgConn conn, AvError error)
{
  const AvReply error_to_reply[AV_ERROR_LAST] = {
    AV_REPLY_NONE,            /* AV_ERROR_NONE */
    AV_REPLY_500_LONG_LINE,   /* AV_ERROR_LONG_LINE */
    AV_REPLY_451_TIMEOUT,     /* AV_ERROR_TIMEOUT */
    AV_REPLY_451_IO_ERROR,    /* AV_ERROR_IO_WRITE */
    AV_REPLY_451_IO_ERROR,    /* AV_ERROR_IO_READ */
    AV_REPLY_421_AV_ENGINE_NA,/* AV_ERROR_ENGINE_NA */
    AV_REPLY_451_AV_ERROR,    /* AV_ERROR_ENGINE */
    AV_REPLY_500_INPUT_FULL,  /* AV_ERROR_INPUT_FULL */
    AV_REPLY_503_BAD_SEQUENCE,/* AV_ERROR_OUT_OF_SYNC */
    AV_REPLY_NONE,            /* AV_ERROR_CONN_CLOSE */
    AV_REPLY_421_SHUTDOWN,    /* AV_ERROR_SHUTDOWN */
    AV_REPLY_451_RESOURCES,   /* AV_ERROR_RESOURCES */
    AV_REPLY_421_TOO_MANY_CONN,/* AV_ERROR_TOO_MANY_CONN */
    AV_REPLY_552_STORAGE,     /* AV_ERROR_STORAGE */
    AV_REPLY_500_BDAT,        /* AV_ERROR_BDAT */
    AV_REPLY_552_CONTENT,     /* AV_ERROR_DROP_MAIL */
    AV_REPLY_500_CONTENT,     /* AV_ERROR_CONTENT */
  };
  AvState old_state = conn->av_state;

  SSH_ASSERT(error_to_reply[AV_ERROR_LAST - 1]);

  if (old_state == AV_ST_ERROR)
    return AV_IO_READY;

  conn->error = error;

  /* Close content stream and free resources */
  ssh_avalg_close_content(conn);
  ssh_avalg_free_inject(&conn->inject);

  /* Log error into system log */

  /* Mail drop is already logged into mail or system log. Connection closed
     from envelope state is normal. */
  if (error != AV_ERROR_DROP_MAIL)
    if (!(error == AV_ERROR_CONN_CLOSE && old_state == AV_ST_ENVELOPE))
      ssh_avalg_log_error(conn);

  conn->error_time = ssh_time();
  conn->error_reply = error_to_reply[error];

  return ssh_avalg_new_state(conn, AV_ST_ERROR);
}

/* Timeout call-back function */
static void ssh_avalg_timeout_cb(void *context)
{
  AvAlgCtx ctx = (AvAlgCtx)context;
  SshListItem list_item;
  AvAlgConn conn;
  SshTime time;

  /* Create session to AVESERVER if not already created */
  if (!ctx->av_eng.registered)
    {
      if (ssh_appgw_conn_to_engine(ctx))
        if (!ssh_avalg_command_eng(&ctx->av_eng,
              AV_COMMAND_GET_KEY_INFO, NULL))
          ssh_appgw_conn_close_engine(&ctx->av_eng);

    }
  else
    {
      /* Ping AV engine */
      if (ctx->av_eng.command == AV_COMMAND_NONE)
        if (!ssh_avalg_command_eng(&ctx->av_eng, AV_COMMAND_PING, NULL))
          ssh_appgw_conn_close_engine(&ctx->av_eng);
    }

  /* Check connection timeouts */
  time = ssh_time();
  list_item = ctx->conn_list.next;
  while (list_item != &ctx->conn_list)
    {
      conn = (AvAlgConn)list_item;
      if (conn->av_state != AV_ST_ERROR)
        {
          if (time - conn->start_time > conn->config->timeout)
            {
              /* Try to write reply to client. This may not succeed. */
              ssh_avalg_to_error_state(conn, AV_ERROR_TIMEOUT);
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      else
        {
          /* Force close if it stays error state */
          const int MAX_ERROR_STATE_TIME = 5;  /* seconds */
          if (time - conn->error_time > MAX_ERROR_STATE_TIME)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Force out of error state"));
              ssh_fsm_set_next(&conn->thread_i, ssh_avalg_st_terminate);
              ssh_fsm_set_next(&conn->thread_r, ssh_avalg_st_terminate);
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      list_item = list_item->next;
    }

  ssh_register_timeout(&ctx->timeout,
    AVALG_TIMEOUT_INTERVAL, 0, ssh_avalg_timeout_cb, context);
}

/* Convert configuration string to action */
static AvAction
ssh_avalg_string_to_action(const char *str, const char **string_out)
{
  /* Mail content actions */
  const struct{
    const AvAction action;
    const char *string;
  } actions[]={
    {AV_ACTION_PASS,"[pass]"},
    {AV_ACTION_DROP,"[drop]"},
    {AV_ACTION_REPLACE,"[replace]"},
    {AV_ACTION_REPLACE_AND_REPLY,"[replace!]"},
    {AV_ACTION_ADD,"[add]"},
    {AV_ACTION_ADD_AND_REPLY,"[add!]"}
  };
  int i;
  int str_len;

  if (string_out)
    *string_out = NULL;

  if (*str == '\0')
    return AV_ACTION_PASS;  /* default, pass mail */

  str_len = strlen(str);

  for(i = 0; i < sizeof(actions)/sizeof(actions[0]); i++)
    {
      int len = strlen(actions[i].string);
      if (str_len >= len && memcmp(actions[i].string, str, len) == 0)
        {
          if (str_len > len && string_out)
            *string_out = str + len;
          return actions[i].action;
        }
    }
  return AV_ACTION_PASS;  /* default, pass mail */
}

/* Split line into tokens. Return number of tokens found. */
static int
ssh_avalg_tokenize(char *line, int line_len, char *(token_ptrs[]),
                   int tbl_size)
{
  int i;
  int tok_index = 0;
  /* Token delimiters are white space, : ( ) < > characters */
  char *delimiters = ":()<>";

  /* Scan line for tokens, insert pointer to token start and end into
     a table */
  for(i = 0; i < line_len;)
    {
      char c = *(line + i);
      Boolean is_space = isspace((int)c);
      Boolean is_delimiter =
        is_space ? FALSE : (strchr(delimiters, c) != NULL);

      if (tok_index & 1) /* if we are inside a token */
        {
          if (is_space)
            {
               /* Token end */
              token_ptrs[tok_index++] = line + i - 1;
              if (tok_index >= tbl_size)
                break;
                i++;
            }
          else if (is_delimiter)
            {
              if ((line + i) == token_ptrs[tok_index - 1])
                {
                  /* Token is a single delimeter */
                  token_ptrs[tok_index++] = line + i;
                  i++;
                }
              else
                token_ptrs[tok_index++] = line + i - 1;
              if (tok_index >= tbl_size)
                break;
            }
          else
            i++;
        }
      else  /* we are looking for token start */
        {
          if (!is_space)
            {
              token_ptrs[tok_index++] = line + i; /* token start */
              if (tok_index >= tbl_size)
                break;
              if (!is_delimiter)
                i++;
            }
          else
            i++;
        }
    }
  return tok_index;
}

/* Check if line contains SMTP command. Return command or none. */
static SmtpCommand ssh_avalg_get_cmd(char *(token_ptrs[]), int tbl_size)
{
  const struct
  {
    const SmtpCommand code;
    union {
      const char as_char[SMTP_CMD_LEN + 1];
      const SshUInt32 as_int;
    } cmd;
  } smtp_commands[] = {
    {SMTP_CMD_NOOP,{"NOOP"}}, {SMTP_CMD_HELO,{"HELO"}},
    {SMTP_CMD_EHLO,{"EHLO"}}, {SMTP_CMD_MAIL,{"MAIL"}},
    {SMTP_CMD_RCPT,{"RCPT"}}, {SMTP_CMD_DATA,{"DATA"}},
    {SMTP_CMD_RSET,{"RSET"}}, {SMTP_CMD_VRFY,{"VRFY"}},
    {SMTP_CMD_EXPN,{"EXPN"}}, {SMTP_CMD_HELP,{"HELP"}},
    {SMTP_CMD_QUIT,{"QUIT"}}, {SMTP_CMD_SEND,{"SEND"}},
    {SMTP_CMD_SOML,{"SOML"}}, {SMTP_CMD_SAML,{"SAML"}},
    {SMTP_CMD_TURN,{"TURN"}}, {SMTP_CMD_BDAT,{"BDAT"}},
    {SMTP_CMD_NONE,{"NONE"}}
  };
  union {
    char as_char[SMTP_CMD_LEN + 1];
    SshUInt32 as_int;
  } token;
  int i;
  int token_len;

  if (tbl_size < 2)
    return SMTP_CMD_NONE;

  token_len = token_ptrs[1] - token_ptrs[0] + 1;

  if (token_len != SMTP_CMD_LEN)
    return SMTP_CMD_NONE;

  memcpy(token.as_char, token_ptrs[0], token_len);
  token.as_char[SMTP_CMD_LEN] = '\0';
  ssh_avalg_to_upper(token.as_char, SMTP_CMD_LEN);

  /* All commands are 4 bytes long. Compare as integers */
  for(i = 0; smtp_commands[i].code != SMTP_CMD_NONE; i++)
    {
      if (token.as_int == smtp_commands[i].cmd.as_int)
        break;
    }
  return smtp_commands[i].code;
}

/* Check if line contains SMTP command. Return command or none. */
static SmtpCommand ssh_avalg_has_cmd(char *line, int line_len, int cmds)
{
  const int MAX_TOKEN_PTRS = 128;
  char *(token_ptrs[MAX_TOKEN_PTRS]);
  int num_tokens;
  SmtpCommand smtp_cmd;

  if (line_len == 0)
    return SMTP_CMD_NONE;

  num_tokens = ssh_avalg_tokenize(line,line_len,token_ptrs,
    MAX_TOKEN_PTRS) / 2;

  if (num_tokens == 0)
    return SMTP_CMD_NONE;

  smtp_cmd = ssh_avalg_get_cmd(token_ptrs,num_tokens * 2);

  return (smtp_cmd & cmds) ? smtp_cmd : SMTP_CMD_NONE;
}

/* Get reply code from a reply line. Return reply code if last line of reply,
   negative if reply continues in the next line. */
static int ssh_avalg_get_reply_code(char *(token_ptrs[]), int tbl_size)
{
  /* Ehlo keywords we filter out. We don't support chunking */
  const struct{
    const int len;
    const char *string;
  } keywords[] = {
    {12, "250-CHUNKING"},
    {8 , "250-TURN"},
    {14, "250-BINARYMIME"}
  };
  const int REPLY_CODE_LEN = 3;
  const int MAX_TOKEN_LEN = 16;
  char token[MAX_TOKEN_LEN + 1];
  int i;
  int token_len = token_ptrs[1] - token_ptrs[0] + 1;

  if (token_len < REPLY_CODE_LEN)
    return SMTP_REPLY_CONTINUES;
  if (token_len > MAX_TOKEN_LEN)
    return SMTP_REPLY_CONTINUES;

  memcpy(token, token_ptrs[0], token_len);
  token[token_len] = '\0';

  for(i = 0; i < REPLY_CODE_LEN; i++)
    if (!isdigit((int)token[i]))
      return SMTP_REPLY_CONTINUES;

  if (token_len == REPLY_CODE_LEN)
    return atoi(token);

  /* Check for ehlo extension keywords we filter out */
  ssh_avalg_to_upper(token, token_len);
  for(i = 0; i < sizeof(keywords)/sizeof(keywords[0]); i++)
    {
      if (keywords[i].len == token_len &&
          memcmp(token, keywords[i].string, token_len) == 0)
        return SMTP_REPLY_FILTER;
    }
  return SMTP_REPLY_CONTINUES;
}

/* Write data into a stream. Return ready/would block/eof. */
static AvIoState ssh_avalg_wr_stream(SshStream stream, AvAlgBuff buff)
{
  int wrote;

  /* If stream is not open or nothing to write */
  if (!stream || buff->pos == 0)
    return AV_IO_BLOCK;

  wrote = ssh_stream_write(stream, buff->data, buff->pos);

  if (wrote < 0)
    return AV_IO_BLOCK; /* Would block. Wait. */
  else if (wrote == 0)
    {
      /* Write failed */
      SSH_DEBUG(SSH_D_ERROR,("write failed.. file closed"));
      return AV_IO_EOF;
    }

  buff->pos -= wrote;
  if (buff->pos)
    memcpy(buff->data, &buff->data[wrote], buff->pos);

  return AV_IO_READY;
}

/* Read data from a stream. Return ready/would block/eof. */
static AvIoState ssh_avalg_rd_stream(SshStream stream, AvAlgBuff buff)
{
  int read;

  if (!stream || buff->pos >= sizeof(buff->data))
    return AV_IO_BLOCK;

  /* Read some data */
  read = ssh_stream_read(stream, &buff->data[buff->pos],
    sizeof(buff->data) - buff->pos);

  if (read < 0)
    return AV_IO_BLOCK; /* Would block. Wait for more input */
  else if (read == 0)
    return AV_IO_EOF;

  buff->pos += read;

  return AV_IO_READY;
}

/* Make content to inject into content body. Return TRUE on success. */
static Boolean
ssh_avalg_get_body_inject(AvAlgInject inject, const char *str,
                          const char *result_str)
{
  char *buff;
  char *dst;
  int str_len = 0;
  int result_len = 0;
  int nl_cnt = 0;
  int max_line;
  const char *plast;
  const char *empty_line = "\r\n";
  const int HEADER_LEN = 2; /* empty line before body */
  const int TRAILER_LEN = 2;

  if (str)
    str_len = strlen(str);

  /* Result string may contain multiple lines. \n characters will be
     replaced by \n\r */

  if (result_str)
    {
      nl_cnt = ssh_avalg_count_nl(result_str, &plast, &max_line);
      if (max_line < AVALG_MAX_LINE)
          result_len = strlen(result_str);
      else
        nl_cnt = 0;
    }

  buff = ssh_calloc(1, str_len + result_len + nl_cnt + HEADER_LEN +
    TRAILER_LEN + 1);
  if (!buff)
    return FALSE;

  dst = buff;

  /* Empty line */
  memcpy(dst, empty_line, HEADER_LEN);
  dst += HEADER_LEN;

  /* Copy configured string */
  if (str_len)
    memcpy(dst, str, str_len);

  dst += str_len;

  /* Copy viruses found list from av-engine */
  if (result_len)
    dst = ssh_avalg_copy_string(dst, result_str) - 1;

  memcpy(dst, empty_line, TRAILER_LEN);
  dst += TRAILER_LEN;

  inject->buff = buff;
  inject->pos = 0;
  inject->size = dst - buff;
  inject->content_part = CONTENT_BODY;

  return TRUE;
}

/* Make content to inject into content header. Return TRUE on success. */
static Boolean
ssh_avalg_get_header_inject(AvAlgInject inject, ContentPart content_part,
                            const char *str, const char *field_name)
{
  char *buff;
  char *dst;
  int str_len = 0;
  int name_len = 0;
  int max_folding = 0;
  /* Room to add one header line plus folding */
  const int EXTRA_LEN = AVALG_MAX_LINE + 3;

  if (!str)
    return TRUE;  /* nothing to inject */

  str_len = strlen(str);

  max_folding = str_len / 2;/* folding, each \r,\n pair adds \t */

  name_len = strlen(field_name);

  buff = ssh_calloc(1, str_len + name_len + max_folding + EXTRA_LEN + 1);
  if (!buff)
    return FALSE;

  dst = buff;

  /* Field name */
  memcpy(dst, field_name, name_len);
  dst += name_len;

  /* Copy configured string */
  memcpy(dst, str, str_len);

  /* Add folding if multiple lines */
  dst = ssh_avalg_add_folding(dst, str_len);

  /* Action strings end in with line end (cr,lf), remove last \t added
     by ssh_avalg_add_folding() */
  dst--;

  inject->buff = buff;
  inject->pos = 0;
  inject->size = dst - buff;
  inject->content_part = content_part;

  return TRUE;
}

/* Add content header line into header buffer */
void ssh_avalg_add_header_inject(AvAlgInject inject, char *line, int len)
{
  const int FOLDING_LEN = 3;
  char *pc;

  /* Remove field name from content */
  pc = strchr(line, ':');
  pc++;
  /* Skip space */
  while (*pc == ' ' || *pc == '\t')
    pc++;

  len -= pc - line;

  /* If only field name, nothing to add */
  if (len == 2)
    return;

  /* Remove line end from inject */
  inject->size -= 2;

  /* Add line end plus folding */
  memcpy(inject->buff + inject->size, "\r\n\t", FOLDING_LEN);
  inject->size += FOLDING_LEN;

  /* Add line from content minus field name */
  memcpy(inject->buff + inject->size, pc, len);
  inject->size += len;

  SSH_DEBUG_HEXDUMP(AVALG_D_INJECT,
    ("Inject, len %d:",
    inject->size),
    inject->buff, inject->size);
}

/* Inject data into mail content */
static AvIoState ssh_avalg_inject(AvAlgIo io)
{
  AvAlgInject inject = &io->conn->inject;
  int len;

  len = inject->size - inject->pos;
  len = sizeof(io->out_buf.data) < len ? sizeof(io->out_buf.data) : len;
  ssh_avalg_copy_data(&io->out_buf, inject->buff + inject->pos, len);
  inject->pos += len;
  if (inject->pos == inject->size)
    ssh_avalg_free_inject(inject);
  return AV_IO_READY;
}

/* Handle input from SMTP client in ENVELOPE state. Return READY or BLOCK.*/
static AvIoState ssh_avalg_hnd_client_envelope(AvAlgIo io)
{
  AvAlgConn conn = io->conn;
  const char *line_end = ssh_avalg_has_line(io->in_buf.data, io->in_buf.pos);
  int line_len;
  SmtpCommand smtp_cmd;
  int data_cmds;

  if (!line_end)
    return AV_IO_BLOCK;

  /* Move data from client to server one line at a time */
  line_len = line_end - (char *)io->in_buf.data + 1;

#ifdef DEBUG_LIGHT
  ssh_avalg_print_input_line(io, line_len);
#endif

  data_cmds = SMTP_CMD_DATA | SMTP_CMD_SEND | SMTP_CMD_SOML | SMTP_CMD_SAML;
  smtp_cmd = ssh_avalg_has_cmd(io->in_buf.data, line_len,
    data_cmds | SMTP_CMD_TURN | SMTP_CMD_BDAT);

  if (smtp_cmd == SMTP_CMD_NONE)
    {
      ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      conn->cmds_out++;
      return AV_IO_READY;
    }

  /* Check for DATA cmd from SMTP client */
  if (smtp_cmd & data_cmds)
    {
      ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      conn->cmds_out++;
      return ssh_avalg_new_state(conn, AV_ST_WAIT_REPLY);
    }
  else if (smtp_cmd == SMTP_CMD_TURN)
    {
      ssh_avalg_delete_data(&io->in_buf, line_len);
      ssh_fsm_continue(&conn->thread_r);
      return ssh_avalg_new_state(conn, AV_ST_TURN);
    }
  else if (smtp_cmd == SMTP_CMD_BDAT)
    return ssh_avalg_to_error_state(conn, AV_ERROR_BDAT);
  else
    {
      ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      conn->cmds_out++;
      return AV_IO_READY;
    }
}

/* Handle error state. Return ready or block */
static AvIoState ssh_avalg_hnd_error(AvAlgIo io)
{
  AvAlgConn conn = io->conn;

  ssh_avalg_delete_data(&io->in_buf, io->in_buf.pos);

  /* If out stream is closed, the thread is done */
  if (io->dst_eof)
    return AV_IO_EOF;

  /* Try write reply to client if requested. It may not succeed if there is
      no room in output buffer. */
  if (conn->error_reply != AV_REPLY_NONE)
    {
      if (ssh_avalg_wr_reply(&io->out_buf, conn->error_reply))
        {
          conn->error_reply = AV_REPLY_NONE;
          return AV_IO_READY;
        }
      else
        return AV_IO_BLOCK;
    }
  else
    {
      /* Wait for output buffer to empty */
      return io->out_buf.pos ? AV_IO_BLOCK : AV_IO_EOF;
    }
}

/* Handle send content state. Return ready or block */
static AvIoState ssh_avalg_hnd_client_send_content(AvAlgIo io)
{
  AvAlgConn conn = io->conn;
  AvAlgMailContent content = &conn->content;
  AvAlgInject inject = &conn->inject;
  int len;

  SSH_ASSERT(io->out_buf.pos == 0);

  /* There should be no input from client after content ends until reply.
     If input buffer fills, go to error state. */
  if (ALG_BUFF_ROOM(&io->in_buf) == 0)
    return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);

  /* If we are injecting our own content into mail, continue doing it until
     inject buffer is exhausted */
  if (inject->pos)
    return ssh_avalg_inject(io);

  /* Stream will be closed on eof in the thread main loop */
  if (content->stream == NULL && content->buff.pos == 0)
    {
      /* If we haven't injected yet, do it now */
      if (inject->size)
        return ssh_avalg_inject(io);

      /* All content has been sent */
      /* Send content end mark to server */
      ssh_avalg_copy_data(&io->out_buf, ".\r\n", 3);
      /* If we let server reply, go to envelope state */
      if (conn->content_end_reply == AV_REPLY_NONE)
        {
          conn->cmds_out++;
          conn->start_time = ssh_time();
          return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
        }
      else
        {
          /* ALG will reply and block server reply */
          return ssh_avalg_new_state(conn, AV_ST_SEND_END);
        }
    }

  if (content->buff.pos == 0)
    return AV_IO_BLOCK; /* need more data */

  /* Process data from content buffer */
  len = ssh_avalg_filter_content(&conn->filter, content->buff.data,
    content->buff.pos);
  if (len == 0) /* more data required */
    return AV_IO_BLOCK;
  /* Check if we are in a correct place to start inject our content */
  if (inject->size)
    {
      if (inject->content_part == CONTENT_BODY)
        {
          /* Inject into body */
          if (conn->filter.part == CONTENT_BODY)
            {
              ssh_avalg_backtrack_filter(&conn->filter);
              return ssh_avalg_inject(io);
            }
        }
      else
        {
          /* Inject into header */
          if (inject->content_part == conn->filter.part)
            {
              if (len < 0)
                {
                  /* Consume line */
                  ssh_avalg_delete_data(&content->buff, -len);
                  return ssh_avalg_inject(io);
                }
              else
                {
                  ssh_avalg_add_header_inject(inject, content->buff.data, len);
                  ssh_avalg_delete_data(&content->buff, len);
                  return ssh_avalg_inject(io);
                }
            }
          else if (conn->filter.part == CONTENT_HDR_END)
            {
              /* Header is missing a field we want to inject into. Add it. */
              ssh_avalg_backtrack_filter(&conn->filter);
              return ssh_avalg_inject(io);
            }
        }
    }

  if (len < 0)
    {
      ssh_avalg_delete_data(&content->buff, -len);
      return AV_IO_READY;
    }
  else
    {
      ssh_avalg_move(&io->out_buf, &conn->content.buff, len);
      return AV_IO_READY;
    }
}

/* Anti-virus check complete */
static AvIoState ssh_avalg_av_check_complete(AvAlgConn conn)
{
  SshAppgwAvConfig config = conn->config;
  const char *str;
  const char *virus_str;
  AvAction action;

  /* Is virus-check ready */
  if (!conn->scan_result.ready)
    return AV_IO_BLOCK;

  /* Scan result is available */

  /* If content is pgp encrypted, Kaspersky engine does not return
     result protected. Set result to protected if we parsed mime
     content-type encrypted */
  if (conn->mime_parser.content_type == MIME_CONTENT_TYPE_ENCRYPTED &&
      conn->scan_result.result == AV_CHECK_RESULT_CLEAN)
    conn->scan_result.result = AV_CHECK_RESULT_PROTECTED;

  virus_str = conn->scan_result.infect_list;
  switch(conn->scan_result.result)
    {
      case AV_CHECK_RESULT_CLEAN: str = config->ok_action; break;
      case AV_CHECK_RESULT_VIRUS: str = config->virus_action; break;
      case AV_CHECK_RESULT_WARNING: str = config->warning_action; break;
      case AV_CHECK_RESULT_SUSPECT: str = config->suspect_action; break;
      case AV_CHECK_RESULT_PROTECTED: str = config->protected_action; break;
      case AV_CHECK_RESULT_CORRUPT: str = config->corrupt_action; break;
      case AV_CHECK_RESULT_ERROR: str = config->error_action; break;
      case AV_CHECK_RESULT_PARTIAL: str = config->partial_action; break;
      default:
        SSH_NOTREACHED;
    }

  /* Get action from configuration string */
  action = ssh_avalg_string_to_action(str, &str);

  /* Log scan result into mail or system log */
  ssh_avalg_log_scan_result(conn, action);

  switch(action)
    {
      case AV_ACTION_PASS:
        /* Pass mail to server */
        ssh_avalg_init_filter(&conn->filter, CONTENT_ALL);
        if (ssh_avalg_open_content(conn, TRUE))
          ssh_avalg_new_state(conn, AV_ST_SEND_CONTENT);
        else
          ssh_avalg_to_error_state(conn, AV_ERROR_IO_READ);
        break;
      case AV_ACTION_REPLACE:
      case AV_ACTION_REPLACE_AND_REPLY:
        ssh_avalg_init_filter(&conn->filter,
          CONTENT_HDR_PASS | CONTENT_HDR_END);
          /* Replace content body with configured message */
          if (ssh_avalg_open_content(conn, TRUE))
            {
              if (ssh_avalg_get_body_inject(&conn->inject, str, virus_str))
                {
                  /* Either pass server reply to client or generate permanent
                      negative reply and block server reply */
                  conn->content_end_reply =
                    action == AV_ACTION_REPLACE_AND_REPLY ?
                      AV_REPLY_552_CONTENT : AV_REPLY_NONE;
                  ssh_avalg_new_state(conn, AV_ST_SEND_CONTENT);
                }
              else
                ssh_avalg_to_error_state(conn, AV_ERROR_RESOURCES);
            }
          else
            ssh_avalg_to_error_state(conn, AV_ERROR_IO_READ);
          break;
      case AV_ACTION_ADD:
      case AV_ACTION_ADD_AND_REPLY:
        ssh_avalg_init_filter(&conn->filter, CONTENT_ALL);
          /* Add to content header a configured message */
          if (ssh_avalg_open_content(conn, TRUE))
            {
              if (ssh_avalg_get_header_inject(&conn->inject,
                    CONTENT_HDR_SUBJECT, str, "Subject: "))
                {
                  /* Either pass server reply to client or generate permanent
                      negative reply and block server reply */
                  conn->content_end_reply =
                    action == AV_ACTION_ADD_AND_REPLY ?
                      AV_REPLY_552_CONTENT : AV_REPLY_NONE;
                  ssh_avalg_new_state(conn, AV_ST_SEND_CONTENT);
                }
              else
                ssh_avalg_to_error_state(conn, AV_ERROR_RESOURCES);
            }
          else
            ssh_avalg_to_error_state(conn, AV_ERROR_IO_READ);
          break;
      case AV_ACTION_DROP:
          /* Drop mail. In order to do that, connection has to be closed */
          ssh_avalg_to_error_state(conn, AV_ERROR_DROP_MAIL);
          break;
      default:
        SSH_NOTREACHED;
    }
  return AV_IO_READY;
}

/* Handle input from SMTP client. Return ready/block/eof */
static AvIoState ssh_avalg_hnd_client_input(AvAlgIo io)
{
  AvAlgCtx ctx;
  AvAlgConn conn = io->conn;
  const char *line_end;
  int line_len = 0;

  SSH_DEBUG(AVALG_D_STATE,
    ("C state: %s",ssh_avalg_state_string(conn->av_state)));

  if (conn->av_state == AV_ST_ERROR)
    {
      ssh_avalg_delete_data(&io->in_buf, io->in_buf.pos);
      return AV_IO_EOF;
    }

  /* Wait for output buffer to empty before continuing */
  if (io->out_buf.pos)
    return AV_IO_BLOCK;

  line_end = ssh_avalg_has_line(io->in_buf.data, io->in_buf.pos);
  if (line_end)
    line_len = line_end - (char *)io->in_buf.data + 1;
  else if (ALG_BUFF_ROOM(&io->in_buf) == 0)
    {
      /* Input buffer is full but there is no line end. Line is too long. */
      ssh_avalg_delete_data(&io->in_buf, io->in_buf.pos);
      return ssh_avalg_to_error_state(conn, AV_ERROR_LONG_LINE);
    }

  switch(conn->av_state)
    {
      case AV_ST_START:
        if (line_len == 0)
          break;
        /* Pass QUIT command to server. All other commands are blocked. */
        if (ssh_avalg_has_cmd(io->in_buf.data, line_len, SMTP_CMD_QUIT) !=
            SMTP_CMD_NONE)
          ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
        else
          ssh_avalg_delete_data(&io->in_buf, line_len);
        return AV_IO_READY;
      case AV_ST_ENVELOPE:
        return ssh_avalg_hnd_client_envelope(io);
      case AV_ST_TURN:
        /* There should be no input from client after TURN command until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);
        break;
      case AV_ST_WAIT_REPLY:
        /* There should be no input from client after DATA command until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);
        break;
      case AV_ST_RECEIVE_CONTENT:
        if (line_len == 0)
          break;
        if (line_len == 3 && io->in_buf.data[0] == '.')
          {
            /* End marker is not written into the file because when
               sending out, we want to be sure that timing of end marker
               is controlled. */
            ssh_avalg_delete_data(&io->in_buf, line_len);
            return ssh_avalg_new_state(conn, AV_ST_CONTENT_END);
          }
        else
          {
            SshStreamStatsStruct stream_stats;
            /* Check that content size does not exceed limit */
            ssh_stream_get_stats(conn->content.stream, &stream_stats);
            if (stream_stats.written_bytes >= conn->config->max_content_size)
              return ssh_avalg_to_error_state(conn, AV_ERROR_STORAGE);

            /* Parse content to detect mime partial messages */
            if (!ssh_avalg_parse_mime(&conn->mime_parser, io->in_buf.data,
                  line_len))
              return ssh_avalg_to_error_state(conn, AV_ERROR_CONTENT);

            ssh_avalg_move(&conn->content.buff, &io->in_buf, line_len);
            return AV_IO_READY;
          }
        break;
      case AV_ST_CONTENT_END:
        /* There should be no input from client after content ends until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);

          /* Wait for buffer to empty before closing stream */
          if (ALG_BUFF_BYTES(&conn->content.buff) == 0)
            {
              /* Get number of bytes written (content size) */
              SshStreamStatsStruct stream_stats;
              ssh_stream_get_stats(conn->content.stream, &stream_stats);
              conn->content.size = stream_stats.written_bytes;
              /* Close file */
              ssh_avalg_close_content(conn);

              /* Reinsert connection into end of connection list. This way
                 connections in wait engine state are in wait order in the
                 list. */
              ctx = (AvAlgCtx)conn->ctx->user_context;
              SSH_LIST_REMOVE(&conn->link);
              SSH_LIST_ADD(&ctx->conn_list, &conn->link);
              /* Wait to get hold of av-engine to do a scan */
              return ssh_avalg_new_state(conn, AV_ST_WAIT_ENGINE);
            }
        break;
      case AV_ST_WAIT_ENGINE:
        /* There should be no input from client after content ends until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);

          ctx = (AvAlgCtx)conn->ctx->user_context;

          /* If engine has died, proceed to av check state */
          if (!ctx->av_eng.registered)
            {
              ssh_avalg_free_scan_result(conn);
              conn->scan_result.ready = TRUE;
              conn->scan_result.result = AV_CHECK_RESULT_ERROR;
              return ssh_avalg_new_state(conn, AV_ST_CHECK);
            }

          /* If mail content type is mime partial and action is not pass,
             proceed to av check state */
          if (conn->mime_parser.content_type == MIME_CONTENT_TYPE_PARTIAL &&
              (ssh_avalg_string_to_action(conn->config->partial_action, NULL)
              != AV_ACTION_PASS))
            {
              ssh_avalg_free_scan_result(conn);
              conn->scan_result.ready = TRUE;
              conn->scan_result.result = AV_CHECK_RESULT_PARTIAL;
              return ssh_avalg_new_state(conn, AV_ST_CHECK);
            }

          /* If no other connection is using av-engine. Reserve it and
             perform scan. */
          if (ctx->av_eng.command == AV_COMMAND_NONE)
            {
              ssh_avalg_free_scan_result(conn);
              if (ssh_avalg_command_eng(&ctx->av_eng, AV_COMMAND_SCAN,
                  conn->content.name))
                {
                  ctx->av_eng.user_tag = conn->tag;
                  ssh_avalg_new_state(conn, AV_ST_CHECK);
                }
              else
                {
                  ssh_appgw_conn_close_engine(&ctx->av_eng);
                  ssh_avalg_to_error_state(conn, AV_ERROR_ENGINE);
                }
              return AV_IO_READY;
            }
        break;
      case AV_ST_CHECK:
        /* There should be no input from client after content ends until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);

        return ssh_avalg_av_check_complete(conn);
      case AV_ST_SEND_CONTENT:
        return ssh_avalg_hnd_client_send_content(io);
        /* There should be no input from client after content ends until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);

        /* If there has been eof, stream has been closed */
        if (conn->content.stream == NULL && conn->content.buff.pos == 0)
          {
            /* Free extra content buffer */
            ssh_avalg_free_inject(&conn->inject);

            /* Send content end mark to server */
            if (ssh_avalg_copy_data(&io->out_buf, ".\r\n", 3))
              {
                /* If we let server reply, go to envelope state */
                if (conn->content_end_reply == AV_REPLY_NONE)
                  {
                    conn->cmds_out++;
                    conn->start_time = ssh_time();
                    return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
                  }
                else
                  {
                    /* ALG will reply and block server reply */
                    return ssh_avalg_new_state(conn, AV_ST_SEND_END);
                  }
              }
            break;
          }
        else
          {
            if (conn->content.buff.pos &&
                ssh_avalg_move(&io->out_buf, &conn->content.buff,
                  conn->content.buff.pos))
              return AV_IO_READY;
          }
        break;
      case AV_ST_SEND_END:
        /* There should be no input from client after content ends until reply.
           If input buffer fills, go to error state. */
        if (ALG_BUFF_ROOM(&io->in_buf) == 0)
          return ssh_avalg_to_error_state(conn, AV_ERROR_INPUT_FULL);
        break;
      case AV_ST_ERROR:
      case AV_ST_LAST:
        SSH_NOTREACHED;
    }
  return AV_IO_BLOCK;
}

/* Handle input from SMTP server. Return ready/block/eof */
static AvIoState ssh_avalg_hnd_server_input(AvAlgIo io)
{
  AvAlgConn conn = io->conn;
  int line_len = 0;
  const int MAX_TOKEN_PTRS = 128;
  char *(token_ptrs[MAX_TOKEN_PTRS]);
  int num_tokens;
  const char *line_end;
  int reply_code = -1;

  SSH_DEBUG(AVALG_D_STATE,
    ("S state: %s",ssh_avalg_state_string(conn->av_state)));

  if (conn->av_state == AV_ST_ERROR)
    return ssh_avalg_hnd_error(io);

  /* Wait for output buffer to empty before continuing */
  if (io->out_buf.pos)
    return AV_IO_BLOCK;

  line_end = ssh_avalg_has_line(io->in_buf.data, io->in_buf.pos);
  if (line_end)
    {
      line_len = line_end - (char *)io->in_buf.data + 1;

#ifdef DEBUG_LIGHT
      ssh_avalg_print_input_line(io, line_len);
#endif

      num_tokens =
        ssh_avalg_tokenize(io->in_buf.data, line_len, token_ptrs,
          MAX_TOKEN_PTRS) / 2;

      if (num_tokens)
        reply_code = ssh_avalg_get_reply_code(token_ptrs, num_tokens * 2);
    }
  else if (ALG_BUFF_ROOM(&io->in_buf) == 0)
    {
      /* Input buffer is full but there is no line end. Line is too long. */
      ssh_avalg_delete_data(&io->in_buf, io->in_buf.pos);
      return ssh_avalg_to_error_state(conn, AV_ERROR_LONG_LINE);
    }

  switch(conn->av_state)
    {
    case AV_ST_START:
      if (line_len == 0)
        break;
      /* Wait for 220 greeting reply from server */
      if (reply_code == 220)
        {
          ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
          return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
        }
      else
        {
          if (reply_code == SMTP_REPLY_FILTER)
            ssh_avalg_delete_data(&io->in_buf, line_len);
          else
            ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
          return AV_IO_READY;
        }
      break;
    case AV_ST_ENVELOPE:
      if (line_len == 0)
        break;
      /* Move data drom SMTP server to client. If we have last line of a
         reply, decrease commands outstanding count. */
      if (reply_code == SMTP_REPLY_FILTER)
        ssh_avalg_delete_data(&io->in_buf, line_len);
      else
        ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      if (reply_code > 0)
        conn->cmds_out--;
      if (reply_code == 354)
        {
          /* Start mail input from server. We are out of sync.
             Close down. */
          return ssh_avalg_to_error_state(conn, AV_ERROR_OUT_OF_SYNC);
        }
      return AV_IO_READY;
    case AV_ST_TURN:
      if (line_len)
        {
          /* If have lines coming in from server but no commands outstanding,
             go to error state */
          if (conn->cmds_out == 0)
            return ssh_avalg_to_error_state(conn, AV_ERROR_OUT_OF_SYNC);

          /* Pass line from server to client */
          if (reply_code == SMTP_REPLY_FILTER)
            ssh_avalg_delete_data(&io->in_buf, line_len);
          else
            ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
          if (reply_code > 0)
            conn->cmds_out--;
          return AV_IO_READY;
        }
      /* If there are no commands outstanding, reply negative to TURN
         command */
      if (conn->cmds_out == 0)
        {
          /* Copy response into buffer */
          ssh_avalg_wr_reply(&io->out_buf, AV_REPLY_502_TURN);
          return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
        }
      break;
    case AV_ST_WAIT_REPLY:
      if (line_len == 0)
        break;
      ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      if (reply_code > 0)
        conn->cmds_out--;
      if (conn->cmds_out == 0)
        {
          if (reply_code == 354)
            {
              /* Server responded with 354 Enter mail ... */
              if (!ssh_avalg_open_content(conn, FALSE))
                {
                  /* Cannot open file to write into. Block server response. */
                  ssh_avalg_delete_data(&io->out_buf, line_len);
                  return ssh_avalg_to_error_state(conn, AV_ERROR_IO_WRITE);
                }
              ssh_avalg_init_mime_parser(&conn->mime_parser);
              ssh_avalg_new_state(conn, AV_ST_RECEIVE_CONTENT);
            }
          else
            ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
          ssh_fsm_continue(&conn->thread_i);
        }
      return AV_IO_READY;
    case AV_ST_RECEIVE_CONTENT:
    case AV_ST_CONTENT_END:
    case AV_ST_WAIT_ENGINE:
    case AV_ST_CHECK:
    case AV_ST_SEND_CONTENT:
      /* Pass lines from server to client */
      if (line_len == 0)
        break;
      ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
      return AV_IO_READY;
    case AV_ST_SEND_END:
      if (line_len == 0)
        break;
      /* If server replies with anything else than 5xx reply, block it and
         send one reply from here */
      if (reply_code >= SMTP_REPLY_PERMANENT_NEGATIVE)
        {
          ssh_avalg_move(&io->out_buf, &io->in_buf, line_len);
          conn->cmds_out++;
          conn->start_time = ssh_time();
          return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
        }
      else
        {
          ssh_avalg_wr_reply(&io->out_buf, conn->content_end_reply);
          ssh_avalg_delete_data(&io->in_buf, line_len);
          conn->cmds_out++;
          conn->start_time = ssh_time();
          return ssh_avalg_new_state(conn, AV_ST_ENVELOPE);
        }
      break;
    case AV_ST_ERROR:
    case AV_ST_LAST:
      SSH_NOTREACHED;
    }
  return AV_IO_BLOCK;
}

/* Write data to output stream. Return ready/would block/eof. */
static AvIoState ssh_avalg_wr_out(AvAlgIo io)
{
  AvIoState wr_state = ssh_avalg_wr_stream(io->dst, &io->out_buf);

  if (wr_state == AV_IO_EOF)
    io->dst_eof = 1;

  return wr_state;
}

/* Read data from input stream. Return ready/would block/eof. */
static AvIoState ssh_avalg_rd_in(AvAlgIo io)
{
  AvIoState rd_state = ssh_avalg_rd_stream(io->src, &io->in_buf);

  if (rd_state == AV_IO_BLOCK)
    {
      /* We would block.  Check if we should terminate */
      if (io->terminate)
        {
          /** Connection closed */
          SSH_DEBUG(SSH_D_LOWOK,("shutting down connection"));
          return AV_IO_EOF;
        }
    }

  if (rd_state == AV_IO_EOF)
    {
      SSH_DEBUG(SSH_D_LOWOK,("shutting down connection"));
    }

  return rd_state;
}

/***************************** State functions ******************************/

/* Thread to process SMTP in client to server direction */
SSH_FSM_STEP(ssh_avalg_st_client)
{
  AvAlgCtx tcp_ctx = (AvAlgCtx) fsm_context;
  AvAlgIo io = (AvAlgIo) thread_context;
  AvAlgConn conn = io->conn;
  AvAlgMailContent content = &conn->content;
  AvIoState out_state;
  AvIoState in_state;
  AvIoState wr_state;
  AvIoState rd_state;
  AvIoState proc_state;

  /* Check if the system is shutting down */
  if (tcp_ctx->shutdown)
      ssh_avalg_to_error_state(conn, AV_ERROR_SHUTDOWN);

  /* Try to write data to smtp server */
  out_state = ssh_avalg_wr_out(io);
  if (out_state == AV_IO_EOF) /* Out stream closed */
    ssh_avalg_to_error_state(conn, AV_ERROR_CONN_CLOSE);

  /* Try to read data from smtp client */
  in_state = ssh_avalg_rd_in(io);
  if (in_state == AV_IO_EOF)  /* In stream closed */
    ssh_avalg_to_error_state(conn, AV_ERROR_CONN_CLOSE);

  /* Try to write to content stream (file) */
  wr_state = ssh_avalg_wr_stream(content->is_input ? NULL : content->stream,
    &content->buff);
  if (wr_state == AV_IO_EOF)  /* Error in file i/o */
    ssh_avalg_to_error_state(conn, AV_ERROR_IO_WRITE);

  /* Try to read from content stream */
  rd_state = ssh_avalg_rd_stream(content->is_input ? content->stream : NULL,
    &content->buff);
  if (rd_state == AV_IO_EOF)  /* end of file or error */
    {
      /* Check that all bytes were read and close stream */
      SshStreamStatsStruct stream_stats;
      ssh_stream_get_stats(conn->content.stream, &stream_stats);
      ssh_avalg_close_content(io->conn);
      if (stream_stats.read_bytes != conn->content.size)
        ssh_avalg_to_error_state(conn, AV_ERROR_IO_READ);
    }

  /* Process input data */
  proc_state = ssh_avalg_hnd_client_input(io);
  if (proc_state == AV_IO_EOF)
    {
      /* Request to terminate */
      SSH_FSM_SET_NEXT(ssh_avalg_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  if (proc_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (out_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (in_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (wr_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (rd_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;

  /* Wait for input or output */
  return SSH_FSM_SUSPENDED;
}

/* Thread to process SMTP in server to client direction */
SSH_FSM_STEP(ssh_avalg_st_server)
{
  AvAlgCtx tcp_ctx = (AvAlgCtx) fsm_context;
  AvAlgIo io = (AvAlgIo) thread_context;
  AvAlgConn conn = io->conn;
  AvIoState out_state;
  AvIoState in_state;
  AvIoState proc_state;

  /* Check if the system is shutting down */
  if (tcp_ctx->shutdown)
      ssh_avalg_to_error_state(conn, AV_ERROR_SHUTDOWN);

  /* Try to write data to smtp client */
  out_state = ssh_avalg_wr_out(io);
  if (out_state == AV_IO_EOF) /* Out stream closed */
    ssh_avalg_to_error_state(conn, AV_ERROR_CONN_CLOSE);

  /* Try to read data from smtp server */
  in_state = ssh_avalg_rd_in(io);
  if (in_state == AV_IO_EOF)  /* In stream closed */
    ssh_avalg_to_error_state(conn, AV_ERROR_CONN_CLOSE);

  /* Process input data */
  proc_state = ssh_avalg_hnd_server_input(io);
  if (proc_state == AV_IO_EOF)
    {
      /* Request to terminate */
      SSH_FSM_SET_NEXT(ssh_avalg_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  if (proc_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (out_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;
  if (in_state != AV_IO_BLOCK)
    return SSH_FSM_YIELD;

  /* Wait for input or output */
  return SSH_FSM_SUSPENDED;
}

/* Client or server thread in waiting to terminate */
SSH_FSM_STEP(ssh_avalg_st_terminate)
{
  AvAlgIo io = (AvAlgIo) thread_context;
  AvAlgConn conn = io->conn;

  SSH_DEBUG(SSH_D_LOWOK,("%d, entering terminate state", conn->tag));

  /* This thread is finished */
  io->active = 0;

  /* Check if we were the last thread in the connection */
  if (!conn->io_i.active && !conn->io_r.active)
    {
      /* Indicate no more data to be written */
      ssh_stream_output_eof(conn->io_i.dst);
      ssh_stream_output_eof(conn->io_r.dst);
      /* Register a timeout to destroy the connection object */
      ssh_xregister_timeout(0, 0, ssh_avalg_connection_terminate, conn);
    }

  /* Terminate this thread */
  return SSH_FSM_FINISH;
}


/************************ Initializing with firewall ************************/

/* Find configure structure from list by service ID */
static SshAppgwAvConfig find_config(SshListItem list, SshUInt32 service_id)
{
  return (SshAppgwAvConfig)ssh_avalg_find_list_item(list,
    offsetof(struct SshAppgwAvConfigRec, service_id),
    service_id);
}

/* Destroy av-alg */
static void ssh_avalg_destroy_cb(void *context)
{
  AvAlgCtx ctx = (AvAlgCtx) context;

  ssh_cancel_timeout(&ctx->timeout);

  /* Destroy av-engine connection */
  ssh_appgw_conn_destroy_engine(&ctx->av_eng);

  ssh_fsm_uninit(&ctx->fsm);

  if (ctx->registered)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);
      ssh_appgw_unregister_local(ctx->pm, SSH_APPGW_AV_IDENT, AVALG_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  /* Free all config data objects */
  while (!SSH_LIST_IS_EMPTY(&ctx->config_list))
    {
      SshAppgwAvConfig c =
        (SshAppgwAvConfig)ctx->config_list.next;

      SSH_LIST_REMOVE(&c->link);
      ssh_appgw_av_config_destroy(c);
    }

  ssh_free(ctx);
}

/* Destroy av-alg */
static void ssh_avalg_destroy(AvAlgCtx ctx)
{
  /* Register a zero-timeout to destroy the application gateway
     instance.  This is needed since this function is called also from
     thread destructors and the FSM library needs to access the FSM
     context that will be destroyed when the context is freed. */
  ssh_xregister_timeout(0, 0, ssh_avalg_destroy_cb, ctx);
}

/* Check if av-alg can be destroyed */
static void ssh_avalg_check_shutdown(AvAlgCtx ctx)
{
  if (ctx->shutdown && SSH_LIST_IS_EMPTY(&ctx->conn_list))
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway */
    ssh_avalg_destroy(ctx);
}

/* Create new connection instance */
static void ssh_appgw_av_new_instance(SshAppgwContext ctx, AvAlgCtx tcp_ctx)
{
  AvAlgConn conn;
  SshAppgwAvConfig config;

  SSH_DEBUG(SSH_D_NICETOKNOW,
    ("New AV connection %@.%d > %@.%d",
    ssh_ipaddr_render, &ctx->initiator_ip,
    ctx->initiator_port,
    ssh_ipaddr_render, &ctx->responder_ip,
    ctx->responder_port));
  SSH_DEBUG(SSH_D_NICETOKNOW,
    ("Responder sees initiator as `%@.%d'",
    ssh_ipaddr_render, &ctx->initiator_ip_after_nat,
    ctx->initiator_port));
  SSH_DEBUG(SSH_D_NICETOKNOW,
    ("Initiator sees responder as `%@.%d'",
    ssh_ipaddr_render, &ctx->responder_ip_after_nat,
    ctx->responder_port));

  /* Lookup its configuration data */
  config = find_config(&tcp_ctx->config_list, ctx->service_id);
  if (config == NULL)
    {
      ssh_appgw_audit_event(ctx, SSH_AUDIT_WARNING, SSH_AUDIT_TXT,
                            "No configuration data specified for "
                            "this service.",
                            SSH_AUDIT_ARGUMENT_END);
      ssh_appgw_done(ctx);
      return;
    }

  /* Create a new connection */
  conn = ssh_calloc(1, sizeof(*conn));
  if (conn == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate av-alg connection"));
      ssh_appgw_done(ctx);
      return;
    }

  tcp_ctx->conn_count++;  /* count of connections created */
  tcp_ctx->conn_act++;    /* count of active connections */

  /* Generate file name to save mail content */
  if (ssh_snprintf(conn->content.name, sizeof(conn->content.name),
        "%s/qsav%x.dat", config->working_dir, tcp_ctx->conn_count) == -1)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not generate content file name"));
      ssh_free(conn);
      ssh_appgw_done(ctx);
      return;
    }

  /* Store configuration data */
  conn->config = config;

  conn->start_time = ssh_time();

  /* Link connection to the gateway's list of active connections */
  SSH_LIST_ADD(&tcp_ctx->conn_list, &conn->link);

  /* Store application level gateway framework's context */
  conn->ctx = ctx;

  /* Store application gateway context into SshAppgwContext's `user_context' */
  ctx->user_context = tcp_ctx;

  conn->tag = tcp_ctx->conn_count; /* tag to ID this connection */
  SSH_DEBUG(SSH_D_NICETOKNOW,("Connection tag %d", conn->tag));

  /* Save IP addresses for logging */
  conn->initiator_ip = ctx->initiator_ip;
  conn->responder_ip = ctx->responder_ip;

  /* Set stream callbacks */
  ssh_stream_set_callback(conn->ctx->initiator_stream,
                          ssh_avalg_stream_cb, conn);
  ssh_stream_set_callback(conn->ctx->responder_stream,
                          ssh_avalg_stream_cb, conn);

  /* Check if temporary 421 response should be given to client. We are
     exceeding allowed number of active connections. */
  if (tcp_ctx->conn_act > config->max_connections)
    ssh_avalg_to_error_state(conn, AV_ERROR_TOO_MANY_CONN);

  /* Check if temporary 421 response should be given to client. No connection
     to AVESERVER */
  if (!tcp_ctx->av_eng.registered &&
       ssh_avalg_string_to_action(config->error_action,
        NULL) != AV_ACTION_PASS)
      ssh_avalg_to_error_state(conn, AV_ERROR_ENGINE_NA);

  /* Setup I/O threads */

  conn->io_i.active = 1;
  conn->io_i.initiator = 1;
  conn->io_i.src = conn->ctx->initiator_stream;
  conn->io_i.dst = conn->ctx->responder_stream;
  conn->io_i.conn = conn;

  ssh_fsm_thread_init(&tcp_ctx->fsm, &conn->thread_i,
                      ssh_avalg_st_client,
                      NULL_FNPTR, NULL_FNPTR,
                      &conn->io_i);

  conn->io_r.active = 1;
  conn->io_r.src = conn->ctx->responder_stream;
  conn->io_r.dst = conn->ctx->initiator_stream;
  conn->io_r.conn = conn;

  ssh_fsm_thread_init(&tcp_ctx->fsm, &conn->thread_r,
                      ssh_avalg_st_server,
                      NULL_FNPTR, NULL_FNPTR,
                      &conn->io_r);
}

/* Connection callback */
static void
ssh_appgw_av_conn_cb(SshAppgwContext ctx, SshAppgwAction action,
                     const unsigned char *udp_data,
                     size_t udp_len,
                     void *context)
{
  AvAlgCtx tcp_ctx = (AvAlgCtx) context;
  AvAlgConn conn;
  SshListItem list_item;
  SshAppgwAvConfig config;
  SshAppgwAvConfig c;

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      /* Lookup configuration data */
      config = find_config(&tcp_ctx->config_list, ctx->service_id);
      if (config)
        {
          SshIpAddrStruct ip = ctx->responder_ip;
          SshUInt16 port = ctx->responder_port;

          if (SSH_IP_DEFINED(&config->redirect_ip))
            ip = config->redirect_ip;
          if (config->redirect_port)
            port = config->redirect_port;

          ssh_appgw_redirect(ctx, &ip, port);
        }
      else
        {
          /* No redirection */
          ssh_appgw_redirect(ctx, &ctx->responder_ip, ctx->responder_port);
        }
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("New configuration data for service %u:",
                         ctx->service_id),
                         ctx->config_data, ctx->config_data_len);

      /* Unmarshal configuration data */
      config = ssh_appgw_av_config_unmarshal(ctx->config_data,
        ctx->config_data_len);
      if (config == NULL)
        {
          ssh_appgw_audit_event(ctx, SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Could not decode configuration data",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "%s: Could not decode configuration data "
                        "for service %u",
                        SSH_APPGW_NAME, ctx->service_id);
          return;
        }

      /* Store service ID */
      config->service_id = ctx->service_id;

      /* Do we already know this service ID? */
      c = find_config(&tcp_ctx->config_list, ctx->service_id);
      if (c)
        {
          SSH_LIST_REMOVE(&c->link);
          ssh_appgw_av_config_destroy(c);
          /* Connections that hold pointer to old config are set
             to new one */
          for (list_item = tcp_ctx->conn_list.next;
            list_item != &tcp_ctx->conn_list; list_item = list_item->next)
            {
              conn = (AvAlgConn)list_item;
              if (conn->config == c)
                conn->config = config;
            }
        }

      /* Configuration data for a service object */
      SSH_LIST_ADD(&tcp_ctx->config_list, &config->link);
      break;

    case SSH_APPGW_SHUTDOWN:
      tcp_ctx->shutdown = 1;

      if (!SSH_LIST_IS_EMPTY(&tcp_ctx->conn_list))
        {
          /* We have active connections so let's notify them about the
              shutdown.  They will terminate after they receive the
              notification */
          for (list_item = tcp_ctx->conn_list.next;
            list_item != &tcp_ctx->conn_list; list_item = list_item->next)
            {
              conn = (AvAlgConn)list_item;
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      else
        {
          /* Shutdown immediately */
          ssh_avalg_destroy(tcp_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      ssh_appgw_av_new_instance(ctx, tcp_ctx);
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

/* Terminate connection and free resources */
static void ssh_avalg_connection_terminate(void *context)
{
  AvAlgConn conn = (AvAlgConn) context;
  AvAlgCtx tcp_ctx;

  /* Get application gateway context */
  tcp_ctx = (AvAlgCtx) conn->ctx->user_context;
  conn->ctx->user_context = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("AV connection %d, %@.%d > %@.%d terminated",
             conn->tag,
             ssh_ipaddr_render, &conn->ctx->initiator_ip,
             conn->ctx->initiator_port,
             ssh_ipaddr_render, &conn->ctx->responder_ip,
             conn->ctx->responder_port));

  ssh_stream_set_callback(conn->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(conn->ctx->responder_stream, NULL_FNPTR, NULL);

  /* Free extra content */
  ssh_avalg_free_inject(&conn->inject);

  /* Close and delete content file */
  ssh_avalg_close_content(conn);
  unlink(conn->content.name);

  /* Free scan result strings */
  ssh_avalg_free_scan_result(conn);

  ssh_appgw_done(conn->ctx);

  /* Remove us from the application gateway's list of connections */
  SSH_LIST_REMOVE(&conn->link);

  tcp_ctx->conn_act--;

  /* Free our connection structure */
  ssh_free(conn);

  /* And check if the system is shutting down */
  ssh_avalg_check_shutdown(tcp_ctx);
}

/* av-alg register callback */
static void ssh_appgw_av_reg_cb(SshAppgwError error, void *context)
{
  AvAlgCtx ctx = (AvAlgCtx) context;

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
                    "registration failed: %s",
                    SSH_APPGW_NAME, why);
      ssh_avalg_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  ctx->registered = 1;
}

/* Initialize av-alg */
void ssh_appgw_av_init(SshPm pm)
{
  AvAlgCtx ctx;
  SshAppgwParamsStruct params;

  appgw_av_ctx = ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not create application gateway: out of memory.",
                    SSH_APPGW_NAME);
      return;
    }
  ctx->pm = pm;
  SSH_LIST_INIT(&ctx->conn_list);
  SSH_LIST_INIT(&ctx->config_list);
  ssh_fsm_init(&ctx->fsm, ctx);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_AV_IDENT;
  params.printable_name =  "Anti-Virus SMTP";
  params.version = AVALG_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;


  /* First timeout after 1 second to connect to av-engine */
  ssh_register_timeout(&ctx->timeout, 1, 0, ssh_avalg_timeout_cb, ctx);

  ssh_appgw_register_local(ctx->pm,
                           &params,
                           SSH_APPGW_F_REDIRECT,
                           ssh_appgw_av_conn_cb, ctx,
                           ssh_appgw_av_reg_cb, ctx);
}


/*********************** Handling configuration data ************************/

/* Create an empty configuration */
SshAppgwAvConfig ssh_appgw_av_config_create(void)
{
  SshAppgwAvConfig config;

  config = ssh_calloc(1, sizeof(*config));

  SSH_IP_UNDEFINE(&config->redirect_ip);

  return config;
}

/* Destroy configuration */
void ssh_appgw_av_config_destroy(SshAppgwAvConfig config)
{
  if (config == NULL)
    return;

  if (config->strings_buff)
    ssh_free(config->strings_buff);

  ssh_free(config);
}

/* Move parameters from integer table to structure */
static void
ssh_appgw_av_ints_to_config(SshAppgwAvConfig config, SshUInt32 ints[])
{
  char *buff = config->strings_buff;

  /* Move parameters into config structure */
  config->redirect_port = ints[SSH_APPGW_AV_OFFS_REDIRECT_PORT];
  config->max_connections = ints[SSH_APPGW_AV_OFFS_MAX_CONNECTIONS];
  config->max_content_size = ints[SSH_APPGW_AV_OFFS_MAX_CONTENT_SIZE];
  config->timeout = ints[SSH_APPGW_AV_OFFS_TIMEOUT];
  config->engines = ints[SSH_APPGW_AV_OFFS_ENGINES];

  config->redir_ip = buff + ints[SSH_APPGW_AV_OFFS_REDIRECT_IP];
  config->working_dir = buff + ints[SSH_APPGW_AV_OFFS_WORKING_DIR];
  config->engine_addr = buff + ints[SSH_APPGW_AV_OFFS_ENGINE_ADDR];

  config->ok_action = buff + ints[SSH_APPGW_AV_OFFS_OK_ACTION];
  config->virus_action = buff + ints[SSH_APPGW_AV_OFFS_VIRUS_ACTION];
  config->warning_action = buff + ints[SSH_APPGW_AV_OFFS_WARNING_ACTION];
  config->suspect_action = buff + ints[SSH_APPGW_AV_OFFS_SUSPECT_ACTION];

  config->protected_action = buff + ints[SSH_APPGW_AV_OFFS_PROTECTED_ACTION];
  config->corrupt_action = buff + ints[SSH_APPGW_AV_OFFS_CORRUPT_ACTION];
  config->error_action = buff + ints[SSH_APPGW_AV_OFFS_AV_ERROR_ACTION];
  config->partial_action = buff + ints[SSH_APPGW_AV_OFFS_PARTIAL_ACTION];
}

/* Move parameters from structure to integer table */
static void
ssh_appgw_av_config_to_ints(SshUInt32 ints[SSH_APPGW_AV_NUM_PARAMS],
                            SshAppgwAvConfig config)
{
  char *buff = config->strings_buff;

  memset(ints, 0, sizeof(ints));

  ints[SSH_APPGW_AV_OFFS_REDIRECT_PORT] = config->redirect_port;
  ints[SSH_APPGW_AV_OFFS_MAX_CONNECTIONS] = config->max_connections;
  ints[SSH_APPGW_AV_OFFS_MAX_CONTENT_SIZE] = config->max_content_size;
  ints[SSH_APPGW_AV_OFFS_TIMEOUT] = config->timeout;
  ints[SSH_APPGW_AV_OFFS_ENGINES] = config->engines;

  ints[SSH_APPGW_AV_OFFS_REDIRECT_IP] = config->redir_ip - buff;
  ints[SSH_APPGW_AV_OFFS_WORKING_DIR] = config->working_dir - buff;
  ints[SSH_APPGW_AV_OFFS_ENGINE_ADDR] = config->engine_addr - buff;

  ints[SSH_APPGW_AV_OFFS_OK_ACTION] = config->ok_action - buff;
  ints[SSH_APPGW_AV_OFFS_VIRUS_ACTION] = config->virus_action - buff;
  ints[SSH_APPGW_AV_OFFS_WARNING_ACTION] = config->warning_action - buff;
  ints[SSH_APPGW_AV_OFFS_SUSPECT_ACTION] = config->suspect_action - buff;
  ints[SSH_APPGW_AV_OFFS_PROTECTED_ACTION] = config->protected_action - buff;
  ints[SSH_APPGW_AV_OFFS_CORRUPT_ACTION] = config->corrupt_action - buff;
  ints[SSH_APPGW_AV_OFFS_AV_ERROR_ACTION] = config->error_action - buff;
  ints[SSH_APPGW_AV_OFFS_PARTIAL_ACTION] = config->partial_action - buff;
}

/* Configure parameters. Return index to invalid parameter on error. */
int ssh_appgw_av_config(SshAppgwAvConfig config,
                        const unsigned char *(param_tbl[]))
{
  /* Default values for parameters */
  const struct{
    int param;
    char *value;
  } defaults[]={
    {SSH_APPGW_AV_OFFS_MAX_CONNECTIONS, "100"},
    {SSH_APPGW_AV_OFFS_MAX_CONTENT_SIZE, "10485760"},
    {SSH_APPGW_AV_OFFS_TIMEOUT, "600"},
    {SSH_APPGW_AV_OFFS_ENGINES, "1"},
    {SSH_APPGW_AV_OFFS_ENGINE_ADDR,"/var/run/aveserver"},
    {SSH_APPGW_AV_OFFS_WORKING_DIR,"/tmp"},
    {SSH_APPGW_AV_OFFS_VIRUS_ACTION,
     "[replace]This message contained a virus. The message was deleted.\n"},
    {SSH_APPGW_AV_OFFS_AV_ERROR_ACTION, "[drop]"}
  };
  int i, j;
  int str_len;
  char *buff;
  SshUInt32 ints[SSH_APPGW_AV_NUM_PARAMS];

  memset(ints, 0, sizeof(ints));

  /* Set default values to parameters */
  for(i = 0; i < SSH_APPGW_AV_NUM_PARAMS; i++)
    for(j = 0; j < sizeof(defaults)/sizeof(defaults[0]); j++)
      if (param_tbl[i] == NULL && defaults[j].param == i)
        param_tbl[i] = defaults[j].value;

  /* Set integer parameters into configuration */
  for(i = 0; i < SSH_APPGW_AV_NUM_INT_PARAMS; i++)
    {
      if (param_tbl[i])
        {
          ints[i] = atoi(param_tbl[i]);
          if (ints[i] == 0)
            return i;
        }
    }

  /* Check that string parameters lines are not too long and action is valid.
     Calculate number of new lines in strings. If string does not end with \n,
     it may be added. */
  str_len = 0;
  for(i = SSH_APPGW_AV_OFFS_OK_ACTION; i < SSH_APPGW_AV_NUM_PARAMS; i++)
    if (param_tbl[i])
      {
        int max_line;
        const char *plast;
        str_len += ssh_avalg_count_nl(param_tbl[i], &plast, &max_line);
        if (max_line >= AVALG_MAX_LINE)
          return i;
        /* If string does not end into new line, cr,nl may be added */
        if (!plast)
          str_len += 2;
        /* Verify that action is valid */
        if (ssh_avalg_string_to_action(param_tbl[i], NULL) != AV_ACTION_PASS)
          continue;
        if (strncmp(param_tbl[i], "[pass]", 6) != 0)
          return i;
      }

  /* Calculate total length of strings */
  for(i = SSH_APPGW_AV_NUM_INT_PARAMS; i < SSH_APPGW_AV_NUM_PARAMS; i++)
    if (param_tbl[i])
        str_len += strlen(param_tbl[i]) + 1;

  str_len++;  /* start from offset 1, 0 offset will mark NULL string */

  /* Allocate buffer for strings */
  config->strings_buff=ssh_calloc(1, str_len);
  if (!config->strings_buff)
    return FALSE;

  config->strings_size = str_len;

  /* Copy strings into allocated buffer */
  buff = config->strings_buff;
  buff++; /* offset 0 will mark NULL string */
  for(i = SSH_APPGW_AV_NUM_INT_PARAMS; i < SSH_APPGW_AV_NUM_PARAMS; i++)
    {
      const char *src = param_tbl[i];
      if (src == NULL)
        continue;
      ints[i] = buff - config->strings_buff;
      buff = ssh_avalg_copy_string(buff, src);
      /* Add new line to action strings if is missing */
      if (i >= SSH_APPGW_AV_OFFS_OK_ACTION)
        if (*(buff - 2) != '\n' && *(buff - 2) != ']')
          {
            memcpy(buff - 1, "\r\n", 3);
            buff += 2;
          }
    }

  /* Move parameters into config structure */
  ssh_appgw_av_ints_to_config(config, ints);

  /* Copy av-engine address into gateway context */
  if (config->engine_addr)
    {
      str_len = strlen(config->engine_addr) + 1;
      if (str_len <= sizeof(appgw_av_ctx->av_eng.address))
        memcpy(appgw_av_ctx->av_eng.address, config->engine_addr, str_len);
    }

  /* Parse redirect IP address */
  if (*(config->redir_ip))
    {
      if (!ssh_ipaddr_parse(&config->redirect_ip, config->redir_ip))
        return SSH_APPGW_AV_OFFS_REDIRECT_IP;
    }

  return SSH_APPGW_AV_NUM_PARAMS;
}

/* Encode configuration into binary format */
unsigned char *
ssh_appgw_av_config_marshal(SshAppgwAvConfig config, size_t *data_len_return)
{
  unsigned char *data;
  SshUInt32 ints[SSH_APPGW_AV_NUM_PARAMS];

  ssh_appgw_av_config_to_ints(ints, config);

  /* Encode config data */
  *data_len_return =
    ssh_encode_array_alloc(
      &data,
      SSH_FORMAT_DATA, ints, sizeof(ints),
      SSH_FORMAT_UINT32_STR, config->strings_buff, config->strings_size,
      SSH_FORMAT_END);

  if (*data_len_return == 0)
    return NULL;

  return data;
}

/* Decode configuration from binary format */
SshAppgwAvConfig
ssh_appgw_av_config_unmarshal(const unsigned char *data, size_t data_len)
{
  SshAppgwAvConfig config;
  SshUInt32 ints[SSH_APPGW_AV_NUM_PARAMS];

  /* Allocate a config object */
  config = ssh_appgw_av_config_create();
  if (config == NULL)
    goto error;

  if (data_len)
    {
      if (ssh_decode_array(
            data, data_len, SSH_FORMAT_DATA, ints, sizeof(ints),
            SSH_FORMAT_UINT32_STR, &config->strings_buff,
            &config->strings_size, SSH_FORMAT_END) != data_len)
        goto error;

      /* Store configuration data */
      ssh_appgw_av_ints_to_config(config, ints);

      if (*config->redir_ip)
        ssh_ipaddr_parse(&config->redirect_ip, config->redir_ip);
    }

  /* All done */
  return config;


  /* Error handling */

 error:

  ssh_appgw_av_config_destroy(config);

  return NULL;
}

#endif /* !VXWORKS */
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
#endif /* WITH_AV_ALG */
#endif /* SSHDIST_AV */
