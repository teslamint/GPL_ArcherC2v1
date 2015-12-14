/*
 *
 * appgw_ftp.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application gateway for File Transfer Protocol (FTP).
 *
 * References:
 *
 *   RFC  959   FILE TRANSFER PROTOCOL (FTP)
 *   RFC 2428   FTP Extensions for IPv6 and NATs
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshfsm.h"
#include "appgw_api.h"
#include "appgw_ftp.h"
#include "sshencode.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwFtp"

/* The name of the application gateway as shown in syslog events. */
#define SSH_APPGW_NAME                  "FTPALG"

/* Version. */
#define SSH_APPGW_FTP_VERSION           1

/* The maximum line length in the control channel. */
#define SSH_APPGW_FTP_MAX_LINE_LEN      512

/* The number of bytes reserved for application gateway generated
   replies. */
#define SSH_APPGW_FTP_BUF_RESERVE       64

/* IO buffer size for the control channel. */
#define SSH_APPGW_FTP_IO_BUF_LEN        \
(SSH_APPGW_FTP_MAX_LINE_LEN + SSH_APPGW_FTP_BUF_RESERVE)

/* Check whether the character `ch' is a decimal digit. */
#define SSH_IS_DIGIT(ch) ('0' <= (ch) && (ch) <= '9')

/* The known FTP commands. */
typedef enum
{
  SSH_APPGW_FTP_CMD_ABOR,
  SSH_APPGW_FTP_CMD_ACCT,
  SSH_APPGW_FTP_CMD_ALLO,
  SSH_APPGW_FTP_CMD_APPE,
  SSH_APPGW_FTP_CMD_CDUP,
  SSH_APPGW_FTP_CMD_CWD,
  SSH_APPGW_FTP_CMD_DELE,
  SSH_APPGW_FTP_CMD_EPSV,
  SSH_APPGW_FTP_CMD_EPRT,
  SSH_APPGW_FTP_CMD_FEAT,
  SSH_APPGW_FTP_CMD_HELP,
  SSH_APPGW_FTP_CMD_LIST,
  SSH_APPGW_FTP_CMD_LPSV,
  SSH_APPGW_FTP_CMD_LPRT,
  SSH_APPGW_FTP_CMD_MLSD,
  SSH_APPGW_FTP_CMD_MLST,
  SSH_APPGW_FTP_CMD_MKD,
  SSH_APPGW_FTP_CMD_MDTM,
  SSH_APPGW_FTP_CMD_MODE,
  SSH_APPGW_FTP_CMD_NLST,
  SSH_APPGW_FTP_CMD_NOOP,
  SSH_APPGW_FTP_CMD_OPTS,
  SSH_APPGW_FTP_CMD_PASS,
  SSH_APPGW_FTP_CMD_PASV,
  SSH_APPGW_FTP_CMD_PORT,
  SSH_APPGW_FTP_CMD_PWD,
  SSH_APPGW_FTP_CMD_QUIT,
  SSH_APPGW_FTP_CMD_REIN,
  SSH_APPGW_FTP_CMD_REST,
  SSH_APPGW_FTP_CMD_RETR,
  SSH_APPGW_FTP_CMD_RMD,
  SSH_APPGW_FTP_CMD_RNFR,
  SSH_APPGW_FTP_CMD_RNTO,
  SSH_APPGW_FTP_CMD_SITE,
  SSH_APPGW_FTP_CMD_SIZE,
  SSH_APPGW_FTP_CMD_SMNT,
  SSH_APPGW_FTP_CMD_STAT,
  SSH_APPGW_FTP_CMD_STOR,
  SSH_APPGW_FTP_CMD_STOU,
  SSH_APPGW_FTP_CMD_STRU,
  SSH_APPGW_FTP_CMD_SYST,
  SSH_APPGW_FTP_CMD_TYPE,
  SSH_APPGW_FTP_CMD_USER,
  SSH_APPGW_FTP_CMD_CLNT,

  SSH_APPGW_FTP_NUM_COMMANDS
} SshAppgwFtpCommand;

/* Number of 32 bit words in the bitmask disabling FTP commands. */
#define SSH_APPGW_FTP_NUM_DISABLE_WORDS \
((SSH_APPGW_FTP_NUM_COMMANDS + 31) / 32)

/* Disable command `cmd' from the configuration object `config'. */
#define SSH_APPGW_FTP_DISABLE(config, cmd)      \
((config)->disable_mask[(cmd) / 32] |= (1 << ((cmd) % 32)))

/* A predicate to check whether the command `cmd' is disabled in the
   configuration object `config'. */
#define SSH_APPGW_FTP_IS_DISABLED(config, cmd)  \
((config)->disable_mask[(cmd) / 32] & (1 << ((cmd) % 32)))

/* Configuration data object. */
struct SshAppgwFtpConfigRec
{
  struct SshAppgwFtpConfigRec *next;

  /* Service ID of this configuration data. */
  SshUInt32 service_id;

  /* Content filter for data connections. */
  SshAppgwFtpContentFilterType content_filter;

  /* Flags. */
  SshUInt32 flags;

  /* Bitmap of disabled commands. */
  SshUInt32 disable_mask[SSH_APPGW_FTP_NUM_DISABLE_WORDS];
};

/* Buffer for FTP control connection. */
struct SshAppgwFtpBufferRec
{
  unsigned char buf[SSH_APPGW_FTP_IO_BUF_LEN];
  size_t data_in_buf;
};

typedef struct SshAppgwFtpBufferRec SshAppgwFtpBufferStruct;
typedef struct SshAppgwFtpBufferRec *SshAppgwFtpBuffer;

/* An FTP control connection. */
struct SshAppgwFtpConnectionRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwFtpConnectionRec *next;
  struct SshAppgwFtpConnectionRec *prev;

  /* Flags. */
  unsigned int reply_1st_line : 1; /* Reading first reply line. */
  unsigned int reply_special : 1;  /* Special reply code. */
  unsigned int io_bsr_seen : 1;    /* `\r' character seen in input. */
  unsigned int passive : 1;        /* Passive mode. */
  unsigned int port_open : 1;      /* Port open (`open_port_handle' valid).*/
  unsigned int failed : 1;         /* Status of a sub-operation. */

  /* The FSM thread handling the connection. */
  SshFSMThreadStruct thread;

  /* The application gateway context. */
  SshAppgwContext ctx;

  /* Buffers for `client->server' and `server->client' streams. */
  SshAppgwFtpBufferStruct client_to_server;
  SshAppgwFtpBufferStruct server_to_client;

  /* The last command. */
  SshAppgwFtpCommand last_command;

  /* The last reply code from the server. */
  SshUInt32 last_reply_code;

  /* Configuration data for this connection. */
  SshAppgwFtpConfig config;

  /* Content filter of the current/last data connection. */
  SshAppgwFtpContentFilterType content_filter;

  /* Handle for the current open data connection.  This is valid when
     `port_open' is set. */
  SshUInt32 open_port_handle;

  /* I/O sub-state machine. */
  struct
  {
    /* I/O buffer and stream. */
    SshAppgwFtpBuffer buffer;
    SshStream stream;

    /* Offset to the buffer. */
    size_t offset;

    /* Continuation states. */
    SshFSMStepCB success_cb;
    SshFSMStepCB too_long_line_cb;
    SshFSMStepCB failure_cb;
  } io;

  /* Context data for various sub-operations (protocol commands,
     etc.). */
  union
  {
    struct
    {
      SshIpAddrStruct new_dst_ip;
      SshUInt16 new_dst_port;
    } open_port;
  } u;
};

typedef struct SshAppgwFtpConnectionRec SshAppgwFtpConnectionStruct;
typedef struct SshAppgwFtpConnectionRec *SshAppgwFtpConnection;

/* An IO structure for data connection handling. */
struct SshAppgwFtpIORec
{
  /* Flags. */
  unsigned int active : 1;      /* Thread active. */

  /* Source stream. */
  SshStream from;

  /* Destination stream. */
  SshStream to;

  /* Buffer for data being copied. */
  unsigned char buf[1024];
  size_t data_in_buf;
  size_t bufpos;

  /* Number of bytes transmitted. */
  SshUInt64 bytes_transmitted;

  /* MD5 digest of the transmitted data. */
  SshHash hash;

  /* The data connection to which this IO structure belongs to. */
  struct SshAppgwFtpDataConnectionRec *connection;
};

typedef struct SshAppgwFtpIORec SshAppgwFtpIOStruct;
typedef struct SshAppgwFtpIORec *SshAppgwFtpIO;

/* An FTP data connection. */
struct SshAppgwFtpDataConnectionRec
{
  /* Link fields for list of active connection. */
  struct SshAppgwFtpDataConnectionRec *next;
  struct SshAppgwFtpDataConnectionRec *prev;

  /* An application gateway context. */
  SshAppgwContext ctx;

  /* Thread copying data from initiator to responder. */
  SshFSMThreadStruct thread_i;
  SshAppgwFtpIOStruct io_i;

  /* Thread copying data from responder to initiator. */
  SshFSMThreadStruct thread_r;
  SshAppgwFtpIOStruct io_r;
};

typedef struct SshAppgwFtpDataConnectionRec SshAppgwFtpDataConnectionStruct;
typedef struct SshAppgwFtpDataConnectionRec *SshAppgwFtpDataConnection;

/* Context data for FTP application gateways. */
struct SshAppgwFtpCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* FSM controlling the gateway. */
  SshFSMStruct fsm;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */
  unsigned int shutdown : 1;    /* The system is shutting down. */

  /* Active FTP control connections. */
  SshAppgwFtpConnection connections;

  /* Active FTP data connections. */
  SshAppgwFtpDataConnection data_connections;

  /* Known configuration data objects. */
  SshAppgwFtpConfig config_data;
};

typedef struct SshAppgwFtpCtxRec SshAppgwFtpCtxStruct;
typedef struct SshAppgwFtpCtxRec *SshAppgwFtpCtx;


/******************* Prototypes for static help functions *******************/

/* Check if the system is shutting down and if so, unregister and
   destroy the application gateway instance. */
static void ssh_appgw_ftp_check_shutdown(SshAppgwFtpCtx ctx);

/* Destroy and optionally unregister FTP application gateway instance
   `ctx'. */
static void ssh_appgw_ftp_destroy(SshAppgwFtpCtx ctx);


/************ Prototypes for control connection state functions *************/

SSH_FSM_STEP(ssh_appgw_ftp_st_read_line);
SSH_FSM_STEP(ssh_appgw_ftp_st_skip_to_eol);
SSH_FSM_STEP(ssh_appgw_ftp_st_write_line);

SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply);
SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply_line);
SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply_line_done);
SSH_FSM_STEP(ssh_appgw_ftp_st_server_reply_too_long);

SSH_FSM_STEP(ssh_appgw_ftp_st_read_cmd);
SSH_FSM_STEP(ssh_appgw_ftp_st_read_cmd_done);
SSH_FSM_STEP(ssh_appgw_ftp_st_client_cmd_too_long);

SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_line_too_long);
SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_not_allowed);
SSH_FSM_STEP(ssh_appgw_ftp_st_error_operation_not_allowed);
SSH_FSM_STEP(ssh_appgw_ftp_st_error_unknown_command);
SSH_FSM_STEP(ssh_appgw_ftp_st_error_invalid_arguments);
SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_not_implemented);

SSH_FSM_STEP(ssh_appgw_ftp_st_send_reply);

SSH_FSM_STEP(ssh_appgw_ftp_st_failure);
SSH_FSM_STEP(ssh_appgw_ftp_st_terminate);

/* Handling FTP commands. */

SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_passby);
SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_port);
SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_port_open_result);
SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_pasv);

/* Handling server reply codes. */

SSH_FSM_STEP(ssh_appgw_ftp_st_reply_entering_pasv);
SSH_FSM_STEP(ssh_appgw_ftp_st_reply_entering_pasv_open_result);


/************** Prototypes for data connection state functions **************/

SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_wait_input);
SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_write_data);
SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_terminate);


/************************ Registry for FTP commands *************************/

#ifdef SSHN
#undef SSHN
#endif /* SSHNN */
#define SSHN(name) #name, sizeof(#name) - 1, SSH_APPGW_FTP_CMD_ ## name

/* Registry for known FTP commands. */
static const struct
{
  char *name;
  size_t namelen;
  SshAppgwFtpCommand command;
  SshFSMStepCB action;
} ssh_appgw_ftp_commands[] =
{
  {SSHN(ABOR), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(ACCT), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(ALLO), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(APPE), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(CDUP), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(CWD),  ssh_appgw_ftp_st_cmd_passby},
  {SSHN(DELE), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(EPSV), ssh_appgw_ftp_st_cmd_pasv},   /* RFC 2428 */
  {SSHN(EPRT), ssh_appgw_ftp_st_cmd_port},   /* RFC 2428 */
  {SSHN(FEAT), ssh_appgw_ftp_st_cmd_passby}, /* RFC 2989 */
  {SSHN(HELP), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(LIST), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(LPSV), ssh_appgw_ftp_st_cmd_passby}, /* BSD */
  {SSHN(LPRT), ssh_appgw_ftp_st_cmd_passby}, /* BSD */
  {SSHN(MLSD), ssh_appgw_ftp_st_cmd_passby}, /* BSD */
  {SSHN(MLST), ssh_appgw_ftp_st_cmd_passby}, /* BSD */
  {SSHN(MKD),  ssh_appgw_ftp_st_cmd_passby},
  {SSHN(MDTM), ssh_appgw_ftp_st_cmd_passby}, /* in the next FTP RFC //bsd */
  {SSHN(MODE), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(NLST), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(NOOP), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(OPTS), ssh_appgw_ftp_st_cmd_passby}, /* BSD */
  {SSHN(PASS), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(PASV), ssh_appgw_ftp_st_cmd_pasv},
  {SSHN(PORT), ssh_appgw_ftp_st_cmd_port},
  {SSHN(PWD),  ssh_appgw_ftp_st_cmd_passby},
  {SSHN(QUIT), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(REIN), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(REST), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(RETR), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(RMD),  ssh_appgw_ftp_st_cmd_passby},
  {SSHN(RNFR), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(RNTO), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(SITE), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(SIZE), ssh_appgw_ftp_st_cmd_passby}, /* in the next FTP RFC //bsd */
  {SSHN(SMNT), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(STAT), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(STOR), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(STOU), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(STRU), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(SYST), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(TYPE), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(USER), ssh_appgw_ftp_st_cmd_passby},
  {SSHN(CLNT), ssh_appgw_ftp_st_cmd_passby}, /* CLNT CLIENTNAME VERSION //???*/
  {NULL, 0, 0, NULL_FNPTR},
};

/* Registry for interesting server return codes. */
static const struct
{
  SshUInt32 code;
  SshFSMStepCB action;
} ssh_appgw_ftp_server_codes[] =
{
  /* 227 Entering Passive Mode. */
  {227, ssh_appgw_ftp_st_reply_entering_pasv},

  /* 229 Extended Passive Mode Entered. */
  {229, ssh_appgw_ftp_st_reply_entering_pasv},

  {0, NULL_FNPTR},
};


/************************** Static help functions ***************************/

/* Prepend data `data' into buffer `buffer'. */
static void
ssh_appgw_buffer_prepend(SshAppgwFtpBuffer buffer, const char *data)
{
  size_t datalen = strlen(data);

  SSH_ASSERT(sizeof(buffer->buf) - buffer->data_in_buf >= datalen);

  /* Make space for new data. */
  memmove(buffer->buf + datalen, buffer->buf, buffer->data_in_buf);

  /* Prepend data. */
  memcpy(buffer->buf, data, datalen);
  buffer->data_in_buf += datalen;
}

/* Consume `len' bytes from the beginning of the buffer. */
static void
ssh_appgw_buffer_consume(SshAppgwFtpBuffer buffer, size_t len)
{
  SSH_ASSERT(buffer->data_in_buf >= len);

  memmove(buffer->buf, buffer->buf + len, buffer->data_in_buf - len);
  buffer->data_in_buf -= len;
}

/* Completion callback for ssh_appgw_open_port() operation. */
static void
ssh_appgw_ftp_open_port_cb(SshAppgwContext ctx, Boolean success,
                           const SshIpAddr new_dst_ip,
                           SshUInt16 new_dst_port,
                           SshUInt32 open_port_handle,
                           void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshAppgwFtpConnection conn
    = (SshAppgwFtpConnection) ssh_fsm_get_tdata(thread);

  if (success)
    {
      conn->failed = 0;
      conn->port_open = 1;
      conn->open_port_handle = open_port_handle;
      conn->u.open_port.new_dst_ip = *new_dst_ip;
      conn->u.open_port.new_dst_port = new_dst_port;
    }
  else
    {
      conn->failed = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Close an possible open data port of the FTP connection `conn'. */
static void
ssh_appgw_ftp_close_port(SshAppgwFtpConnection conn)
{
  if (conn->port_open)
    {
      ssh_appgw_close_port(conn->ctx, conn->open_port_handle);
      conn->port_open = 0;
    }
}


/******************** Control connection state functions ********************/

#define SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION() \
  if (ftp_ctx->shutdown) \
    { \
      SSH_DEBUG(SSH_D_LOWSTART, ("The system is shutting down")); \
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_terminate); \
      return SSH_FSM_CONTINUE; \
    }

SSH_FSM_STEP(ssh_appgw_ftp_st_read_line)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  while (1)
    {
      unsigned char *cp;
      size_t to_read;
      int read;

      /* Do we already have a full line? */
      cp = conn->io.buffer->buf;

      for (; conn->io.offset < conn->io.buffer->data_in_buf; conn->io.offset++)
        if (conn->io.buffer->buf[conn->io.offset] == '\r')
          {
            if (conn->io.offset + 1 < conn->io.buffer->data_in_buf
                && conn->io.buffer->buf[conn->io.offset + 1] == '\n')
              {
                /* Found it. */
                conn->io.offset += 2;
                SSH_FSM_SET_NEXT(conn->io.success_cb);
                return SSH_FSM_YIELD;
              }
            else if (conn->io.offset + 1 >= conn->io.buffer->data_in_buf)
              {
                /* Not enough data yet. */
                break;
              }
          }

      /* Can we read more? */
      if (conn->io.buffer->data_in_buf >= SSH_APPGW_FTP_MAX_LINE_LEN)
        {
          /* No we can't. */
          SSH_FSM_SET_NEXT(conn->io.too_long_line_cb);
          return SSH_FSM_YIELD;
        }

      to_read = SSH_APPGW_FTP_MAX_LINE_LEN - conn->io.buffer->data_in_buf;

      /* Read. */
      read = ssh_stream_read(conn->io.stream,
                             (conn->io.buffer->buf
                              + conn->io.buffer->data_in_buf),
                             to_read);
      if (read == 0)
        {
          /* An EOF. */
          if (conn->io.offset > 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Premature EOF"));
              conn->io.offset = 0;
            }
          SSH_FSM_SET_NEXT(conn->io.success_cb);
          return SSH_FSM_YIELD;
        }
      else if (read < 0)
        {
          /* Would block. */
          return SSH_FSM_SUSPENDED;
        }
      else
        {
          /* Read something.  Check if we now have a full line. */
          conn->io.buffer->data_in_buf += read;
        }
    }

  /*NOTREACHED*/
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_skip_to_eol)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  unsigned char buf[1];
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  while (1)
    {
      int read;

      /* Read. */
      read = ssh_stream_read(conn->io.stream, buf, 1);
      if (read == 0)
        {
          /* An EOF. */
          conn->io.offset = 0;
          SSH_FSM_SET_NEXT(conn->io.success_cb);
          return SSH_FSM_YIELD;
        }
      else if (read < 0)
        {
          /* Would block. */
          return SSH_FSM_SUSPENDED;
        }
      else
        {
          /* Read something. */
          if (conn->io_bsr_seen)
            {
              if (buf[0] == '\n')
                {
                  /* End of line found. */
                  SSH_FSM_SET_NEXT(conn->io.success_cb);
                  return SSH_FSM_YIELD;
                }
              else if (buf[0] == '\r')
                {
                  /* Nothing here since we already have our `\r' flag
                     set. */
                }
              else
                {
                  /* This was not a valid EOL sequence. */
                  conn->io_bsr_seen = 0;
                }
            }
          else
            {
              if (buf[0] == '\r')
                conn->io_bsr_seen = 1;
            }
        }
    }
  /*NOTREACHED*/
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_write_line)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  while (conn->io.offset)
    {
      int wrote;

      wrote = ssh_stream_write(conn->io.stream, conn->io.buffer->buf,
                               conn->io.offset);
      if (wrote == 0)
        {
          /* A premature EOF. */
          SSH_DEBUG(SSH_D_FAIL, ("Premature EOF"));
          SSH_FSM_SET_NEXT(conn->io.failure_cb);
          return SSH_FSM_YIELD;
        }
      else if (wrote < 0)
        {
          /* Would block. */
          return SSH_FSM_SUSPENDED;
        }
      else
        {
          /* Wrote something. */
          ssh_appgw_buffer_consume(conn->io.buffer, wrote);
          conn->io.offset -= wrote;
        }
    }

  /* Wrote all. */
  SSH_FSM_SET_NEXT(conn->io.success_cb);
  return SSH_FSM_YIELD;
}


SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Starting to read server's reply. */
  conn->reply_1st_line = 1;

  /* And read one line of reply message. */
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_read_reply_line);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply_line)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();


  /* Call a sub-state machine which reads one line. */
  conn->io.buffer = &conn->server_to_client;
  conn->io.stream = conn->ctx->responder_stream;
  conn->io.offset = 0;
  conn->io.success_cb = ssh_appgw_ftp_st_read_reply_line_done;
  conn->io.too_long_line_cb = ssh_appgw_ftp_st_server_reply_too_long;
  conn->io.failure_cb = ssh_appgw_ftp_st_failure;

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_read_line);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_read_reply_line_done)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  size_t len;
  unsigned char *cp;
  SshUInt32 i;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  if (conn->io.offset == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Server has closed the connection"));
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_failure);
      return SSH_FSM_YIELD;
    }

  /* Now we have a line of input in our buffer.  Let's see what it
     is. */
  cp = conn->server_to_client.buf;
  len = conn->io.offset;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Read line:"), cp, len);

  if (conn->reply_1st_line)
    {
      /* The line should start as `ddd-' or `ddd '. */
      if (len >= 6
          && SSH_IS_DIGIT(cp[0])
          && SSH_IS_DIGIT(cp[1])
          && SSH_IS_DIGIT(cp[2])
          && (cp[3] == '-' || cp[3] == ' '))
        {
          /* It is a valid first reply line.  Do we have any special
             actions for this reply code? */

          conn->reply_special = 0;
          conn->last_reply_code = atoi((char *)cp);

          for (i = 0; ssh_appgw_ftp_server_codes[i].code; i++)
            if (ssh_appgw_ftp_server_codes[i].code == conn->last_reply_code)
              {
                /* Yes, this a special reply code for which we have an
                   action. */
                conn->reply_special = 1;
                break;
              }
        }

      /* The first line processed. */
      conn->reply_1st_line = 0;
    }

  /* Prepare to write it to the client.  We write from the `io.buffer'
     `io.offset' bytes. */
  conn->io.stream = conn->ctx->initiator_stream;

  /* Is it a valid terminal line? */
  if (len >= 6
      && SSH_IS_DIGIT(cp[0])
      && SSH_IS_DIGIT(cp[1])
      && SSH_IS_DIGIT(cp[2])
      && cp[3] == ' ')
    {
      /* Yes it is.  Here we could check that the reply code matches
         for multi-line replies but actually it does not break
         anything to process only the last reply line. */
      conn->last_reply_code = atoi((char *)cp);

      /* Any special actions for this reply code? */
      for (i = 0; ssh_appgw_ftp_server_codes[i].code; i++)
        if (ssh_appgw_ftp_server_codes[i].code == conn->last_reply_code)
          {
            /* Yes. */
            SSH_DEBUG(SSH_D_LOWOK, ("Special reply code %u",
                                    (unsigned int)
				    conn->last_reply_code));
            SSH_FSM_SET_NEXT(ssh_appgw_ftp_server_codes[i].action);
            return SSH_FSM_YIELD;
          }

      /* Check if this is a final status or a preliminary reply in
         which case we must read more. */
      if (cp[0] == '1')
        {
          /* Preliminary reply */
          conn->io.success_cb = ssh_appgw_ftp_st_read_reply;
        }
      else
        {
          /* Final reply line.  We will continue reading more commands
             from the client. */
          conn->io.success_cb = ssh_appgw_ftp_st_read_cmd;
          /* This would be a good place to do post-checks for commands
             since now we know the last command and server's reply. */
        }
    }
  else
    {
      /* No it isn't.  We must read more reply lines. */
      if (conn->reply_special)
        {
          /* It is a special reply code.  Let's ignore everything but
             the final reply line. */
          ssh_appgw_buffer_consume(conn->io.buffer, conn->io.offset);
          conn->io.offset = 0;

          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_read_reply_line);
          return SSH_FSM_YIELD;
        }

      /* Not a special reply code.  Pass the line to client and read
         more. */
      conn->io.success_cb = ssh_appgw_ftp_st_read_reply_line;
    }

  conn->io.failure_cb = ssh_appgw_ftp_st_failure;

  /* Write output. */
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_write_line);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_server_reply_too_long)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Too long reply line from the server.  However, since all
     interesting data in server's replies are in the first 4 bytes
     (except in the `Entering Passive Mode' cases), we simply truncate
     the reply.  Note that it is safe to append data to our input
     buffer since we have reserved some extra space for the appended
     items. */

  SSH_ASSERT(conn->io.buffer->data_in_buf > 0);
  if (conn->io.buffer->buf[conn->io.buffer->data_in_buf - 1] == '\r')
    {
      conn->io.buffer->buf[conn->io.buffer->data_in_buf++] = '\n';
      conn->io.offset += 1;
      conn->io_bsr_seen = 1;
    }
  else
    {
      conn->io.buffer->buf[conn->io.buffer->data_in_buf++] = '\r';
      conn->io.buffer->buf[conn->io.buffer->data_in_buf++] = '\n';
      conn->io.offset += 2;
      conn->io_bsr_seen = 0;
    }

  /* And skip the rest of the line.  After that we continue as we did
     receive a valid reply line from the server. */
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_skip_to_eol);

  return SSH_FSM_YIELD;
}


SSH_FSM_STEP(ssh_appgw_ftp_st_read_cmd)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Call a sub-state machine which reads one line. */

  conn->io.buffer = &conn->client_to_server;
  conn->io.stream = conn->ctx->initiator_stream;
  conn->io.offset = 0;
  conn->io.success_cb = ssh_appgw_ftp_st_read_cmd_done;
  conn->io.too_long_line_cb = ssh_appgw_ftp_st_client_cmd_too_long;
  conn->io.failure_cb = ssh_appgw_ftp_st_failure;

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_read_line);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_read_cmd_done)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  size_t len, pos;
  unsigned char *cp;
  SshUInt32 i;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  if (conn->io.offset == 0)
    {
      /* No more commands from the client. */
      if (conn->last_reply_code == 221
          || conn->last_reply_code == 421)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Shutting down"));
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_terminate);
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Client has closed the connection"));
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_failure);
        }
      return SSH_FSM_YIELD;
    }

  /* Now we have a command in out input buffer.  Let's parse it. */

  cp = conn->client_to_server.buf;
  len = conn->io.offset;

  for (pos = 0; pos < len; pos++)
    {
      if (cp[pos] == ' ' || cp[pos] == '\r')
        break;

      /* Convert the command to upper-case. */
      if ('a' <= cp[pos] && cp[pos] <= 'z')
        cp[pos] = cp[pos] - 'a' + 'A';
    }
  SSH_ASSERT(pos < len);

  /* Check how to handle this command. */
  for (i = 0; ssh_appgw_ftp_commands[i].name; i++)
    if (ssh_appgw_ftp_commands[i].namelen == pos
        && memcmp(cp, ssh_appgw_ftp_commands[i].name, pos) == 0)
      {
        /* We know this command. */
        SSH_DEBUG(SSH_D_LOWOK, ("Command `%.*s'", (int) len - 2, cp));

        /* Store it as our last command. */
        conn->last_command = ssh_appgw_ftp_commands[i].command;

        /* Is the command disabled? */
        if (SSH_APPGW_FTP_IS_DISABLED(conn->config,
                                      ssh_appgw_ftp_commands[i].command))
          {
            SSH_DEBUG(SSH_D_LOWOK, ("The command is disabled"));
            ssh_appgw_audit_event(conn->ctx,
                                  SSH_AUDIT_NOTICE,
                                  SSH_AUDIT_TXT, "Command disabled",
                                  SSH_AUDIT_FTP_COMMAND, cp, pos,
                                  SSH_AUDIT_ARGUMENT_END);
            SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_error_command_not_allowed);
          }
        else
          {
            SSH_FSM_SET_NEXT(ssh_appgw_ftp_commands[i].action);
          }

        /* And handle command. */
        return SSH_FSM_YIELD;
      }

  /* An unknown command. */
  SSH_DEBUG(SSH_D_FAIL, ("Unknown command `%.*s'", (int) pos, cp));
  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "Unknown command",
                        SSH_AUDIT_FTP_COMMAND, cp, pos,
                        SSH_AUDIT_ARGUMENT_END);

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_error_unknown_command);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_client_cmd_too_long)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Skip the too long command. */
  SSH_ASSERT(conn->io.buffer->data_in_buf > 0);
  if (conn->io.buffer->buf[conn->io.buffer->data_in_buf - 1] == '\r')
    conn->io_bsr_seen = 1;
  else
    conn->io_bsr_seen = 0;

  /* Skip the whole input buffer. */
  conn->io.offset = conn->io.buffer->data_in_buf;

  /* And reply with an error message. */
  conn->io.success_cb = ssh_appgw_ftp_st_error_command_line_too_long;

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_skip_to_eol);

  return SSH_FSM_YIELD;
}


SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_line_too_long)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "500 Command line too long.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_not_allowed)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "500 Command not allowed.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_error_operation_not_allowed)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "500 Operation not allowed.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_error_unknown_command)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "500 Unknown command.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_error_invalid_arguments)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_audit_event(conn->ctx,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT, "Invalid arguments for command",
                        SSH_AUDIT_ARGUMENT_END);

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "501 Invalid arguments.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_error_command_not_implemented)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  ssh_appgw_buffer_prepend(&conn->server_to_client,
                           "502 Command not implemented.\r\n");
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_send_reply)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  unsigned char *cp;
  unsigned char *sep;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Consume the possible invalid command. */
  if (conn->io.offset > 0)
    ssh_appgw_buffer_consume(&conn->client_to_server, conn->io.offset);

  /* Store status code of this reply. */
  cp = conn->server_to_client.buf;
  conn->last_reply_code = atoi((char *)cp);

  /* Resolve the length of the message. */
  sep = (unsigned char *)strchr((char *)cp, '\n');
  SSH_ASSERT(sep != NULL);
  conn->io.offset = sep - cp + 1;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Sending reply:"), cp, conn->io.offset);

  /* Write error message to client and wait for new commands. */

  conn->io.stream = conn->ctx->initiator_stream;
  conn->io.buffer = &conn->server_to_client;
  conn->io.success_cb = ssh_appgw_ftp_st_read_cmd;
  conn->io.failure_cb = ssh_appgw_ftp_st_failure;

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_write_line);

  return SSH_FSM_YIELD;
}


SSH_FSM_STEP(ssh_appgw_ftp_st_failure)
{
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_terminate);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_terminate)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Terminating control connection"));
  return SSH_FSM_FINISH;
}

/* Handling FTP commands. */

SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_passby)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;

  /* Pass command to the server and wait for its reply. */

  conn->io.stream = conn->ctx->responder_stream;
  conn->io.success_cb = ssh_appgw_ftp_st_read_reply;
  conn->io.failure_cb = ssh_appgw_ftp_st_failure;

  SSH_ASSERT(conn->io.offset > 0);
  SSH_ASSERT(conn->io.buffer == &conn->client_to_server);

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_write_line);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_port)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  unsigned char *cp, *sep;
  size_t len;
  SshIpAddrStruct addr;
  SshUInt16 port;
  SshUInt32 flags;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  /* Passive mode off (active mode). */
  conn->passive = 0;

  cp = conn->client_to_server.buf;
  len = conn->client_to_server.data_in_buf;

  if (cp[0] == 'E')
    {
      int delimiter;
      Boolean ipv6;
      size_t i;
      unsigned char buf[64];
      char *end;

      /* EPRT command. */
      /* EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d> */

      if (len < 13)
        {
        invalid_eprt:
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid EPRT command"));
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_error_invalid_arguments);
          return SSH_FSM_YIELD;
        }
      len -= 4;
      cp += 4;
      if (cp[0] != ' ')
        goto invalid_eprt;

      len--;
      cp++;
      delimiter = *cp;

      len--;
      cp++;

      switch (*cp)
        {
        case '1':
          ipv6 = FALSE;
          break;

        case '2':
          ipv6 = TRUE;
          break;

        default:
          goto invalid_eprt;
          break;
        }

      len--;
      cp++;
      if (*cp != delimiter)
        goto invalid_eprt;

      len--;
      cp++;

      /* Find the end of the IP address. */
      for (i = 0; i < len && cp[i] != delimiter; i++)
        ;
      if (i >= len || i >= sizeof(buf) - 1)
        goto invalid_eprt;

      memcpy(buf, cp, i);
      buf[i] = '\0';

      if (!ssh_ipaddr_parse(&addr, buf))
        goto invalid_eprt;

      if (SSH_IP_IS4(&addr) && ipv6)
        goto invalid_eprt;

      len -= i;
      cp += i;

      if (len == 0)
        goto invalid_eprt;

      len--;
      cp++;

      /* Read TCP port number. */
      for (i = 0; i < len && cp[i] != delimiter; i++)
        ;
      if (i >= len || i >= sizeof(buf) - 1)
        goto invalid_eprt;

      memcpy(buf, cp, i);
      buf[i] = '\0';

      port = (SshUInt32) ssh_ustrtoul(buf, &end, 10);
      if (*end != '\0')
        goto invalid_eprt;

      /* EPRT command parsed. */
    }
  else
    {
      unsigned int h1, h2, h3, h4, p1, p2;
      unsigned char addr_buf[4];

      /* PORT command. */

      sep = (unsigned char *)strchr((char *)cp, '\r');
      SSH_ASSERT(sep != NULL);

      *sep = '\0';
      if (sscanf((char *)cp, "PORT %u,%u,%u,%u,%u,%u",
                 &h1, &h2, &h3, &h4, &p1, &p2) != 6)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid PORT command"));
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_error_invalid_arguments);
          return SSH_FSM_YIELD;
        }
      *sep = '\r';

      addr_buf[0] = (unsigned char) h1;
      addr_buf[1] = (unsigned char) h2;
      addr_buf[2] = (unsigned char) h3;
      addr_buf[3] = (unsigned char) h4;

      SSH_IP_DECODE(&addr, addr_buf, 4);
      port = (p1 << 8) + p2;
    }

  /* Check that `addr' matches our client's IP address. */
  if (!SSH_IP_EQUAL(&addr, &conn->ctx->initiator_ip))
    {
      /* It does not match.  Is client allowed to change its IP? */
      if ((conn->config->flags & SSH_APPGW_FTP_CLIENT_CAN_CHANGE_IP) == 0)
        {
          char buf[256];

          /* No it isn't. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Client changed its IP address from %@ to %@",
                     ssh_ipaddr_render, &conn->ctx->initiator_ip,
                     ssh_ipaddr_render, &addr));
          ssh_snprintf(buf, sizeof(buf), "IP address changed to %@",
                       ssh_ipaddr_render, &addr);
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_FTP_IP_CHANGE,
                                SSH_AUDIT_COMMAND,
                                conn->client_to_server.buf, 4,
                                SSH_AUDIT_TXT, buf,
                                SSH_AUDIT_ARGUMENT_END);
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_error_operation_not_allowed);
          return SSH_FSM_YIELD;
        }
    }

  /* Close possible old data port. */
  ssh_appgw_ftp_close_port(conn);

  SSH_DEBUG(SSH_D_MIDSTART, ("Opening port %@.%u",
                             ssh_ipaddr_render, &addr,
                             (unsigned int) port));

  flags = 0;

  if (conn->config->content_filter != SSH_APPGW_FTP_CONTENT_FILTER_NONE)
    {
      /* Store the content filter type of this data transfer. */
      conn->content_filter = conn->config->content_filter;
      flags |= SSH_APPGW_OPEN_THISGW;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_cmd_port_open_result);
  SSH_FSM_ASYNC_CALL(ssh_appgw_open_port(conn->ctx,
                                         NULL,
                                         0, port,
                                         flags,
                                         ssh_appgw_ftp_open_port_cb,
                                         thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_port_open_result)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  char buf[64];

  /* Some other event woke us up before the pme_add_rule()
     has completed. Wait till the engine/PM api call completes
     before continuing. */
  if (conn->failed == 0 && conn->port_open == 0)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_cmd_port_open_result);
      SSH_FSM_ASYNC_CALL(;);
    }

  if (conn->failed)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Data port opening failed"));
      ssh_appgw_buffer_prepend(&conn->server_to_client,
                               "500 Data port opening failed.\r\n");
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Port `%@:%u' opened",
                              ssh_ipaddr_render, &conn->u.open_port.new_dst_ip,
                              (unsigned int) conn->u.open_port.new_dst_port));

      /* Consume old port command. */
      SSH_ASSERT(conn->io.offset > 0);
      ssh_appgw_buffer_consume(&conn->client_to_server, conn->io.offset);
      conn->io.offset = 0;

      /* Create new command. */
      ssh_snprintf(buf, sizeof(buf), "PORT %u,%u,%u,%u,%u,%u\r\n",
                   (unsigned int) SSH_IP4_BYTE1(&conn->u.open_port.new_dst_ip),
                   (unsigned int) SSH_IP4_BYTE2(&conn->u.open_port.new_dst_ip),
                   (unsigned int) SSH_IP4_BYTE3(&conn->u.open_port.new_dst_ip),
                   (unsigned int) SSH_IP4_BYTE4(&conn->u.open_port.new_dst_ip),
                   (unsigned int) ((conn->u.open_port.new_dst_port >> 8)
                                   & 0x00ff),
                   (unsigned int) (conn->u.open_port.new_dst_port & 0x00ff));
      ssh_appgw_buffer_prepend(&conn->client_to_server, buf);
      conn->io.offset = strlen(buf);
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_cmd_passby);
    }

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_cmd_pasv)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;

  /* Passive mode on. */
  conn->passive = 1;
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_cmd_passby);

  return SSH_FSM_YIELD;
}


/* Handling server reply codes. */

SSH_FSM_STEP(ssh_appgw_ftp_st_reply_entering_pasv)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  unsigned char *cp;
  size_t i, j, len;
  SshUInt16 port = 0;
  SshUInt32 flags;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_CONTROL_HANDLE_EXCEPTION();

  cp = conn->server_to_client.buf;
  len = conn->server_to_client.data_in_buf;

  if (conn->last_reply_code == 227)
    {
      unsigned int h1, h2, h3, h4, p1, p2;
      SshIpAddrStruct addr;
      unsigned char addr_buf[4];

      /* Lookup a string of format (h1,h2,h3,h4,p1,p2). */
      for (i = 0; i < len; i++)
        if (cp[i] == '(')
          {
            char *cp2;
            int result;

            cp2 = strchr((char *)(cp + i), ')');
            if (cp2 == NULL)
              /* No terminator found. */
              continue;

            *cp2 = '\0';
            result = sscanf((char *)(cp + i), "(%u,%u,%u,%u,%u,%u",
                            &h1, &h2, &h3, &h4, &p1, &p2);
            *cp2 = ')';

            if (result == 6)
              {
                /* Found it. */

                addr_buf[0] = (unsigned char) h1;
                addr_buf[1] = (unsigned char) h2;
                addr_buf[2] = (unsigned char) h3;
                addr_buf[3] = (unsigned char) h4;

                SSH_IP_DECODE(&addr, &addr_buf, 4);

                port = (p1 << 8) + p2;
                break;
              }
          }

      if (i >= len)
        goto malformed_pasv_reply;

      /* Check that the `addr' matches server's IP address. */
      if (!SSH_IP_EQUAL(&addr, &conn->ctx->responder_ip))
        {
          /* It does not match.  Is server allowed to change its IP? */
          if ((conn->config->flags & SSH_APPGW_FTP_SERVER_CAN_CHANGE_IP) == 0)
            {
              char buf[256];
              char *cmd;

              /* No it isn't. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Server changed its IP address from %@ to %@",
                         ssh_ipaddr_render, &conn->ctx->responder_ip,
                         ssh_ipaddr_render, &addr));
              ssh_snprintf(buf, sizeof(buf), "IP address changed to %@",
                           ssh_ipaddr_render, &addr);

              switch (conn->last_command)
                {
                case SSH_APPGW_FTP_CMD_EPRT:
                  cmd = "EPRT";
                  break;

                case SSH_APPGW_FTP_CMD_PORT:
                  cmd = "PORT";
                  break;

                default:
                  cmd = "????";
                  break;
                }

              ssh_appgw_audit_event(conn->ctx,
                                    SSH_AUDIT_FTP_IP_CHANGE,
                                    SSH_AUDIT_FTP_COMMAND, cmd, 4,
                                    SSH_AUDIT_TXT, buf,
                                    SSH_AUDIT_ARGUMENT_END);

              /* Consume server's original reply. */
              ssh_appgw_buffer_consume(&conn->server_to_client,
                                       conn->io.offset);
              conn->io.offset = 0;

              /* Create an error reply. */
              ssh_appgw_buffer_prepend(&conn->server_to_client,
                                       "500 Operation not allowed.\r\n");
              SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);
              return SSH_FSM_YIELD;
            }
        }
    }
  else
    {
      SSH_ASSERT(conn->last_reply_code == 229);

      /* Lookup a string of format (<d><d><d><tcp-port><d>). */
      for (i = 0; i < len; i++)
        if (cp[i] == '(' && i + 7 < len)
          {
            /* This is a potential start. */
            if (cp[i + 1] == cp[i + 2]
                && cp[i + 1] == cp[i + 3]
                && SSH_IS_DIGIT(cp[i + 4]))
              {
                /* Read possible port number.  The maximum port number
                   length is the length of string `65535' that is 5
                   digits. */
                for (j = i + 4;
                     (j < len
                      && SSH_IS_DIGIT(cp[j])
                      && j < i + 4 + 5);
                     j++)
                  {
                    port *= 10;
                    port += cp[j] - '0';
                  }

                if (j >= len)
                  continue;

                /* Check the terminator sequence `<d>)'. */
                if (cp[j] == cp[i + 1]
                    && j + 1 < len && cp[j + 1] == ')')
                  {
                    /* Found it. */
                    break;
                  }
              }
          }

      if (i >= len)
        {
        malformed_pasv_reply:
          SSH_DEBUG(SSH_D_FAIL, ("Malformed reply line: no port found"));

          /* Consume server's original reply. */
          ssh_appgw_buffer_consume(&conn->server_to_client, conn->io.offset);
          conn->io.offset = 0;

          /* Create an error reply. */
          ssh_appgw_buffer_prepend(&conn->server_to_client,
                                   "500 Data port opening failed.\r\n");
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);
          return SSH_FSM_YIELD;
        }
    }

  /* Consume server's original reply. */
  ssh_appgw_buffer_consume(&conn->server_to_client, conn->io.offset);
  conn->io.offset = 0;

  /* Close possible old data port. */
  ssh_appgw_ftp_close_port(conn);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Opening port %@.%u",
             ssh_ipaddr_render, &conn->ctx->responder_ip_after_nat,
             (unsigned int) port));

  flags = SSH_APPGW_OPEN_FROM_INITIATOR;

  if (conn->config->content_filter != SSH_APPGW_FTP_CONTENT_FILTER_NONE)
    {
      /* Store the content filter type of this data transfer. */
      conn->content_filter = conn->config->content_filter;
      flags |= SSH_APPGW_OPEN_THISGW;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_reply_entering_pasv_open_result);
  SSH_FSM_ASYNC_CALL(ssh_appgw_open_port(conn->ctx,
                                         NULL, 0, port,
                                         flags,
                                         ssh_appgw_ftp_open_port_cb,
                                         thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_appgw_ftp_st_reply_entering_pasv_open_result)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) thread_context;
  char buf[128];

  /* Some other event woke us up before the pme_add_rule()
     has completed. Wait till the engine/PM api call completes
     before continuing. */
  if (conn->failed == 0 && conn->port_open == 0)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_reply_entering_pasv_open_result);
      SSH_FSM_ASYNC_CALL(;);
    }

  if (conn->failed)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Data port opening failed"));
      ssh_appgw_buffer_prepend(&conn->server_to_client,
                               "500 Data port opening failed.\r\n");
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Port `%@:%u' opened",
                              ssh_ipaddr_render, &conn->u.open_port.new_dst_ip,
                              (unsigned int) conn->u.open_port.new_dst_port));

      /* The old reply line has already been consumed. */
      SSH_ASSERT(conn->io.offset == 0);

      /* Create new reply message. */
      if (conn->last_command == SSH_APPGW_FTP_CMD_EPSV)
        ssh_snprintf(buf, sizeof(buf),
                     "229 Entering Extended Passive Mode (|||%u|)\r\n",
                     (unsigned int) conn->u.open_port.new_dst_port);
      else
        ssh_snprintf(
                buf, sizeof(buf),
                "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u)\r\n",
                (unsigned int) SSH_IP4_BYTE1(&conn->u.open_port.new_dst_ip),
                (unsigned int) SSH_IP4_BYTE2(&conn->u.open_port.new_dst_ip),
                (unsigned int) SSH_IP4_BYTE3(&conn->u.open_port.new_dst_ip),
                (unsigned int) SSH_IP4_BYTE4(&conn->u.open_port.new_dst_ip),
                (unsigned int) ((conn->u.open_port.new_dst_port >> 8)
                                & 0x00ff),
                (unsigned int) (conn->u.open_port.new_dst_port & 0x00ff));

      ssh_appgw_buffer_prepend(&conn->server_to_client, buf);
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_st_send_reply);
    }

  return SSH_FSM_YIELD;
}


/********************* Data connection state functions **********************/

#define SSH_APPGW_FTP_DATA_HANDLE_EXCEPTION() \
  if (ftp_ctx->shutdown) \
    { \
      SSH_DEBUG(SSH_D_LOWSTART, ("The system is shutting down")); \
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_data_st_io_terminate); \
      return SSH_FSM_CONTINUE; \
    }


SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_wait_input)
{
  SshAppgwFtpIO io = (SshAppgwFtpIO) thread_context;
  int read;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_DATA_HANDLE_EXCEPTION();

  read = ssh_stream_read(io->from, io->buf, sizeof(io->buf));
  if (read < 0)
    {
      return SSH_FSM_SUSPENDED;
    }
  else if (read == 0)
    {
      /* Signal that we won't write any more data. */
      ssh_stream_output_eof(io->to);
      SSH_FSM_SET_NEXT(ssh_appgw_ftp_data_st_io_terminate);
    }
  else
    {
      io->data_in_buf = read;
      io->bytes_transmitted += read;

      if (io->hash)
        ssh_hash_update(io->hash, io->buf, read);

      SSH_FSM_SET_NEXT(ssh_appgw_ftp_data_st_io_write_data);
    }

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_write_data)
{
  SshAppgwFtpIO io = (SshAppgwFtpIO) thread_context;
  int wrote;
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) fsm_context;

  SSH_APPGW_FTP_DATA_HANDLE_EXCEPTION();

  SSH_ASSERT(io->data_in_buf);
  SSH_ASSERT(io->bufpos < io->data_in_buf);

  while (io->bufpos < io->data_in_buf)
    {
      wrote = ssh_stream_write(io->to, io->buf + io->bufpos,
                               io->data_in_buf - io->bufpos);
      if (wrote < 0)
        {
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_ftp_data_st_io_terminate);
          return SSH_FSM_YIELD;
        }
      else
        {
          io->bufpos += wrote;
        }
    }

  SSH_ASSERT(io->bufpos >= io->data_in_buf);
  io->bufpos = 0;
  io->data_in_buf = 0;
  SSH_FSM_SET_NEXT(ssh_appgw_ftp_data_st_io_wait_input);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(ssh_appgw_ftp_data_st_io_terminate)
{
  SshAppgwFtpIO io = (SshAppgwFtpIO) thread_context;

  /* This thread is finished. */
  io->active = 0;

  /* We are all done.  Our destructor callback will handle reporting
     about this transfer, etc. */
  return SSH_FSM_FINISH;
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_ftp_data_thread_destructor(SshFSM fsm, void *context)
{
  SshAppgwFtpCtx ftp_ctx = ssh_fsm_get_gdata_fsm(fsm);
  SshAppgwFtpIO io = (SshAppgwFtpIO) context;
  SshAppgwFtpDataConnection data = io->connection;
  unsigned char bytes[8];
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t digest_len = 0;

  if (data->io_i.active || data->io_r.active)
    /* This was not the last thread. */
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("FTP data connection %@.%d > %@.%d terminated",
             ssh_ipaddr_render, &data->ctx->initiator_ip,
             data->ctx->initiator_port,
             ssh_ipaddr_render, &data->ctx->responder_ip,
             data->ctx->responder_port));

  if (data->io_i.bytes_transmitted)
    {
      SSH_PUT_64BIT(bytes, data->io_i.bytes_transmitted);
      if (data->io_i.hash)
        {
          ssh_hash_final(data->io_i.hash, digest);
          digest_len = ssh_hash_digest_length("md5");
        }
    }
  else if (data->io_r.bytes_transmitted)
    {
      SSH_PUT_64BIT(bytes, data->io_r.bytes_transmitted);
      if (data->io_r.hash)
        {
          ssh_hash_final(data->io_r.hash, digest);
          digest_len = ssh_hash_digest_length("md5");
        }
    }
  else
    {
      SSH_PUT_64BIT(bytes, 0);
    }

  ssh_appgw_audit_event(data->ctx,
                        SSH_AUDIT_APPGW_SESSION_END,
                        SSH_AUDIT_TRANSMIT_BYTES, bytes, 8,
                        SSH_AUDIT_TRANSMIT_DIGEST, digest, digest_len,
                        SSH_AUDIT_ARGUMENT_END);





  ssh_stream_set_callback(data->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(data->ctx->responder_stream, NULL_FNPTR, NULL);

  ssh_appgw_done(data->ctx);

  if (data->io_i.hash)
    ssh_hash_free(data->io_i.hash);
  if (data->io_r.hash)
    ssh_hash_free(data->io_r.hash);

  /* Remove this data connection from the application gateway's list
     of active data connections. */

  if (data->next)
    data->next->prev = data->prev;

  if (data->prev)
    data->prev->next = data->next;
  else
    ftp_ctx->data_connections = data->next;

  /* Free the data connection structure. */
  ssh_free(data);

  /* And check if the system is shutting down. */
  ssh_appgw_ftp_check_shutdown(ftp_ctx);
}

static void
ssh_appgw_ftp_data_stream_cb(SshStreamNotification notification, void *context)
{
  SshAppgwFtpDataConnection data = (SshAppgwFtpDataConnection) context;

  if (data->io_i.active)
    ssh_fsm_continue(&data->thread_i);
  if (data->io_r.active)
    ssh_fsm_continue(&data->thread_r);
}


static void
ssh_appgw_ftp_thread_destructor(SshFSM fsm, void *context)
{
  SshAppgwFtpCtx ftp_ctx = ssh_fsm_get_gdata_fsm(fsm);
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("FTP control connection %@.%d > %@.%d terminated",
             ssh_ipaddr_render, &conn->ctx->initiator_ip,
             conn->ctx->initiator_port,
             ssh_ipaddr_render, &conn->ctx->responder_ip,
             conn->ctx->responder_port));





  ssh_stream_set_callback(conn->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(conn->ctx->responder_stream, NULL_FNPTR, NULL);

  ssh_appgw_ftp_close_port(conn);
  ssh_appgw_done(conn->ctx);

  /* Remove us from the application gateway's list of connections. */

  if (conn->next)
    conn->next->prev = conn->prev;

  if (conn->prev)
    conn->prev->next = conn->next;
  else
    ftp_ctx->connections = conn->next;

  /* Free our connection structure. */
  ssh_free(conn);

  /* And check if the system is shutting down. */
  ssh_appgw_ftp_check_shutdown(ftp_ctx);
}

static void
ssh_appgw_ftp_stream_cb(SshStreamNotification notification, void *context)
{
  SshAppgwFtpConnection conn = (SshAppgwFtpConnection) context;

  ssh_fsm_continue(&conn->thread);
}


static void
ssh_appgw_ftp_conn_cb(SshAppgwContext ctx,
                      SshAppgwAction action,
                      const unsigned char *udp_data,
                      size_t udp_len,
                      void *context)
{
  SshAppgwFtpCtx ftp_ctx = (SshAppgwFtpCtx) context;
  SshAppgwFtpConnection conn;
  SshAppgwFtpConfig config;
  SshAppgwFtpConfig c;

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

      /* Unmarshal configuration data. */
      config = ssh_appgw_ftp_config_unmarshal(ctx->config_data,
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
                        SSH_APPGW_NAME,
			(unsigned int) ctx->service_id);
          return;
        }
#ifdef DEBUG_LIGHT
      {
        SshUInt32 i;
        Boolean first = TRUE;
        char *cp = "???";

        for (i = 0; ssh_appgw_ftp_commands[i].name; i++)
          if (SSH_APPGW_FTP_IS_DISABLED(config,
                                        ssh_appgw_ftp_commands[i].command))
            {
              if (first)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, ("Disabled commands:"));
                  first = FALSE;
                }
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("  %s", ssh_appgw_ftp_commands[i].name));
            }
        switch (config->content_filter)
          {
          case SSH_APPGW_FTP_CONTENT_FILTER_NONE:
            cp = "none";
            break;

          case SSH_APPGW_FTP_CONTENT_FILTER_SIMPLE:
            cp = "simple";
            break;

          case SSH_APPGW_FTP_CONTENT_FILTER_MD5:
            cp = "MD5";
            break;
          }
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Content filter `%s'", cp));

        if (config->flags)
          {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Flags:"));
            if (config->flags & SSH_APPGW_FTP_CLIENT_CAN_CHANGE_IP)
              SSH_DEBUG(SSH_D_NICETOKNOW, ("  client-can-change-ip"));
            if (config->flags & SSH_APPGW_FTP_SERVER_CAN_CHANGE_IP)
              SSH_DEBUG(SSH_D_NICETOKNOW, ("  server-can-change-ip"));
          }
      }
#endif /* DEBUG_LIGHT */

      /* Store service ID. */
      config->service_id = ctx->service_id;

      /* Do we already know this service ID? */
      for (c = ftp_ctx->config_data; c; c = c->next)
        if (c->service_id == config->service_id)
          {
            /* Steal attributes from the new config object. */
            config->next = c->next;
            memcpy(c, config, sizeof(*config));

            /* Clear new fields so they won't ge tfreed when the
               object is freed. */
            memset(config, 0, sizeof(*config));
            ssh_appgw_ftp_config_destroy(config);
            return;
          }

      /* Configuration data for a new service object. */
      config->next = ftp_ctx->config_data;
      ftp_ctx->config_data = config;
      break;

    case SSH_APPGW_SHUTDOWN:
      ftp_ctx->shutdown = 1;

      if (ftp_ctx->connections || ftp_ctx->data_connections)
	{
	  SshAppgwFtpDataConnection data;

	  /* We have active connections.  We notify the control and data
	     connections about the shutdown. */

	  for (data = ftp_ctx->data_connections; data; data = data->next)
	    {
	      ssh_fsm_continue(&data->thread_i);
	      ssh_fsm_continue(&data->thread_r);
	    }

	  for (conn = ftp_ctx->connections; conn; conn = conn->next)
	    ssh_fsm_continue(&conn->thread);
	}
      else
        {
          /* Shutdown immediately. */
          ssh_appgw_ftp_destroy(ftp_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New ftp %s connection %@.%d > %@.%d",
                 ctx->master ? "data" : "control",
                 ssh_ipaddr_render, &ctx->initiator_ip,
                 ctx->initiator_port,
                 ssh_ipaddr_render, &ctx->responder_ip,
                 ctx->responder_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &ctx->initiator_ip_after_nat,
                 ctx->initiator_port_after_nat));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &ctx->responder_ip_after_nat,
                 ctx->responder_port_after_nat));

      /* Lookup its configuration data. */
      for (config = ftp_ctx->config_data; config; config = config->next)
        if (config->service_id == ctx->service_id)
          break;

      if (config == NULL)
        {
          ssh_appgw_audit_event(ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "No configuration data specified for "
                                "this service.",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_appgw_done(ctx);
          return;
        }

      if (ctx->master)
        {
          SshAppgwFtpDataConnection data;
          SshCryptoStatus crypto_status;

          data = ssh_calloc(1, sizeof(*data));
          if (data == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not allocate FTP data connection"));
              ssh_appgw_done(ctx);
              return;
            }

          /* Link data connection to the gateway's list of active
             connections. */
          data->next = ftp_ctx->data_connections;
          if (ftp_ctx->data_connections)
            ftp_ctx->data_connections->prev = data;
          ftp_ctx->data_connections = data;

          data->ctx = ctx;

          /* Link the connection object to the context's
             `user_context' field. */
          ctx->user_context = data;

          /* Fetch the connection object of our control connection. */
          conn = (SshAppgwFtpConnection) ctx->master->user_context;

          /* Setup IO threads. */

          data->io_i.active = 1;
          data->io_i.from = ctx->initiator_stream;
          data->io_i.to = ctx->responder_stream;
          data->io_i.connection = data;

          data->io_r.active = 1;
          data->io_r.from = ctx->responder_stream;
          data->io_r.to = ctx->initiator_stream;
          data->io_r.connection = data;

          /* Init content filter. */
          switch (conn->content_filter)
            {
            case SSH_APPGW_FTP_CONTENT_FILTER_NONE:
              /* This should not be reached at all. */
              break;

            case SSH_APPGW_FTP_CONTENT_FILTER_SIMPLE:
              /* Nothing special here. */
              break;

            case SSH_APPGW_FTP_CONTENT_FILTER_MD5:
              crypto_status = ssh_hash_allocate("md5", &data->io_i.hash);
              if (crypto_status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Could not allocate MD5 hash: %s",
                             ssh_crypto_status_message(crypto_status)));
                  data->io_i.hash = NULL;
                }

              crypto_status = ssh_hash_allocate("md5", &data->io_r.hash);
              if (crypto_status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Could not allocate MD5 hash: %s",
                             ssh_crypto_status_message(crypto_status)));
                  data->io_r.hash = NULL;
                }
              break;
            }

          /* Start IO threads. */
          ssh_fsm_thread_init(&ftp_ctx->fsm, &data->thread_i,
                              ssh_appgw_ftp_data_st_io_wait_input,
                              NULL_FNPTR, ssh_appgw_ftp_data_thread_destructor,
                              &data->io_i);
          ssh_fsm_thread_init(&ftp_ctx->fsm, &data->thread_r,
                              ssh_appgw_ftp_data_st_io_wait_input,
                              NULL_FNPTR, ssh_appgw_ftp_data_thread_destructor,
                              &data->io_r);

          /* Set stream callbacks. */
          ssh_stream_set_callback(data->ctx->initiator_stream,
                                  ssh_appgw_ftp_data_stream_cb, data);
          ssh_stream_set_callback(data->ctx->responder_stream,
                                  ssh_appgw_ftp_data_stream_cb, data);
        }
      else
        {
          conn = ssh_calloc(1, sizeof(*conn));
          if (conn == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not allocate FTP control connection"));
              ssh_appgw_done(ctx);
              return;
            }

          /* Link control connection to gateway's list of active
             connections. */
          conn->next = ftp_ctx->connections;
          if (ftp_ctx->connections)
            ftp_ctx->connections->prev = conn;
          ftp_ctx->connections = conn;

          conn->ctx = ctx;
          conn->config = config;

          /* Link the connection object to the context's
             `user_context' field. */
          ctx->user_context = conn;

          /* As a default, the passive mode is off. */
          conn->passive = 0;

          ssh_stream_set_callback(conn->ctx->initiator_stream,
                                  ssh_appgw_ftp_stream_cb, conn);
          ssh_stream_set_callback(conn->ctx->responder_stream,
                                  ssh_appgw_ftp_stream_cb, conn);

          /* Start a thread to handle the FTP control connection. */
          ssh_fsm_thread_init(&ftp_ctx->fsm, &conn->thread,
                              ssh_appgw_ftp_st_read_reply, NULL_FNPTR,
                              ssh_appgw_ftp_thread_destructor, conn);
        }
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_FLOW_INVALID:
      {
	SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow invalid"));
	
	/* Fetch the connection object. */
	conn = (SshAppgwFtpConnection) (ctx->master ? 
					ctx->master->user_context :
					ctx->user_context);
	
	if (conn && conn->port_open)
	  {
	    ssh_fsm_set_next(&conn->thread, ssh_appgw_ftp_st_terminate);
	    ssh_fsm_continue(&conn->thread);
	  }
	break;
      }
    }
}

static void
ssh_appgw_ftp_check_shutdown(SshAppgwFtpCtx ctx)
{
  if (ctx->shutdown
      && ctx->connections == NULL
      && ctx->data_connections == NULL)
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway. */
    ssh_appgw_ftp_destroy(ctx);
}


static void
ssh_appgw_ftp_destroy_cb(void *context)
{
  SshAppgwFtpCtx ctx = (SshAppgwFtpCtx) context;

  ssh_fsm_uninit(&ctx->fsm);

  if (ctx->registered)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);
      ssh_appgw_unregister_local(ctx->pm,
                                 SSH_APPGW_FTP_IDENT,
                                 SSH_APPGW_FTP_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  /* Free all config data objects. */
  while (ctx->config_data)
    {
      SshAppgwFtpConfig c = ctx->config_data;

      ctx->config_data = c->next;
      ssh_appgw_ftp_config_destroy(c);
    }

  ssh_free(ctx);
}


static void
ssh_appgw_ftp_destroy(SshAppgwFtpCtx ctx)
{
  /* Register a zero-timeout to destroy the application gateway
     instance.  This is needed since this function is called also from
     thread destructors and the FSM library needs to access the FSM
     context that will be destroyed when the context is freed. */
  ssh_xregister_timeout(0, 0, ssh_appgw_ftp_destroy_cb, ctx);
}


static void
ssh_appgw_ftp_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwFtpCtx ctx = (SshAppgwFtpCtx) context;

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
      ssh_appgw_ftp_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  ctx->registered = 1;
}


void
ssh_appgw_ftp_init(SshPm pm)
{
  SshAppgwFtpCtx ctx;
  SshAppgwParamsStruct params;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not create application gateway: out of memory.",
                    SSH_APPGW_NAME);
      return;
    }
  ctx->pm = pm;
  ssh_fsm_init(&ctx->fsm, ctx);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_FTP_IDENT;
  params.printable_name = "File Transfer Protocol";
  params.version = SSH_APPGW_FTP_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;

  ssh_appgw_register_local(ctx->pm,
                           &params,
                           0,
                           ssh_appgw_ftp_conn_cb, ctx,
                           ssh_appgw_ftp_reg_cb, ctx);
}


/*********************** Handling configuration data ************************/

SshAppgwFtpConfig
ssh_appgw_ftp_config_create(void)
{
  SshAppgwFtpConfig config;

  config = ssh_calloc(1, sizeof(*config));

  return config;
}


void
ssh_appgw_ftp_config_destroy(SshAppgwFtpConfig config)
{
  if (config == NULL)
    return;

  ssh_free(config);
}


Boolean
ssh_appgw_ftp_config_disable_cmd(SshAppgwFtpConfig config, const char *command)
{
  SshUInt32 i;

  /* Check real FTP commands. */
  for (i = 0; ssh_appgw_ftp_commands[i].name; i++)
    if (strcmp(ssh_appgw_ftp_commands[i].name, command) == 0)
      {
        SSH_APPGW_FTP_DISABLE(config, ssh_appgw_ftp_commands[i].command);
        return TRUE;
      }

  /* Check for meta-commands. */
  if (strcmp(command, "ACTIVE") == 0)
    {
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_EPRT);
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_PORT);
    }
  else if (strcmp(command, "PASSIVE") == 0)
    {
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_EPSV);
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_PASV);
    }
  else if (strcmp(command, "UPLOAD") == 0)
    {
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_STOR);
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_STOU);
    }
  else if (strcmp(command, "DOWNLOAD") == 0)
    {
      SSH_APPGW_FTP_DISABLE(config, SSH_APPGW_FTP_CMD_RETR);
    }
  else
    {
      /* An unknown command. */
      return FALSE;
    }

  return TRUE;
}


void
ssh_appgw_ftp_config_content_filter(SshAppgwFtpConfig config,
                                    SshAppgwFtpContentFilterType filter)
{
  config->content_filter = filter;
}


void
ssh_appgw_ftp_config_set_flags(SshAppgwFtpConfig config, SshUInt32 flags)
{
  config->flags = flags;
}


unsigned char *
ssh_appgw_ftp_config_marshal(SshAppgwFtpConfig config, size_t *data_len_return)
{
  unsigned char *data;
  unsigned char disable_mask[SSH_APPGW_FTP_NUM_DISABLE_WORDS
                             * sizeof(SshUInt32)];
  SshUInt32 i;

  /* Encode disable mask. */
  for (i = 0; i < SSH_APPGW_FTP_NUM_DISABLE_WORDS; i++)
    SSH_PUT_32BIT(disable_mask + i * sizeof(SshUInt32),
                  config->disable_mask[i]);

  *data_len_return = ssh_encode_array_alloc(
                        &data,
                        SSH_FORMAT_UINT32, (SshUInt32) config->content_filter,
                        SSH_FORMAT_UINT32, config->flags,
                        SSH_FORMAT_DATA, disable_mask, sizeof(disable_mask),
                        SSH_FORMAT_END);
  if (*data_len_return == 0)
    /* Could not encode. */
    return NULL;

  return data;
}


SshAppgwFtpConfig
ssh_appgw_ftp_config_unmarshal(const unsigned char *data, size_t data_len)
{
  SshAppgwFtpConfig config;
  SshUInt32 content_filter;
  unsigned char disable_mask[SSH_APPGW_FTP_NUM_DISABLE_WORDS
                             * sizeof(SshUInt32)];
  SshUInt32 i;

  /* Allocate a config object. */
  config = ssh_calloc(1, sizeof(*config));
  if (config == NULL)
    goto error;

  if (data_len)
    {
      if (ssh_decode_array(data, data_len,
                           SSH_FORMAT_UINT32, &content_filter,
                           SSH_FORMAT_UINT32, &config->flags,
                           SSH_FORMAT_DATA, disable_mask, sizeof(disable_mask),
                           SSH_FORMAT_END) != data_len)
        goto error;

      /* Store configuration data. */

      config->content_filter = content_filter;

      for (i = 0; i < SSH_APPGW_FTP_NUM_DISABLE_WORDS; i++)
        config->disable_mask[i] = SSH_GET_32BIT(disable_mask
                                                + i * sizeof(SshUInt32));
    }

  /* All done. */
  return config;


  /* Error handling. */

 error:

  ssh_appgw_ftp_config_destroy(config);

  return NULL;
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
