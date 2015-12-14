/*
 *
 * appgw_http_internal.h
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Internal header for HTTP APPGW.
 *
 */

#ifndef SSH_APPGW_HTTP_INTERNAL_H

#define SSH_APPGW_HTTP_H 1

#define SSH_APPGW_NAME "HTTPALG"
#define SSH_APPGW_HTTP_NAME "HTTP Appgw"

/* Use 404, "Access Denied" makes many browsers ask for a user/password */
#define SSH_APPGW_HTTP_ERROR_CODE 404

/* Identification string. */
#define SSH_APPGW_HTTP_IDENT        "alg-http@ssh.com"

/* Version. */
#define SSH_APPGW_HTTP_VERSION      1

/* Size of I/O buffer for HTTP */
#define SSH_APPGW_HTTP_BUFSIZ 8192

/* Timeout for connections */
#define SSH_APPGW_HTTP_INACTIVE_TIMEOUT 120

typedef enum {
  SSH_APPGW_HTTP_TE_NONE = 0,
  SSH_APPGW_HTTP_TE_CHUNKED = 1
} SshAppgwHttpTransferEncoding;

typedef enum {
  SSH_APPGW_HTTP_HTTPV_NONE = 0,
  SSH_APPGW_HTTP_HTTPV_09 = 1,
  SSH_APPGW_HTTP_HTTPV_10 = 2,
  SSH_APPGW_HTTP_HTTPV_11 = 3,
  SSH_APPGW_HTTP_HTTPV_UNKNOWN = 128
} SshAppgwHttpVersion;

typedef enum {
  SSH_APPGW_HTTP_REQ_NONE = 0,
  SSH_APPGW_HTTP_REQ_CUT = 1,
  SSH_APPGW_HTTP_REQ_INJECT = 2,
  SSH_APPGW_HTTP_REQ_PASS = 3
} SshAppgwHttpRequestStatus;

/* HTTP Methods */

typedef enum {
  SSH_APPGW_HTTP_METHOD_NONE = 0,
  SSH_APPGW_HTTP_METHOD_OPTIONS = 1,
  SSH_APPGW_HTTP_METHOD_GET = 2,
  SSH_APPGW_HTTP_METHOD_HEAD = 3,
  SSH_APPGW_HTTP_METHOD_POST = 4,
  SSH_APPGW_HTTP_METHOD_PUT = 5,
  SSH_APPGW_HTTP_METHOD_DELETE = 6,
  SSH_APPGW_HTTP_METHOD_TRACE = 7,
  SSH_APPGW_HTTP_METHOD_CONNECT = 8
} SshAppgwHttpMethod;

/* A block action. This defines the reply to be sent */

struct SshAppgwHttpBlockActionRec
{
  /* Link to next */
  struct SshAppgwHttpBlockActionRec *next;

  /* Name of block */
  unsigned char *name;

  /* Reply code */
  int code;

  /* Content-Type of message */
  unsigned char *content_type;

  /* Additional headers */
  int header_len;
  unsigned char *header;

  /* Payload of message */
  int data_len;
  unsigned char *data;
};

typedef struct SshAppgwHttpBlockActionRec SshAppgwHttpBlockActionStruct;

struct SshAppgwHttpMatchClauseRec
{
  /* Name of clause */
  unsigned char *name;

  /* These regexes match the lines in the header */
  SshRegexMatcher hdr_regex;
  unsigned char *hdr_regex_str;

  /* The recipient host by name */
  unsigned char *host;

  /* Minimum length of URL */
  int min_url_length;
};

typedef struct SshAppgwHttpMatchClauseRec SshAppgwHttpMatchClauseStruct;

struct SshAppgwHttpRuleRec
{
  struct SshAppgwHttpRuleRec *next;

  int precedence;

  unsigned char *name;
  int nclauses;
  SshAppgwHttpMatchClause *clauses;

  SshAppgwHttpRuleAction action;
  SshAppgwHttpBlockAction block;
};

typedef struct SshAppgwHttpRuleRec SshAppgwHttpRuleStruct;

struct SshAppgwHttpReplyActionRec
{
  /* Pointer to next entry in chain */
  struct SshAppgwHttpReplyActionRec *next;
  int msg_number;
  SshAppgwHttpRequestStatus status;

  unsigned int close_after_action:1;
  SshAppgwHttpVersion http_version;

  char *buf;
  size_t bufsize;
  size_t data_in_buf;
  size_t offset;
};

typedef struct SshAppgwHttpReplyActionRec *SshAppgwHttpReplyAction;
typedef struct SshAppgwHttpReplyActionRec SshAppgwHttpReplyActionStruct;

struct SshAppgwHttpRequestMethodRec
{
  /* Pointer to next entry in chain */
  struct SshAppgwHttpRequestMethodRec *next;

  /* Message this refers to */
  int msg_number;

  /* HTTP method of the request */
  SshAppgwHttpMethod method;
};

typedef struct SshAppgwHttpRequestMethodRec *SshAppgwHttpRequestMethod;
typedef struct SshAppgwHttpRequestMethodRec SshAppgwHttpRequestMethodStruct;

/* The state of a HTTP connection is stored throughout the entire Appgw
   instance. This is done to keep the memory usage to a minimum. It
   does unfortunately result in some complexity in manipulating
   or accessing the state.

   A SshAppgwHttpState instances state_i and state_r hold state which
   is common to both the I->R and R->I streams.

   The SshAppgwHttpIO io_i and io_r instances hold the actual buffers
   containing the HTTP requests and responses.

   The SshAppgwHttpRequestState instance req_i holds state which is
   relevant only to HTTP requests.

   The SshAppgwHttpReplyState reply_r holds state which is relevant
   only to HTTP responses.

   The SshAppgwHttpConn holds state relevant to the whole connection. */

struct SshAppgwHttpStateRec
{
  /* Parser state */

  unsigned int reading_hdr : 1;
  unsigned int reading_body : 1;
  unsigned int ignore_body : 1;
  unsigned int reading_chunk_hdr : 1;
  unsigned int reading_chunk_data_end : 1;
  unsigned int reading_chunk_trailer :1;

  /* Status of current connection */

  unsigned int message_body_present : 1;
  unsigned int initial_line_read : 1;
  unsigned int non_persistent_connection:1;
  unsigned int body_length_valid:1;
  unsigned int nmsgs;
  unsigned int flush_buf: 1; /* Signal to flush buffer */

  size_t       body_length;
  size_t       body_read;

  SshAppgwHttpTransferEncoding transfer_encoding;
  SshAppgwHttpVersion http_version;
};

typedef struct SshAppgwHttpStateRec SshAppgwHttpStateStruct;
typedef struct SshAppgwHttpStateRec *SshAppgwHttpState;

struct SshAppgwHttpRequestStateRec
{
  /* Current Request Information */
  SshAppgwHttpMethod current_method;

  unsigned int request_line_valid;
  int host_line_index;
};

typedef struct SshAppgwHttpRequestStateRec SshAppgwHttpRequestStateStruct;
typedef struct SshAppgwHttpRequestStateRec *SshAppgwHttpRequestState;

struct SshAppgwHttpReplyStateRec
{
  SshAppgwHttpReplyAction actions;
  SshAppgwHttpRequestMethod methods;
  SshAppgwHttpMethod current_method;
  int return_code;
};

typedef struct SshAppgwHttpReplyStateRec SshAppgwHttpReplyStateStruct;
typedef struct SshAppgwHttpReplyStateRec *SshAppgwHttpReplyState;

/* An I/O structure for unidirectional communication. */
struct SshAppgwHttpIORec
{
  /* Flags. */
  unsigned int active : 1;      /* Thread active. */
  unsigned int terminate : 1;   /* Terminate when already read data
                                   has been flushed. */

  /* Source stream. */
  SshStream src;

  /* Destination stream. */
  SshStream dst;

  /* Buffer for data being copied. */
  unsigned char buf[SSH_APPGW_HTTP_BUFSIZ];
  size_t offset_in_buf;
  size_t data_in_buf;
  size_t bufpos;

  /* Pointer to the connection structure. */
  struct SshAppgwHttpConnRec *conn;
  struct SshAppgwHttpStateRec *state;
};

typedef struct SshAppgwHttpIORec SshAppgwHttpIOStruct;
typedef struct SshAppgwHttpIORec *SshAppgwHttpIO;

/* A TCP connection through the gateway. */
struct SshAppgwHttpConnRec
{
  /* Service id for connection */
  int service_id;

  /* Link fields for list of active connections. */
  struct SshAppgwHttpConnRec *next;
  struct SshAppgwHttpConnRec *prev;

  /* Flags. */
  unsigned int teardown : 1; /* Tear the connection */
  unsigned int inactive : 1; /* Has the connection been inactive? */

  /* The application gateway context. */
  SshAppgwContext ctx;
  struct SshAppgwHttpCtxRec *http_ctx;

  /* Thread handling the initiator->responder communication. */
  SshFSMThreadStruct thread_i;
  SshAppgwHttpIOStruct io_i;
  SshAppgwHttpStateStruct state_i;
  SshAppgwHttpRequestStateStruct req_i;

  /* Thread handling the responder->initiator communication. */
  SshAppgwHttpStateStruct state_r;
  SshFSMThreadStruct thread_r;
  SshAppgwHttpIOStruct io_r;
  SshAppgwHttpReplyStateStruct reply_r;
};

typedef struct SshAppgwHttpConnRec SshAppgwHttpConnStruct;
typedef struct SshAppgwHttpConnRec *SshAppgwHttpConn;

struct SshAppgwHttpConfigRec
{
  /* Next configuration */
  struct SshAppgwHttpConfigRec *next;

  /* Service_id we are associated with */
  int service_id;
  char *service_name;

  /* TCP Redirect */
  SshIpAddrStruct tcp_dst;
  SshUInt16 tcp_port;

  /* Array of pointers to SshAppgwHttpClauseStruct's */
  int nclauses;
  SshAppgwHttpMatchClause *clauses;

  /* Linked list of blocks */
  SshAppgwHttpBlockAction blocks;

  /* Linked list of rules */
  SshAppgwHttpRule rules;

  /* sshregex library context */
  SshRegexContext regex_ctx;
};

typedef struct SshAppgwHttpConfigRec SshAppgwHttpConfigStruct;


/* Context data for TCP pass-through gateways. */
struct SshAppgwHttpCtxRec
{
  /* Global conn id */
  int conn_id;

  /* Policy manager. */
  SshPm pm;

  /* FSM controlling the gateway. */
  SshFSMStruct fsm;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */
  unsigned int shutdown : 1;    /* The system is shutting down. */

  /* Active TCP connections through this gateway. */
  SshAppgwHttpConn connections;

  /* Configurations */
  SshAppgwHttpConfig configs;
};

typedef struct SshAppgwHttpCtxRec SshAppgwHttpCtxStruct;
typedef struct SshAppgwHttpCtxRec *SshAppgwHttpCtx;

/* Prototypes for internal functions */

void
ssh_appgw_http_free_clause(SshAppgwHttpMatchClause clause);

SshAppgwHttpMatchClause
ssh_appgw_http_find_clause(SshAppgwHttpConfig config,
                           const unsigned char *clause_name);


/********************* Prototypes for appgw_http.c ********************/

SshAppgwHttpConfig
ssh_appgw_http_get_config(const SshAppgwHttpCtx http_ctx,int service_id);

const char*
ssh_appgw_get_service_name(const SshAppgwHttpConn con);

/********************* Prototypes for appgw_http_state.c **************/

void
ssh_appgw_http_replyaction_free(SshAppgwHttpReplyAction act);

void
ssh_appgw_http_handle_state(SshAppgwHttpIO io,
                            SshAppgwHttpConn con,
                            SshAppgwHttpState state);

Boolean
ssh_appgw_http_is_inject(SshAppgwHttpIO io,
                         SshAppgwHttpConn con,
                         SshAppgwHttpState state);

void
ssh_appgw_msg_begin(SshAppgwHttpConn con,
                    SshAppgwHttpState state);

void
ssh_appgw_hdr_reset_state(SshAppgwHttpState state);

#endif /* SSH_APPGW_HTTP_INTERNAL_H */
