/*
 *
 * t-l2tp.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test program for L2TP library.
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"
#include "sshcrypt.h"
#include "sshl2tp.h"
#include "sshnameserver.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "t-l2tp"

#define RESPONDER_PORT "1702"

#define FAILURE(msg)                                    \
do                                                      \
  {                                                     \
    fprintf(stderr, "%s: %s\n", test->name, (msg));     \
    failures++;                                         \
  }                                                     \
while (0)

/* Responder tunnel request actions. */
typedef enum
{
  SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
  SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT
} SshL2tpTestResponderTunnelRequest;

/* Responder session request actions. */
typedef enum
{
  SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
  SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
  SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT
} SshL2tpTestResponderSessionRequest;

/* Responder session actions. */
typedef enum
{
  SSH_L2TP_T_R_SESSION_NOTREACHED,
  SSH_L2TP_T_R_SESSION_CLOSE
} SshL2tpTestResponderSession;

/* Initiator actions. */
typedef enum
{
  SSH_L2TP_T_I_SESSION
} SshL2tpTestInitiatorCase;

/* A test case. */
struct SshL2tpTestCaseRec
{
  char *name;

  /* Responder. */
  SshL2tpTestResponderTunnelRequest r_tunnel_req;
  SshL2tpTestResponderSessionRequest r_session_req;
  SshL2tpTestResponderSession r_session;

  SshL2tpTunnelResultCode r_result;
  SshL2tpErrorCode r_error;
  unsigned char *r_error_message;
  size_t r_error_message_len;

  SshUInt16 q931_cause_code;
  SshUInt8 q931_cause_msg;
  unsigned char *q931_advisory_message;
  size_t q931_advisory_message_len;

  /* Initiator. */
  Boolean lac;
  SshL2tpTestInitiatorCase initiator;
};

typedef struct SshL2tpTestCaseRec SshL2tpTestCaseStruct;
typedef struct SshL2tpTestCaseRec *SshL2tpTestCase;

/* The test cases. */
static SshL2tpTestCaseStruct tests[] =
{
  {"CCE responder reject",
   SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   0, 0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"CCE responder reject with status",
   SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED,
   0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"CCE responder reject with error",
   SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_TUNNEL_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"CCE responder reject with status, error, and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_TUNNEL_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   (unsigned char *) "Insufficient resources", 22,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"CCE responder reject with status and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED,
   0,
   (unsigned char *) "Unauthorized, really", 22,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder reject",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   0, 0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder reject with status",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder reject with error",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_SESSION_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder reject with status, error, and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_SESSION_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   "Out of phone lines", 18,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder reject with status and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_REJECT,
   SSH_L2TP_T_R_SESSION_NOTREACHED,

   SSH_L2TP_SESSION_RESULT_PERMANENTLY_UNAVAILABLE,
   0,
   "Really, no phone lines", 22,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   0, 0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with error",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   NULL, 0,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status, error, and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_ERROR,
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
   "No lines left", 13,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status and message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0,
   "Really, no lines left", 21,
   0, 0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status and Q.931 cause code",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,

   /* Q.931 cause code, cause message, advisory message */
   42,
   0, NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status and Q.931 cause code and cause message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,

   /* Q.931 cause code, cause message, advisory message */
   42, 7,
   NULL, 0,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status and Q.931 cause code and advisory message",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,

   /* Q.931 cause code, cause message, advisory message */
   42, 0,
   "Q.931 advisory message", 22,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  {"IC responder close with status and full Q.931 cause code",
   SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT,
   SSH_L2TP_T_R_SESSION_CLOSE,

   SSH_L2TP_SESSION_RESULT_BUSY,
   0, NULL, 0,

   /* Q.931 cause code, cause message, advisory message */
   42, 7,
   "Another Q.931 advisory message", 30,

   TRUE,
   SSH_L2TP_T_I_SESSION},

  /* TODO:
     - WEN
     - SLI
     - outgoing call:
       - different failures
       - passing attributes in outgoing call completion */

  {0},
};

/* The current test case. */
static int test_number = 0;
static SshL2tpTestCase test = NULL;

/* The number of failures. */
static SshUInt32 failures = 0;

/* The name of the program. */
static char *program = NULL;

static SshL2tpParamsStruct responder_params = {0};
static SshL2tp responder = NULL;
static SshL2tpServer responder_server = NULL;

static SshL2tpParamsStruct initiator_params = {0};
static SshL2tp initiator = NULL;
static SshL2tpServer initiator_server = NULL;


/********************* Prototypes for static functions **********************/

/* Run the next test or shutdown the system if all tests have been
   executed. */
static void run_test(void);


/******************************** Responder *********************************/

static SshOperationHandle
r_tunnel_request(SshL2tpTunnelInfo info,
                 SshL2tpTunnelRequestCompletionCB completion_cb,
                 void *completion_cb_context,
                 void *callback_context)
{
  SSH_ASSERT(test != NULL);

  switch (test->r_tunnel_req)
    {
    case SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT:
      (*completion_cb)(FALSE, NULL, 0, NULL,
                       test->r_result, test->r_error,
                       test->r_error_message, test->r_error_message_len,
                       completion_cb_context);
      break;

    case SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT:
      (*completion_cb)(TRUE, NULL, 0, NULL, 0, 0, NULL, 0,
                       completion_cb_context);
      break;
    }

  return NULL;
}


static void
r_tunnel_status(SshL2tpTunnelInfo info, SshL2tpTunnelStatus status,
                void *callback_context)
{
  SshL2tpTestCase t_test = (SshL2tpTestCase) info->upper_level_data;

  switch (status)
    {
    case SSH_L2TP_TUNNEL_OPEN_FAILED:
      if (test->r_tunnel_req != SSH_L2TP_T_R_TUNNEL_REQUEST_REJECT)
        FAILURE("R: SshL2tpTunnelStatusCB: FAILED reached");
      break;

    case SSH_L2TP_TUNNEL_OPENED:
      if (test->r_tunnel_req != SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT)
        FAILURE("R: SshL2tpTunnelStatusCB: OPENED reached");

      info->upper_level_data = test;
      break;

    case SSH_L2TP_TUNNEL_TERMINATED:
      if (t_test == NULL)
        {
          FAILURE("R: tunnel upper_level_data unset");
        }
      else
        {
          if (t_test->r_tunnel_req != SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT)
            FAILURE("R: SshL2tpTunnelStatusCB reached ");
        }
      break;
    }
}


static SshOperationHandle
r_session_request(SshL2tpSessionInfo info,
                  SshL2tpSessionRequestCompletionCB completion_cb,
                  void *completion_cb_context,
                  void *callback_context)
{
  switch (test->r_session_req)
    {
    case SSH_L2TP_T_R_SESSION_REQUEST_NOTREACHED:
      FAILURE("R: SshL2tpSessionRequestCB reached");
      (*completion_cb)(FALSE, 0, 0, NULL, 0, completion_cb_context);
      break;

    case SSH_L2TP_T_R_SESSION_REQUEST_REJECT:
      (*completion_cb)(FALSE,
                       test->r_result, test->r_error,
                       test->r_error_message, test->r_error_message_len,
                       completion_cb_context);
      break;

    case SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT:
      (*completion_cb)(TRUE, 0, 0, NULL, 0, completion_cb_context);
      break;
    }

  return NULL;
}


static void
r_session_status(SshL2tpSessionInfo info, SshL2tpSessionStatus status,
                 void *callback_context)
{
  SshL2tpTestCase s_test = (SshL2tpTestCase) info->upper_level_data;

  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      if (test->r_session != SSH_L2TP_T_R_SESSION_NOTREACHED)
        {
          FAILURE("R: SshL2tpSessionStatusCB called with "
                  "SSH_L2TP_SESSION_OPEN_FAILED");
          return;
        }
      break;

    case SSH_L2TP_SESSION_OPENED:
      if (test->r_session_req != SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT)
        FAILURE("R: SshL2tpSessionStatusCB reached with "
                "SSH_L2TP_SESSION_OPENED");

      info->upper_level_data = test;





      switch (test->r_session)
        {
        case SSH_L2TP_T_R_SESSION_NOTREACHED:
          SSH_NOTREACHED;
          break;

        case SSH_L2TP_T_R_SESSION_CLOSE:
          ssh_l2tp_session_close(responder, info->tunnel->local_id,
                                 info->local_id,
                                 test->r_result, test->r_error,
                                 test->r_error_message,
                                 test->r_error_message_len,
                                 test->q931_cause_code,
                                 test->q931_cause_msg,
                                 test->q931_advisory_message,
                                 test->q931_advisory_message_len);
          break;
        }
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      if (s_test == NULL)
        {
          FAILURE("R: session upper_level_data unset");
        }
      break;

    case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
      break;

    case SSH_L2TP_SESSION_SET_LINK_INFO:
      break;
    }
}


static SshOperationHandle
r_lac_outgoing_call(SshL2tpSessionInfo info,
                    SshL2tpLacOutgoingCallCompletionCB completion_cb,
                    void *completion_cb_context,
                    void *callback_context)
{



  SSH_NOTREACHED;

  return NULL;
}


/******************************** Initiator *********************************/

/* No tunnel request callback. */

static void
i_tunnel_status(SshL2tpTunnelInfo info, SshL2tpTunnelStatus status,
                void *callback_context)
{
}

/* No session request callback. */

static void
i_session_status(SshL2tpSessionInfo info, SshL2tpSessionStatus status,
                 void *callback_context)
{
  /* Check the result. */
  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      if (test->r_tunnel_req == SSH_L2TP_T_R_TUNNEL_REQUEST_ACCEPT)
        {
          if (test->r_session_req == SSH_L2TP_T_R_SESSION_REQUEST_ACCEPT)
            {
              FAILURE("I: session open failed");
            }
          else if (info == NULL)
            {
              FAILURE("I: no info");
            }
          else
            {
              /* Rejected as expected. */
              if (test->r_result)
                {
                  /* Rejected for a specific reason. */
                  if (info->result_code != test->r_result
                      || info->error_code != test->r_error
                      || (info->error_message_len != test->r_error_message_len)
                      || memcmp(info->error_message, test->r_error_message,
                                test->r_error_message_len) != 0)
                    FAILURE("I: received wrong session termination "
                            "result code");
                }
              else
                {
                  /* Rejected for the default administrative reason. */
                  if ((info->result_code
                       != SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE)
                      || info->error_code != 0
                      || info->error_message != NULL
                      || info->error_message_len != 0)
                    {
                      FAILURE("I: received wrong default session termination "
                              "result code");
                    }
                }
            }
        }
      else
        {
          SshL2tpTunnelInfo tinfo;

          if (info == NULL)
            {
              FAILURE("I: no info");
            }
          else
            {
              /* Rejected as expected. */
              tinfo = info->tunnel;
              if (test->r_result)
                {
                  /* Rejected for a specific reason. */
                  if (tinfo->result_code != test->r_result
                      || tinfo->error_code != test->r_error
                      || (tinfo->error_message_len
                          != test->r_error_message_len)
                      || memcmp(tinfo->error_message, test->r_error_message,
                                test->r_error_message_len) != 0)
                    FAILURE("I: received wrong tunnel termination "
                            "result code");
                }
              else
                {
                  /* Rejected for the default unauthorized reason. */
                  if (tinfo->result_code != SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED
                      || tinfo->error_code != 0
                      || tinfo->error_message != NULL
                      || tinfo->error_message_len != 0)
                    {
                      FAILURE("I: received wrong default tunnel termination "
                              "result code");
                    }
                }
            }
        }

      /* And run the next test. */
      run_test();
      break;

    case SSH_L2TP_SESSION_OPENED:
      switch (test->initiator)
        {
        case SSH_L2TP_T_I_SESSION:
          return;
          break;
        }
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      if (test->r_result)
        {
          /* Terminated for a specific reason. */
          if (info->result_code != test->r_result
              || info->error_code != test->r_error
              || (info->error_message_len != test->r_error_message_len)
              || memcmp(info->error_message, test->r_error_message,
                        test->r_error_message_len) != 0)
            FAILURE("I: received wrong session termination result code");
        }
      else
        {
          /* Terminated for the administrative reason. */
          if (info->result_code != SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE
              || info->error_code != 0
              || info->error_message != NULL
              || info->error_message_len != 0)
            {
              FAILURE("I: received wrong default session termination "
                      "result code");
            }
        }

      /* Check Q.931 cause codes. */
      if (info->q931_cause_code != test->q931_cause_code
          || info->q931_cause_msg != test->q931_cause_msg
          || info->q931_advisory_message_len != test->q931_advisory_message_len
          || (info->q931_advisory_message && !test->q931_advisory_message)
          || (!info->q931_advisory_message && test->q931_advisory_message)
          || (test->q931_advisory_message
              && memcmp(info->q931_advisory_message,
                        test->q931_advisory_message,
                        test->q931_advisory_message_len) != 0))
        {
          FAILURE("I: received wrong Q.931 cause code");
        }

      /* Run the next test. */
      run_test();
      break;

    case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
      break;

    case SSH_L2TP_SESSION_SET_LINK_INFO:
      break;
    }
}

/* No LAC outgoing call callback. */


/****************************** Running tests *******************************/

static void
run_test()
{
  test = &tests[test_number++];

  if (test->name == NULL)
    {
      /* All done. */
      printf("%s: All tests run: #failures=%lu\n",
             program, (unsigned long ) failures);

      ssh_l2tp_destroy(responder, NULL, NULL);
      responder = NULL;
      responder_server = NULL;

      ssh_l2tp_destroy(initiator, NULL, NULL);
      initiator = NULL;
      initiator_server = NULL;

      return;
    }

  printf("%s: Running test `%s'\n", program, test->name);

  switch (test->initiator)
    {
    case SSH_L2TP_T_I_SESSION:
      if (test->lac)
        ssh_l2tp_lac_session_open(initiator, initiator_server, 0,
                                  "127.0.0.1", RESPONDER_PORT,
                                  NULL, 0, NULL,
                                  i_session_status, NULL);
      else
        ssh_l2tp_lac_session_open(initiator, initiator_server, 0,
                                  "127.0.0.1", RESPONDER_PORT,
                                  NULL, 0, NULL,
                                  i_session_status, NULL);
      break;
    }
}


int
main(int argc, char *argv[])
{
  int opt;
  int exit_value = 1;

  ssh_global_init();
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
      ssh_warning("Could not initialize the crypto library.");
      exit(1);
    }

  /* Resolve program name. */
  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  while ((opt = ssh_getopt(argc, argv, "0D:", NULL)) != EOF)
    {
      switch (opt)
        {
        case '0':
          exit_value = 0;
          break;

        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        }
    }

  ssh_event_loop_initialize();

  /* Create responder. */

  responder = ssh_l2tp_create(&responder_params,
                              r_tunnel_request, r_tunnel_status,
                              r_session_request, r_session_status,
                              r_lac_outgoing_call,
                              NULL);
  if (responder == NULL)
    {
      fprintf(stderr, "%s: could not create L2TP responder\n", program);
      exit(exit_value);
    }

  /* Start responder server. */
  responder_server = ssh_l2tp_server_start(responder, "127.0.0.1",
                                           RESPONDER_PORT);
  if (responder_server == NULL)
    {
      fprintf(stderr, "%s: could not start L2TP responder server\n", program);
      exit(exit_value);
    }

  /* Create initiator. */
  initiator = ssh_l2tp_create(&initiator_params,
                              NULL, i_tunnel_status,
                              NULL, i_session_status,
                              NULL, NULL);
  if (initiator == NULL)
    {
      fprintf(stderr, "%s: could not create L2TP initiator\n", program);
      exit(exit_value);
    }

  /* Start initiator server. */
  initiator_server = ssh_l2tp_server_start(initiator, "127.0.0.1", NULL);
  if (initiator_server == NULL)
    {
      fprintf(stderr, "%s: could not start L2TP initiator server\n", program);
      exit(exit_value);
    }

  /* Start running tests. */
  run_test();

  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  if (responder)
    ssh_l2tp_destroy(responder, NULL, NULL);
  if (initiator)
    ssh_l2tp_destroy(initiator, NULL, NULL);

  ssh_crypto_library_uninitialize();

  ssh_util_uninit();
  if (exit_value)
    return failures;

  return 0;
}
