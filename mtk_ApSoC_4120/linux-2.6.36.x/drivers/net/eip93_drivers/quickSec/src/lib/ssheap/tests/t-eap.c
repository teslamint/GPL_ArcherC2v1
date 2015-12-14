/*
  t-eap.c

  Copyright:
          Copyright (c) 2002-2007 SFNT Finland Oy.
  All Rights Reserved.
*/

#include <stdio.h>
#include "sshincludes.h"
#include "sshbuffer.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshnameserver.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshlocalstream.h"
#include "ssheap.h"
#include "t-eap.h"
#include "t-eap-files.h"

#define SSH_DEBUG_MODULE "SshTEap"

Boolean global_error_seen = FALSE;

#ifdef WIN32
HANDLE exit_notify_thread;
SHELLEXECUTEINFO t_eap = {0};
#endif /* WIN32 */


SSH_FSM_STEP(eap_start);
SSH_FSM_STEP(eap_loop);

typedef struct SshTEapRec
{
  SshLocalListener listener;

  SshEap eap;
  SshEapConfiguration config;
#ifdef SSHDIST_RADIUS
  SshEapRadiusConfigurationStruct radius_config;
#endif /* SSHDIST_RADIUS */
  SshEapConnection connection;

  /* Stream for sending/receiving EAP packets. */
  SshStream stream;

  /* Data fields used for parsing EAP buffers from the stream. */  
  int input_state;
  SshUInt8 input_len_buf[4];
  size_t input_buflen;
  size_t input_len;
  unsigned char *input_buf;

  unsigned char *output_buf;
  size_t output_len;
  size_t output_written;

  SshEapTestParamsStruct params;
  SshEapTestConfigCB config_handler;
  SshEapTestTokenCB token_handler;
  SshEapTestDestroyCB destroy_handler;
  void *user_context;

  /* FSM */
  SshFSM fsm;
  SshFSMThread thread;
  SshFSMConditionStruct condition;
  
  Boolean auth_timeout;   /* Test has timed out  */
  Boolean completed;      /* Test has finished. */
  Boolean in_error;       /* In error state. */
} *SshTEap;

static void test_halt(void *ctx)
{
  SshTEap t = (SshTEap)ctx;
  
  SSH_DEBUG(SSH_D_HIGHOK, 
	    ("Halting test program (client=%d)", t->params.client));

  t->completed = TRUE;
  ssh_fsm_condition_signal(t->fsm, &t->condition);
}

/* A dummy timeout used to prevent the event loop from exiting before the
   FSM thread finishes. */
static void dummy_timeout(void *ctx)
{
  ssh_xregister_timeout(1, 0, dummy_timeout, NULL);
}


SSH_FSM_STEP(eap_start)
{
  SshTEap t;

  t = ssh_fsm_get_tdata(thread);

  if (t->in_error) return SSH_FSM_FINISH;

  if (t->stream == NULL)
    SSH_FSM_CONDITION_WAIT(&t->condition);

  ssh_xregister_timeout(0, 0, dummy_timeout, NULL);

  SSH_FSM_SET_NEXT(eap_loop);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(eap_loop)
{
  SshTEap t;

  t = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("entering fsm loop"));

  if (t->auth_timeout == TRUE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("In auth timeout, move to FSM finish"));
      return SSH_FSM_FINISH;
    }

  if (t->in_error)
    {
      SSH_DEBUG(SSH_D_HIGHOK,("In error, ending fsm loop"));
      return SSH_FSM_FINISH;
    }

  if (t->completed)
    {
      SSH_DEBUG(SSH_D_HIGHOK,("Test completed, ending fsm loop"));
      return SSH_FSM_FINISH;
    }

  /* Wait until the condition is signalled */
  SSH_DEBUG(SSH_D_HIGHOK,("Waiting for an event..."));
  SSH_FSM_CONDITION_WAIT(&t->condition);
}

typedef struct TestEapSignalCtxRec {
  SshTEap t;
  SshUInt8 type;
  SshEapSignal signal;
  SshBuffer buf;
} *TestEapSignalCtx;

void handle_signal(void *context);

void eap_authenticate(void *context)
{
  SshTEap t = (SshTEap)context;

  ssh_eap_authenticate(t->eap, SSH_EAP_AUTH_CONTINUE);
}

static void eap_signal_cb(SshEap eap,
			  SshUInt8 type,
			  SshEapSignal signal,
			  SshBuffer buf,
			  void *ctx)
{
  TestEapSignalCtx context = ssh_xcalloc(1, sizeof(*context));
  SshTEap t = (SshTEap)ctx;

  context->t = t;
  context->type = type;
  context->signal = signal;

  if (buf != NULL)
    {
      context->buf = ssh_xbuffer_allocate();
      
      ssh_xbuffer_append(context->buf, 
			 ssh_buffer_ptr(buf),
			 ssh_buffer_len(buf));
    }      

  handle_signal(context);
}

 
void handle_signal(void *context)
{
  TestEapSignalCtx ctx = context;
  SshTEap t = ctx->t;
  SshUInt8 type = ctx->type;
  SshEapSignal signal = ctx->signal;
  SshBuffer buf = ctx->buf;
  SshEapTokenStruct token;
  unsigned char *key;
  size_t keylen;

  SSH_DEBUG(SSH_D_MIDOK,
             ("received signal %d type %d buf %s",
             signal, type, (buf == NULL ? "<no>" : "<yes>")));

  if (signal == SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT)
    t->auth_timeout = TRUE;
		    

  switch (signal)
    {
    case SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME:
    case SSH_EAP_SIGNAL_AUTH_FAIL_REPLY:
    case SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION:
    case SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR:
    case SSH_EAP_SIGNAL_FATAL_ERROR:
    case SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT: 
      
      SSH_DEBUG(SSH_D_ERROR, ("authentication failed"));
      global_error_seen = TRUE;
      test_halt(t);
      break;

    case SSH_EAP_SIGNAL_IDENTITY:
      if (t->params.client == FALSE)
        {
          if (buf != NULL)
            {
              SshUInt8 *strbuf = ssh_xmalloc(ssh_buffer_len(buf) + 1);

              strncpy(strbuf, ssh_buffer_ptr(buf), ssh_buffer_len(buf));
              strbuf[ssh_buffer_len(buf)] = '\0';

              SSH_DEBUG(SSH_D_MIDOK,("received id: %s",strbuf));
              ssh_xfree(strbuf);
            }

#ifdef SSHDIST_RADIUS
          if (t->radius_config.radius_client != NULL)
            ssh_eap_radius_attach(t->eap, &t->radius_config);
#endif /* SSHDIST_RADIUS */
	  ssh_xregister_timeout(0, 0, eap_authenticate, t);
        }
      else
        {
          SSH_NOTREACHED;
        }
      break;

    case SSH_EAP_SIGNAL_NEED_TOKEN:
      SSH_ASSERT(buf != NULL);

      t->token_handler(t->eap, type, buf, &token, t->user_context);
      break;

    case SSH_EAP_SIGNAL_AUTH_OK_USERNAME:
      SSH_DEBUG(SSH_D_HIGHOK,("username authentication ok"));
      test_halt(t);
      break;

    case SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK:
    case SSH_EAP_SIGNAL_AUTH_PEER_OK: 
      SSH_DEBUG(SSH_D_HIGHOK,("authentication ok"));
      ssh_eap_master_session_key(t->eap, &key, &keylen, NULL, NULL);

      if (key)
	{
	  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Derived session key"),
			    key, keylen);
	  ssh_free(key);
	}
      else
	SSH_DEBUG(SSH_D_HIGHOK,("No session key derived"));

      test_halt(t);
      break;

    default:
      break;
    }

  if (ctx->buf)
    ssh_buffer_free(ctx->buf);
  ssh_xfree(ctx);
}



/* Very simple reader from SshStream */
static void read_stream_input(SshTEap t)
{
  unsigned char dummy[1];
  int bytes_read;

  if (t->stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Stream not initialized cannot read input"));
      return;
    }
 again:

  /* The first four bytes encode the length of the EAP packet. */
  switch (t->input_state)
    {
    case 0:
    case 1:
    case 2:
    case 3:
      bytes_read = ssh_stream_read(t->stream,
				   t->input_len_buf + t->input_state,
				   4 - t->input_state);

      if (bytes_read > 0)
        {
          t->input_state += bytes_read;
        }

    if (bytes_read == 0)
      {
        SSH_DEBUG(SSH_D_MIDOK, ("Received EOF from stream"));
        t->completed = TRUE;
	ssh_fsm_condition_signal(t->fsm, &t->condition);
	return;
      }

    if (bytes_read < 0)
      {
        SSH_DEBUG(SSH_D_FAIL, ("Read %d bytes from stream", bytes_read));
	return;
      }

    /* Keep reading until failure or a full EAP packet is received. */
    if (t->input_state < 4)
      goto again;

  default:

    if (t->input_buf == NULL)
      {
        t->input_buflen = 
	  (t->input_len_buf[0] << 24) | 
	  (t->input_len_buf[1] << 16) |
          (t->input_len_buf[2] << 8)  | 
	  t->input_len_buf[3];

        t->input_buf = ssh_xmalloc(t->input_buflen);
        t->input_len = 0;
      }

    bytes_read = ssh_stream_read(t->stream,
				 t->input_buf + t->input_len,
				 t->input_buflen - t->input_len);
    if (bytes_read > 0)
      {
        t->input_len += bytes_read;
      }

    if (bytes_read == 0)
      {
        SSH_DEBUG(SSH_D_MIDOK, ("received EOF from stream"));

        t->completed = TRUE;
	ssh_fsm_condition_signal(t->fsm, &t->condition);
	return;
      }

    if (bytes_read < 0)
      return;

    if (t->input_len == t->input_buflen)
      {
        /* Houston, we have a message */
        SshBuffer buf;

	/* Read again to trigger failure so that the stream callback 
	   will be called again when the next EAP packet is received. 
	   SshStreamCallback will not be called for the 
	   SSH_STREAM_INPUT_AVAILABLE notification type unless a previous 
	   call failed. */
	bytes_read = ssh_stream_read(t->stream, dummy, sizeof(dummy));
	SSH_ASSERT(bytes_read <= 0);	
	
        buf = ssh_xbuffer_allocate();
        ssh_xbuffer_append(buf, t->input_buf, t->input_buflen);

        SSH_TRACE_HEXDUMP(SSH_D_LOWOK,
                          ("EAP input packet: length %d bytes",
			   ssh_buffer_len(buf)),
                          ssh_buffer_ptr(buf),
			  ssh_buffer_len(buf));


        ssh_eap_connection_input_packet(t->connection, buf);

        ssh_buffer_free(buf);
        ssh_xfree(t->input_buf);


	/* Clear the fields used for EAP packet parsing. */
        t->input_buf = NULL;
        t->input_state = 0;
        t->input_buflen = 0;
        t->input_len = 0;
	memset(t->input_len_buf, 0, sizeof(t->input_len_buf));
	return;
      }

    /* Keep reading until failure or a full EAP packet is received. */
    goto again;
    break;
    }
}

void write_stream_output(SshTEap t)
{
  int bytes_written;

  if (t->stream == NULL)
    return;

  if (t->output_len != 0)
    {
      SSH_ASSERT(t->output_written < t->output_len);
      
      bytes_written = ssh_stream_write(t->stream, 
				       t->output_buf + t->output_written, 
				       t->output_len - t->output_written);

      if (bytes_written < 0)
	return;
      
      if (bytes_written == 0)
	{
	  SSH_DEBUG(SSH_D_MIDOK, ("Received EOF from stream"));
	  t->completed = TRUE;
	  ssh_fsm_condition_signal(t->fsm, &t->condition);
	  return;
	}

      t->output_written += bytes_written;
      
      if (t->output_written == t->output_len)
	{
	  t->output_len = 0;
	  t->output_written = 0;
	  ssh_xfree(t->output_buf);
	  t->output_buf = NULL;
	}
    }
}

static void
test_stream_cb(SshStreamNotification notification, void *ctx)
{
  SshTEap t = (SshTEap)ctx;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      SSH_DEBUG(SSH_D_LOWOK, ("Input available from the stream"));
      read_stream_input(t);
      break;

    case  SSH_STREAM_CAN_OUTPUT:
      SSH_DEBUG(SSH_D_LOWOK, ("Can output to the stream"));
      write_stream_output(t);
      break;

    case SSH_STREAM_DISCONNECTED:
      SSH_DEBUG(SSH_D_LOWOK, ("Stream disconnected"));
      break;
    default:
      break;
    }
}

static void
test_output_cb(SshEapConnection con, void *ctx, const SshBuffer buf)
{
  SshTEap t;
  unsigned char *ptr;
  unsigned long len;

  t = (SshTEap)ctx;

  len = ssh_buffer_len(buf);
  ptr = ssh_buffer_ptr(buf);

  SSH_TRACE_HEXDUMP(SSH_D_HIGHOK, ("send packet: length %d", len), ptr, len);

  t->output_buf = ssh_xmalloc(len + 4);
  t->output_len = len + 4;
  t->output_written = 0;

  t->output_buf[0] = (unsigned char)((len >> 24) & 0xFF);
  t->output_buf[1] = (unsigned char)((len >> 16) & 0xFF);
  t->output_buf[2] = (unsigned char)((len >> 8) & 0xFF);
  t->output_buf[3] = (unsigned char)(len & 0xFF);

  memcpy(t->output_buf + 4, ptr, len);

  write_stream_output(t);
}

/* Start EAP authentication round */
static void authenticator_begin_eap(void* ctx)
{
  SshTEap t;
  const char *id_request = "Please send your identity";

  t = (SshTEap)ctx;

  SSH_DEBUG(SSH_D_HIGHOK, ("commencing test"));

  SSH_ASSERT(t->params.client == FALSE);

  /* Trigger identification */
  
  if (t->params.no_identity == FALSE)
    {
      ssh_eap_send_identification_request(t->eap,
					  id_request, 
					  strlen(id_request));
    }
  else
    {
      ssh_eap_authenticate(t->eap, SSH_EAP_AUTH_CONTINUE);
    }
}

static void
test_destructor(SshFSM fsm, void* ctx)
{
  SshTEap t = (SshTEap)ctx;

  SSH_DEBUG(SSH_D_HIGHOK, ("shutting down EAP components"));

  ssh_cancel_timeouts(dummy_timeout, NULL);
      
  if (t->destroy_handler)
    t->destroy_handler(t->user_context);
  
  if (t->eap != NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Calling eap destroy"));
      ssh_eap_destroy(t->eap);
    }

  ssh_eap_connection_destroy(t->connection);
  ssh_eap_config_destroy(t->config);

  if (t->listener != NULL)
    { 
      SSH_DEBUG(SSH_D_HIGHOK, ("unlink %s", t->params.local_listener_path));

      ssh_local_destroy_listener(t->listener);
      unlink(t->params.local_listener_path);
    }

  if (t->params.local_listener_path)
    ssh_xfree(t->params.local_listener_path);

  ssh_fsm_condition_uninit(&t->condition);

  if (t->stream != NULL)
    ssh_stream_destroy(t->stream);

  if (t->input_buf)
    ssh_xfree(t->input_buf);    

#ifdef SSHDIST_RADIUS
  if (t->radius_config.radius_client != NULL)
    {
      ssh_radius_url_destroy_avpset(t->radius_config.default_avps);
      ssh_radius_client_server_info_destroy(
					    t->radius_config.radius_servers);
      ssh_radius_client_destroy(t->radius_config.radius_client);
    }
#endif /* SSHDIST_RADIUS */
}

void configure_eap_params(SshTEap t)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Configuring test parameters"));

  t->config = ssh_eap_config_create();
  SSH_ASSERT(t->config != NULL);  

  t->config->auth_timeout_sec = 120;
  t->config->retransmit_delay_sec = 5;
  t->config->num_retransmit = 3;
  t->config->signal_cb = eap_signal_cb;
#ifdef SSHDIST_RADIUS
    if (t->params.radius_url != NULL)
      t->config->radius_buffer_identity = TRUE;
#endif /* SSHDIST_RADIUS */

  t->connection = ssh_eap_connection_create_cb(test_output_cb, t);

  if (t->params.client)
    {
      t->eap = ssh_eap_create_client(t, t->config, t->connection);
    }
  else
    {
      t->eap = ssh_eap_create_server(t, t->config, t->connection);
    }
  SSH_ASSERT(t->eap != NULL);

  if (t->config_handler)
    t->config_handler(t->eap, t->user_context);
}

void
eap_local_listener_callback(SshStream stream, void *context)
{
  SshTEap t = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("In EAP local listener callback"));

  ssh_fsm_condition_signal(t->fsm, &t->condition);

  if (stream == NULL)
    {
      t->in_error = TRUE;
      ssh_warning("Could not connect to local listener");
      return;
    }

  t->stream = stream;
  ssh_stream_set_callback(t->stream, test_stream_cb, t);

  if (t->params.client == FALSE)
    ssh_xregister_timeout(0, 0, authenticator_begin_eap, t);
}

void local_connect_cb(void *context)
{
  SshTEap t = context;

  SSH_ASSERT(t->params.server == TRUE);

  ssh_local_connect(t->params.local_listener_path,
		    eap_local_listener_callback,
		    t);
}


#ifdef WIN32
DWORD WINAPI exit_server_notifier(void *context)
{
   /* Wait here for the process to finish */
   WaitForSingleObject(((SHELLEXECUTEINFO*)context)->hProcess,
                       60L*60L*1000L);
   ((SHELLEXECUTEINFO*)context)->hProcess = NULL;

  return ERROR_SUCCESS;
}
#endif /* WIN32 */


#ifdef SSHDIST_RADIUS
static Boolean configure_radius_params(SshTEap t)
{
  SshRadiusClientParamsStruct radius_params;
  SshEapRadiusConfiguration radius_config;

  if (t->params.client)
    return TRUE;

  radius_config = &t->radius_config;
  memset(radius_config, 0, sizeof(SshEapRadiusConfigurationStruct));
  
  if (t->params.radius_url != NULL)
    {
      SshRadiusUrlStatus url_status;
      const char *str;
      char *url;
      
      url = t->params.radius_url;
      
      url_status = ssh_radius_url_isok(url);
      
      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
	{
	  str = ssh_find_keyword_name(ssh_radius_url_status_codes,
				      url_status);

	  SSH_DEBUG(SSH_D_FAIL, ("Error parsing RADIUS url"));
	  return FALSE;
	}
      
      url_status = ssh_radius_url_init_params(&radius_params, url);
      
      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Error initializing RADIUS params"));
	  return FALSE;
	}
      
      radius_config->radius_client =
	ssh_radius_client_create(&radius_params);
      
      ssh_radius_url_uninit_params(&radius_params);
      
      if (radius_config->radius_client == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Error creating RADIUS client"));
	  return FALSE;
	}
      
      radius_config->radius_servers =
	ssh_radius_client_server_info_create();
      
      if (radius_config->radius_servers == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Error adding RADIUS servers"));
	  return FALSE;
	}
      
      url_status = 
	ssh_radius_url_add_server(radius_config->radius_servers, url);
      
      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Error adding RADIUS server to server info"));
	  return FALSE;
	}
      
      url_status = ssh_radius_url_create_avpset(
						&radius_config->default_avps,
						url);

      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Error creating default AVP set"));
	  return FALSE;
	}
      

      radius_config->ignore_radius_session_timeout = FALSE;
    }

  return TRUE;
}
#endif /* SSHDIST_RADIUS */


int
test_eap_run(const char *program, 
	     SshEapTestParams params,
	     SshEapTestConfigCB config_handler,
	     SshEapTestTokenCB token_handler,
	     SshEapTestDestroyCB destroy_handler,
	     void *context)
{
  SshTEap t;
  SshFSM fsm;
  SshFSMThread thread;
  SshLocalStreamParamsStruct local_stream_params;
#ifndef WIN32
  int status;
  pid_t child_pid = 0;
#endif /* WIN32 */

  if (params == NULL || token_handler == NULL)
    {
      ssh_warning("Params and token handler must be specified");
      exit(1);
    }

  ssh_crypto_library_initialize();
  ssh_event_loop_initialize();
  
  t = ssh_xcalloc(1, sizeof(*t));
  t->config_handler = config_handler;
  t->token_handler = token_handler;
  t->destroy_handler = destroy_handler;
  t->user_context = context;

  fsm = ssh_fsm_create(NULL);
  t->fsm = fsm;

  ssh_fsm_condition_init(fsm, &t->condition);

  thread = ssh_fsm_thread_create(fsm, eap_start, NULL_FNPTR, 
				 test_destructor, t);
                                 
  t->thread = thread;

  SSH_ASSERT(params != NULL);
  t->params = *params;

  /* Copy memory from the 'params' to t->params */
  if (params->local_listener_path)
    {
      t->params.local_listener_path 
	= ssh_xstrdup(params->local_listener_path);
    }
  
  ssh_event_loop_lock();

  if (t->params.client == FALSE && t->params.server == FALSE)
    {
#ifdef WIN32
      TCHAR path[512];
      DWORD dwid;
#endif
      int rng;

      
      rng = 	  
	(((int)ssh_random_get_byte()) << 24) | 
	(((int)ssh_random_get_byte()) << 16) | 
	(((int)ssh_random_get_byte()) << 8) | 
	(int)ssh_random_get_byte();

      t->params.local_listener_path = ssh_xcalloc(1, 128);

      ssh_snprintf(t->params.local_listener_path, 128,
		   "/tmp/teap.%x", rng);
      
#ifdef WIN32
      /* get full path for this application */
      if (GetModuleFileName(NULL, path, 512) == 0)
        ssh_fatal("Could not get module path to the application.");

      /* parse process parameters */
      t_eap.cbSize = sizeof(t_eap);
      t_eap.fMask = SEE_MASK_NOCLOSEPROCESS;
      t_eap.lpFile = path;
      t_eap.lpParameters = TEXT(" -c"); 
      t_eap.lpDirectory = TEXT("");
      t_eap.nShow = SW_SHOWNORMAL;

      /* execute client process */
      ShellExecuteEx(&t_eap);

      if (t_eap.hProcess == NULL)
        ssh_fatal("Shell execute failed");

      /* make client exit notifier */
      exit_notify_thread =
        CreateThread(NULL, 0, exit_server_notifier,
                     ((void*)&t_eap), 0, &dwid);
      if (exit_notify_thread == 0)
        ssh_fatal("create thread failed");

      SSH_DEBUG(3, ("Server start"));
#else /* WIN32 */
      child_pid = fork();
      if (child_pid < 0)
        ssh_fatal("Fork failed: %.200s", strerror(errno));

      /* The parent process acts as the EAP server. */
      if (child_pid != 0)
        {
          SSH_DEBUG(SSH_D_HIGHSTART, ("Server start, client pid = %d",
				      child_pid));
	  t->params.server = TRUE;

        }
      else
        {
          SSH_DEBUG(SSH_D_HIGHSTART, ("Client start"));
	  t->params.client = TRUE;
        }
#endif /* !WIN32 */

    }

#ifdef SSHDIST_RADIUS
  if (!configure_radius_params(t))
    exit(1);
#endif /* SSHDIST_RADIUS */

  if (t->params.local_listener_path == NULL)
    {
      ssh_warning("Local listener path must be given");
      exit(1);
    }
  
  memset(&local_stream_params, 0, sizeof(local_stream_params));
  local_stream_params.access = SSH_LOCAL_STREAM_ACCESS_ALL;
  
  if (t->params.client)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Creating local listener to %s",
			       t->params.local_listener_path));

      t->listener = 
	ssh_local_make_listener(t->params.local_listener_path,
				&local_stream_params,
				eap_local_listener_callback,
				t);
    }
  else
    {
      ssh_xregister_timeout(0, 500000, local_connect_cb, t);
    }

 ssh_event_loop_unlock();
 configure_eap_params(t);

  ssh_event_loop_run();

  SSH_DEBUG(SSH_D_MIDOK, ("event loop exit"));

  ssh_fsm_destroy(fsm);
  fsm = NULL;

  ssh_event_loop_run();

  ssh_event_loop_lock();
#ifdef WIN32
  /* Terminate 'client exit notify' -thread if it's still
     running. */
  if (exit_notify_thread)
    {
      CloseHandle(exit_notify_thread);
      exit_notify_thread = NULL;
    }

  /* Kill client process if it is still runnning (for some
     peculiar reason). */
  if (t_eap.hProcess)
    {
      TerminateProcess(t_eap.hProcess, 0);
    }
#else /* WIN32 */

  if (child_pid != 0)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Waiting for the child process to end"));
      wait(&status);
      
      SSH_DEBUG(SSH_D_HIGHOK, ("Child process ended with status %d", status));

      if (WIFEXITED(status))
	status = WEXITSTATUS(status);
      
      if (status != 0)
	global_error_seen = TRUE;
    }
#endif /* WIN32 */
 ssh_event_loop_unlock();

  ssh_xfree(t);

  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();
  ssh_crypto_library_uninitialize();
  
  ssh_util_uninit();

  if (global_error_seen)
    {
      ssh_warning("Errors seen during execution, exiting with error code");
      exit(1);
    }

  return 0;
}
