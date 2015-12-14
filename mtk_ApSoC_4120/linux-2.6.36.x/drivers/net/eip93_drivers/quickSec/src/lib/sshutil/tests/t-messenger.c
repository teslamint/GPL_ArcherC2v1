/*****************************************************************************
 * Author: A. Philip Patel <andy@ssh.com>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *                    All rights reserved 
 *
 * Client/server chat program (in an effort to learn tcp, eloop, fsm, etc.)
 * - specify IP and port to connect to
 * - type stuff at the prompt, it get sent
 * - stuff typed at the other end is printed out
 *
 * Should be like this:
 * keyboard input -> io buffer -> tcp out stream
 * tcp in stream -> tcp buffer -> io out stream
 */

#define SSH_DEBUG_MODULE "t-messenger"
#define SSH_T_MESSENGER_DEBUG 0
#define SSH_T_MESSENGER_DISCONNECTED 0
#define SSH_T_MESSENGER_CONNECTED 1

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtcp.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshfsm.h"
#include "sshfdstream.h"
#include "sshnameserver.h"

/*
 * Structs and prototypes should go here
 */

/*
 * Context is a struct containing all variables
 * needed by different routines in the program
 * for control, etc.
 */
typedef struct t_messenger_context
{
  char*                 phost;  /* Host IP */
  char*                 pport;  /* Port to use */
  int                   state;  /* For fsm state games */
  unsigned int          timeout; /* Timeout in seconds for eventloop thingy */
  SshTcpListener        ptcplistener; /* tcp listener if this is a server */
  SshFSM                fsm;
  SshFSMThread          thread;
  SshFSMCondition       cv;
  SshStream             ptcpstream;     /* Internally used by tcp functions */
  SshStream             piostream;      /* Used for reading keyboard input */
  SshBuffer             ptcpbuffer;     /* Used to buffer tcp data */
  SshBuffer             piobuffer;      /* Used to buffer stdio data */
} t_messenger_context;

/*
 * This is for the two FSM states
 */

SSH_FSM_STEP(connected);
SSH_FSM_STEP(disconnected);

/*
 * Function for handling setup of tcp stream
 */
void t_messenger_tcp_callback(SshTcpError error,
                              SshStream stream,
                              void *context);
/*
 * Function prototype for callback function to handle streams
 */
void t_messenger_io_stream_callback(SshStreamNotification notification,
                                    void* context);
void t_messenger_tcp_stream_callback(SshStreamNotification notification,
                                     void* context);
/*
 * Write data from a buffer out to the other stream
 */
void t_messenger_io_buffer_write(void* context);
void t_messenger_tcp_buffer_write(void* context);

/*
 * Function prototype for timeout callback function needed by eventloop
 */
void t_messenger_timeout_callback(void *context);

/****************************************************************************
 * Main
 *
 */

int main(int argc, char* argv[])
{
  /* Define Variables */
  t_messenger_context context;
  context.timeout = 1;
  context.phost = 0;
  context.pport = "45223";
  context.ptcpstream = 0;
  context.piostream = 0;
  context.ptcplistener = 0;
  context.state = SSH_T_MESSENGER_DISCONNECTED;

  /* Get the command-line parameters */
  fprintf(stderr, "This program is: %s\n", argv[0]);
  if (argc > 1)
    {
      context.phost = argv[1];
      fprintf(stderr, "Host to connect to: %s\n", context.phost);
    }
  else
    {
      fprintf(stderr, "Acting as server\n");
    }

  /*
   * 1. Initialize Event Loop
   */
  ssh_event_loop_initialize();

  context.fsm = ssh_fsm_create(NULL);
  if (NULL == context.fsm)
    {
      fprintf(stderr, "Couldn't create FSM\n");
      return 1;
    }

  context.thread = ssh_fsm_thread_create(context.fsm,
                                         disconnected,
                                         NULL_FNPTR,
                                         NULL_FNPTR,
                                         &context);
  if (NULL == context.thread)
    {
      fprintf(stderr, "Unable to create thread\n");
      return 1;
    }

  context.cv = ssh_fsm_condition_create(context.fsm);

  /*
   * 2. Create input/output streams
   */

  /* Initialize keyboard stream */
  context.piobuffer = ssh_buffer_allocate();
  context.piostream = ssh_stream_fd_stdio();
  ssh_stream_set_callback(context.piostream,
                          t_messenger_io_stream_callback,
                          &context);

  /* Initialize tcp stream */
  context.ptcpbuffer = ssh_buffer_allocate();
  if (context.phost)
    {
      /* Act as client, so connect to defined host */
      fprintf(stderr, "Connecting to %s\n", context.phost);

      ssh_tcp_connect(context.phost,
                      context.pport,
                      NULL,
                      t_messenger_tcp_callback,
                      &context);
    }
  else
    {
      /* Act as server, so listen for a connection */
      fprintf(stderr, "Waiting for connection\n");

      ssh_tcp_make_listener(SSH_IPADDR_ANY_IPV4,
                            context.pport,
                            NULL,
                            t_messenger_tcp_callback,
                            &context);
    }

  /*
   * 3. Register timeouts
   */
  ssh_xregister_timeout(context.timeout,
                        0,
                        t_messenger_timeout_callback,
                        &context);

  /*
   * 4. Enter event loop
   */
  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "Entering event loop\n");

  ssh_event_loop_run();

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "Exiting event loop\n");

  /*
   * 5. Event loop returns
   */
  ssh_fsm_destroy(context.fsm);

  /*
   * 6. Uninitialize event loop
   */
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_buffer_free(context.piobuffer);
  ssh_buffer_free(context.ptcpbuffer);

  return 0;

}


/****************************************************************************
 * Subs
 *
 */

/*
 * This is the callback for handling tcp streams
 */
void t_messenger_tcp_callback(SshTcpError error,
                              SshStream stream,
                              void *context)
{
  t_messenger_context *pcontext = context;

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "t_messenger_tcp_callback\n");


  switch (error)
    {
    case SSH_TCP_OK:
      /* Connection was made via client method */
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "[SSH TCP OK]\n");

      pcontext->ptcpstream = stream;
      pcontext->state=SSH_T_MESSENGER_CONNECTED;
      ssh_fsm_condition_signal(pcontext->fsm, pcontext->cv);
      ssh_stream_set_callback(pcontext->ptcpstream,
                              t_messenger_tcp_stream_callback,
                              pcontext);
      break;
    case SSH_TCP_NEW_CONNECTION:
      /* Connection was made via server method */
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "[SSH TCP NEW CONNECTION]\n");

      pcontext->state=SSH_T_MESSENGER_CONNECTED;
      ssh_fsm_condition_signal(pcontext->fsm, pcontext->cv);
      pcontext->ptcpstream = stream;
      ssh_stream_set_callback(pcontext->ptcpstream,
                              t_messenger_tcp_stream_callback,
                              pcontext);
      break;
    case SSH_TCP_NO_ADDRESS:
      break;
    case SSH_TCP_NO_NAME:
      break;
    case SSH_TCP_UNREACHABLE:
      break;
    case SSH_TCP_REFUSED:
      break;
    case SSH_TCP_TIMEOUT:
      break;
    case SSH_TCP_FAILURE:
      break;
    default:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "nothing happened\n");
      break;
    }
}


/*
 * This is the callback for handling the keyboard input stream
 */
void t_messenger_io_stream_callback(SshStreamNotification notification,
                                    void* context)
{
  t_messenger_context *pcontext = context;
  char buf[32];
  int i;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "io:[INPUT AVAILABLE]\n");

      while ((i = ssh_stream_read(pcontext->piostream, buf, sizeof(buf))) > 0)
        {
          ssh_buffer_append(pcontext->piobuffer, buf, i);
          if (SSH_T_MESSENGER_DEBUG)
            fprintf(stderr, "io:buffer filled\n");

          t_messenger_io_buffer_write(pcontext);
        }
      break;
    case SSH_STREAM_CAN_OUTPUT:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "io:[CAN OUTPUT]\n");

      t_messenger_tcp_buffer_write(pcontext);
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fsm_condition_signal(pcontext->fsm, pcontext->cv);
      break;
    default:
      break;
    }
}

/*
 * This is the callback for handling tcp stream
 */
void t_messenger_tcp_stream_callback(SshStreamNotification notification,
                                     void* context)
{
  t_messenger_context *pcontext = context;
  char buf[32];
  int i;

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "t_messenger_tcp_stream_callback\n");

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "tcp:[INPUT AVAILABLE]\n");

      do
        {
          i = ssh_stream_read(pcontext->ptcpstream, buf, sizeof(buf));
          if (i > 0)
            {
              ssh_buffer_append(pcontext->ptcpbuffer, buf, i);
              if (SSH_T_MESSENGER_DEBUG)
                fprintf(stderr, "tcp:buffer filled\n");

              t_messenger_tcp_buffer_write(pcontext);
            }
          else if (0 == i)
            {
              pcontext->state=SSH_T_MESSENGER_DISCONNECTED;
              ssh_fsm_condition_signal(pcontext->fsm, pcontext->cv);
            }
        } while (i > 0);
      break;
    case SSH_STREAM_CAN_OUTPUT:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "tcp:[CAN OUTPUT]\n");

      t_messenger_io_buffer_write(pcontext);
      break;
    case SSH_STREAM_DISCONNECTED:
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "tcp:[DISCONNECTED]\n");

      pcontext->state=SSH_T_MESSENGER_DISCONNECTED;
      ssh_fsm_condition_signal(pcontext->fsm, pcontext->cv);
      break;
    default:
      break;
    }
}

/*
 * This routine writes io buffer out to tcp stream
 */
void t_messenger_io_buffer_write(void* context)
{
  t_messenger_context *pcontext = context;
  int i;
  /* Check that the tcp stream exists first! */
  if (!pcontext->ptcpstream)
    {
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "io:[BUFFER WRITE] no tcp stream\n");

      return;
    }


  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "io:[BUFFER WRITE] (to tcp stream)\n");

  if (ssh_buffer_len(pcontext->piobuffer)>0)
    {
      i = ssh_stream_write(pcontext->ptcpstream,
                           ssh_buffer_ptr(pcontext->piobuffer),
                           ssh_buffer_len(pcontext->piobuffer));
      if (i > 0)
        {
          ssh_buffer_consume(pcontext->piobuffer, i);
        }
    }
}

/*
 * This one writes tcp buffer out to io stream (to screen)
 */
void t_messenger_tcp_buffer_write(void* context)
{
  t_messenger_context *pcontext = context;
  int i;

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "tcp:[BUFFER WRITE] (to io stream)\n");

  if (ssh_buffer_len(pcontext->ptcpbuffer)>0)
    {
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "writing data\n");

      i = ssh_stream_write(pcontext->piostream,
                           ssh_buffer_ptr(pcontext->ptcpbuffer),
                           ssh_buffer_len(pcontext->ptcpbuffer));
      if (i > 0)
        {
          ssh_buffer_consume(pcontext->ptcpbuffer, i);
        }
    }
  else
    {
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "nothing to write\n");
    }
}

/*
 * This one is just for implementing timeouts
 */
void t_messenger_timeout_callback(void *context)
{
  t_messenger_context *pcontext = context;
  if (SSH_T_MESSENGER_DISCONNECTED == pcontext->state)
    {
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "[TIMEOUT CALLBACK] Messenger is disconnected\n");
    }
  else
    {
      if (SSH_T_MESSENGER_DEBUG)
        fprintf(stderr, "[TIMEOUT CALLBACK] Messenger is connected\n");
    }
  /* register a new timeout */
  ssh_xregister_timeout(pcontext->timeout,
                        0,
                        t_messenger_timeout_callback,
                        pcontext);
}

/*
 * And here we are at the FSM routines
 */

SSH_FSM_STEP(connected)
{
  t_messenger_context *pcontext = thread_context;

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "[SSH FSM STEP] connected\n");

  if (SSH_T_MESSENGER_DISCONNECTED == pcontext->state)
    {
      fprintf(stderr, "Disconnected\n");
      SSH_FSM_SET_NEXT(disconnected);
      return SSH_FSM_CONTINUE;
    }
  SSH_FSM_CONDITION_WAIT(pcontext->cv);
  return SSH_FSM_WAIT_CONDITION;
}

SSH_FSM_STEP(disconnected)
{
  t_messenger_context *pcontext = thread_context;

  if (SSH_T_MESSENGER_DEBUG)
    fprintf(stderr, "[SSH FSM STEP] disconnected\n");

  if (SSH_T_MESSENGER_CONNECTED == pcontext->state)
    {
      char remote_host_name[255];
      ssh_tcp_get_remote_address(pcontext->ptcpstream, remote_host_name, 255);
      fprintf(stderr, "Connection established from %s!\n", remote_host_name);
      SSH_FSM_SET_NEXT(connected);
      return SSH_FSM_CONTINUE;
    }
  SSH_FSM_CONDITION_WAIT(pcontext->cv);
  return SSH_FSM_WAIT_CONDITION;
}
