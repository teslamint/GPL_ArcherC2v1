/*

t-stream.c

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Thu Oct 24 23:10:57 1996 ylo

*/

#include "sshincludes.h"
#include "sshtcp.h"
#include "sshnameserver.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshfsm.h"
#include "sshrand.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "Main"

static Boolean name_service = FALSE;
static Boolean outside_tests = FALSE;

#define PASSES 100

/* Socks URL format: socks://user@server:port/ */
# define SOCKSHOST  ""
/* Dotted IP address. */
# define SOCKSIP    ""
/* Socks URL omitting local addresses from socks processing:
  format: socks://user@server:port/comma-sep-exception-masks */
# define SOCKSLOCAL ""

#define OUTSIDESSHHOST "www.iki.fi"
#define OUTSIDESSHIP "212.16.100.1"

# define LOCALHOST_IP "127.0.0.1"
# define LOCALHOST_NAME "localhost"

/* Program name */
char *program;

SshFSMThreadStruct thread[1];
SshFSMStruct fsm[1];
int pass;

SSH_FSM_STEP(t_stream_start);
SSH_FSM_STEP(t_stream_test_start);
SSH_FSM_STEP(t_stream_test_inet);
SSH_FSM_STEP(t_stream_test_listener);
SSH_FSM_STEP(t_stream_test_connectfail);
SSH_FSM_STEP(t_stream_test_connectfail_ip);
SSH_FSM_STEP(t_stream_connect_outside);
SSH_FSM_STEP(t_stream_connectfail_outside_sockshost);
SSH_FSM_STEP(t_stream_connectfail_outside_socksip);
SSH_FSM_STEP(t_stream_connectfail_outside_ip);
SSH_FSM_STEP(t_stream_connect_outside_sockshost);
SSH_FSM_STEP(t_stream_connect_outside_socksip);
SSH_FSM_STEP(t_stream_connect_outside_ip);
SSH_FSM_STEP(t_stream_connect);
SSH_FSM_STEP(t_stream_connect_ip);
SSH_FSM_STEP(t_stream_test_end);
SSH_FSM_STEP(t_stream_end);

#ifdef DEBUG_LIGHT
SshFSMStateDebugStruct t_stream_fsm_names[] =
{
  SSH_FSM_STATE("start", "Start", t_stream_start)
  SSH_FSM_STATE("test_start", "Test start", t_stream_test_start)
  SSH_FSM_STATE("test_inet", "Test inet", t_stream_test_inet)
  SSH_FSM_STATE("test_listener", "Test listener", t_stream_test_listener)
  SSH_FSM_STATE("test_connectfail", "Test connectfail",
		t_stream_test_connectfail)
  SSH_FSM_STATE("connect_outside", "Connect outside start",
		t_stream_connect_outside)
  SSH_FSM_STATE("connectfail_outside_sockshost", "Failing outside sockshost",
		t_stream_connectfail_outside_sockshost)
  SSH_FSM_STATE("connectfail_outside_socksip", "Failing outside socksip",
		t_stream_connectfail_outside_socksip)
  SSH_FSM_STATE("connect_outside_sockshost", "Outside connect sockshost",
		t_stream_connect_outside_sockshost)
  SSH_FSM_STATE("connect_outside_socksip", "Outside connect socksip",
		t_stream_connect_outside_socksip)
  SSH_FSM_STATE("connect", "Connect", t_stream_connect)
  SSH_FSM_STATE("test_end", "Test end", t_stream_test_end)
  SSH_FSM_STATE("end", "end", t_stream_end)
};
int t_stream_fsm_names_count = SSH_FSM_NUM_STATES(t_stream_fsm_names);
#endif /* DEBUG_LIGHT */

SshBufferStruct send_buffer, expect_buffer;
unsigned long send_count = 0, read_count = 0;

SSH_FSM_STEP(t_stream_start)
{
  pass = 0;
  printf("Doing %d iterations of stream test:\n", PASSES);
  SSH_FSM_SET_NEXT(t_stream_test_start);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(t_stream_test_start)
{
  unsigned char buf[1024];
  int i, j;

  printf(" %d", pass);
  fflush(stdout);

  SSH_DEBUG(SSH_D_MIDSTART, ("Stream test start pass %d", pass));
  ssh_buffer_init(&send_buffer);
  ssh_buffer_init(&expect_buffer);

  for (i = 0; i < 100; i++)
    {
      for (j = 0; j < sizeof(buf); j++)
	buf[j] = ssh_rand();
      ssh_buffer_append(&send_buffer, buf, sizeof(buf));
      ssh_buffer_append(&expect_buffer, buf, sizeof(buf));
      send_count += sizeof(buf);
    }
  SSH_FSM_SET_NEXT(t_stream_test_inet);
  return SSH_FSM_CONTINUE;
}

char *ok_netmask_tests[][2] = {
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.4" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.22" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.0" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.255" },
  { "1.2.3.4", "1.2.3.4" },
  { "1.2.3.4/8", "1.2.3.4" },
  { "1.2.3.4/8", "1.3.4.5" },
  { "1.2.3.4/16", "1.2.4.5" },
  { "1.2.3.4/16", "1.2.44.22" },
  { "1.2.3.4/24", "1.2.3.4" },
  { "1.2.3.4/24", "1.2.3.255" },
  { "1.2.3.4/28", "1.2.3.6" },
  { "1.2.3.4/28", "1.2.3.15" }
};

char *fail_netmask_tests[][2] = {
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.5" },
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.22" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.5.22" },
  { "1.2.3.4", "2.3.4.255" },
  { "1.2.3.4", "1.2.3.5" },
  { "1.2.3.4/8", "2.3.4.5" },
  { "1.2.3.4/16", "2.2.44.22" },
  { "1.2.3.4/24", "1.2.4.22" },
  { "1.2.3.4/24", "1.3.3.22" },
  { "1.2.3.4/24", "2.2.3.22" },
  { "1.2.3.4/28", "1.2.3.16" },
  { "1.2.3.4/28", "1.2.3.64" },
  { "1.2.3.4/28", "1.2.3.128" },
  { "1.2.3.4/28", "1.2.3.255" }
};

SSH_FSM_STEP(t_stream_test_inet)
{
  unsigned char buf[1024];
  int i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Testing inet"));
  /* Get port by service and service by port tests. */
#ifndef _WIN32_WCE
  if (ssh_inet_get_port_by_service("telnet", "tcp") != 23)
    ssh_fatal("get_port_by_service telnet failed");
  ssh_inet_get_service_by_port(23, "tcp", (char *) buf, sizeof(buf));
  if (strcmp((char *) buf, "telnet") != 0)
    ssh_fatal("get_service_by_port failed");
#else
  if (ssh_inet_get_port_by_service("telnet", "tcp") != 23)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("get_port_by_service telnet failed (Windows CE built "
                 "without system message table resources)"));
      if (ssh_inet_get_port_by_service("23", "tcp") != 23)
        ssh_fatal("get_port_by_service \"23\" failed");
      ssh_inet_get_service_by_port(23, "tcp", (char *)buf, sizeof(buf));
      if (strcmp((char *)buf, "23") != 0)
        ssh_fatal("get_service_by_port failed");
    }
  else
    {
      /* Windows CE built with system message table resources. 
         ssh_inet_get_service_by_port must succeed. */
      ssh_inet_get_service_by_port(23, "tcp", (char *)buf, sizeof(buf));
      if (strcmp((char *)buf, "telnet") != 0)
        ssh_fatal("get_service_by_port failed");
    }
#endif /* _WIN32_WCE */

  /* Inet addr tests. */
  if (!ssh_inet_is_valid_ip_address("255.2.0.40") ||
      ssh_inet_is_valid_ip_address("1.2.304.4") ||
      ssh_inet_is_valid_ip_address("5.4.3.2.1"))
    ssh_fatal("is_valid_ip_address failed");

  if (ssh_inet_ip_address_compare("1.2.3.4", "001.002.003.04") != 0 ||
      ssh_inet_ip_address_compare("1.2.3.4", "4.3.2.1") == 0)
    ssh_fatal("ip_address_compare failed");

  for (i = 0;
       i < sizeof(ok_netmask_tests) / sizeof(*ok_netmask_tests);
       i++)
    {
      if (!ssh_inet_compare_netmask(ok_netmask_tests[i][0],
				    ok_netmask_tests[i][1]))
	ssh_fatal("ssh_inet_compare_netmask failed, "
		  "netmask = %s, ip = %s",
		  ok_netmask_tests[i][0], ok_netmask_tests[i][1]);
      if (ssh_inet_compare_netmask(fail_netmask_tests[i][0],
				   fail_netmask_tests[i][1]))
	ssh_fatal("ssh_inet_compare_netmask succeded "
		  "(should fail), netmask = %s, ip = %s",
		  fail_netmask_tests[i][0], fail_netmask_tests[i][1]);
    }
  SSH_FSM_SET_NEXT(t_stream_test_listener);
  return SSH_FSM_CONTINUE;
}

void listenerfail_callback(SshTcpError status, SshStream stream, void *context)
{
  ssh_fatal("listenerfail_callback called");
}

SSH_FSM_STEP(t_stream_test_listener)
{
  SshTcpListener failing_listener1, failing_listener2;

  SSH_DEBUG(SSH_D_MIDSTART, ("Testing failing listeners"));
  /* Try creating a failing listener. */
  failing_listener1 = ssh_tcp_make_listener(SSH_IPADDR_ANY_IPV4, "34512", NULL,
					    listenerfail_callback, NULL);
  if (!failing_listener1)
    ssh_fatal("Creating listener1 failed");
  failing_listener2 = ssh_tcp_make_listener(SSH_IPADDR_ANY_IPV4, "34512", NULL,
					    listenerfail_callback, NULL);
  if (failing_listener2)
    ssh_fatal("Creating listener2 succeeded when it should fail.");
  ssh_tcp_destroy_listener(failing_listener1);

  SSH_FSM_SET_NEXT(t_stream_test_connectfail);
  return SSH_FSM_CONTINUE;
}

void connectfail_done(SshTcpError status, SshStream stream, void *context)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Connection failed"));
  if (status == SSH_TCP_OK)
    ssh_fatal("Connectfail_done: succeeded when should have failed");
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(t_stream_test_connectfail)
{
  SshTcpConnectParamsStruct params;

  /* Try making a failing connection. */
  memset(&params, 0, sizeof(params));
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  SSH_FSM_SET_NEXT(t_stream_test_connectfail_ip);
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect to 127.0.0.1:34514"));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect("127.1", "34514", &params,
				     connectfail_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_test_connectfail_ip)
{
  SshIpAddrStruct ip[1];

  if (outside_tests)
    SSH_FSM_SET_NEXT(t_stream_connect_outside);
  else
    SSH_FSM_SET_NEXT(t_stream_connect);
   
  ssh_ipaddr_parse(ip, "127.1");
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect to 127.0.0.1:34514"));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect_ip(ip, 34514,
					NULL, 0, NULL,
					connectfail_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_connect_outside)
{
  if (pass % 50 != 3)
    {
      SSH_FSM_SET_NEXT(t_stream_connect);
      SSH_DEBUG(SSH_D_MIDSTART, ("Skip outside tests"));
      return SSH_FSM_CONTINUE;
    }
  SSH_DEBUG(SSH_D_MIDSTART, ("Run outside tests"));
  SSH_FSM_SET_NEXT(t_stream_connectfail_outside_sockshost);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(t_stream_connectfail_outside_sockshost)
{
  SshTcpConnectParamsStruct params;

  memset(&params, 0, sizeof(params));
  params.socks_server_url = SOCKSHOST;
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  SSH_FSM_SET_NEXT(t_stream_connectfail_outside_socksip);
  /* Try connecting with socks to a failing address. */
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %s:34512 through %s",
			     OUTSIDESSHHOST, SOCKSHOST));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect(OUTSIDESSHHOST, "34512", &params,
				     connectfail_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_connectfail_outside_socksip)
{
  SshTcpConnectParamsStruct params;

  memset(&params, 0, sizeof(params));
  params.socks_server_url = SOCKSIP;
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  SSH_FSM_SET_NEXT(t_stream_connectfail_outside_ip);
  /* Try connecting with socks to a failing address. */
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %s:34512 through %s",
			     OUTSIDESSHHOST, SOCKSIP));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect(OUTSIDESSHHOST, "34512", &params,
				     connectfail_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_connectfail_outside_ip)
{
  SshIpAddrStruct ip[1];

  SSH_FSM_SET_NEXT(t_stream_connect_outside_sockshost);
  /* Try connecting with socks to a failing address. */
  ssh_ipaddr_parse(ip, OUTSIDESSHIP);
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %@:34512",
			     ssh_ipaddr_render, ip));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect_ip(ip, 34512, NULL, 0, NULL,
					connectfail_done, NULL);
		     );
}

void connectssh_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = (SshStream)context;
  unsigned char buf[1];
  int len;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      while ((len = ssh_stream_read(stream, buf, 1)) > 0)
        {
          if (buf[0] == '\n')
            break;
        }
      if (len == 0 ||
          (len == 1 && buf[0] == '\n'))
        {
          ssh_stream_destroy(stream);
	  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
          return;
        }
      break;
    case SSH_STREAM_CAN_OUTPUT:
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("connectssh_callback: received DISCONNECTED");
    default:
      ssh_fatal("connectssh_callback: unexpected notification %d",
                notification);
    }
}

void connectssh_done(SshTcpError status, SshStream stream, void *context)
{
  if (status != SSH_TCP_OK)
    ssh_fatal("connectssh_done: connecting to %s ssh failed",
              OUTSIDESSHHOST);
  ssh_stream_set_callback(stream, connectssh_callback, (void *)stream);
}

SSH_FSM_STEP(t_stream_connect_outside_sockshost)
{
  SshTcpConnectParamsStruct params;

  memset(&params, 0, sizeof(params));
  params.socks_server_url = SOCKSHOST;
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  SSH_FSM_SET_NEXT(t_stream_connect_outside_socksip);

  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %s:22 through %s",
			     OUTSIDESSHIP, SOCKSHOST));
  /* Try connecting with socks to a successful address. */
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect(OUTSIDESSHIP, "22", &params,
				     connectssh_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_connect_outside_socksip)
{
  SshTcpConnectParamsStruct params;

  memset(&params, 0, sizeof(params));
  params.socks_server_url = SOCKSIP;
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  SSH_FSM_SET_NEXT(t_stream_connect_outside_ip);

  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %s:22 through %s",
			     OUTSIDESSHIP, SOCKSIP));
  /* Try connecting with socks to a successful address. */
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect(OUTSIDESSHIP, "22", &params,
				     connectssh_done, NULL);
		     );
}

SSH_FSM_STEP(t_stream_connect_outside_ip)
{
  SshIpAddrStruct ip[1];

  SSH_FSM_SET_NEXT(t_stream_connect);

  ssh_ipaddr_parse(ip, OUTSIDESSHIP);
  SSH_DEBUG(SSH_D_MIDSTART, ("Trying to connect %@:22",
			     ssh_ipaddr_render, ip));
  /* Try connecting with socks to a successful address. */
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect_ip(ip, 22, NULL, 0, NULL,
				     connectssh_done, NULL);
		     );
}

int exited;
SshTcpListener listener1, listener2;

void connect2_done(SshTcpError error, SshStream stream, void *context)
{
  if (error != SSH_TCP_OK || stream == NULL)
    ssh_fatal("Connect2 failed");
  ssh_stream_destroy(stream);
  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Connect to port 34513 done, exited = %d",
			     exited));
}

void listener2_callback(SshTcpError status, SshStream stream, void *context)
{
  char buf[100];

  if (status != SSH_TCP_NEW_CONNECTION)
    ssh_fatal("listener2 status %d", status);

  if (!ssh_tcp_get_remote_address(stream, buf, sizeof(buf)) ||
      strcmp(buf, "127.0.0.1") != 0)
    ssh_fatal("listener2 remote address");

  memset(buf, 0, sizeof(buf));
  if (!ssh_tcp_get_local_address(stream, buf, sizeof(buf)) ||
      strcmp(buf, "127.0.0.1") != 0)
    ssh_fatal("listener2 remote address");

  ssh_stream_destroy(stream);
  ssh_tcp_destroy_listener(listener2);

  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Accept to port 34513 done, exited = %d",
			     exited));
}

void server1_read(SshStream stream)
{
  int ret;
  unsigned char buf[1024];

  for (;;)
    {
      ret = ssh_stream_read(stream, buf, sizeof(buf));
      if (ret < 0)
        return;
      if (ret == 0)
        {
          if (read_count != send_count)
            ssh_fatal("server1_read eof received, read_count %ld "
                      "send_count %ld",
                      read_count, send_count);
          break;
        }
      if (memcmp(buf, ssh_buffer_ptr(&expect_buffer), ret) != 0)
        ssh_fatal("server1_read data does not match");
      ssh_buffer_consume(&expect_buffer, ret);
      read_count += ret;
    }
  /* All data has been received. */
  ssh_stream_destroy(stream);
  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Read from port 34512 done, exited = %d",
			     exited));
}

void server1_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = context;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      server1_read(stream);
      break;
    case SSH_STREAM_CAN_OUTPUT:
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("server1_callback: received disconnect");
    default:
      ssh_fatal("server1_callback notification %d", notification);
    }
}

void listener1_callback(SshTcpError status, SshStream stream, void *context)
{
  if (status != SSH_TCP_NEW_CONNECTION)
    ssh_fatal("listener1 status %d", status);

  ssh_stream_set_callback(stream, server1_callback, stream);

  ssh_tcp_destroy_listener(listener1);
  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Accept of port 34512 done, exited = %d",
			     exited));
}

void connect1_write(SshStream stream)
{
  int len;

  while (ssh_buffer_len(&send_buffer) > 0)
    {
      len = ssh_buffer_len(&send_buffer);
      len = ssh_stream_write(stream, ssh_buffer_ptr(&send_buffer), len);
      if (len < 0)
        return;
      if (len == 0)
        ssh_fatal("connect1_write failed");
      ssh_buffer_consume(&send_buffer, len);
    }

  ssh_stream_output_eof(stream);
  ssh_stream_destroy(stream);
  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Write to port 34512 done, exited = %d",
			     exited));
}

void connect1_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = context;
  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      break;
    case SSH_STREAM_CAN_OUTPUT:
      connect1_write(stream);
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("connect1_callback disconnected");
    }
}

void connect1_done(SshTcpError status, SshStream stream, void *context)
{
  char buf[100];

  if (context != (void *)3)
    ssh_fatal("connect1 bad context");

  if (status != SSH_TCP_OK)
    ssh_fatal("connect1 bad status %d", status);

  if (!ssh_tcp_get_local_port(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 local port");

  if (atoi(buf) < 1024 || atoi(buf) > 65535)
    ssh_fatal("connect1 local port value %d", buf);

  if (!ssh_tcp_get_remote_port(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 remote port");

  if (strcmp(buf, "34512") != 0)
    ssh_fatal("connect1 remote port value %d", buf);

  if (!ssh_tcp_get_local_address(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 local address");

  if (!ssh_tcp_get_remote_address(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 remote address");

  if (ssh_tcp_has_ip_options(stream))
    ssh_fatal("connect1 ip options");

  if (ssh_stream_read(stream, (unsigned char *) buf, sizeof(buf)) >= 0)
    ssh_fatal("connect1 read should have failed");

  ssh_stream_set_callback(stream, connect1_callback, (void *)stream);

  exited++;
  if (exited > 5)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_DEBUG(SSH_D_MIDSTART, ("Connect to port 34512 done, exited = %d",
			     exited));
}

void timeout(void *context)
{
  SshTcpConnectParamsStruct params;

  if (context != (void *)1)
    ssh_fatal("connect1 bad context");

  memset(&params, 0, sizeof(params));
  params.socks_server_url = "";
  params.connection_attempts = 2;
  params.connection_timeout = 30;

  if (name_service)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Try connect to %s:34513", LOCALHOST_NAME));
      ssh_tcp_connect(LOCALHOST_NAME, "34513", &params,
		      connect2_done, (void *)2);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Try connect to %s:34513", LOCALHOST_IP));
      ssh_tcp_connect(LOCALHOST_IP, "34513", &params,
		      connect2_done, (void *)2);
    }
}


SSH_FSM_STEP(t_stream_connect)
{
  SshTcpConnectParamsStruct params;
  unsigned char buf[1024];

  exited = 0;

  /* Create two listeners, make a connection, and pass some data.
     This tests
     - that the callbacks get called when set
     - that data can be transmitted
     - that EOF is passed ok */
  listener1 = ssh_tcp_make_listener(SSH_IPADDR_ANY_IPV4, "34512", NULL,
				    listener1_callback, NULL);
  listener2 = ssh_tcp_make_listener("127.0.0.1", "34513", NULL,
				    listener2_callback, NULL);
  ssh_xregister_timeout(0L, 50000L, timeout, (void *)1);

  if (name_service)
    {
      ssh_tcp_get_host_name((char *) buf, sizeof(buf));
      if (strchr(buf, '.') == NULL) 
	ssh_fatal("Hostname %s is not fully qualified domain name", buf);
    }
  else
    {
      strncpy((char *) buf, LOCALHOST_IP, sizeof (buf));
      buf[sizeof (buf) - 1] = '\0';
    }

  memset(&params, 0, sizeof(params));
  params.connection_attempts = 2;
  params.connection_timeout = 30;
  params.socks_server_url = SOCKSLOCAL;
  SSH_FSM_SET_NEXT(t_stream_connect_ip);
  SSH_DEBUG(SSH_D_MIDSTART, ("Try connect to %s:34512", buf));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect((char *) buf, "34512",
				     &params, connect1_done,
				     (void *)3);
		     );
}

SSH_FSM_STEP(t_stream_connect_ip)
{
  SshIpAddrStruct ip[1];
  SshTcpConnectParamsStruct params;

  exited = 0;

  /* Create two listeners, make a connection, and pass some data.
     This tests
     - that the callbacks get called when set
     - that data can be transmitted
     - that EOF is passed ok */
  ssh_ipaddr_parse(ip, "127.0.0.1");
  listener1 = ssh_tcp_make_listener_ip(NULL, 34512, NULL,
				       listener1_callback, NULL);
  listener2 = ssh_tcp_make_listener_ip(ip, 34513, NULL,
				       listener2_callback, NULL);
  ssh_xregister_timeout(0L, 50000L, timeout, (void *)1);

  memset(&params, 0, sizeof(params));
  params.local_reusable = SSH_TCP_REUSABLE_BOTH;

  SSH_FSM_SET_NEXT(t_stream_test_end);
  SSH_DEBUG(SSH_D_MIDSTART, ("Try connect to %@:34512",
			     ssh_ipaddr_render, ip));
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_connect_ip(ip, (SshUInt16) 34512, ip,
					(SshUInt16) 34555 + pass,
					&params, connect1_done,
					(void *)3);
		     );
}

SSH_FSM_STEP(t_stream_test_end)
{
  ssh_buffer_uninit(&send_buffer);
  ssh_buffer_uninit(&expect_buffer);
  
  if (pass++ >= PASSES)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("That was final round"));
      SSH_FSM_SET_NEXT(t_stream_end);
      return SSH_FSM_CONTINUE;
    }
  SSH_DEBUG(SSH_D_MIDSTART, ("Continue to next round"));
  SSH_FSM_SET_NEXT(t_stream_test_start);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(t_stream_end)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Uninitializing"));
  ssh_name_server_uninit();
  return SSH_FSM_FINISH;
}

int main(int argc, char **argv)
{
  const char *debug_string = "2";
  int c, errflg = 0;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "nod:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
        case 'n': name_service = TRUE; break;
        case 'o': outside_tests = TRUE; break;
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr, 
      "Usage: %s [-d debug_flags] [-o outside_tests] [-n name_service]\n", 
	      program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();
  ssh_fsm_init(fsm, NULL);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(fsm,
			       t_stream_fsm_names,
			       t_stream_fsm_names_count);
#endif /* DEBUG_LIGHT */
  ssh_fsm_thread_init(fsm, thread, t_stream_start, NULL, NULL, NULL);
#ifdef DEBUG_LIGHT
  ssh_fsm_set_thread_name(thread, "TestThread");
#endif /* DEBUG_LIGHT */

  ssh_event_loop_run();

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
