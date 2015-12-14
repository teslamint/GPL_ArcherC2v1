/*
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 * 
 *  Description:
 *       Test tool for testing IKEv2 multiple authentications
 *       defined in RFC 4739
 *       
 */

#include "sshincludes.h"

#include "sshdebug.h"
#include "sshfsm.h"
#include "ssheloop.h"
#ifdef SSHDIST_UTIL_TCP
#include "sshnameserver.h"
#endif /* SSHDIST_UTIL_TCP */
#include "sshgetopt.h"
#include "sshglobals.h"
#include "sshcrypt.h"
#ifdef SSHDIST_IKE_CERT_AUTH
#include "x509.h"
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_RADIUS
#include "sshradius.h"
#endif /* SSHDIST_RADIUS */
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
#include "sshrand.h"

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"

#include "dummy-if.h"

#define SSH_DEBUG_MODULE "Main"

/* Program name */
char *program;

struct SshIkev2ParamsRec params;

extern SshSADInterfaceStruct dummy_if;

#define MAX_SERVERS 4

SshSADHandle sad_handle;
SshIkev2 ikev2;
unsigned int num_servers;
SshIkev2Server server[MAX_SERVERS];
SshIkev2Sa global_ike_sa;

SshFSMStruct global_fsm[1];
SshOperationHandle global_operation;
Boolean client_running;
int opt_client, opt_server;

/* A comma separated list of local IP addresses */
const char *opt_local_ip;

SshUInt16 opt_local_port;
SshUInt16 opt_local_nat_port, opt_remote_nat_port;
const char *opt_remote_ip;
SshUInt16 opt_remote_port;

SshIkev2PayloadTS tsi_local, tsi_remote;
const char *opt_tsi_local_string, *opt_tsi_remote_string;

#ifdef SSHDIST_IKE_MOBIKE
Boolean mobike_supported = FALSE;
#endif /* SSHDIST_IKE_MOBIKE */

Boolean use_multiple_auth = TRUE;

#define IKEV2_INBOUND_SPIS 20
SshUInt32 global_inbound_spis[IKEV2_INBOUND_SPIS];
int global_spi_num = 0;

const char *opt_policy = NULL;

const char *cert_config = "certificates.config";

/* pad-dummy.c */
int d_pad_allocate(const unsigned char *cert_config);
void d_pad_destroy(void);

Boolean use_certs = FALSE;

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
Boolean use_eap = FALSE;

#ifdef SSHDIST_RADIUS
SshEapRadiusConfiguration radius_config = NULL;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

SSH_FSM_STEP(ikev2_init);
SSH_FSM_STEP(ikev2_sa_start);
void ikev2_cont(void *context);

SshFSMThreadStruct main_thread[1];
SshFSMThreadStruct sa_thread[1];

/**********************************************************************/
/* Main thread. */

SSH_FSM_STEP(ikev2_start);
SSH_FSM_STEP(ikev2_start_negotiation);
SSH_FSM_STEP(ikev2_wait);
SSH_FSM_STEP(ikev2_stop);
SSH_FSM_STEP(ikev2_servers_stop);
SSH_FSM_STEP(ikev2_uninit);
SSH_FSM_STEP(ikev2_free_ek);
SSH_FSM_STEP(ikev2_stop_name_server);
SSH_FSM_STEP(ikev2_finish);

SSH_FSM_STEP(ikev2_init)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Initializing IKEv2 library"));

  SSH_FSM_SET_NEXT(ikev2_start);

  ikev2 = ssh_ikev2_create(&params);
  if (ikev2 == NULL)
    SSH_FSM_SET_NEXT(ikev2_uninit);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_start)
{
  SshIpAddrStruct ip_addr[1];
  char ip_string[512], *str;
  int i, ofs;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Starting IKEv2 server"));

  SSH_FSM_SET_NEXT(ikev2_start_negotiation);

  sad_handle = d_sad_allocate(opt_policy);

  d_pad_allocate(cert_config);

  SSH_ASSERT(strlen(opt_local_ip) < sizeof(ip_string));

  /* Parse opt_local_ip a comma separated list of local IP adrresses 
     and start a server on each address. */
  for (i = 0, ofs = 0; i < MAX_SERVERS && ofs >= 0; i++)
    {
      str = strchr(opt_local_ip + ofs, ',');
      if (str)
	{
	  memcpy(ip_string, opt_local_ip + ofs, str - (opt_local_ip + ofs));
	  ip_string[str - (opt_local_ip + ofs)] = '\0';
	  ofs += (str - (opt_local_ip + ofs)) + 1;
	}
      else
	{
	  strcpy(ip_string, opt_local_ip + ofs);
	  ofs = -1;
	}
      
      ssh_ipaddr_parse(ip_addr, ip_string);
      
      SSH_DEBUG(SSH_D_LOWOK, ("Starting server on local address %@",
			      ssh_ipaddr_render, ip_addr));
      
      server[i] = ssh_ikev2_server_start(ikev2, ip_addr,
					 opt_local_port, opt_local_nat_port,
					 opt_remote_port, opt_remote_nat_port,
					 &dummy_if, sad_handle);
      
      if (server[i] == NULL)
	{
	  SSH_FSM_SET_NEXT(ikev2_uninit);	
	  return SSH_FSM_CONTINUE;
	}
    }
  num_servers = i;

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_start_negotiation)
{
  SSH_FSM_SET_NEXT(ikev2_wait);

  tsi_local = ssh_ikev2_ts_allocate(sad_handle);
  tsi_remote = ssh_ikev2_ts_allocate(sad_handle);

  if (tsi_local == NULL
      || tsi_remote == NULL
      || ssh_ikev2_string_to_ts(opt_tsi_local_string, tsi_local) == -1
      || ssh_ikev2_string_to_ts(opt_tsi_remote_string, tsi_remote) == -1)
    {
      SSH_FSM_SET_NEXT(ikev2_stop);
      return SSH_FSM_CONTINUE;
    }

  if (opt_client)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Starting negotiation thread"));
      ssh_fsm_thread_init(global_fsm, sa_thread, ikev2_sa_start,
			  NULL, NULL, NULL);
      client_running = TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Server only"));
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_wait)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Waiting for shutdown signal"));

  SSH_FSM_SET_NEXT(ikev2_stop);
  return SSH_FSM_SUSPENDED;
}

void ikev2_server_stopped(SshIkev2Error error, void *context)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("IKEv2 server shut down done = %d", error));
  if (error != SSH_IKEV2_ERROR_OK)
    ssh_warning("IKEv2 server stop failed");
  SSH_FSM_CONTINUE_AFTER_CALLBACK(main_thread);
}

SSH_FSM_STEP(ikev2_stop)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Shutting down server"));

  if (global_operation)
    {
      ssh_operation_abort(global_operation);
      global_operation = NULL;
    }
  if (client_running)
    {
      ssh_fsm_kill_thread(sa_thread);
    }
  ssh_cancel_timeouts(ikev2_cont, sa_thread);

  ssh_ikev2_ts_free(sad_handle, tsi_local);
  ssh_ikev2_ts_free(sad_handle, tsi_remote);

  SSH_FSM_SET_NEXT(ikev2_servers_stop);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_servers_stop)
{
  SshIkev2Server tmp;
  int i = 0;
  
  while (server[i] == NULL)
    i++;
  
  if (i < num_servers && server[i])
    {
      tmp = server[i];
      server[i] = NULL;
      SSH_FSM_ASYNC_CALL(ssh_ikev2_server_stop(tmp, 0,
					       ikev2_server_stopped,
					       NULL));
      SSH_NOTREACHED;
    }
  
  SSH_FSM_SET_NEXT(ikev2_uninit);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_uninit)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying IKEv2"));

  if (sad_handle)
    d_sad_destroy(sad_handle);
  d_pad_destroy();

  SSH_FSM_SET_NEXT(ikev2_stop_name_server);

  if (ikev2)
    ssh_ikev2_destroy(ikev2);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_stop_name_server)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Shutting down name server"));

  SSH_FSM_SET_NEXT(ikev2_finish);
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_finish)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Finish"));

  return SSH_FSM_FINISH;
}

/**********************************************************************/
/* sa_thread. */

SSH_FSM_STEP(ikev2_sa_allocate);
SSH_FSM_STEP(ikev2_ipsec_sa_create);
SSH_FSM_STEP(ikev2_ipsec_sa_child);
SSH_FSM_STEP(ikev2_ipsec_sa_rekey);
SSH_FSM_STEP(ikev2_ike_sa_update);
SSH_FSM_STEP(ikev2_ipsec_sa_delete);
SSH_FSM_STEP(ikev2_ike_sa_delete);
SSH_FSM_STEP(ikev2_ipsec_sa_done);

int g_wait_operations = 0;
Boolean g_ike_nomatch = 0;
Boolean g_ipsec_nomatch = 0;
Boolean g_error_seen = 0;

#define FAIL(m)					        \
do {							\
  ssh_warning(m);                                       \
  SSH_NOTREACHED;                                       \
  ssh_fsm_set_next(sa_thread, ikev2_ipsec_sa_done);	\
 } while (0)

SSH_FSM_STEP(ikev2_sa_start)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Sa negotiation start"));
  SSH_FSM_SET_NEXT(ikev2_sa_allocate);

  return SSH_FSM_CONTINUE;
}

void ikev2_sa_allocated(SshIkev2Error error,
			SshIkev2Sa ike_sa,
			void *context)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("IKEv2 sa allocate done = %d", error));
  if (error != SSH_IKEV2_ERROR_OK || ike_sa == NULL)
    FAIL("ipsec sa allocate failed");
  SSH_FSM_CONTINUE_AFTER_CALLBACK(sa_thread);
  global_operation = NULL;
  global_ike_sa = ike_sa;
}


SSH_FSM_STEP(ikev2_sa_allocate)
{
  SshIpAddrStruct ip_addr[1];
  SshUInt32 flags = 0;

  ssh_ipaddr_parse(ip_addr, opt_remote_ip);

#ifdef SSHDIST_IKE_MOBIKE
  if (mobike_supported)
    flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE;
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Allocate IKE SA"));
  SSH_FSM_SET_NEXT(ikev2_ipsec_sa_create);

  SSH_FSM_ASYNC_CALL(global_operation =
		     ssh_ikev2_ike_sa_allocate(server[0], ip_addr, flags,
					       ikev2_sa_allocated, NULL));

}


void ikev2_ipsec_sa_created(SshSADHandle sad_handle,
			    SshIkev2Sa sa,
			    SshIkev2ExchangeData ed,
			    SshIkev2Error error)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("IPsec SA create done = %d", error));
  SSH_ASSERT(global_spi_num < sizeof(global_inbound_spis) /
	     sizeof(*global_inbound_spis));
  if (error != SSH_IKEV2_ERROR_OK)
    FAIL("IPsec sa create failed");
  global_inbound_spis[global_spi_num++] = ed->ipsec_ed->spi_inbound;

  if (--g_wait_operations < 1)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(sa_thread);

  if (ed->ipsec_ed->operation_handle == global_operation)
    global_operation = NULL;
}

void ikev2_ipsec_sa_failed(SshSADHandle sad_handle,
			   SshIkev2Sa sa,
			   SshIkev2ExchangeData ed,
			   SshIkev2Error error)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("IPsec SA fail done = %d", error));
  if (error == SSH_IKEV2_ERROR_OK)
    FAIL("Non matching SA succeeded.");

  if (--g_wait_operations < 1)
    {
      SSH_FSM_CONTINUE_AFTER_CALLBACK(sa_thread);
      global_operation = NULL;
    }

  if (error != SSH_IKEV2_ERROR_SA_UNUSABLE &&
      error != SSH_IKEV2_ERROR_WINDOW_FULL)
    {
      /* This was some other error message that we do not know about. This
	 might be because of the run-encode-fail or something else. Consider
	 this as fatal error. */
      FAIL("Error: Got some other error message than what was expected.");
      global_ike_sa = NULL;
    }
}

SSH_FSM_STEP(ikev2_ipsec_sa_create)
{
  SshIkev2ExchangeData ed;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Create IPsec SA"));

  SSH_FSM_SET_NEXT(ikev2_ike_sa_delete);

  ssh_ikev2_ts_take_ref(sad_handle, tsi_local);
  ssh_ikev2_ts_take_ref(sad_handle, tsi_remote);

  ed = ssh_ikev2_ipsec_create_sa(global_ike_sa, 0);
  if (ed == NULL)
    {
      FAIL("Error allocating exchange data");
      return SSH_FSM_CONTINUE;
    }

  g_wait_operations = 1;
  SSH_FSM_ASYNC_CALL(global_operation =
		     ssh_ikev2_ipsec_send(ed, NULL, tsi_local, tsi_remote,
					  ikev2_ipsec_sa_created);
                     ssh_ikev2_ts_free(sad_handle, tsi_local);
		     ssh_ikev2_ts_free(sad_handle, tsi_remote);
		     );
}

void ikev2_cont(void *context)
{
  SSH_FSM_CONTINUE_AFTER_CALLBACK(context);
}

void ikev2_ike_sa_deleted(SshSADHandle sad_handle,
			  SshIkev2Sa ike_sa,
			  SshIkev2ExchangeData ed,
			  SshIkev2Error error)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("INFO IKE SA done = %d", error));
  if (error != SSH_IKEV2_ERROR_OK)
    FAIL("ssh_ikev2_delete_n failed");

  if (--g_wait_operations < 1)
    SSH_FSM_CONTINUE_AFTER_CALLBACK(sa_thread);
  global_operation = NULL;

}


SSH_FSM_STEP(ikev2_ike_sa_delete)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Delete IKE SA"));

  SSH_FSM_SET_NEXT(ikev2_ipsec_sa_done);

  if (global_ike_sa == NULL)
    return SSH_FSM_CONTINUE;
  g_wait_operations = 1;
  SSH_FSM_ASYNC_CALL(global_operation =
		     ssh_ikev2_ike_sa_delete(global_ike_sa, 0,
					     ikev2_ike_sa_deleted));
}

SSH_FSM_STEP(ikev2_ipsec_sa_done)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("IPsec SAs done, client in finish"));
  ssh_fsm_continue(main_thread);
  client_running = FALSE;
  return SSH_FSM_FINISH;
}

#ifdef WIN32
HANDLE exit_notify_thread;
SHELLEXECUTEINFO t_ike = {0};

DWORD WINAPI exit_server_notifier(void *context)
{
   /* Wait here for the process to finish */
   WaitForSingleObject(((SHELLEXECUTEINFO*)context)->hProcess,
                       60L*60L*1000L);
   ((SHELLEXECUTEINFO*)context)->hProcess = NULL;
  ssh_fsm_continue(main_thread);

  return ERROR_SUCCESS;
}
#else
pid_t parent_pid;
#endif /* WIN32 */

void ikev2_stop_signal(int signal, void *context)
{
  SSH_DEBUG(SSH_D_UNCOMMON, ("Shutting down (signal)"));
  ssh_fsm_continue(main_thread);
}

void ikev2_error_received(int signal, void *context)
{
  SSH_DEBUG(SSH_D_UNCOMMON, ("Client ended with error"));
  g_error_seen = 1;
}

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#ifdef SSHDIST_RADIUS
static Boolean test_configure_radius(char *url)
{
  SshRadiusUrlStatus url_status;
  SshRadiusClientParamsStruct radius_params;
  const char *str;

  SSH_ASSERT(radius_config == NULL);
  radius_config = ssh_xcalloc(1, sizeof(*radius_config));

  url_status = ssh_radius_url_isok(url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      str = ssh_find_keyword_name(ssh_radius_url_status_codes,
				  url_status);

      SSH_DEBUG(SSH_D_ERROR, ("Error parsing RADIUS url: %s",
			      (str != NULL ? str : "unknown error")));
      return FALSE;
    }

  if (ssh_radius_url_init_params(&radius_params, url) !=
      SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot initialize RADIUS params"));
      return FALSE;
    }

  if ((radius_config->radius_client = ssh_radius_client_create(&radius_params))
      == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error creating RADIUS client"));
      ssh_radius_url_uninit_params(&radius_params);
      return FALSE;
    }
  ssh_radius_url_uninit_params(&radius_params);

  if ((radius_config->radius_servers = ssh_radius_client_server_info_create())
      == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error adding RADIUS servers"));
      return FALSE;
    }

  if (ssh_radius_url_add_server(radius_config->radius_servers, url)
      != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_ERROR,  ("Error adding RADIUS server to server info"));
      return FALSE;
    }

  if (ssh_radius_url_create_avpset(&radius_config->default_avps, url)
      != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error creating default AVP set"));
      return FALSE;
    }

  /* XXX read from policy  */
  if (!ssh_radius_url_set_avpset_avp(radius_config->default_avps,
				     SSH_RADIUS_AVP_USER_NAME,
				     "bob", strlen("bob")))
    return FALSE;

  radius_config->ignore_radius_session_timeout = FALSE;
  return TRUE;
}
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

static void main_thread_destructor(SshFSM fsm, void *context)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Entered main thread destructor"));

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#ifdef SSHDIST_RADIUS
  if (radius_config)
    {
      ssh_radius_url_destroy_avpset(radius_config->default_avps);
      ssh_radius_client_server_info_destroy(radius_config->radius_servers);
      ssh_radius_client_destroy(radius_config->radius_client);

      ssh_xfree(radius_config);
      radius_config = NULL;
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
}


#define DEBUG_COLOR(_x,_y) "%c(27)%c(91)%c(" # _x ")%c(" # _y ")%c(109)"
#define DEBUG_COLOR_OFF() "%c(27)%c(91)%c(109)"

int main(int argc, char **argv)
{
  int c, errflg = 0;
  const char *debug_string = "Main=9,SshIkev2*=4,*Auth*=10,TestIkev2*=4";
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#ifdef SSHDIST_RADIUS
 char *radius_url = NULL;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */


  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, 
                         argv, 
                         "d:i:p:n:N:I:P:t:T:f:y:Y:r:g:xcseEm:1:2",
			 NULL))
         != EOF)
    {
      switch (c)
        {
	case 'c': opt_client++; break;
	case 's': opt_server++; break;
        case 'd': debug_string = ssh_optarg; break;
	case 'i': opt_local_ip = ssh_optarg; break;
	case 'p': opt_local_port = atoi(ssh_optarg); break;
	case 'n': opt_local_nat_port = atoi(ssh_optarg); break;
	case 'I': opt_remote_ip = ssh_optarg; break;
	case 'P': opt_remote_port = atoi(ssh_optarg); break;
	case 'N': opt_remote_nat_port = atoi(ssh_optarg); break;
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
	case 'e': use_eap = TRUE; break;
#ifdef SSHDIST_RADIUS
        case 'r': radius_url = ssh_optarg; break;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_MOBIKE
	case 'm' : mobike_supported = TRUE; break;
#endif /* SSHDIST_IKE_MOBIKE */
	case 't': opt_tsi_local_string = ssh_optarg; break;
	case 'T': opt_tsi_remote_string = ssh_optarg; break;
	case 'f': opt_policy = ssh_optarg; break;
	case 'g': cert_config = ssh_optarg; break;
	case 'x': use_certs = TRUE; break;
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
              "Usage: %s [-c | -s] "
	      "[-d debug_flags] [-i local_ip] "
	      "[-p local_port] [-n nat_port] "
	      "[-I remote_ip] [-P remote_port] [-N remote_nat_port] "
	      "[-t tsi_local] [-T tsi_remote] "
	      "[-f policy] "
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
	      "[-e] "
#ifdef SSHDIST_RADIUS
	      "[-r radius_url] "
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_MOBIKE
	      "[-m] "
#endif /* SSHDIST_IKE_MOBIKE */
	      "[-x] "
	      "[-g pad_policy] "
	      "\n",
	      program);
      exit(1);
    }

#ifdef DEBUG_LIGHT
  ssh_debug_set_level_string(debug_string);
#endif /* DEBUG_LIGHT */

#ifdef SSHDIST_IKE_CERT_AUTH
  if (!ssh_x509_library_initialize(NULL))
    ssh_fatal("Cannot initialize certificate and crypto library");
#else /* SSHDIST_IKE_CERT_AUTH */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */





  ssh_rand_seed(ssh_random_get_byte());

  memset(&params, 0, sizeof(params));

#ifdef SSHDIST_IKE_MOBIKE
  params.mobike_worry_counter = 2;
#endif /* SSHDIST_IKE_MOBIKE */
  params.retry_limit = 3;
  params.retry_timer_msec = 500;

  ssh_event_loop_initialize();
  ssh_event_loop_lock();

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#ifdef SSHDIST_RADIUS
  if (opt_client  == 0 && radius_url != NULL)
    {
      if (!test_configure_radius(radius_url))
	ssh_fatal("Cannot configure radius from input URL %s", radius_url);
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

  if (opt_client == 0 &&
      opt_server == 0)
    {
#ifdef WIN32
      TCHAR path[512];
      DWORD dwid;

      /* get full path for this application */
      if (GetModuleFileName(NULL, path, 512) == 0)
        ssh_fatal("Could not get module path to the application.");

      /* parse process parameters */
      t_ike.cbSize = sizeof(t_ike);
      t_ike.fMask = SEE_MASK_NOCLOSEPROCESS;
      t_ike.lpFile = path;
      t_ike.lpParameters = TEXT(" -c"); 
      t_ike.lpDirectory = TEXT("");
      t_ike.nShow = SW_SHOWNORMAL;

      /* execute client process */
      ShellExecuteEx(&t_ike);

      if (t_ike.hProcess == NULL)
        ssh_fatal("Shell execute failed");

      /* make client exit notifier */
      exit_notify_thread =
        CreateThread(NULL, 0, exit_server_notifier,
                     ((void*)&t_ike), 0, &dwid);
      if (exit_notify_thread == 0)
        ssh_fatal("create thread failed");

      SSH_DEBUG(3, ("Server start"));
#else /* WIN32 */
      parent_pid = fork();
      if (parent_pid < 0)
        ssh_fatal("Fork failed: %.200s", strerror(errno));
      /* In the client both opt_server and opt_client will have > 0
	 values, meaning that it is client, but it should kill server when it
	 is done. In server there is only the opt_server set. */
      opt_server++;
      if (parent_pid != 0)
        {
#ifdef DEBUG_LIGHT
	  const char *term;

          /* Parent, make this client */
	  term = getenv("TERM");
	  if (term != NULL && strcmp(term, "xterm") == 0)
	    ssh_debug_set_format_string("%W(75)(9)"
					DEBUG_COLOR(51,49)
					"CLIENT "/*"%Dh:%Dm:%Ds "*/
					"%m/%s:%n:%f "
					"                                     "
					"                                     "
					"%M"
					DEBUG_COLOR_OFF(),
					FALSE);
	  else
	    ssh_debug_set_format_string("%W(75)(9)"
					"%Dh:%Dm:%Ds "
					"CLIENT "
					"%m/%s:%n:%f "
					"                                     "
					"                                     "
					"%M",
					FALSE);

#endif /* DEBUG_LIGHT */

          SSH_DEBUG(SSH_D_HIGHSTART, ("Client start"));
	  opt_client++;
        }
      else
        {
#ifdef DEBUG_LIGHT
	  const char *term;

          /* Child, make this server */
	  term = getenv("TERM");
	  if (term != NULL && strcmp(term, "xterm") == 0)
	    ssh_debug_set_format_string("%W(75)(9)"
					DEBUG_COLOR(51,52)
					"SERVER "/*"%Dh:%Dm:%Ds "*/
					"%m/%s:%n:%f "
					"                                     "
					"                                     "
					"%M"
					DEBUG_COLOR_OFF(),
					FALSE);
	  else
	    ssh_debug_set_format_string("%W(75)(9)"
					"%Dh:%Dm:%Ds "
					"SERVER "
					"%m/%s:%n:%f "
					"                                     "
					"                                     "
					"%M",
					FALSE);
#endif /* DEBUG_LIGHT */

          SSH_DEBUG(SSH_D_HIGHSTART, ("Server start, client pid = %d",
				      parent_pid));
        }
#endif /* !WIN32 */
    }
  else
    {
#ifdef DEBUG_LIGHT
      const char *term;

      term = getenv("TERM");
      if (term != NULL && strcmp(term, "xterm") == 0)
	{
	  ssh_debug_set_format_string("%W(75)(9)"
				      "%?[<(3)]" DEBUG_COLOR(51,49)
				      "%/[=(4)]" DEBUG_COLOR(51,50)
				      "%/[=(5)]" DEBUG_COLOR(51,52)
				      "%/[<(8)]" DEBUG_COLOR(51,53)
				      "%/[=(9)]" DEBUG_COLOR_OFF()
				      "%:" DEBUG_COLOR(51,54)
				      "%."
				      "%Dh:%Dm:%Ds "
				      "%m/%s:%n:%f "
				      "                                     "
				      "                                     "
				      "%M"
				      DEBUG_COLOR_OFF(),
				      FALSE);
	}
      else
	{
	  ssh_debug_set_format_string("%W(75)(9)"
				      "%."
				      "%Dh:%Dm:%Ds "
				      "%m/%s:%n:%f "
				      "                                     "
				      "                                     "
				      "%M",
				      FALSE);
	}
#endif /* DEBUG_LIGHT */
    }

  if (opt_local_ip == NULL)
    opt_local_ip = "127.0.0.1";
  if (opt_remote_ip == NULL)
    opt_remote_ip = "127.0.0.1";
  if (opt_tsi_local_string == NULL)
    opt_tsi_local_string = "ipv4(127.0.0.1)";
  if (opt_tsi_remote_string == NULL)
    opt_tsi_remote_string = "ipv4(127.0.0.1)";

  if (opt_client)
    {
      if (opt_local_port == 0)
	opt_local_port = 1501;
      if (opt_local_nat_port == 0)
	opt_local_nat_port = 4501;
      if (opt_remote_port == 0)
	opt_remote_port = 1500;
      if (opt_remote_nat_port == 0)
	opt_remote_nat_port = 4500;
    }
  else
    {
      if (opt_local_port == 0)
	opt_local_port = 1500;
      if (opt_local_nat_port == 0)
	opt_local_nat_port = 4500;
      if (opt_remote_port == 0)
	opt_remote_port = 1501;
      if (opt_remote_nat_port == 0)
	opt_remote_nat_port = 4501;
    }

  ssh_fsm_init(global_fsm, NULL);

  ssh_fsm_thread_init(global_fsm, main_thread, ikev2_init, NULL,
		      main_thread_destructor, NULL);
#ifdef DEBUG_LIGHT
  ssh_fsm_set_thread_name(main_thread, "MainThread");
#endif /* DEBUG_LIGHT */

#ifndef WIN32
  ssh_register_signal(SIGHUP, ikev2_stop_signal, NULL);
  ssh_register_signal(SIGUSR1, ikev2_error_received, NULL);
#endif /* WIN32 */
#ifndef _WIN32_WCE
  ssh_register_signal(SIGINT, ikev2_stop_signal, NULL);
#endif /* _WIN32_WCE */

  ssh_event_loop_unlock();
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
  if (t_ike.hProcess)
    {
      TerminateProcess(t_ike.hProcess, 0);
    }
#else /* WIN32 */
  if (parent_pid != 0)
    {
      /* Parent, kill child server. */
      if (g_error_seen)
	{
	  kill(parent_pid, SIGUSR1);
	}
      kill(parent_pid, SIGHUP);
      sleep(5);
      kill(parent_pid, SIGHUP);
    }
#endif /* WIN32 */

  ssh_fsm_uninit(global_fsm);

  ssh_event_loop_unlock();
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */
  ssh_event_loop_uninitialize();

#ifdef SSHDIST_IKE_CERT_AUTH
  ssh_x509_library_uninitialize();
#else /* SSHDIST_IKE_CERT_AUTH */
  ssh_crypto_library_uninitialize();
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef DEBUG_LIGHT
  ssh_debug_uninit();
#endif /* DEBUG_LIGHT */
  ssh_global_uninit();











  if (g_error_seen)
    {
      ssh_warning("Errors seen during execution, exiting with error code");
      exit(1);
    }

  return 0;
}
