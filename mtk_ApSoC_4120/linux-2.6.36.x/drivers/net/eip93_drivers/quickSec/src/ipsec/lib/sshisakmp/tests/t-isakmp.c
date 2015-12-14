/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/t-isakmp.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 11:22 Sep 15 1997 kivinen
 *        Last Modification : 15:04 Nov  1 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.2999
 *        
 *
 *        Description       : Isakmp test module
 *
 *        $Log: t-isakmp.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:50  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_util.h"
#include "sshdebug.h"
#include "sshenum.h"
#include "sshtimeouts.h"
#include "sshtcp.h"
#include "sshgetput.h"
#ifdef SSHDIST_IKE_CERT_AUTH
#include "sshfileio.h"
#endif /* SSHDIST_IKE_CERT_AUTH */
#include "sshber.h"
#include "sshurl.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshglobals.h"
#include "sshexternalkey.h"
#include "sshnameserver.h"

#ifdef SSHDIST_LDAP
#include "sshldap.h"
#endif /* SSHDIST_LDAP */

#ifdef SSHDIST_IKE_CERT_AUTH
#include "sshasn1.h"
#include "x509.h"
#include "cmi.h"
#include "sshbase64.h"

#endif /* SSHDIST_IKE_CERT_AUTH */

#include "test_policy.h"
#ifdef SSHDIST_ISAKMP_CFG_MODE
#include "xauth_demo.h"
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#define SSH_DEBUG_MODULE "SshIkeTest"

#undef DO_CERT_TESTS
#ifdef SSHDIST_IKE_CERT_AUTH






#endif /* SSHDIST_IKE_CERT_AUTH */

/* Program name */
char *program;

/* Call fatal in case of error */
Boolean call_fatal_on_error;

void test_callback(void *context);
void test_ipsec_delete_callback(void *context);
void cleanup_deletes(TestScriptContext test_context);

#ifdef WIN32
DWORD WINAPI exit_server_notifier(void *context)
{
   assert(context);

   /* Wait here for the process to finish */
   WaitForSingleObject(((SHELLEXECUTEINFO*)context)->hProcess,
                       60L*60L*1000L);
   ((SHELLEXECUTEINFO*)context)->hProcess = NULL;
   ssh_event_loop_abort();
}

BOOL WINAPI control_handler(DWORD dwCtrlType)
{
  switch (dwCtrlType)
    {
    case CTRL_BREAK_EVENT:
    case CTRL_C_EVENT:
      /* stop console application if ^C -pressed */
      ssh_event_loop_abort();
      return TRUE;
      break;
    }

  return FALSE;
}
#else  /* WIN32 */
void received_signal(int signal, void *context)
{
  TestScriptContext test_context = context;

  SSH_DEBUG(3, ("Signal received shutting down the server"));
  if (test_context->server_context)
    ssh_ike_stop_server(test_context->server_context);
  test_context->server_context = NULL;
  if (test_context->isakmp_context)
    ssh_ike_uninit(test_context->isakmp_context);
  test_context->isakmp_context = NULL;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef DO_CERT_TESTS
  if (test_context->pm != NULL &&
      ((SshIkePMCertCache) (test_context->pm->certificate_cache))->cert_cache
      != NULL)
    {
      ssh_cm_free(((SshIkePMCertCache) (test_context->pm->
                                        certificate_cache))->cert_cache);
      ((SshIkePMCertCache) (test_context->pm->
                            certificate_cache))->cert_cache = NULL;
    }
#endif /* DO_CERT_TESTS */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_unregister_signal(SIGHUP);
  ssh_unregister_signal(SIGINT);
  ssh_unregister_signal(SIGQUIT);
  ssh_unregister_signal(SIGTERM);

  ssh_unregister_signal(SIGUSR1);
  ssh_unregister_signal(SIGUSR2);
  ssh_cancel_timeouts(test_callback, test_context);
  cleanup_deletes(test_context);
  return;
}
#endif /* WIN32 */

Boolean dump_statistics_negotiation(SshIkeNegotiation negotiation,
                                    SshIkeNegotiationStatistics statistics,
                                    void *context)
{
  if (statistics->quick_mode)
    {
      ssh_debug("  Quick mode negotiation, message id = 0x%08x",
                statistics->quick_mode_pm_info->message_id);
      ssh_debug("    Connection %s:%s <-> %s:%s",
                statistics->quick_mode_pm_info->local_ip,
                statistics->quick_mode_pm_info->local_port,
                statistics->quick_mode_pm_info->remote_ip,
                statistics->quick_mode_pm_info->remote_port);
      ssh_debug("    Identities %s/%s <-> %s/%s",
                statistics->quick_mode_pm_info->local_i_id_txt,
                statistics->quick_mode_pm_info->local_r_id_txt,
                statistics->quick_mode_pm_info->remote_i_id_txt,
                statistics->quick_mode_pm_info->remote_r_id_txt);
      ssh_debug("    This end is %s",
                statistics->quick_mode_pm_info->this_end_is_initiator ?
                "initiator" : "responder");
      ssh_debug("    SA expire %d kB, %d seconds",
                statistics->quick_mode_pm_info->sa_expire_timer_kb,
                statistics->quick_mode_pm_info->sa_expire_timer_sec);
    }
  else
    {
      ssh_debug("  Phase 2 negotiation, exchange_type = %d, "
                "message id = 0x%08x",
                statistics->phaseii_pm_info->exchange_type,
                statistics->phaseii_pm_info->message_id);
      ssh_debug("    Connection %s:%s <-> %s:%s",
                statistics->phaseii_pm_info->local_ip,
                statistics->phaseii_pm_info->local_port,
                statistics->phaseii_pm_info->remote_ip,
                statistics->phaseii_pm_info->remote_port);
      ssh_debug("    This end is %s",
                statistics->phaseii_pm_info->this_end_is_initiator ?
                "initiator" : "responder");
    }
  ssh_debug("    Caller notification%s sent",
            statistics->caller_notification_sent ? "" : " not");
  if (statistics->waiting_for_done)
    ssh_debug("    Waiting for done");
  if (statistics->waiting_for_remove)
    ssh_debug("    Waiting for remove");
  if (statistics->waiting_for_policy_manager)
    ssh_debug("    Waiting for policy manager to respond");

  return TRUE;
}

Boolean dump_statistics_isakmp_sa(SshIkeNegotiation negotiation,
                                  SshIkeStatistics statistics,
                                  void *context)
{
  SshUInt32 *cnt = (SshUInt32 *) context;
  char *t1, *t2;
  int i;

  ssh_debug("ISAKMP SA %d, Cookies: %08x %08x - %08x %08x",
            *cnt,
            SSH_GET_32BIT(statistics->pm_info->cookies->initiator_cookie),
            SSH_GET_32BIT(statistics->pm_info->cookies->initiator_cookie + 4),
            SSH_GET_32BIT(statistics->pm_info->cookies->responder_cookie),
            SSH_GET_32BIT(statistics->pm_info->cookies->responder_cookie + 4));
  ssh_debug("  Connection %s:%s <-> %s:%s",
            statistics->pm_info->local_ip, statistics->pm_info->local_port,
            statistics->pm_info->remote_ip, statistics->pm_info->remote_port);
  ssh_debug("  Identities %s <-> %s",
            statistics->pm_info->local_id_txt,
            statistics->pm_info->remote_id_txt);
  ssh_debug("  ISAKMP Version number %d.%d, exchange_type = %d",
            statistics->pm_info->major_version,
            statistics->pm_info->minor_version,
            statistics->pm_info->exchange_type);
  ssh_debug("  This end is %s, authentication type = %d",
            statistics->pm_info->this_end_is_initiator ?
            "initiator" : "responder", statistics->pm_info->auth_method);
  ssh_debug("  SA Created = %s, expires = %s",
            (t1 = ssh_readable_time_string(statistics->pm_info->sa_start_time,
                                           FALSE)),
            (t2 = ssh_readable_time_string(statistics->pm_info->sa_expire_time,
                                           FALSE)));
  ssh_xfree(t1);
  ssh_xfree(t2);

#ifdef SSHDIST_IKE_CERT_AUTH
  ssh_debug("  SA Received %d certificates",
            statistics->pm_info->number_of_certificates);
  for (i = 0; i < statistics->pm_info->number_of_certificates; i++)
    {
      SshX509Certificate cert;
      char *ldap_name;

      if (statistics->pm_info->certificate_encodings[i] !=
          SSH_IKE_CERTIFICATE_ENCODING_X509_SIG &&
          statistics->pm_info->certificate_encodings[i] !=
          SSH_IKE_CERTIFICATE_ENCODING_X509_KE)
        {
          ssh_debug("    Certificate %d has type %d", i,
                    statistics->pm_info->certificate_encodings[i]);
          continue;
        }
      else
        {
          ssh_debug("    Certificate %d is X.509 certificate", i);
        }
      cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (cert == NULL)
        {
          ssh_debug("    Out of memory decoding certificate");
          continue;
        }
      if (ssh_x509_cert_decode((const unsigned char *)
                               statistics->pm_info->certificates[i],
                               statistics->pm_info->certificate_lens[i],
                               cert) != SSH_X509_OK)
        {
          ssh_x509_cert_free(cert);
          ssh_debug("    Could not decode certificate number %d", i);
          continue;
        }
      if (ssh_x509_cert_get_subject_name(cert, &ldap_name))
        {
          ssh_debug("    Certificate %d subject name = %s", i, ldap_name);
          ssh_xfree(ldap_name);
        }
      else
        {
          ssh_debug("    Certificate %d doesn't have subject name", i);
        }

      if (ssh_x509_cert_get_issuer_name(cert, &ldap_name))
        {
          ssh_debug("    Certificate %d issuer name = %s", i, ldap_name);
          ssh_xfree(ldap_name);
        }
      else
        {
          ssh_debug("    Certificate %d doesn't have issuer name", i);
        }
      ssh_x509_cert_free(cert);
    }
#endif /* SSHDIST_IKE_CERT_AUTH */


  if (statistics->phase_1_done)
    ssh_debug("  Phase 1 is already done");
  else
    ssh_debug("  Phase 1 is not yet done");

  ssh_debug("  This ISAKMP SA contains %d negotiations on progress "
            "and %d private groups",
            statistics->number_of_negotiations,
            statistics->private_groups_count);
  ssh_debug("  This ISAKMP SA was last used %s and it has transferred "
            "%d bytes",
            (t1 = ssh_readable_time_string(statistics->last_use_time, FALSE)),
            statistics->byte_count);
  ssh_xfree(t1);
  ssh_debug("  Algorithms are %s, %s, %s",
            statistics->encryption_algorithm_name,
            statistics->hash_algorithm_name,
            statistics->prf_algorithm_name);
  ssh_debug("  Retry limit is %d, retry timer is %d.%06d, "
            "and max retry %d.%06d",
            statistics->default_retry_limit,
            statistics->default_retry_timer,
            statistics->default_retry_timer_usec,
            statistics->default_retry_timer_max,
            statistics->default_retry_timer_max_usec);
  ssh_debug("  Expire timer is %d.%06d",
            statistics->default_expire_timer,
            statistics->default_expire_timer_usec);
  ssh_debug("  Caller notification%s sent",
            statistics->caller_notification_sent ? "" : " not");
  if (statistics->waiting_for_done)
    ssh_debug("  Waiting for done");
  if (statistics->waiting_for_remove)
    ssh_debug("  Waiting for remove");
  if (statistics->waiting_for_policy_manager)
    ssh_debug("  Waiting for policy manager to respond");

  ssh_ike_foreach_negotiation(negotiation, dump_statistics_negotiation, NULL);
  (*cnt)++;
  return TRUE;
}

void dump_statistics(int signal, void *context)
{
  TestScriptContext test_context = context;
  SshUInt32 cnt = 0;

  ssh_debug("Dumping out statistics for all ISAKMP SAs:");
  ssh_ike_foreach_isakmp_sa(test_context->server_context,
                            dump_statistics_isakmp_sa,
                            &cnt);
  ssh_debug("Dumped out %d ISAKMP SAs", cnt);
}

void test_ipsec_delete_callback(void *context)
{
  TestDeleteContext del = (TestDeleteContext) context;
  TestScriptContext test_context = del->test_context;
  TestDeleteContext *p;
  SshIkeErrorCode ret;

  phase_ii++;
  ret = ssh_ike_connect_delete(del->server, NULL,
                               del->remote_name, del->remote_port,
                               SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA |
                               SSH_IKE_FLAGS_USE_DEFAULTS,
                               SSH_IKE_DOI_IPSEC, del->protocol_id,
                               1, &del->spi, del->spi_size);
  if (ret != SSH_IKE_ERROR_OK)
    {
      phase_ii--;
      if (ret == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
        {
          SSH_IKE_DEBUG(3, NULL, ("Ipsec delete notify send failed, "
                                  "because no sa found (deleted?)"));
          SSH_DEBUG(3, ("ssh_ike_connect_delete failed, "
                        "because no sa found (deleted?)"));
        }
      else
        {
          SSH_IKE_DEBUG(3, NULL, ("Ipsec delete notify send failed"));
          SSH_DEBUG(3, ("ssh_ike_connect_delete failed"));
          if (call_fatal_on_error)
            ssh_fatal("ssh_ike_connect_delete failed");
        }
    }
  ssh_xfree(del->spi);
  ssh_xfree(del->remote_name);
  ssh_xfree(del->remote_port);
  for (p = &(test_context->deletes); *p != NULL; p = &((*p)->next))
    {
      if (*p == del)
        {
          *p = del->next;
          break;
        }
    }
  del->next = NULL;
  ssh_xfree(del);
}

void cleanup_deletes(TestScriptContext test_context)
{
  TestDeleteContext del, next;

  for (del = test_context->deletes; del != NULL; del = next)
    {
      ssh_xfree(del->spi);
      ssh_xfree(del->remote_name);
      ssh_xfree(del->remote_port);
      next = del->next;
      del->next = NULL;
      ssh_cancel_timeouts(test_ipsec_delete_callback, del);
      ssh_xfree(del);
    }
  test_context->deletes = NULL;
}

void sa_callback(SshIkeNegotiation negotiation,
                 SshIkePMPhaseQm pm_info,
                 int number_of_sas,
                 SshIkeIpsecSelectedSA sas,
                 SshIkeIpsecKeymat keymat,
                 void *sa_callback_context)
{
  int i, j;
  SshCryptoStatus cret;
  TestScriptContext test_context = (TestScriptContext) sa_callback_context;

  for (i = 0; i < number_of_sas; i++)
    {
      for (j = 0; j < sas[i].number_of_protocols; j++)
        {
          int key_len;
          unsigned char key_out[1024];
          TestDeleteContext del;

	  key_len = 0;

          if (sas[i].protocols[j].protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
            {
              switch (sas[i].protocols[j].transform_id.ipsec_ah)
                {
                case SSH_IKE_IPSEC_AH_TRANSFORM_AH_MD5: key_len = 128; break;
                case SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA: key_len = 160; break;
                case SSH_IKE_IPSEC_AH_TRANSFORM_AH_DES: key_len = 64; break;
                default: key_len = 256; break;
                }
            }
          else if (sas[i].protocols[j].protocol_id ==
                   SSH_IKE_PROTOCOL_IPSEC_ESP)
            {
              switch (sas[i].protocols[j].transform_id.ipsec_esp)
                {
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV64:
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES:
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV32:
                  key_len = 64; break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3DES:
                  key_len = 192; break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC5:
                  key_len = -128; break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_IDEA:
                  key_len = 128; break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAST:
                  key_len = -128;break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH:
                  key_len = -128; break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3IDEA:
                  key_len = 384;break;
                case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC4:
                  key_len = -128; break;
                default: key_len = 128; break;
                }
              if (key_len < 0)
                {
                  if (sas[i].protocols[j].attributes.key_length != 0 &&
                      sas[i].protocols[j].attributes.key_length < 256)
                    key_len = sas[i].protocols[j].attributes.key_length;
                  else
                    key_len = -key_len;
                }
              switch (sas[i].protocols[j].attributes.auth_algorithm)
                {
                case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_MD5:
                  key_len += 128; break;
                case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA_1:
                  key_len += 160; break;
                default:
                  break;
                }
            }

          cret = ssh_ike_ipsec_keys(negotiation, keymat,
                                    sas[i].protocols[j].spi_size_in,
                                    sas[i].protocols[j].spi_in,
                                    sas[i].protocols[j].protocol_id,
                                    key_len, key_out);
          if (cret != SSH_CRYPTO_OK)
            {
              if (call_fatal_on_error)
                ssh_fatal("ssh_ike_ipsec_keys failed: %s",
                          ssh_crypto_status_message(cret));
              ssh_warning("ssh_ike_ipsec_keys failed: %s",
                          ssh_crypto_status_message(cret));
              continue;
            }

          SSH_IKE_DEBUG_BUFFER(8, negotiation, "Ipsec key in",
                               (key_len + 7) / 8, key_out);

          SSH_DEBUG(8,
                    ("Ipsec key in = %08x %08x %08x %08x %08x %08x %08x %08x",
                     SSH_GET_32BIT(key_out),
                     SSH_GET_32BIT(key_out + 4),
                     SSH_GET_32BIT(key_out + 8),
                     SSH_GET_32BIT(key_out + 12),
                     SSH_GET_32BIT(key_out + 16),
                     SSH_GET_32BIT(key_out + 20),
                     SSH_GET_32BIT(key_out + 24),
                     SSH_GET_32BIT(key_out + 28)));

          cret = ssh_ike_ipsec_keys(negotiation, keymat,
                                    sas[i].protocols[j].spi_size_out,
                                    sas[i].protocols[j].spi_out,
                                    sas[i].protocols[j].protocol_id,
                                    key_len, key_out);
          if (cret != SSH_CRYPTO_OK)
            {
              if (call_fatal_on_error)
                ssh_fatal("ssh_ike_ipsec_keys failed: %s",
                          ssh_crypto_status_message(cret));
              ssh_warning("ssh_ike_ipsec_keys failed: %s",
                          ssh_crypto_status_message(cret));
              continue;
            }

          SSH_IKE_DEBUG_BUFFER(8, negotiation, "Ipsec key out",
                               (key_len + 7) / 8, key_out);
          SSH_DEBUG(8,
                    ("Ipsec key out = %08x %08x %08x %08x %08x %08x %08x %08x",
                     SSH_GET_32BIT(key_out),
                     SSH_GET_32BIT(key_out + 4),
                     SSH_GET_32BIT(key_out + 8),
                     SSH_GET_32BIT(key_out + 12),
                     SSH_GET_32BIT(key_out + 16),
                     SSH_GET_32BIT(key_out + 20),
                     SSH_GET_32BIT(key_out + 24),
                     SSH_GET_32BIT(key_out + 28)));

          del = ssh_xcalloc(1, sizeof(struct TestDeleteContextRec));
          del->test_context = test_context;
          del->next = test_context->deletes;
          test_context->deletes = del;
          del->server = test_context->server_context;
          del->protocol_id = sas[i].protocols[j].protocol_id;
          del->spi_size = sas[i].protocols[j].spi_size_out;
          del->spi = ssh_xmemdup(sas[i].protocols[j].spi_out, del->spi_size);
          del->remote_name = ssh_xstrdup(pm_info->remote_ip);
          del->remote_port = ssh_xstrdup(pm_info->remote_port);
          ssh_xregister_timeout(ssh_random_get_byte() % 10, 0,
                               test_ipsec_delete_callback,
                               del);
        }
    }

  if (test_context->test == TEST_SERVER_ISAKMP)
    ssh_event_loop_abort();
  return;
}

void restart_ike_delayed(void *context)
{
  TestScriptContext test_context = context;
  ssh_debug("Restarting ike");

  ssh_ike_stop_server(test_context->server_context);
  test_context->server_context =
    ssh_ike_start_server(test_context->isakmp_context,
                         NULL, NULL, test_context->pm, sa_callback,
                         test_context);
  if (test_context->server_context == NULL)
    {
      SSH_IKE_DEBUG(3, NULL, ("Starting isakmp server failed, "
                              "address propably already in use, "
                              "try some other port instead "
                              "or wait some time"));
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_start_server failed");
      /* Cancel all timeouts, and if the server is down, then we should
         exit the event loop. */
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, test_context);
      ssh_warning("ssh_ike_start_server failed");
    }
}

void restart_ike(int signal, void *context)
{
  ssh_xregister_timeout(0, 0, restart_ike_delayed, context);
}


const SshKeywordStruct test_cases[] = {
  { "isakmp", TEST_ISAKMP },
  { "ipsec", TEST_IPSEC },
  { "ngm", TEST_NGM },
#ifdef SSHDIST_ISAKMP_CFG_MODE
  { "cfg", TEST_CFG },
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  { "sleep", TEST_SLEEP },
  { "clear", TEST_CLEAR },
  { "isakmp_loop", TEST_LOOP_ISAKMP },
  { "isakmp_async_loop", TEST_LOOP_ASYNC_ISAKMP },
  { "ipsec_loop", TEST_LOOP_IPSEC },
  { "isakmp_test_client", TEST_CLIENT_ISAKMP },
  { "isakmp_test_server", TEST_SERVER_ISAKMP },
  { NULL, 0 }
};

void ike_notify_callback(SshIkeNotifyMessageType error,
                         SshIkeNegotiation negotiation,
                         void *callback_context)
{
  TestScriptContext context = (TestScriptContext) callback_context;

  if (error == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      SSH_IKE_DEBUG(4, negotiation, ("Negotiation succeeded"));
      SSH_DEBUG(4, ("Negotiation %d/0x%x succeeded", context->test,
                    context->current_test_count));
    }
  else
    {
      SSH_IKE_DEBUG(4, negotiation,
                    ("Negotiation failed with error code = %s (%d)",
                     ssh_ike_error_code_to_string(error), error));
      SSH_DEBUG(3, ("Negotiation %d/0x%x failed with error code = %s (%d)",
                    context->test, context->current_test_count,
                    ssh_ike_error_code_to_string(error), error));
      if (call_fatal_on_error)
        {
          ssh_fatal("Negotiation %d/0x%x failed with error code = %s (%d)",
                    context->test, context->current_test_count,
                    ssh_ike_error_code_to_string(error), error);
        }
      ssh_xregister_timeout(0, 0, test_callback, context);
      return;
    }
  
  test_callback(context);
  return;
}

void ike_async_notify_callback(SshIkeNotifyMessageType error,
                               SshIkeNegotiation negotiation,
                               void *callback_context)
{
  TestScriptContext context = (TestScriptContext) callback_context;

  context->completed_ops++;

  if (error == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      SSH_IKE_DEBUG(4, negotiation, ("Negotiation succeeded"));
    }
  else
    {
      SSH_IKE_DEBUG(4, negotiation,
                    ("Negotiation failed with error code = %s (%d)",
                     ssh_ike_error_code_to_string(error), error));
      ssh_fatal("IKE connection has failed with error %d", error);
    }

  if (context->completed_ops == context->total_ops)
    { 
      SshUInt64 s;
      SshUInt32 ns, sec;
      
      ssh_time_measure_stop(&context->timer);
      ssh_time_measure_get_value(&context->timer, &s, &ns);
      sec = (SshUInt32)s;
      
      printf("Time consumed: %ld secs and %ld milli secs, "
             "%ld operations completed \n",
             sec, ns / 1000000, context->completed_ops);   

      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);
      ssh_event_loop_abort();
      exit(0);
      return;  
    }
  
  /* Debug ouput intermediate progress */
  if (context->completed_ops % 25 == 0)
    {
      SshUInt64 s;
      SshUInt32 ns, sec;
      ssh_time_measure_get_value(&context->timer, &s, &ns);
      sec = (SshUInt32)s;
      
      SSH_DEBUG(5, ("Time consumed so far %ld secs and %ld milli secs, "
                    "%ld operations completed \n",
                    sec, ns / 1000000, context->completed_ops));
    }
  
  return;
}




unsigned char zeros[32];

SshIkePayloadID ike_fill_id(SshIkeIpsecIdentificationType type,
                            SshIkeIpsecIPProtocolID proto,
                            SshUInt16 port,
                            const char *name)
{
  SshIkePayloadID id;
  int len;
  SshIpAddrStruct ipaddr;

  id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));
  id->id_type = type;
  id->protocol_id = proto;
  id->port_number = port;
  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv4_addr);
      id->identification_len = 4;
      break;
    case IPSEC_ID_FQDN:
      id->identification.fqdn = ssh_xstrdup(name);
      id->identification_len = strlen((char *) id->identification.fqdn);
      break;
    case IPSEC_ID_USER_FQDN:
      len = strlen(program) + strlen(name) + 2;
      id->identification.fqdn = ssh_xmalloc(len);
      ssh_snprintf((char *) id->identification.fqdn, len, "%s@%s", program,
                   name);
      id->identification_len = len - 1;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv4_addr_subnet);
      memset(id->identification.ipv4_addr_netmask, 255, 4);
      id->identification_len = 8;
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv4_addr_range1);
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv4_addr_range2);
      id->identification_len = 8;
      break;
    case IPSEC_ID_IPV6_ADDR:
      memset(id->identification.ipv6_addr, 0, 16);
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv6_addr + 12);
      id->identification_len = 16;
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      memset(id->identification.ipv6_addr_subnet, 0, 16);
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv6_addr_subnet + 12);
      memset(id->identification.ipv6_addr_netmask, 255, 16);
      id->identification_len = 32;
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      memset(id->identification.ipv6_addr_range1, 0, 16);
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv6_addr_range1 + 12);
      memset(id->identification.ipv6_addr_range2, 0, 16);
      if (!ssh_ipaddr_parse(&ipaddr, name))
        {
          if (call_fatal_on_error)
             ssh_fatal("Invalid ip-number");
          ssh_warning("Invalid ip-number");
          return NULL;
        }
      SSH_IP4_ENCODE(&ipaddr, id->identification.ipv6_addr_range2 + 12);
      id->identification_len = 32;
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      id->identification.asn1_data = ssh_xstrdup("Junkkia");
      id->identification_len =
        strlen((char *) id->identification.asn1_data);
      break;
    case IPSEC_ID_KEY_ID:
      id->identification.key_id = ssh_xstrdup("Junkkia");
      id->identification_len =
        strlen((char *) id->identification.key_id);
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      ssh_fatal("XXX Not yet supported");
      break;
#endif /* SSHDIST_IKE_ID_LIST */
    }
  return id;
}

void ike_fill_grp_params(SshIkeSAAttributeList list, int grp,
                         SshMPInteger *options)
{
  SshMPIntegerStruct tmp[1];

  if (options)
    {
      switch (grp)
        {
        case 0: /* RSA */
          ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                                SSH_IKE_VALUES_GRP_TYPE_MODP);
          break;
        case 1: /* ECP */
          ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                                SSH_IKE_VALUES_GRP_TYPE_ECP);
          break;
        case 2: /* EC2N */
          ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                                SSH_IKE_VALUES_GRP_TYPE_EC2N);
          break;
        }
      ssh_ike_data_attribute_list_add_mpint(
                                        list, SSH_IKE_CLASSES_GRP_PRIME,
                                        options[MPINT_OPTION_PHASE_1_PRIME]);
      ssh_ike_data_attribute_list_add_mpint(
                                        list, SSH_IKE_CLASSES_GRP_GEN1,
                                        options[MPINT_OPTION_PHASE_1_GEN1]);
      if (grp > 0)
        {
          ssh_ike_data_attribute_list_add_mpint(
                                        list, SSH_IKE_CLASSES_GRP_GEN2,
                                        options[MPINT_OPTION_PHASE_1_GEN2]);
          ssh_ike_data_attribute_list_add_mpint(
                                        list,
                                        SSH_IKE_CLASSES_GRP_CURVEA,
                                        options[MPINT_OPTION_PHASE_1_CURVEA]);
          ssh_ike_data_attribute_list_add_mpint(
                                        list,
                                        SSH_IKE_CLASSES_GRP_CURVEB,
                                        options[MPINT_OPTION_PHASE_1_CURVEB]);
          ssh_ike_data_attribute_list_add_mpint(
                                        list,
                                        SSH_IKE_CLASSES_GRP_ORDER,
                                        options[MPINT_OPTION_PHASE_1_ORDER]);
          ssh_ike_data_attribute_list_add_mpint(
                                list,
                                SSH_IKE_CLASSES_GRP_CARDINALITY,
                                options[MPINT_OPTION_PHASE_1_CARDINALITY]);
        }
      return;
    }

  ssh_mprz_init(tmp);

  switch (grp)
    {
    case 0:
      /* RSA Group */
      ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                            SSH_IKE_VALUES_GRP_TYPE_MODP);
      ssh_mprz_set_str(tmp,
                       "2402446397916800587203161115380919919101477704283249"
                       "4703028003761374916599167494583876194866160745979948"
                       "4054706036700683783803157304995236873256870673881872"
                       "2186710399107542491436753573625778328000710503359099"
                       "595423805076306793358719", 0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_PRIME,
                                            tmp);
      ssh_mprz_set_str(tmp, "2", 0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN1,
                                            tmp);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case 1:
      /* ECP group */
      ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                            SSH_IKE_VALUES_GRP_TYPE_ECP);
      ssh_mprz_set_str(tmp, "31407857097127860965216287356072559134859825543",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_PRIME,
                                            tmp);

      ssh_mprz_set_str(tmp, "2731256435122317801261871679028549091389013906",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_CURVEA,
                                             tmp);

      ssh_mprz_set_str(tmp, "10714317566020843022911894761291265613594418240",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_CURVEB,
                                             tmp);

      ssh_mprz_set_str(tmp, "31407857097127860965216427618348169229298502938",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list,
                                            SSH_IKE_CLASSES_GRP_CARDINALITY,
                                             tmp);

      ssh_mprz_set_str(tmp, "16392655484387136812157475999461840857228033620",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN1,
                                            tmp);

      ssh_mprz_set_str(tmp, "2799086322187201568878931628895797117411224036",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN2,
                                            tmp);

      ssh_mprz_set_str(tmp, "402664834578562320066877277158309861914083371",
                       0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_ORDER,
                                            tmp);
      break;
#endif /* SSHDIST_CRYPT_ECP */





































    case 3:
      /* 2nd RSA Group */
      ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                            SSH_IKE_VALUES_GRP_TYPE_MODP);
      ssh_mprz_set_str(tmp,
                       "14119048864730642695149794793967942497493137936919"
                       "96901464401265624664092916197582344104304920877361"
                       "72907390888290563508264155720409054555597508847013"
                       "93262430363329380943564299878455404479180074914741"
                       "93914515342005599350136282025940442202348649212123"
                       "60009141120460241474543779193546148756924903705307"
                       "227659707", 0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_PRIME,
                                            tmp);
      ssh_mprz_set_str(tmp, "2", 0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN1,
                                            tmp);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case 4:
      /* 2nd ECP group */
      ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                            SSH_IKE_VALUES_GRP_TYPE_ECP);
      ssh_mprz_set_str(tmp,
                     "40950177705606685781046242922154881607956178336371883",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_PRIME,
                                            tmp);

      ssh_mprz_set_str(tmp,
                     "24746273018219762494198595506743299332378325756031886",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_CURVEA,
                                             tmp);

      ssh_mprz_set_str(tmp,
                     "6503278719366954296567774236884439158775557920331547",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_CURVEB,
                                             tmp);

      ssh_mprz_set_str(tmp,
                     "40950177705606685781046243158324028591251169648712266",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list,
                                            SSH_IKE_CLASSES_GRP_CARDINALITY,
                                             tmp);

      ssh_mprz_set_str(tmp,
                     "6408402137441767794969170236925842559451119808358974",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN1,
                                            tmp);

      ssh_mprz_set_str(tmp,
                     "39032544798419387403330432854399185547513580950826190",
                     0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_GEN2,
                                            tmp);

      ssh_mprz_set_str(tmp,
                       "2750918830149582546086674940099692905498533497831", 0);
      ssh_ike_data_attribute_list_add_mpint(list, SSH_IKE_CLASSES_GRP_ORDER,
                                            tmp);
      break;
#endif /* SSHDIST_CRYPT_ECP */





































    }
  ssh_mprz_clear(tmp);
}

Boolean ike_fill_one_transform(SshIkePayloadT transform,
                               int encr_alg, int hash_alg, int auth_meth,
                               int grp, SshUInt64 time_limit, int key_len,
                               SshMPInteger *options)
{
  SshIkeSAAttributeList list;
  list = ssh_ike_data_attribute_list_allocate();
  if (list == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_list_allocate failed");
      ssh_warning("ssh_ike_data_attribute_list_allocate failed");
      return FALSE;
    }

  ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_ENCR_ALG,
                                        encr_alg);
  if (time_limit != 0)
    {
      ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_LIFE_TYPE,
                                            SSH_IKE_VALUES_LIFE_TYPE_SECONDS);
      ssh_ike_data_attribute_list_add_int(list, SSH_IKE_CLASSES_LIFE_DURATION,
                                          time_limit);
    }
  ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_HASH_ALG,
                                        hash_alg);
  ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_AUTH_METH,
                                        auth_meth);

  if (grp <= 10)
    ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_DESC, grp);
  else
    ike_fill_grp_params(list, grp - 11, options);

  if (key_len != 0)
    ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_KEY_LEN,
                                          key_len);
  transform->sa_attributes =
    ssh_ike_data_attribute_list_get(list, &transform->number_of_sa_attributes);
  if (transform->sa_attributes == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_get failed");
      ssh_warning("ssh_ike_data_attribute_get failed");
      return FALSE;
    }
  ssh_ike_data_attribute_list_free(list);
  return TRUE;
}

/* 2, 4 */
#define XCHG_TYPE(x) (((x) & 0xf))
#define XCHG_TYPE_SUPPORTED(x) \
  ((x) == SSH_IKE_XCHG_TYPE_IP || (x) == SSH_IKE_XCHG_TYPE_AGGR || \
   (x) == 0xe)

/* 1..4 */
#define AUTH_METHOD(x) (((x) >> 4) & 0xf)
#ifdef DO_CERT_TESTS
#define AUTH_METHOD_SUPPORTED(x) \
  ((x) > 0 && (x) <= SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION)
#else /* DO_CERT_TESTS */
#define AUTH_METHOD_SUPPORTED(x) \
  ((x) > 0 && (x) <= SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY)
#endif /* DO_CERT_TESTS */

/* 1, 5 */
#ifdef SSHDIST_CRYPT_DES
#define DES_CHECK(x) ((x) == SSH_IKE_VALUES_ENCR_ALG_DES_CBC || \
                      (x) == SSH_IKE_VALUES_ENCR_ALG_3DES_CBC)
#else /* SSHDIST_CRYPT_DES */
#define DES_CHECK(x) 0
#endif /* SSHDIST_CRYPT_DES */

/* 2 */







#define IDEA_CHECK(x) 0


/* 3 */
#ifdef SSHDIST_CRYPT_BLOWFISH
#define BLOWFISH_CHECK(x) ((x) == SSH_IKE_VALUES_ENCR_ALG_BLOWFISH_CBC)
#else /* SSHDIST_CRYPT_BLOWFISH */
#define BLOWFISH_CHECK(x) 0
#endif /* SSHDIST_CRYPT_BLOWFISH */

/* 4 */



#define RC5_CHECK(x) 0


/* 6 */



#define CAST_CHECK(x) 0


/* 7 */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#define AES_CHECK(x) ((x) == SSH_IKE_VALUES_ENCR_ALG_AES_CBC)
#else /* SSHDIST_CRYPT_RIJNDAEL */
#define AES_CHECK(x) 0
#endif /* SSHDIST_CRYPT_RIJNDAEL */

/* 8 */



#define SERPENT_CHECK(x) 0


/* 9 */



#define TWOFISH_CHECK(x) 0


/* a */



#define RC6_CHECK(x) 0


/* b */



#define MARS_CHECK(x) 0



/* 1, (2), 3, 5, 6, (0xFF07, 0xFF08, 0xFF09, 0xFF0A, 0xFF0B) */
#define ENCR_ALG(x) ((((x) >> 8) & 0xf) | ((((x)>>8) & 0xf) > 7 ? 0xFF00 : 0))
#define ENCR_ALG_SUPPORTED(x) \
     ((((x) > 0) && \
       (DES_CHECK(x) || IDEA_CHECK(x) || BLOWFISH_CHECK(x) || RC5_CHECK(x) || \
        CAST_CHECK(x) || SERPENT_CHECK(x) || TWOFISH_CHECK(x) || \
        RC6_CHECK(x) || AES_CHECK(x) || MARS_CHECK(x))))

/* 1..4 */
#define HASH_ALG(x) ((((x) >> 12) & 0xf) | ((((x)>>12) & 0xf) > 7 ? 0xFF00:0))















#define HASH_ALG_SUPPORTED(x) \
  ((x) > 0 && (x) < SSH_IKE_VALUES_HASH_ALG_TIGER)



/* 1..2..4, 5, 11 (rsa), 12 (ecp), 13 (ec2n) = private group */
#define GROUP_DESC(x) (((x) >> 16) & 0xf)
#ifdef SSHDIST_CRYPT_ECP





#define GROUP_DESC_SUPPORTED(x) \
  (((x) > 0 && (x) <= SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024) || \
    (x) == SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536 || \
    (x) == 11 || (x) == 12)

#else /* SSHDIST_CRYPT_ECP */





#define GROUP_DESC_SUPPORTED(x) \
  (((x) > 0 && (x) <= SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024) || \
    (x) == SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536 || (x) == 11)

#endif /* SSHDIST_CRYPT_ECP */

/* 0..5 == 0, 40, 64, 80, 128, 448 */
int cipher_len[] = { 0, 40, 64, 80, 128, 448 };
#define KEY_LEN_VALUE(x) (cipher_len[(((x) >> 20) & 0xf)])
#define KEY_LEN(x) (((x) >> 20) & 0xf)
#define KEY_LEN_SUPPORTED(x) ((x) <= 5)
#define ENCR_ALG_KEY_LEN_SUPPORTED(e,k) \
  ((k) == 0 || \
   ((e) == SSH_IKE_VALUES_ENCR_ALG_BLOWFISH_CBC) || \
   ((e) == SSH_IKE_VALUES_ENCR_ALG_RC5_R16_B64_CBC && \
    (k) <= 4) || \
   ((e) == SSH_IKE_VALUES_ENCR_ALG_CAST_CBC && \
    (k) <= 4))

/* 0, 1 */
#define INITIAL_CONTACT(x)  (((x) & 0x08000000))
#define INITIAL_CONTACT_SUPPORTED(x) 1

/* 0..5 == 0, 4, 8, 12, 16, do not fill */
#define SPI_SIZE_VALUE(x) ((((x) >> 24) & 0x7) * 4)
#define SPI_SIZE(x) (((x) >> 24) & 0x7)
#define SPI_SIZE_SUPPORTED(x) ((x) <= 5)

/* 0..9 */
#define LOCAL_ID(x) (((x) >> 28) & 0xf)
#define LOCAL_ID_SUPPORTED(x) ((x) < IPSEC_ID_DER_ASN1_DN)

#define SSH_IKE_TEST_SUPPORTED(x) \
  ((x) == 0xffffffff || \
   (INITIAL_CONTACT_SUPPORTED(INITIAL_CONTACT(x)) && \
    XCHG_TYPE_SUPPORTED(XCHG_TYPE(x)) && \
    AUTH_METHOD_SUPPORTED(AUTH_METHOD(x)) && \
    LOCAL_ID_SUPPORTED(LOCAL_ID(x)) && \
    ENCR_ALG_SUPPORTED(ENCR_ALG(x)) && \
    HASH_ALG_SUPPORTED(HASH_ALG(x)) && \
    GROUP_DESC_SUPPORTED(GROUP_DESC(x)) && \
    KEY_LEN_SUPPORTED(KEY_LEN(x)) && \
    ENCR_ALG_KEY_LEN_SUPPORTED(ENCR_ALG(x),KEY_LEN(x)) && \
    SPI_SIZE_SUPPORTED(SPI_SIZE(x))))


void ike_test_async(TestScriptContext context, 
                    SshIkeServerContext server_context,
                    const char *remote_ip, 
                    const char *remote_port,
                    long test);

void ike_test_async_start(void *context)
{
  TestScriptContext test_context = context; 

  ike_test_async(test_context, test_context->server_context, 
                 test_context->remote_ip, test_context->remote_port, 
                 test_context->test_number);
}

void ike_test_async(TestScriptContext context, 
                    SshIkeServerContext server_context,
                    const char *remote_ip, 
                    const char *remote_port,
                    long test)
{
  SshIkeNegotiation neg;
  SshIkeErrorCode err;
  SshIkePayloadID local_id;
  SshIkePayloadSA sa_proposal;
  SshIkeExchangeType exchange_type;
  SshIkeAttributeAuthMethValues auth_method;
  SshIkePayloadPProtocol proto;
  SshUInt32 encrypt_last_packet;

  if (context->started_ops == 0)
    {
      ssh_time_measure_reset(&context->timer);
      ssh_time_measure_start(&context->timer);
    }

  if (context->started_ops == context->total_ops + 10)
    {
      SSH_DEBUG(1, ("Have started all %d IKE negotiations. Now wait for end", 
                    context->started_ops));
      return;
    }

  context->started_ops++;

  exchange_type = XCHG_TYPE(test);
  encrypt_last_packet = 0;
  if (exchange_type == 0xe)
    {
      exchange_type = SSH_IKE_XCHG_TYPE_AGGR;
      encrypt_last_packet = SSH_IKE_IKE_FLAGS_AGGR_ENCRYPT_LAST_PACKET;
    }
  auth_method = AUTH_METHOD(test);
  local_id = ike_fill_id(LOCAL_ID(test) + 1, SSH_IPPROTO_UDP,
                         0, context->server_name);
  if (local_id == NULL)
    {
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
  sa_proposal->doi = SSH_IKE_DOI_IPSEC;
  sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sa_proposal->number_of_proposals = 1;
  sa_proposal->proposals = ssh_xcalloc(1, sizeof(struct SshIkePayloadPRec));
  sa_proposal->proposals[0].proposal_number = 1;
  sa_proposal->proposals[0].number_of_protocols = 1;
  sa_proposal->proposals[0].protocols =
    ssh_xcalloc(1, sizeof(struct SshIkePayloadPProtocolRec));
  proto = &(sa_proposal->proposals[0].protocols[0]);
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
  proto->spi_size = SPI_SIZE_VALUE(test);
  if (proto->spi_size == 20)
    {
      proto->spi = NULL;
      proto->spi_size = SSH_IKE_COOKIE_LENGTH;
    }
  else
    {
      proto->spi = ssh_xmemdup(zeros, proto->spi_size);
    }

  proto->number_of_transforms = 1;
  proto->transforms = ssh_xcalloc(proto->number_of_transforms,
                                  sizeof(struct SshIkePayloadTRec));

  if (!ike_fill_one_transform(&(proto->transforms[0]),
                              ENCR_ALG(test), HASH_ALG(test),
                              AUTH_METHOD(test),
                              GROUP_DESC(test),
                              context->life_time_parameter,
                              KEY_LEN_VALUE(test),
                              NULL))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }
  proto->transforms[0].transform_number = 1;
  proto->transforms[0].transform_id.isakmp = SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;

  if (INITIAL_CONTACT(test))
    {
      /* If this is initial contact, clear the ISAKMP SA from the memory. */
      ssh_ike_remove_isakmp_sa_by_address(context->isakmp_context,
                                          NULL, NULL,
                                          NULL, NULL, 0);
    }

  phase_i++;
  err = ssh_ike_connect(server_context, &neg, remote_ip, remote_port,
                        local_id, sa_proposal,
                        exchange_type, NULL, NULL,
                        SSH_IKE_FLAGS_USE_DEFAULTS |
                        (INITIAL_CONTACT(test) ?
                         SSH_IKE_IKE_FLAGS_SEND_INITIAL_CONTACT : 0) |
                        encrypt_last_packet |
                        ((context->flags & 0x8000) ?
                         SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS : 0),
                        ike_async_notify_callback,
                        context);
  if (err != SSH_IKE_ERROR_OK)
    {
      ssh_fatal("IKE connection failure with error %d", err);
      phase_i--;
      SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
    }

  ssh_xregister_timeout(0, context->async_loop_timeout, 
                        ike_test_async_start, context);
}





void ike_test(TestScriptContext context, SshIkeServerContext server_context,
              const char *remote_ip, const char *remote_port,
              long test, Boolean wait_flag)
{
  SshIkeNegotiation neg;
  SshIkeErrorCode err;
  SshIkePayloadID local_id;
  SshIkePayloadSA sa_proposal;
  SshIkeExchangeType exchange_type;
  SshIkeAttributeAuthMethValues auth_method;
  SshIkePayloadPProtocol proto;
  SshUInt32 encrypt_last_packet;

  exchange_type = XCHG_TYPE(test);
  encrypt_last_packet = 0;
  if (exchange_type == 0xe)
    {
      exchange_type = SSH_IKE_XCHG_TYPE_AGGR;
      encrypt_last_packet = SSH_IKE_IKE_FLAGS_AGGR_ENCRYPT_LAST_PACKET;
    }
  auth_method = AUTH_METHOD(test);
  local_id = ike_fill_id(LOCAL_ID(test) + 1, SSH_IPPROTO_UDP,
                         0, context->server_name);
  if (local_id == NULL)
    {
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
  sa_proposal->doi = SSH_IKE_DOI_IPSEC;
  sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sa_proposal->number_of_proposals = 1;
  sa_proposal->proposals = ssh_xcalloc(1, sizeof(struct SshIkePayloadPRec));
  sa_proposal->proposals[0].proposal_number = 1;
  sa_proposal->proposals[0].number_of_protocols = 1;
  sa_proposal->proposals[0].protocols =
    ssh_xcalloc(1, sizeof(struct SshIkePayloadPProtocolRec));
  proto = &(sa_proposal->proposals[0].protocols[0]);
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
  proto->spi_size = SPI_SIZE_VALUE(test);
  if (proto->spi_size == 20)
    {
      proto->spi = NULL;
      proto->spi_size = SSH_IKE_COOKIE_LENGTH;
    }
  else
    {
      proto->spi = ssh_xmemdup(zeros, proto->spi_size);
    }

#if 0
  proto->number_of_transforms = 2;
  proto->transforms = ssh_xcalloc(proto->number_of_transforms,
                                  sizeof(struct SshIkePayloadTRec));

  if (!ike_fill_one_transform(&(proto->transforms[0]),
                              ENCR_ALG(test), HASH_ALG(test),
                              SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES,
                              GROUP_DESC(test),
                              context->life_time_parameter,
                              KEY_LEN_VALUE(test),
                              NULL))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  proto->transforms[0].transform_number = 1;
  proto->transforms[0].transform_id.isakmp = SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;

  if (ike_fill_one_transform(&(proto->transforms[1]),
                             ENCR_ALG(test), HASH_ALG(test), AUTH_METHOD(test),
                             GROUP_DESC(test),
                             context->life_time_parameter, KEY_LEN_VALUE(test),
                             NULL))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }
  proto->transforms[1].transform_number = 2;
  proto->transforms[1].transform_id.isakmp = SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;
#else
  proto->number_of_transforms = 1;
  proto->transforms = ssh_xcalloc(proto->number_of_transforms,
                                  sizeof(struct SshIkePayloadTRec));

  if (!ike_fill_one_transform(&(proto->transforms[0]),
                              ENCR_ALG(test), HASH_ALG(test),
                              AUTH_METHOD(test),
                              GROUP_DESC(test),
                              context->life_time_parameter,
                              KEY_LEN_VALUE(test),
                              NULL))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }
  proto->transforms[0].transform_number = 1;
  proto->transforms[0].transform_id.isakmp = SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;
#endif

  if (INITIAL_CONTACT(test))
    {
      /* If this is initial contact, clear the ISAKMP SA from the memory. */
      ssh_ike_remove_isakmp_sa_by_address(context->isakmp_context,
                                          NULL, NULL,
                                          NULL, NULL, 0);
    }

  SSH_DEBUG(3, ("Test 0x%x starts, xchg = %d, auth = %d, local_id = %d, "
                "encr = %d, hash = %d, group = %d, key_len = %d, spi = %d%s",
                test, exchange_type, auth_method, local_id->id_type,
                ENCR_ALG(test), HASH_ALG(test), GROUP_DESC(test),
                KEY_LEN_VALUE(test), SPI_SIZE_VALUE(test),
                (INITIAL_CONTACT(test) ? ", initial contact" : "")));
  phase_i++;
  err = ssh_ike_connect(server_context, &neg, remote_ip, remote_port,
                        local_id, sa_proposal,
                        exchange_type, NULL, NULL,
                        SSH_IKE_FLAGS_USE_DEFAULTS |
                        (INITIAL_CONTACT(test) ?
                         SSH_IKE_IKE_FLAGS_SEND_INITIAL_CONTACT : 0) |
                        encrypt_last_packet |
                        ((context->flags & 0x8000) ?
                         SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS : 0),
                        (wait_flag ? ike_notify_callback : NULL_FNPTR),
                        context);
  if (err != SSH_IKE_ERROR_OK)
    {
      phase_i--;
      SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  return;
}

Boolean ipsec_fill_one_transform(SshIkePayloadT transform,
                                 int grp, int encapsulation,
                                 SshUInt64 time_limit, SshUInt64 kb_limit,
                                 int key_len, int auth_alg)
{
  SshIkeSAAttributeList list;

  list = ssh_ike_data_attribute_list_allocate();
  if (list == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_list_allocate failed");
      ssh_warning("ssh_ike_data_attribute_list_allocate failed");
      return FALSE;
    }

  if (grp != 0)
    {
      if (grp >= 11 && grp <= 16)
        ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_GRP_DESC,
                                              39323 + grp - 11);
      else
        ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_GRP_DESC,
                                              grp);
    }
  if (encapsulation)
    ssh_ike_data_attribute_list_add_basic(list,
                                          IPSEC_CLASSES_ENCAPSULATION_MODE,
                                          encapsulation);

  if (time_limit)
    {
      ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_SA_LIFE_TYPE,
                                            IPSEC_VALUES_LIFE_TYPE_SECONDS);
      ssh_ike_data_attribute_list_add_int(list, IPSEC_CLASSES_SA_LIFE_DURATION,
                                          time_limit);
    }

  if (kb_limit)
    {
      ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_SA_LIFE_TYPE,
                                            IPSEC_VALUES_LIFE_TYPE_KILOBYTES);
      ssh_ike_data_attribute_list_add_int(list, IPSEC_CLASSES_SA_LIFE_DURATION,
                                          kb_limit);
    }

  if (auth_alg != 0)
    ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_AUTH_ALGORITHM,
                                          auth_alg);

  if (key_len != 0)
    ssh_ike_data_attribute_list_add_basic(list, IPSEC_CLASSES_KEY_LENGTH,
                                          key_len);
  transform->sa_attributes =
    ssh_ike_data_attribute_list_get(list, &transform->number_of_sa_attributes);
  if (transform->sa_attributes == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_get failed");
      ssh_warning("ssh_ike_data_attribute_get failed");
      return FALSE;
    }

  ssh_ike_data_attribute_list_free(list);
  return TRUE;
}

/* 1..3: 1 = ah + esp, 2 = ah, 3 = esp/ah */
#define IPSEC_PROTO(x) (((x)) & 0xf)
#define IPSEC_PROTO_SUPPORTED(x) \
  ((x) > 0 && (x) <= 3)

/* 1..3: 1 = none, 2 = MD5, 3 = SHA */
#define IPSEC_AH_TRANS(x) (((x) >> 4) & 0xf)
#define IPSEC_AH_TRANS_SUPPORTED(x) \
  ((x) > 0 && (x) <= 3)
#define IPSEC_AH_PROTO_SUPPORTED(a,p) \
  (((p) == 3 || (a) >= 2))

/* 2, 3, 7 : 2 = DES, 3 = 3DES, 7 = BLOWFISH */
#define IPSEC_ESP_TRANS(x) (((x) >> 8) & 0xf)
#define IPSEC_ESP_TRANS_SUPPORTED(x) \
  ((x) > 0 && \
   ((x) == SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES || \
    (x) == SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3DES || \
    (x) == SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH))

/* 0..2..4, 5 : 0 == no group, 11 = private rsa group 39323, 12 = private ecp
   group 39324, 13 = private ec2n group 39325 */
#define IPSEC_GROUP_DESC(x) (((x) >> 12) & 0xf)
#ifdef SSHDIST_CRYPT_ECP





#define IPSEC_GROUP_DESC_SUPPORTED(x) \
  ((x) <= SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024 || \
   (x) == SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536 || \
   (x) == 11 || (x) == 12)

#else /* SSHDIST_CRYPT_ECP */





#define IPSEC_GROUP_DESC_SUPPORTED(x) \
  ((x) <= SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024 || \
   (x) == SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536 || \
   (x) == 11)

#endif /* SSHDIST_CRYPT_ECP */

/* 1..2: 1 = tunnel, 2 = transport */
#define IPSEC_ENC(x) (((x) >> 16) & 0xf)
#define IPSEC_ENC_SUPPORTED(x) ((x) > 0 && (x) <= 2)

/* 0..5 == 0, 40, 64, 80, 128, 448 */
#define IPSEC_KEY_LEN_VALUE(x) (cipher_len[(((x) >> 20) & 0xf)])
#define IPSEC_KEY_LEN(x) (((x) >> 20) & 0xf)
#define IPSEC_KEY_LEN_SUPPORTED(x) ((x) <= 5)
#define IPSEC_ENCR_ALG_KEY_LEN_SUPPORTED(e,k) \
  ((k) == 0 || \
   ((e) == SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH))

/* 0..9 */
#define IPSEC_ID(x) (((x) >> 24) & 0xf)
#define IPSEC_ID_SUPPORTED(x) ((x) < IPSEC_ID_DER_ASN1_DN)

#define IPSEC_TEST_SUPPORTED(x) \
  ((x) == 0xffffffff || \
   (IPSEC_PROTO_SUPPORTED(IPSEC_PROTO(x)) && \
    IPSEC_AH_TRANS_SUPPORTED(IPSEC_AH_TRANS(x)) && \
    IPSEC_AH_PROTO_SUPPORTED(IPSEC_AH_TRANS(x),IPSEC_PROTO(x)) && \
    IPSEC_ESP_TRANS_SUPPORTED(IPSEC_ESP_TRANS(x)) && \
    IPSEC_GROUP_DESC_SUPPORTED(IPSEC_GROUP_DESC(x)) && \
    IPSEC_ENC_SUPPORTED(IPSEC_ENC(x)) && \
    IPSEC_KEY_LEN_SUPPORTED(IPSEC_KEY_LEN(x)) && \
    IPSEC_ENCR_ALG_KEY_LEN_SUPPORTED(IPSEC_ESP_TRANS(x),IPSEC_KEY_LEN(x)) && \
    IPSEC_ID_SUPPORTED(IPSEC_ID(x))))

void ipsec_test(TestScriptContext context, SshIkeServerContext server_context,
                const char *remote_ip, const char *remote_port,
                long test, Boolean wait_flag)
{
  SshIkeNegotiation neg;
  SshIkeErrorCode err;
  SshIkePayloadID local_id, remote_id;
  SshIkePayloadSA sa_proposal, *sa_proposals;
  SshIkePayloadPProtocol proto;
  unsigned char *spi;

  sa_proposals = ssh_xcalloc(1, sizeof(SshIkePayloadSA));
  sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
  sa_proposals[0] = sa_proposal;
  sa_proposal->doi = SSH_IKE_DOI_IPSEC;
  sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;

  sa_proposal->number_of_proposals = 1;
  sa_proposal->proposals = ssh_xcalloc(1, sizeof(struct SshIkePayloadPRec));
  sa_proposal->proposals[0].proposal_number = 1;
  if (IPSEC_PROTO(test) == 1)
    sa_proposal->proposals[0].number_of_protocols = 2;
  else
    sa_proposal->proposals[0].number_of_protocols = 1;

  sa_proposal->proposals[0].protocols =
    ssh_xcalloc(sa_proposal->proposals[0].number_of_protocols,
                sizeof(struct SshIkePayloadPProtocolRec));

  proto = &(sa_proposal->proposals[0].protocols[0]);
  if (IPSEC_PROTO(test) != 1)
    proto->protocol_id = IPSEC_PROTO(test);
  else
    proto->protocol_id = 2;
  proto->spi_size = 4;
  spi = ssh_xmalloc(4);
  spi[0] = ssh_random_get_byte();
  spi[1] = ssh_random_get_byte();
  spi[2] = ssh_random_get_byte();
  spi[3] = ssh_random_get_byte();
  proto->spi = spi;
  proto->number_of_transforms = 1;
  proto->transforms = ssh_xcalloc(1, sizeof(struct SshIkePayloadTRec));
  proto->transforms[0].transform_number = 1;
  if (IPSEC_PROTO(test) <= 2)
    proto->transforms[0].transform_id.ipsec_ah =
      IPSEC_AH_TRANS(test);
  else if (IPSEC_PROTO(test) == 3)
    proto->transforms[0].transform_id.ipsec_esp =
      IPSEC_ESP_TRANS(test);

  if (!ipsec_fill_one_transform(&(proto->transforms[0]),
                                IPSEC_GROUP_DESC(test),
                                IPSEC_ENC(test),
                                3600, 1000, KEY_LEN_VALUE(test),
                                (IPSEC_PROTO(test) == 3 &&
                                 IPSEC_AH_TRANS(test) != 1) ?
                                IPSEC_AH_TRANS(test) - 1 : 0))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ssh_xfree(sa_proposals);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  if (IPSEC_PROTO(test) == 1)
    {
      proto = &(sa_proposal->proposals[0].protocols[1]);
      proto->protocol_id = 3;
      proto->spi_size = 4;
      proto->spi = ssh_xmemdup(spi, 4);
      proto->number_of_transforms = 1;
      proto->transforms = ssh_xcalloc(1, sizeof(struct SshIkePayloadTRec));
      proto->transforms[0].transform_number = 1;
      proto->transforms[0].transform_id.ipsec_esp =
        IPSEC_ESP_TRANS(test);

      if (!ipsec_fill_one_transform(&(proto->transforms[0]),
                                    IPSEC_GROUP_DESC(test),
                                    IPSEC_ENC(test),
                                    3600, 1001, KEY_LEN_VALUE(test),
                                    (IPSEC_AH_TRANS(test) != 1) ?
                                    IPSEC_AH_TRANS(test) - 1 : 0))
        {
          ssh_ike_free_sa_payload(sa_proposal);
          ssh_xfree(sa_proposals);
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                              NULL, context);
          return;
        }
    }

  if (context->local_host_name)
    local_id = ike_fill_id(IPSEC_ID(test) + 1, SSH_IPPROTO_TCP,
                           0, context->local_host_name);
  else
    local_id = NULL;

  if (context->remote_host_name)
    remote_id = ike_fill_id(IPSEC_ID(test) + 1, SSH_IPPROTO_TCP,
                            0, context->remote_host_name);
  else
    remote_id = NULL;

  SSH_DEBUG(3, ("Test 0x%x starts, proto = %d, ah = %d, esp = %d, "
                "group = %d, encoding = %d, key_len = %d, id = %d",
                test, IPSEC_PROTO(test), IPSEC_AH_TRANS(test),
                IPSEC_ESP_TRANS(test), IPSEC_GROUP_DESC(test),
                IPSEC_ENC(test), IPSEC_KEY_LEN_VALUE(test),
                IPSEC_ID(test)));

  phase_qm++;
  err = ssh_ike_connect_ipsec(server_context, &neg, NULL,
                              remote_ip, remote_port,
                              local_id, remote_id, 1, sa_proposals,
                              NULL,
                              (IPSEC_GROUP_DESC(test) == 0 ?
                               SSH_IKE_FLAGS_USE_DEFAULTS :
                               (SSH_IKE_IPSEC_FLAGS_WANT_PFS |
                                SSH_IKE_FLAGS_USE_DEFAULTS)),
                              (wait_flag ? ike_notify_callback : NULL_FNPTR),
                              context);

  if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      phase_qm--;
      SSH_DEBUG(1, ("No isakmp sa found in ipsec connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
      ssh_ike_free_sa_payload(sa_proposal);
      ssh_xfree(sa_proposals);
    }
  else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
    {
      phase_qm--;
      SSH_DEBUG(1, ("Isakmp sa negotiation still in progress ipsec connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
      ssh_ike_free_sa_payload(sa_proposal);
      ssh_xfree(sa_proposals);
    }
  else if (err != SSH_IKE_ERROR_OK)
    {
      phase_qm--;
      SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
      ssh_ike_free_sa_payload(sa_proposal);
      ssh_xfree(sa_proposals);
    }
  return;
}

Boolean ngm_fill_one_transform(SshIkePayloadT transform, int grp,
                               int grp_number)
{
  SshIkeSAAttributeList list;
  list = ssh_ike_data_attribute_list_allocate();
  if (list == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_list_allocate failed");
      ssh_warning("ssh_ike_data_attribute_list_allocate failed");
      return FALSE;
    }

  ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_DESC,
                                        grp_number);
  ike_fill_grp_params(list, grp, NULL);

  transform->sa_attributes =
    ssh_ike_data_attribute_list_get(list, &transform->number_of_sa_attributes);
  if (transform->sa_attributes == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_get failed");
      ssh_warning("ssh_ike_data_attribute_get failed");
      return FALSE;
    }
  ssh_ike_data_attribute_list_free(list);
  return TRUE;
}

#define NGM_TEST_MODP_SUPPORTED(x) ((x) == 0 || (x) == 3)

#ifdef SSHDIST_CRYPT_ECP
#define NGM_TEST_ECP_SUPPORTED(x) ((x) == 1 || (x) == 4)
#else /* SSHDIST_CRYPT_ECP */
#define NGM_TEST_ECP_SUPPORTED(x) (0)
#endif /* SSHDIST_CRYPT_ECP */




#define NGM_TEST_EC2N_SUPPORTED(x) (0)


#define NGM_TEST_SUPPORTED(x) \
  ((x) == 0xffffffff || \
   (NGM_TEST_ECP_SUPPORTED(x) || \
    NGM_TEST_EC2N_SUPPORTED(x) || \
    NGM_TEST_MODP_SUPPORTED(x)))

void ngm_test(TestScriptContext context, SshIkeServerContext server_context,
              const char *remote_ip, const char *remote_port,
              long test, Boolean wait_flag)
{
  SshIkeNegotiation neg;
  SshIkeErrorCode err;
  SshIkePayloadSA sa_proposal;
  SshIkePayloadPProtocol proto;
  unsigned char *spi;

  sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
  sa_proposal->doi = SSH_IKE_DOI_IPSEC;
  sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sa_proposal->number_of_proposals = 1;
  sa_proposal->proposals = ssh_xcalloc(1, sizeof(struct SshIkePayloadPRec));
  sa_proposal->proposals[0].proposal_number = 1;
  sa_proposal->proposals[0].number_of_protocols = 1;
  sa_proposal->proposals[0].protocols =
    ssh_xcalloc(sa_proposal->proposals[0].number_of_protocols,
                sizeof(struct SshIkePayloadPProtocolRec));

  proto = &(sa_proposal->proposals[0].protocols[0]);
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
  proto->spi_size = 0;
  spi = ssh_xmalloc(1);
  spi[0] = 0;
  proto->spi = spi;
  proto->number_of_transforms = 1;
  proto->transforms = ssh_xcalloc(1, sizeof(struct SshIkePayloadTRec));
  proto->transforms[0].transform_number = 1;
  proto->transforms[0].transform_id.generic =
    SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;

  if (!ngm_fill_one_transform(&(proto->transforms[0]), test, 39323 + test))
    {
      ssh_ike_free_sa_payload(sa_proposal);
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  SSH_DEBUG(3, ("Ngm test %x starts", test));

  phase_ii++;
  err = ssh_ike_connect_ngm(server_context, &neg, NULL,
                            remote_ip, remote_port,
                            sa_proposal, NULL, SSH_IKE_FLAGS_USE_DEFAULTS,
                            (wait_flag ? ike_notify_callback : NULL_FNPTR),
                            context);

  if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      phase_ii--;
      SSH_DEBUG(1, ("No isakmp sa found in ngm connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
    {
      phase_ii--;
      SSH_DEBUG(1, ("Isakmp sa negotiation still in progress in ngm connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  else if (err != SSH_IKE_ERROR_OK)
    {
      phase_ii--;
      SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  return;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE

void ike_cfg_notify_callback(SshIkeNegotiation negotiation,
                             SshIkePMPhaseII pm_info,
                             SshIkeNotifyMessageType error_code,
                             int number_of_attr_payloads,
                             SshIkePayloadAttr *attributes,
                             void *notify_callback_context)
{
  TestScriptContext context = (TestScriptContext) notify_callback_context;
  int i, j;
  SshUInt32 value;

  if (error_code != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      SSH_DEBUG(3, ("Cfg mode ends, with error code = %s (%d)",
                    ssh_ike_error_code_to_string(error_code), error_code));
      ike_notify_callback(error_code, negotiation, context);
      return;
    }

  SSH_DEBUG(3, ("Cfg mode ends"));
  for (i = 0; i < number_of_attr_payloads; i++)
    {
      SSH_DEBUG(3,
                ("attribute[%d], type = %d, identifier = %d, # attrs = %d",
                 i,
                 attributes[i]->type,
                 attributes[i]->identifier,
                 attributes[i]->number_of_attributes));
      if (attributes[i]->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY)
        {
          SSH_DEBUG(3, ("Other end returned following values:"));
          for (j = 0; j < attributes[i]->number_of_attributes; j++)
            {
              if (attributes[i]->attributes[j].attribute_length == 0)
                {
                  SSH_DEBUG(3, ("Attribute %d not set",
                                attributes[i]->attributes[j].attribute_type));
                }
              else if (ssh_ike_get_data_attribute_int(&(attributes[i]->
                                                        attributes[j]),
                                                      &value,
                                                      0))
                {
                  SSH_DEBUG(3, ("Attribute %d = %08x",
                                attributes[i]->attributes[j].attribute_type,
                                value));
                }
              else
                {
                  SSH_DEBUG(3, ("Variable length attribute %d",
                                attributes[i]->attributes[j].attribute_type));
                }
            }
        }
      else if (attributes[i]->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK)
        {
          SSH_DEBUG(3, ("Other end acknowledged following values:"));
          for (j = 0; j < attributes[i]->number_of_attributes; j++)
            {
              if (attributes[i]->attributes[j].attribute_length == 0)
                {
                  SSH_DEBUG(3, ("%d acknowledged",
                                attributes[i]->attributes[j].attribute_type));
                }
              else if (ssh_ike_get_data_attribute_int(&(attributes[i]->
                                                        attributes[j]),
                                                      &value,
                                                      0))
                {
                  SSH_DEBUG(3, ("Attribute %d has data = %08x",
                                attributes[i]->attributes[j].attribute_type,
                                value));
                }
              else
                {
                  SSH_DEBUG(3, ("Variable length attribute %d has data",
                                attributes[i]->attributes[j].attribute_type));
                }
            }
        }
      else
        {
          SSH_DEBUG(3, ("Invalid message type: %d", attributes[i]->type));
        }
    }
  ike_notify_callback(error_code, negotiation, context);
}

void ike_xauth_notify_callback(SshIkeNegotiation negotiation,
                               SshIkePMPhaseII pm_info,
                               SshIkeNotifyMessageType error_code,
                               SshIkeXauthType type,
                               const unsigned char *username,
                               size_t username_len,
                               const unsigned char *password,
                               size_t password_len,
                               void *callback_context)
{
  TestScriptContext context = (TestScriptContext) callback_context;
  char username_txt[128], password_txt[128];

  if (error_code != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      SSH_DEBUG(3, ("Xauth mode ends, with error code = %s (%d)",
                    ssh_ike_error_code_to_string(error_code), error_code));
      ike_notify_callback(error_code, negotiation, context);
      return;
    }

  if (username_len >= sizeof(username_txt))
    username_len = sizeof(username_txt) - 1;
  if (username)
    {
      strncpy(username_txt, (char *) username, username_len);
      username_txt[username_len] = '\0';
    }
  else
    strcpy(username_txt, "no username");

  if (password_len >= sizeof(password_txt))
    password_len = sizeof(password_txt) - 1;
  if (password)
    {
      strncpy(password_txt, (char *) password, username_len);
      password_txt[password_len] = '\0';
    }
  else
    strcpy(password_txt, "no password");

  SSH_DEBUG(3, ("Xauth mode ends, type = %d, username = %s, password = %s",
                type, username_txt, password_txt));
  ike_notify_callback(error_code, negotiation, context);
}

void cfg_test(TestScriptContext context, SshIkeServerContext server_context,
              const char *remote_ip, const char *remote_port,
              long test, Boolean wait_flag)
{
  SshIkeNegotiation neg;
  SshIkeErrorCode err;
  SshIkePayloadAttr *attrs;
  size_t len;
  unsigned char buf[4];
  SshIkeSAAttributeList list;

  if (test == 2)
    {
      phase_ii++;
      err = ssh_ike_connect_xauth_password(server_context, &neg, NULL,
                                           remote_ip, remote_port,
                                           SSH_IKE_XAUTH_TYPE_RADIUS_CHAP,
                                           NULL,
                                           SSH_IKE_FLAGS_USE_DEFAULTS |
                                           SSH_IKE_FLAGS_USE_EXTENDED_TIMERS,
                                           ike_xauth_notify_callback,
                                           context);

      if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
        {
          phase_ii--;
          SSH_DEBUG(1, ("No isakmp sa found in cfg connect"));
          if (wait_flag)
            {
              ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                  NULL, context);
            }
        }
      else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
        {
          phase_ii--;
          SSH_DEBUG(1, ("Isakmp sa negotiation still in progress in "
                        "cfg connect"));
          if (wait_flag)
            {
              ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                  NULL, context);
            }
        }
      else if (err != SSH_IKE_ERROR_OK)
        {
          phase_ii--;
          SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
          if (wait_flag)
            {
              ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                  NULL, context);
            }
        }
      return;
    }

  attrs = ssh_xcalloc(1, sizeof(SshIkePayloadAttr));
  attrs[0] = ssh_xcalloc(1, sizeof(struct SshIkePayloadAttrRec));
  len = 0;
  switch (test)
    {
    case 0:
      attrs[0]->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST;
      len = 0;
      break;
    case 1:
      attrs[0]->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET;
      len = 4;
      break;
    }

  attrs[0]->identifier = test;
  list = ssh_ike_data_attribute_list_allocate();
  if (list == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_list_allocate failed");
      ssh_warning("ssh_ike_data_attribute_list_allocate failed");
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  SSH_PUT_32BIT(buf, 0x7f000001);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_ADDRESS,
                                  buf, len);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NETMASK,
                                  buf, len);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DNS,
                                  buf, len);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NBNS,
                                  buf, len);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DHCP,
                                  buf, len);
  ssh_ike_data_attribute_list_add(list,
                                  SSH_IKE_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY,
                                  buf, len);

  attrs[0]->attributes =
    ssh_ike_data_attribute_list_get(list, &attrs[0]->number_of_attributes);
  if (attrs[0]->attributes == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_ike_data_attribute_list_get failed");
      ssh_warning("ssh_ike_data_attribute_list_get failed");
      ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                          NULL, context);
      return;
    }

  ssh_ike_data_attribute_list_free(list);

  SSH_DEBUG(3, ("Cfg test starts"));

  phase_ii++;
  err = ssh_ike_connect_cfg(server_context, &neg, NULL,
                            remote_ip, remote_port,
                            1, attrs, NULL, SSH_IKE_FLAGS_USE_DEFAULTS,
                            ike_cfg_notify_callback,
                            context);

  if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      phase_ii--;
      SSH_DEBUG(1, ("No isakmp sa found in cfg connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
    {
      phase_ii--;
      SSH_DEBUG(1, ("Isakmp sa negotiation still in progress in cfg connect"));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  else if (err != SSH_IKE_ERROR_OK)
    {
      phase_ii--;
      SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
      if (wait_flag)
        {
          ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                              NULL, context);
        }
    }
  return;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


void ike_client_test(TestScriptContext context,
                     SshIkeServerContext server_context,
                     const char *remote_ip, const char *remote_port,
                     long test, Boolean wait_flag)
{
  int key_lengths[10] = { 0, 40, 56, 64, 80, 88, 96, 128, 160, 448 };

  switch (test)
    {
    case 0:
      /* Isakmp test */
      {
        SshIkeNegotiation neg;
        SshIkeErrorCode err;
        SshIkePayloadID local_id;
        SshIkePayloadSA sa_proposal;
        SshIkeExchangeType exchange_type;
        SshIkeAttributeAuthMethValues auth_method;
        SshIkePayloadPProtocol proto;
        int i, j;
        unsigned long value;
        int proposals, max_proposals;

        exchange_type = context->argv[CLIENT_ARG_XCHG_TYPE];
        auth_method = context->upper_context->auth;
        local_id = ike_fill_id(IPSEC_ID_IPV4_ADDR,
                               0, 0, context->server_name);
        if (local_id == NULL)
          {
            ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                NULL, context);
            return;
          }

        sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
        sa_proposal->doi = SSH_IKE_DOI_IPSEC;
        sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
        value = 1;
        proposals = 0;
        for (i = 0; i < MAX_PROPOSALS; i++)
          {
            if ((context->argv[CLIENT_ARG_PROPOSAL] / value) % 10 == 1)
              proposals++;
            if ((context->argv[CLIENT_ARG_PROPOSAL] / value) % 10 == 2)
              break;
            value *= 10;
          }
        max_proposals = proposals + 1;
        sa_proposal->number_of_proposals = max_proposals;
        sa_proposal->proposals = ssh_xcalloc(max_proposals,
                                             sizeof(struct SshIkePayloadPRec));
        i = 0;
        for (proposals = 0; proposals < max_proposals; proposals++)
          {
            int transforms;

            sa_proposal->proposals[proposals].proposal_number = proposals + 1;
            sa_proposal->proposals[proposals].number_of_protocols = 1;
            sa_proposal->proposals[proposals].protocols =
              ssh_xcalloc(1, sizeof(struct SshIkePayloadPProtocolRec));
            proto = &(sa_proposal->proposals[proposals].protocols[0]);
            proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
            proto->spi = NULL;
            proto->spi_size = SSH_IKE_COOKIE_LENGTH;

            value = 1;
            transforms = 0;
            for (j = i; j < MAX_PROPOSALS; j++)
              {
                transforms++;
                if ((context->argv[CLIENT_ARG_PROPOSAL] / value) % 10 == 1 ||
                    (context->argv[CLIENT_ARG_PROPOSAL] / value) % 10 == 2)
                  break;
                value *= 10;
              }

            proto->number_of_transforms = transforms;
            proto->transforms = ssh_xcalloc(transforms,
                                            sizeof(struct SshIkePayloadTRec));

            value = 1;
            for (j = 0; j < i; j++)
              value *= 10;
            i = j + 1;

            for (j = 0; j < transforms; j++)
              {
                proto->transforms[j].transform_number = j + 1;
                proto->transforms[j].transform_id.isakmp =
                  SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;
                if (!ike_fill_one_transform(&(proto->transforms[j]),
                                            (context->
                                             argv[CLIENT_ARG_ENCR_ALG] /
                                             value) % 10,
                                            (context->
                                             argv[CLIENT_ARG_HASH_ALG] /
                                             value) % 10,
                                            context->upper_context->auth,
                                            context->argv[CLIENT_ARG_GRP],
                                            0,
                                            key_lengths[(context->
                                                 argv[CLIENT_ARG_KEY_LEN]
                                                         / value) % 10],
                                            context->upper_context->
                                            options_mpint))
                  {
                    ssh_ike_id_free(local_id);
                    ssh_ike_free_sa_payload(sa_proposal);
                    ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                        NULL, context);
                    return;
                  }
                value *= 10;
              }
          }

        phase_i++;
        err = ssh_ike_connect(server_context, &neg, remote_ip, remote_port,
                              local_id, sa_proposal,
                              exchange_type, NULL, NULL,
                              ((context->flags & 0x8000) ?
                               SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS :
                               0),
                              (wait_flag ? ike_notify_callback : NULL_FNPTR),
                              context);
        if (err != SSH_IKE_ERROR_OK)
          {
            phase_i--;
            SSH_IKE_DEBUG(1, NULL,
                          ("ssh_ike_connect failed, err = %d", err));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        break;
      }
    case 1:
      /* New group mode test */
      {
        SshIkeNegotiation neg;
        SshIkeErrorCode err;
        SshIkePayloadSA sa_proposal;
        SshIkePayloadPProtocol proto;
        unsigned char *spi;
        SshIkeSAAttributeList list;

        if (ssh_mprz_cmp_ui(context->upper_context->
			    options_mpint[MPINT_OPTION_NGM_PRIME], 0) == 0 ||
            ssh_mprz_cmp_ui(context->upper_context->
			    options_mpint[MPINT_OPTION_NGM_GEN1], 0) == 0)
          {
            ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_CONNECTED,
                                NULL, context);
            return;
          }

        sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
        sa_proposal->doi = SSH_IKE_DOI_IPSEC;
        sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
        sa_proposal->number_of_proposals = 1;
        sa_proposal->proposals = ssh_xcalloc(1,
                                             sizeof(struct SshIkePayloadPRec));
        sa_proposal->proposals[0].proposal_number = 1;
        sa_proposal->proposals[0].number_of_protocols = 1;
        sa_proposal->proposals[0].protocols =
          ssh_xcalloc(sa_proposal->proposals[0].number_of_protocols,
                      sizeof(struct SshIkePayloadPProtocolRec));

        proto = &(sa_proposal->proposals[0].protocols[0]);
        proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
        proto->spi_size = 0;
        spi = ssh_xmalloc(1);
        spi[0] = 0;
        proto->spi = spi;
        proto->number_of_transforms = 1;
        proto->transforms = ssh_xcalloc(1, sizeof(struct SshIkePayloadTRec));
        proto->transforms[0].transform_number = 1;
        proto->transforms[0].transform_id.generic =
          SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;
        list = ssh_ike_data_attribute_list_allocate();
        if (list == NULL)
          {
            if (call_fatal_on_error)
              ssh_fatal("ssh_ike_data_attribute_list_allocate failed");
            ssh_warning("ssh_ike_data_attribute_list_allocate failed");
            ssh_ike_free_sa_payload(sa_proposal);
            ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                NULL, context);
            return;
          }

        ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_DESC,
                                              context->
                                              argv[CLIENT_ARG_NGM_GRP_NUMBER]);
        ssh_ike_data_attribute_list_add_basic(list, SSH_IKE_CLASSES_GRP_TYPE,
                                              context->
                                              argv[CLIENT_ARG_NGM_GRP_TYPE]);

        ssh_ike_data_attribute_list_add_mpint(
				       list, SSH_IKE_CLASSES_GRP_PRIME,
				       context->upper_context->
				       options_mpint[MPINT_OPTION_NGM_PRIME]);
        ssh_ike_data_attribute_list_add_mpint(
					      list, SSH_IKE_CLASSES_GRP_GEN1,
                                        context->upper_context->
                                        options_mpint[MPINT_OPTION_NGM_GEN1]);
        if (context->argv[CLIENT_ARG_NGM_GRP_TYPE] !=
            SSH_IKE_VALUES_GRP_TYPE_MODP)
          {
            ssh_ike_data_attribute_list_add_mpint(
                                        list, SSH_IKE_CLASSES_GRP_GEN2,
                                        context->upper_context->
                                        options_mpint[MPINT_OPTION_NGM_GEN2]);
            ssh_ike_data_attribute_list_add_mpint(
                                list, SSH_IKE_CLASSES_GRP_CURVEA,
                                context->upper_context->
                                options_mpint[MPINT_OPTION_NGM_CURVEA]);
            ssh_ike_data_attribute_list_add_mpint(
                                list, SSH_IKE_CLASSES_GRP_CURVEB,
                                context->upper_context->
                                options_mpint[MPINT_OPTION_NGM_CURVEB]);
            if (ssh_mprz_cmp_ui(context->upper_context->
                                options_mpint[MPINT_OPTION_NGM_CARDINALITY],
                                0) != 0)
              ssh_ike_data_attribute_list_add_mpint(
                                list, SSH_IKE_CLASSES_GRP_CARDINALITY,
                                context->upper_context->
                                options_mpint[MPINT_OPTION_NGM_CARDINALITY]);
            ssh_ike_data_attribute_list_add_mpint(
                                        list, SSH_IKE_CLASSES_GRP_ORDER,
                                        context->upper_context->
                                        options_mpint[MPINT_OPTION_NGM_ORDER]);
          }
        proto->transforms[0].sa_attributes =
          ssh_ike_data_attribute_list_get(list, &proto->transforms[0].
                                          number_of_sa_attributes);
        if (proto->transforms[0].sa_attributes == NULL)
          {
            if (call_fatal_on_error)
              ssh_fatal("ssh_ike_data_attribute_list_get failed");
            ssh_warning("ssh_ike_data_attribute_list_get failed");
            ssh_ike_free_sa_payload(sa_proposal);
            ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                NULL, context);
            return;
          }
        ssh_ike_data_attribute_list_free(list);

        phase_ii++;
        err = ssh_ike_connect_ngm(server_context, &neg, NULL,
                                  remote_ip, remote_port,
                                  sa_proposal, NULL,
                                  SSH_IKE_FLAGS_USE_DEFAULTS,
                                  (wait_flag
                                    ? ike_notify_callback : NULL_FNPTR),
                                  context);

        if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
          {
            phase_ii--;
            SSH_IKE_DEBUG(1, NULL, ("No isakmp sa found in ngm connect"));
            SSH_DEBUG(1, ("No isakmp sa found in ngm connect"));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
          {
            phase_ii--;
            SSH_IKE_DEBUG(1, NULL, ("Isakmp sa negotiation still "
                                    "in progress in ngm connect"));
            SSH_DEBUG(1, ("Isakmp sa negotiation still in progress "
                          "in ngm connect"));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        else if (err != SSH_IKE_ERROR_OK)
          {
            phase_ii--;
            SSH_IKE_DEBUG(1, NULL,
                          ("ssh_ike_connect failed, err = %d", err));
            SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        break;
      }
    case 2:
      /* Ipsec quick mode test */
      {
        SshIkeNegotiation neg;
        SshIkeErrorCode err;
        SshIkePayloadID local_id, remote_id;
        SshIkePayloadSA sa_proposal, *sa_proposals;
        SshIkePayloadPProtocol proto;
        unsigned char *spi;
        unsigned long value, value2;
        int proposals, max_proposals;
        int i, j, k;

        sa_proposals = ssh_xcalloc(1, sizeof(SshIkePayloadSA));
        sa_proposal = ssh_xcalloc(1, sizeof(struct SshIkePayloadSARec));
        sa_proposals[0] = sa_proposal;
        sa_proposal->doi = SSH_IKE_DOI_IPSEC;
        sa_proposal->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;

        value = 1;
        proposals = 0;
        for (i = 0; i < MAX_PROPOSALS; i++)
          {
            if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value) % 10 == 1)
              proposals++;
            if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value) % 10 == 2)
              break;
            value *= 10;
          }
        max_proposals = proposals + 1;
        sa_proposal->number_of_proposals = max_proposals;
        sa_proposal->proposals = ssh_xcalloc(max_proposals,
                                             sizeof(struct SshIkePayloadPRec));
        i = 0;
        value = 1;
        for (proposals = 0; proposals < max_proposals; proposals++)
          {
            int transforms;
            int l;

            sa_proposal->proposals[proposals].proposal_number = proposals + 1;
            if ((context->argv[CLIENT_ARG_QM_AH_PROTO] / value) % 10 != 0 ||
                (context->argv[CLIENT_ARG_QM_ESP_PROTO] / value) % 10 != 0)
              {
                if ((context->argv[CLIENT_ARG_QM_AH_PROTO]
                     / value) % 10 != 0 &&
                    (context->argv[CLIENT_ARG_QM_ESP_PROTO] / value) % 10 != 0)
                  {
                    sa_proposal->proposals[proposals].number_of_protocols = 2;
                  }
                else
                  {
                    sa_proposal->proposals[proposals].number_of_protocols = 1;
                  }
                sa_proposal->proposals[proposals].protocols =
                  ssh_xcalloc(sa_proposal->proposals[proposals].
                              number_of_protocols,
                              sizeof(struct SshIkePayloadPProtocolRec));

                l = 0;
                if ((context->argv[CLIENT_ARG_QM_AH_PROTO] / value) % 10 != 0)
                  {
                    proto = &(sa_proposal->proposals[proposals].protocols[l]);
                    proto->protocol_id = SSH_IKE_PROTOCOL_IPSEC_AH;

                    proto->spi_size = 4;
                    spi = ssh_xmalloc(4);
                    spi[0] = ssh_random_get_byte();
                    spi[1] = ssh_random_get_byte();
                    spi[2] = ssh_random_get_byte();
                    spi[3] = ssh_random_get_byte();
                    proto->spi = spi;

                    value2 = value;
                    transforms = 0;
                    for (j = i; j < MAX_PROPOSALS; j++)
                      {
                        if ((context->argv[CLIENT_ARG_QM_AH_PROTO]
                             / value2) % 10 != 0)
                          transforms++;
                        if ((context->argv[CLIENT_ARG_QM_PROPOSAL]
                             / value2) % 10 == 1 ||
                            (context->argv[CLIENT_ARG_QM_PROPOSAL]
                             / value2) % 10 == 2)
                          break;
                        value2 *= 10;
                      }

                    proto->number_of_transforms = transforms;

                    proto->transforms = ssh_xcalloc(transforms,
                                                    sizeof(struct
                                                           SshIkePayloadTRec));

                    k = 0;
                    value2 = value;
                    for (j = i; j < MAX_PROPOSALS; j++)
                      {
                        if ((context->argv[CLIENT_ARG_QM_AH_PROTO] / value2)
                            % 10 != 0)
                          {
                            proto->transforms[k].transform_number = j + 1;
                            proto->transforms[k].transform_id.ipsec_ah =
                              (context->argv[CLIENT_ARG_QM_AH_PROTO] /
                               value2) % 10;
                            if (!ipsec_fill_one_transform
                                (&(proto->transforms[k]),
                                 (context->argv[CLIENT_ARG_QM_GROUP] == 9) ?
                                 context->argv[CLIENT_ARG_NGM_GRP_NUMBER] :
                                 context->argv[CLIENT_ARG_QM_GROUP],
                                 (context->argv[CLIENT_ARG_QM_AH_MODE] /
                                  value2) % 10,
                                 0, 0,
                                 key_lengths[(context->
                                              argv[CLIENT_ARG_QM_AH_KEY_LEN] /
                                              value2) % 10],
                                 ((context->argv[CLIENT_ARG_QM_AH_PROTO] /
                                   value2) % 10) - 1))
                              {
                                ssh_ike_free_sa_payload(sa_proposal);
                                ike_notify_callback
                                  (SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                   NULL, context);
                                return;
                              }

                            k++;
                          }
                        if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 1 ||
                            (context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 2)
                          break;

                        value2 *= 10;
                      }
                    l++;
                  }
                if ((context->argv[CLIENT_ARG_QM_ESP_PROTO] / value) % 10 != 0)
                  {
                    proto = &(sa_proposal->proposals[proposals].protocols[l]);
                    proto->protocol_id = SSH_IKE_PROTOCOL_IPSEC_ESP;

                    proto->spi_size = 4;
                    spi = ssh_xmalloc(4);
                    spi[0] = ssh_random_get_byte();
                    spi[1] = ssh_random_get_byte();
                    spi[2] = ssh_random_get_byte();
                    spi[3] = ssh_random_get_byte();
                    proto->spi = spi;

                    value2 = value;
                    transforms = 0;
                    for (j = i; j < MAX_PROPOSALS; j++)
                      {
                        if ((context->argv[CLIENT_ARG_QM_ESP_PROTO] / value2)
                            % 10 != 0)
                          transforms++;
                        if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 1 ||
                            (context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 2)
                          break;
                        value2 *= 10;
                      }

                    proto->number_of_transforms = transforms;

                    proto->transforms = ssh_xcalloc(transforms,
                                                    sizeof(struct
                                                           SshIkePayloadTRec));

                    k = 0;
                    value2 = value;
                    for (j = i; j < MAX_PROPOSALS; j++)
                      {
                        if ((context->argv[CLIENT_ARG_QM_ESP_PROTO] / value2)
                            % 10 != 0)
                          {
                            proto->transforms[k].transform_number = j + 1;
                            proto->transforms[k].transform_id.ipsec_esp =
                              (context->argv[CLIENT_ARG_QM_ESP_PROTO] /
                               value2) % 10;
                            if (proto->transforms[k].
                                transform_id.ipsec_esp == 1)
                              proto->transforms[k].transform_id.ipsec_esp = 11;

                            if (!ipsec_fill_one_transform
                                (&(proto->transforms[k]),
                                 (context->argv[CLIENT_ARG_QM_GROUP] == 9) ?
                                 context->argv[CLIENT_ARG_NGM_GRP_NUMBER] :
                                 context->argv[CLIENT_ARG_QM_GROUP],
                                 (context->argv[CLIENT_ARG_QM_ESP_MODE] /
                                  value2) % 10,
                                 0, 0,
                                 key_lengths[(context->
                                              argv[CLIENT_ARG_QM_ESP_KEY_LEN] /
                                              value2) % 10],
                                 (context->argv[CLIENT_ARG_QM_ESP_AUTH] /
                                  value2) % 10))
                              {
                                ssh_ike_free_sa_payload(sa_proposal);
                                ike_notify_callback
                                  (SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY,
                                   NULL, context);
                                return;
                              }
                            k++;
                          }

                        if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 1 ||
                            (context->argv[CLIENT_ARG_QM_PROPOSAL] / value2)
                            % 10 == 2)
                          break;

                        value2 *= 10;
                      }
                    l++;
                  }
                if (l == 0)
                  {
                    proposals--;
                    max_proposals--;
                  }
              }

            for (j = i; j < MAX_PROPOSALS; j++)
              {
                if ((context->argv[CLIENT_ARG_QM_PROPOSAL] / value)
                    % 10 == 1 ||
                    (context->argv[CLIENT_ARG_QM_PROPOSAL] / value)
                    % 10 == 2)
                  break;
                value *= 10;
              }
            value *= 10;
            i = j + 1;
          }
        if (context->local_host_name)
          local_id = ike_fill_id(IPSEC_ID_IPV4_ADDR,
                                 SSH_IPPROTO_TCP, 0,
                                 context->local_host_name);
        else
          local_id = NULL;

        if (context->remote_host_name)
          remote_id = ike_fill_id(IPSEC_ID_IPV4_ADDR,
                                  SSH_IPPROTO_TCP, 0,
                                  context->remote_host_name);
        else
          remote_id = NULL;

        phase_qm++;
        err = ssh_ike_connect_ipsec(server_context, &neg, NULL,
                                    remote_ip, remote_port,
                                    local_id, remote_id, 1, sa_proposals,
                                    NULL,
                                    ((context->argv[CLIENT_ARG_QM_GROUP]
                                      == 0) ?
                                     SSH_IKE_FLAGS_USE_DEFAULTS :
                                     (SSH_IKE_IPSEC_FLAGS_WANT_PFS |
                                      SSH_IKE_FLAGS_USE_DEFAULTS)),
                                    (wait_flag ? ike_notify_callback :
                                     NULL_FNPTR),
                                    context);

        if (err == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
          {
            phase_qm--;
            SSH_IKE_DEBUG(1, NULL, ("No isakmp sa found in ipsec connect"));
            SSH_DEBUG(1, ("No isakmp sa found in ipsec connect"));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        else if (err == SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS)
          {
            phase_qm--;
            SSH_IKE_DEBUG(1, NULL, ("Isakmp sa negotiation still "
                                    "in progress ipsec connect"));
            SSH_DEBUG(1, ("Isakmp sa negotiation still in progress "
                          "ipsec connect"));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        else if (err != SSH_IKE_ERROR_OK)
          {
            phase_qm--;
            SSH_IKE_DEBUG(1, NULL,
                          ("ssh_ike_connect failed, err = %d", err));
            SSH_DEBUG(1, ("ssh_ike_connect failed, err = %d", err));
            if (wait_flag)
              {
                ike_notify_callback(SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED,
                                    NULL, context);
              }
          }
        break;
      }
    default:
      ssh_fatal("ike_client_test gets test > 2 (%d)", test);
      break;
    }

  return;
}

void test_callback(void *context)
{
  TestScriptContext test_context = (TestScriptContext) context;
  Boolean install_timeout = TRUE;
  SshUInt32 test, limit, incr;

retry:
  if (test_context->isakmp_context == NULL ||
      test_context->server_context == NULL)
    {
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, test_context);
      return;
    }
  if (test_context->next_test_count == 0xffffffff)
    {
      const char *p;
      char *q;

      if (!*test_context->current_test)
        {
          ssh_event_loop_abort();
          return;
        }
      test_context->test =
        ssh_find_partial_keyword_number_case_insensitive(test_cases,
                                                         test_context->
                                                         current_test,
                                                         &p);
      if (test_context->test == -1)
        ssh_fatal("Unknown test: %s", test_context->current_test);
      test_context->argc = 0;
      if (*p == '(')
        {
          do {
            p++;
            if ((test_context->argv[test_context->argc++] = strtol(p, &q, 0))
                && p == q)
              {
                ssh_fatal("Invalid numeric argument: %s", p);
              }
            p = q;
          } while (*p == ',' && test_context->argc < MAX_ARGS);
          if (*p++ != ')')
            {
              ssh_fatal("Syntax error waiting for ): %s", --p);
            }
        }
      switch (test_context->test)
        {
        case TEST_CLIENT_ISAKMP:
          if (test_context->argc != 17)
            ssh_fatal("ike_test_server needs 17 arguments");

          test_context->sleep_msec = 0;
          test_context->next_test_count = 0;
          break;
        case TEST_SERVER_ISAKMP:
          if (test_context->argc != 11)
            ssh_fatal("ike_test_server needs 11 arguments");

          test_context->sleep_msec = test_context->argv[0];
          test_context->next_test_count = 0;
          break;
        case TEST_ISAKMP:
          if (test_context->argc < 1)
            {
              ssh_fatal("Isakmp needs one argument : %s",
                        test_context->current_test);
            }
          test_context->sleep_msec = test_context->argv[0];
          if (test_context->argc > 1)
            test_context->next_test_count = test_context->argv[1];
          else
            test_context->next_test_count = 0;

          if (!SSH_IKE_TEST_SUPPORTED(test_context->next_test_count))
            {
              limit = 0xffffffff;
              incr = 1;
              if (test_context->argc > 2)
                limit = test_context->argv[2];
              if (test_context->argc > 4)
                incr = test_context->argv[4];

              while ((test_context->next_test_count += incr) &&
                     test_context->next_test_count < limit)
                if (SSH_IKE_TEST_SUPPORTED(test_context->next_test_count))
                  break;
              if (test_context->next_test_count >= limit)
                test_context->next_test_count = 0xffffffff;
            }
          break;
        case TEST_IPSEC:
          if (test_context->argc < 1)
            {
              ssh_fatal("ipsec needs one argument : %s",
                        test_context->current_test);
            }
          test_context->sleep_msec = test_context->argv[0];
          if (test_context->argc > 1)
            test_context->next_test_count = test_context->argv[1];
          else
            test_context->next_test_count = 0;

          if (!IPSEC_TEST_SUPPORTED(test_context->next_test_count))
            {
              incr = 1;
              limit = 0xffffffff;
              if (test_context->argc > 2)
                limit = test_context->argv[2];
              if (test_context->argc > 4)
                incr = test_context->argv[4];

              while ((test_context->next_test_count += incr) &&
                     test_context->next_test_count < limit)
                if (IPSEC_TEST_SUPPORTED(test_context->next_test_count))
                  break;
              if (test_context->next_test_count >= limit)
                test_context->next_test_count = 0xffffffff;
            }
          break;
        case TEST_NGM:
          if (test_context->argc < 1)
            {
              ssh_fatal("ngm needs one argument : %s",
                        test_context->current_test);
            }
          test_context->sleep_msec = test_context->argv[0];
          if (test_context->argc > 1)
            test_context->next_test_count = test_context->argv[1];
          else
            test_context->next_test_count = 0;

          if (!NGM_TEST_SUPPORTED(test_context->next_test_count))
            {
              incr = 1;
              limit = 0xffffffff;
              if (test_context->argc > 2)
                limit = test_context->argv[2];
              if (test_context->argc > 4)
                incr = test_context->argv[4];

              while ((test_context->next_test_count += incr) &&
                     test_context->next_test_count < limit)
                if (NGM_TEST_SUPPORTED(test_context->next_test_count))
                  break;
              if (test_context->next_test_count >= limit)
                test_context->next_test_count = 0xffffffff;
            }
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case TEST_CFG:
          test_context->next_test_count = 0;
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        case TEST_SLEEP:
          if (test_context->argc != 1)
            {
              ssh_fatal("Sleep needs one argument : %s",
                        test_context->current_test);
            }
          test_context->sleep_msec = test_context->argv[0];
          test_context->next_test_count = 0;
          break;
        case TEST_CLEAR:
          if (test_context->argc != 1)
            {
              ssh_fatal("Clear needs one argument : %s",
                        test_context->current_test);
            }
          test_context->next_test_count = 0;
          break;
        case TEST_LOOP_ISAKMP:
        case TEST_LOOP_ASYNC_ISAKMP:
          if (test_context->argc < 1)
            {
              ssh_fatal("loop_isakmp needs two arguments : %s cnt test",
                        test_context->current_test);
            }
          test_context->sleep_msec = 0;
          if (test_context->argc >= 1)
            test_context->current_test_count = test_context->argv[1];
          else
            test_context->current_test_count = 0;
          test_context->next_test_count = test_context->argv[0] - 1;

          if (!SSH_IKE_TEST_SUPPORTED(test_context->current_test_count))
            {
              limit = 0xffffffff;
              while (++test_context->current_test_count &&
                     test_context->current_test_count < limit)
                if (SSH_IKE_TEST_SUPPORTED(test_context->current_test_count))
                  break;
              if (test_context->current_test_count >= limit)
                test_context->current_test_count = 0xffffffff;
            }
          break;
        case TEST_LOOP_IPSEC:
          if (test_context->argc < 1)
            {
              ssh_fatal("loop_ipsec needs two arguments : %s",
                        test_context->current_test);
            }
          test_context->sleep_msec = 0;
          if (test_context->argc >= 1)
            test_context->current_test_count = test_context->argv[1];
          else
            test_context->current_test_count = 0;
          test_context->next_test_count = test_context->argv[0] - 1;

          if (!IPSEC_TEST_SUPPORTED(test_context->current_test_count))
            {
              limit = 0xffffffff;
              while (++test_context->current_test_count &&
                     test_context->current_test_count < limit)
                if (IPSEC_TEST_SUPPORTED(test_context->current_test_count))
                  break;
              if (test_context->current_test_count >= limit)
                test_context->current_test_count = 0xffffffff;
            }
          break;
        }
      if (*p == ',')
        test_context->current_test = ++p;
      else if (!*p)
        test_context->current_test = p;
      else
        ssh_fatal("Syntax error waiting for ,: %s", p);
    }
  test = test_context->next_test_count;
  if (test == 0xffffffff)
    goto retry;
  switch (test_context->test)
    {
    case TEST_SERVER_ISAKMP:
      test_context->current_test_count = test;
      if (test_context->next_test_count == 1)
        {
          SSH_IKE_DEBUG(3, NULL, ("Timeout exceeded"));
          test_context->sleep_msec = 1;
          test_context->next_test_count = 0xffffffff;
        }
      else
        {
          ++test_context->next_test_count;
        }
      break;
    case TEST_CLIENT_ISAKMP:
      test_context->current_test_count = test;
      ++test_context->next_test_count;
      if (test_context->next_test_count > 2)
        test_context->next_test_count = 0xffffffff;
      break;
    case TEST_ISAKMP:
      test_context->current_test_count = test;
      limit = 0xffffffff;
      incr = 1;
      if (test_context->argc > 2)
        limit = test_context->argv[2];
      if (test_context->argc > 4)
        incr = test_context->argv[4];

      while ((test_context->next_test_count += incr) &&
             test_context->next_test_count < limit)
        if (SSH_IKE_TEST_SUPPORTED(test_context->next_test_count))
          break;
      if (test_context->next_test_count >= limit)
        test_context->next_test_count = 0xffffffff;
      break;
    case TEST_IPSEC:
      test_context->current_test_count = test;
      limit = 0xffffffff;
      incr = 1;
      if (test_context->argc > 2)
        limit = test_context->argv[2];
      if (test_context->argc > 4)
        incr = test_context->argv[4];

      while ((test_context->next_test_count += incr) &&
             test_context->next_test_count < limit)
        if (IPSEC_TEST_SUPPORTED(test_context->next_test_count))
          break;
      if (test_context->next_test_count >= limit)
        test_context->next_test_count = 0xffffffff;
      break;
    case TEST_NGM:
      test_context->current_test_count = test;
      limit = 0xffffffff;
      incr = 1;
      if (test_context->argc > 2)
        limit = test_context->argv[2];
      if (test_context->argc > 4)
        incr = test_context->argv[4];

      while ((test_context->next_test_count += incr) &&
             test_context->next_test_count < limit)
        if (NGM_TEST_SUPPORTED(test_context->next_test_count))
          break;
      if (test_context->next_test_count >= limit)
        test_context->next_test_count = 0xffffffff;
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case TEST_CFG:
      test_context->current_test_count = test;
      test_context->next_test_count++;
      if (test_context->next_test_count > 2)
        test_context->next_test_count = 0xffffffff;
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case TEST_SLEEP:
      test_context->current_test_count = test;
      test_context->next_test_count = 0xffffffff;
      break;
    case TEST_CLEAR:
      test_context->current_test_count = test;
      test_context->next_test_count = 0xffffffff;
      break;
    case TEST_LOOP_ISAKMP:
    case TEST_LOOP_ASYNC_ISAKMP:
      test_context->next_test_count--;
      test = test_context->current_test_count;
      break;
    case TEST_LOOP_IPSEC:
      test_context->next_test_count--;
      test = test_context->current_test_count;
      break;
    }

  switch (test_context->test)
    {
    case TEST_CLIENT_ISAKMP:
      install_timeout = FALSE;
      ike_client_test(test_context,
                      test_context->server_context,
                      test_context->remote_ip,
                      test_context->remote_port,
                      test, !install_timeout);
      break;
    case TEST_SERVER_ISAKMP:
      /* Nothing to be done here */
      break;
    case TEST_ISAKMP:
      install_timeout = FALSE;

      if (test_context->argc > 3 &&
          test_context->argv[3])
        install_timeout = TRUE;

      ike_test(test_context,
               test_context->server_context, test_context->remote_ip,
               test_context->remote_port, test,
               !install_timeout);
      break;
    case TEST_IPSEC:
      install_timeout = FALSE;

      if (test_context->argc > 3 &&
          test_context->argv[3])
        install_timeout = TRUE;

      ipsec_test(test_context,
                 test_context->server_context, test_context->remote_ip,
                 test_context->remote_port, test,
                 !install_timeout);
      break;
    case TEST_NGM:
      install_timeout = FALSE;
      if (test_context->argc > 3 &&
          test_context->argv[3])
        install_timeout = TRUE;

      ngm_test(test_context,
               test_context->server_context, test_context->remote_ip,
               test_context->remote_port, test,
               !install_timeout);
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case TEST_CFG:
      install_timeout = FALSE;
      cfg_test(test_context,
               test_context->server_context, test_context->remote_ip,
               test_context->remote_port, test,
               FALSE);
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case TEST_SLEEP:
      break;
    case TEST_CLEAR:
      ssh_ike_remove_isakmp_sa_by_address(test_context->isakmp_context,
                                          NULL, NULL,
                                          NULL, NULL,
                                          test_context->argv[0] ?
                                          SSH_IKE_REMOVE_FLAGS_SEND_DELETE
                                          : 0);
      break;
    case TEST_LOOP_ISAKMP:
      install_timeout = FALSE;

      ike_test(test_context,
               test_context->server_context, test_context->remote_ip,
               test_context->remote_port, test,
               !install_timeout);
      break;
    case TEST_LOOP_ASYNC_ISAKMP:
      install_timeout = FALSE;
      test_context->test_number = test;
      test_context->total_ops = test_context->next_test_count + 2;
      test_context->completed_ops = 0; 
      test_context->started_ops = 0; 
      SSH_DEBUG(5, ("total_ops is %d", test_context->total_ops));
      ike_test_async(test_context, test_context->server_context, 
                     test_context->remote_ip, test_context->remote_port, 
                     test_context->test_number); 
      break;
    case TEST_LOOP_IPSEC:
      install_timeout = FALSE;
      ipsec_test(test_context,
                 test_context->server_context, test_context->remote_ip,
                 test_context->remote_port, test,
                 !install_timeout);
      break;
    }

  if (install_timeout)
    ssh_xregister_timeout(test_context->sleep_msec / 1000,
                         (test_context->sleep_msec % 1000) * 1000,
                         test_callback,
                         test_context);
}

#define BUF_SIZE 1024
#define MAX_KEYS 64

Boolean ike_add_string(SshADTContainer mapping, const char *type,
                       const char *value,
                       const char *data, size_t data_len)
{
  SshIkePMPreSharedKeyItem item;
  struct SshIkePayloadIDRec id;
  unsigned char buf[32];
  char *id_buffer;

  id.protocol_id = 0;
  id.port_number = 0;
  id.port_range_end = 0;

  if (strcmp(type, "ip") == 0)
    {
      id.identification_len = sizeof(buf);
      if (!ssh_inet_strtobin(value, buf, &id.identification_len))
        return FALSE;
      if (id.identification_len == 4)
        {
          id.id_type = IPSEC_ID_IPV4_ADDR;
          memcpy(id.identification.ipv4_addr, buf, id.identification_len);
        }
      else if (id.identification_len == 16)
        {
          id.id_type = IPSEC_ID_IPV6_ADDR;
          memcpy(id.identification.ipv6_addr, buf, id.identification_len);
        }
      else
        ssh_fatal("Invalid length returned from ssh_inet_strtobin");
    }
  else if (strcmp(type, "fqdn") == 0)
    {
      id.id_type = IPSEC_ID_FQDN;
      id.identification.fqdn = (char *) value;
      id.identification_len = strlen(value);
    }
  else if (strcmp(type, "userfqdn") == 0)
    {
      id.id_type = IPSEC_ID_USER_FQDN;
      id.identification.user_fqdn = (char *) value;
      id.identification_len = strlen(value);
    }
  else
    {
      return FALSE;
    }

  id_buffer = ssh_xmalloc(BUF_SIZE);

  ssh_ike_id_to_string(id_buffer, BUF_SIZE, &id);
  if (ssh_adt_strmap_exists(mapping, id_buffer))
    {
      SshADTHandle h;
      SshIkePMPreSharedKeyItem old_item;

      h = ssh_adt_get_handle_to_equal(mapping, id_buffer);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      old_item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(old_item->data);
      ssh_xfree(old_item);
      ssh_adt_strmap_remove(mapping, id_buffer);
    }
  item = ssh_xcalloc(1, sizeof(*item));
  item->data = ssh_xmemdup(data, data_len);
  item->data_len = data_len;
  ssh_adt_strmap_add(mapping, id_buffer, item);
  ssh_xfree(id_buffer);
  return TRUE;
}

Boolean ike_add_item(SshADTContainer mapping,
                     const char *type, const char *value,
                     const char *certificate, size_t certificate_len,
                     SshPrivateKey private_key)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  struct SshIkePayloadIDRec id;
  SshIkePMPrivateKeyItem item;
  unsigned char buf[32];
  char *id_buffer;

  id.protocol_id = 0;
  id.port_number = 0;
  id.port_range_end = 0;

  if (strcmp(type, "ip") == 0)
    {
      id.identification_len = sizeof(buf);
      if (!ssh_inet_strtobin(value, buf, &id.identification_len))
        return FALSE;
      if (id.identification_len == 4)
        {
          id.id_type = IPSEC_ID_IPV4_ADDR;
          memcpy(id.identification.ipv4_addr, buf, id.identification_len);
        }
      else if (id.identification_len == 16)
        {
          id.id_type = IPSEC_ID_IPV6_ADDR;
          memcpy(id.identification.ipv6_addr, buf, id.identification_len);
        }
      else
        ssh_fatal("Invalid length returned from ssh_inet_strtobin");
    }
  else if (strcmp(type, "fqdn") == 0)
    {
      id.id_type = IPSEC_ID_FQDN;
      id.identification.fqdn = (char *) value;
      id.identification_len = strlen(value);
    }
  else if (strcmp(type, "userfqdn") == 0)
    {
      id.id_type = IPSEC_ID_USER_FQDN;
      id.identification.user_fqdn = (char *) value;
      id.identification_len = strlen(value);
    }
  else
    {
      return FALSE;
    }
  id_buffer = ssh_xmalloc(BUF_SIZE);

  ssh_ike_id_to_string(id_buffer, BUF_SIZE, &id);
  if (ssh_adt_strmap_exists(mapping, id_buffer))
    {
      SshIkePMPrivateKeyItem old_item;
      SshADTHandle h;

      h = ssh_adt_get_handle_to_equal(mapping, id_buffer);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      old_item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(old_item->certificate);
      ssh_private_key_free(old_item->key);
      ssh_xfree(old_item);
      ssh_adt_strmap_remove(mapping, id_buffer);
    }
  item = ssh_xcalloc(1, sizeof(*item));
  item->certificate = ssh_xmemdup(certificate, certificate_len);
  item->certificate_len = certificate_len;
  if (ssh_private_key_copy(private_key, &item->key) != SSH_CRYPTO_OK)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_private_key_copy failed");
      ssh_warning("ssh_private_key_copy failed");
      ssh_free(item->certificate);
      ssh_free(item);
      ssh_xfree(id_buffer);
      return FALSE;
    }

  ssh_adt_strmap_add(mapping, id_buffer, item);
  ssh_xfree(id_buffer);
#endif /* SSHDIST_IKE_CERT_AUTH */
  return TRUE;
}

void ike_destroy_strings(SshADTContainer mapping)
{
  SshIkePMPreSharedKeyItem item;
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(mapping);
      h != SSH_ADT_INVALID;
      h = ssh_adt_enumerate_next(mapping, h))
    {
      item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(item->data);
      ssh_xfree(item);
    }
  ssh_adt_destroy(mapping);
}

void ike_destroy_items(SshADTContainer mapping)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshIkePMPrivateKeyItem item;
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(mapping);
      h != SSH_ADT_INVALID;
      h = ssh_adt_enumerate_next(mapping, h))
    {
      item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(item->certificate);
      ssh_private_key_free(item->key);
      ssh_xfree(item);
    }
  ssh_adt_destroy(mapping);
#endif /* SSHDIST_IKE_CERT_AUTH */

  return;
}

Boolean read_config_file(const char *file,
                         SshIkePMContext pm,
                         Boolean trust_all_certificates,
                         const char *local_ip_txt,
                         Boolean no_crls,
                         const char *ldap_server)
{
  FILE *fp = NULL;
  int i;
  char *buffer;
  char *key, *p, *value;
#ifdef DO_CERT_TESTS
  unsigned char *tmp;
  size_t len;
  int max_cas;
  SshIkePMCertCache certificate_cache = NULL;
  SshIkePMPrivateKeyCache private_key_cache = NULL;
  SshCMConfig cm_config = NULL;
#endif /* DO_CERT_TESTS */
  SshIkePMPreSharedKeyCache pre_shared_key_cache = NULL;
  char *environment_name = NULL;
  char **keys;
  char **values;
  int number_of_keys;
#ifdef DO_CERT_TESTS
  SshCMLocalNetworkStruct local_network;
#endif /* DO_CERT_TESTS */

  buffer = ssh_xmalloc(BUF_SIZE);
  keys = ssh_xmalloc(MAX_KEYS * sizeof(char *));
  values = ssh_xmalloc(MAX_KEYS * sizeof(char *));

  number_of_keys = 0;

  pm->pre_shared_key_cache = ssh_xcalloc(1, sizeof(*pre_shared_key_cache));
#ifdef DO_CERT_TESTS
  pm->certificate_cache = ssh_xcalloc(1, sizeof(*certificate_cache));
  pm->private_key_cache = ssh_xcalloc(1, sizeof(*private_key_cache));
#endif /* DO_CERT_TESTS */

  pre_shared_key_cache = pm->pre_shared_key_cache;
#ifdef DO_CERT_TESTS
  certificate_cache = pm->certificate_cache;
  private_key_cache = pm->private_key_cache;
#endif /* DO_CERT_TESTS */








  pre_shared_key_cache->mapping = ssh_adt_create_strmap();
#ifdef DO_CERT_TESTS
  private_key_cache->rsa_mapping = ssh_adt_create_strmap();
  private_key_cache->dss_mapping = ssh_adt_create_strmap();

  certificate_cache->number_of_master_cas = 0;
  max_cas = 10;
  certificate_cache->master_cas = ssh_xcalloc(max_cas,
                                              sizeof(unsigned char *));
  certificate_cache->master_ca_lens = ssh_xcalloc(max_cas, sizeof(size_t));

  cm_config = ssh_cm_config_allocate();
  if (cm_config == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_cm_config_allocate failed");
      goto error;
    }
#if 0
  ssh_cm_config_set_notify_callbacks(cm_config,
                                     ssh_ike_revoke_notify_cb,
                                     pm);
#endif
  ssh_cm_config_set_default_time_lock(cm_config, 300);
  ssh_cm_config_set_max_path_length(cm_config, 100);
  ssh_cm_config_set_max_restarts(cm_config, 300);
  ssh_cm_config_set_validity_secs(cm_config, 300);
  ssh_cm_config_set_crl_validity_secs(cm_config, 300, 300);
  ssh_cm_config_set_nega_cache_invalid_secs(cm_config, 300);

  certificate_cache->cert_cache = ssh_cm_allocate(cm_config);
  cm_config = NULL;
  if (certificate_cache->cert_cache == NULL)
    {
      if (call_fatal_on_error)
        ssh_fatal("ssh_cm_allocate failed");
      ssh_warning("ssh_cm_allocate failed");
      goto error;
    }

  memset(&local_network, 0, sizeof(local_network));
  local_network.socks = getenv("SSH_SOCKS_SERVER");
  if (getenv("http_proxy"))
    local_network.proxy = getenv("http_proxy");
  local_network.timeout_msecs = 10*1000; /* 10 seconds. */

  ssh_cm_edb_set_local_network(certificate_cache->cert_cache,
                               &local_network);
#ifdef SSHDIST_LDAP
  ssh_cm_edb_ldap_init(certificate_cache->cert_cache, ldap_server);
#endif /* SSHDIST_LDAP */
  ssh_cm_edb_http_init(certificate_cache->cert_cache);
  certificate_cache->trust_all_certificates = trust_all_certificates;
#endif /* DO_CERT_TESTS */

  SSH_DEBUG(5, ("Reading certificate cache config from %s", file));
  fp = fopen(file, "rb");
  if (fp == NULL)
    {
      printf("read_cert_cache_file: cannot read non-existing file %s.\n",
             file);
      ssh_xfree(buffer);
      ssh_xfree(keys);
      ssh_xfree(values);
      return TRUE;
    }

  while (1)
    {
      fgets(buffer, BUF_SIZE, fp);

      if (feof(fp))
        {
          strcpy(buffer, "[end]");
        }

      for (key = buffer; *key && isspace((unsigned char) *key); key++)
        ;
      if (*key == '#' || !*key)
        continue;
      for (p = key; *p && !isspace((unsigned char) *p); p++)
        ;
      if (*p)
        {
          *p++ = '\0';
          for (; *p && isspace((unsigned char) *p); p++)
            ;
        }
      if (*key == '[')
        {
          /* New environment */
          if (environment_name)
            {
              /* Store previous environment */
              if (strcmp(environment_name, "[ca]") == 0)
                {
#ifdef DO_CERT_TESTS
                  SshCMCertificate cert;
                  SshX509Certificate opencert;
                  int cnt;

                  for (i = 0; i < number_of_keys; i++)
                    {
                      char *filename;

                      filename = values[i];

                      SSH_DEBUG(7, ("Adding ca certificate %s", filename));
                      if (strcmp(keys[i], "binary-public-key") == 0)
                        {
                          if (!ssh_read_file(filename, &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read binary file %s",
                                          filename);
                              ssh_warning("Could not read binary file %s",
                                          filename);
                              goto error;
                            }
                        }
                      else if (strcmp(keys[i], "hexl-public-key") == 0)
                        {
                          if (!ssh_read_file_hexl(filename, &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read hexl "
                                          "encoded file %s",
                                          filename);
                              ssh_warning("Could not read hexl "
                                          "encoded file %s",
                                          filename);
                              goto error;
                            }
                        }
                      else
                        {
                          if (!ssh_read_file_base64(filename, &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read base64 "
                                          "encoded file %s",
                                          filename);
                              ssh_warning("Could not read base64 "
                                          "encoded file %s",
                                          filename);
                              goto error;
                            }
                        }
                      if (len == 0)
                        {
                          if (call_fatal_on_error)
                            ssh_fatal("read returned error");
                          ssh_warning("read returned error");
                          goto error;
                        }

                      cert = ssh_cm_cert_allocate(certificate_cache->
                                                  cert_cache);
                      if (cert == NULL)
                        {
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_allocate failed");
                          ssh_warning("ssh_cm_cert_allocate failed");
                          goto error;
                        }
                      if (ssh_cm_cert_set_ber(cert, tmp, len) !=
                          SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_set_ber failed");
                          ssh_warning("ssh_cm_cert_set_ber failed");
                          goto error;
                        }

                      if (ssh_cm_cert_force_trusted(cert) != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_force_trusted failed");
                          ssh_warning("ssh_cm_cert_force_trusted failed");
                          goto error;
                        }

                      if (max_cas >= certificate_cache->number_of_master_cas)
                        {
                          max_cas += 10;
                          certificate_cache->master_cas =
                            ssh_xrealloc(certificate_cache->master_cas,
                                         max_cas *
                                         sizeof(unsigned char *));
                          certificate_cache->master_ca_lens =
                            ssh_xrealloc(certificate_cache->master_ca_lens,
                                         max_cas * sizeof(size_t));
                        }

                      if (ssh_cm_cert_get_x509(cert, &opencert)
                          != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_get_x509 failed");
                          ssh_warning("ssh_cm_cert_get_x509 failed");
                          goto error;
                        }

                      cnt = certificate_cache->number_of_master_cas;
                      if (ssh_x509_cert_get_subject_name_der(opencert,
                                                             &certificate_cache
                                                             ->master_cas[cnt],
                                                             &certificate_cache
                                                             ->master_ca_lens
                                                             [cnt]) == FALSE)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_x509_cert_free(opencert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_x509_cert_get_subject_name_der");
                          ssh_warning("ssh_x509_cert_get_subject_name_der");
                          goto error;
                        }
                      certificate_cache->number_of_master_cas++;
                      ssh_x509_cert_free(opencert);

                      if (no_crls)
                        if (ssh_cm_cert_non_crl_issuer(cert) !=
                            SSH_CM_STATUS_OK)
                          {
                            ssh_cm_cert_free(cert);
                            ssh_xfree(tmp);
                            if (call_fatal_on_error)
                              ssh_fatal("ssh_cm_cert_non_crl_issuer failed");
                            ssh_warning("ssh_cm_cert_non_crl_issuer failed");
                            goto error;
                          }


                      if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_set_locked failed");
                          ssh_warning("ssh_cm_cert_set_locked failed");
                          goto error;
                        }

                      if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_add failed");
                          ssh_warning("ssh_cm_add failed");
                          goto error;
                        }

                      ssh_xfree(tmp);
                    }
#endif /* DO_CERT_TESTS */
                }
              else if (strcmp(environment_name, "[rsa-key]") == 0 ||
                       strcmp(environment_name, "[dsa-key]") == 0)
                {
#ifdef DO_CERT_TESTS
                  char *filename, *certificate;
                  SshADTContainer mapping;
                  SshPrivateKey private_key;
                  SshCMCertificate cert;
                  int priv_format = 0;
                  int cert_format = 0;

                  if (strcmp(environment_name, "[rsa-key]") == 0)
                    mapping = private_key_cache->rsa_mapping;
                  else
                    mapping = private_key_cache->dss_mapping;

                  filename = NULL;
                  certificate = NULL;
                  for (i = 0; i < number_of_keys; i++)
                    {
                      if (strcmp(keys[i], "private-key") == 0)
                        {
                          priv_format = 1;
                          if (filename)
                            ssh_fatal("Private key given twice in "
                                      "the %s environment", environment_name);
                          filename = values[i];
                        }
                      else if (strcmp(keys[i], "binary-private-key") == 0)
                        {
                          priv_format = 0;
                          if (filename)
                            ssh_fatal("Private key given twice "
                                      "in the %s environment",
                                      environment_name);
                          filename = values[i];
                        }
                      else if (strcmp(keys[i], "hexl-private-key") == 0)
                        {
                          priv_format = 2;
                          if (filename)
                            ssh_fatal("Private key given twice in "
                                      "the %s environment", environment_name);
                          filename = values[i];
                        }
                      else if (strcmp(keys[i], "certificate") == 0)
                        {
                          cert_format = 1;
                          if (certificate)
                            ssh_fatal("certificate given twice in "
                                      "the %s environment", environment_name);
                          certificate = values[i];
                        }
                      else if (strcmp(keys[i], "binary-certificate") == 0)
                        {
                          cert_format = 0;
                          if (certificate)
                            ssh_fatal("certificate given twice in "
                                      "the %s environment", environment_name);
                          certificate = values[i];
                        }
                      else if (strcmp(keys[i], "hexl-certificate") == 0)
                        {
                          cert_format = 2;
                          if (certificate)
                            ssh_fatal("certificate given twice in "
                                      "the %s environment", environment_name);
                          certificate = values[i];
                        }
                    }
                  if (!filename)
                    ssh_fatal("No private key given for %s environment",
                              environment_name);

                  if (!certificate)
                    ssh_fatal("No certificate given for %s environment",
                              environment_name);

                  SSH_DEBUG(7, ("Adding private key %s", filename));
                  if (priv_format == 0)
                    {
                      if (!ssh_read_file(filename, &tmp, &len))
                        {
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read binary file %s",
                                      filename);
                          ssh_warning("Could not read binary file %s",
                                      filename);
                          goto error;
                        }
                    }
                  else if (priv_format == 1)
                    {
                      if (!ssh_read_file_base64(filename, &tmp, &len))
                        {
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read base64 "
                                      "encoded file %s",
                                      filename);
                          ssh_warning("Could not read base64 "
                                      "encoded file %s",
                                      filename);
                          goto error;
                        }
                    }
                  else
                    {
                      if (!ssh_read_file_hexl(filename, &tmp, &len))
                        {
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read hexl "
                                      "encoded file %s",
                                      filename);
                          ssh_warning("Could not read hexl "
                                      "encoded file %s",
                                      filename);
                          goto error;
                        }
                    }

                  if (len == 0)
                    {
                      if (call_fatal_on_error)
                        ssh_fatal("read returned error");
                      ssh_warning("read returned error");
                      goto error;
                    }
                  private_key = ssh_x509_decode_private_key(tmp, len);
                  if (private_key == NULL)
                    {
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ssh_x509_decode_private_key failed");
                      ssh_warning("ssh_x509_decode_private_key failed");
                      goto error;
                    }
                  ssh_xfree(tmp);

                  SSH_DEBUG(7, ("Adding certificate %s", certificate));
                  if (cert_format == 0)
                    {
                      if (!ssh_read_file(certificate, &tmp, &len))
                        {
                          ssh_private_key_free(private_key);
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read binary file %s",
                                      filename);
                          ssh_warning("Could not read binary file %s",
                                      filename);
                          goto error;
                        }
                    }
                  else if (cert_format == 1)
                    {
                      if (!ssh_read_file_base64(certificate, &tmp, &len))
                        {
                          ssh_private_key_free(private_key);
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read base64 "
                                      "encoded file %s",
                                      filename);
                          ssh_warning("Could not read base64 "
                                      "encoded file %s",
                                      filename);
                          goto error;
                        }
                    }
                  else
                    {
                      if (!ssh_read_file_hexl(certificate, &tmp, &len))
                        {
                          ssh_private_key_free(private_key);
                          if (call_fatal_on_error)
                            ssh_fatal("Could not read hexl "
                                      "encoded file %s",
                                      filename);
                          ssh_warning("Could not read hexl "
                                      "encoded file %s",
                                      filename);
                          goto error;
                        }
                    }

                  if (len == 0)
                    {
                      ssh_private_key_free(private_key);
                      if (call_fatal_on_error)
                        ssh_fatal("read returned error");
                      ssh_warning("read returned error");
                      goto error;
                    }

                  cert = ssh_cm_cert_allocate(certificate_cache->cert_cache);
                  if (cert == NULL)
                    {
                      ssh_private_key_free(private_key);
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ssh_cm_cert_allocate failed");
                      ssh_warning("ssh_cm_cert_allocate failed");
                      goto error;
                    }
                  if (ssh_cm_cert_set_ber(cert, tmp, len) !=
                      SSH_CM_STATUS_OK)
                    {
                      ssh_cm_cert_free(cert);
                      ssh_private_key_free(private_key);
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ssh_cm_cert_set_ber failed");
                      ssh_warning("ssh_cm_cert_set_ber failed");
                      goto error;
                    }

                  if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
                    {
                      ssh_cm_cert_free(cert);
                      ssh_private_key_free(private_key);
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ssh_cm_cert_set_locked failed");
                      ssh_warning("ssh_cm_cert_set_locked failed");
                      goto error;
                    }

                  if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
                    {
                      ssh_cm_cert_free(cert);
                      ssh_private_key_free(private_key);
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ssh_cm_add failed");
                      ssh_warning("ssh_cm_add failed");
                      goto error;
                    }

                  if (!ike_add_item(mapping, "ip", local_ip_txt,
                                   tmp, len, private_key))
                    {
                      ssh_private_key_free(private_key);
                      ssh_xfree(tmp);
                      if (call_fatal_on_error)
                        ssh_fatal("ike_add_item failed");
                      ssh_warning("ike_add_item failed");
                      goto error;
                    }
                  for (i = 0; i < number_of_keys; i++)
                    {
                      /* This will add the valid keys to the database, rest
                         are ignored. */
                      ike_add_item(mapping, keys[i], values[i],
                                   tmp, len, private_key);
                    }
                  ssh_private_key_free(private_key);
                  ssh_xfree(tmp);
#endif /* DO_CERT_TESTS */
                }
              else if (strcmp(environment_name, "[pre-shared-key]") == 0)
                {
                  char *pre_shared_key;

                  pre_shared_key = NULL;
                  for (i = 0; i < number_of_keys; i++)
                    {
                      if (strcmp(keys[i], "key") == 0)
                        {
                          if (pre_shared_key)
                            ssh_fatal("Pre shared key given twice in "
                                      "the %s environment", environment_name);
                          pre_shared_key = values[i];
                        }
                    }
                  if (!pre_shared_key)
                    ssh_fatal("No pre shared key key given for %s environment",
                              environment_name);

                  for (i = 0; i < number_of_keys; i++)
                    {
                      /* This will add valid keys to the db, rest are
                         ignored. */
                      ike_add_string(pre_shared_key_cache->mapping,
                                     keys[i], values[i], pre_shared_key,
                                     strlen(pre_shared_key));
                    }
                }
              else if (strcmp(environment_name, "[certificates]") == 0)
                {
#ifdef DO_CERT_TESTS
                  for (i = 0; i < number_of_keys; i++)
                    {
                      SshCMCertificate cert;

                      SSH_DEBUG(7, ("Adding certificate %s", values[i]));
                      if (strcmp(keys[i], "binary-certificate") == 0)
                        {
                          if (!ssh_read_file(values[i], &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read binary file %s",
                                          values[i]);
                              ssh_warning("Could not read binary file %s",
                                          values[i]);
                              goto error;
                            }
                        }
                      else if (strcmp(keys[i], "hexl-certificate") == 0)
                        {
                          if (!ssh_read_file_hexl(values[i], &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read hexl encoded "
                                          "file %s",
                                          values[i]);
                              ssh_warning("Could not read hexl encoded "
                                          "file %s",
                                          values[i]);
                              goto error;
                            }
                        }
                      else
                        {
                          if (!ssh_read_file_base64(values[i], &tmp, &len))
                            {
                              if (call_fatal_on_error)
                                ssh_fatal("Could not read base64 encoded "
                                          "file %s",
                                          values[i]);
                              ssh_warning("Could not read base64 encoded "
                                          "file %s",
                                          values[i]);
                              goto error;
                            }
                        }

                      if (len == 0)
                        {
                          if (call_fatal_on_error)
                            ssh_fatal("read returned error");
                          ssh_warning("read returned error");
                          goto error;
                        }

                      cert = ssh_cm_cert_allocate(certificate_cache->
                                                  cert_cache);
                      if (cert == NULL)
                        {
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_allocate failed");
                          ssh_warning("ssh_cm_cert_allocate failed");
                          goto error;
                        }
                      if (ssh_cm_cert_set_ber(cert, tmp, len) !=
                          SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_set_ber failed");
                          ssh_warning("ssh_cm_cert_set_ber failed");
                          goto error;
                        }

                      if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_cert_set_locked failed");
                          ssh_warning("ssh_cm_cert_set_locked failed");
                          goto error;
                        }

                      if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
                        {
                          ssh_cm_cert_free(cert);
                          ssh_xfree(tmp);
                          if (call_fatal_on_error)
                            ssh_fatal("ssh_cm_add failed");
                          ssh_warning("ssh_cm_add failed");
                          goto error;
                        }
                      ssh_xfree(tmp);
                    }
#endif /* DO_CERT_TESTS */
                }
              else
                {
                  ssh_fatal("Unknown environment name : %s", environment_name);
                }
              ssh_xfree(environment_name);
              environment_name = NULL;
            }
          for (i = 0; i < number_of_keys; i++)
            {
              ssh_xfree(keys[i]);
              ssh_xfree(values[i]);
            }
          number_of_keys = 0;
          if (feof(fp))
            break;
          environment_name = ssh_xstrdup(key);
          continue;
        }
      if (*p++ != '=')
        ssh_fatal("Syntax error in cert config file waiting for '='");
      for (; *p && isspace((unsigned char) *p); p++)
        ;
      for (value = p; *p && !isspace((unsigned char) *p); p++)
        ;
      *p = '\0';
      keys[number_of_keys] = ssh_xstrdup(key);
      values[number_of_keys] = ssh_xstrdup(value);
      number_of_keys++;
    }
  fclose(fp);
  ssh_xfree(buffer);
  ssh_xfree(keys);
  ssh_xfree(values);
  return TRUE;
#ifdef DO_CERT_TESTS
 error:
#endif /* DO_CERT_TESTS */
  for (i = 0; i < number_of_keys; i++)
    {
      ssh_xfree(keys[i]);
      ssh_xfree(values[i]);
    }
  ssh_xfree(environment_name);
#ifdef DO_CERT_TESTS
  if (fp != NULL)
    fclose(fp);
  if (certificate_cache->cert_cache)
    {
      ssh_cm_free(certificate_cache->cert_cache);
    }
  if (cm_config)
    ssh_cm_config_free(cm_config);
  if (certificate_cache)
    {
      ssh_xfree(certificate_cache->master_ca_lens);
      ssh_xfree(certificate_cache->master_cas);
    }
  if (private_key_cache)
    {
      ssh_adt_destroy(private_key_cache->rsa_mapping);
      ssh_adt_destroy(private_key_cache->dss_mapping);
    }
#endif /* DO_CERT_TESTS */
  if (pre_shared_key_cache)
    ssh_adt_destroy(pre_shared_key_cache->mapping);
#ifdef DO_CERT_TESTS
  ssh_xfree(private_key_cache);
  ssh_xfree(certificate_cache);
#endif /* DO_CERT_TESTS */
  ssh_xfree(pre_shared_key_cache);
  ssh_xfree(values);
  ssh_xfree(keys);
  ssh_xfree(buffer);
  return FALSE;
}

typedef struct SshMacroRec {
  const char *macro_name;
  const char *replacement;
} SshMacro;

/* isakmp(,0xkgheax,), ipsec(,0xtgehp,) */
const SshMacro test_macros[] = {
  { "all", "sleep(2000),isakmp(1,0,0xfffff),sleep(5000),ngm(1,0,0xf),"
#ifdef SSHDIST_ISAKMP_CFG_MODE
    "sleep(5000),cfg(0),"
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    "sleep(5000),ipsec(1,0,0x1ffff),sleep(10000)" },
  { "short", "sleep(2000),"
    "isakmp(1,0x11510,0x1151f,0,0x00001)," /* All exchange methods */
    "isakmp(1,0x11502,0x115f2,0,0x00010)," /* All auhentication methods */
    "isakmp(1,0x11500,0x115ff,0,0x00001)," /* All xchg and auth methods */
    "isakmp(1,0x11014,0x11f14,0,0x00100)," /* All encryption algorithms */
    "isakmp(1,0x10514,0x1f514,0,0x01000)," /* All hash functions */
    "isakmp(1,0x01514,0xf1514,0,0x10000)," /* All groups */
    "sleep(5000),ngm(1,0,0xf)," /* All newgroup tests */
#ifdef SSHDIST_ISAKMP_CFG_MODE
    "sleep(5000),cfg(0),"
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    "sleep(5000),"
    "ipsec(1,0x11330,0x1133f,0,0x00001)," /* All protocols*/
    "ipsec(1,0x11301,0x113f1,0,0x00010)," /* All hash/auth algorithms */
    "ipsec(1,0x11031,0x11f31,0,0x00100)," /* All encryption algorithms */
    "ipsec(1,0x10331,0x1f331,0,0x01000)," /* All groups */
    "ipsec(1,0x01331,0xf1331,0,0x10000)," /* All modes (tunnel/transport) */
    "sleep(15000)" },

  { "all-grp", "sleep(2000),"
    "isakmp(1,0x11112,0x11112),isakmp(1,0x21112,0x21112),"



    "isakmp(1,0x51112,0x51112),isakmp(1,0xb1112,0xb1112),"
#ifdef SSHDIST_CRYPT_ECP
    "isakmp(1,0xc1112,0xc1112),"
#endif /* SSHDIST_CRYPT_ECP */



    "sleep(2000)"
  },

  { "qm-md5-no-pfs-grp1", "qm-esp-des-md5-no-pfs,qm-esp-des-md5-grp1" },
  { "qm-sha-no-pfs-grp1", "qm-esp-des-sha-no-pfs,qm-esp-des-sha-grp1" },
  { "qm-md5-no-pfs-grp2", "qm-esp-des-md5-no-pfs,qm-esp-des-md5-grp2" },
  { "qm-sha-no-pfs-grp2", "qm-esp-des-sha-no-pfs,qm-esp-des-sha-grp2" },

  /* PSK */
  { "all-psk-des-md5",
    "mm-psk-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-des-sha",
    "mm-psk-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-des", "all-psk-des-md5,all-psk-des-sha" },

  { "all-psk-idea-md5",
    "mm-psk-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-idea-sha",
    "mm-psk-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-idea", "all-psk-idea-md5,all-psk-idea-sha" },

  { "all-psk-blowfish-md5",
    "mm-psk-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-blowfish-sha",
    "mm-psk-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-blowfish", "all-psk-blowfish-md5,all-psk-blowfish-sha" },

  { "all-psk-rc5-md5",
    "mm-psk-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-rc5-sha",
    "mm-psk-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-rc5", "all-psk-rc5-md5,all-psk-rc5-sha" },

  { "all-psk-3des-md5",
    "mm-psk-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-3des-sha",
    "mm-psk-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-3des", "all-psk-3des-md5,all-psk-3des-sha" },

  { "all-psk-cast-md5",
    "mm-psk-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-psk-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-psk-cast-sha",
    "mm-psk-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-psk-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-psk-cast", "all-psk-cast-md5,all-psk-cast-sha" },

  { "all-psk",
    "all-psk-des,"
#ifdef WITH_IDEA
    "all-psk-idea,"
#endif /* WITH_IDEA */
    "all-psk-blowfish,"



    "all-psk-3des,"
    "all-psk-cast" },
  { "all-psk-des-blowfish-3des", "all-psk-des,all-psk-blowfish,all-psk-3des" },

  /* PSK-mm */
  { "all-mm-psk-des-md5",
    "mm-psk-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-des-sha",
    "mm-psk-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-des", "all-mm-psk-des-md5,all-mm-psk-des-sha" },

  { "all-mm-psk-des-md5-grp2",
    "mm-psk-des-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-des-sha-grp2",
    "mm-psk-des-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-des-grp2", "all-mm-psk-des-md5-grp2,all-mm-psk-des-sha-grp2" },

  { "all-mm-psk-idea-md5",
    "mm-psk-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-idea-sha",
    "mm-psk-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-idea", "all-mm-psk-idea-md5,all-mm-psk-idea-sha" },

  { "all-mm-psk-idea-md5-grp2",
    "mm-psk-idea-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-idea-sha-grp2",
    "mm-psk-idea-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-idea-grp2",
    "all-mm-psk-idea-md5-grp2,all-mm-psk-idea-sha-grp2" },

  { "all-mm-psk-blowfish-md5",
    "mm-psk-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-blowfish-sha",
    "mm-psk-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-blowfish", "all-mm-psk-blowfish-md5,all-mm-psk-blowfish-sha" },

  { "all-mm-psk-blowfish-md5-grp2",
    "mm-psk-blowfish-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-blowfish-sha-grp2",
    "mm-psk-blowfish-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-blowfish-grp2",
    "all-mm-psk-blowfish-md5-grp2,all-mm-psk-blowfish-sha-grp2" },

  { "all-mm-psk-rc5-md5",
    "mm-psk-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-rc5-sha",
    "mm-psk-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-rc5", "all-mm-psk-rc5-md5,all-mm-psk-rc5-sha" },

  { "all-mm-psk-rc5-md5-grp2",
    "mm-psk-rc5-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-rc5-sha-grp2",
    "mm-psk-rc5-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-rc5-grp2",
    "all-mm-psk-rc5-md5-grp2,all-mm-psk-rc5-sha-grp2" },

  { "all-mm-psk-3des-md5",
    "mm-psk-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-3des-sha",
    "mm-psk-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-3des", "all-mm-psk-3des-md5,all-mm-psk-3des-sha" },

  { "all-mm-psk-3des-md5-grp2",
    "mm-psk-3des-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-3des-sha-grp2",
    "mm-psk-3des-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-3des-grp2",
    "all-mm-psk-3des-md5-grp2,all-mm-psk-3des-sha-grp2" },

  { "all-mm-psk-cast-md5",
    "mm-psk-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-cast-sha",
    "mm-psk-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-mm-psk-cast", "all-mm-psk-cast-md5,all-mm-psk-cast-sha" },

  { "all-mm-psk-cast-md5-grp2",
    "mm-psk-cast-md5-grp2,qm-md5-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-cast-sha-grp2",
    "mm-psk-cast-sha-grp2,qm-sha-no-pfs-grp2,clear(0)" },
  { "all-mm-psk-cast-grp2",
    "all-mm-psk-cast-md5-grp2,all-mm-psk-cast-sha-grp2" },

  { "all-mm-psk",
    "all-mm-psk-des,"
#ifdef WITH_IDEA
    "all-mm-psk-idea,"
#endif /* WITH_IDEA */
    "all-mm-psk-blowfish,"



    "all-mm-psk-3des,"
    "all-mm-psk-cast" },

#ifdef DO_CERT_TESTS
  /* DSS */
  { "all-dss-sig-des-md5",
    "mm-dss-sig-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-des-sha",
    "mm-dss-sig-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-des", "all-dss-sig-des-md5,all-dss-sig-des-sha" },

  { "all-dss-sig-idea-md5",
    "mm-dss-sig-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-idea-sha",
    "mm-dss-sig-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-idea", "all-dss-sig-idea-md5,all-dss-sig-idea-sha" },

  { "all-dss-sig-blowfish-md5",
    "mm-dss-sig-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-blowfish-sha",
    "mm-dss-sig-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-blowfish",
    "all-dss-sig-blowfish-md5,all-dss-sig-blowfish-sha" },

  { "all-dss-sig-rc5-md5",
    "mm-dss-sig-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-rc5-sha",
    "mm-dss-sig-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-rc5",
    "all-dss-sig-rc5-md5,all-dss-sig-rc5-sha" },

  { "all-dss-sig-3des-md5",
    "mm-dss-sig-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-3des-sha",
    "mm-dss-sig-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-3des", "all-dss-sig-3des-md5,all-dss-sig-3des-sha" },

  { "all-dss-sig-cast-md5",
    "mm-dss-sig-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-dss-sig-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-cast-sha",
    "mm-dss-sig-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-dss-sig-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-dss-sig-cast", "all-dss-sig-cast-md5,all-dss-sig-cast-sha" },

  { "all-dss-sig",
    "all-dss-sig-des,"
#ifdef WITH_IDEA
    "all-dss-sig-idea,"
#endif /* WITH_IDEA */
    "all-dss-sig-blowfish,"



    "all-dss-sig-3des,"
    "all-dss-sig-cast" },

  /* RSA sig */
  { "all-rsa-sig-des-md5",
    "mm-rsa-sig-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-des-sha",
    "mm-rsa-sig-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-des", "all-rsa-sig-des-md5,all-rsa-sig-des-sha" },

  { "all-rsa-sig-idea-md5",
    "mm-rsa-sig-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-idea-sha",
    "mm-rsa-sig-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-idea", "all-rsa-sig-idea-md5,all-rsa-sig-idea-sha" },

  { "all-rsa-sig-blowfish-md5",
    "mm-rsa-sig-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-blowfish-sha",
    "mm-rsa-sig-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-blowfish",
    "all-rsa-sig-blowfish-md5,all-rsa-sig-blowfish-sha" },

  { "all-rsa-sig-rc5-md5",
    "mm-rsa-sig-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-rc5-sha",
    "mm-rsa-sig-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-rc5",
    "all-rsa-sig-rc5-md5,all-rsa-sig-rc5-sha" },

  { "all-rsa-sig-3des-md5",
    "mm-rsa-sig-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-3des-sha",
    "mm-rsa-sig-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-3des", "all-rsa-sig-3des-md5,all-rsa-sig-3des-sha" },

  { "all-rsa-sig-cast-md5",
    "mm-rsa-sig-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-cast-sha",
    "mm-rsa-sig-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-sig-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-sig-cast", "all-rsa-sig-cast-md5,all-rsa-sig-cast-sha" },

  { "all-rsa-sig",
    "all-rsa-sig-des,"
#ifdef WITH_IDEA
    "all-rsa-sig-idea,"
#endif /* WITH_IDEA */
    "all-rsa-sig-blowfish,"



    "all-rsa-sig-3des,"
    "all-rsa-sig-cast" },

  /* RSA enc */
  { "all-rsa-enc-des-md5",
    "mm-rsa-enc-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-des-sha",
    "mm-rsa-enc-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-des", "all-rsa-enc-des-md5,all-rsa-enc-des-sha" },

  { "all-rsa-enc-idea-md5",
    "mm-rsa-enc-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-idea-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-idea-sha",
    "mm-rsa-enc-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-idea-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-idea", "all-rsa-enc-idea-md5,all-rsa-enc-idea-sha" },

  { "all-rsa-enc-blowfish-md5",
    "mm-rsa-enc-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-blowfish-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-blowfish-sha",
    "mm-rsa-enc-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-blowfish-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-blowfish",
    "all-rsa-enc-blowfish-md5,all-rsa-enc-blowfish-sha" },

  { "all-rsa-enc-rc5-md5",
    "mm-rsa-enc-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-rc5-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-rc5-sha",
    "mm-rsa-enc-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-rc5-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-rc5",
    "all-rsa-enc-rc5-md5,all-rsa-enc-rc5-sha" },

  { "all-rsa-enc-3des-md5",
    "mm-rsa-enc-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-3des-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-3des-sha",
    "mm-rsa-enc-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-3des-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-3des", "all-rsa-enc-3des-md5,all-rsa-enc-3des-sha" },

  { "all-rsa-enc-cast-md5",
    "mm-rsa-enc-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-cast-md5-grp1,qm-md5-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-cast-sha",
    "mm-rsa-enc-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0),"
    "ag-rsa-enc-cast-sha-grp1,qm-sha-no-pfs-grp1,clear(0)" },
  { "all-rsa-enc-cast", "all-rsa-enc-cast-md5,all-rsa-enc-cast-sha" },

  { "all-rsa-enc",
    "all-rsa-enc-des,"
#ifdef WITH_IDEA
    "all-rsa-enc-idea,"
#endif /* WITH_IDEA */
    "all-rsa-enc-blowfish,"



    "all-rsa-enc-3des,"
    "all-rsa-enc-cast" },
#endif /* DO_CERT_TESTS */

  /* Generic */
  { "server", "sleep(86400000)" },
  { "mm-md5", "mm-psk-des-md5-grp1" },
  { "mm-sha", "mm-psk-des-sha-grp1" },
  { "ag-md5", "ag-psk-des-md5-grp1" },
  { "ag-sha", "ag-psk-des-sha-grp1" },
  { "initial-mm-md5", "isakmp(1,0x08051712,0x08051712)" },
  { "mm-md5-qm-cesp", "mm-md5,qm-esp-des-md5-grp1" },
  { "mm-sha-qm-cesp", "mm-sha,qm-esp-des-sha-grp1" },
  { "mm-md5-qm-cesp-nopfs", "mm-md5,qm-esp-des-md5-no-pfs" },
  { "mm-sha-qm-cesp-nopfs", "mm-sha,qm-esp-des-sha-no-pfs" },

  { "mm-md5-ngm-qm-cesp", "mm-md5,ngm(1,0,0xf)"
    ",qm-esp-des-md5-grpb"
#ifdef SSHDIST_CRYPT_ECP
    ",qm-esp-des-md5-grpc"
#endif /* SSHDIST_CRYPT_ECP */



  },

  /* Individual tests */
  { "mm-psk-des-md5-grp1", "isakmp(1,0x11112,0x11112)" },
  { "mm-psk-des-sha-grp1", "isakmp(1,0x12112,0x12112)" },
  { "mm-psk-des-md5-grp2", "isakmp(1,0x21112,0x21112)" },
  { "mm-psk-des-sha-grp2", "isakmp(1,0x22112,0x22112)" },
  { "mm-psk-idea-md5-grp1", "isakmp(1,0x11212,0x11212)" },
  { "mm-psk-idea-sha-grp1", "isakmp(1,0x12212,0x12212)" },
  { "mm-psk-idea-md5-grp2", "isakmp(1,0x21212,0x21212)" },
  { "mm-psk-idea-sha-grp2", "isakmp(1,0x22212,0x22212)" },
  { "mm-psk-blowfish-md5-grp1", "isakmp(1,0x11312,0x11312)" },
  { "mm-psk-blowfish-sha-grp1", "isakmp(1,0x12312,0x12312)" },
  { "mm-psk-blowfish-md5-grp2", "isakmp(1,0x21312,0x21312)" },
  { "mm-psk-blowfish-sha-grp2", "isakmp(1,0x22312,0x22312)" },
  { "mm-psk-rc5-md5-grp1", "isakmp(1,0x11412,0x11412)" },
  { "mm-psk-rc5-sha-grp1", "isakmp(1,0x12412,0x12412)" },
  { "mm-psk-rc5-md5-grp2", "isakmp(1,0x21412,0x21412)" },
  { "mm-psk-rc5-sha-grp2", "isakmp(1,0x22412,0x22412)" },
  { "mm-psk-3des-md5-grp1", "isakmp(1,0x11512,0x11512)" },
  { "mm-psk-3des-sha-grp1", "isakmp(1,0x12512,0x12512)" },
  { "mm-psk-3des-md5-grp2", "isakmp(1,0x21512,0x21512)" },
  { "mm-psk-3des-sha-grp2", "isakmp(1,0x22512,0x22512)" },
  { "mm-psk-cast-md5-grp1", "isakmp(1,0x11612,0x11612)" },
  { "mm-psk-cast-sha-grp1", "isakmp(1,0x12612,0x12612)" },
  { "mm-psk-cast-md5-grp2", "isakmp(1,0x21612,0x21612)" },
  { "mm-psk-cast-sha-grp2", "isakmp(1,0x22612,0x22612)" },

#ifdef DO_CERT_TESTS
  { "mm-dss-sig-des-md5-grp1", "isakmp(1,0x11122,0x11122)" },
  { "mm-dss-sig-des-sha-grp1", "isakmp(1,0x12122,0x12122)" },
  { "mm-dss-sig-des-md5-grp2", "isakmp(1,0x21122,0x21122)" },
  { "mm-dss-sig-des-sha-grp2", "isakmp(1,0x22122,0x22122)" },
  { "mm-dss-sig-idea-md5-grp1", "isakmp(1,0x11222,0x11222)" },
  { "mm-dss-sig-idea-sha-grp1", "isakmp(1,0x12222,0x12222)" },
  { "mm-dss-sig-idea-md5-grp2", "isakmp(1,0x21222,0x21222)" },
  { "mm-dss-sig-idea-sha-grp2", "isakmp(1,0x22222,0x22222)" },
  { "mm-dss-sig-blowfish-md5-grp1", "isakmp(1,0x11322,0x11322)" },
  { "mm-dss-sig-blowfish-sha-grp1", "isakmp(1,0x12322,0x12322)" },
  { "mm-dss-sig-blowfish-md5-grp2", "isakmp(1,0x21322,0x21322)" },
  { "mm-dss-sig-blowfish-sha-grp2", "isakmp(1,0x22322,0x22322)" },
  { "mm-dss-sig-rc5-md5-grp1", "isakmp(1,0x11422,0x11422)" },
  { "mm-dss-sig-rc5-sha-grp1", "isakmp(1,0x12422,0x12422)" },
  { "mm-dss-sig-rc5-md5-grp2", "isakmp(1,0x21422,0x21422)" },
  { "mm-dss-sig-rc5-sha-grp2", "isakmp(1,0x22422,0x22422)" },
  { "mm-dss-sig-3des-md5-grp1", "isakmp(1,0x11522,0x11522)" },
  { "mm-dss-sig-3des-sha-grp1", "isakmp(1,0x12522,0x12522)" },
  { "mm-dss-sig-3des-md5-grp2", "isakmp(1,0x21522,0x21522)" },
  { "mm-dss-sig-3des-sha-grp2", "isakmp(1,0x22522,0x22522)" },
  { "mm-dss-sig-cast-md5-grp1", "isakmp(1,0x11622,0x11622)" },
  { "mm-dss-sig-cast-sha-grp1", "isakmp(1,0x12622,0x12622)" },
  { "mm-dss-sig-cast-md5-grp2", "isakmp(1,0x21622,0x21622)" },
  { "mm-dss-sig-cast-sha-grp2", "isakmp(1,0x22622,0x22622)" },

  { "mm-rsa-sig-des-md5-grp1", "isakmp(1,0x11132,0x11132)" },
  { "mm-rsa-sig-des-sha-grp1", "isakmp(1,0x12132,0x12132)" },
  { "mm-rsa-sig-des-md5-grp2", "isakmp(1,0x21132,0x21132)" },
  { "mm-rsa-sig-des-sha-grp2", "isakmp(1,0x22132,0x22132)" },
  { "mm-rsa-sig-idea-md5-grp1", "isakmp(1,0x11232,0x11232)" },
  { "mm-rsa-sig-idea-sha-grp1", "isakmp(1,0x12232,0x12232)" },
  { "mm-rsa-sig-idea-md5-grp2", "isakmp(1,0x21232,0x21232)" },
  { "mm-rsa-sig-idea-sha-grp2", "isakmp(1,0x22232,0x22232)" },
  { "mm-rsa-sig-blowfish-md5-grp1", "isakmp(1,0x11332,0x11332)" },
  { "mm-rsa-sig-blowfish-sha-grp1", "isakmp(1,0x12332,0x12332)" },
  { "mm-rsa-sig-blowfish-md5-grp2", "isakmp(1,0x21332,0x21332)" },
  { "mm-rsa-sig-blowfish-sha-grp2", "isakmp(1,0x22332,0x22332)" },
  { "mm-rsa-sig-rc5-md5-grp1", "isakmp(1,0x11432,0x11432)" },
  { "mm-rsa-sig-rc5-sha-grp1", "isakmp(1,0x12432,0x12432)" },
  { "mm-rsa-sig-rc5-md5-grp2", "isakmp(1,0x21432,0x21432)" },
  { "mm-rsa-sig-rc5-sha-grp2", "isakmp(1,0x22432,0x22432)" },
  { "mm-rsa-sig-3des-md5-grp1", "isakmp(1,0x11532,0x11532)" },
  { "mm-rsa-sig-3des-sha-grp1", "isakmp(1,0x12532,0x12532)" },
  { "mm-rsa-sig-3des-md5-grp2", "isakmp(1,0x21532,0x21532)" },
  { "mm-rsa-sig-3des-sha-grp2", "isakmp(1,0x22532,0x22532)" },
  { "mm-rsa-sig-cast-md5-grp1", "isakmp(1,0x11632,0x11632)" },
  { "mm-rsa-sig-cast-sha-grp1", "isakmp(1,0x12632,0x12632)" },
  { "mm-rsa-sig-cast-md5-grp2", "isakmp(1,0x21632,0x21632)" },
  { "mm-rsa-sig-cast-sha-grp2", "isakmp(1,0x22632,0x22632)" },

  { "mm-rsa-enc-des-md5-grp1", "isakmp(1,0x11142,0x11142)" },
  { "mm-rsa-enc-des-sha-grp1", "isakmp(1,0x12142,0x12142)" },
  { "mm-rsa-enc-des-md5-grp2", "isakmp(1,0x21142,0x21142)" },
  { "mm-rsa-enc-des-sha-grp2", "isakmp(1,0x22142,0x22142)" },
  { "mm-rsa-enc-idea-md5-grp1", "isakmp(1,0x11242,0x11242)" },
  { "mm-rsa-enc-idea-sha-grp1", "isakmp(1,0x12242,0x12242)" },
  { "mm-rsa-enc-idea-md5-grp2", "isakmp(1,0x21242,0x21242)" },
  { "mm-rsa-enc-idea-sha-grp2", "isakmp(1,0x22242,0x22242)" },
  { "mm-rsa-enc-blowfish-md5-grp1", "isakmp(1,0x11342,0x11342)" },
  { "mm-rsa-enc-blowfish-sha-grp1", "isakmp(1,0x12342,0x12342)" },
  { "mm-rsa-enc-blowfish-md5-grp2", "isakmp(1,0x21342,0x21342)" },
  { "mm-rsa-enc-blowfish-sha-grp2", "isakmp(1,0x22342,0x22342)" },
  { "mm-rsa-enc-rc5-md5-grp1", "isakmp(1,0x11442,0x11442)" },
  { "mm-rsa-enc-rc5-sha-grp1", "isakmp(1,0x12442,0x12442)" },
  { "mm-rsa-enc-rc5-md5-grp2", "isakmp(1,0x21442,0x21442)" },
  { "mm-rsa-enc-rc5-sha-grp2", "isakmp(1,0x22442,0x22442)" },
  { "mm-rsa-enc-3des-md5-grp1", "isakmp(1,0x11542,0x11542)" },
  { "mm-rsa-enc-3des-sha-grp1", "isakmp(1,0x12542,0x12542)" },
  { "mm-rsa-enc-3des-md5-grp2", "isakmp(1,0x21542,0x21542)" },
  { "mm-rsa-enc-3des-sha-grp2", "isakmp(1,0x22542,0x22542)" },
  { "mm-rsa-enc-cast-md5-grp1", "isakmp(1,0x11642,0x11642)" },
  { "mm-rsa-enc-cast-sha-grp1", "isakmp(1,0x12642,0x12642)" },
  { "mm-rsa-enc-cast-md5-grp2", "isakmp(1,0x21642,0x21642)" },
  { "mm-rsa-enc-cast-sha-grp2", "isakmp(1,0x22642,0x22642)" },
#endif /* DO_CERT_TESTS */

  { "ag-psk-des-md5-grp1", "isakmp(1,0x11114,0x11114)" },
  { "ag-psk-des-sha-grp1", "isakmp(1,0x12114,0x12114)" },
  { "ag-psk-des-md5-grp2", "isakmp(1,0x21114,0x21114)" },
  { "ag-psk-des-sha-grp2", "isakmp(1,0x22114,0x22114)" },
  { "ag-psk-idea-md5-grp1", "isakmp(1,0x11214,0x11214)" },
  { "ag-psk-idea-sha-grp1", "isakmp(1,0x12214,0x12214)" },
  { "ag-psk-idea-md5-grp2", "isakmp(1,0x21214,0x21214)" },
  { "ag-psk-idea-sha-grp2", "isakmp(1,0x22214,0x22214)" },
  { "ag-psk-blowfish-md5-grp1", "isakmp(1,0x11314,0x11314)" },
  { "ag-psk-blowfish-sha-grp1", "isakmp(1,0x12314,0x12314)" },
  { "ag-psk-blowfish-md5-grp2", "isakmp(1,0x21314,0x21314)" },
  { "ag-psk-blowfish-sha-grp2", "isakmp(1,0x22314,0x22314)" },
  { "ag-psk-rc5-md5-grp1", "isakmp(1,0x11414,0x11414)" },
  { "ag-psk-rc5-sha-grp1", "isakmp(1,0x12414,0x12414)" },
  { "ag-psk-rc5-md5-grp2", "isakmp(1,0x21414,0x21414)" },
  { "ag-psk-rc5-sha-grp2", "isakmp(1,0x22414,0x22414)" },
  { "ag-psk-3des-md5-grp1", "isakmp(1,0x11514,0x11514)" },
  { "ag-psk-3des-sha-grp1", "isakmp(1,0x12514,0x12514)" },
  { "ag-psk-3des-md5-grp2", "isakmp(1,0x21514,0x21514)" },
  { "ag-psk-3des-sha-grp2", "isakmp(1,0x22514,0x22514)" },
  { "ag-psk-cast-md5-grp1", "isakmp(1,0x11614,0x11614)" },
  { "ag-psk-cast-sha-grp1", "isakmp(1,0x12614,0x12614)" },
  { "ag-psk-cast-md5-grp2", "isakmp(1,0x21614,0x21614)" },
  { "ag-psk-cast-sha-grp2", "isakmp(1,0x22614,0x22614)" },

#ifdef DO_CERT_TESTS
  { "ag-dss-sig-des-md5-grp1", "isakmp(1,0x11124,0x11124)" },
  { "ag-dss-sig-des-sha-grp1", "isakmp(1,0x12124,0x12124)" },
  { "ag-dss-sig-des-md5-grp2", "isakmp(1,0x21124,0x21124)" },
  { "ag-dss-sig-des-sha-grp2", "isakmp(1,0x22124,0x22124)" },
  { "ag-dss-sig-idea-md5-grp1", "isakmp(1,0x11224,0x11224)" },
  { "ag-dss-sig-idea-sha-grp1", "isakmp(1,0x12224,0x12224)" },
  { "ag-dss-sig-idea-md5-grp2", "isakmp(1,0x21224,0x21224)" },
  { "ag-dss-sig-idea-sha-grp2", "isakmp(1,0x22224,0x22224)" },
  { "ag-dss-sig-blowfish-md5-grp1", "isakmp(1,0x11324,0x11324)" },
  { "ag-dss-sig-blowfish-sha-grp1", "isakmp(1,0x12324,0x12324)" },
  { "ag-dss-sig-blowfish-md5-grp2", "isakmp(1,0x21324,0x21324)" },
  { "ag-dss-sig-blowfish-sha-grp2", "isakmp(1,0x22324,0x22324)" },
  { "ag-dss-sig-rc5-md5-grp1", "isakmp(1,0x11424,0x11424)" },
  { "ag-dss-sig-rc5-sha-grp1", "isakmp(1,0x12424,0x12424)" },
  { "ag-dss-sig-rc5-md5-grp2", "isakmp(1,0x21424,0x21424)" },
  { "ag-dss-sig-rc5-sha-grp2", "isakmp(1,0x22424,0x22424)" },
  { "ag-dss-sig-3des-md5-grp1", "isakmp(1,0x11524,0x11524)" },
  { "ag-dss-sig-3des-sha-grp1", "isakmp(1,0x12524,0x12524)" },
  { "ag-dss-sig-3des-md5-grp2", "isakmp(1,0x21524,0x21524)" },
  { "ag-dss-sig-3des-sha-grp2", "isakmp(1,0x22524,0x22524)" },
  { "ag-dss-sig-cast-md5-grp1", "isakmp(1,0x11624,0x11624)" },
  { "ag-dss-sig-cast-sha-grp1", "isakmp(1,0x12624,0x12624)" },
  { "ag-dss-sig-cast-md5-grp2", "isakmp(1,0x21624,0x21624)" },
  { "ag-dss-sig-cast-sha-grp2", "isakmp(1,0x22624,0x22624)" },

  { "ag-rsa-sig-des-md5-grp1", "isakmp(1,0x11134,0x11134)" },
  { "ag-rsa-sig-des-sha-grp1", "isakmp(1,0x12134,0x12134)" },
  { "ag-rsa-sig-des-md5-grp2", "isakmp(1,0x21134,0x21134)" },
  { "ag-rsa-sig-des-sha-grp2", "isakmp(1,0x22134,0x22134)" },
  { "ag-rsa-sig-idea-md5-grp1", "isakmp(1,0x11234,0x11234)" },
  { "ag-rsa-sig-idea-sha-grp1", "isakmp(1,0x12234,0x12234)" },
  { "ag-rsa-sig-idea-md5-grp2", "isakmp(1,0x21234,0x21234)" },
  { "ag-rsa-sig-idea-sha-grp2", "isakmp(1,0x22234,0x22234)" },
  { "ag-rsa-sig-blowfish-md5-grp1", "isakmp(1,0x11334,0x11334)" },
  { "ag-rsa-sig-blowfish-sha-grp1", "isakmp(1,0x12334,0x12334)" },
  { "ag-rsa-sig-blowfish-md5-grp2", "isakmp(1,0x21334,0x21334)" },
  { "ag-rsa-sig-blowfish-sha-grp2", "isakmp(1,0x22334,0x22334)" },
  { "ag-rsa-sig-rc5-md5-grp1", "isakmp(1,0x11434,0x11434)" },
  { "ag-rsa-sig-rc5-sha-grp1", "isakmp(1,0x12434,0x12434)" },
  { "ag-rsa-sig-rc5-md5-grp2", "isakmp(1,0x21434,0x21434)" },
  { "ag-rsa-sig-rc5-sha-grp2", "isakmp(1,0x22434,0x22434)" },
  { "ag-rsa-sig-3des-md5-grp1", "isakmp(1,0x11534,0x11534)" },
  { "ag-rsa-sig-3des-sha-grp1", "isakmp(1,0x12534,0x12534)" },
  { "ag-rsa-sig-3des-md5-grp2", "isakmp(1,0x21534,0x21534)" },
  { "ag-rsa-sig-3des-sha-grp2", "isakmp(1,0x22534,0x22534)" },
  { "ag-rsa-sig-cast-md5-grp1", "isakmp(1,0x11634,0x11634)" },
  { "ag-rsa-sig-cast-sha-grp1", "isakmp(1,0x12634,0x12634)" },
  { "ag-rsa-sig-cast-md5-grp2", "isakmp(1,0x21634,0x21634)" },
  { "ag-rsa-sig-cast-sha-grp2", "isakmp(1,0x22634,0x22634)" },

  { "ag-rsa-enc-des-md5-grp1", "isakmp(1,0x11144,0x11144)" },
  { "ag-rsa-enc-des-sha-grp1", "isakmp(1,0x12144,0x12144)" },
  { "ag-rsa-enc-des-md5-grp2", "isakmp(1,0x21144,0x21144)" },
  { "ag-rsa-enc-des-sha-grp2", "isakmp(1,0x22144,0x22144)" },
  { "ag-rsa-enc-idea-md5-grp1", "isakmp(1,0x11244,0x11244)" },
  { "ag-rsa-enc-idea-sha-grp1", "isakmp(1,0x12244,0x12244)" },
  { "ag-rsa-enc-idea-md5-grp2", "isakmp(1,0x21244,0x21244)" },
  { "ag-rsa-enc-idea-sha-grp2", "isakmp(1,0x22244,0x22244)" },
  { "ag-rsa-enc-blowfish-md5-grp1", "isakmp(1,0x11344,0x11344)" },
  { "ag-rsa-enc-blowfish-sha-grp1", "isakmp(1,0x12344,0x12344)" },
  { "ag-rsa-enc-blowfish-md5-grp2", "isakmp(1,0x21344,0x21344)" },
  { "ag-rsa-enc-blowfish-sha-grp2", "isakmp(1,0x22344,0x22344)" },
  { "ag-rsa-enc-rc5-md5-grp1", "isakmp(1,0x11444,0x11444)" },
  { "ag-rsa-enc-rc5-sha-grp1", "isakmp(1,0x12444,0x12444)" },
  { "ag-rsa-enc-rc5-md5-grp2", "isakmp(1,0x21444,0x21444)" },
  { "ag-rsa-enc-rc5-sha-grp2", "isakmp(1,0x22444,0x22444)" },
  { "ag-rsa-enc-3des-md5-grp1", "isakmp(1,0x11544,0x11544)" },
  { "ag-rsa-enc-3des-sha-grp1", "isakmp(1,0x12544,0x12544)" },
  { "ag-rsa-enc-3des-md5-grp2", "isakmp(1,0x21544,0x21544)" },
  { "ag-rsa-enc-3des-sha-grp2", "isakmp(1,0x22544,0x22544)" },
  { "ag-rsa-enc-cast-md5-grp1", "isakmp(1,0x11644,0x11644)" },
  { "ag-rsa-enc-cast-sha-grp1", "isakmp(1,0x12644,0x12644)" },
  { "ag-rsa-enc-cast-md5-grp2", "isakmp(1,0x21644,0x21644)" },
  { "ag-rsa-enc-cast-sha-grp2", "isakmp(1,0x22644,0x22644)" },
#endif /* DO_CERT_TESTS */

  { "qm-esp-des-md5-no-pfs", "ipsec(1,0x10223,0x10223)" },
  { "qm-esp-des-md5-grp1", "ipsec(1,0x11223,0x11223)" },
  { "qm-esp-des-md5-grp2", "ipsec(1,0x12223,0x12223)" },
  { "qm-esp-des-md5-grpb", "ipsec(1,0x1b223,0x1b223)" },
  { "qm-esp-des-md5-grpc", "ipsec(1,0x1c223,0x1c223)" },
  { "qm-esp-des-md5-grpd", "ipsec(1,0x1d223,0x1d223)" },

  { "qm-esp-des-sha-no-pfs", "ipsec(1,0x10323,0x10323)" },
  { "qm-esp-des-sha-grp1", "ipsec(1,0x11323,0x11323)" },
  { "qm-esp-des-sha-grp2", "ipsec(1,0x12323,0x12323)" },
  { "qm-esp-des-sha-grpb", "ipsec(1,0x1b323,0x1b323)" },
  { "qm-esp-des-sha-grpc", "ipsec(1,0x1c323,0x1c323)" },
  { "qm-esp-des-sha-grpd", "ipsec(1,0x1d323,0x1d323)" },

  { "qm-ah-des-md5-no-pfs", "ipsec(1,0x10222,0x10222)" },
  { "qm-ah-des-md5-grp1", "ipsec(1,0x11222,0x11222)" },
  { "qm-ah-des-md5-grp2", "ipsec(1,0x12222,0x12222)" },
  { "qm-ah-des-md5-grpb", "ipsec(1,0x1b222,0x1b222)" },
  { "qm-ah-des-md5-grpc", "ipsec(1,0x1c222,0x1c222)" },
  { "qm-ah-des-md5-grpd", "ipsec(1,0x1d222,0x1d222)" },

  { "qm-ah-des-sha-no-pfs", "ipsec(1,0x10322,0x10322)" },
  { "qm-ah-des-sha-grp1", "ipsec(1,0x11322,0x11322)" },
  { "qm-ah-des-sha-grp2", "ipsec(1,0x12322,0x12322)" },
  { "qm-ah-des-sha-grpb", "ipsec(1,0x1b322,0x1b322)" },
  { "qm-ah-des-sha-grpc", "ipsec(1,0x1c322,0x1c322)" },
  { "qm-ah-des-sha-grpd", "ipsec(1,0x1d322,0x1d322)" },

  { "qm-esp-ah-des-md5-no-pfs", "ipsec(1,0x10221,0x10221)" },
  { "qm-esp-ah-des-md5-grp1", "ipsec(1,0x11221,0x11221)" },
  { "qm-esp-ah-des-md5-grp2", "ipsec(1,0x12221,0x12221)" },
  { "qm-esp-ah-des-md5-grpb", "ipsec(1,0x1b221,0x1b221)" },
  { "qm-esp-ah-des-md5-grpc", "ipsec(1,0x1c221,0x1c221)" },
  { "qm-esp-ah-des-md5-grpd", "ipsec(1,0x1d221,0x1d221)" },

  { "qm-esp-ah-des-sha-no-pfs", "ipsec(1,0x10321,0x10321)" },
  { "qm-esp-ah-des-sha-grp1", "ipsec(1,0x11321,0x11321)" },
  { "qm-esp-ah-des-sha-grp2", "ipsec(1,0x12321,0x12321)" },
  { "qm-esp-ah-des-sha-grpb", "ipsec(1,0x1b321,0x1b321)" },
  { "qm-esp-ah-des-sha-grpc", "ipsec(1,0x1c321,0x1c321)" },
  { "qm-esp-ah-des-sha-grpd", "ipsec(1,0x1d321,0x1d321)" },

  { NULL, NULL }
};

void ike_fatal(const char *buffer, void *ctx)
{
  fflush(stderr);
  fflush(stdout);
  fprintf(stderr, "IKE FATAL: %s\n", buffer);
  fflush(stderr);
  exit(1);
}

int expand_word(const SshMacro *table, SshBuffer buffer,
                char *word, size_t len)
{
  int i;

  for (i = 0; table[i].macro_name != NULL; i++)
    {
      if (strlen(table[i].macro_name) == len &&
          strncmp(table[i].macro_name, word, len) == 0)
        {
          ssh_xbuffer_append(buffer, (unsigned char *) table[i].replacement,
                             strlen(table[i].replacement));
          return 1;
        }
    }
  if (table[i].macro_name == NULL)
    {
      ssh_xbuffer_append(buffer, (unsigned char *) word, len);
    }
  return 0;
}

int expand_macros(const SshMacro *table, char **test_string)
{
  SshBufferStruct buffer;
  int replacements, len;
  char *p, *q;

  ssh_buffer_init(&buffer);
  replacements = 0;

  q = *test_string;
  p = strchr(q, ',');

  while (p != NULL)
    {
      for (; *q && isspace((unsigned char) *q); q++)
        ;
      len = p - q;
      for (; len > 0 && isspace((unsigned char) q[len]); len--)
        ;

      replacements += expand_word(table, &buffer, q, len);
      ssh_xbuffer_append(&buffer, (unsigned char *) ",", 1);

      q = p + 1;
      p = strchr(q, ',');
    }

  /* Last word */
  for (; *q && isspace((unsigned char) *q); q++)
    ;
  len = strlen(q);
  for (; len > 0 && isspace((unsigned char) q[len]); len--)
    ;

  replacements += expand_word(table, &buffer, q, len);

  ssh_xbuffer_append(&buffer, (unsigned char *) "\0", 1);
  ssh_xfree(*test_string);
  *test_string = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
  SSH_DEBUG(9, ("Expanded line = %s", *test_string));
  return replacements;
}

int main(int argc, char **argv)
{
  int c, errflg = 0;
  const char *default_ip = NULL;
  const char *default_port = NULL;
  const char *remote_ip = "127.0.0.1";
  const char *remote_port = NULL;
  const char *default_s_port = "1500";
  const char *default_c_port = "1501";
  const char *debug_string = "SshIke*=4";
  char *test_string = "short";
  const char *local_host_name = NULL;
  const char *remote_host_name = NULL;
  const char *cert_config = "master.certconf";
  const char *auth_data = NULL;
  const char *vendor_id_txt = "Ssh t-isakmp $Revision: #1 $";
  const char *options_mpint = NULL;





  int i;
  int auth = 1;
  int flags = 0x0;
  struct SshIkeParamsRec params;
  SshIkeContext context;
  Boolean server = FALSE, client = FALSE;
  SshIkeServerContext server_context;
  struct SshIkePMContextRec pm;
  struct TestScriptContextRec test_context;
  struct UpperPolicyManagerContextRec upper_ctx;
  pid_t pid;
  char *ldap_server = "ldap://ryijy.sfnt.local:389/";
  SshUInt32 life_type_parameter = 3600;
  SshUInt32 async_loop_timeout = 0;
  Boolean extended_timeouts = FALSE;
  SshAuditContext audit_context = NULL;
  char *ek_accelerator_type = NULL;
  char *ek_accelerator_init_info = NULL;
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  SshIkePolicyFunctionsStruct policy_funcs = {
    ssh_policy_new_connection,
    ssh_policy_new_connection_phase_ii,
    ssh_policy_new_connection_phase_qm,
    ssh_policy_find_pre_shared_key,
#ifdef SSHDIST_IKE_CERT_AUTH
    ssh_policy_find_public_key,
    ssh_policy_find_private_key,
    ssh_policy_new_certificate,
    ssh_policy_request_certificates,
    ssh_policy_get_certificate_authorities,
#endif /* SSHDIST_IKE_CERT_AUTH */
    ssh_policy_isakmp_nonce_data_len,
    ssh_policy_isakmp_id,
    ssh_policy_isakmp_vendor_id,
    ssh_policy_isakmp_request_vendor_ids,
    ssh_policy_isakmp_select_sa,
    ssh_policy_ngm_select_sa,
    ssh_policy_qm_select_sa,
    ssh_policy_qm_nonce_data_len,
    ssh_policy_qm_local_id,
    ssh_policy_qm_remote_id,
#ifdef SSHDIST_ISAKMP_CFG_MODE
    ssh_policy_cfg_fill_attrs,
    ssh_policy_cfg_notify_attrs,
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    ssh_policy_delete,
    ssh_policy_notification,
    ssh_policy_phase_i_notification,
    ssh_policy_phase_qm_notification,
    ssh_policy_isakmp_sa_freed,
    ssh_policy_qm_sa_freed,
    ssh_policy_phase_ii_sa_freed,
    ssh_policy_negotiation_done_isakmp,
    ssh_policy_negotiation_done_qm,
    ssh_policy_negotiation_done_phase_ii,
#ifdef SSHDIST_IKE_CERT_AUTH
    NULL_FNPTR,                  /* certificate_request */
#endif /* SSHDIST_IKE_CERT_AUTH */
    ssh_policy_phase_i_server_changed,
    ssh_policy_phase_qm_server_changed,
    ssh_policy_phase_ii_server_changed
  };
#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */

#ifdef WIN32
  char param[512];
  char path[512];
  SHELLEXECUTEINFO t_ike = {0};
  HANDLE exit_notify_thread;
  DWORD dwid;
#endif /* WIN32 */

  ssh_debug_register_callbacks(ike_fatal, NULL_FNPTR, NULL_FNPTR, NULL);

  call_fatal_on_error = TRUE;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

#ifdef DEBUG_LIGHT
  ssh_ike_logging_level = 4;
#endif /* DEBUG_LIGHT */

  while ((c = ssh_getopt(argc, argv,
                         "i:p:I:B:P:d:t:scS:C:h:H:f:x:eEl:a:A:O:V:L:K:y:Y:T:",
                         NULL))
         != EOF)
    {
      switch (c)
        {
        case 's': server = TRUE; break;
        case 'c': client = TRUE; break;
        case 'i': default_ip = ssh_optarg; break;
        case 'p': default_port = ssh_optarg; break;
        case 'I': remote_ip = ssh_optarg; break;
        case 'P': remote_port = ssh_optarg; break;
        case 'S': default_s_port = ssh_optarg; break;
        case 'C': default_c_port = ssh_optarg; break;
        case 'd': debug_string = ssh_optarg; break;
        case 't': test_string = ssh_optarg; break;
        case '?': errflg++; break;
        case 'h': local_host_name  = ssh_optarg; break;
        case 'H': remote_host_name = ssh_optarg; break;



        case 'f': flags = strtol(ssh_optarg, NULL, 0); break;
        case 'x': cert_config = ssh_optarg; break;
        case 'e': call_fatal_on_error = FALSE; break;
        case 'E': extended_timeouts = TRUE; break;
#ifdef DEBUG_LIGHT
        case 'l': ssh_ike_logging_level = strtol(ssh_optarg, NULL, 0); break;
#endif /* DEBUG_LIGHT */
        case 'a': auth = strtol(ssh_optarg, NULL, 0); break;
        case 'A': auth_data = ssh_optarg; break;
        case 'O': options_mpint = ssh_optarg; break;
        case 'V': vendor_id_txt = ssh_optarg; break;
        case 'K': life_type_parameter = atoi(ssh_optarg); break;
        case 'L': ldap_server = ssh_optarg; break;
        case 'y': ek_accelerator_type = ssh_optarg; break;
        case 'Y': ek_accelerator_init_info = ssh_optarg; break;
        case 'T': async_loop_timeout = atoi(ssh_optarg); break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
              "Usage: %s "
              "[-sce] [-i/I ip] [-p/P/S/C port] [-l ike_logging level] "
              "[-d debug_flags] [-t test_opts] [-h local_host] "
              "[-H remote_host] [-f flags] [-x x509_certificate_cache_file] "
              "[-a auth_type] [-A auth_data] [-O mp_int options] "
              "[-L ldap_server:port,ldap_server:port,...] "
              "[-K isakmp_life_value_in_seconds] "



              "[-T timeout in microseconds]\n", program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);


#ifdef SSHDIST_IKE_CERT_AUTH
  if (!ssh_x509_library_initialize(NULL))
    ssh_fatal("Cannot initialize certificate and crypto library");
#else /* SSHDIST_IKE_CERT_AUTH */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp_generator);
#endif /* SSHDIST_CRYPT_ECP */




  pid = 0;
  /* Both FALSE or both TRUE */
  if (server == client)
    {
      if (default_port)
        ssh_fatal("-p option cannot be used to set port when in "
                  "server/client mode, use -S and -C");
      SSH_DEBUG(3, ("Both server and client"));

#ifdef WIN32
      /* get full path for this application */
      if (GetModuleFileName(NULL, path, 512) == 0)
        ssh_fatal("Could not get module path to the application.");

      /* make client command line string */
      ssh_snprintf(param, sizeof(param), " -c");

      /* parse process parameters */
      t_ike.cbSize = sizeof(t_ike);
      t_ike.fMask = SEE_MASK_NOCLOSEPROCESS;
      t_ike.lpFile = path;
      t_ike.lpParameters = param;
      t_ike.lpDirectory = "";
      t_ike.nShow = SW_NORMAL;

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
      default_port = default_s_port;
      if (remote_port == NULL)
        remote_port = default_c_port;
      test_string = "sleep(3600000)";

#else /* WIN32 */

      pid = fork();
      if (pid < 0)
        ssh_fatal("Fork failed: %.200s", strerror(errno));
      if (pid != 0)
        {
          /* Parent, make this client */
          SSH_DEBUG(3, ("Client start"));
          default_port = default_c_port;
          if (remote_port == NULL)
            remote_port = default_s_port;
        }
      else
        {
          /* Child, make this server */
          SSH_DEBUG(3, ("Server start, client pid = %d", pid));
          default_port = default_s_port;
          if (remote_port == NULL)
            remote_port = default_c_port;
          test_string = "sleep(3600000)";
        }
#endif /* !WIN32 */
    }
  else if (server)
    {
      /* Make this server */
      SSH_DEBUG(3, ("Server start"));
      if (default_port == NULL)
        default_port = default_s_port;
      if (remote_port == NULL)
        remote_port = default_c_port;
    }
  else if (client)
    {
      /* Make this client */
      SSH_DEBUG(3, ("Client start"));
      if (default_port == NULL)
        default_port = default_c_port;
      if (remote_port == NULL)
        remote_port = default_s_port;
    }
  else
    ssh_fatal("Not a server or client");

  ssh_event_loop_initialize();

  ssh_event_loop_lock();

  memset(&upper_ctx, 0, sizeof(upper_ctx));
  upper_ctx.auth = auth;
  upper_ctx.test_context = &test_context;
  for (i = 0; i < MAX_MPINT_OPTIONS; i++)
    {
      upper_ctx.options_mpint[i] = ssh_mprz_malloc();
      if (upper_ctx.options_mpint[i] == NULL)
	exit(1);

      ssh_mprz_set_str(upper_ctx.options_mpint[i], "0", 10);
    }
  if (options_mpint != NULL)
    {
      const char *p, *q;

      i = 0;
      p = options_mpint;
      while (p != NULL && i < MAX_MPINT_OPTIONS)
        {
          q = strchr(p, ',');
          if (q == NULL)
            {
              if (ssh_mprz_set_str(upper_ctx.options_mpint[i], p, 0) < 0)
                ssh_fatal("Invalid mp_int: %s", p);
              if (ssh_mprz_byte_size(upper_ctx.options_mpint[i]) > 512)
                ssh_fatal("Invalid mp_int: %s", p);
              i++;
            }
          else
            {
              char *t;

              t = ssh_xmalloc(1 + q - p);
              memcpy(t, p, q - p);
              t[q - p] = '\0';

              if (ssh_mprz_set_str(upper_ctx.options_mpint[i], t, 0) < 0)
                ssh_fatal("Invalid mp_int: %s", t);
              if (ssh_mprz_byte_size(upper_ctx.options_mpint[i]) > 512)
                ssh_fatal("Invalid mp_int: %s", p);
              i++;
              ssh_xfree(t);
              q++;
            }
          p = q;
        }
    }

  memset(&params, 0, sizeof(params));
  params.ignore_cr_payloads = ((flags & 0x0040) != 0);
  params.no_key_hash_payload = ((flags & 0x0080) != 0);
  params.no_cr_payloads = ((flags & 0x0100) != 0);
  params.do_not_send_crls = ((flags & 0x1000) != 0);
  params.send_full_chains = ((flags & 0x2000) != 0);
  params.trust_icmp_messages = ((flags & 0x4000) == 0);

  if (default_ip == NULL)
    params.default_ip = "0.0.0.0";
  else
    params.default_ip = default_ip;
  params.default_port = default_port;
  if (extended_timeouts)
    {
      params.base_retry_limit = 30;
      params.base_retry_timer = 5;
      params.base_retry_timer_usec = 0;
      params.base_retry_timer_max = 60;
      params.base_retry_timer_max_usec = 0;
      params.base_expire_timer = 1800;
      params.base_expire_timer_usec = 0;
      params.extended_retry_limit = 30;
      params.extended_retry_timer = 5;
      params.extended_retry_timer_usec = 0;
      params.extended_retry_timer_max = 60;
      params.extended_retry_timer_max_usec = 0;
      params.extended_expire_timer = 1800;
      params.extended_expire_timer_usec = 0;
    }
  else
    {
      params.base_retry_limit = 30;
      params.base_retry_timer = 2;
      params.base_retry_timer_usec = 0;
      params.base_retry_timer_max = 15;
      params.base_retry_timer_max_usec = 0;
      params.base_expire_timer = 60;
      params.base_expire_timer_usec = 0;
      params.extended_retry_limit = 0;
      params.extended_retry_timer = 0;
      params.extended_retry_timer_usec = 0;
      params.extended_retry_timer_max = 0;
      params.extended_retry_timer_max_usec = 0;
      params.extended_expire_timer = 0;
      params.extended_expire_timer_usec = 0;
    }
  params.secret_recreate_timer = 0;
  params.spi_size = 0;
  params.zero_spi = ((flags & 0x0008) != 0);
  params.max_key_length = 0;
  params.max_isakmp_sa_count = 2000;
  params.randomizers_default_cnt = 2;
  params.randomizers_default_max_cnt = 100;
  params.randomizers_default_retry = 0;
  params.randomizers_private_cnt = 1;
  params.randomizers_private_max_cnt = 30;
  params.randomizers_private_retry = 0;

  /* Init externalkey if an accelerator has been specified. */
#ifdef SSHDIST_EXTERNALKEY
  if (ek_accelerator_type)
    {
      SshExternalKey externalkey;
      SshEkStatus status;
      char *short_name;

      externalkey = ssh_ek_allocate();
      if (externalkey == NULL)
        goto error;

      /* Add accelerator provider. */
      status = ssh_ek_add_provider(externalkey,
                                   ek_accelerator_type,
                                   ek_accelerator_init_info,
                                   NULL,
                                   SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                   &short_name);
      if (status != SSH_EK_OK)
        goto error;

      params.external_key = externalkey;
      params.accelerator_short_name = short_name;
    }
#endif /* SSHDIST_EXTERNALKEY */

  if (!read_config_file(cert_config, &pm,
                        (flags & 0x0020) != 0, params.default_ip,
                        (flags & 0x0800) != 0, ldap_server))
    goto error;

  /* Pre shared key */
  if (auth == 1 && auth_data != NULL)
    {
      char *pre_shared_key;
      size_t pre_shared_key_len;
      SshIkePMPreSharedKeyCache pre_shared_key_cache =
        pm.pre_shared_key_cache;

      pre_shared_key = ssh_xmalloc(strlen(auth_data) / 2 + 2);
      pre_shared_key_len = strlen(auth_data) / 2;

      for (i = 0; i < pre_shared_key_len; i++)
        {
          if (isxdigit((unsigned char) auth_data[i * 2]) &&
              isxdigit((unsigned char) auth_data[i * 2 + 1]))
            {
              if (isdigit((unsigned char) auth_data[i * 2]))
                pre_shared_key[i] = (auth_data[i * 2] - '0') << 4;
              else
                pre_shared_key[i] =
		  (tolower((unsigned char) auth_data[i * 2]) - 'a' + 10)
		    << 4;
              if (isdigit((unsigned char) auth_data[i * 2 + 1]))
                pre_shared_key[i] |= (auth_data[i * 2 + 1] - '0');
              else
                pre_shared_key[i] |=
		  (tolower((unsigned char) auth_data[i * 2 + 1]) -
		   'a' + 10);
            }
          else
            ssh_fatal("Invalid hex digit in pre shared key %s", auth_data);
        }
      if (!ike_add_string(pre_shared_key_cache->mapping,
                          "ip", remote_ip, pre_shared_key,
                          pre_shared_key_len))
        ssh_fatal("Adding of ip = %s to pre_shared_key failed",
                  remote_ip);
      if (!ike_add_string(pre_shared_key_cache->mapping,
                          "ip", "0.0.0.0", pre_shared_key,
                          pre_shared_key_len))
        ssh_fatal("Adding of ip = 0.0.0.0 to pre_shared_key failed");
    }
  /* Nonce lengths */
  pm.upper_context = &upper_ctx;
  upper_ctx.nonce_len = 16;
  upper_ctx.qm_nonce_len = 16;
  upper_ctx.local_name = local_host_name;
  upper_ctx.remote_name = remote_host_name;
  if (strlen(vendor_id_txt))
    {
      SshCryptoStatus cret;
      SshHash hash;

      cret = ssh_hash_allocate("md5", &hash);
      if (cret != SSH_CRYPTO_OK)
        ssh_fatal("ssh_hash_allocate md5 failed");

      upper_ctx.vendor_id_len = ssh_hash_digest_length(ssh_hash_name(hash));
      upper_ctx.vendor_id = ssh_xmalloc(upper_ctx.vendor_id_len);

      ssh_hash_reset(hash);
      ssh_hash_update(hash, vendor_id_txt, strlen(vendor_id_txt));
      ssh_hash_final(hash, upper_ctx.vendor_id);
      ssh_hash_free(hash);
    }
  else
    {
      upper_ctx.vendor_id_len = 0;
      upper_ctx.vendor_id = NULL;
    }

  audit_context = ssh_audit_create(NULL_FNPTR, NULL_FNPTR, NULL);
  context = ssh_ike_init(&params, audit_context);
  if (context == 0)
    goto error;
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  ssh_ike_register_policy_functions(context, &policy_funcs);
#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */

  server_context = ssh_ike_start_server(context, default_ip, default_port,
                                        &pm, sa_callback, &test_context);

  if (server_context == 0)
    {
      SSH_IKE_DEBUG(3, NULL, ("Starting isakmp server failed, "
                              "address propably already in use, "
                              "try some other port instead or wait "
                              "some time"));
      ssh_ike_uninit(context);
      goto error;
    }






















  test_context.isakmp_context = context;
  test_context.server_context = server_context;
  test_context.deletes = NULL;
  test_context.pm = &pm;
  test_context.flags = flags;
  ssh_register_signal(SIGHUP, received_signal, &test_context);
  ssh_register_signal(SIGINT, received_signal, &test_context);
  ssh_register_signal(SIGQUIT, received_signal, &test_context);
  ssh_register_signal(SIGTERM, received_signal, &test_context);

  ssh_register_signal(SIGUSR1, dump_statistics, &test_context);
  ssh_register_signal(SIGUSR2, restart_ike, &test_context);
  test_string = ssh_xstrdup(test_string);
  while (expand_macros(test_macros, &test_string))
    ;
  test_context.test_string = test_string;
  test_context.current_test = test_string;
  test_context.test = 0;
  test_context.next_test_count = 0xffffffff;
  test_context.sleep_msec = 10;
  test_context.remote_ip = remote_ip;
  test_context.remote_port = remote_port;
  test_context.local_host_name = local_host_name;
  test_context.remote_host_name = remote_host_name;
  test_context.life_time_parameter = life_type_parameter;
  test_context.upper_context = &upper_ctx;
  test_context.async_loop_timeout = async_loop_timeout;
  ssh_time_measure_init(&test_context.timer);
  ssh_time_measure_start(&test_context.timer);

  if (default_ip)
    test_context.server_name = default_ip;
  else
    test_context.server_name = "0.0.0.0";

  ssh_xregister_timeout(0, 0, test_callback, &test_context);

  ssh_event_loop_unlock();
  ssh_event_loop_run();

  /* Exiting... */
  ssh_event_loop_lock();
  if (server == client)
    {
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
          TerminateProcess(t_ike.hProcess,0);
        }
#else /* WIN32 */
      if (pid != 0)
        {
          /* Parent, kill child server. */
          kill(pid, 1);
          sleep(2);
          kill(pid, 1);
        }
#endif /* WIN32 */
    }

  cleanup_deletes(&test_context);

  if (test_context.server_context != NULL)
    ssh_ike_stop_server(test_context.server_context);
  if (test_context.isakmp_context != NULL)
    ssh_ike_uninit(test_context.isakmp_context);
#ifdef DO_CERT_TESTS
  if (((SshIkePMCertCache) (pm.certificate_cache))->cert_cache != NULL)
    ssh_cm_free(((SshIkePMCertCache) (pm.certificate_cache))->cert_cache);
  for (i = 0;
      i < ((SshIkePMCertCache) (pm.certificate_cache))->number_of_master_cas;
      i++)
    ssh_xfree(((SshIkePMCertCache) (pm.certificate_cache))
              ->master_cas[i]);

  ssh_xfree(((SshIkePMCertCache) (pm.certificate_cache))
            ->master_cas);
  ssh_xfree(((SshIkePMCertCache) (pm.certificate_cache))
            ->master_ca_lens);

  ike_destroy_items(((SshIkePMPrivateKeyCache) (pm.private_key_cache))
                    ->rsa_mapping);
  ike_destroy_items(((SshIkePMPrivateKeyCache) (pm.private_key_cache))
                    ->dss_mapping);

  ssh_xfree(pm.private_key_cache);
  ssh_xfree(pm.certificate_cache);
#endif /* DO_CERT_TESTS */

  ike_destroy_strings(((SshIkePMPreSharedKeyCache) (pm.pre_shared_key_cache))
                      ->mapping);

  ssh_xfree(pm.pre_shared_key_cache);
  ssh_xfree(test_string);

  for (i = 0; i < MAX_MPINT_OPTIONS; i++)
    ssh_mprz_free(upper_ctx.options_mpint[i]);
  
  if (phase_i != 0)
    ssh_warning("Phase I done callbacks missing %d", phase_i);
  if (phase_qm != 0)
    ssh_warning("Phase QM done callbacks missing %d", phase_qm);
  if (phase_ii != 0)
    ssh_warning("Phase II done callbacks missing %d", phase_ii);
 error:
  ssh_xfree(upper_ctx.vendor_id);
  if (audit_context)
    ssh_audit_destroy(audit_context);
  ssh_event_loop_unlock();
  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

#ifdef SSHDIST_IKE_CERT_AUTH
  ssh_x509_library_uninitialize();
#else /* SSHDIST_IKE_CERT_AUTH */
  ssh_crypto_library_uninitialize();
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_debug_uninit();
  ssh_global_uninit();









  return 0;
}
