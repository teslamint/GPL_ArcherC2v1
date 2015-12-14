/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/test_policy.h,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 18:56 Dec  7 1997 kivinen
 *        Last Modification : 11:54 Feb  3 2005 kivinen
 *        State             : $State: Exp $
 *        Version           : 1.85
 *        
 *
 *        Description       : Isakmp policy manager defines
 *
 *        $Log: test_policy.h,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:51  treychen_hc
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
 *        $EndLog$
 */


#ifndef TEST_POLICY_H
#define TEST_POLICY_H

#include "isakmp.h"
#include "sshadt_strmap.h"
#include "sshtimemeasure.h"
#include "sshglobals.h"

extern int phase_i;
extern int phase_qm;
extern int phase_ii;

typedef enum {
  TEST_ISAKMP,
  TEST_IPSEC,
  TEST_NGM,
#ifdef SSHDIST_ISAKMP_CFG_MODE
  TEST_CFG,
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  TEST_SLEEP,
  TEST_CLEAR,
  TEST_LOOP_ISAKMP,
  TEST_LOOP_IPSEC,
  TEST_LOOP_ASYNC_ISAKMP,
  TEST_CLIENT_ISAKMP,
  TEST_SERVER_ISAKMP
} TestCase;

#define MAX_ARGS                20

#define CLIENT_ARG_XCHG_TYPE            0
#define CLIENT_ARG_PROPOSAL             1
#define CLIENT_ARG_ENCR_ALG             2
#define CLIENT_ARG_HASH_ALG             3
#define CLIENT_ARG_GRP                  4
#define CLIENT_ARG_KEY_LEN              5

#define CLIENT_ARG_NGM_GRP_TYPE         6
#define CLIENT_ARG_NGM_GRP_NUMBER       7

#define CLIENT_ARG_QM_PROPOSAL          8
#define CLIENT_ARG_QM_GROUP             9
#define CLIENT_ARG_QM_AH_PROTO          10
#define CLIENT_ARG_QM_AH_MODE           11
#define CLIENT_ARG_QM_AH_KEY_LEN        12
#define CLIENT_ARG_QM_ESP_PROTO         13
#define CLIENT_ARG_QM_ESP_MODE          14
#define CLIENT_ARG_QM_ESP_AUTH          15
#define CLIENT_ARG_QM_ESP_KEY_LEN       16

#define MAX_MPINT_OPTIONS       14

#define MPINT_OPTION_PHASE_1_PRIME              0
#define MPINT_OPTION_PHASE_1_GEN1               1
#define MPINT_OPTION_PHASE_1_GEN2               2
#define MPINT_OPTION_PHASE_1_CURVEA             3
#define MPINT_OPTION_PHASE_1_CURVEB             4
#define MPINT_OPTION_PHASE_1_CARDINALITY        5
#define MPINT_OPTION_PHASE_1_ORDER              6

#define MPINT_OPTION_NGM_PRIME                  7
#define MPINT_OPTION_NGM_GEN1                   8
#define MPINT_OPTION_NGM_GEN2                   9
#define MPINT_OPTION_NGM_CURVEA                 10
#define MPINT_OPTION_NGM_CURVEB                 11
#define MPINT_OPTION_NGM_CARDINALITY            12
#define MPINT_OPTION_NGM_ORDER                  13

#define MAX_PROPOSALS           9

#ifdef SSHDIST_IKE_CERT_AUTH
/* Certificate cache context. */
typedef struct SshIsakmpPMCertCacheRec {
  void *cert_cache;             /* Certificate cache context */
  int number_of_master_cas;     /* Number of master certificates */
  unsigned char **master_cas;   /* Our master ca servers */
  size_t *master_ca_lens;
  Boolean trust_all_certificates; /* Insert all certificates as ca to cache, so
                                     we trust them all, used for debugging, DO
                                     NOT set this in real use. */







} *SshIkePMCertCache;
#endif /* SSHDIST_IKE_CERT_AUTH */

typedef struct UpperPolicyManagerContextRec {
  /* t-isakmp www-testing needs these */
  int auth;
  struct TestScriptContextRec *test_context;
  SshMPInteger options_mpint[MAX_MPINT_OPTIONS];

  int nonce_len;                /* Nonce length for isakmp sa */
  int qm_nonce_len;             /* Nonce length for quick mode sa */
  const char *local_name;       /* Local ip for quick mode */
  const char *remote_name;      /* Remote ip for quick mode */
  size_t vendor_id_len;         /* Length of vendor id */
  unsigned char *vendor_id;     /* Vendor id */

} *UpperPolicyManagerContext;

typedef struct TestDeleteContextRec *TestDeleteContext;

typedef struct TestScriptContextRec {
  SshIkeContext isakmp_context;
  SshIkeServerContext server_context;
  SshIkePMContext pm;
  const char *test_string;
  const char *current_test;
  TestCase test;
  SshUInt32 current_test_count;
  SshUInt32 next_test_count;
  int sleep_msec;
  unsigned long argv[MAX_ARGS];
  int argc;
  const char *remote_ip;
  const char *remote_port;
  const char *local_host_name;
  const char *remote_host_name;
  UpperPolicyManagerContext upper_context;
  const char *server_name;
  SshUInt32 life_time_parameter;
  int flags;
  TestDeleteContext deletes;

  SshUInt32 async_loop_timeout;
  SshUInt32 test_number;
  SshUInt32 completed_ops;
  SshUInt32 started_ops;
  SshUInt32 total_ops;
  SshTimeMeasureStruct timer;
} *TestScriptContext;

struct TestDeleteContextRec {
  TestDeleteContext next;
  TestScriptContext test_context;
  SshIkeServerContext server;
  SshIkeProtocolIdentifiers protocol_id;
  size_t spi_size;
  unsigned char *spi;
  char *remote_name;
  char *remote_port;
};

#ifdef SSHDIST_IKE_CERT_AUTH
/* Private key mapping item */
typedef struct SshIkePMPrivateKeyItemRec {
  unsigned char *certificate;   /* Certificate data */
  size_t certificate_len;       /* Length of certificate data */
  SshPrivateKey key;            /* Private key */
} *SshIkePMPrivateKeyItem;

/* Private key cache context */
typedef struct SshIkePMPrivateKeyCacheRec {
  /* Private key mappings. The key is in format understood by
     ssh_ike_string_to_id. The data item is SshIkePMPrivateKeyItem
     (pointer). */
  SshADTContainer rsa_mapping;
  SshADTContainer dss_mapping;
} *SshIkePMPrivateKeyCache;
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Pre shared key mapping item */
typedef struct SshIkePMPreSharedKeyItemRec {
  unsigned char *data;   /* Pre shared key */
  size_t data_len;       /* Length of pre shared key */
} *SshIkePMPreSharedKeyItem;

/* Pre shared key cache context */
typedef struct SshIkePMPreSharedKeyCacheRec {
  /* Pre shared key mappings. The key is in format understood by
     ssh_ike_string_to_id. If mapping for remote host is not found then
     "ipv4(0.0.0.0)" is used as a key and if it is found it is used as a
     general key for all remote hosts. Insert that key to mapping only if you
     want to have default key for all remote hosts. The data item is
     SshIkePMPreSharedKeyCache. */
  SshADTContainer mapping;
} *SshIkePMPreSharedKeyCache;

#ifdef DEBUG_LIGHT
SSH_GLOBAL_DECLARE(int, ssh_ike_logging_level);
#define ssh_ike_logging_level SSH_GLOBAL_USE_INIT(ssh_ike_logging_level)
void ssh_ike_debug(int level, const char *file, int line, const char *func,
                   SshIkeNegotiation negotiation,
                   char *description);
void ssh_ike_debug_buffer(int level, const char *file, int line,
                          const char *func, SshIkeNegotiation negotiation,
                          const char *string, size_t len,
                          const unsigned char *buffer);

/* Max lenght of 32 bit integer as a string (9 digits + nul or 0x + 8 + nul =
   11) */
#define SSH_IKE_STR_INT32_LEN   11
/* Max length of ip number as a string (ipv4 = 3 * 4 + 3 + nul = 16,
   ipv6 = 4 * 8 + 7 + nul = 40 */
#define SSH_IKE_STR_IP_LEN      40
#ifdef __GNUC__
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, __FUNCTION__, \
                              (negotiation), (string), (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, __FUNCTION__, \
                              (negotiation), \
                              (ssh_debug_format varcall), \
                              (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG(level,negotiation,varcall) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug(level, __FILE__, __LINE__, __FUNCTION__, \
                       (negotiation), \
                       ssh_debug_format varcall); \
  } while(0)
#else /* __GNUC__ */
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, NULL, (negotiation), \
                              (string), (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, NULL, (negotiation), \
                              (ssh_debug_format varcall), \
                              (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG(level,negotiation,varcall) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug(level, __FILE__, __LINE__, NULL, \
                       (negotiation), \
                       ssh_debug_format varcall); \
  } while(0)
#endif /* __GNUC__ */
#else /* DEBUG_LIGHT */
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer)
#define SSH_IKE_DEBUG(level,negotiation,varcall)
#endif /* DEBUG_LIGHT */


/* Some prototypes.*/

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. If the packet contained authentication HASH or was encrypted that
   processing is done before that. */
void ssh_policy_phase_i_server_changed(SshIkePMPhaseI pm_info,
                                       SshIkeServerContext new_server,
                                       const unsigned char *new_remote_ip,
                                       const unsigned char *new_remote_port);

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done, thus it
   might be better to postpone the actual changing of the server to the
   private_payload_phase_qm_output function.

   This is not called if new quick mode exchange initially starts using
   different ip or port than the IKE SA. This is called if the initial quick
   mode exchange initially starts using different server than the IKE SA. In
   that case this is called after the new_connection callback. */
void ssh_policy_phase_qm_server_changed(SshIkePMPhaseQm pm_info,
                                        SshIkeServerContext new_server,
                                        const unsigned char *new_remote_ip,
                                        const unsigned char *new_remote_port);

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done.

   This is not called if new phase ii exchange initially starts using different
   ip or port than the IKE SA. This is called if the initial phase ii exchange
   initially starts using different server than the IKE SA. In that case this
   is called after the new_connection callback. */
void ssh_policy_phase_ii_server_changed(SshIkePMPhaseII pm_info,
                                        SshIkeServerContext new_server,
                                        const unsigned char *new_remote_ip,
                                        const unsigned char *new_remote_port);

#endif /* TEST_POLICY_H */
