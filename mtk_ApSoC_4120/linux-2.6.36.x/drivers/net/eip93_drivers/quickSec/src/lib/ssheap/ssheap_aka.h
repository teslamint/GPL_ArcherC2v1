/**
  ssheap_aka.h

  @copyright
          Copyright (c) 2002-2004 SFNT Finland Oy - 
  all Rights Reserved.

*/

#ifndef SSH_EAP_AKA_H
#define SSH_EAP_AKA_H 1

/* Common client and server functionality */
void *ssh_eap_aka_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_aka_destroy(SshEapProtocol, SshUInt8, void*);
SshEapOpStatus ssh_eap_aka_signal(SshEapProtocolSignalEnum, 
				  SshEap, SshEapProtocol, SshBuffer);
SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol, 
                SshEap eap, SshUInt8 type);

#ifdef SSHDIST_EAP_AKA
/* Client only functionality below */

/* Decoding codes for EAP AKA */
#define SSH_EAP_AKA_DEC_OK                  0

/* EAP aka error codes. */
#define SSH_EAP_AKA_ERR_GENERAL             50
#define SSH_EAP_AKA_ERR_INVALID_IE          51
#define SSH_EAP_AKA_ERR_PACKET_CORRUPTED    52
#define SSH_EAP_AKA_ERR_MEMALLOC_FAILED     53
#define SSH_EAP_AKA_ERR_INVALID_STATE       54
#define SSH_EAP_AKA_ERR_USE_AKA_DASH        55 /* Flag for defining that 
                                                  server wishes to use the 
						  AKA-DASH over AKA */
/* EAP aka-dash error codes */
#ifdef SSHDIST_EAP_AKA_DASH
#define SSH_EAP_AKA_DASH_ERR_AUTN_INCORRECT 56 /* Send EAP-Response as
						  AKA-Auth-Reject */
#define SSH_EAP_AKA_DASH_ERR_ALT_KDF        57 /* Send EAP-Response as 
						  alternate KDF */
/* EAP aka-dash general condition codes */
#define SSH_EAP_AKA_DASH_KDF_FIRST_MATCH    58 /* Found the match in AT_KDFs 
						  list as first one */
#define SSH_EAP_AKA_DASH_KDF_ALT_MATCH      59 /* Found the match in AT_KDFs
                                                  list other than position
						  first */
#define SSH_EAP_AKA_DASH_KDF_NO_MATCH       60 /* Found no match in the 
						  AT_KDFs list */
#endif /* SSHDIST_EAP_AKA_DASH */

#define SSH_EAP_AKA_MAX_IDENTITY_MSGS      3

#define SSH_EAP_AKA_IDENTITY_REPLY_LEN     8
#define SSH_EAP_AKA_SYNCH_REPLY_LEN        24
#define SSH_EAP_AKA_AUTH_REJ_REPLY_LEN     8
#define SSH_EAP_AKA_NOTIF_REPLY_LEN        8
#define SSH_EAP_AKA_CHALLENGE_REPLY_LEN    48
#define SSH_EAP_AKA_CLIENT_ERROR_REPLY_LEN 12

#ifdef SSHDIST_EAP_AKA_DASH
#define SSH_EAP_AKA_DASH_CHALLENGE_ALT_KDF_REPLY_LEN 12
#endif /* SSHDIST_EAP_AKA_DASH */

#define SSH_EAP_AKA_MSK_LEN       64
#define SSH_EAP_AKA_EMSK_LEN      64
#define SSH_EAP_AKA_KENCR_LEN     16
#ifdef SSHDIST_EAP_AKA_DASH
/* Size of the authentication key is 32 bytes in aka-dash,
   whereas in aka, size of the authentication key is 16 bytes */
#define SSH_EAP_AKA_DASH_KAUT_LEN 32
#endif /* SSHDIST_EAP_AKA_DASH */
#define SSH_EAP_AKA_KAUT_LEN      16
#define SSH_EAP_AKA_RAND_LEN      16
#define SSH_EAP_AKA_MAC_LEN       16
#define SSH_EAP_AKA_AUTS_LEN      14
#define SSH_EAP_AKA_AUTN_LEN      16
#define SSH_EAP_AKA_CK_LEN        16
#define SSH_EAP_AKA_IK_LEN        16

/* Flags for EAP AKA protocol state. RFC 4187 strictly defines, 
   which information elements may exist and what state and 
   therefore we'll have to maintain strict state of the 
   protocol. */
#define SSH_EAP_AKA_IDENTITY_RCVD    0x0001
#define SSH_EAP_AKA_CHALLENGE_RCVD   0x0002
#define SSH_EAP_AKA_SYNCH_REQ_SENT   0x0004
#define SSH_EAP_AKA_PROT_SUCCESS     0x0008
#define SSH_EAP_AKA_PROCESSING_RAND  0x0010
#define SSH_EAP_AKA_FULLID_RCVD      0x0020
#define SSH_EAP_AKA_PERMID_RCVD      0x0040
#define SSH_EAP_AKA_ANYID_RCVD       0x0080
#define SSH_EAP_AKA_STATE_FAILED     0x0100
/* Flag for keeping the track of the bidding request */
#define SSH_EAP_AKA_BIDDING_REQ_RCVD 0x0200

#ifdef SSHDIST_EAP_AKA_DASH
/* Some flags for keeping track of the alternate KDF */
#define SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_SENT   0x0400
#define SSH_EAP_AKA_DASH_CHALLENGE_KDF_ALT_RCVD   0x0800

/* Different KDF values supported by Quicksec EAP-AKA' */
typedef enum {
  /* if doesnt match with any values of the KDF received from server. */
  SSH_EAP_KDF_FAIL = 0,

  /* This is the default transfrom value as per the draft of the EAP-AKA'.
     Dont change this value without consultation of the draft. */
  SSH_EAP_KDF_SHA256 = 1
} SSH_EAP_KDF_VALUE;
#endif /* SSHDIST_EAP_AKA_DASH */

typedef struct SshEapAkaIdentityRec {
  SshUInt8 rand[SSH_EAP_AKA_RAND_LEN];
  SshUInt8 autn[SSH_EAP_AKA_AUTN_LEN];
  SshUInt8 auts[SSH_EAP_AKA_AUTS_LEN];

  SshUInt8 IK[SSH_EAP_AKA_IK_LEN];
  SshUInt8 CK[SSH_EAP_AKA_CK_LEN];
#ifdef SSHDIST_EAP_AKA_DASH
  SshUInt8 IK_dash[SSH_EAP_AKA_IK_LEN];
  SshUInt8 CK_dash[SSH_EAP_AKA_CK_LEN];
#endif /* SSHDIST_EAP_AKA_DASH */

  SshUInt8 res[16];
  SshUInt8 res_len;

} *SshEapAkaIdentity, SshEapAkaIdentityStruct;

typedef struct SshEapAkaStateRec {
  SshUInt32 aka_proto_flags; 
  
  SshUInt8  msk[SSH_EAP_AKA_MSK_LEN];
  SshUInt8  emsk[SSH_EAP_AKA_EMSK_LEN];
  SshUInt8  K_encr[SSH_EAP_AKA_KENCR_LEN];
  union
    {
      SshUInt8  K_aut[SSH_EAP_AKA_KAUT_LEN];
#ifdef SSHDIST_EAP_AKA_DASH
      SshUInt8  K_aut_dash[SSH_EAP_AKA_DASH_KAUT_LEN];
#endif /* SSHDIST_EAP_AKA_DASH */
    } aut;

  SshEapAkaIdentityStruct aka_id;

  SshBuffer user;

  SshUInt8  response_id;
  SshUInt8  user_len;
  SshUInt8  identity_msg_cnt;
  /* Transform value, this transform represents the capability for KDF 
     algorithm */
  SshUInt32 transform; 
#ifdef SSHDIST_EAP_AKA_DASH
  /* Network name and length of the same from AT_KDF_INPUT */
  SshBuffer network_name;
  SshUInt16 network_name_len;
  /* Information from PM whether to verify the network_name or not */
  Boolean verify_kdfinput;
  /* kdf used for calculating the keys */
  SSH_EAP_KDF_VALUE use_kdf;
#endif /* SSHDIST_EAP_AKA_DASH */

  SshBuffer last_pkt;

} *SshEapAkaState, SshEapAkaStateStruct;

#endif /* SSHDIST_EAP_AKA */
#endif /** SSH_EAP_AKA_H */
