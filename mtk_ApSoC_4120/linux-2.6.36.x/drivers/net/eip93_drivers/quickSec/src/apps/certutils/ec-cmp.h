/*
  File: ec-cmp.h

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                  All rights reserved.

  Description:
        CMP enrollment client library.
*/

typedef enum {
  SSH_EC_CA_ID_NAME,
  SSH_EC_CA_ID_CERT,
  SSH_EC_CA_ID_RA_CERT  /* not yet */
} SshEcCAIdType;

typedef struct SshEcCmpCARec
{
  SshCmpVersion protocol_version;
  Boolean transport_level_poll;
  SshEcCAIdType identity_type;
  union
  {
    unsigned char *name;
    struct {
      unsigned char *data; size_t len;
    } cert;
  } identity;

  char *address;
  char *socks;
  char *proxy;
} *SshEcCmpCA, SshEcCmpCAStruct;

typedef enum {
  SSH_EC_EE_ID_PSK,
  SSH_EC_EE_ID_CERT,
  SSH_EC_EE_ID_RA       /* No EE pop, send in RA signed envelope. */
} SshEcEEIdType;
typedef struct SshEcCmpAuthRec
{
  SshEcEEIdType identity_type;
  union {
    struct
    {
      unsigned int count;
      unsigned char *kid, *key;
      size_t kid_len, key_len;
      char *name; /* optional */
    } psk;
#define id_count identity.psk.count
#define id_kid identity.psk.kid
#define id_key identity.psk.key
#define id_kid_len identity.psk.kid_len
#define id_key_len identity.psk.key_len
#define id_name identity.psk.name
    struct
    {
      unsigned char *data; size_t len;
      SshPrivateKey prvkey;
    } cert;
#define id_cert identity.cert.data
#define id_cert_len identity.cert.len
#define id_prvkey identity.cert.prvkey
  } identity;
} *SshEcCmpAuth, SshEcCmpAuthStruct;

typedef struct SshEcCmpKeyPairRec
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
} *SshEcCmpKeyPair, SshEcCmpKeyPairStruct;

typedef void (*SshEcCmpCertRepCB)(SshCmpStatus *accept_or_reject,
                                  void *context);

typedef SshOperationHandle
(*SshEcCmpCB)(SshCmpStatus status,
              SshCmpCertStatusSet certs, unsigned int ncerts,
              SshCmpCertSet extra, unsigned int nextra,
              SshEcCmpCertRepCB reply, void *reply_context,
              void *context);

/* Error and pending replies are received via this callback. */
typedef void (*SshEcCmpErrorCB)(SshCmpStatus status,
                                unsigned int pollid, unsigned int pollwhen,
                                SshStr status_string,
                                SshStr error_reason,
                                SshStr human_instructions,
                                void *context);

typedef void (*SshEcCmpDoneCB)(void *context);

SshOperationHandle
ssh_ec_cmp_enroll(SshCmpBodyType which,
                  SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshEcCmpKeyPair keypair, Boolean backup,
                  Boolean encrypt_pop,
                  SshX509Certificate certtemp,
                  SshEcCmpCB callback,
                  SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context);

SshOperationHandle
ssh_ec_cmp_recover(SshEcCmpCA ca,
                   SshEcCmpAuth authenticator,
                   SshX509Certificate certtemp,
                   SshPublicKey protocol_encryption_key,
                   SshEcCmpCB callback, SshEcCmpDoneCB done,
                   SshEcCmpErrorCB error,
                   void *callback_context);

typedef void
(*SshEcCmpRevokeCB)(SshCmpRevokedSet certs, unsigned int ncerts,
                    void *context);

SshOperationHandle
ssh_ec_cmp_revoke(SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshX509Certificate certtemp,
                  SshEcCmpRevokeCB callback,
                  SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context);

SshOperationHandle
ssh_ec_cmp_poll(SshEcCmpCA ca,
                SshEcCmpAuth authenticator,
                SshUInt32 nreq, SshMPInteger reqs,
                SshEcCmpCB callback,
                SshEcCmpDoneCB done,
                SshEcCmpErrorCB error,
                void *callback_context);
