/*
  File: dummy-if.h

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
	Interface to dummy SAD/PAD/SPD.
*/

#include "sshincludes.h"
#include "sshsad.h"
#include "pm_ike_sad.h"

extern SshSADInterfaceStruct dummy_if;

SshSADHandle d_sad_allocate(const char *policy);
void d_sad_destroy(SshSADHandle sad_handle);

Boolean ssh_ikev2_sa_freelist_create(SshSADHandle sad_handle);
Boolean ssh_ikev2_sa_freelist_destroy(SshSADHandle sad_handle);
Boolean ssh_ikev2_ts_freelist_create(SshSADHandle sad_handle);
Boolean ssh_ikev2_ts_freelist_destroy(SshSADHandle sad_handle);
Boolean ssh_ikev2_conf_freelist_create(SshSADHandle sad_handle);
Boolean ssh_ikev2_conf_freelist_destroy(SshSADHandle sad_handle);

/* Known algorithms */
struct TransformDefRec {
  SshIkev2TransformType transform;
  size_t keylen;
};

extern struct TransformDefRec d_sad_ciphers[];
extern size_t d_sad_ciphers_num;
extern struct TransformDefRec d_sad_prfs[];
extern size_t d_sad_prfs_num;
extern struct TransformDefRec d_sad_integs[];
extern size_t d_sad_integs_num;
extern struct TransformDefRec d_sad_dhs[];
extern size_t d_sad_dhs_num;
extern struct TransformDefRec d_sad_esns[];
extern size_t d_sad_esns_num;
