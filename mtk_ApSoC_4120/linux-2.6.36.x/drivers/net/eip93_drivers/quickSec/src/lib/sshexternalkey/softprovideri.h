/*

softprovideri.h

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved

Created: Mon Nov  8 15:04:46 1999 vsuontam
Last modified: Fri Mar 07 11:58:42 2003 vsuontam

  Some structures and message identifier shared by softprovider and
  the sshsoftkey interface.

*/

#ifndef SOFT_PROVIDERI_INCLUDED
#define SOFT_PROVIDERI_INCLUDED

#include "sshexternalkey.h"
#include "sshtimeouts.h"


/* The structure used in "SSH_SOFT_ADD_KEY_AND_CERT" message */
typedef struct SshSoftAddKeyCertRec
{
  SshPrivateKey priv;
  const unsigned char *cert;
  size_t cert_len;
  const char *key_label;
  SshEkStatus status; /* The provider fills this */
} *SshSoftAddKeyCert, SshSoftAddKeyCertStruct;

/* The message used to add keys and certificates */
#define SSH_SOFTPROVIDER_ADD_KEY_AND_CERT_MESSAGE \
"SSH_EK_MESSAGE_SOFT_ADD_KEY_CERT"


#endif /* SOFT_PROVIDERI_INCLUDED */
