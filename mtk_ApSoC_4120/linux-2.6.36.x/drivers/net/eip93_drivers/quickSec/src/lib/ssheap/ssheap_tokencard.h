/**
  ssheap_tokencard.h

  @copyright
          Copyright (c) 2002-2004 SFNT Finland Oy - 
  all Rights Reserved.
  
*/

#ifndef SSH_EAP_TOKENCARD_H

#define SSH_EAP_TOKENCARD_H 1

void* ssh_eap_tokencard_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_tokencard_destroy(SshEapProtocol, SshUInt8,void*);
SshEapOpStatus ssh_eap_tokencard_signal(SshEapProtocolSignalEnum, SshEap, 
					SshEapProtocol, SshBuffer);

#endif
