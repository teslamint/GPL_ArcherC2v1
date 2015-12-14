/**
  ssheap_otp.h

  @copyright
          Copyright (c) 2002-2004 SFNT Finland Oy - 
  all Rights Reserved.
  
*/

#ifndef SSH_EAP_OTP_H

#define SSH_EAP_OTP_H 1

void* ssh_eap_otp_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_otp_destroy(SshEapProtocol, SshUInt8, void*);
SshEapOpStatus ssh_eap_otp_signal(SshEapProtocolSignalEnum, SshEap, 
				  SshEapProtocol, SshBuffer);


#endif
