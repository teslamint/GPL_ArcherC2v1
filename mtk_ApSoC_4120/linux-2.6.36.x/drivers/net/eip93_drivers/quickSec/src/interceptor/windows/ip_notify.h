/**
   
   @copyright
   Copyright (c) 2010 - 2010, AuthenTec Oy.  All rights reserved.
   
   ip_notify.h
   
   This file contains definitions for IP address and route change 
   notifications.
   
*/


#ifndef SSH_IP_NOTIFY_H
#define SSH_IP_NOTIFY_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Registers IP address and route change notifications */
Boolean
ssh_register_ip_notifications(SshInterceptor interceptor);


/* Cancels previously registered IP address and route change notifications */
void
ssh_cancel_ip_notifications(SshInterceptor interceptor);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_IP_NOTIFY_H */
