/*

kernel_timeouts.h

Author: Tatu Ylonen <ylo@ssh.fi>
        Antti Huima <huima@ssh.fi>
        Tero Kivinen <kivinen@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved.

Timeout processing for kernel code (more precisely, for the IPSEC
engine).  This header is machine-independent; however, the implementation is
machine-dependent.

*/

#ifndef SSHKERNELTIMEOUTS_H
#define SSHKERNELTIMEOUTS_H

/* Special wild-card context arguments to ssh_kernel_timeout_cancel. */
#define SSH_KERNEL_ALL_CALLBACKS ((SshKernelTimeoutCallback)1)
#define SSH_KERNEL_ALL_CONTEXTS  ((void *)1)

/* Callback functions of this type are called when a timeout occurs.
   The function receives as argument the context supplied when the
   timeout was registered.  A timeout is delivered only once, but can
   be reregistered in the callback function. */
typedef void (*SshKernelTimeoutCallback)(void *context);

/* Registers a timeout function that is to be called once when the specified
   time has elapsed.  The callback function may get called concurrently with
   other functions.

   The timeout will be delivered approximately after the specified time.  The
   exact time may differ somewhat from the specified time.

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function.
   The timeout cannot be zero. */
void ssh_kernel_timeout_register(SshUInt32 seconds, SshUInt32 microseconds,
                                 SshKernelTimeoutCallback callback,
                                 void *context);

/* Cancels any timeouts with a matching callback function and context.  If any
   such timeouts are currently executing, this does not return until they
   have completed execution.  Any matching timeouts inserted while waiting
   for such callbacks to return are also cancelled.
   
   `callback' may be SSH_KERNEL_ALL_CALLBACKS, which matches any function, and
   `context' may be SSH_KERNEL_ALL_CONTEXTS, which matches any context. */
void ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                               void *context);

#endif /* SSHKERNELTIMEOUTS_H */
