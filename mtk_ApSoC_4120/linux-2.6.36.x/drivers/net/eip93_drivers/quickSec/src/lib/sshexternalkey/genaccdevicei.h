/*

  Author: Patrick Irwin <irwin@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                  All rights reserved.

  Created: Tue Dec 11   2001 [irwin]

  File: genaccdevicei.h

  Description: The internal header file used by genaccprovider to get 
  a uniform interface for devices which perform accelerated public key 
  operations.

*/

#ifndef GEN_ACC_DEVICEI_H
#define GEN_ACC_DEVICEI_H

/* The pointer type that represents a device that performs accelerated 
   crypto operations. */ 
typedef struct SshAccDeviceRec *SshAccDevice;

#include "sshmp.h"
#include "sshcrypt.h"
#include "sshexternalkey.h"
#include "sshoperation.h"
#include "genaccprovideri.h"
#include "genaccprov.h"


/* The SshAccDeviceStatus below is used as a return value for function 
   calls. */
typedef enum
{
  /* The operation was successful. */
  SSH_ACC_DEVICE_OK = 0, 

  /* Not enough memory to complete the operation. */
  SSH_ACC_DEVICE_NO_MEMORY = 1,

  /* The operation is unsupported. */
  SSH_ACC_DEVICE_UNSUPPORTED = 2,

  /* Device was not registered as the internal slot table was exhausted.
     It can be enlargened using the *_MAX_SLOTS define. */
  SSH_ACC_DEVICE_SLOTS_EXHAUSTED = 3,

  /* Generic failure status error. */
  SSH_ACC_DEVICE_FAIL = 4
}
SshAccDeviceStatus;


struct SshAccDeviceRec
{
  SshAccDeviceDef ops;

  /* TRUE when the device has been successfully initialized */
  Boolean is_initialized;

  /* TRUE if RSA computations are done using the CRT */
  Boolean rsa_crt;

  /* The maximum modulus size in bits for which the accelerator 
     can perform the modexp operation. */
  SshUInt32 max_modexp_size;

  /* device specific initialization information can be added here. */
  char *device_info;

  /* Used by the externalkey layer */
  SshEkNotifyCB notify_cb;
  void *notify_context;

  /* Context for the device. */
  void *context;
};


/* Maximum number of accelerator devices. This can be increaed if 
   needed. */
#define SSH_ACC_MAX_DEVICES 8


/*********** Initialization and Freeing Operations ******************/


/* Allocate and initialize the device. 'name' is the unique name used to
   identify the device. device_init_info is the initialization string 
   passed to the init() function in the SshAccDeviceDef structure. 

   If 'wait_for_message' is TRUE the device initialization is delayed until 
   the initializing message function (ssh_acc_device_initialize_from_message) 
   is called.

*/ 
SshAccDeviceStatus ssh_acc_device_allocate(const char *name,
                                           const char *init_info,
                                           void *extra_args,
                                           Boolean wait_for_message,
                                           SshAccDevice *device);

/* This function initializes the device using 'message' as the 
   'extra_args' argument in the ssh_acc_device_allocate function. */
SshAccDeviceStatus 
ssh_acc_device_initialize_from_message(SshAccDevice device, void *message);

/* Uninitialize the device, this frees the memory allocated to the device. */  
void ssh_acc_device_free(SshAccDevice device);


/*********** The Modular Exponentation Operation ***********/

SshOperationHandle 
ssh_acc_device_modexp_op(SshAccDevice device, 
                         SshMPIntegerConst base, 
                         SshMPIntegerConst exp,
                         SshMPIntegerConst modulus, 
                         SshAccDeviceReplyCB callback, 
                         void *reply_context);


/******************** RSA CRT operation ********************/

SshOperationHandle 
ssh_acc_device_rsa_crt_op(SshAccDevice device, 
			  SshMPIntegerConst input, 
			  SshMPIntegerConst p,
			  SshMPIntegerConst q, 
			  SshMPIntegerConst dp,
			  SshMPIntegerConst dq,
			  SshMPIntegerConst u,
			  SshAccDeviceReplyCB callback, 
			  void *reply_context);

/*********** Operation to get Random Bytes from the Device. *********/

SshOperationHandle 
ssh_acc_device_get_random_bytes(SshAccDevice device, 
                                SshUInt32 bytes_requested, 
                                SshAccDeviceReplyCB callback, 
                                void *reply_context);


#endif /* GEN_ACC_DEVICEI_H */


