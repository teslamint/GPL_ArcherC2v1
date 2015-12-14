/*
 *
 * sshasyncop.h
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * The header file for asynchronous operations. A generic layer for
 * executing asynchronous operations over a reliable communication
 * channel, like the ipm-engine, some device or a TCP connection.
 *
 */

#ifndef SSHASYNCOP_H
#define SSHASYNCOP_H

#include "sshoperation.h"

/***************** Handling asynchronous operation objects ******************/

/* An asynchronous operation object. */
typedef struct SshAsyncOpCtxRec *SshAsyncOpCtx;

/* Success status of an asynchronous operation. */
typedef enum
{
  /* The operation was successful and the operation was called. */
  SSH_ASYNC_OP_SUCCESS                  = 0,

  /* The operation failed because there were not enough memory. */
  SSH_ASYNC_OP_ERROR_MEMORY             = 1,

  /* The called operation was not known. */
  SSH_ASYNC_OP_ERROR_OPERATION_UNKNOWN  = 2,

  /* Some other unspecified error occurred. */
  SSH_ASYNC_OP_ERROR_OTHER              = 3
} SshAsyncOpResult;

/* A callback function of this type is called to notify the success of
   an asynchronous operation.  The argument `result' specifies the
   success of the operation.  If the operation was successful, the
   argument `result_data', `result_data_len' contain the result of the
   operation. */
typedef void (*SshAsyncOpCompletionCB)(SshAsyncOpResult result,
                                       const unsigned char *result_data,
                                       size_t result_data_len,
                                       void *context);

/* Methods for an asynchronous operation implementation. */
struct SshAsyncOpMethodsRec
{
  /* Execute an asynchronous operation. */
  SshOperationHandle (*execute)(void *context,
                                SshUInt32 procedure_id,
                                const unsigned char *data,
                                size_t data_len,
                                SshAsyncOpCompletionCB callback,
                                void *callback_context);
};

typedef struct SshAsyncOpMethodsRec SshAsyncOpMethodsStruct;
typedef struct SshAsyncOpMethodsRec *SshAsyncOpMethods;

/* Create an asynchronous operation object using methods `methods'. */
SshAsyncOpCtx ssh_async_op_create(SshAsyncOpMethods methods, void *context);

/* Destroy an asynchronous operation object `asyncop'. */
void ssh_async_op_destroy(SshAsyncOpCtx asyncop);


/******************** Executing asynchronous operations *********************/

/* Execute an asynchronous operation `procedure_id' with the context
   `context'.  The arguments `data', `data_len' specify the arguments
   of the operation.  The contents of the data `data' is opaque for
   this framework.  It is simply passed to the operation without any
   assumptions about its contents.  The callback function `callback'
   will be called to complete the operation. */
SshOperationHandle ssh_async_op_execute(SshAsyncOpCtx asyncop,
                                        SshUInt32 procedure_id,
                                        const unsigned char *data,
                                        size_t data_len,
                                        SshAsyncOpCompletionCB callback,
                                        void *callback_context);


/**************** Pre-allocated asynchronous operation values ***************/

/* do the (hardware accelerated) modular exponentiation */
#define SSH_ASYNCOP_MODP 0x01

/* get random bits from the hardware */
#define SSH_ASYNCOP_RNG 0x02

#endif /* not SSHASYNCOP_H */
