/*
 *
 * sshasyncop.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Create and execute asynchronous operations 
 *
 */

#include "sshincludes.h"
#include "sshasyncop.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAsyncOp"

/* An asynchronous operation object. */
struct SshAsyncOpCtxRec
{
  SshAsyncOpMethods methods;
  void *context;
};

/***************** Handling asynchronous operation objects ******************/

SshAsyncOpCtx
ssh_async_op_create(SshAsyncOpMethods methods, void *context)
{
  SshAsyncOpCtx ctx = ssh_calloc(1, sizeof(*ctx));

  if (ctx == NULL)
    return NULL;

  ctx->methods = methods;
  ctx->context = context;

  return ctx;
}


void
ssh_async_op_destroy(SshAsyncOpCtx asyncop)
{
  ssh_free(asyncop);
}


/******************** Executing asynchronous operations *********************/

SshOperationHandle
ssh_async_op_execute(SshAsyncOpCtx asyncop,
                     SshUInt32 procedure_id,
                     const unsigned char *data,
                     size_t data_len,
                     SshAsyncOpCompletionCB callback,
                     void *callback_context)
{
  return (*asyncop->methods->execute)(asyncop->context,
                                      procedure_id,
                                      data, data_len,
                                      callback,
                                      callback_context);
}
