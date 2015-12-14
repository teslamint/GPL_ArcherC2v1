/*
  File: softacc.c

  Copyright:
          Copyright (c) 2008 SFNT Finland Oy.
                  All rights reserved

  Example file which configures an accelerated device. The 'accelerated' 
  operations are performed here in software. This implementation uses 
  threads to offload modexp operations to separate threads.

  This accelerator is only enabled if thread support is present.

*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshoperation.h"
#include "sshgetput.h"
#include "sshthreadedmbox.h"

#include "sshencode.h"
#include "sshcrypt.h"
#include "genaccdevicei.h"
#include "genaccprov.h"

#define SSH_DEBUG_MODULE "SshEKSoftAcc"

#define SSH_SOFT_ACCEL_MAX_THREADS 32

typedef struct SoftAccelRec
{
  SshThreadedMbox mbox;

} *SoftAccel;

/* Device initialization. */
Boolean ssh_soft_init(const char *initialization_info, 
                       void *extra_args, 
                       void **device_context)
{
  SoftAccel accel;
  unsigned int num_threads = SSH_SOFT_ACCEL_MAX_THREADS;

  SSH_DEBUG(SSH_D_LOWSTART, 
	    ("Have called the soft accelerator init function"));

#ifndef HAVE_THREADS
  return FALSE;
#endif /*  HAVE_THREADS */
  
  if ((accel = ssh_calloc(1, sizeof(*accel))) == NULL)
    return FALSE;
  
  if (initialization_info && !strncmp(initialization_info, 
				      "num-threads=",
				      strlen("num-threads=")))
    {
      num_threads = atoi(initialization_info + strlen("num-threads="));
      
      if (num_threads > SSH_SOFT_ACCEL_MAX_THREADS)
	num_threads = SSH_SOFT_ACCEL_MAX_THREADS;
    }
  SSH_DEBUG(SSH_D_HIGHOK, ("Using %d threads", num_threads));
  
  accel->mbox = ssh_threaded_mbox_create((SshInt32)num_threads);
  if (!accel->mbox)
    {
      ssh_free(accel);
      return FALSE;
    }
  
  *device_context = accel;
  return TRUE;
}
void ssh_soft_uninit(void *device_context)
{
  SoftAccel accel = device_context;

  if (accel->mbox)
    ssh_threaded_mbox_destroy(accel->mbox);
  
  ssh_free(accel);
  SSH_DEBUG(SSH_D_LOWSTART, ("Have uninitialized the soft accelerator"));
}


/************************************************************************/

typedef struct SoftModexpCtxRec
{
  SoftAccel accel;

  SshMPIntegerStruct base; 
  SshMPIntegerStruct exponent;
  SshMPIntegerStruct modulus;
  SshMPIntegerStruct ret;

  Boolean aborted;
  SshCryptoStatus status;
  SshAccDeviceReplyCB callback;
  SshOperationHandleStruct op[1];
  void *reply_context;
  unsigned char *buf;
  size_t buf_len;

} *SoftModexpCtx;

static void soft_modexp_abort(void *context)
{
  SoftModexpCtx ctx = context;

  ctx->aborted = TRUE;
}

static void soft_modexp_completion(void *context)
{
  SoftModexpCtx ctx = context;

  SSH_DEBUG(SSH_D_LOWOK,("In the modexp completion"));

  if (!ctx->aborted)
    {
      (*ctx->callback)(ctx->status, ctx->buf, ctx->buf_len, 
		       ctx->reply_context);
      
      ssh_operation_unregister(ctx->op);
    }      
  
  ssh_mprz_clear(&ctx->ret);
  ssh_mprz_clear(&ctx->base);
  ssh_mprz_clear(&ctx->exponent);
  ssh_mprz_clear(&ctx->modulus);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}

static void soft_modexp_thread_cb(void *context)
{
  SoftModexpCtx ctx = context;

  /* Do the math operation. */
  ssh_mprz_powm(&ctx->ret, &ctx->base, &ctx->exponent, &ctx->modulus);
  
  /* Linearize the MP integer to the buffer */
  if (!ssh_mprz_isnan(&ctx->ret))
    {
      ssh_mprz_get_buf(ctx->buf, ctx->buf_len, &ctx->ret);
      ctx->status = SSH_CRYPTO_OK;
    }  
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Ctx operation failed"));
      ctx->status = SSH_CRYPTO_OPERATION_FAILED;
    }
  
  /* Pass the message back to the event loop */
  SSH_DEBUG(SSH_D_LOWOK,("In the thread message handler, passing control "
			 "back to eloop"));
  




  if (!ssh_threaded_mbox_send_to_eloop(ctx->accel->mbox,
				       soft_modexp_completion, ctx))
    {
      ssh_mprz_clear(&ctx->ret);
      ssh_mprz_clear(&ctx->base);
      ssh_mprz_clear(&ctx->exponent);
      ssh_mprz_clear(&ctx->modulus);
      ssh_free(ctx->buf);
      ssh_free(ctx);      
    }
}

SshOperationHandle ssh_soft_modexp(void *device_context,
                                    SshAccDeviceOperationId op_id,
                                    const unsigned char *data,
                                    size_t data_len,
                                    SshAccDeviceReplyCB callback, 
                                    void *reply_context)
{
  SoftAccel accel;
  SoftModexpCtx modexp;
  unsigned char *b, *e, *m;
  size_t b_len, e_len, mod_len;

  accel = device_context;

  /* Decode the data buffer to extract the MP Integers */
  if (ssh_decode_array(data, data_len,
		       SSH_DECODE_UINT32_STR_NOCOPY(&b, &b_len),
		       SSH_DECODE_UINT32_STR_NOCOPY(&e, &e_len),
		       SSH_DECODE_UINT32_STR_NOCOPY(&m, &mod_len),
		       SSH_FORMAT_END) != data_len)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }    

  if ((modexp = ssh_calloc(1, sizeof(*modexp))) == NULL)
    { 
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }
  
  /* Allocate and set the MP Integers. */
  ssh_mprz_init(&modexp->base);
  ssh_mprz_init(&modexp->exponent);
  ssh_mprz_init(&modexp->modulus);
  ssh_mprz_init(&modexp->ret);
  
  ssh_mprz_set_buf(&modexp->base, b, b_len);
  ssh_mprz_set_buf(&modexp->exponent, e, e_len);
  ssh_mprz_set_buf(&modexp->modulus, m, mod_len);

  modexp->buf_len = mod_len;
  modexp->buf = ssh_calloc(1, modexp->buf_len);

  /* Check memory allocation failures. */
  if (ssh_mprz_isnan(&modexp->base) ||
      ssh_mprz_isnan(&modexp->exponent) ||
      ssh_mprz_isnan(&modexp->modulus) ||
      ssh_mprz_isnan(&modexp->ret) ||
      (modexp->buf == NULL))
    goto error;

  modexp->accel = accel;  
  modexp->reply_context = reply_context;
  modexp->callback = callback;

  ssh_operation_register_no_alloc(modexp->op, soft_modexp_abort, modexp);

  if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
					soft_modexp_thread_cb,
					modexp))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot send mbox operation to thread"));
      goto error;
    }
  return modexp->op; 
  
 error:
  SSH_DEBUG(SSH_D_FAIL, ("Soft accelerator modexp operation failed"));  

  if (modexp != NULL)
    {
      if (modexp->op)  
	ssh_operation_unregister(modexp->op);
      
      ssh_mprz_clear(&modexp->ret);
      ssh_mprz_clear(&modexp->base);
      ssh_mprz_clear(&modexp->exponent);
      ssh_mprz_clear(&modexp->modulus);
      if (modexp->buf)
	ssh_free(modexp->buf);
      ssh_free(modexp);
    } 

  (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
  return NULL;
}

/* The soft operation execute function. This is the entry point to
   the accelerator, when it is requested an operation. */
SshOperationHandle ssh_soft_execute(void *device_context,
                                     SshAccDeviceOperationId operation_id,
                                     const unsigned char *data,
                                     size_t data_len,
                                     SshAccDeviceReplyCB callback, 
                                     void *context)
{
  switch(operation_id)
    {
    case SSH_ACC_DEVICE_OP_MODEXP:
      return ssh_soft_modexp(device_context, operation_id, data, data_len,
			     callback, context);
      
    default:
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
      return NULL;
    }
}

/* Device configuration. */
struct SshAccDeviceDefRec ssh_acc_dev_soft_ops =
{
  "soft",
  16384,
  ssh_soft_init,
  ssh_soft_uninit,
  ssh_soft_execute
};
