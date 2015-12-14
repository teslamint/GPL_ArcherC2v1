/*
 *
 * engine_asyncop.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Engine side implementation of the asynchronous operations.
 *
 */


#include "sshincludes.h"

#ifdef SSHDIST_ASYNCOP
#include "engine_internal.h"
#ifdef SSHDIST_IPSEC_HWACCEL
#include "engine_hwaccel.h"
#endif /* SSHDIST_IPSEC_HWACCEL */

#define SSH_DEBUG_MODULE "SshIpsecPmAsyncopEngine"

typedef struct SshEngineIpmAsyncOpCtxRec
{
  /* The engine object. */
  SshEngine engine;

  /* Completion callback and its context. */
  SshPmeAsyncopCB callback;
  void *context;

  /* Result of the operation. */
  SshAsyncOpResult result;
  unsigned char *result_data;
  size_t result_data_len;

  /* Is the `result_data' field dynamically allocated. */
  Boolean result_data_dynamic;

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* An user-mode timeout calling the completion callback. */
  SshTimeoutStruct timeout;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
} *SshEngineIpmAsyncOpCtx, SshEngineIpmAsyncOpCtxStruct;

/* completes a generic asynchop */
void ssh_pme_asyncop_complete_now(void *context)
{
  SshEngineIpmAsyncOpCtx ctx = (SshEngineIpmAsyncOpCtx) context;

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Check if the system is still running. */
  if (!ssh_engine_upcall_timeout(ctx->engine))
    {
      /* No.  We are shutting down. */
      if (ctx->result_data_dynamic)
        ssh_free(ctx->result_data);
      ssh_free(ctx);
      return;
    }
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /* Call the callback. */
  (*ctx->callback)(ctx->engine->pm, ctx->result,
                   ctx->result_data, ctx->result_data_len,
                   ctx->context);

  /* And cleanup. */
  if (ctx->result_data_dynamic)
    ssh_free(ctx->result_data);
  ssh_free(ctx);
}

void ssh_pme_asyncop_complete(SshEngineIpmAsyncOpCtx ctx,
                              SshAsyncOpResult result,
                              const unsigned char *result_data,
                              size_t result_data_len)
{
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Record one upcall to the policy manager. */
  ssh_kernel_mutex_lock(ctx->engine->flow_control_table_lock);
  ssh_engine_record_upcall(ctx->engine);
  ssh_kernel_mutex_unlock(ctx->engine->flow_control_table_lock);

  /* Store result arguments. */
  if (result_data)
    {
      ctx->result_data = ssh_memdup(result_data, result_data_len);
      if (ctx->result_data)
        {
          ctx->result_data_len = result_data_len;
          ctx->result_data_dynamic = TRUE;
          ctx->result = result;
        }
      else
        {
          /* Out of memory. */
          ctx->result = SSH_ASYNC_OP_ERROR_MEMORY;
        }
    }
  else
    {
      /* No data. */
      ctx->result = result;
    }

  /* Schedule a timeout to the user-mode to call the completion
     callback. */
  ssh_register_timeout(&ctx->timeout, 0, 0, ssh_pme_asyncop_complete_now, ctx);
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  /* Complete the operation immediately. */

  ctx->result = result;
  ctx->result_data = (unsigned char *) result_data;
  ctx->result_data_len = result_data_len;
  ctx->result_data_dynamic = FALSE;

  ssh_pme_asyncop_complete_now(ctx);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
}


#ifdef SSHDIST_IPSEC_HWACCEL
void
ssh_pme_asyncop_complete_modp(const SshHWAccelBigInt result,
                              void *context)
{
  SshEngineIpmAsyncOpCtx ctx = (SshEngineIpmAsyncOpCtx)context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  if (result == NULL)
    {
      /* the operation failed, send an error back */
      ssh_pme_asyncop_complete(ctx, SSH_ASYNC_OP_ERROR_OTHER, NULL, 0);
    }
  else
    {
      /* the operation was succesful, send the result data back to the
         policymanager */
      ssh_pme_asyncop_complete(ctx,
                               SSH_ASYNC_OP_SUCCESS,
                               (unsigned char *)result->v,
                               result->size);
    }
}


void
ssh_pme_asyncop_complete_rng(const unsigned char *random_bytes,
                             size_t random_bytes_length,
                             void *context)
{
  SshEngineIpmAsyncOpCtx ctx = (SshEngineIpmAsyncOpCtx)context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("called"));

  if (random_bytes == NULL)
    {
      /* the operation failed, send an error back */
      ssh_pme_asyncop_complete(ctx, SSH_ASYNC_OP_ERROR_OTHER, NULL, 0);
    }
  else
    {
      /* the operation was succesful, send the result data back to the
         policymanager */
      ssh_pme_asyncop_complete(ctx,
                               SSH_ASYNC_OP_SUCCESS,
                               random_bytes,
                               random_bytes_length);
    }
}
#endif /* SSHDIST_IPSEC_HWACCEL */

/* receives an asyncop packet from the policymanager. The
   operation_index is only meaningful when the pm-engine communication
   channel is used. The data is freed when this function returns */
void ssh_engine_pme_asyncop(SshEngine engine,
			    SshUInt32 procedure_id,
			    const unsigned char *op_data,
			    size_t op_data_len,
			    SshPmeAsyncopCB callback,
			    void *context)
{
  SshEngineIpmAsyncOpCtx ctx;
  SshAsyncOpResult result = SSH_ASYNC_OP_ERROR_OTHER;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      result = SSH_ASYNC_OP_ERROR_MEMORY;
      goto fail;
    }

  ctx->engine = engine;
  ctx->callback = callback;
  ctx->context = context;

  /* Check the requested operation. */
  switch (procedure_id)
    {
    case SSH_ASYNCOP_MODP:
      {
        SshHWAccelBigIntStruct base;
        SshHWAccelBigIntStruct exp;
        SshHWAccelBigIntStruct mod;

        if (ssh_decode_array(op_data, op_data_len,
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             (unsigned char **)&base.v, (size_t *)&base.size),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             (unsigned char **)&exp.v, (size_t *)&exp.size),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             (unsigned char **)&mod.v, (size_t *)&mod.size),
                             SSH_FORMAT_END) != op_data_len)
          {
            SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                              ("Bad modp packet from policy manager"),
                              op_data, op_data_len);
            goto fail;
          }
#ifdef SSHDIST_IPSEC_HWACCEL
        /* call the hwaccel modp function */
        ssh_hwaccel_perform_modp(&base, &exp, &mod,
                                 ssh_pme_asyncop_complete_modp,
                                 ctx);
#else /* SSHDIST_IPSEC_HWACCEL */
	goto fail;
#endif /* SSHDIST_IPSEC_HWACCEL */
        break;
      }
    case SSH_ASYNCOP_RNG:
      {
        SshUInt32 bytes_requested;

        /* Decode the requested bytes from the operation buffer */
        if (ssh_decode_array(op_data, op_data_len,
			     SSH_DECODE_UINT32(&bytes_requested),
			     SSH_FORMAT_END) != op_data_len)
	  goto fail;

#ifdef SSHDIST_IPSEC_HWACCEL
        /* Call the hwaccel modp function */
        ssh_hwaccel_get_random_bytes(bytes_requested,
                                     ssh_pme_asyncop_complete_rng,
                                     ctx);
#else /* SSHDIST_IPSEC_HWACCEL */
	goto fail;
#endif /* SSHDIST_IPSEC_HWACCEL */
        break;
      }

    default:
      {
        SSH_DEBUG(SSH_D_ERROR, ("unsupported asyncop received"));
        result = SSH_ASYNC_OP_ERROR_OPERATION_UNKNOWN;
        goto fail;
      }
    }

  /* All done. */
  return;


  /* Error handling.  We can complete the operation directly since we
     are invoked from a PM call. */

 fail:

  if (ctx)
    ssh_free(ctx);

  (*callback)(engine->pm, result, NULL, 0, context);
}

#endif /* SSHDIST_ASYNCOP */
