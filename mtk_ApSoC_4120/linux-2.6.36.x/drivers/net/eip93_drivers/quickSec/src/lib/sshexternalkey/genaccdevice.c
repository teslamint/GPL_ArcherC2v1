/*

  Copyright:
          Copyright (c) 2008 SFNT Finland Oy.
                  All rights reserved.

  Created: Tue Dec 11, 2001

  File: genaccdevice.c

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshexternalkey.h"
#include "genaccdevicei.h"
#include "genaccprovideri.h"
#include "sshproxykey.h"

#ifdef DEBUG_LIGHT
#include "dummyacc.h"
#endif /* DEBUG_LIGHT */

#ifdef HAVE_THREADS
#include "softacc.h"
#endif /* HAVE_THREADS */

























#ifdef SSHDIST_IPSEC_HWACCEL_OCF
#ifdef ENABLE_OCF_SP
#include "ocf_acc.h"
#endif /* ENABLE_OCF_SP */
#endif /* SSHDIST_IPSEC_HWACCEL_OCF */

#ifdef SSHDIST_IPSEC_HWACCEL_SAFENET_1X41
#if defined(HAVE_SAFENET) || defined(HAVE_SAFENET_SLAD)
#include "safenet_acc.h"
#endif /* HAVE_SAFENET */
#endif /* SSHDIST_IPSEC_HWACCEL_SAFENET_1X41 */


#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_CAVIUM_OCTEON
#include "octeon_acc.h"
#endif /* ENABLE_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */







#define SSH_DEBUG_MODULE "SshEKGenAccDevice"

SSH_DATA_INITONCE
static SshAccDeviceDef ssh_acc_device_def[SSH_ACC_MAX_DEVICES] =
{


















#ifdef SSHDIST_IPSEC_HWACCEL_OCF
#ifdef ENABLE_OCF_SP
  &ssh_acc_dev_ocf_ops,
#endif /* ENABLE_OCF_SP */
#endif /* SSHDIST_IPSEC_HWACCEL_OCF */







#ifdef SSHDIST_IPSEC_HWACCEL_SAFENET_1X41
#if defined(HAVE_SAFENET) || defined(HAVE_SAFENET_SLAD)
  &ssh_acc_dev_safenet_ops, 
#endif /* HAVE_SAFENET */
#endif /* SSHDIST_IPSEC_HWACCEL_SAFENET_1X41 */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_CAVIUM_OCTEON
  &ssh_octeon_dev_ops,
#endif /* ENABLE_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */







#ifdef HAVE_THREADS
  &ssh_acc_dev_soft_ops,
#endif /* HAVE_THREADS */

#ifdef DEBUG_LIGHT
  /* Keep this last in the list. */ 
  &ssh_acc_dev_dummy_ops,
#endif /* DEBUG_LIGHT */

   NULL, /* ... continued to the end. */
};


/* Register 'device_def' to the list of supported devices,
   ssh_acc_device_def[] */
SshAccDeviceStatus
ssh_acc_register_device(SshAccDeviceDef device_def)
{
  int i;

  if (device_def == NULL)
    return SSH_ACC_DEVICE_FAIL;

  for (i = 0; i < SSH_ACC_MAX_DEVICES; i++)
    {
      if (ssh_acc_device_def[i] == NULL)
        {
          /* Empty slot detected. */
          ssh_acc_device_def[i] = device_def;
          return SSH_ACC_DEVICE_OK;
        }

      if (ssh_acc_device_def[i] == device_def)
        /* Same device_def added already. */
        return SSH_ACC_DEVICE_OK;
    }
  SSH_DEBUG(SSH_D_FAIL,("%s\n", "Cannot register the device."));
  return SSH_ACC_DEVICE_SLOTS_EXHAUSTED;
}


/* Allocate and initialize a device. */
SshAccDeviceStatus
ssh_acc_device_allocate(const char *name,
                        const char *init_info,
                        void *extra_args,
                        Boolean wait_for_message,
                        SshAccDevice *device)
{
  SshAccDevice dev;
  int i;

  *device = NULL;

  if (name == NULL)
    return SSH_ACC_DEVICE_FAIL;
  
  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    {
      if (strcmp(ssh_acc_device_def[i]->name, name))
        continue;
      
      if ((dev = ssh_calloc(1, sizeof(*dev))) == NULL)
        return SSH_ACC_DEVICE_NO_MEMORY;
      
      if (init_info)
        {
          if ((dev->device_info = ssh_strdup(init_info)) == NULL)
            {
              ssh_free(dev);
              return SSH_ACC_DEVICE_NO_MEMORY;
            }
        }
      
      dev->ops = ssh_acc_device_def[i];
      dev->is_initialized = FALSE;
      dev->max_modexp_size = dev->ops->max_modexp_size;      

      /* Delay initialization until the message is recived */
      if (wait_for_message)
	{
	  *device = dev;
	  return SSH_ACC_DEVICE_OK;
	}
      
      if (dev->ops->init(init_info, extra_args, &dev->context))
        {
          dev->is_initialized = TRUE;
	  *device = dev;
	  return SSH_ACC_DEVICE_OK;
        }
      else 
        {
	  if (dev->device_info)
	    ssh_free(dev->device_info);
	  ssh_free(dev);
	  return SSH_ACC_DEVICE_FAIL;
        }
    }      
  return SSH_ACC_DEVICE_UNSUPPORTED;
}

SshAccDeviceStatus
ssh_acc_device_initialize_from_message(SshAccDevice device, void *message)
{
  SshAccDeviceStatus status;

  /* Only initialize once. */
  if (!device || device->is_initialized)
    return SSH_ACC_DEVICE_FAIL;

  status = device->ops->init(device->device_info, message,
                             &device->context);

  if (status == SSH_ACC_DEVICE_OK)
    device->is_initialized = TRUE;

  return status;
}



/* Uninitialize and free a device. */
void ssh_acc_device_free(SshAccDevice device)
{
  if (device)
    {
      if (device->is_initialized)
	device->ops->uninit(device->context);
      
      ssh_free(device->device_info);
      ssh_free(device);
    }
}


/* Perform software modexp */
static Boolean modexp_op_buf(unsigned char *ret, 
                             size_t ret_len,
                             const unsigned char *base,
                             size_t base_len, 
                             const unsigned char *exp,
                             size_t exp_len, 
                             const unsigned char *mod,
                             size_t mod_len)
{
  SshMPIntegerStruct b, e, m, r;

  if (ret_len < mod_len)
    return FALSE;

  memset(ret, 0, ret_len);
  ssh_mprz_init(&b);
  ssh_mprz_init(&e);
  ssh_mprz_init(&m);
  ssh_mprz_init(&r);
  
  ssh_mprz_set_buf(&b, base, base_len);
  ssh_mprz_set_buf(&e, exp, exp_len);
  ssh_mprz_set_buf(&m, mod, mod_len);
  
  ssh_mprz_powm(&r, &b, &e, &m);

  ssh_mprz_clear(&b);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&m);
  
  if (ssh_mprz_get_buf(ret, ret_len, &r) == 0) 
    {
      ssh_mprz_clear(&r);
      return FALSE;
    }
  ssh_mprz_clear(&r);
  return TRUE;  
} 
                                   

/********** The Device Modular Exponentation Operation. ************/

typedef struct SshAccDeviceModExpContextRec {
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;
  unsigned char *data;
  size_t data_len; 
  SshAccDeviceReplyCB callback;
  void *context;
} *SshAccDeviceModExpContext;


void ssh_acc_device_modexp_op_abort(void *context)
{
  SshAccDeviceModExpContext ctx = context;

  ssh_operation_abort(ctx->sub_op);
  ssh_free(ctx->data);
  ssh_free(ctx);
}

void ssh_acc_device_modexp_op_free(void *context)
{
  SshAccDeviceModExpContext ctx = context;

  ssh_operation_unregister(ctx->op);
  ssh_acc_device_modexp_op_abort(ctx);
}

void ssh_acc_device_modexp_op_done(SshCryptoStatus status,
                                   const unsigned char *data,
                                   size_t data_len,
                                   void *context)
{

  SshAccDeviceModExpContext ctx = context;
  
  ctx->sub_op = NULL;
  
  if (status == SSH_CRYPTO_OK)
    {
      /* No array decoding is needed. */
      (*ctx->callback)(SSH_CRYPTO_OK, data, data_len, ctx->context);
      ssh_acc_device_modexp_op_free(ctx);
      return;
    }
  else 
    {
      unsigned char *b, *e, *m, *ret;
      size_t b_len, e_len, mod_len, ret_len;

      /* The accelerated operation has failed, instead perform the operation 
	 in software. */
      SSH_DEBUG(SSH_D_FAIL, ("Accelerated modexp operation has failed, "
			     "now performing the operation in software"));
      
      /* Decode the data buffer to extract the original parameters */
      if (ssh_decode_array(ctx->data, ctx->data_len,
			   SSH_DECODE_UINT32_STR_NOCOPY(&b, &b_len),
			   SSH_DECODE_UINT32_STR_NOCOPY(&e, &e_len),
			   SSH_DECODE_UINT32_STR_NOCOPY(&m, &mod_len),
			   SSH_FORMAT_END) != ctx->data_len)
        {
          (*ctx->callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, ctx->context);
	  ssh_acc_device_modexp_op_free(ctx);
          return;
        }
      
      ret_len = mod_len;
      if ((ret = ssh_calloc(1, ret_len)) == NULL)
        {
          (*ctx->callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, ctx->context);
	  ssh_acc_device_modexp_op_free(ctx);
          return;
        }
      
      if (modexp_op_buf(ret, ret_len, b, b_len, 
                        e, e_len, m, mod_len))
        {
          (*ctx->callback)(SSH_CRYPTO_OK, ret, ret_len, ctx->context);
        }
      else
        {
          (*ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, ctx->context);
        }

      ssh_acc_device_modexp_op_free(ctx);
      ssh_free(ret);
      return;
    } 

}

/* The modexp operation with input as unsigned char buffers. */
SshOperationHandle
ssh_acc_device_modexp_op_buf(SshAccDevice device,
                             const unsigned char *base,
                             size_t base_len, 
                             const unsigned char *exp,
                             size_t exp_len, 
                             const unsigned char *mod,
                             size_t mod_len, 
                             SshAccDeviceReplyCB callback,
                             void *reply_context)
{
  SshAccDeviceModExpContext modexp_ctx;
  SshOperationHandle sub_op;
  unsigned char *data;
  size_t data_len;

  if (!device || !device->is_initialized)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  /* Is acceleration supported for this modulus size? */
  if (mod_len * 8 > device->max_modexp_size)
    {  
      unsigned char *ret;
      size_t ret_len;

      SSH_DEBUG(SSH_D_FAIL, ("Accelerated modexp operation unsupported for "
			     "this modulus size, doing modexp in software."));

      ret_len = mod_len;
      if ((ret = ssh_calloc(1, ret_len)) == NULL)
        {
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
      
      if (modexp_op_buf(ret, ret_len, base, base_len, 
                        exp, exp_len, mod, mod_len))
        {
          (*callback)(SSH_CRYPTO_OK, ret, ret_len, reply_context);
        }
      else
        {
          (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
        }
      
      ssh_free(ret);
      return NULL;
    }

  /* Encode the data */
  data_len = ssh_encode_array_alloc(&data,
                                    SSH_ENCODE_UINT32_STR(base, base_len),
                                    SSH_ENCODE_UINT32_STR(exp, exp_len),
                                    SSH_ENCODE_UINT32_STR(mod, mod_len),
                                    SSH_FORMAT_END);

  /* If no memory */
  if (!data)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Allocate the modexp context */
  if ((modexp_ctx = ssh_calloc(1, sizeof(*modexp_ctx))) != NULL)
    {
      modexp_ctx->callback = callback;
      modexp_ctx->context = reply_context;
      modexp_ctx->data = data;
      modexp_ctx->data_len = data_len;
    }
  else
    {
      ssh_free(data);

      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ssh_operation_register_no_alloc(modexp_ctx->op,
				  ssh_acc_device_modexp_op_abort,
				  modexp_ctx);
  
  sub_op = device->ops->execute(device->context,
                                SSH_ACC_DEVICE_OP_MODEXP,
                                data,
                                data_len,
                                ssh_acc_device_modexp_op_done,
                                modexp_ctx);

  if (sub_op)
    {
      modexp_ctx->sub_op = sub_op;
      return modexp_ctx->op;
    }

  return NULL;
}


/* The Modular Exponentation operation. */
SshOperationHandle
ssh_acc_device_modexp_op(SshAccDevice device,
                         SshMPIntegerConst base,
                         SshMPIntegerConst exponent,
                         SshMPIntegerConst modulus,
                         SshAccDeviceReplyCB callback,
                         void *reply_context)
{
  SshOperationHandle op;
  unsigned char *b, *e, *m;
  size_t b_len, e_len, mod_len;

  if (!device || !device->is_initialized)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  /* convert the MP Integers to buffers */
  b_len = ssh_mprz_byte_size(base);
  e_len = ssh_mprz_byte_size(exponent);
  mod_len = ssh_mprz_byte_size(modulus);

  /* allocate memory */
  b = ssh_malloc(b_len);
  e = ssh_malloc(e_len);
  m = ssh_malloc(mod_len);

  /* if no memory */
  if (b == NULL || e == NULL || m == NULL)
    {
      /* free b, e, m buffers */
      ssh_free(b);
      ssh_free(e);
      ssh_free(m);

      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* mp integers -->  buf  */
  ssh_mprz_get_buf(b, b_len,  base);
  ssh_mprz_get_buf(e, e_len,  exponent);
  ssh_mprz_get_buf(m, mod_len,  modulus);

  op = ssh_acc_device_modexp_op_buf(device,
                                    b, b_len,
                                    e, e_len, 
                                    m, mod_len,
                                    callback, 
                                    reply_context);

  ssh_free(b);
  ssh_free(e);
  ssh_free(m);

  return op;
}

/************ RSA CRT operation. ************/

typedef struct SshAccDeviceCRTContextRec {
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;
  unsigned char *data;
  size_t data_len; 
  SshAccDeviceReplyCB callback;
  void *context;
} *SshAccDeviceCRTContext;


void ssh_acc_device_rsa_crt_op_abort(void *context)
{
  SshAccDeviceCRTContext ctx = context;

  ssh_operation_abort(ctx->sub_op);
  ssh_free(ctx->data);
  ssh_free(ctx);
}

void ssh_acc_device_rsa_crt_op_free(void *context)
{
  SshAccDeviceCRTContext ctx = context;

  ssh_operation_unregister(ctx->op);
  ssh_acc_device_rsa_crt_op_abort(ctx);
}

void ssh_acc_device_rsa_crt_op_done(SshCryptoStatus status,
                                   const unsigned char *data,
                                   size_t data_len,
                                   void *context)
{

  SshAccDeviceModExpContext ctx = context;
  
  ctx->sub_op = NULL;
  
  if (status == SSH_CRYPTO_OK)
    (*ctx->callback)(SSH_CRYPTO_OK, data, data_len, ctx->context);
  else 
    (*ctx->callback)(status, NULL, 0, ctx->context);

  ssh_acc_device_rsa_crt_op_free(ctx);
  return;
}

SshOperationHandle 
ssh_acc_device_rsa_crt_op(SshAccDevice device, 
			  SshMPIntegerConst input, 
			  SshMPIntegerConst P,
			  SshMPIntegerConst Q, 
			  SshMPIntegerConst DP,
			  SshMPIntegerConst DQ,
			  SshMPIntegerConst U,
			  SshAccDeviceReplyCB callback, 
			  void *reply_context)
{
  SshOperationHandle sub_op;
  SshAccDeviceCRTContext crt_ctx;
  unsigned char *x, *p, *q, *dp, *dq, *u;
  size_t x_len, p_len, q_len, dp_len, dq_len, u_len;
  unsigned char *data;
  size_t data_len;


  if (!device || !device->is_initialized || !device->rsa_crt)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  /* convert the MP Integers to buffers */
  x_len = ssh_mprz_byte_size(input);
  p_len = ssh_mprz_byte_size(P);
  q_len = ssh_mprz_byte_size(Q);
  dp_len = ssh_mprz_byte_size(DP);
  dq_len = ssh_mprz_byte_size(DQ);
  u_len = ssh_mprz_byte_size(U);

    /* allocate memory */
  x = ssh_malloc(x_len);
  p = ssh_malloc(p_len);
  q = ssh_malloc(q_len);
  dp = ssh_malloc(dp_len);
  dq = ssh_malloc(dq_len);
  u = ssh_malloc(u_len);


/* if no memory */
  if (x == NULL || p == NULL || q == NULL || u == NULL || dp == NULL 
      || dq == NULL)
    {
      ssh_free(x); ssh_free(p); ssh_free(q); 
      ssh_free(u); ssh_free(dp); ssh_free(dq);
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* mp integers -->  buf  */
  ssh_mprz_get_buf(x, x_len,  input);
  ssh_mprz_get_buf(p, p_len,  P);
  ssh_mprz_get_buf(q, q_len,  Q);
  ssh_mprz_get_buf(dp, dp_len,  DP);
  ssh_mprz_get_buf(dq, dq_len,  DQ);
  ssh_mprz_get_buf(u, u_len,  U);

  /* Encode the data */
  data_len = 
    ssh_encode_array_alloc(&data,
                           SSH_ENCODE_UINT32_STR(x, x_len),
                           SSH_ENCODE_UINT32_STR(p, p_len),
                           SSH_ENCODE_UINT32_STR(q, q_len),
                           SSH_ENCODE_UINT32_STR(dp, dp_len),
                           SSH_ENCODE_UINT32_STR(dq, dq_len),
                           SSH_ENCODE_UINT32_STR(u, u_len),
                           SSH_FORMAT_END);

  ssh_free(x); ssh_free(p); ssh_free(q); 
  ssh_free(u); ssh_free(dp); ssh_free(dq);

  /* If no memory */
  if (!data)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Allocate the crt context */
  if ((crt_ctx = ssh_calloc(1, sizeof(*crt_ctx))) != NULL)
    {
      crt_ctx->callback = callback;
      crt_ctx->context = reply_context;
      crt_ctx->data = data;
      crt_ctx->data_len = data_len;
    }
  else
    {
      ssh_free(data);
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ssh_operation_register_no_alloc(crt_ctx->op,
				  ssh_acc_device_rsa_crt_op_abort,
				  crt_ctx);
  
  sub_op = device->ops->execute(device->context,
				SSH_ACC_DEVICE_OP_RSA_CRT,
                                data,
                                data_len,
                                ssh_acc_device_rsa_crt_op_done,
                                crt_ctx);
  
  if (sub_op)
    {
      crt_ctx->sub_op = sub_op;
      return crt_ctx->op;
    }

  return NULL;

}

/************ Get Random Bytes From The Device. ************/

SshOperationHandle
ssh_acc_device_get_random_bytes(SshAccDevice device,
                                SshUInt32 bytes_requested,
                                SshAccDeviceReplyCB callback,
                                void *reply_context)
{
 unsigned char buf[4];


  if (!device || !device->is_initialized)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,("Calling the get random bytes function for %d bytes",
                         (int) bytes_requested));
  
 /* Encode the requested bytes to the operation buffer */     
  ssh_encode_array(buf, 4,
                   SSH_ENCODE_UINT32(bytes_requested),
                   SSH_FORMAT_END);

  return device->ops->execute(device->context,
                              SSH_ACC_DEVICE_OP_GET_RANDOM,
                              buf, 4,
                              callback,
                              reply_context);
}



/*************************************************************************/

/* Returns a comma-separated list of supported device names.
   The caller must free the returned value with ssh_free(). */
char *
ssh_acc_device_get_supported(void)
{
  int i;
  size_t list_len, offset;
  unsigned char *list, *tmp;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    {
      size_t newsize;
      newsize = offset + 1 + !!offset +
        strlen(ssh_acc_device_def[i]->name);

      if (list_len < newsize)
        {
          newsize *= 2;

          if ((tmp = ssh_realloc(list, list_len, newsize)) == NULL)
            {
              ssh_free(list);
              return NULL;
            }
          list = tmp;
          list_len = newsize;
        }

      offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                             offset ? "," : "",
                             ssh_acc_device_def[i]->name);

    }
  return ssh_sstr(list);
}

Boolean
ssh_acc_device_supported(const char *name)
{
  unsigned int i;

  if (name == NULL)
    return FALSE;

  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    if (strcmp(ssh_acc_device_def[i]->name, name) == 0)
      return TRUE;

  return FALSE;
}

