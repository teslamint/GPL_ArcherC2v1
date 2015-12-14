/*
  Copyright:
          Copyright (c) 2006 SFNT Finland Oy.
                  All rights reserved.

  All rights reserved.

  File: octeon_acc.c
  

  Accelerator for Octeon.

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

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_CAVIUM_OCTEON

#include "cryptlib.h"
#include "octeon_acci.h"

#define SSH_DEBUG_MODULE "SshEKOcteonAcc"

/* Device generic attributes */
#define SSH_DEV_OCTEON_MAX_THREADS 2 

#define  OCTEON_MAX_OFFLOAD_BYTE_SIZE 256
#define  OCTEON_MAX_RAND_BYTES        512


static void endian_swap(unsigned char *to, const unsigned char *from,
                        int len)
{
  int i;
  
  for (i = 0; i < len; i++)
    {
      *(to + i) = *(from + len - 1 - i);
    }
}


static void octeon_make_long_num(unsigned char *dst, const unsigned char *
                                 src, int len)
{
  int i;

  SSH_ASSERT ((len & 0x7) == 0);
  for (i = 0 ; i < len ; i += 8)
    {
       dst[i + 0] = src [i + 7];
       dst[i + 1] = src [i + 6];
       dst[i + 2] = src [i + 5];
       dst[i + 3] = src [i + 4];
       dst[i + 4] = src [i + 3];
       dst[i + 5] = src [i + 2];
       dst[i + 6] = src [i + 1];
       dst[i + 7] = src [i + 0];
    } 
}



/* Context structure for the accelarator */
typedef struct OcteonAccelRec
{
  Boolean use_threads;
  SshThreadedMbox mbox;
}OcteonAccelStruct, *OcteonAccel;


/* Initialization function for accelarator */
Boolean ssh_octeon_init (const char *init_string,
                         void * extra_args,
                         void ** device_context)
{
  OcteonAccel accel; 
  SSH_DEBUG(SSH_D_LOWOK, ("Octeon device initialization called"));
  *device_context = NULL;

  /* Do any initialization stuff here. */
  if (crypto_init() < 0)
    return FALSE;

  /* Initialize the random number generator */
  ssh_octeon_init_rng();  
  
  /* After the device has been successfully initialized, create a context for
   further operations. */
  accel = ssh_calloc(1, sizeof(*accel));
  if (NULL == accel)
    {
      crypto_close();
      return FALSE;
    }

  if (init_string && strcmp(init_string,"use-threads") == 0)
    {
      accel->use_threads = TRUE;



      accel->mbox = ssh_threaded_mbox_create(SSH_DEV_OCTEON_MAX_THREADS);
      if (NULL == accel->mbox)
        {
          ssh_free(accel);
	  return FALSE;
	}
    }

  *device_context = accel;

  SSH_DEBUG(SSH_D_LOWOK, ("Octeon device initialization completed"));
  return TRUE;
}


/* Uninitialization function for the accelerator. */
void ssh_octeon_uninit(void *context)
{
  OcteonAccel accel = (OcteonAccel) context;
 
  if (accel->mbox)
    ssh_threaded_mbox_destroy(accel->mbox);

  ssh_free(accel);

  crypto_close();
  SSH_DEBUG(SSH_D_MIDOK, ("Octeon accelerator uninited"));
}

/**************************************************************************/
typedef struct OcteonModExpCtxRec{
  OcteonAccel accel;
  SshOperationHandleStruct handle[1];
  Boolean aborted;
  SshAccDeviceReplyCB callback;
  void *reply_context;
  SshTimeoutStruct timeout;

  unsigned char res[OCTEON_MAX_OFFLOAD_BYTE_SIZE];
  unsigned char base[OCTEON_MAX_OFFLOAD_BYTE_SIZE];
  unsigned char exp[OCTEON_MAX_OFFLOAD_BYTE_SIZE];
  unsigned char mod[OCTEON_MAX_OFFLOAD_BYTE_SIZE];

  size_t b_len, e_len, mod_len, orig_mod_len;
}* OcteonModExpCtx;

static void octeon_modexp_abort(void *ctx)
{
  OcteonModExpCtx context = (OcteonModExpCtx) ctx;
  if (context != NULL)
    context->aborted = TRUE;
}

static void octeon_modexp_finish(void *ctx)
{
  OcteonModExpCtx context = (OcteonModExpCtx) ctx;
  unsigned char temp [OCTEON_MAX_OFFLOAD_BYTE_SIZE];
  unsigned char *result;
  int i = 0;

  if (context->aborted)
    {
      ssh_free(context);
      return;
    }
  ssh_operation_unregister(context->handle);
 /* Check that the length of result is less than the length of 
  modulus. */
  memset( temp, 0, OCTEON_MAX_OFFLOAD_BYTE_SIZE);

  if (memcmp(temp, context->res + context->mod_len, 
        OCTEON_MAX_OFFLOAD_BYTE_SIZE - context->mod_len) != 0)
  {
    SSH_DEBUG(SSH_D_FAIL, ("Result is too big"));
    (*context->callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0,
 		       context->reply_context);
  }

  endian_swap(temp, context->res, context->mod_len);
#ifdef WORDS_BIGENDIAN 
  octeon_make_long_num(context->res, temp, context->mod_len);
  result = context->res;
#else /* WORDS_BIGENDIAN */
  result = temp;
#endif /* WORDS_BIGENDIAN */
  
  for (i = 0; i < context->mod_len && 
              ((context->mod_len - i) > context->orig_mod_len);
              i++)
    {
      if (result[i]  != 0)
        break;
    }

#ifdef DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP (SSH_D_MIDOK, ("Result is "),
		                  result + i, context->mod_len - i);
#endif
  SSH_DEBUG(SSH_D_MIDOK, ("Modexp operation on Octeon is successful"));
  (*context->callback)(SSH_CRYPTO_OK, result + i ,context->mod_len - i,
		       context->reply_context);
  ssh_free(context);
}

static void octeon_modexp_operation(void * ctx)
{
  OcteonModExpCtx context = (OcteonModExpCtx) ctx;
  
  if (context->aborted)
    {
      ssh_free(context);
      return;
    }

/* Perform the operation here */
  cvm_ModExp((SshUInt64 *)context->res, (SshUInt64 *)context->base,
             (SshUInt64 *)context->exp, (SshUInt64 *)context->mod, 
             ((context->mod_len <<3) /192) +1,
	     context->e_len, context->mod_len, context->b_len); 

  if (context->accel->use_threads)
    {
      ssh_threaded_mbox_send_to_eloop(context->accel->mbox,
                                      octeon_modexp_finish, context);
      return;
    }
  else
    {
      octeon_modexp_finish(context);
      return;
    }
  SSH_NOTREACHED;
}
  
SshOperationHandle ssh_octeon_modexp(void *device_context,
                                     SshAccDeviceOperationId operation_id,
                                     const unsigned char *data,
                                     size_t data_len,
                                     SshAccDeviceReplyCB callback,
                                     void *context)
{
  OcteonAccel accel; 
  OcteonModExpCtx ctx;
  unsigned char *base, *exponent, *modulus;
  unsigned char temp[OCTEON_MAX_OFFLOAD_BYTE_SIZE];

#ifdef WORDS_BIGENDIAN
  unsigned char temp1[OCTEON_MAX_OFFLOAD_BYTE_SIZE];
#endif /* WORDS_BIGENDIAN */

  int offset = 0;

  accel = (OcteonAccel) device_context;
  ctx = ssh_calloc(1, sizeof(*ctx));

  if (NULL == ctx)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, context);
      return NULL;
    }

  ctx->accel = accel;
  ctx->callback = callback;
  ctx->reply_context = context;

  SSH_DEBUG(SSH_D_LOWOK, ("Decoding the attributes given to Octeon Accel"));
  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&base, &ctx->b_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&exponent, &ctx->e_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&modulus, &ctx->mod_len),
		       SSH_FORMAT_END) != data_len)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, context);
      return NULL;
    }

  SSH_ASSERT(ctx->b_len <= ctx->mod_len);
  SSH_ASSERT(ctx->e_len <= ctx->mod_len);
 
  /* Check the modulus length for boundary conditions. */
  if (ctx->mod_len < 4)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Input data to the modexp is too short"));
      (*callback)(SSH_CRYPTO_DATA_TOO_SHORT, NULL, 0, context);
      ssh_free(ctx);
      return NULL;
    }

  
  if (ctx->mod_len > OCTEON_MAX_OFFLOAD_BYTE_SIZE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Input data to the modexp is too long"));
      (*callback)(SSH_CRYPTO_DATA_TOO_LONG, NULL, 0, context);
      ssh_free(ctx);
      return NULL;
    }

#ifdef DEBUG_HEAVY
  SSH_DEBUG(SSH_D_MIDOK, (" Base length %d Exponent len %d mod len %d",
                        ctx->b_len, ctx->e_len, ctx->mod_len));
#endif 

  ctx->orig_mod_len = ctx->mod_len;  
  /* Convert to little endian. On big endian machines add leading 
  zeroes as necessary. */
  memset(temp, 0, OCTEON_MAX_OFFLOAD_BYTE_SIZE); 
#ifdef WORDS_BIGENDIAN
  offset = ctx->b_len & 0x7 ? 8 - (ctx->b_len & 0x7): 0;
#endif /* WORDS_BIGENDIAN */
  memcpy(temp + offset, base, ctx->b_len);
  ctx->b_len += offset; 
#ifdef WORDS_BIGENDIAN 
  endian_swap(temp1, temp, ctx->b_len);
  octeon_make_long_num(ctx->base, temp1, ctx->b_len);
#else /* WORDS_BIGENDIAN */
  endian_swap(ctx->base, temp, ctx->b_len);
#endif /* WORDS_BIGENDIAN */


  memset(temp, 0, OCTEON_MAX_OFFLOAD_BYTE_SIZE); 
#ifdef WORDS_BIGENDIAN
  offset = ctx->e_len & 0x7 ? 8 - (ctx->e_len & 0x7): 0;
#endif /* WORDS_BIGENDIAN */
  memcpy(temp + offset, exponent, ctx->e_len);
  ctx->e_len += offset;
#ifdef WORDS_BIGENDIAN
  endian_swap(temp1, temp, ctx->e_len);
  octeon_make_long_num(ctx->exp, temp1, ctx->e_len);
#else /* WORDS_BIGENDIAN */
  endian_swap(ctx->exponent, temp, ctx->e_len);
#endif /* WORDS_BIGENDIAN */


  memset(temp, 0, OCTEON_MAX_OFFLOAD_BYTE_SIZE); 
#ifdef WORDS_BIGENDIAN
  offset = ctx->mod_len & 0x7 ? 8 - (ctx->mod_len & 0x7): 0;
#endif /* WORDS_BIGENDIAN */
  memcpy(temp + offset, modulus, ctx->mod_len);
  ctx->mod_len += offset;
#ifdef WORDS_BIGENDIAN 
  endian_swap(temp1, temp, ctx->mod_len);
  octeon_make_long_num(ctx->mod, temp1, ctx->mod_len);
#else /* WORDS_BIGENDIAN */
  endian_swap(ctx->mod, temp, ctx->mod_len);
#endif /* WORDS_BIGENDIAN */

#ifdef DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Base is"), ctx->base, ctx->b_len);
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Exponent is"), ctx->exp, ctx->e_len);
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Modulus is"), ctx->mod, ctx->mod_len);

#endif 

  ssh_operation_register_no_alloc(ctx->handle,
				  octeon_modexp_abort, ctx);
  
  if (accel->use_threads)
    {
      if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
					    octeon_modexp_operation,
					    ctx))
	{
	  (*ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, 
			   context);
	  ssh_operation_unregister(ctx->handle);
	  ssh_free(ctx);
	  return NULL;
	}
    }
  else 
    {
      ssh_register_timeout(&ctx->timeout, 0, 0, 
                           octeon_modexp_operation, ctx);
    }
  return ctx->handle;
}


/**************************************************************************/
SshOperationHandle 
ssh_octeon_get_random_bytes(void *device_context,
                            SshAccDeviceOperationId operation_id,
                            const unsigned char *data,
                            size_t data_len,
                            SshAccDeviceReplyCB callback,
                            void *context)
{
  SshUInt32 bytes_requested;
  unsigned char buffer[OCTEON_MAX_RAND_BYTES] = {0};
  SshUInt32 status;

  if (data_len != 4)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, context);
      return NULL;
    }

  bytes_requested = SSH_GET_32BIT(data);

  if (bytes_requested == 0)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, context);
      return NULL;
    }

  if (data_len > OCTEON_MAX_RAND_BYTES)
    bytes_requested = OCTEON_MAX_RAND_BYTES;

  SSH_DEBUG(SSH_D_LOWOK, ("Get %d random bytes from octeon", bytes_requested));

  status = ssh_octeon_get_random(buffer, bytes_requested);

  if (status)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Get Random bytes op is successfull"));
      (*callback)(SSH_CRYPTO_OK, buffer, bytes_requested, context);
      return NULL;
    } 
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Get Random bytes op failed"));
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, context);
      return NULL;
    }
  
  return NULL;
}

/**************************************************************************/

/* The operation execution function. This is called when the device is 
 asked to perform an operation. */
SshOperationHandle ssh_octeon_execute(void *device_context,
                                       SshAccDeviceOperationId operation_id,
                                       const unsigned char *data,
                                       size_t data_len,
                                       SshAccDeviceReplyCB callback,
                                       void *context)
{
  switch (operation_id)
    {
      case SSH_ACC_DEVICE_OP_MODEXP:
        return ssh_octeon_modexp(device_context, operation_id,
                                 data, data_len, callback, context);
      case SSH_ACC_DEVICE_OP_GET_RANDOM:
        return ssh_octeon_get_random_bytes(device_context, operation_id, 
			                   data, data_len, callback, 
                                           context);
      case SSH_ACC_DEVICE_OP_RSA_CRT:
      default:
        (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
    }
  return NULL;
}



/* Device configuration. */
struct SshAccDeviceDefRec ssh_octeon_dev_ops =
  {
    "octeon",
    (OCTEON_MAX_OFFLOAD_BYTE_SIZE - 1) * 8,
    ssh_octeon_init,
    ssh_octeon_uninit,
    ssh_octeon_execute
  };
#endif /* ENABLE_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

