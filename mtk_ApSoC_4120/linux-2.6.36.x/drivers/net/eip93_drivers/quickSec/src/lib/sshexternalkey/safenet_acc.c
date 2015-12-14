/*
  Copyright:
  Copyright (c) 2002-2005 SFNT Finland Oy.
  All rights reserved.

  All rights reserved.

  File: safenet_acc.c

  Accelerator for Safenet chips using UDM or SLAD.

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

#ifdef HAVE_SAFENET
#include "udm.h"
#include "initblk.h"
#ifdef CGX_BIG_ENDIAN
#define SAFENET_ACC_BIG_ENDIAN
#endif
#elif defined(HAVE_SAFENET_SLAD)
#define SAFENET_DEBUG
#include "safenet_pe.h"
#include "slad.h"
#include "slad_pka.h"
#ifdef SLAD_BIG_ENDIAN
#define SAFENET_ACC_BIG_ENDIAN
#endif
#endif



#if defined(HAVE_SAFENET) || defined(HAVE_SAFENET_SLAD)
#define SSH_SAFENET_DWORD_LENGTH 4
#define SSH_SAFENET_FIRST_DEVICE 0

#define SSH_DEBUG_MODULE "SshEKSafenetAcc"

/* How many threads (in addition to the event loop thread) used for 
   performing big math operations */
#define SSH_SAFENET_ACCEL_MAX_THREADS 1

#define SAFENET_OFFLOAD_BYTES 256
#define SAFENET_MAX_RNG_BYTES 256

#define STROBEWIDTH_1841 5          /* exp Strobe width for 184x */
#define PLL_CONFIG_1841 0x2852128e  /* expclk=210MHz, sysclk=62.5MHz, 
				       input=25MHz*/

#define STROBEWIDTH_1842 4          /* exp Strobe width for 184x */
#define PLL_CONFIG_1842 0x1e27128e  /* expclk=250MHz, sysclk=100MHz, 
				       input=40MHz*/
#define STROBEWIDTH_CONS 2
#define PLL_CONFIG_CONS 0x168e128e  /* conservative values for unknown 
				       input clock */


typedef struct SafenetAccelRec
{
  Boolean use_threads;
  SshThreadedMbox mbox;
} *SafenetAccel;

#define SSH_UDM_MAXIMUM_DEVICES 8   

#ifdef HAVE_SAFENET
UDM_DEVICEINFO SafenetdeviceInfo[SSH_UDM_MAXIMUM_DEVICES];
#elif defined(HAVE_SAFENET_SLAD)
PE_DEVICE_INIT SafenetdeviceInfo[SSH_UDM_MAXIMUM_DEVICES];
#endif

#ifdef SAFENET_ACC_BIG_ENDIAN
static void safenet_copy_key_material(unsigned char *dst, 
                                      const unsigned char *src, 
                                      int len)
{
  int i;

  SSH_ASSERT(len % 4 == 0);
  /* Swap byte order of each 4 bytes. */
  for (i = 0; i < len; i += 4) 
    {
      dst[i + 0] = src[i + 3];
      dst[i + 1] = src[i + 2];
      dst[i + 2] = src[i + 1];
      dst[i + 3] = src[i + 0];
    }
}
#endif /* SAFENET_ACC_BIG_ENDIAN */

#ifdef HAVE_SAFENET
/* Device initialization. */
Boolean ssh_safenet_init(const char *initialization_info,
                         void *extra_args,
                         void **device_context)
{
  SafenetAccel accel;
  UDM_DEVICEINFO device_info;
  Boolean found = FALSE;
  Boolean can_use_threads = TRUE;
  int status, i;
  int device_count=0;

  for (i = 0; i < SSH_UDM_MAXIMUM_DEVICES; i++)
    {
      if ((status = udm_device_info(i, &device_info)) != UDM_DRVSTAT_SUCCESS)
        continue;

      SSH_DEBUG(SSH_D_MIDOK, ("Found a device of type %d",
			      device_info.device_type)); 
      
      /* store the copy of the udm_device_info in a global structure */
      memcpy(&(SafenetdeviceInfo[device_count]), &device_info,
	     sizeof(UDM_DEVICEINFO));

      device_count++;

      /* Only enable threads for the 184x devices. */
      if (device_info.device_type == UDM_DEVICETYPE_1841)
	SSH_DEBUG(SSH_D_HIGHOK, ("This is an 1841 type device.")); 
      else
	can_use_threads = FALSE;

      found = TRUE;

#if 0
      /* The CGX public key accelerator is disabled when used with 
	 Safenet v1.0 silicon because of some problems when the CGX and 
	 UDM are enabled together. */
      if (device_info.device_type == UDM_DEVICETYPE_1141)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("CGX is disabled for the v1.0 devices")); 
	  return FALSE;
	}
#endif
    }
  if (!found)
    {
      SSH_DEBUG(SSH_D_ERROR, ("No device found")); 
      return FALSE;
    }

  if ((accel = ssh_calloc(1, sizeof(*accel))) == NULL)
    {
      return FALSE;
    }

  if (can_use_threads && initialization_info &&
      !strcmp(initialization_info, "use-threads"))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Creating threaded mbox, maximum %d threads", 
			       SSH_SAFENET_ACCEL_MAX_THREADS));

      accel->use_threads = TRUE;
      accel->mbox = ssh_threaded_mbox_create(SSH_SAFENET_ACCEL_MAX_THREADS);

      if (!accel->mbox)
	{
	  ssh_free(accel);
	  return FALSE;
	}
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Initializing Safenet accelerator"));

  for (i = 0; i < SSH_UDM_MAXIMUM_DEVICES; i++)
    {
      if ((status = udm_device_info(i, &device_info)) != UDM_DRVSTAT_SUCCESS)
        continue;
      
      if (device_info.device_type == UDM_DEVICETYPE_1841)
	{
	  unsigned int pll_config, strobewidth;
	  
	  /* Default conservative values. */
	  pll_config = PLL_CONFIG_CONS;
	  strobewidth = STROBEWIDTH_CONS;
	  
	  /* If the user has configured a specific device type, then set the 
	     pll config and strobe width. We assume that the users know what 
	     they are doing.*/
#ifdef SSH_SAFENET_USE_1840_DEVICE
	  SSH_DEBUG(SSH_D_HIGHOK, 
		    ("SSH_SAFENET_USE_1840_DEVICE is configured"));
	  pll_config = PLL_CONFIG_1841;
	  strobewidth = STROBEWIDTH_1841;
#endif  /* SSH_SAFENET_USE_1840_DEVICE */
	  
#ifdef SSH_SAFENET_USE_1841_DEVICE
	  SSH_DEBUG(SSH_D_HIGHOK, 
		    ("SSH_SAFENET_USE_1841_DEVICE is configured"));
	  pll_config = PLL_CONFIG_1841;
	  strobewidth = STROBEWIDTH_1841;
#endif  /* SSH_SAFENET_USE_1840_DEVICE */
	  
#ifdef SSH_SAFENET_USE_1842_DEVICE
	  SSH_DEBUG(SSH_D_HIGHOK, 
		    ("SSH_SAFENET_USE_1842_DEVICE is configured"));
	  pll_config = PLL_CONFIG_1842;
	  strobewidth = STROBEWIDTH_1842;
#endif  /* SSH_SAFENET_USE_1842_DEVICE */
  
	  SSH_DEBUG(SSH_D_HIGHOK, ("Setting the pll_config and strobewidth "
				   "to %x, %x", pll_config, strobewidth));

	  udm_pcicfg_write(i, 0x5c, pll_config);
	  udm_bus_write(i, &strobewidth, 0x3c14, 4);
	}  
    }

  *device_context = accel;

  SSH_DEBUG(SSH_D_MIDOK, ("CGX initialized successfully"));
  return TRUE;
}
#elif defined(HAVE_SAFENET_SLAD)
/* Safenet PE Device initialization. */
Boolean ssh_safenet_init(const char *initialization_info,
                         void *extra_args,
                         void **device_context)
{
  SafenetAccel accel;
  int device_count=1;

  /* Initialize all devices using PE call */
  if (!safenet_pe_init(SafenetdeviceInfo, &device_count))
    {
      SSH_DEBUG(SSH_D_ERROR, ("No device found"));
      return FALSE;
    }

  if ((accel = ssh_calloc(1, sizeof(*accel))) == NULL)
    {
      return FALSE;
    }

  *device_context = accel;

  SSH_DEBUG(SSH_D_MIDOK, ("CGX initialized successfully"));
  return TRUE;
}
#endif /* #ifdef HAVE_SAFENET */


void ssh_safenet_uninit(void *device_context)
{
  SafenetAccel accel = device_context;
  SSH_DEBUG(SSH_D_MIDOK, ("Called Safenet uninit."));

  if (accel->mbox)
    ssh_threaded_mbox_destroy(accel->mbox);

  ssh_free(accel);
  return;
}

static void endian_swap(unsigned char *to, const unsigned char *from, int len)
{
  int i;
  
  for (i = 0; i < len; i++)
    {
      *(to + i) = *(from + len - 1 - i);
    }
}

typedef struct SafenetModexpCtxRec {
  SafenetAccel accel; 

  SshOperationHandleStruct op[1];
  Boolean aborted;

  unsigned char res[SAFENET_OFFLOAD_BYTES];
  unsigned char base[SAFENET_OFFLOAD_BYTES];
  unsigned char exp[SAFENET_OFFLOAD_BYTES];
  unsigned char mod[SAFENET_OFFLOAD_BYTES]; 
  
  size_t b_len, e_len, mod_len, ret_len;

  SshAccDeviceReplyCB callback;
  void *reply_context;

  SshTimeoutStruct timeout;
} *SafenetModexpCtx;

static void modexp_cb_abort(void *ctx)
{
  SafenetModexpCtx context = ctx;

  if (context)
    context->aborted = TRUE;
}


static void modexp_finish(void *context)
{
  SafenetModexpCtx ctx =  context;
  size_t offset, ret_length;
  unsigned char temp[SAFENET_OFFLOAD_BYTES];

  SSH_DEBUG(SSH_D_LOWOK, ("In the modexp completion operation"));

  offset = 0;

  if (ctx->aborted)
    {
      ssh_free(ctx);
      return;
    }
  ssh_operation_unregister(ctx->op);
 
  ret_length = ctx->ret_len;

  /* Check the return length is sane */
  if (ret_length < 0 || ret_length > SAFENET_OFFLOAD_BYTES)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Returned length %d is invalid", ret_length)); 
      (*ctx->callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, ctx->reply_context);
      ssh_free(ctx);
      return;
    }
  
  /* Check that if the return length is longer than what it should be, 
     then the extra bytes are zero */
  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  
  if (ret_length > ctx->mod_len)
    {
      /* using 'temp' here just to check the relevant bytes of 'res' 
	 are zero*/
      if (memcmp(temp, ctx->res + offset + ctx->mod_len, 
		 ret_length - ctx->mod_len))
	{
	  SSH_DEBUG(3, ("cgx modexp failed, returned number is too big")); 
	  (*ctx->callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, 
			   ctx->reply_context);
	  ssh_free(ctx);
	  return;
	}
      else 
	{
	  ret_length = ctx->mod_len;
	}
    }  
  /* Convert the result back to big endian */
  endian_swap(temp + (ctx->mod_len - ret_length), ctx->res + offset, 
	      ret_length);

  SSH_DEBUG(SSH_D_LOWOK, ("Safenet modexp operation successful"));
      
  (*ctx->callback)(SSH_CRYPTO_OK, temp, ctx->mod_len, ctx->reply_context);
  ssh_free(ctx);
}


static void modexp_operation(void *context)
{
  SafenetModexpCtx ctx = (SafenetModexpCtx) context;
  EXPMOD_PARAM_BLK  expmod_blk; 
  int status;
  unsigned  int temp;
  unsigned  int len_of_response;
  unsigned  int mod = 0;
#ifdef SAFENET_ACC_BIG_ENDIAN
  unsigned  char buf[SAFENET_OFFLOAD_BYTES];
#endif

  if (ctx->aborted)
    {
      ssh_free(ctx);
      return;
    }

  mod = ctx->b_len % SSH_SAFENET_DWORD_LENGTH; 
  if (mod != 0)
    {
      /* If the length is in bytes, needs to be devided by 4 */    
      expmod_blk.asize = (ctx->b_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {  
      expmod_blk.asize = ctx->b_len / SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, ctx->base,expmod_blk.asize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material(ctx->base, buf,
			    expmod_blk.asize * SSH_SAFENET_DWORD_LENGTH);
#endif
  expmod_blk.a = (unsigned int *)ctx->base;
  mod = ctx->e_len % SSH_SAFENET_DWORD_LENGTH; 

  if (mod != 0)
    {
      expmod_blk.psize = (ctx->e_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      expmod_blk.psize = ctx->e_len / SSH_SAFENET_DWORD_LENGTH;  
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, ctx->exp, expmod_blk.psize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material(ctx->exp, buf,
			    expmod_blk.psize * SSH_SAFENET_DWORD_LENGTH);
#endif
  expmod_blk.p = (unsigned int *)ctx->exp;
  mod = ctx->mod_len % SSH_SAFENET_DWORD_LENGTH; 
  if (mod != 0)
    {
      expmod_blk.msize= (ctx->mod_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      expmod_blk.msize = ctx->mod_len / SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, ctx->mod, expmod_blk.msize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material(ctx->mod, buf,
			    expmod_blk.msize * SSH_SAFENET_DWORD_LENGTH);
#endif
  expmod_blk.m = (unsigned int *)ctx->mod;
  expmod_blk.ressize = sizeof(ctx->res) / SSH_SAFENET_DWORD_LENGTH; 
  expmod_blk.res = (unsigned int *)ctx->res;
  memset(expmod_blk.res, 0, sizeof(ctx->res));

  /* Check about the size of response buffer */
#ifdef HAVE_SAFENET
  status = udm_expmod(SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_num,
		      &expmod_blk);
  /* See how to handle the return status value from udm */
  if (status == UDM_DRVSTAT_SUCCESS)
#elif defined(HAVE_SAFENET_SLAD)

    status = 
      slad_expmod(SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_number,
		  &expmod_blk);
  if (status == SLAD_DRVSTAT_SUCCESS)
#endif
    {
      for (temp = 0; temp < expmod_blk.ressize; temp++)
        {
          if ((expmod_blk.res[expmod_blk.ressize -1 - temp]) != 0)
	    break;
        }
      /* size of response is in dword length */
      len_of_response = (expmod_blk.ressize - temp) * SSH_SAFENET_DWORD_LENGTH;

#ifdef SAFENET_ACC_BIG_ENDIAN
      memset(buf, 0, SAFENET_OFFLOAD_BYTES);
      safenet_copy_key_material(buf , (unsigned char *)expmod_blk.res,
				len_of_response);
      memcpy(ctx->res, buf, len_of_response);
#else
      memcpy(ctx->res, (unsigned char *)expmod_blk.res, len_of_response);
#endif
      ctx->ret_len = len_of_response;
    }
  else
    {
      len_of_response = -1; /* Failure */
      ctx->ret_len = len_of_response;
    }

  /* copy the data back in ctx */
  if (ctx->accel->use_threads)
    {
      /* Return control to the event loop */
      (void)ssh_threaded_mbox_send_to_eloop(ctx->accel->mbox,
					    modexp_finish, ctx);

      return;
    }  
  else
    {
      modexp_finish(ctx);
      return;
    }
}
 

SshOperationHandle ssh_safenet_modexp(void *device_context,
                                      SshAccDeviceOperationId op_id,
                                      const unsigned char *data,
                                      size_t data_len,
                                      SshAccDeviceReplyCB callback, 
                                      void *reply_context)
{
  SafenetAccel accel;
  SafenetModexpCtx ctx;
  unsigned char temp[SAFENET_OFFLOAD_BYTES];
  unsigned char *b, *e, *m; 
  
 
  accel = device_context;

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    { 
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ctx->accel = accel; 
  ctx->callback = callback;
  ctx->reply_context = reply_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Starting the safenet modexp operation"));
  
  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&b, &ctx->b_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&e, &ctx->e_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&m, &ctx->mod_len),
                       SSH_FORMAT_END) != data_len)
    
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(ctx);
      return NULL;
    }

  SSH_ASSERT(ctx->b_len <= ctx->mod_len);
  SSH_ASSERT(ctx->e_len <= ctx->mod_len);

  /* Check the input length is not too small */
  if (ctx->mod_len < 4)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Input data to the modexp is too short"));
      (*callback)(SSH_CRYPTO_DATA_TOO_SHORT, NULL, 0, reply_context);

      ssh_free(ctx);
      return NULL;
    }

  /* Check the input length is not too large */
  if (ctx->mod_len > SAFENET_OFFLOAD_BYTES)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Input data to the modexp is too long"));
      (*callback)(SSH_CRYPTO_DATA_TOO_LONG, NULL, 0, reply_context);

      ssh_free(ctx);
      return NULL;
    }

  /* Convert to little endian */
  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, b, ctx->b_len); 
  endian_swap(ctx->base, temp, ctx->b_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, e, ctx->e_len); 
  endian_swap(ctx->exp, temp, ctx->e_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, m, ctx->mod_len); 
  endian_swap(ctx->mod, temp, ctx->mod_len);

  ssh_operation_register_no_alloc(ctx->op,
				  modexp_cb_abort, ctx);
  
  if (accel->use_threads)
    {
      if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
					    modexp_operation,
					    ctx))
	{
	  (*ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, 
			   ctx->reply_context);
	  
	  ssh_operation_unregister(ctx->op);
	  ssh_free(ctx);
	  return NULL;
	}
    }
  else
    {
      ssh_register_timeout(&ctx->timeout, 0, 0, modexp_operation, ctx);
    }
  return ctx->op;
}


/*************************************************************************/

typedef struct SafenetCRTCtxRec {
  SafenetAccel accel; 

  SshOperationHandleStruct op[1];
  Boolean aborted;

  unsigned char res[SAFENET_OFFLOAD_BYTES ];
  unsigned char input[SAFENET_OFFLOAD_BYTES];
  unsigned char params[5 * SAFENET_OFFLOAD_BYTES];
  
  size_t X_len, max_len, mod_len;
  size_t P_len,Q_len,DP_len,DQ_len,U_len;
  size_t ret_len;

  SshTimeoutStruct timeout;
  
  SshAccDeviceReplyCB callback;
  void *reply_context;

} *SafenetCRTCtx;

static void crt_cb_abort(void *ctx)
{
  SafenetCRTCtx context = ctx;

  if (context)
    context->aborted = TRUE;
}

static void crt_finish(void *context)
{
  SafenetCRTCtx ctx = context;
  unsigned char temp[SAFENET_OFFLOAD_BYTES];
  size_t ret_len;

  SSH_DEBUG(SSH_D_LOWOK, ("In the RSA CRT completion operation"));

  if (ctx->aborted)
    {
      ssh_free(ctx);
      return;
    }

  ssh_operation_unregister(ctx->op);

  ret_len = ctx->ret_len;
  /* Check that if the return length is longer than what it should be, 
     then the extra bytes are zero */
  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 

  if (ret_len > ctx->mod_len)
    {
      /* using 'temp' here just to check the relevant bytes of 'res' are zero*/
      if (memcmp(temp, ctx->res + ctx->mod_len, ret_len - ctx->mod_len))
        {
          SSH_DEBUG(SSH_D_FAIL, 
		    ("CGX RSA CRT failed, returned number is too big"));

	  (*ctx->callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, 
			   ctx->reply_context);
	  ssh_free(ctx);
	  return;
        }
      else 
        {
          ret_len = ctx->mod_len;
        }
    }  

  /* Convert the result back to big endian */
  endian_swap(temp + (ctx->mod_len - ret_len), ctx->res , ret_len);

  SSH_DEBUG(SSH_D_LOWOK, ("Safenet RSA CRT operation successful"));
  (*ctx->callback)(SSH_CRYPTO_OK, temp, ctx->mod_len, ctx->reply_context);
  ssh_free(ctx);
  return; 
}

static void crt_operation(void *context)
{
  SafenetCRTCtx ctx = context; 
  EXPCRTMOD_PARAM_BLK  crt_param_blk;
  int                 len_of_param;
  int status, temp;
  int len_of_response;
  int mod = 0;
#ifdef SAFENET_ACC_BIG_ENDIAN
  unsigned char buf[SAFENET_OFFLOAD_BYTES];
#endif

  if (ctx->aborted)
    {
      ssh_free(ctx);
      return;
    }

  len_of_param = ctx->max_len;
  
  mod = ctx->X_len % SSH_SAFENET_DWORD_LENGTH;
  if (mod == 0)
    {
      crt_param_blk.asize = ctx->X_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.asize = (ctx->X_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, ctx->input,crt_param_blk.asize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material(ctx->input, buf,
			    crt_param_blk.asize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.a = (unsigned int *)ctx->input;
  
  mod = crt_param_blk.qsize % SSH_SAFENET_DWORD_LENGTH;
  if (mod == 0)
    {
      crt_param_blk.qsize = ctx->Q_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.qsize = (ctx->Q_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, ctx->params, crt_param_blk.qsize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material(ctx->params, buf,
			    crt_param_blk.qsize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.q = (unsigned int *)ctx->params;
  
  mod = crt_param_blk.psize % SSH_SAFENET_DWORD_LENGTH;

  if (mod == 0)
    {
      crt_param_blk.psize = ctx->P_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.psize = (ctx->P_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, (ctx->params + len_of_param),
	 crt_param_blk.psize * SSH_SAFENET_DWORD_LENGTH);

  safenet_copy_key_material((ctx->params + len_of_param), buf,
			    crt_param_blk.psize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.p = (unsigned int *)(ctx->params + len_of_param);
  
  mod = crt_param_blk.dqsize % SSH_SAFENET_DWORD_LENGTH;
  if (mod == 0)
    {
      crt_param_blk.dqsize = ctx->DQ_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.dqsize = (ctx->DQ_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, (ctx->params + 2 * len_of_param),
	 crt_param_blk.dqsize * SSH_SAFENET_DWORD_LENGTH);

  safenet_copy_key_material((ctx->params + 2 * len_of_param),buf,
			    crt_param_blk.dqsize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.dq = (unsigned int *)(ctx->params + 2 * len_of_param);
  
  mod = crt_param_blk.dpsize % SSH_SAFENET_DWORD_LENGTH;

  if (mod == 0)
    {
      crt_param_blk.dpsize = ctx->DP_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.dpsize = (ctx->DP_len + SSH_SAFENET_DWORD_LENGTH - mod) /
	SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, (ctx->params + 3 * len_of_param),
	 crt_param_blk.dpsize * SSH_SAFENET_DWORD_LENGTH);

  safenet_copy_key_material((ctx->params + 3 * len_of_param), buf,
			    crt_param_blk.dpsize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.dp = (unsigned int *)(ctx->params + 3 * len_of_param);
  
  mod = crt_param_blk.usize % SSH_SAFENET_DWORD_LENGTH;

  if (mod == 0)
    {
      crt_param_blk.usize = ctx->U_len / SSH_SAFENET_DWORD_LENGTH;
    }
  else
    {
      crt_param_blk.usize = (ctx->U_len + 4 - mod) / SSH_SAFENET_DWORD_LENGTH;
    }
#ifdef SAFENET_ACC_BIG_ENDIAN
  memset(buf, 0, SAFENET_OFFLOAD_BYTES);
  memcpy(buf, (ctx->params + 4 * len_of_param),
	 crt_param_blk.usize * SSH_SAFENET_DWORD_LENGTH);
  safenet_copy_key_material((ctx->params + 4 * len_of_param), buf,
			    crt_param_blk.usize * SSH_SAFENET_DWORD_LENGTH);
#endif
  crt_param_blk.qinv = (unsigned int *)(ctx->params + 4 * len_of_param);
  
  crt_param_blk.ressize = sizeof(ctx->res) / SSH_SAFENET_DWORD_LENGTH; 
  crt_param_blk.res = (unsigned int *)ctx->res;
  memset(ctx->res, 0, sizeof(ctx->res));

#ifdef HAVE_SAFENET
  status = 
    udm_expcrtmod(SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_num,
		  &crt_param_blk);
  if (status == UDM_DRVSTAT_SUCCESS)
#elif defined(HAVE_SAFENET_SLAD)
    status = 
      slad_expcrtmod(SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_number,
		     &crt_param_blk);
  if (status == SLAD_DRVSTAT_SUCCESS)
#endif
    {
      for (temp = 0; temp < crt_param_blk.ressize; temp++)
 	{
   	  if ((crt_param_blk.res[crt_param_blk.ressize - 1 - temp]) != 0)
      	    break;
 	}

      /* size of response is in dword length */
      len_of_response = 
	SSH_SAFENET_DWORD_LENGTH * (crt_param_blk.ressize - temp);

#ifdef SAFENET_ACC_BIG_ENDIAN
      memset(buf,0,SAFENET_OFFLOAD_BYTES);
      safenet_copy_key_material(buf , (unsigned char *)crt_param_blk.res,
				len_of_response);
      memcpy(ctx->res, buf,len_of_response);
#else 
      memcpy(ctx->res, (unsigned char *)crt_param_blk.res, len_of_response);
#endif 
      ctx->ret_len = len_of_response;
    }
  else
    {
      len_of_response = -1; /* Failure */
      ctx->ret_len = len_of_response;
    }

  if (ctx->accel->use_threads)
    {
      /* Return control to the event loop */
      (void)ssh_threaded_mbox_send_to_eloop(ctx->accel->mbox,
					    crt_finish, ctx);
      return;
    }  
  else
    {
      crt_finish(ctx);
      return;
    }
}

SshOperationHandle ssh_safenet_rsa_crt(void *device_context,
				       SshAccDeviceOperationId op_id,
				       const unsigned char *data,
				       size_t data_len,
				       SshAccDeviceReplyCB callback, 
				       void *reply_context)
{
  SafenetAccel accel; 
  SafenetCRTCtx ctx;
  unsigned char temp[SAFENET_OFFLOAD_BYTES]; 
  unsigned char *X, *P, *Q, *DP, *DQ, *U;
  size_t X_len, P_len, Q_len, DP_len, DQ_len, U_len;
  size_t mod_len, max_len;

  accel = device_context;

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ctx->accel = accel; 
  ctx->callback = callback;
  ctx->reply_context = reply_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Starting the safenet RSA CRT operation"));
  
  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&X, &X_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&P, &P_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&Q, &Q_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&DP, &DP_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&DQ, &DQ_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&U, &U_len),
                       SSH_FORMAT_END) != data_len)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(ctx);
      return NULL;
    }
  
  mod_len = P_len + Q_len;

  max_len = (P_len > Q_len) ? P_len : Q_len;
  SSH_ASSERT(DP_len <= max_len);
  SSH_ASSERT(DQ_len <= max_len);
  SSH_ASSERT(U_len <= max_len);
  
  /* Roundup to a multiple of 8 */
  if (max_len & 0x7)
    max_len = 8 * ((max_len + 7)/ 8);

  ctx->mod_len = mod_len;
  ctx->max_len = max_len;
  ctx->X_len = X_len;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
	    ("input len %d, plen %d, qlen %d, dplen %d, dqlen %d, ulen %d",
	     X_len, P_len, Q_len, DP_len, DQ_len, U_len));  
  
  /* Check the input length is not too large */
  if (X_len > SAFENET_OFFLOAD_BYTES || max_len > SAFENET_OFFLOAD_BYTES)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Input data to the RSA CRT is too long"));
      (*callback)(SSH_CRYPTO_DATA_TOO_LONG, NULL, 0, reply_context);
      ssh_free(ctx);
      return NULL;
    }

  memset(ctx->params, 0, sizeof(ctx->params)); 

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, X, X_len); 
  endian_swap(ctx->input, temp, X_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, Q, Q_len); 
  endian_swap(ctx->params, temp, Q_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, P, P_len); 
  endian_swap(ctx->params + max_len, temp, P_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, DQ, DQ_len); 
  endian_swap(ctx->params + 2 * max_len, temp, DQ_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, DP, DP_len); 
  endian_swap(ctx->params + 3 * max_len, temp, DP_len);

  memset(temp, 0, SAFENET_OFFLOAD_BYTES); 
  memcpy(temp, U, U_len); 
  endian_swap(ctx->params + 4 * max_len, temp, U_len);


  ctx->Q_len = Q_len;
  ctx->P_len = P_len;
  ctx->DP_len = DP_len;
  ctx->DQ_len = DQ_len;
  ctx->U_len = U_len;

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Input buffer"), 
		    ctx->input, ctx->X_len);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("RSA CRT Params"), 
		    ctx->params, 5 * max_len);


  ssh_operation_register_no_alloc(ctx->op, crt_cb_abort, ctx);

  if (accel->use_threads)
    {
      if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
                                            crt_operation,
                                            ctx))
        {
          (*ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, 
			   ctx->reply_context);
          
          ssh_operation_unregister(ctx->op);
          ssh_free(ctx);
          return NULL;
        }
    }
  else
    {
      ssh_register_timeout(&ctx->timeout, 0, 0, crt_operation, ctx);
    }

  return ctx->op;
}


SshOperationHandle 
ssh_safenet_get_random_bytes(void *device_context,
                             const unsigned char *data,
                             size_t data_len,
                             SshAccDeviceReplyCB callback, 
                             void *reply_context)
{
  SshUInt32 bytes_requested;
  unsigned char buffer[SAFENET_MAX_RNG_BYTES];
  RANDOM_PARAM_BLK  random_blk;
  int   status = 0;
  SSH_DEBUG(SSH_D_LOWOK, ("Get random bytes from Safenet device"));

  if (data_len != 4)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);
      return NULL;
    }
  
  bytes_requested = SSH_GET_32BIT(data);
 
  memset(buffer, 0, SAFENET_MAX_RNG_BYTES);

  /* Ensure that bytes_requested is not bigger than SAFENET_MAX_RNG_BYTES */
  if (bytes_requested > SAFENET_MAX_RNG_BYTES)
    bytes_requested = SAFENET_MAX_RNG_BYTES;

  if (bytes_requested == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Get random bytes requested zero bytes"));
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);
      return NULL;

    }

  random_blk.size = bytes_requested;	
  random_blk.output = buffer;

#ifdef HAVE_SAFENET
  status =
    udm_get_random(SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_num,
		   &random_blk);
  if (status == UDM_DRVSTAT_SUCCESS)
#elif defined(HAVE_SAFENET_SLAD)
    status = slad_get_random
      (SafenetdeviceInfo[SSH_SAFENET_FIRST_DEVICE].device_number,
       &random_blk);
  if (status == SLAD_DRVSTAT_SUCCESS)
#endif
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Safenet get random bytes op. successful"));
      (*callback)(SSH_CRYPTO_OK, buffer, bytes_requested, reply_context);
      return NULL;

    }
  else
    {
      SSH_DEBUG(3, ("Get random bytes failed, code=%lx\n", status));
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);
      return NULL;
    }   

  return NULL;

}


/* The safenet operation execute function. This is the entry point to
   the accelerator, when it requests an operation. */
SshOperationHandle ssh_safenet_execute(void *device_context,
				       SshAccDeviceOperationId operation_id,
				       const unsigned char *data,
				       size_t data_len,
				       SshAccDeviceReplyCB callback, 
				       void *context)
{
  switch(operation_id)
    {
    case SSH_ACC_DEVICE_OP_MODEXP:
      return ssh_safenet_modexp(device_context, operation_id, data, data_len,
				callback, context);

    case SSH_ACC_DEVICE_OP_GET_RANDOM:
      return ssh_safenet_get_random_bytes(device_context, data, data_len,
					  callback, context);
#if 0
    case SSH_ACC_DEVICE_OP_RSA_CRT:
      return ssh_safenet_rsa_crt(device_context, operation_id, data, data_len,
				 callback, context);
#endif
    default:
      {
        (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
        return NULL;
      }
    }
}

#ifdef HAVE_SAFENET_SLAD
BOOL safenet_pe_init(PE_DEVICE_INIT device_init[], UINT32* device_count)
{
  Boolean found = FALSE;
  int status;
  UINT32 vers;
  UINT32 count;
  int i;
  SLAD_DEVICEINFO device_info;

  SSH_ASSERT(*device_count<=PE_MAX_DEVICES);
  
  for (i=0; i<*device_count; i++)
    { 
      device_init[i].found = FALSE;
      device_init[i].device_number = 0;
    }

  /* Get driver version. */
  status = slad_driver_version (&vers);

  if (status != SLAD_DRVSTAT_SUCCESS)
    {
#ifdef SAFENET_DEBUG
      printf("Cannot determine the SLAD driver version \n");
#endif /* SAFENET_DEBUG */
      return FALSE;
    }

#ifdef SAFENET_DEBUG
  printf("SLAD version %x.%02x\n",
         (vers >> 24) & 0xff, (vers >> 16) &0xff);
#endif /* SAFENET_DEBUG */

  /*  prepare supported devices list */

  /* Get device info and store the number of devices */
  count = 0;
  for (i = 0 ; i < *device_count; i++)
    {
      status = slad_device_info (i, &device_info);

      if (status != SLAD_DRVSTAT_SUCCESS)
	{
#ifdef SAFENET_DEBUG
	  printf("Cannot get the device info driver version\n");
#endif /* SAFENET_DEBUG */
	  continue;
	}
      found = TRUE;
      device_init[i].found = TRUE;
      device_init[i].device_number = i;
      count++;
    }
  *device_count = count;
  return found;
}

#endif /* HAVE_SAFENET_SLAD */

/* Device configuration. */
struct SshAccDeviceDefRec ssh_acc_dev_safenet_ops =
  {
    "safenet",
    (SAFENET_OFFLOAD_BYTES * 8) - 2,
    ssh_safenet_init,
    ssh_safenet_uninit,
    ssh_safenet_execute
  };
  
#endif /* HAVE_SAFENET || HAVE_SAFENET_SLAD */
