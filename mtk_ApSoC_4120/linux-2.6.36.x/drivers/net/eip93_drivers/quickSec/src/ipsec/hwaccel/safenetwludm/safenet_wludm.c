/*

safenet_wludm.c

Author: Sunil Kumar <skumar1@in.safenet-inc.com>

  Copyright:
          Copyright (c) 2002, 2003, 2006 SFNT Finland Oy.
              All rights reserved.

*/

#include "sshincludes.h"
#include "engine_hwaccel.h"
#include "interceptor.h"
#include "sshcrypt.h"
/* WLUDM files included */
#include "udm.h"
#include "initblk.h"
#include "kernel_mutex.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineHwaccelWludm"

/* Perform zero-copying handling of packet data if possible. This define 
   should only be enabled on environments where packet data can be assumed 
   to be from DMA'able memory. This parameter cannot be enabled on non-Linux 
   platforms. */  
#undef SSH_SAFENET_PACKET_IS_DMA
#ifdef __linux__
#include "linux_internal.h"
#define SSH_SAFENET_PACKET_IS_DMA
#endif /* __linux__ */


#ifndef KERN_NOTICE
#define KERN_NOTICE ".. "
#endif

#define SSH_UDM_MAX_DEVICES 1

#define CGX_CRYPTO_NULL   0x000F
#define CGX_MAC_NULL      0x000F

#define MAC_INPUT_BLOCK_SIZE 64
#define SHA_OUTPUT_BLOCK_SIZE 20
#define MD5_OUTPUT_BLOCK_SIZE 16

#define swap_endian(n)  (((n >> 24) & 0x000000ff) + ((n >> 8) & 0x0000ff00) \
			+ ((n << 8) & 0x00ff0000) + ((n << 24) & 0xff000000))

typedef struct SshWludmDeviceRec *SshWludmDevice;
typedef struct SshWludmDeviceRec SshWludmDeviceStruct;

/* The data structure holding the device parameters */
struct SshWludmDeviceRec {

  struct SshWludmDeviceRec *next;
  int device_number; 
  UDM_DEVICEINFO device_info;
  int session_count;
};

static SshWludmDeviceStruct devices[SSH_UDM_MAX_DEVICES];
static SshWludmDevice wludm_devices;

struct SshHWAccelRec
{
  Boolean for_mac;
  Boolean for_encryption;
  Boolean encrypt;
  hash_cntxt hash;
  AES_crypto_cntxt  cipher;
  secretkey sk;
  size_t iv_len;
  unsigned char iv[16];
  unsigned char ipad[MAC_INPUT_BLOCK_SIZE];
  unsigned char opad[MAC_INPUT_BLOCK_SIZE];
  size_t digest_size;
  SshWludmDevice device;
  SshInterceptor interceptor;  
};

typedef struct SshHWAccelFinishRec
{
  SshInterceptorPacket pp;
  SshHWAccelCompletion completion;
  void *completion_context;
} *SshHWAccelFinish;

/* Allocates a hardware acceleration context for IPSEC transformations
   with cipher des/3des and with mac hmac-sha1-96, hmac-md5-96 or without a
   mac. It Fails for other ciphers and macs. The allocated accelerator
   is syncronous. */
SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
                                   Boolean  encrypt,
                                   const char *cipher_name,
                                   const unsigned char *cipher_key,
                                   size_t cipher_key_len,
                                   const unsigned char *cipher_iv,
                                   size_t cipher_iv_len,
                                   Boolean ah_style_mac,
                                   const char *mac_name,
                                   const unsigned char *mac_key,
                                   size_t mac_key_len)
{
  SshHWAccel accel = NULL;
  UINT16 ciph_mode, ciph_alg = CGX_CRYPTO_NULL;
  UINT16 hash_alg = CGX_MAC_NULL;
  size_t count;
  
  if (!interceptor)
    return NULL;
  /* Allocate the acceleration (session) context */
  accel = ssh_calloc(1, sizeof(*accel));
  if (!accel)
    {
      SSH_DEBUG(SSH_D_FAIL, ("unable to allocate accel."));
      return NULL;
    }
  accel->device = wludm_devices;
  accel->interceptor = interceptor;
  
  /* Get the ESP cipher algorithm */
  if (cipher_name && strcmp(cipher_name, "none"))
    {
      if (!strcmp(cipher_name, "3des-cbc"))
	{
	  ciph_alg = (UINT16) CGX_TRIPLE_DES_A;
	  ciph_mode = CGX_CBC_M;
	}
      else if (!strcmp(cipher_name, "des-cbc"))
	{
	  ciph_alg = (UINT16) CGX_DES_A;
	  ciph_mode = CGX_CBC_M;
	}
      else
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unsupported Cipher algorithm %s", 
				 cipher_name));
	  ssh_free(accel);
	  return NULL;
	}
 
      accel->sk.type = ciph_alg;
      accel->sk.extra  = NULL;
      accel->sk.length = (UINT16) cipher_key_len;
      if (cipher_key != NULL)
	memcpy(accel->sk.k, cipher_key, cipher_key_len);
      accel->cipher.config = ciph_mode;
      accel->cipher.key = 1;	  
      if (cipher_iv_len)
	{
	  memcpy(accel->cipher.iv, cipher_iv, cipher_iv_len);
	  memcpy(accel->iv, cipher_iv, cipher_iv_len);
	  accel->iv_len = cipher_iv_len;
	}
      else
	{
    	  accel->iv_len = 0;
	}
    }
  else
    {
      ciph_alg = CGX_CRYPTO_NULL;
    }

  /* Get the mac algorithm */
  if (mac_name)
    {
      if (!strcmp(mac_name, "hmac-sha1-96"))
	{
	  hash_alg = (UINT16) CGX_SHS_A;
	  accel->digest_size = SHA_OUTPUT_BLOCK_SIZE;
	}
      else if (!strcmp(mac_name, "hmac-md5-96"))
	{
	  hash_alg = (UINT16) CGX_MD5_A;
	  accel->digest_size = MD5_OUTPUT_BLOCK_SIZE;
	}
      else if (!strcmp(mac_name, "none"))
	{
	  hash_alg = CGX_MAC_NULL;
	}
      else
     	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unsupported MAC algorithm %s", mac_name));
	  ssh_free(accel);
	  return NULL;
	}
      accel->hash.algorithm = hash_alg;

      if (mac_key_len > MAC_INPUT_BLOCK_SIZE)
	{
	  ssh_free(accel);
	  return NULL;
	}
      
      for (count = 0; count < MAC_INPUT_BLOCK_SIZE; count++)
	{
	  accel->ipad[count] = 0x36;
	  accel->opad[count] = 0x5c;
	}
      for (count = 0; count < mac_key_len; count++)
	{
	  accel->ipad[count] ^= mac_key[count];
	  accel->opad[count] ^= mac_key[count];
	}
    }
  
  /* Verify we don't have both null cipher and null mac */
  if (hash_alg == CGX_MAC_NULL && ciph_alg == CGX_CRYPTO_NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot have both null cipher and null mac"));
      ssh_free(accel);
      return NULL;
    }
  
  if (hash_alg != CGX_MAC_NULL)
    accel->for_mac = TRUE;
  else
    accel->for_mac = FALSE;

  if (ciph_alg != CGX_CRYPTO_NULL)
    {
      accel->encrypt = TRUE;
      if (encrypt) 
        accel->for_encryption = TRUE;
      else
	accel->for_encryption = FALSE;
    }
  else
    accel->encrypt = FALSE;
  
  return accel;
}


/* Allocates a hardware acceleration context for
   compression/decompression using algorithm specified at
   `compression_name' This context is assumed to be used for the
   IPCOMP transformation. */

SshHWAccel ssh_hwaccel_alloc_ipcomp(SshInterceptor interceptor,
                                    Boolean compress,
                                    const char *compression_name)
{
  return NULL;
}

/* Frees the hardware acceleration context.  The engine guarantees
   that no operations will be in progress using the context when this
   is called. */

void ssh_hwaccel_free(SshHWAccel accel)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_hwaccel_free called"));
  ssh_free(accel);
}


void swap_endian_w (void * buf, size_t num_of_words)
{
  int i = 0;
  for (i = 0; i < num_of_words; i++)
    *((UINT32 *)buf + i) = swap_endian( *((UINT32 *)buf + i));
}


Boolean ssh_hwaccel_perform_ipsec_mac(SshHWAccel accel,
				      unsigned char *packet,
				      size_t mac_start_offset,
				      size_t mac_len,
				      size_t icv_offset)
{
  unsigned char buf[MAC_INPUT_BLOCK_SIZE + 20];
  BYTE *digest, *digest_ipad;
  hash_cntxt hash_ipad; 
  int status;

  memset(&hash_ipad, 0, sizeof(hash_ipad));

  hash_ipad.algorithm = accel->hash.algorithm;

  /* This operation could be optimized away by doing it on acceleration 
     context allocation (in ssh_hwaccel_alloc_ipsec). */
  if ((status = udm_hash_sync(0, &hash_ipad, accel->ipad, 
			      MAC_INPUT_BLOCK_SIZE,
			      CGX_HASH_INIT_MASK, 0))
      != UDM_DRVSTAT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("udm_hash_sync operation failed"));
      return FALSE;
    }

  if ((status = udm_hash_sync(0, &hash_ipad, 
			      packet + mac_start_offset, mac_len,
			      CGX_HASH_FINAL_MASK, 0))
      != UDM_DRVSTAT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("udm_hash_sync operation failed"));
      return FALSE;
    }
  digest_ipad = (BYTE *)hash_ipad.state.shs.digest;
  
  swap_endian_w(digest_ipad, accel->digest_size / 4);

  SSH_ASSERT(sizeof(buf) >= MAC_INPUT_BLOCK_SIZE + accel->digest_size);
  memcpy(buf, accel->opad, MAC_INPUT_BLOCK_SIZE);
  memcpy(buf + MAC_INPUT_BLOCK_SIZE, digest_ipad, accel->digest_size);
  
  if ((status = udm_hash_sync(0, &accel->hash, buf, 
			     MAC_INPUT_BLOCK_SIZE + accel->digest_size,
			     CGX_HASH_INIT_MASK | CGX_HASH_FINAL_MASK, 0))
      != UDM_DRVSTAT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("udm_hash_sync operation failed"));
      return FALSE;
    }
  /* The pointer to the digest output for hash operations */
  digest = (BYTE *)accel->hash.state.shs.digest;
  
  swap_endian_w(digest, accel->digest_size / 4);
  
  /* copy the first 96 bits in the packet */
  memcpy(packet + icv_offset, digest, 12);

  return TRUE;  
}

/*`hardware-accelerated' processing for an IPSEC transformation.  */
void ssh_hwaccel_perform_ipsec(SshHWAccel accel,
                               SshInterceptorPacket pp,
                               size_t encrypt_iv_offset,
                               size_t encrypt_len_incl_iv,
                               size_t mac_start_offset,
                               size_t mac_len,
                               size_t icv_offset,
                               SshHWAccelCompletion completion,
                               void *completion_context)
{
  SshWludmDevice device = accel->device; 
  unsigned char *packet, *crstart;
  size_t packet_len;
  unsigned int chunk_sz = 120;
  int status;
  
  packet_len = ssh_interceptor_packet_len(pp);
  packet = NULL;

  /* Get contiguous packet */
#ifdef SSH_SAFENET_PACKET_IS_DMA
  {
    SshInterceptorInternalPacket ipp;

    ipp = (SshInterceptorInternalPacket)pp;
    SSH_ASSERT(packet_len = ipp->skb->len);
    packet = ipp->skb->data;
  }
#else /* SSH_SAFENET_PACKET_IS_DMA */
  if ((packet = (unsigned char *) ssh_malloc(packet_len)) == NULL)
    goto fail;

  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  /* Get the pointer to the start of encrypted/decrypted packet */
  crstart = packet + encrypt_iv_offset + accel->iv_len;
	  
  if (accel->encrypt)
    {
      if (accel->for_encryption)
	{
	  memcpy(packet + encrypt_iv_offset, accel->cipher.iv, accel->iv_len);

          if ((status = udm_crypto_sync(device->device_number, &accel->cipher,
				       &accel->sk, crstart, 
				       (encrypt_len_incl_iv - accel->iv_len),
				       crstart, 
				       (encrypt_len_incl_iv - accel->iv_len),
				       0, 0, CGX_ENCRYPT_D, chunk_sz))
	      != UDM_DRVSTAT_SUCCESS)	
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("udm_crypto_sync operation failed"));
	      goto fail;
	    }
          if (accel->for_mac)
            if (!ssh_hwaccel_perform_ipsec_mac(accel, packet, mac_start_offset,
					       mac_len, icv_offset))
	      {
		SSH_DEBUG(SSH_D_FAIL, ("mac operation failed"));
                goto fail;
	      }
	}
      else
        {
	  if (accel->for_mac)
            if (!ssh_hwaccel_perform_ipsec_mac(accel, packet, mac_start_offset,
					       mac_len, icv_offset))
	      {
                SSH_DEBUG(SSH_D_FAIL, ("mac operation failed"));
		goto fail;
	      }
  
	  memcpy(packet + encrypt_iv_offset, accel->cipher.iv, accel->iv_len);
          if ((status = udm_crypto_sync(device->device_number, &accel->cipher,
				       &accel->sk, crstart, 
				       (encrypt_len_incl_iv - accel->iv_len),
				       crstart, 
				       (encrypt_len_incl_iv - accel->iv_len),
				       0, 0, CGX_DECRYPT_D, chunk_sz))
	      != UDM_DRVSTAT_SUCCESS)	
	    {
              SSH_DEBUG(SSH_D_FAIL, ("udm_crypto_sync operation failed"));
              goto fail;
	    }
	}
    }
  else
    {
      if (accel->for_mac)
        if (!ssh_hwaccel_perform_ipsec_mac(accel, packet, mac_start_offset,
					   mac_len, icv_offset))
	  {
	    SSH_DEBUG(SSH_D_FAIL, ("mac operation failed"));
	    goto fail;
	  }
    }
  
  memcpy(accel->iv, packet + (packet_len - accel->iv_len), accel->iv_len);
  
#ifndef SSH_SAFENET_PACKET_IS_DMA
  if (!ssh_interceptor_packet_copyin(pp, 0, packet, packet_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("copyin failed, dropping packet"));
      pp = NULL;
      goto fail;
    }
  ssh_free(packet);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  (*completion)(pp, SSH_HWACCEL_OK, completion_context);
  return;

 fail:
  if (pp != NULL)
    ssh_interceptor_packet_free(pp);
#ifndef SSH_SAFENET_PACKET_IS_DMA
  ssh_free(packet);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  (*completion)(NULL, SSH_HWACCEL_CONGESTED, completion_context);
  return;
}


/*  Performs hardware-accelerated compression/decompression.  This
    function compresses/decompresses a portion of `pp' as specified by
    the hardware acceleration context.  */

void ssh_hwaccel_perform_ipcomp(SshHWAccel accel,
                                SshInterceptorPacket pp,
                                size_t offset,
                                size_t len,
                                SshHWAccelCompletion completion,
                                void *completion_context)
{
  SSH_NOTREACHED;
}


/* Allocates a hardware acceleration context for combination of IPsec
   transformations. The `flags' determines whether the instance is to
   be used for decapsulation or encapsulation, as well as the types of
   transforms to perform. Ther order of transforms is fixed, in
   decryption order AH->ESP->IPcomp->IPIP (and reverse encryption order).
   The {ah,esp,ipcomp,ipip}_ parameters should be only used
   if the relevant bit is set in the `flags' bitmask.
*/
SshHWAccel
ssh_hwaccel_alloc_combined(SshInterceptor interceptor,

                           SshUInt32 requested_ops,
			   SshUInt32 *provided_ops,

                           SshUInt32 ah_spi,
                           const char *ah_macname,
                           const unsigned char *ah_authkey,
                           size_t ah_authkeylen,

                           SshUInt32 esp_spi,
                           const char *esp_macname,
                           const char *esp_ciphname,
                           const unsigned char *esp_authkey,
                           size_t esp_authkeylen,
                           const unsigned char *esp_ciphkey,
                           size_t esp_ciphkeylen,
                           const unsigned char *esp_iv,
                           size_t esp_ivlen,

                           SshUInt32 ipcomp_cpi,
                           const char *ipcomp_compname,

                           SshIpAddr ipip_src, SshIpAddr ipip_dst,
                           SshUInt32 seq_num_low,
                           SshUInt32 seq_num_high,
			   SshUInt16 natt_remote_port,
			   const unsigned char *natt_oa_l,
			   const unsigned char *natt_oa_r)
{
  *provided_ops = 0;
  return NULL;
}

void ssh_hwaccel_perform_combined(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  SshHWAccelCompletion completion,
                                  void *completion_context)
{
  SSH_NOTREACHED;
}

void ssh_hwaccel_free_combined(SshHWAccel accel)
{
  SSH_NOTREACHED;
}

void ssh_hwaccel_perform_modp(const SshHWAccelBigInt b,
                              const SshHWAccelBigInt e,
                              const SshHWAccelBigInt m,
                              SshHWAccelModPCompletion callback,
                              void *callback_context)
{
  (*callback)(NULL, callback_context);
}


void ssh_hwaccel_get_random_bytes(size_t bytes_requested,
                                  SshHWAccelRandomBytesCompletion callback,
                                  void *callback_context)
{
  (*callback)(NULL, 0, callback_context);
}

Boolean ssh_safenet_device_init(SshWludmDevice device)
{
  INIT_BLOCK initblock;
  int status;

  /* Uninitialize the deivce before testing for PCI swapping */
  udm_device_uninit(device->device_number);

  /* Setup the initialization block and initialize */
  memset (&initblock, 0, sizeof(initblock));
  status = udm_device_init(device->device_number, &initblock);

  return (status == UDM_DRVSTAT_SUCCESS);
}


/* Dummy stubs to enable interceptor module to work properly. */
Boolean ssh_hwaccel_init()
{
  SshWludmDevice device;
  UDM_DEVICEINFO device_info;
  UINT32 vers;
  int status;
  UINT32 dev_no = 0;

  SSH_DEBUG(SSH_D_HIGHOK, ("Hardware acceleration initialization entered"));

  /* Get driver version. */
  status = udm_driver_version(&vers);

  if (status != UDM_DRVSTAT_SUCCESS)
    goto fail;
  
  /* Get device info and store the number of devices */
  status = udm_device_info(dev_no, &device_info);
  
  if (status != UDM_DRVSTAT_SUCCESS)
    goto fail;

  /* We support the following device types at present */
  device = &devices[0];

  device->device_number = dev_no;
  memcpy(&device->device_info, &device_info, sizeof(device_info));


  if (!ssh_safenet_device_init(device))
    goto fail;

  /* Insert the device to the global list */
  device->next = wludm_devices;
  wludm_devices = device;
  
  /* printk("Wireless UDM Device initialized Successfully \n"); */
  return TRUE;
 fail:

  printk("Hardware acceleration initialization failed, using software "
	 "crypto\n");
  ssh_hwaccel_uninit();
  return FALSE;

}	  
	
void ssh_hwaccel_uninit()
{
  SshWludmDevice device;

  device = wludm_devices;
  /*  printk("Hardware acceleration WLUDM uninitialized\n");   */
  udm_device_uninit(device->device_number);
  memset(&device, 0, sizeof(device)); 

  wludm_devices = NULL;
}

const char *ssh_safenet_get_printable_status(int driver_status)
{
  switch (driver_status)
    {
    case UDM_DRVSTAT_SUCCESS:
      return "The operation was successful";
    case UDM_DRVSTAT_COMMAND_INVALID:
      return "The command was invalid";
    case UDM_DRVSTAT_DEVICE_INVALID :
      return "Invalid device number specified";
    case UDM_DRVSTAT_DEVICE_NOT_FOUND :
      return "Device not found";
    case UDM_DRVSTAT_DEVICE_NOT_INIT :
      return "Device not initialized";
    case UDM_DRVSTAT_CDR_FULL :
      return "CDR queue full";
    case UDM_DRVSTAT_PDR_FULL :
      return "PDR command queue full";
    case UDM_DRVSTAT_MALLOC_ERR :
      return "No memory available";
    case UDM_DRVSTAT_UPLOAD_ERR :
      return "Device upload error";
    case UDM_DRVSTAT_INIT_FAIL :
      return "Device initialization failed";
    case UDM_DRVSTAT_CDR_EMPTY :
      return "CDR queue empty";
    case UDM_DRVSTAT_PDR_EMPTY :
      return "PDR queue  empty";
    case UDM_DRVSTAT_GDR_FULL :
      return "GDR queue full";
    case UDM_DRVSTAT_IOCTL_ERR :
      return "IOCTL error";
    case UDM_DRVSTAT_USERMODE_API_ERR :
      return "Usermode API error";
    case UDM_DRVSTAT_BAD_PARAM_CDR_BUSID :
      return "Bad CDR Busid parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_ENTRIES :
      return "Bad CDR entry parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_POLL_DELAY :
      return "Bad CDR poll delay specified";
    case UDM_DRVSTAT_BAD_PARAM_CDR_DELAY_AFTER :
      return "Bad CDR delay after parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_INT_COUNT :
      return "Bad CDR count int parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_BUSID :
      return "Bad PDR busid";
    case UDM_DRVSTAT_BAD_PARAM_PDR_ENTRIES :
      return "Bad number of PDR entries";
    case UDM_DRVSTAT_BAD_PARAM_PDR_POLL_DELAY :
      return "Bad PDR poll delay";
    case UDM_DRVSTAT_BAD_PARAM_PDR_DELAY_AFTER :
      return "Bad PDR delay after parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_INT_COUNT :
      return "Bad PDR int count parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_OFFSET :
      return "Bad PDR offset";
    case UDM_DRVSTAT_BAD_PARAM_SA_BUSID :
      return "Bad SA busid";
    case UDM_DRVSTAT_BAD_PARAM_SA_ENTRIES :
      return "Bad number of SA entries";
    case UDM_DRVSTAT_BAD_PARAM_SA_CONFIG :
      return "Bad SA configuration parameter";
    case UDM_DRVSTAT_BAD_PARAM_PAR_SRC_BUSID :
      return "Bad PAR source busid";
    case UDM_DRVSTAT_BAD_PARAM_PAR_SRC_SIZE :
      return "Bad PAR source size";
    case UDM_DRVSTAT_BAD_PARAM_PAR_DST_BUSID :
      return "Bad PAR desitination busid";
    case UDM_DRVSTAT_BAD_PARAM_PAR_DST_SIZE :
      return "Bad PAR destination size";
    case UDM_DRVSTAT_BAD_PARAM_PAR_CONFIG :
      return "Bad configuration parameter";
    case UDM_DRVSTAT_INTERNAL_ERR :
      return "Internal error";
    default:
      return "Unknown Status";
    }
}


