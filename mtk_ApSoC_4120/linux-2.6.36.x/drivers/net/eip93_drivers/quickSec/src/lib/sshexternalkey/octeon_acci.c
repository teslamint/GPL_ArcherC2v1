/*
  Copyright:
          Copyright (c) 2006 SFNT Finland Oy.
                  All rights reserved.

  All rights reserved.

  File: octeon_acci.c
  
  Internal functions for accelerator on Octeon  
*/ 

#include "sshincludes.h"
#include "octeon_acci.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_CAVIUM_OCTEON

#define SSH_DEBUG_MODULE "SshEKOcteonAcci"

#define RNM_CONTROL_STATUS_REGISTER_ADDRESS 0x0001180040000000ull
#define RNG_LOAD_ADDRESS 0x1400000000000ull


typedef union OcteonRNMControlStatusRec
{
  SshUInt64 status_register;
  struct
    {
#ifdef WORDS_BIGENDIAN
      SshUInt64 reserved :60;
      SshUInt64 rng_reset :1;
      SshUInt64 rnm_reset :1;
      SshUInt64 rng_enbl :1;   /* Enable RNG */
      SshUInt64 ent_enbl :1;   /* Enable Entropy */
#else /* WORDS_BIGENDIAN */
      SshUInt64 ent_enbl :1;
      SshUInt64 rng_enbl :1;
      SshUInt64 rnm_reset :1;
      SshUInt64 rng_reset :1;
      SshUInt64 reserved : 60;
#endif /* WORDS_BIGENDIAN */
    }s;
}OcteonRNMControlStatusStruct;


void ssh_octeon_init_rng(void)
{
  OcteonRNMControlStatusStruct reg;

  /* Set the msb to 1 to signify physical address */

  volatile SshUInt64 *rng = (volatile SshUInt64 *)
                           (RNM_CONTROL_STATUS_REGISTER_ADDRESS | 1LL << 63); 
  
  reg.status_register = 0; /* Clear all bits */
  reg.s.rng_enbl = 1; /* Enable RNG */
  reg.s.ent_enbl = 1; /* Enable source of entropy */
  
  *rng = reg.status_register;

  SSH_DEBUG( SSH_D_LOWOK, ("Successfully initialized Octeon RNG"));
}


Boolean ssh_octeon_is_rng_initialized(void)
{
  OcteonRNMControlStatusStruct reg;

  /* Set the msb to 1 to signify physical address */
  volatile SshUInt64 *rng = (volatile SshUInt64 *)
                 (RNM_CONTROL_STATUS_REGISTER_ADDRESS | 1ll << 63) ; 

  reg.status_register = *rng;

  return reg.s.rng_enbl;

}

/* Gets n number of random bytes. It is fatal to call this function if 
  RNG is not enabled. */

SshUInt32 ssh_octeon_get_random( unsigned char * buffer, SshUInt32 len)
{
/* RNG Core generates 64 bit random number every 91 cycle.*/
  SshUInt32 length = 0;
  unsigned char * data = buffer;
  SshUInt64 temp;


  SSH_ASSERT(ssh_octeon_is_rng_initialized());
  for (length = len ; length >= 8; length -= 8, data += 8)
    {
      *(SshUInt64 *)data = *(SshUInt64 *)(RNG_LOAD_ADDRESS | 1ll << 63); 
    }
  if (length)
    {
      temp = *(volatile SshUInt64 *)(RNG_LOAD_ADDRESS | 1ll << 63); 
      memcpy(data, &temp, length);
    }
  return len;
}
#endif /* ENABLE_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
