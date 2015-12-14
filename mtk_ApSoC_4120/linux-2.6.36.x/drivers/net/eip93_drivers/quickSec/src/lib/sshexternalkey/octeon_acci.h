
/*
  Copyright:
          Copyright (c) 2006 SFNT Finland Oy.
                  All rights reserved.

  All rights reserved.

  File: octeon_acci.h
  
  Internal functions for accelerator on Octeon  
*/ 

#ifndef OCTEON_ACC_I_H
#define OCTEON_ACC_I_H

void ssh_octeon_init_rng(void);
Boolean ssh_octeon_is_rng_initialized(void);
SshUInt32 ssh_octeon_get_random( unsigned char * buffer, SshUInt32 len);
#endif /* OCTEON_ACC_I_H */
