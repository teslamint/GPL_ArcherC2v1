/*

  t-c64.c 

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved


  Created Thu May 11 09:39:30 2000. 

 Test program for 64 bit integers and 64 bit unsigned integers. 
  
*/

#include "sshincludes.h"

int main()
{
  SshUInt64 max_ui = SSH_C64(18446744073709551615); /* 2^64 - 1 */
  SshInt64 max_i = SSH_C64(9223372036854775807);  /* (2^64) / 2 - 1 */

  if (max_i * 2 + 1 != max_ui)
    ssh_fatal("64-bit integer comparison error. ");

  return 0;
}

