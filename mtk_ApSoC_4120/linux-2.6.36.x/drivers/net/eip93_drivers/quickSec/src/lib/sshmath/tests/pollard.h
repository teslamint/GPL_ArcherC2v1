/*

  pollard.h

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Fri Jan 14 21:39:56 2000.

  */

#ifndef SSH_POLLARD_H
#define SSH_POLLARD_H

/* Pollard rho method of factorization. Good for finding small (about 10 digit)
   factors.

   factor       the factor that is found (if search fails then it is not set)
   composite    the integer to be factored
   steps        the number of steps allowed for the rho method (good value
                could be in range of 16,000,000).
   coefficient  the constant coefficient of the polynomial x^2 + c. Usually
                1 or 3. If algorithm fails then running again with another
                constant might still yield a result.

   Returns a boolean value indicating whether the algorithm succeeded
   or failed.  Failure indicates that a factor was not found.
   */

Boolean ssh_pollard_rho(SshMPInteger factor, SshMPIntegerConst composite,
                        SshWord steps, SshWord coefficient);


#endif /* SSH_POLLARD_H */
