/*
  fft.h

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
                All rights reserved.

  Implementation of complex FFT. This version is a children of the
  version by J.G.G. Dobbe in DDJ Feb '95. 
*/
#ifndef FFT_H
#define FFT_H

/* FFT routines.
   Input:
     double *re  - table of real parts of the complex input array
     double *im  - table of imaginary parts of the complex input array
     unsigned int exp - 2^exp is the length of the complex input array
     int inv     - if 0 then FFT if 1 then inverse FFT */
void fft(double *re, double *im, unsigned int exp, int inv);

#endif /* FFT_H */
