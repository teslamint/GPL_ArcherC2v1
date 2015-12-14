/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshutil
 *
 *        Creation          : 06:49 Aug 20 1996 kivinen
 *        Last Modification : 13:53 Sep  8 2006 kivinen
 *        Version           : 1.10
 *        
 *
 *        Description       : Replacement functions for strcasecmp
 *
 */

#include "sshincludes.h"

int strcasecmp(const char *s1, const char *s2)
{
  while (*s1 && (*s1 == *s2 ||
		 tolower(*(unsigned char *)s1) ==
		 tolower(*(unsigned char *)s2)))
    {
      s1++;
      s2++;
    }
  return (int) *(unsigned char *)s1 - (int) *(unsigned char *)s2;
}
