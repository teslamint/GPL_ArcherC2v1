/*

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
	  All rights reserved.

  Calendar time retrieval and manipulation.

*/

#include "sshincludes.h"
#include "sshgetput.h"
#undef time

#define SSH_DEBUG_MODULE "SshTime"

/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
SshTime ssh_time(void)
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;

  /* This can not fail */
  gettimeofday(&tv, NULL);
  return (SshTime)tv.tv_sec;
#else
  return (SshTime)(time(NULL));
#endif
}

/* Returns seconds and microseconds to 'time' from epoch
   "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void ssh_get_time_of_day(SshTimeValue tptr)
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;

  /* This can not fail */
  gettimeofday(&tv, NULL);

  tptr->seconds = (SshInt64) tv.tv_sec;
  tptr->microseconds = (SshInt64) tv.tv_usec;
  return;
#else
  tptr->seconds = (SshInt64) (time(NULL));
  tptr->microseconds = (SshInt64) 0;
  return;
#endif
}


/* eof (sshtime.c) */
