/*
    Copyright (c) 2000, 2003	    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL		

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


/*  Just returns current time as double, with most possible precision...  */

double get_time (void) {
	struct timeval tv;
	double d;

	gettimeofday (&tv, NULL);

	d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;

	return d;
}
