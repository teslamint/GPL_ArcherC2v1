/*
** $Id: //WIFI_SOC/release/SDK_4_1_0_0/source/linux-2.6.21.x/drivers/char/pcm/si321x/proslic_api/proslic_timer_intf.h#1 $
**
** system.h
** System specific functions header file
**
** Author(s): 
** laj
**
** Distributed by: 
** Silicon Laboratories, Inc
**
** File Description:
** This is the header file for the system specific functions like timer functions.
**
** Dependancies:
** proslic_datatypes.h
** definition of timeStamp structure
**
*/


#ifndef TIMER_INTF_H
#define TIMER_INTF_H

/*
** System time delay function pointer 
*/
typedef int (*system_delay_fptr) (void *hTimer, int timeInMs);

/*
** System time elapsed function pointer 
*/
typedef int (*system_timeElapsed_fptr) (void *hTimer, void *startTime, int *timeInMs);

typedef int (*system_getTime_fptr) (void *hTimer, void *time);



#endif
/*
** $Log: proslic_timer_intf.h,v $
** Revision 1.5  2008/01/21 21:19:03  lajordan
** renaming to lower case
**
** Revision 1.3  2007/02/21 16:55:06  lajordan
** moved function prototypes out
**
** Revision 1.2  2007/02/16 23:54:56  lajordan
** no message
**
** Revision 1.1.1.1  2006/07/13 20:26:08  lajordan
** no message
**
** Revision 1.1  2006/07/07 21:39:22  lajordan
** no message
**
** Revision 1.1.1.1  2006/07/06 22:06:23  lajordan
** no message
**
** Revision 1.1  2006/06/21 22:42:26  laj
** new api style
**
**
*/
