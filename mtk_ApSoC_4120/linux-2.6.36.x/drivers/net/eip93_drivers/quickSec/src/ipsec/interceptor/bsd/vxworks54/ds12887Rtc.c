/* ds12887Rtc.c - DS12887 Rea-Time Clock chip driver */

/* Copyright 1997 Wind River Systems Inc. */

/*
modification history
--------------------
01c,01may97,leo  initial version
*/

/*
DESCRIPTION
This module is to be used by including it from <target>/sysLib.c file,
it adds two functions to handle to RTC chip for the BSP.
This driver is written for the Dallas Semiconductor 12887,
but should work well with any PC motherboard, with a compatible chip.

The date and time format here is compatible with ANSI time,
and one should define INCLUDE_RTC in <target>config.h
to enable these functions.

Although it is much easier to use this chip in binary mode,
this driver uses it in BCD mode, so that the time and date
settings are compatible with the BIOS and MS-DOS.

*/


#include "vxWorks.h"
#include "time.h"
#include "intLib.h"
#include "sysLib.h"

/* real time clock (RTC), from pcPentium/pc.h, check these on your <arch> */
#define RTC_INDEX               0x70
#define RTC_DATA                0x71

/* macro to check that <v> is between <l> and <h> inclusive range */
#define CHECK_RANGE(v,l,h)      (((v)>=(l))&&((v)<=(h)))

/* Macros to convert 2-digit BCD into binary and vice versa */
#define BIN2BCD(b)      (((b)%10) | (((b)/10)<<4))
#define BCD2BIN(b)      (((b)&0xf) + ((b)>>4)*10)

/* RTC register access, macros should be defined for a particular BSP */
#if     CPU_FAMILY==I80X86

#define RTC_REG_SET(reg,val)    \
        (sysOutByte(RTC_INDEX,(reg)),sysOutByte(RTC_DATA,(val)))
#define RTC_REG_GET(reg) (sysOutByte(RTC_INDEX,(reg)),sysInByte(RTC_DATA))

#else /* CPU_FAMILY==I80X86 */
#ifndef RTC_JMP
#define RTC_JMP         1
#endif

/* real time clock (RTC) base, check these on your <arch> */
#ifndef RTC_BASE
#define RTC_BASE        0x800000
#endif

#define RTC_REG(o)              ((volatile u_char *)(RTC_BASE+(o)*RTC_JMP))
#define RTC_REG_SET(reg,val)    (*RTC_REG(reg) = (val))
#define RTC_REG_GET(reg)        (*RTC_REG(reg))



#define RTC_REG_GET(reg)        1
#endif /* CPU_FAMILY==I80X86 */

/******************************************************************************
*
* sysRtcGet - get the current date and time from a Real Time Clock chip
*
* The values are returned in a ANSI time structure.
* During initialization phase, the POSIX clock of the system is
* set according to the Real Time Clock time and date, thus
* it is recommended to use the POSIX functions and avoid calling
* this function from the application software,
* to acheive similar results but with greater portability.
*
* NOTE: Interrupts are locked during reading of the values from the chip.
*
* RETURNS: OK or ERROR
*
* SEE ALSO
* clockLib(), ansiTime
*
*/

STATUS sysRtcGet
    (
    struct tm *tm
    )
    {
    FAST int ipl ;
    FAST count = 50;

    ipl = intLock();

    /* wait until registers update is done, then we got 244 us
     * to read the regs without loosing sanity
     */
    while ((count--) && (RTC_REG_GET(0x0a) & 0x80));

    tm->tm_hour = RTC_REG_GET( 0x04);   /* get BCD regs as is */
    tm->tm_min  = RTC_REG_GET( 0x02);   /* while ints are off, */
    tm->tm_sec  = RTC_REG_GET( 0x00);   /* and decode later */
    tm->tm_mon  = RTC_REG_GET( 0x08);
    tm->tm_mday = RTC_REG_GET( 0x07);
    tm->tm_year = RTC_REG_GET( 0x09);
    tm->tm_wday = RTC_REG_GET( 0x06);

    intUnlock(ipl);


    /* corrections - all registers are BCD, we need them in binary */
    tm->tm_hour = BCD2BIN( tm->tm_hour );
    tm->tm_min  = BCD2BIN( tm->tm_min  );
    tm->tm_sec  = BCD2BIN( tm->tm_sec  );
    tm->tm_mon  = BCD2BIN( tm->tm_mon  );
    tm->tm_mday = BCD2BIN( tm->tm_mday );
    tm->tm_year = BCD2BIN( tm->tm_year );
    tm->tm_wday = BCD2BIN( tm->tm_wday );

    /* corrections -  some fields range is defined differently */
    tm->tm_mon -- ;     /* chip does 1-12, POSIX needs 0-11 */
    tm->tm_wday -- ;    /* chip does 1-7, POSIX needs 0-6 */

    /* corrections - handle year after y2k */
    if (tm->tm_year < 80)
        tm->tm_year += 100 ;

    /* These fields are unknown, filled with 0 */
    tm->tm_yday = 0;    /* days since January 1         - [0, 365] */
    tm->tm_isdst= 0;    /* Daylight Saving Time flag */

    return OK ;
    }

/******************************************************************************
*
* sysRtcSet  - Set the time and date into the RTC chip
*
* NOTE
* Setting the time is done with interrupts locked, but it is expected
* to be called rarely.
*
* RETURNS: OK or ERROR if values are out of range.
*/

STATUS sysRtcSet
    (
    const struct tm *timedate
    )
    {
    struct tm t1 = * timedate ;
    FAST struct tm *tm = &t1 ;          /* make a local copy of the argument */
    FAST count = 50;
    FAST int ipl ;

    /* Check value ranges */

    if (!CHECK_RANGE( tm->tm_sec,  0, 59)) return ERROR ;
    if (!CHECK_RANGE( tm->tm_min,  0, 59)) return ERROR ;
    if (!CHECK_RANGE( tm->tm_hour, 0, 23)) return ERROR ;
    if (!CHECK_RANGE( tm->tm_mday, 1, 31)) return ERROR ;
    if (!CHECK_RANGE( tm->tm_mon , 0, 11)) return ERROR ;

    /* correction - for y2k */
    if (tm->tm_year > 99)
        tm->tm_year -= 100 ;

    if (!CHECK_RANGE( tm->tm_year, 0, 99)) return ERROR ;

    /* corrections - convert to BSD and add offset where needed. */
    tm->tm_hour = BIN2BCD( tm->tm_hour ); 
    tm->tm_min  = BIN2BCD( tm->tm_min ); 
    tm->tm_sec  = BIN2BCD( tm->tm_sec ); 
    tm->tm_mon  = BIN2BCD( tm->tm_mon+1 ); 
    tm->tm_mday = BIN2BCD( tm->tm_mday ); 
    tm->tm_year = BIN2BCD( tm->tm_year ); 
    tm->tm_wday = BIN2BCD( tm->tm_wday+1 ); 

    ipl = intLock();

    /* wait until registers update is done, then we got 244 us
     * to read the regs without loosing sanity
     */
    while ((count--) && (RTC_REG_GET(0x0a) & 0x80));
    
    RTC_REG_SET( 0x04, tm->tm_hour );
    RTC_REG_SET( 0x02, tm->tm_min );
    RTC_REG_SET( 0x00, tm->tm_sec );
    RTC_REG_SET( 0x08, tm->tm_mon );
    RTC_REG_SET( 0x07, tm->tm_mday);
    RTC_REG_SET( 0x09, tm->tm_year);
    RTC_REG_SET( 0x06, tm->tm_wday);

    intUnlock(ipl);

    return OK ;
    }

/******************************************************************************
*
* sysRtcInit - initialize the RTC chip
*
* This function should called from sysHwInit2(). With this particular
* device, there is nothing we need to do here.
*
*/
STATUS sysRtcInit ( void)
    {
    /* turn the oscilator on, just in case */
    RTC_REG_SET( 0x0a, 0x20 );
    RTC_REG_SET( 0x0b, 0x02 );  /* set 24-hr & BCD modes */
    return OK ;
    }

/******************************************************************************
*
* sysRtcShutdown - put the RTC chip in to sleep mode
*
* The sleep mode is designed to save on battery life during inactive
* storage of the equipment. During this time the date & time do not
* progress.
*
*/

void sysRtcShutdown(void)
    {
    RTC_REG_SET( 0x0a, 0x00 );
    }

/* End Of File */
