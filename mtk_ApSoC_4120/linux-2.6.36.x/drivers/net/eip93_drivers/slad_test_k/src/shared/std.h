/*h*
*
* File:            std.h
*
* Standard header, project wide definitions and declarations.


     Copyright 2007-2010 AuthenTec B.V.

*
*
* Edit History:
*
*Initial revision
* Created.
*
*/

#ifndef _STD_H_
#define _STD_H_   1


#if defined (CGX_BUILD)
#ifndef __OPTIONS_H
                /* verify that options.h has been included */
                /* cause warning to draw attention to this
                egregious omission */
#error CGX builds require that "options.h" be included prior to "std.h".
#endif
#endif


/**************************************************************************
* Platform-dependent Definitions.
* You must externally define one of the SLAD_PLATFORM_xxx defs. This is
* usually done on your compiler command-line or in your project settings.
***************************************************************************/

#if defined (SLAD_PLATFORM_ADAM2)

        /* Legacy definitions. */
#define GENERIC_CGX                1
#define ADAM2                    1

#include <adam2.h>

        /* Are we big or little endian? */
#if defined (_BYTE_ORDER)
#if (_BYTE_ORDER == _BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#endif
#elif defined (EB) || defined (MIPSEB) || defined (__MIPSEB__)
#define SLAD_BIG_ENDIAN
#elif defined (EL) || defined (MIPSEL) || defined (__MIPSEL__)
#else
#error Unable to determine endianness [Adam2]
#endif

typedef unsigned char BYTE;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16)        memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)        memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)        memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)        memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)        memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)        memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_ADI2181)

        /* Legacy definitions. */
#define GENERIC_CGX                1
#define ADI2181                    1

        /* endian is a problem on 214x. there is no byte addressability, but
           CGX on 214x has assumed bytes in little endian order within words,
           EG in 0xHHLL, LL is considered byte 0. Data from a host is typically
           passed across the PCI bus unchanged.

           long integers are stored by compiler convention in big endian order,
           i.e., in 0x12345678, 0x1234 is in word 0.
         */

#undef SLAD_BIG_ENDIAN

typedef unsigned short UINT16;
typedef unsigned long UINT32;

typedef unsigned short BYTE;
typedef signed short int INT16;
typedef unsigned short BOOL;

typedef long int INT32;

typedef UINT16 **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    pm a

extern void memcpyy (UINT16 * dest, UINT16 * src, UINT16 num_wds);
extern void memsett (UINT16 * buf, UINT16 val, UINT16 num_wds);
extern INT16 memcmpp (INT16 * s1, INT16 * s2, UINT16 num_dwds);
#define    memcpy16(d, s, c16)  memcpyy((UINT16*)(d), (UINT16*)(s), (c16))
#define    memcpy8(d, s, c8)    memcpyy((UINT16*)(d), (UINT16*)(s), ((c8)>>1))
#define    memset16(d, c, c16)  memsett((UINT16*)(d), (UINT16)(c), (c16))
#define    memset8(d, c, c8)    memsett((UINT16*)(d), (UINT16)(c), ((c8)>>1))
#define    memcmp16(d, s, c16)  memcmpp((UINT16*)(d), (UINT16*)(s), (c16))
#define    memcmp8(d, s, c8)    memcmpp((UINT16*)(d), (UINT16*)(s), ((c8)>>1))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)
#define byte_sizeof(x)            (2*sizeof(x))

extern BOOL GetSerialNumber (UINT16 *);

#elif defined (SLAD_PLATFORM_ARGUS)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#include <stdlib.h>

        /* Are we big or little endian? */
#if defined (__BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef signed int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)     memcpy(a,b,c)
#define    memsett(a,b,c)     memset(a,b,c)
#define    memcmpp(a,b,c)     memcmp(a,b,c)
#define    memcpy16(d, s, c16) memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)   memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16) memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)   memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16) memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)   memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)         sizeof(x)

#elif defined (SLAD_PLATFORM_ATMOS)

        /* Legacy definitions. */
#define GENERIC_CGX                1

        /* Are we big or little endian? */
#if (_BYTE_ORDER == _BIG_ENDIAN)
                /* Actually, we're big-endian, but everything seems to
                 work when we compile for little-endian. */
                /* I think this is a peculiarity of the ARM processor,
                which treats data bit 0 as the msb. */
                /* #define SLAD_BIG_ENDIAN */
#undef SLAD_BIG_ENDIAN
#else
#undef SLAD_BIG_ENDIAN
#endif

typedef signed short INT16;
typedef unsigned short UINT16;
typedef signed int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_C55)

        /* Legacy definitions. */
#define GENERIC_CGX                1
#define TARGET_C55_DSP            1

typedef unsigned short UINT16;
typedef unsigned long UINT32;

typedef unsigned short BYTE;
typedef signed short int INT16;
typedef unsigned short BOOL;

typedef long int INT32;

typedef unsigned short **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

        /*
           rts55(x) rtl fcns use word counts - not byte counts
           sizeof() yields size in words.
           Therefore, memsett(x, v, sizeof(x)) is platform independent.
         */
#define    memcpyy(a,b,c)        memcpy(a,b,c)
#define    memsett(a,b,c)        memset(a,b,c)
#define    memcmpp(a,b,c)        memcmp(a,b,c)
#define    memcpy16(d, s, c16)   memcpy((UINT16*)(d), (UINT16*)(s), (c16))
#define    memcpy8(d, s, c8)     memcpy((UINT16*)(d), (UINT16*)(s), ((c8)>>1))
#define    memset16(d, c, c16)   memset((UINT16*)(d), (UINT16)(c), (c16))
#define    memset8(d, c, c8)     memset((UINT16*)(d), (UINT16)(c), ((c8)>>1))
#define    memcmp16(d, s, c16)   memcmp((UINT16*)(d), (UINT16*)(s), (c16))
#define    memcmp8(d, s, c8)     memcmp((UINT16*)(d), (UINT16*)(s), ((c8)>>1))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)
#define byte_sizeof(x)            (2 * sizeof (x))

#elif defined (SLAD_PLATFORM_INTEGRITY)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#include <INTEGRITY_types.h>

        /* Are we big or little endian? */
#include <endian.h>
#if defined (__BigEndian) || defined (BigEndian)
#define SLAD_BIG_ENDIAN
#elif defined (__LittleEndian) || defined (LittleEndian)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [Integrity]
#endif

#define BOOL                    Boolean
#define BYTE                    UINT1
#define INT16                    INT2
#define UINT16                    UINT2
#define INT32                    INT4
#define UINT32                    UINT4

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16)        memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)        memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)        memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)        memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)        memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)        memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_LINUX)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#ifdef MODULE
#include <linux/types.h>
#else
#include <asm/types.h>
#define max(A, B)            ((A) > (B) ? A : B)
#define min(A, B)            ((A) < (B) ? A : B)
#endif

        /* Are we big or little endian? */
#ifdef MODULE
#include <asm/byteorder.h>
#if defined (__BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif defined (__LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [Linux]
#endif
#else
#include <endian.h>
#if (__BYTE_ORDER == __BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif (__BYTE_ORDER == __LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [Linux]
#endif
#endif

typedef int BOOL;
#define BYTE                    __u8
#define INT16                    __s16
#define UINT16                    __u16
#define INT32                    __s32
#define UINT32                    __u32

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16)        memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)        memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)        memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)        memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)        memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)        memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_NETBSD)

        /* Legacy definitions. */
#define GENERIC_CGX                1
#include <sys/types.h>


/* Kernel and driver code will have min/max defined, user apps will not. */
#ifndef _KERNEL
#define max(A, B)            ((A) > (B) ? A : B)
#define min(A, B)            ((A) < (B) ? A : B)
#endif

        /* Are we big or little endian? */
#include <sys/endian.h>
#if (_BYTE_ORDER==_BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif (_BYTE_ORDER==_LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [NETBSD]
#endif


typedef int BOOL;
#define BYTE                    uint8_t
#define INT16                    int16_t
#define UINT16                    uint16_t
#define INT32                    int32_t
#define UINT32                    uint32_t

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#elif defined (SLAD_PLATFORM_FREEBSD)

        /* Legacy definitions. */
#define GENERIC_CGX                1
#include <sys/types.h>


/* Kernel and driver code will have min/max defined, user apps will not. */
#ifndef _KERNEL
#define max(A, B)            ((A) > (B) ? A : B)
#define min(A, B)            ((A) < (B) ? A : B)
#endif


        /* Are we big or little endian? */
#include <sys/endian.h>

#if (BYTE_ORDER==BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif (BYTE_ORDER==LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [FREEBSD]
#endif


typedef int BOOL;
#define BYTE                    uint8_t
#define INT16                    int16_t
#define UINT16                    uint16_t
#define INT32                    int32_t
#define UINT32                    uint32_t

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)           memcpy(a,b,c)
#define    memsett(a,b,c)           memset(a,b,c)
#define    memcmpp(a,b,c)           memcmp(a,b,c)
#define    memcpy16(d, s, c16)      memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)        memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)      memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)        memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)      memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)        memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#elif defined (SLAD_PLATFORM_SKELETON)

 /*
    This is not a "real" platform, but a generic example we
    call the Skeleton.
    This section is here only to allow the skeleton code to
    properly compile.
    The skeleton platform is a non-ported code example which
    customers can
    use as a starting point when doing their own porting
    of the CGX/UDM code.
  */

        /* Legacy definitions. */
#define GENERIC_CGX                1

        /*
           Are we big or little endian?
           (This is just our best shot at this determination,
           since this is not a real platform.
         */
#if defined (BIG_ENDIAN) ||
defined (_BIG_ENDIAN) || defined (__BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#endif

typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef signed int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_SOLARIS)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#include <sys/inttypes.h>

/* Kernel and driver code will have min/max defined, user apps will not. */
#ifndef _KERNEL
#define max(A, B)            ((A) > (B) ? A : B)
#define min(A, B)            ((A) < (B) ? A : B)
#endif

        /* Are we big or little endian? */
#include <sys/isa_defs.h>
#if defined (_BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif defined (_LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [Solaris]
#endif

typedef int BOOL;
#define BYTE                    uint8_t
#define INT16                    int16_t
#define UINT16                    uint16_t
#define INT32                    int32_t
#define UINT32                    uint32_t

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_SYMBIAN)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#include <stddef.h>             /* needed to define size_t */
#include <string.h>             /* needed for memcpy, etc. */

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef long INT32;
typedef unsigned long UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       emcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)
#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_TNT)

        /* Legacy definitions. */
#define GENERIC_CGX                1

        /* All our currently supported Phar Lap
        TNT platforms are little endian. */
        /* This may change at any moment! */
#undef SLAD_BIG_ENDIAN

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef signed int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16) memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)   memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16) memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)   memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16) memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)   memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_VXWORKS)

        /* Legacy definitions. */
#define GENERIC_CGX                1

#include <vxWorks.h>

        /* Are we big or little endian? */
#if (_BYTE_ORDER == _BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif (_BYTE_ORDER == _LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [VxWorks]
#endif

typedef unsigned char BYTE;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16)       \
     memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)       \
     memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)     \
       memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)       \
     memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)       \
     memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)       \
     memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_EPI)

        /* Legacy definitions. */
#define GENERIC_CGX                1

typedef unsigned char BYTE;
typedef unsigned char **MEMCPY_TYPE;
typedef int BOOL;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef long INT32;
typedef unsigned long UINT32;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)            memcpy(a,b,c)
#define    memsett(a,b,c)            memset(a,b,c)
#define    memcmpp(a,b,c)            memcmp(a,b,c)
#define    memcpy16(d, s, c16)      \
      memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)       \
 memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)      \
  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)      \
  memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)       \
 memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)      \
  memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)
#define byte_sizeof(x)             sizeof(x)

#elif (defined (SLAD_PLATFORM_WINNT) \
         || defined (SLAD_PLATFORM_WINNT_DRIVER) || \
         defined (SLAD_PLATFORM_WIN2K_DRIVER)|| \
          defined (SLAD_PLATFORM_WINCE))

/* There are minor diffs between NT driver and application (non-driver). */

#if (defined (SLAD_PLATFORM_WINNT) || defined (SLAD_PLATFORM_WINCE))
#include <windows.h>            /* application */
#else
#include <ntddk.h>              /* driver */
#endif

#if defined (CAPI) && defined (_WIN32_WCE)
#include "wincrypt.h"
#endif

/* All our currently supported Windows platforms are
little endian. */
/* This may change at any moment! */

#undef SLAD_BIG_ENDIAN

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
#if ((_MSC_VER < 1200) ||
 defined (SLAD_PLATFORM_WINNT_DRIVER))
/* if below version 6.0, or driver */
typedef long INT32;
typedef unsigned long UINT32;
#endif

typedef unsigned char **MEMCPY_TYPE;

#define PM(a)                    a

#define    memcpyy(a,b,c)         memcpy(a,b,c)
#define    memsett(a,b,c)         memset(a,b,c)
#define    memcmpp(a,b,c)         memcmp(a,b,c)
#define    memcpy16(d, s, c16)    memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)      memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)    memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)      memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)    memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)      memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#define max(a,b)                (((a) > (b)) ? (a) : (b))
#define min(a,b)                (((a) < (b)) ? (a) : (b))

        /* Map printf to kernel-level support as appropriate. */
#if (defined (SLAD_PLATFORM_WINNT_DRIVER) ||
defined (SLAD_PLATFORM_WIN2K_DRIVER))
#define _STDIO_DEFINED
#define printf                    DbgPrint
#endif

#elif defined (SLAD_PLATFORM_WIN9X_DRIVER)

        /* Include 9x DDK definitions. */
#define    WANTVXDWRAPS
#include <basedef.h>
#define BASETYPES
#include <vmm.h>
#include <vtd.h>
#include <vmmreg.h>
#include <vxdwraps.h>

        /* All our currently supported Windows platforms
        are little endian. */
        /* This may change at any moment! */
#undef SLAD_BIG_ENDIAN

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef long INT32;
typedef unsigned long UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)             sizeof(x)

#define max(a,b)                (((a) > (b)) ? (a) : (b))
#define min(a,b)                (((a) < (b)) ? (a) : (b))

        /* Define the ntdef unreferenced parameter macros. */
#define UNREFERENCED_PARAMETER(P)            (P)
#define DBG_UNREFERENCED_PARAMETER(P)        (P)
#define DBG_UNREFERENCED_LOCAL_VARIABLE(V)    (V)

        /* Define the execution modes. */
typedef enum _MODE
{
  KernelMode,
  UserMode,
  MaximumMode
}
MODE;

#elif defined (SLAD_PLATFORM_TMS470)

        /* TI's TMS compiler for ARM cpu */

        /* Legacy definitions. */
#define GENERIC_CGX                1

/*  __FORCE_DWORD_ALIGNMENT should be defined if the processor
 needs
   DWORDs aligned on 4byte boundaries. TIs TMS470 for the ARM
   certainly needs this define.
   For other ARM compilers __FORCE_DWORD_ALIGNMENT should probably be
    defined even though the compiler can
   generate code that uses packed structs, because CGX test code is
   so full of casting UINT16 * to
   UINT32 *.
 */
#ifndef __FORCE_DWORD_ALIGNMENT
#define __FORCE_DWORD_ALIGNMENT
#endif
#if 0
#define USE_ASM_BIGNUMBER_PRIMITIVES
#define USE_ASM_BIGNUMBER_MEM_FUNCTIONS
/* because the CCS library memcpy
* is not optimal */

#endif
typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_ARM_ARCH_3M_PLUS)

        /* ARM architecture 3 cpu with 32x32 multiplier,
        or better, and ARM build tools */

        /* Legacy definitions. */
#define GENERIC_CGX                1

 /*  __FORCE_DWORD_ALIGNMENT should be defined if the
    processor needs
    DWORDs aligned on 4byte boundaries. TIs TMS470 for the
    ARM certainly needs this define.
    For other ARM compilers __FORCE_DWORD_ALIGNMENT should
    probably be defined even though the compiler can
    generate code that uses packed structs, because CGX test
    code is so full of casting UINT16 * to
    UINT32 *.
  */
#ifndef __FORCE_DWORD_ALIGNMENT
#define __FORCE_DWORD_ALIGNMENT
#endif

#define USE_ASM_BIGNUMBER_PRIMITIVES

     /* The armcc compiler in ARM Developer Suite 1.x and
     beyond predefines __ARMCC_VERSION
      * For ADS 1.2, __ARMCC_VERSION = 120bbb
      (bbb is the build number)
      * ADS 1.2 has an efficient, correct,
       memmove() library function, so we dont need
      * to use our own for ADS 1.2. See also comments in bigsubs.h
      *
      * Note that SDT 2.5 is an OLDER compiler than ADS 1.2
      */

#ifndef __ARMCC_VERSION
                /* We are NOT running ADS 1.2 */
#define USE_ASM_BIGNUMBER_MEM_FUNCTIONS
/* define this for old arm tools,
* SDT 2.5 or lower. */
#elif (120 != __ARMCC_VERSION/1000)
                /* We are NOT running ADS 1.2 */
#define USE_ASM_BIGNUMBER_MEM_FUNCTIONS
/* define this for old arm tools,
* SDT 2.5 or lower. */
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)

#define byte_sizeof(x)             sizeof(x)

#elif defined (SLAD_PLATFORM_ARM_3140)

/* ARM architecture 3 cpu with 32x32 multiplier, or better,
and ARM build tools */

/* Legacy definitions. */
#define GENERIC_CGX                1

  /*  __FORCE_DWORD_ALIGNMENT should be defined if the
  processor needs
     DWORDs aligned on 4byte boundaries. TIs TMS470 for the
     ARM certainly needs this define.
     For other ARM compilers __FORCE_DWORD_ALIGNMENT should
      probably be defined even though the compiler can
     generate code that uses packed structs,
      because CGX test code is so full of casting UINT16 * to
     UINT32 *.
   */
#ifndef __FORCE_DWORD_ALIGNMENT
#define __FORCE_DWORD_ALIGNMENT
#endif

/*    #define USE_ASM_BIGNUMBER_PRIMITIVES*/

   /* The armcc compiler in ARM Developer Suite 1.x and
   beyond predefines __ARMCC_VERSION
    * For ADS 1.2, __ARMCC_VERSION = 120bbb (bbb is the build number)
    * ADS 1.2 has an efficient, correct, memmove()
    library function, so we dont need
    * to use our own for ADS 1.2. See also comments in bigsubs.h
    *
    * Note that SDT 2.5 is an OLDER compiler than ADS 1.2
    */

#ifndef __ARMCC_VERSION
                /* We are NOT running ADS 1.2 */
/*#define USE_ASM_BIGNUMBER_MEM_FUNCTIONS *//* define this for old arm tools,
* SDT 2.5 or lower. */
#elif (120 != __ARMCC_VERSION/1000)
                /* We are NOT running ADS 1.2 */
/*#define USE_ASM_BIGNUMBER_MEM_FUNCTIONS *//* define this for old arm tools,
 * SDT 2.5 or lower. */
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef int INT32;
typedef unsigned int UINT32;

typedef unsigned char **MEMCPY_TYPE;

#define WINAPI
#define PM(a)                    a

#define    memcpyy(a,b,c)       memcpy(a,b,c)
#define    memsett(a,b,c)       memset(a,b,c)
#define    memcmpp(a,b,c)       memcmp(a,b,c)
#define    memcpy16(d, s, c16)  memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcpy8(d, s, c8)    memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define    memset16(d, c, c16)  memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define    memset8(d, c, c8)    memset((BYTE*)(d), (int)(c), (c8))
#define    memcmp16(d, s, c16)  memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define    memcmp8(d, s, c8)    memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define max(A, B)                ((A) > (B) ? A : B)
#define min(A, B)                ((A) < (B) ? A : B)

#define byte_sizeof(x)             sizeof(x)

#elif defined(CGX_VENDOR_CUSTOMIZATION_ID) && CGX_VENDOR_CUSTOMIZATION_ID == 1

        /* Legacy definitions. */
#define GENERIC_CGX                1

        /* Are we big or little endian? */
#if (_BYTE_ORDER == _BIG_ENDIAN)
#define SLAD_BIG_ENDIAN
#elif (_BYTE_ORDER == _LITTLE_ENDIAN)
#undef SLAD_BIG_ENDIAN
#else
#error Unable to determine endianness [CGX_VENDOR_CUSTOMIZATION_ID == 1]
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef long INT32;
typedef unsigned long UINT32;

typedef unsigned char **MEMCPY_TYPE;

#if !defined(_SIZE_T) && !defined(_GCC_SIZE_T)

#define _SIZE_T

#if defined(__GNUC__)
#define _GCC_SIZE_T
typedef
__typeof__ (sizeof (0))
  size_t;
#else
typedef unsigned int size_t;
#endif /* __GNUC__ */

#endif /* _SIZE_T */

typedef struct
{
    /* needs to be binary-compatible with old versions */
#ifdef _STDIO_REVERSE
  unsigned char *_ptr;
  /* next character from/to here in buffer */
  int _cnt;
  /* number of available characters in buffer */
#else
  int _cnt;
  /* number of available characters in buffer */
  unsigned char *_ptr;
  /* next character from/to here in buffer */
#endif
  unsigned char *_base;
  /* the buffer */
  unsigned char _flag;
  /* the state of the stream */
  unsigned char _file;
  /* UNIX System file descriptor */
}
FILE;

#define WINAPI
#define PM(a)                    a

extern void *memcpy (void *d, const void *s, size_t bytes);
extern void *memset (void *, int, size_t);
extern void *malloc (size_t num_bytes);
extern void free (void *p);
extern void console_message (const char *str);
extern void buginf (const char *fmt, ...);

#define memcpyy(a,b,c)        memcpy(a,b,c)
#define memsett(a,b,c)        memset(a,b,c)
#define memcmpp(a,b,c)        memcmp(a,b,c)
#define memcpy16(d, s, c16)   memcpy((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define memcpy8(d, s, c8)     memcpy((BYTE*)(d), (BYTE*)(s), (c8))
#define memset16(d, c, c16)   memset((BYTE*)(d), (int)(c), ((c16)<<1))
#define memset8(d, c, c8)     memset((BYTE*)(d), (int)(c), (c8))
#define memcmp16(d, s, c16)   memcmp((BYTE*)(d), (BYTE*)(s), ((c16)<<1))
#define memcmp8(d, s, c8)     memcmp((BYTE*)(d), (BYTE*)(s), (c8))

#define byte_sizeof(x)            sizeof(x)

#define random_init                sfnt_random_init
#define hash_init                sfnt_hash_init
#define cache_flush                sfnt_cache_flush
#define handle_exception        sfnt_handle_exception

#define fflush(x)
#define stderr                    0
#if 0
#define fprintf
#else
#define fprintf(arg1, arg2...)    buginf(## arg2)
#endif
extern int sprintf (char *cp, char *fmt, ...);
#define stdout 1
#define sfnt_debug_info            buginf
#define printf                    buginf

#else

#error CGX PLATFORM NOT SPECIFIED!

#endif


/*
 *    (The following comment refers to the memory operation macros
 *    defined in each of the platform-specific sections above.)
 *
 *    The memory operations will allow the caller to pass in a byte or
 *    word (16bit) count. The macro will translate the count into
 *    the targets appropriate interface and count unit. This means that
 *    on the 2181 target the caller better give a count, when in bytes,
 *    mod 16 or it will be truncated.
 *
 *    Also, note the RTL memcpy, memset, and memcmp operations are
 *    compiled into our base. This is because we don't want to use ADI's
 *    version because they use 0 overhead DO loops and they aren't
 *    allowed in the kernel.
 */


/********************************************************************
* If these haven't been defined by the specific platform, here ya go.
*********************************************************************/

#ifndef TRUE
#define    TRUE        1
#endif

#ifndef FALSE
#define    FALSE        0
#endif

#ifndef NULL
#define    NULL        0
#endif


/**********************************************************
* Common defines and macros.
***********************************************************/

#define    LNULL                0L
#define    MAXBYTE                0xff
#define    MAXUINT16            (0xFFFF)
#define    MAXINT16            (0x7FFF)
#define    MAXUINT32            (0xFFFFFFFFL)
#define    MAXINT32            (0x7FFFFFFFL)
#define BYTE_BITS            8
#define    UINT16_BITS            16
#define    UINT32_BITS            32
#define    UINT32Bits            32
#define    UINT32Mask            (UINT32)0xFFFFFFFFL
#define    UINT32Bytes            4
#define    UINT32Words            2
#define    UINT32Frag            3

#define is_even(A)            (!((A) & 0x0001))
/* 16bit even test */
#define is_odd(A)            ((A) & 0x0001)
/* 16bit odd test */
#define is_max(A, B)        ((A) > (B))
#define is_maxeq(A, B)        ((A) >= (B))
#define is_min(A, B)        ((A) < (B))
#define is_mineq(A, B)        ((A) <= (B))
#define word_sizeof(x)        (sizeof(x)/sizeof(UINT16))

/*
A sizeof macro to convert sizeof to bytes for PC and 2181.
This is only useful when translating between same size data units.
For example this won't work with when trying get size when looking
at a data type of char. On the PC its 1 byte but on the 2181 it is
2 bytes, char, int, and short are 16bit types on the 2181.
*/
#define    SIZEOF(X)            ((sizeof(X) << 1) / sizeof(UINT16))



/*****************************************************************
* Common typedefs.
******************************************************************/
#ifndef SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER
typedef void *VPTR;             /* pointer to any object */
#endif

/* Turn on structure packing. */
#include "pack_begin.h"


/* Data Page Declaration Type, include its public interface */
/* THIS REALLY DOES NOT BELONG HERE!!!!!!!!!!!!!!!!!!! -IDM */
//#include "dpagepi.h"

/*
Support for Little/Big Endian Long Integer.
The following unions allow one to manipulate a 32 bit integer
that could be stored in little or big endian form.
*/

/* target storage */
typedef PACKED_STRUCTURE_ATTRIBUTE_1 struct _endian32
{
#if defined (SLAD_PLATFORM_ADI2181)
  UINT16 msw;
  UINT16 lsw;
#elif defined (SLAD_BIG_ENDIAN)
  UINT16 msw;
   /* these members are used in bignum - gotta get it right */
  UINT16 lsw;
#else
  UINT16 lsw;
  UINT16 msw;
#endif
}
PACKED_STRUCTURE_ATTRIBUTE_2 endian32;

/* little endian storage */
typedef PACKED_STRUCTURE_ATTRIBUTE_1 struct _littleendian32
{
  UINT16 lsw;
  UINT16 msw;
}
PACKED_STRUCTURE_ATTRIBUTE_2 littleendian32;

/* big endian storage */
typedef PACKED_STRUCTURE_ATTRIBUTE_1 struct _bigendian32
{
  UINT16 msw;
  UINT16 lsw;
}
PACKED_STRUCTURE_ATTRIBUTE_2 bigendian32;

typedef PACKED_STRUCTURE_ATTRIBUTE_1 union _UNUM32
{
  UINT32 num32;
  littleendian32 numle;
  bigendian32 numbe;
  endian32 num;
}
PACKED_STRUCTURE_ATTRIBUTE_2 UNUM32;


/* Turn off structure packing. */
#include "pack_end.h"


/* used for inline 12 word buffer copy */
typedef struct _secret_key_copy
{
  UINT16 key[12];
}
secret_key_copy;



#endif /* _STD_H_ */
