/*h*
* File:  pack_begin.h
*
* Turn on structure packing.
*
* Include this file just before any structures that need to be packed,
* then include pack_end.h after the last structure that needs to be packed.
*
*

     Copyright 2007-2008 SafeNet Inc

*
*
* Here is how to do structure packing using pack_begin.h and pack_end.h:
*
*    // This structure is not packed.
*    typedef struct _my_struct1 {
*        char *data;
*        int len;
*    } my_struct1;
*
*    // Turn on structure packing.
*    #include "pack_begin.h"
*
*    // This structure is packed.
*    typedef PACKED_STRUCTURE_ATTRIBUTE_1 struct _my_packed_struct {
*        char msb;
*        char lsb;
*    } PACKED_STRUCTURE_ATTRIBUTE_2 my_packed_struct;
*
*    // Turn off structure packing.
*    #include "pack_end.h"
*
*    // This structure is not packed.
*    typedef struct _my_struct2 {
*        char node;
*        void *buf;
*    } my_struct2;
*
* Note the required placement of PACKED_STRUCTURE_ATTRIBUTE_1 and
* PACKED_STRUCTURE_ATTRIBUTE_2 in the packed structure above.
*
*
*
* Edit History:
*
*
* Initial Check-in v0.1
*
*
* Initial revision
*    Created.
*
*/


/*****************************************************************************
* This header file must *not* be protected against re-inclusion!
* Changes to this file may require corresponding changes to pack_end.h!
*****************************************************************************/


/*****************************************************************************
* Begin structure packing for various compilers.
* Note that this is compiler-dependent, not platform or o/s dependent.
*****************************************************************************/


#if defined (__GNUC__) || defined (__GCC32__)

        /*
           The gnu compiler (gcc).
           __GNUC__ is automatically predefined when using this compiler.
           Note: For the Symbian version of the GNU compiler __GNUC__
           is NOT defined, but __GCC32__ is defined
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2        __attribute__((packed))

#elif defined (__ADSP21XX__) || defined (__ADSP21xx__)

        /*
           The ADI Visual DSP compiler,
           which is a special version of the gnu gcc compiler.
           __GNUC__ is NOT automatically predefined when using this compiler.
           Structure packing is what the VDSP compiler always does by default.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (__arm)

        /*
           The ARM compiler (armcc).
           __arm is automatically predefined when using this compiler.
         */
#ifndef CGX_NO_STRUCTURE_PACKING
#define PACKED_STRUCTURE_ATTRIBUTE_1        __packed
#else
#define PACKED_STRUCTURE_ATTRIBUTE_1
#endif
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (__sun)

        /*
           The Sun compiler.
           __sun is automatically predefined when using this compiler.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2
#pragma pack (1)

#elif defined (__ghs__)

        /*
           The Green Hills compiler.
           __ghs__ is automatically predefined when using this compiler.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2
#pragma pack (1)

#elif defined (_MSC_VER) || defined (__VC32__)

        /*
           The Microsoft compiler.
           _MSC_VER is automatically predefined when using this compiler.
           Note: Symbian uses the MS compiler when building for the
           Symbian WINS emulator, but defines __VC32__ instead.
         */
#pragma warning (disable:4103)
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2
#pragma pack (push, CGX_PACK, 1)

#elif defined (CPPC_TASKING)

        /*
           The Tasking PowerPC compiler.
           CPPC_TASKING must be defined by you!!!
           (Does anyone know a predefine for this compiler?)
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1        _Packed
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (__TMS470__)

        /*
           __TMS470__ is defined by the compiler
           Structure packing not possible for 
           TI's ARM compiler (cl470 for TMS470).
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (__TMS320C55X__)

        /*
           __TMS320C55X__ is defined by the compiler
           Structure packing not possible for TI's C55 compiler.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (_EPI_SIMULATOR_)

        /*
           The EPI simulator.
           Structure packing is not necessary for the EPI simulator.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2

#elif defined (__CW32__)

        /*
           Metrowerks codewarrior.
           This code will not be included if some of the symbols above
           are defined, e.g., when using arm.
         */
#define PACKED_STRUCTURE_ATTRIBUTE_1
#define PACKED_STRUCTURE_ATTRIBUTE_2
#pragma pack (push, 1)

#else

#error Do not know how to do structure packing for this compiler!

#endif
