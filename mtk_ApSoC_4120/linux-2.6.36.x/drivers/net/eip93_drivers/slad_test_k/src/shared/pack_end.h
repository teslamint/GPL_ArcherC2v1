/*h*
* File:  pack_end.h
*
* Turn off structure packing.
*
* Include this file after the last structure that needs to be packed.
*
*

     Copyright 2007-2008 SafeNet Inc

*
*
* Edit History:
*
*
* Initial Check-in v0.1
* Initial revision
* Created.
*
*/


/*****************************************************************************
* This header file must *not* be protected against re-inclusion!
* Changes to this file may require corresponding changes to pack_begin.h!
*****************************************************************************/


/*****************************************************************************
* End structure packing for various compilers.
* Note that this is compiler-dependent, not platform or o/s dependent.
*****************************************************************************/


#undef PACKED_STRUCTURE_ATTRIBUTE_1
#undef PACKED_STRUCTURE_ATTRIBUTE_2

#if defined (__GNUC__) || defined (__GCC32__)

        /*
           The gnu compiler (gcc).
           __GNUC__ is automatically predefined when using this compiler.
           Note: For the Symbian version of the GNU compiler __GNUC__
           is NOT defined, but __GCC32__ is defined
         */

#elif defined (__ADSP21XX__) || defined (__ADSP21xx__)

        /*
           The ADI Visual DSP compiler,
           which is a special version of the gnu gcc compiler.
           __GNUC__ is NOT automatically predefined when using this compiler.
           Structure packing is what the VDSP compiler always does by default.
         */

#elif defined (__arm)

        /*
           The ARM compiler (armcc).
           __arm is automatically predefined when using this compiler.
         */

#elif defined (__sun)

        /*
           The Sun compiler.
           __sun is automatically predefined when using this compiler.
         */
#pragma pack ()

#elif defined (__ghs__)

        /*
           The Green Hills compiler.
           __ghs__ is automatically predefined when using this compiler.
         */
#pragma pack ()

#elif defined (_MSC_VER) || defined (__VC32__)

        /*
           The Microsoft compiler.
           _MSC_VER is automatically predefined when using this compiler.
           Note: Symbian uses the MS compiler when building for the
           Symbian WINS emulator, but defines __VC32__ instead.
         */
#pragma pack (pop, CGX_PACK)

#elif defined (CPPC_TASKING)

        /*
           The Tasking PowerPC compiler.
           CPPC_TASKING must be defined by you!!!
           (Does anyone know a predefine for this compiler?)
         */

#elif defined (__TMS470__)

        /*
           __TMS470__ is defined by the compiler
           Structure packing not possible for TI's
            ARM compiler (cl470 for TMS470).
         */

#elif defined (__TMS320C55X__)

        /*
           __TMS320C55X__ is defined by the compiler
           Structure packing not possible for TI's C55 compiler.
         */

#elif defined (_EPI_SIMULATOR_)

        /*
           The EPI simulator.
           Structure packing is not necessary for the EPI simulator.
         */

#elif defined (__CW32__)

        /*
           Metrowerks codewarrior.
           This code will not be included if some of the symbols above
           are defined, e.g., when using arm.
         */
#pragma pack (pop)

#else

#error Do not know how to do structure packing for this compiler!

#endif
