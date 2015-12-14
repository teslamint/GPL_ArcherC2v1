/***********************************************************
*
* SLAD Test SA Coneverter 
*
*        Copyright 2007-2008 SafeNet Inc
*
*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/



#include "slad_test_sa_converter.h"

#ifdef SLAD_TEST_BUILD_FOR_PE

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

int
slad_convert_sa (unsigned int *generic_sa, int *sa_len,
                 device_type_conf dev_type)
{
  int ok = true;
  unsigned int copy_of_sa[128];
  int copy_to_pos, copy_from_pos;
  // int i ;

  switch (dev_type)
    {
    case EIP_93_I:

#if 0
      /* Move Idigest0 - Idigest4 (5 words) 2 places up */
      memmove (&(generic_sa[8]), &(generic_sa[10]), 5 * WORD_SIZE);

      /* Move Odigest0 - Odigest4 (5 words) 5 places up */
      memmove (&(generic_sa[13]), &(generic_sa[18]), 5 * WORD_SIZE);

      /* Move SPI to nonce (5 words) 8 places up */
      memmove (&(generic_sa[18]), &(generic_sa[26]), 5 * WORD_SIZE);

      /* zeroize remaining 9 words */
      memset (&(generic_sa[23]), 9 * WORD_SIZE);

      generic_sa[23] = 0xabbadead;      // To  trigger processing
      *sa_len = 24;

#endif

#if 1

      //  printf("\n generic_sa[3] : %x \n", generic_sa[3] );

      memset (&copy_of_sa, 0, sizeof (copy_of_sa));
      memcpy (&copy_of_sa, generic_sa, (*sa_len) * sizeof (unsigned int));

      memset (generic_sa, 0, *sa_len * sizeof (unsigned int));

      copy_to_pos = copy_from_pos = 0;
      memcpy (generic_sa + copy_to_pos, copy_of_sa + copy_from_pos,
              8 * sizeof (unsigned int));
      copy_to_pos = 8;
      copy_from_pos = 10;

      memcpy (generic_sa + copy_to_pos, copy_of_sa + copy_from_pos,
              5 * sizeof (unsigned int));
      copy_to_pos += 5;
      copy_from_pos = 18;

      memcpy (generic_sa + copy_to_pos, copy_of_sa + copy_from_pos,
              5 * sizeof (unsigned int));
      copy_to_pos += 5;
      copy_from_pos = 26;

      memcpy (generic_sa + copy_to_pos, copy_of_sa + copy_from_pos,
              5 * sizeof (unsigned int));
      copy_to_pos += 5;
      copy_from_pos = 31;



      generic_sa[23] = 0xabbadead;      // To  trigger processing
      *sa_len = 23; //24 to 23 for EIP93 library

      // printf("\n");

#endif


      break;

    case EIP_93_IE:
      /* zeroize the last 1 word */
      memset (&(generic_sa[31]), 0, 1);
      *sa_len = WORDS_IN_SA - 1;
      break;

    case EIP_93_IS:
      /* Move Idigest0 - Idigest4 (5 words) 2 places up */
      memmove (&(generic_sa[8]), &(generic_sa[10]), 5 * WORD_SIZE);

      /* Move Odigest0 - Odigest4 (5 words) 5 places up */
      memmove (&(generic_sa[13]), &(generic_sa[18]), 5 * WORD_SIZE);

      /* Move SPI to ARC4 I-J (6 words) 8 places up */
      memmove (&(generic_sa[18]), &(generic_sa[26]), 6 * WORD_SIZE);

      /* zeroize remaining 8 words */
      memset (&(generic_sa[24]), 0, 8 * WORD_SIZE);

      *sa_len = WORDS_IN_SA - 8;
      break;

    case EIP_93_IW:
      /* Move Idigest0 - Idigest4 (5 words) 2 places up */
      memmove (&(generic_sa[8]), &(generic_sa[10]), 5 * WORD_SIZE);

      /* Move Odigest0 - Odigest4 (5 words) 5 places up */
      memmove (&(generic_sa[13]), &(generic_sa[18]), 5 * WORD_SIZE);

      /* Move SPI to nonce (5 words) 8 places up */
      memmove (&(generic_sa[18]), &(generic_sa[26]), 5 * WORD_SIZE);

      /* zeroize remaining 9 words */
      memset (&(generic_sa[23]), 0, 9 * WORD_SIZE);

      *sa_len = WORDS_IN_SA - 9;
      break;
    case EIP_93_IESW:
      /* do nothing */
      break;

    default:
#if defined(TEST_PEC_GATHER) || defined(TEST_PEC_SCATTER) 
// Set scatter-bit in Command0 
{
    #define BIT_30  0x40000000U
    #define BIT_31  0x80000000U
    
    int Cmd0_Offset ;

    // Identify offset of command0 for SA revisons 
    if( (*sa_len == 32 ) ||
        (*sa_len == 58 )
    )
    {
        Cmd0_Offset = 0 ;
        LOG_INFO("TestApp:SA filter:SG: SA Rev1 or 2 \n");
    }
    else if(*sa_len < 59 )
    {
        Cmd0_Offset  = 1 ;
        LOG_INFO("TestApp:SA filter:SG: Dynamic SA \n");
    }
    else
       Cmd0_Offset = -1 ;  

    //Set SG flags
    if(Cmd0_Offset!= -1 )   
    {
      #if defined(TEST_PEC_GATHER)
        generic_sa[Cmd0_Offset] |= BIT_30 ;
      #endif

      #if defined(TEST_PEC_SCATTER)
        generic_sa[Cmd0_Offset] |= BIT_31 ;
      #endif
      
    }
    LOG_INFO("TestApp:SA filter:SG: Cmd0 after setting S/G bits: 0x%8x \n", 
              generic_sa[Cmd0_Offset]  ) ;}

#endif

      ok = true;
      break;
    }

  return ok;
}

int
slad_convert_srec (unsigned int *generic_srec, int *srec_len,
                   device_type_conf dev_type)
{
  int ok = true;

  switch (dev_type)
    {
    case EIP_93_I:
      /* Zeroize digest5 - digest7 (3 words) and ARC4 state array (64 words) 
         if present */
      if (*srec_len == WORDS_IN_SREC_WITH_ARC4)
        {
          memset (&(generic_srec[11]), 0,
                  (3 + WORDS_IN_SREC_ARC4) * WORD_SIZE);
        }
      else
        {
          /* Zeroize digest5 - digest7 (3 words) */
          memset (&(generic_srec[11]), 0, 3 * WORD_SIZE);
        }
      *srec_len = 11;           // WORDS_IN_SREC - 3;
      break;

    case EIP_93_IE:
      /* Zeroize ARC4 state array (64 words) if present */
      if (*srec_len == WORDS_IN_SREC_WITH_ARC4)
        {
          memset (&(generic_srec[14]), 0, WORDS_IN_SREC_ARC4 * WORD_SIZE);
        }
      *srec_len = WORDS_IN_SREC;
      break;

    case EIP_93_IS:
      /* Move ARC4 state array (64 words) 3 words up */
      if (*srec_len == WORDS_IN_SREC_WITH_ARC4)
        {
          memmove (&(generic_srec[14]), &(generic_srec[11]),
                   WORDS_IN_SREC_ARC4 * WORD_SIZE);
          memset (&(generic_srec[WORDS_IN_SREC_WITH_ARC4 - 4]), 0, 3);
          *srec_len = WORDS_IN_SREC_WITH_ARC4 - 3;
        }
      else
        {
          /* Zeroize digest5 - digest7 (3 words) */
          memset (&(generic_srec[11]), 0, 3 * WORD_SIZE);
          *srec_len = WORDS_IN_SREC - 3;
        }
      break;

    case EIP_93_IW:
      /* Zeroize digest5 - digest7 (3 words) and ARC4 state array (64 words) 
         if present */
      if (*srec_len == WORDS_IN_SREC_WITH_ARC4)
        {
          memset (&(generic_srec[11]), 0,
                  (3 + WORDS_IN_SREC_ARC4) * WORD_SIZE);
        }
      else
        {
          /* Zeroize digest5 - digest7 (3 words) */
          memset (&(generic_srec[11]), 0, 3 * WORD_SIZE);
        }
      *srec_len = WORDS_IN_SREC - 3;
      break;

    case EIP_93_IESW:
      /* do nothing */
      break;
    default:
      /* do nothing */
      //ok = false;
      ok = true;
      break;
    }

  return ok;
}

#endif
