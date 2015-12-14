/* eip93_level0.h
 *
 * This file contains all the macros and  functions that allow
 * access to the EIP93 registers and to build the values
 * read or written to the registers.
 *
 */

/*****************************************************************************
*                                                                            *
*         Copyright (c) 2008-2009 SafeNet Inc. All Rights Reserved.          *
*                                                                            *
* This confidential and proprietary software may be used only as authorized  *
* by a licensing agreement from SafeNet.                                     *
*                                                                            *
* The entire notice above must be reproduced on all authorized copies that   *
* may only be made to the extent permitted by a licensing agreement from     *
* SafeNet.                                                                   *
*                                                                            *
* For more information or support, please go to our online support system at *
* https://oemsupport.safenet-inc.com or e-mail to oemsupport@safenet-inc.com *
*                                                                            *
*****************************************************************************/

#ifndef INCLUDE_GUARD_EIP93_DHM1_LEVEL0_H
#define INCLUDE_GUARD_EIP93_DHM1_LEVEL0_H

#include "basic_defs.h"           // BIT definitions, bool, uint32_t
#include "hw_access.h"            // Read32, Write32, HWPAL_Device_t
#include "eip93_hw_interface.h"   // the HW interface (register map)
#include "eip93_level0.h"         // EIP93_Read32/Write32[Array]



/*constant for Fault threshold */
#define EIP93_FAULT_BIT_MASK           0XFF
#define EIP93_MAX_FAULT_THRESHOLD      256
#define EIP93_MIN_FAULT_THRESHOLD      1


/* constants for the bits in this register */
//PE Specific
#define EIP93_CONTROL_PE_RESETHOLD         ((uint32_t)(BIT_0))
#define EIP93_CONTROL_PDR_RESETHOLD        ((uint32_t)(BIT_1))
#define EIP93_CONTROL_DHM_ON               ((uint32_t)(~((BIT_8)|(BIT_9))))
#define EIP93_STATUS_OPERATION_DONE        ((uint32_t)(BIT_9))
#define EIP93_STATUS_PE_OUTPUT_DONE        ((uint32_t)(BIT_1))
#define EIP93_STATUS_PE_INPUT_DONE         ((uint32_t)(BIT_0))

//PE command descriptor specific
#define EIP93_DESP_CRTL_REG_HOSTREADY      ((uint32_t)(BIT_0))
#define EIP93_DESP_LEN_REG_HOSTREADY       ((uint32_t)(BIT_22))

//constants & mask
#define EIP93_DESP_CRTL_REG_MASK             0xFF00FF10
#define EIP93_DESP_STAT_REG_MASK             0xFFFFFF10
#define EIP93_10BITS_MASK                    0X3FF
#define EIP93_12BITS_MASK                    0XFFF
#define EIP93_20BITS_MASK                    0xFFFFF
#define EIP93_PE_DHM_VALIDINTERRUPT_MASK     0xE00
#define EIP93_PE_DEFAULT_DRSIZE              5
#define EIP93_PE_SA1_RECORD_SIZE             (23*4)
#define EIP93_PE_SA2_RECORD_SIZE             (58*4)
#define EIP93_PE_SASTATE_RECORD_SIZE         (11*4)
#define EIP93_PE_RUN_MASK           ((uint32_t)~( EIP93_CONTROL_PE_RESETHOLD \
                                               | EIP93_CONTROL_PDR_RESETHOLD))
#define EIP93_SIGNATURE                     0xA25D

//helper functions


/*----------------------------------------------------------------------------
 *EIP93_PE_And_Ring_ResetHold
 *
 * return mask of PE and PDR manger reset hold mask.
 */
static inline uint32_t
EIP93_PE_And_Ring_ResetHold(void)
{
    return (EIP93_CONTROL_PE_RESETHOLD | EIP93_CONTROL_PDR_RESETHOLD);
}


/*----------------------------------------------------------------------------
 *EIP93_Reg_PE_Length_Make
 *
 * Make command descriptor's length part.
 */
static  inline void
EIP93_Reg_PE_Length_Make(
        unsigned int BypassWordsCount,
        unsigned DataCount,
        uint32_t * Reg_PE_Length_Value_p)
{
    uint32_t EIP93_Reg_PE_Length_Value =0;

    //populate bypass count
    EIP93_Reg_PE_Length_Value = (uint32_t )
                                ( BypassWordsCount << 24 );

    //popupale source data lenght
    EIP93_Reg_PE_Length_Value |= (uint32_t )
                                 (EIP93_20BITS_MASK & DataCount);

    *Reg_PE_Length_Value_p = EIP93_Reg_PE_Length_Value;
}


/*----------------------------------------------------------------------------
 * EIP93_Reg_PE_CTRL_Make
 *
 * Make command descriptor's command  part.
 */
static inline void
EIP93_Reg_PE_CTRL_Make(
        uint32_t Control,
        uint32_t * EIP93_Reg_PE_CTRL_Value_p)
{
     // Clear error code, halt and reserved bit fields
     *EIP93_Reg_PE_CTRL_Value_p = Control & EIP93_DESP_CRTL_REG_MASK;

}


/*----------------------------------------------------------------------------
 * EIP93_Reg_PE_Length_DataCntExtract
 *
 * Extracts data lenght from the result descriptor's lenght part.
 */
static inline void
EIP93_Reg_PE_Length_DataCntExtract(
        uint32_t EIP93_Reg_PE_Length_Value,
        unsigned int * DataCount_p)
{
    *DataCount_p =  (unsigned int)
                    (EIP93_Reg_PE_Length_Value & EIP93_20BITS_MASK);

}


/*----------------------------------------------------------------------------
 * EIP93_Reg_PE_Length_BypassedCntExtract
 *
 * Extracts bypassed data count  from the result descriptor's lenght part.
 */
static inline void
EIP93_Reg_PE_Length_BypassedCntExtract(
        uint32_t EIP93_Reg_PE_Length_Value,
        uint8_t * BypassedWordsCount_p)
{
    *BypassedWordsCount_p = (uint8_t)(EIP93_Reg_PE_Length_Value >>24);

}


/*----------------------------------------------------------------------------
 * EIP93_Reg_PE_STAT_StatusExtract
 *
 * Extracts staus fields from the result descriptor's staus part.
 */
static inline void
EIP93_Reg_PE_STAT_StatusExtract(
        uint32_t  EIP93_Reg_PE_STAT_Value,
        uint32_t * Status_p)
{
    *Status_p =  EIP93_Reg_PE_STAT_Value & EIP93_DESP_STAT_REG_MASK;

}


/*----------------------------------------------------------------------------
 * EIP93_Read_Available_Cnt
 *
 */
static inline unsigned int
EIP93_Read_Available_Cnt(uint32_t i)
{
    return (((i >> 12) & EIP93_10BITS_MASK));

}
#endif /* INCLUDE_GUARD_EIP93_LEVEL0_H */

/* end of file eip93_level0.h */


