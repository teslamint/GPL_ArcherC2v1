/* adapter_interrupts_km.c
 *
 * Adapter module responsible for interrupts.
 */

/*****************************************************************************
* Copyright (c) 2008-2010 AuthenTec B.V. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from AuthenTec.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* AuthenTec.
*
* For more information or support, please go to our online support system at
* https://oemsupport.authentec.com. In case you do not have an account for
* this system, please send an e-mail to EmbeddedHW-Support@authentec.com.
*****************************************************************************/




#include "adapter_internal.h"
#include "basic_defs.h"
#include "hw_access.h"

#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>        // spinlock_*
#include "adapter_interrupts_eip93.h"
#include "eip93.h"

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE



#define ADAPTER_MAX_INTERRUPTS 32


static int Adapter_Interrupts_IRQ = -1;
static Adapter_InterruptHandler_t
        Adapter_Interrupts_HandlerFunctions[ADAPTER_MAX_INTERRUPTS];
static spinlock_t Adapter_Interrupts_ConcurrencyLock;

#define INTERRUPT_PIN 1

#ifdef ADAPTER_EIP93PE_INTERRUPTS_TEST_RAW_STATUS
static bool RawInterruptTestStatus = true ;
#endif

#define VPint *(volatile unsigned int *)

//#define ADAPTER_EIP93PE_INTERRUPTS_TEST_RAW_STATUS


/*----------------------------------------------------------------------------
 * Adapter_Interrupts_GetActiveIntNr
 *
 * Returns 0..31 depending on the lowest '1' bit.
 * Returns 32 when all bits are zero
 *
 * Using binary break-down algorithm.
 */
static inline int
Adapter_Interrupts_GetActiveIntNr(
        uint32_t Sources)
{
    unsigned int IntNr = 0;
    unsigned int R16, R8, R4, R2;

    if (Sources == 0)
        return 32;

    // if the lower 16 bits are empty, look at the upper 16 bits
    R16 = Sources & 0xFFFF;
    if (R16 == 0)
    {
        IntNr += 16;
        R16 = Sources >> 16;
    }

    // if the lower 8 bits are empty, look at the high 8 bits
    R8 = R16 & 0xFF;
    if (R8 == 0)
    {
        IntNr += 8;
        R8 = R16 >> 8;
    }

    R4 = R8 & 0xF;
    if (R4 == 0)
    {
        IntNr += 4;
        R4 = R8 >> 4;
    }

    R2 = R4 & 3;
    if (R2 == 0)
    {
        IntNr += 2;
        R2 = R4 >> 2;
    }

    // last two bits are trivial
    // 00 => cannot happen
    // 01 => +0
    // 10 => +1
    // 11 => +0
    if (R2 == 2)
        IntNr++;

    return IntNr;
}


/*----------------------------------------------------------------------------
 * Adapter_Interrupts_TopHalfHandler
 */
static irqreturn_t
Adapter_Interrupts_Top_Half_Handler (
        int irq,
        void * dev_id
)
{
    EIP93_INT_SourceBitmap_t Sources;

    if (irq != Adapter_Interrupts_IRQ)
        return IRQ_NONE;

    if (Adapter_Interrupts_IRQ == -1)
    {
        LOG_CRIT(
         "\nAdapter_Interrupts_Top_Half_Handler: Interrupts not initialized\n");
        return IRQ_NONE ;
    }

    //get EIP93_REG_INT_MASK_STAT register
    EIP93_INT_IsActive(&Adapter_EIP93_IOArea,
                &Sources);

#ifdef ADAPTER_EIP93PE_INTERRUPTS_TEST_RAW_STATUS
    {
        EIP93_INT_SourceBitmap_t Sources_Raw= 0 ;
        EIP93_Status_t res ;


        res = EIP93_INT_IsRawActive(
                   &Adapter_EIP93_IOArea,
                &Sources_Raw );

        if( RawInterruptTestStatus != false)
        {
            if( ( (Sources_Raw & Sources) != Sources) ||
                    ( res != EIP93_STATUS_OK )
                )
            {
                  RawInterruptTestStatus = false ;


            }
        }

    }

#endif // ADAPTER_EIP93PE_INTERRUPTS_TEST_RAW_STATUS
    // EIP93_INT_Acknowledge(&Adapter_EIP93_IOArea,
    //    Sources);

    // Disable the active interrupt sources
    EIP93_INT_Mask(&Adapter_EIP93_IOArea, Sources);

    if (Sources )
    {
    #ifndef RT_EIP93_DRIVER
        LOG_INFO("Adapter_Interrupts_Top_Half_Handler: Sources=0x%08x\n", Sources);
    #endif
    }

    // now figure out which sources are active and call
    // the appropriate interrupt handlers that are installed
    while(Sources)
    {
        int IntNr = Adapter_Interrupts_GetActiveIntNr(Sources);

        // now remove that bit from Sources
        Sources ^= (1 << IntNr);

        // verify we have a handler
        {
            Adapter_InterruptHandler_t H;

            H = Adapter_Interrupts_HandlerFunctions[IntNr];

            if (H)
            {
                // invoke the handler
            #ifndef RT_EIP93_DRIVER
                LOG_WARN("\nAdapter_Interrupts_Top_Half_Handler: calling Handler for interrupt: %d \n",IntNr );
            #endif
          //H() is Adapter_EIP93_InterruptHandler_DescriptorDone() for IRQ_RDR_THRESH_IRQ 
                H(); 
            }
            else
            {
                LOG_CRIT(
                    "Adapter_Interrupts_Top_Half_Handler: "
                    "Disabling interrupt %d with missing handler\n",
                    IntNr);

                EIP93_INT_Mask( //set EIP93_REG_MASK_DISABLE
                &Adapter_EIP93_IOArea,(EIP93_INT_SourceBitmap_t)(1 << IntNr));

            }
        }
    } // while

  return IRQ_HANDLED;
}





/*----------------------------------------------------------------------------
 * Adapter_Interrupt_SetHandler
 */
void
Adapter_Interrupt_SetHandler(
        const int nIRQ,
        Adapter_InterruptHandler_t HandlerFunction)
{
    if (nIRQ >= ADAPTER_MAX_INTERRUPTS)
        return;

    // continue only we have the IRQ hooked
    if (Adapter_Interrupts_IRQ != -1)
    {
    #ifndef RT_EIP93_DRIVER
        LOG_WARN("Adapter_Interrupt_SetHandler: HandlerFnc=%p for interrupt %d\n", HandlerFunction, nIRQ);
    #endif
        Adapter_Interrupts_HandlerFunctions[nIRQ] = HandlerFunction;
    }
}


/*----------------------------------------------------------------------------
 * Adapter_Interrupt_Enable
 */
void
Adapter_Interrupt_Enable(
        const int nIRQ)
{
    if (nIRQ >= ADAPTER_MAX_INTERRUPTS)
        return;

    // continue only we have the IRQ hooked
    if (Adapter_Interrupts_IRQ != -1)
    {
        unsigned long flags;
        const EIP93_INT_SourceBitmap_t Sources = 1 << nIRQ;

    #ifndef RT_EIP93_DRIVER
        LOG_WARN("Adapter_Interrupt_Enable: Enabling interrupt %d\n", nIRQ);
    #endif
        spin_lock_irqsave(&Adapter_Interrupts_ConcurrencyLock, flags);
        //set EIP93_REG_MASK_ENABLE register
        EIP93_INT_UnMask(&Adapter_EIP93_IOArea, Sources );

        spin_unlock_irqrestore(&Adapter_Interrupts_ConcurrencyLock, flags);
    }
}


/*----------------------------------------------------------------------------
 * Adapter_Interrupt_ClearAndEnable
 */
void
Adapter_Interrupt_ClearAndEnable(
        const int nIRQ)
{
    if (nIRQ >= ADAPTER_MAX_INTERRUPTS)
        return;

    // continue only we have the IRQ hooked
    if (Adapter_Interrupts_IRQ != -1)
    {
        unsigned long flags;
        const EIP93_INT_SourceBitmap_t Sources = 1 << nIRQ;
#ifndef RT_EIP93_DRIVER
        LOG_WARN(
            "Adapter_Interrupt_ClearAndEnable: "
            "Enabling interrupt %d\n",
            nIRQ);
#endif

        spin_lock_irqsave(&Adapter_Interrupts_ConcurrencyLock, flags);

        // acknowledge before enable
        // this ensures we do not get an old and remembered detected edge
        // when we enable the interrupt
        EIP93_INT_Acknowledge(
                &Adapter_EIP93_IOArea,
                Sources );

        EIP93_INT_UnMask(
                &Adapter_EIP93_IOArea,
                Sources );

        spin_unlock_irqrestore(&Adapter_Interrupts_ConcurrencyLock, flags);
    }
}


/*----------------------------------------------------------------------------
 * Adapter_Interrupt_Disable
 *
 * This function must be called from a sleepable context!
 */
void
Adapter_Interrupt_Disable(
        const int nIRQ)
{
#ifndef RT_EIP93_DRIVER
    LOG_WARN("Adapter_Interrupt_Disable: Disabling interrupt: 0x%x\n", nIRQ);
#endif
    if (nIRQ >= ADAPTER_MAX_INTERRUPTS)
        return;

    // continue only we have the IRQ hooked
    if (Adapter_Interrupts_IRQ != -1)
    {
        unsigned long flags;
        const EIP93_INT_SourceBitmap_t Sources = 1 << nIRQ;

   #ifndef RT_EIP93_DRIVER
        LOG_WARN("Adapter_Interrupt_Disable: Disabling interrupt %d\n", nIRQ);
   #endif
        spin_lock_irqsave(&Adapter_Interrupts_ConcurrencyLock, flags);
        //set EIP93_REG_MASK_DISABLE redister
          EIP93_INT_Mask(&Adapter_EIP93_IOArea, Sources );

        spin_unlock_irqrestore(&Adapter_Interrupts_ConcurrencyLock, flags);
#ifdef ADAPTER_EIP93PE_INTERRUPTS_TEST_RAW_STATUS
        if( RawInterruptTestStatus == false )
        {
            LOG_CRIT("\n Raw Interrupt Status Mask Test : Failed \n");
        }
        else
            LOG_CRIT("\n Raw Interrupt Status Mask Test : Passed \n");
#endif
    }
}

#ifdef ADAPTER_EIP93_PE_MODE_ARM
// Declare a tasklet struct
DECLARE_TASKLET( \
EIP93_Interrupt_BH_Result,Adapter_EIP93_BH_Handler_ResultGet, 0);
DECLARE_TASKLET( \
EIP93_Interrupt_BH_PutNext, Adapter_EIP93_BH_Handler_PktPut, 0);

#endif

/*----------------------------------------------------------------------------
 * Adapter_EIP93_InterruptHandler_DescriptorDone
 *
 * This function is invoked when the EIP93 has activated the rdr_thresh_irq
 * interrupt.
 */
void
Adapter_EIP93_InterruptHandler_DescriptorDone(void)
{
     tasklet_schedule(&EIP93_Interrupt_BH_Result);

}
/*----------------------------------------------------------------------------
 * Adapter_EIP93_InterruptHandler_DescriptorPut
 *
 * This function is invoked when the EIP93 has activated the cdr_thresh_irq
 * interrupt.
 */

void
Adapter_EIP93_InterruptHandler_DescriptorPut(void)
{
  tasklet_schedule(&EIP93_Interrupt_BH_PutNext);

}

#ifdef RT_EIP93_DRIVER
//static void crypto_irq_dispatch(void)
//{
//    do_IRQ(29);
//}
#endif

/*----------------------------------------------------------------------------
 * Adapter_Interrupts_Init
 */
bool
Adapter_Interrupts_Init(
         const int nIRQ  )
{
   ZEROINIT(Adapter_Interrupts_HandlerFunctions);

   spin_lock_init(&Adapter_Interrupts_ConcurrencyLock);

   if (nIRQ != -1)
   {
        int res;
   
//#ifdef RT_EIP93_DRIVER
//        set_vi_handler(nIRQ, crypto_irq_dispatch);
//#endif
        
        // install the top-half interrupt handler for the given IRQ
        res = request_irq(
                        nIRQ,
                        Adapter_Interrupts_Top_Half_Handler,
                        /*irqflags:*/0,
                        ADAPTER_DRIVER_NAME,
                        NULL);

        if (res)
        {
            LOG_CRIT(
                "Adapter_Interrupts_Init: "
                "request_irq returned %d\n",
                res);
        }
        else //success 
        {
            LOG_INFO(
                "Adapter_Interrupts_Init: "
                "Successfully hooked IRQ %d\n",
                nIRQ);

            Adapter_Interrupts_IRQ = nIRQ;
        }
   }



   LOG_WARN(
   "\nAdapter_Interrupts_Init: call back registered" );
   Adapter_Interrupts_IRQ = nIRQ;

   return true;
}



/*----------------------------------------------------------------------------
 * Adapter_Interrupts_UnInit
 */
void
Adapter_Interrupts_UnInit(void)
{
    if (Adapter_Interrupts_IRQ != -1)
    {
        // disable all interrupts

        EIP93_INT_Mask(&Adapter_EIP93_IOArea, 0xffffffff );
         // unhook the interrupt
        free_irq(Adapter_Interrupts_IRQ, NULL);
        Adapter_Interrupts_IRQ = -1;

        LOG_WARN(
   "\nAdapter_Interrupts_UnInit: call back un-registered with VTBAL" );

    }
}

#else
 ;
#endif // #ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
/* end of file adapter_interrupts.c */

