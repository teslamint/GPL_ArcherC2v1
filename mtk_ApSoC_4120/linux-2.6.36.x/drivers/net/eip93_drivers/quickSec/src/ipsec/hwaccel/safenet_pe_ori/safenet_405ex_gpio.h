/*h*
* File:		safenet_405ex_gpio.h
*
* 405EX platform GPIO access functions for Linux kernel mode.
*  
* Usage:
*  
* For Initialization:
* ===================
*   
*   #include safenet_405ex_gpio.h
*     ...
*   // call GPIO init function in your initialization routine:
*   // this step can be skipped, because this function is called automatically 
*   // anyway
*   // however, if gpio_out functions (see below) are intended to be used in
*   // atomic context
*   // (interrupt BHs and THs, softirq), then GPIO init function must be 
*   // called explicitly
*   // in non-atomic context
*   safenet_linux_gpio_init();
*     ...
*
* For using during testing:
* =========================
*
*   #include safenet_405ex_gpio.h
*     ...
*   // call GPIO out function:
*   safenet_linux_gpio_out_high(4);
*
*   // some code you'd like to measure:
*     ... 
*
*   safenet_linux_gpio_out_low(4);
*     ...
*    
* Note: For testing purposes it is possible to use GPIO signal numbers
*       4-7 and 12-15 when calling safenet_linux_gpio_out.

* For Clean-up:
* ===================
*   
*   #include safenet_405ex_gpio.h
*     ...
*   // call GPIO uninit function in your cleanup routine:
*   // this step is optional, as cleanup is not absolutely neccessary
*   safenet_linux_gpio_uninit();
*     ...
*
*
* Copyright (c) 2007 SafeNet, Inc. All rights reserved.
*
* The source code provided in this file is licensed perpetually and
* royalty-free to the User for exclusive use as sample software to be used in
* developing derivative code based on SafeNet products and technologies. The
* SafeNet source code shall not be redistributed in part or in whole, nor as
* part of any User derivative product containing source code, without the
* express written consent of SafeNet.
*
*
* Edit History:
*
*Initial revision
* 14-11-2007 abykov@safenet-inc.com 	Created.
*/


#ifndef  SAFENET_405EX_GPIO_H
#define  SAFENET_405EX_GPIO_H

#undef SAFENET_DEBUG_USE_GPIO

#ifdef SAFENET_DEBUG_USE_GPIO

void *gpio_base __attribute__ ((weak)) = NULL;


/*  Note: For testing purposes it is possible to use GPIO signal numbers
        4-7 and 12-15 when calling safenet_linux_gpio_out.
*/

bool safenet_linux_gpio_init(void) __attribute__ ((weak));
inline void
safenet_linux_gpio_out_high(unsigned gpio_sig_num) __attribute__ ((weak));
inline void 
safenet_linux_gpio_out_low(unsigned gpio_sig_num) __attribute__ ((weak));
void safenet_linux_gpio_out_hard(unsigned gpio_sig_num, 
				 bool high) __attribute__ ((weak));
void safenet_linux_gpio_uninit(void) __attribute__ ((weak));


inline void safenet_linux_gpio_out_high(unsigned gpio_sig_num)
{ 
        ulong val;
	if (unlikely(!gpio_base))
  	  safenet_linux_gpio_init();
	/* bn <= '1' */ 
	val = in_be32((gpio_base+(GPIO0_OR-GPIO_BASE))); 
  	out_be32((gpio_base+(GPIO0_OR-GPIO_BASE)), val | 1 << (31-gpio_sig_num) ); 
}


inline void safenet_linux_gpio_out_low(unsigned gpio_sig_num)
{ 
        ulong val;
	if (unlikely(!gpio_base))
  	  safenet_linux_gpio_init();
	/* bn <= '0' */ 
	val = in_be32((gpio_base+(GPIO0_OR-GPIO_BASE))); 
        out_be32((gpio_base+(GPIO0_OR-GPIO_BASE)), val &
		 ~(1 << (31-gpio_sig_num)) );
}



void safenet_linux_gpio_out_hard(unsigned gpio_sig_num, bool high)
{ 
        ulong val;
        ulong high_mask;
        ulong gpio_mask;
        ulong gpio_sig_num_mask = 1<<gpio_sig_num;
        static ulong already_called = 0;
        
        if (unlikely(gpio_sig_num > 31))
          return;

        if (unlikely(!gpio_base))
        {
	  if (net_ratelimit())
  	    printk(KERN_INFO "Safenet linux gpio: Not initialized!\n");
	  return;
	}
                
        high_mask = 1 << (31-gpio_sig_num);
        gpio_mask = ~((1 << (31-2*gpio_sig_num))
                       | 
                      (1 << (30-2*gpio_sig_num))
                     );
        
	/* bn <= '0/1' */ 
	val = in_be32((gpio_base+(GPIO0_OR-GPIO_BASE))); 
	if (high)
  	  out_be32((gpio_base+(GPIO0_OR-GPIO_BASE)), val | high_mask ); 
  	else
    	  out_be32((gpio_base+(GPIO0_OR-GPIO_BASE)), val & ~high_mask );
    	
    	
    	if (unlikely(!(gpio_sig_num_mask & already_called)))
    	{
    	  already_called |= gpio_sig_num_mask;
	  /* ODR: bn <= '0' Enable associate output driver */  
	  val = in_be32((gpio_base+(GPIO0_ODR-GPIO_BASE))); 
	  out_be32((gpio_base+(GPIO0_ODR-GPIO_BASE)), val & ~high_mask ); 
	  /* TCR: bn <= '1' Enable associate output driver */  
	  val = in_be32((gpio_base+(GPIO0_TCR-GPIO_BASE))); 
	  out_be32((gpio_base+(GPIO0_TCR-GPIO_BASE)), val | high_mask ); 
	  if (gpio_sig_num < 16)
	  {
  	   /* OSRL: b2n,b2n+1 <= '00' select GPIO0_OR */ 
	   val = in_be32((gpio_base+(GPIO0_OSRL-GPIO_BASE))); 
  	   out_be32((gpio_base+(GPIO0_OSRL-GPIO_BASE)), val & gpio_mask);
	   /* TSRL:  b2n,b2n+1 <= '00' select TCR */
	   val = in_be32((gpio_base+(GPIO0_TSRL-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_TSRL-GPIO_BASE)), val & gpio_mask);
	   /* ISR1L */
	   val = in_be32((gpio_base+(GPIO0_ISR1L-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR1L-GPIO_BASE)), val & gpio_mask);
	   /* ISR2L */
	   val = in_be32((gpio_base+(GPIO0_ISR2L-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR2L-GPIO_BASE)), val & gpio_mask);
	   /* ISR3L */
	   val = in_be32((gpio_base+(GPIO0_ISR3L-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR3L-GPIO_BASE)), val & gpio_mask);
	 }
	 else
	 {
  	   /* OSRH: b2n,b2n+1 <= '00' select GPIO0_OR */ 
	   val = in_be32((gpio_base+(GPIO0_OSRH-GPIO_BASE))); 
  	   out_be32((gpio_base+(GPIO0_OSRH-GPIO_BASE)), val & gpio_mask);
	   /* TSRH:  b2n,b2n+1 <= '00' select TCR */
	   val = in_be32((gpio_base+(GPIO0_TSRH-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_TSRH-GPIO_BASE)), val & gpio_mask);
	   /* ISR1H */
	   val = in_be32((gpio_base+(GPIO0_ISR1H-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR1H-GPIO_BASE)), val & gpio_mask);
	   /* ISR2H */
	   val = in_be32((gpio_base+(GPIO0_ISR2H-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR2H-GPIO_BASE)), val & gpio_mask);
	   /* ISR3H */
	   val = in_be32((gpio_base+(GPIO0_ISR3H-GPIO_BASE)));
	   out_be32((gpio_base+(GPIO0_ISR3H-GPIO_BASE)), val & gpio_mask);
	 }
	}
}

bool safenet_linux_gpio_init(void)
{ 
  if (!gpio_base)
  {
    printk(KERN_INFO "Safenet linux gpio: INITIALIZING...\n");

    if ((gpio_base = ioremap_nocache(GPIO_BASE, 0x100)) == NULL)
    {
	printk(KERN_INFO "Safenet linux gpio: can't get" \
	       " remap phys address 0x%lx\n",GPIO_BASE);
	return false;
    }
  }
  /*  initializing our debug gpio lines: */
  safenet_linux_gpio_out_hard(4, false);
  safenet_linux_gpio_out_hard(5, false);
  safenet_linux_gpio_out_hard(6, false);
  safenet_linux_gpio_out_hard(7, false);
  safenet_linux_gpio_out_hard(12, false);
  safenet_linux_gpio_out_hard(13, false);
  safenet_linux_gpio_out_hard(14, false);
  safenet_linux_gpio_out_hard(15, false);
 
  return true;
}


void safenet_linux_gpio_uninit(void)
{ 
  if (gpio_base)
  {
    printk(KERN_INFO "Safenet linux gpio: CLEANING UP...\n");
    iounmap((void __iomem *)gpio_base);
    /* release_mem_region(gpio_base, 0x100); */
    gpio_base = NULL;
  }
}

#else /* SAFENET_DEBUG_USE_GPIO */

  #define safenet_linux_gpio_init() 1==1
  #define safenet_linux_gpio_out_high(gpio_sig_num) do {} while (0)
  #define safenet_linux_gpio_out_low(gpio_sig_num) do {} while (0)
  #define safenet_linux_gpio_out_hard(gpio_sig_num, high) do {} while (0)
  #define safenet_linux_gpio_uninit() do {} while (0)

#endif /* SAFENET_DEBUG_USE_GPIO  */


#endif /* SAFENET_405EX_GPIO_H */

