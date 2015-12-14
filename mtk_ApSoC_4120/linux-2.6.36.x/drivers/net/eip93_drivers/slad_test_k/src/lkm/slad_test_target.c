/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 SafeNet Inc

*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/

/***********************************************************
* Header files.                                            
*********************************************************/


#define EXPORT_SYMTAB

#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/cache.h>
/*#include <linux/config.h>*/
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
//#include <asm/ibm44x.h>

#include "slad_test.h"
#include "slad_test_target.h"

#include "slad_osal.h"

MODULE_LICENSE ("Proprietary");


/****************************************************************
* Definitions and macros.
*****************************************************************/



#ifdef RT_EIP93_DRIVER
// fix slad_test_major_nr to 234, so we can build a charster device in advance
#define SLAD_TEST_MAJOR_NR 234 
#else
/* If major number not defined, use 0 (dynamic assignment). */
#ifndef SLAD_TEST_MAJOR_NR
#define SLAD_TEST_MAJOR_NR 0
#endif
#endif

#define SLAD_TEST_NO        1

#ifdef RT_EIP93_DRIVER_DEBUG
/*----------------------------------------------------------------------------
 * rt_dump_register
 *
 * This function dumps an Crypto Engine's register.
 * (define RT_DUMP_REGISTER in cs_sladtestapp.h before use it!)
 *
 * Use rt_dump_register(0xfff) to dump all registers.
 * Use rt_dump_register(register_offset) to dump a specific register.
 * The register_offset can be referred in Programmer-Manual.pdf
 */
void
rt_dump_register(
        unsigned int offset)
{
#ifdef RT_DUMP_REGISTER
    unsigned int register_base = 0xbfb70000;
    unsigned int value = 0, i = 0;

    offset &= 0xfff;
    if(offset != 0xfff) /* print for a specific register */
    {
        value = ioread32((void __iomem *)(register_base+offset));
        printk("<address>\t<value>\n0x%08x\t0x%08x\n", register_base+offset, value);
    }
    else /* print for all registers */
    {
        printk("\n[Command Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0; i<=0x1c; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        
        printk("\n[Descriptor Ring Configuration Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0x80; i<=0x9c; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        
        printk("\n[Configuration Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0x100; i<=0x104; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        for(i=0x10c; i<=0x118; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
            printk("0x%08x\t0x%08x\n", register_base+0x120, value);
            printk("0x%08x\t0x%08x\n", register_base+0x1d0, value);
            
        printk("\n[Clock Control and Debug Interface Registers:]\n");
        printk("<address>\t<value>\n");
            printk("0x%08x\t0x%08x\n", register_base+0x1e0, value);
            
        printk("\n[Device Revision and Options Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0x1f4; i<=0x1fc; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        
        printk("\n[Interrupt Control Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0x200; i<=0x214; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        
        printk("\n[SA Registers:]\n");
        printk("<address>\t<value>\n");
        for(i=0x400; i<=0x404; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        for(i=0x420; i<=0x444; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        for(i=0x468; i<=0x478; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }
        for(i=0x500; i<=0x528; i+=0x4){
            value = ioread32((void __iomem *)(register_base+i));
            printk("0x%08x\t0x%08x\n", register_base+i, value);
        }       
    }
#endif 
}
#endif

/*****************************************************************
* Local variables.
******************************************************************/

static const char slad_test_module_name[] = "slad_test_k";
static int slad_test_major_nr = SLAD_TEST_MAJOR_NR;

/******************************************************************
* Linux device driver file operations.
*******************************************************************/

static int
slad_test_fop_open (struct inode *inode, struct file *file)
{
  unsigned int minor = iminor (inode);

  if (minor <= SLAD_TEST_NO)
    {
      //LOG_CRIT ("slad_test_fop_open(); minor %d\n", minor);
      return 0;

    }
  else
    {

      LOG_CRIT ("slad_test_fop_open(); BAD minor %d\n", minor);
      return -1;
    }
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
static int
slad_test_fop_ioctl (struct file *filp, 
                     unsigned int cmd,
                     unsigned long arg)
#else
static int
slad_test_fop_ioctl (struct inode *inode, struct file *file, 
                     unsigned int cmd,
                     unsigned long arg)
#endif
{
  //LOG_CRIT ("slad_test_fop_ioctl(); so what?\n");
  return 0;
}


static ssize_t
slad_test_fop_cread (struct file *filp, char *buf, size_t count,
                     loff_t * ppos)
{
  unsigned int minor = MINOR (filp->f_dentry->d_inode->i_rdev);

  if (minor < SLAD_TEST_NO)
    {

      //  LOG_CRIT ("slad_test_fop_cread(); so what?\n");

    }
  else
    {

      LOG_CRIT ("slad_test_fop_cread(); BAD minor %d\n", minor);
      return -1;
    }

  return 1;
}


static ssize_t
slad_test_fop_cwrite (struct file *filp, const char *buf, 
                      size_t count,
                      loff_t * ppos)
{
  unsigned int minor = MINOR (filp->f_dentry->d_inode->i_rdev);

  SLAD_TEST_DRVCMD drvcmd = { 0 };
  UINT32 st = 0;

  osal_copy_from_app (TRUE, &drvcmd, (void *) buf, 
        sizeof (SLAD_TEST_DRVCMD));

  if (minor < SLAD_TEST_NO)
    {
      switch (drvcmd.cmd)
        {
        case SLAD_TEST_CMD_CONFIGURE_PE:

#ifdef SLAD_TEST_BUILD_FOR_PE
          st = _slad_test_configure_pe (TRUE, drvcmd.pe_confs); //will call PEC_Capabilities_Get & PEC_init (CDR/RDR are allocated and ARM mode is activated)
#endif
          break;

        case SLAD_TEST_CMD_CONFIGURE_PKA:
#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
          st = _slad_test_configure_pka (TRUE, drvcmd.pka_confs);
#endif
          break;

        case SLAD_TEST_CMD_CONFIGURE_RNG:
#ifdef SLAD_TEST_BUILD_FOR_RNG
          st = _slad_test_configure_rng (TRUE, drvcmd.rng_confs);
#endif
          break;

        case SLAD_TEST_CMD_CONFIGURE_TEST:
#ifdef SLAD_TEST_BUILD_FOR_PE
          st = _slad_test_configure_test (TRUE, drvcmd.test_confs);
#endif
          break;

        case SLAD_TEST_CMD_NOTE_TESTS_N_DEVICE:
          st =
            _slad_test_note_tests_n_device (TRUE, 
                    drvcmd.test_device_params);
          break;

        case SLAD_TEST_CMD_NOTE_PE_TEST_RECORD:
#ifdef SLAD_TEST_BUILD_FOR_PE
          st = _slad_test_note_pe_test_record (TRUE, drvcmd.pe_tr); //will call PEC_Capabilities_Get, PEC_SA_Register, PEC_Packet_Put, PEC_Packet_Get, PEC_SA_UnRegister, PEC_UnInit
#endif
          break;

        case SLAD_TEST_CMD_NOTE_PKA_RECORD:
#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
          st = _slad_test_note_pka_record (TRUE, drvcmd.pka_record, drvcmd.num_pka_pkts);
#endif
          break;

        case SLAD_TEST_CMD_NOTE_RNG_RECORD:
#ifdef SLAD_TEST_BUILD_FOR_RNG
          st = _slad_test_note_rng_record (TRUE, drvcmd.rng_record);
#endif
          break;

        case SLAD_TEST_UNINIT_DEVICES:
#ifdef SLAD_TEST_BUILD_FOR_PE
          st = slad_test_uninit_devices (); //will call PEC_UnInit
#endif
          break;

        default:
          printk ("\n Invalid command \n");
          st = SLAD_TEST_STAT_COMMAND_INVALID;
          break;
        }


      drvcmd.status = st;

      osal_copy_to_app (TRUE, (void *) buf, &drvcmd,
                        sizeof (SLAD_TEST_DRVCMD));

    }
  else
    {

      LOG_CRIT ("slad_test_fop_cwrite(); BAD minor %d\n", minor);
      return -1;
    }

  return 1;
}


static int
slad_test_fop_release (struct inode *inode, struct file *filp)
{
  //LOG_CRIT ("slad_test_fop_release();\n");
  return 0;
}


/* File Operations Structure. */
static struct file_operations slad_test_fops = {
  .owner = THIS_MODULE,         /* module owner */
  .read = slad_test_fop_cread,  /* read */
  .write = slad_test_fop_cwrite,        /* write */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	.unlocked_ioctl =     slad_test_fop_ioctl,	/* ioctl */
#else	
    .ioctl =      slad_test_fop_ioctl,			/* ioctl */
#endif  
  .open = slad_test_fop_open,   /* open */
  .release = slad_test_fop_release,     /* release */
};







/*************************************************************
*
**************************************************************/
static int
slad_test_init (void)
{
  int status;

  /* Register this driver. */
  status =
    register_chrdev (slad_test_major_nr, slad_test_module_name,
                     &slad_test_fops);

  switch (status)
    {

    case -EINVAL:

      printk
("SLAD Test Module: '%s' FAILED to load, major number %d is invalid.\n",
         slad_test_module_name, slad_test_major_nr);
      break;

    case -EBUSY:

      printk
 ("SLAD Test Module: '%s' FAILED to load, major number %d is in use.\n",
         slad_test_module_name, slad_test_major_nr);
      break;

    default:
      if (slad_test_major_nr == 0)
        {
          slad_test_major_nr = status;
        }

      printk (
"SLAD Test Module: '%s', loaded successfully, major=%d\n",
              slad_test_module_name, slad_test_major_nr);

      break;
    }

  /* Status will contain the return code for register_chrdev */
  /* a zero or positive return code indicates success. */
  if (status > 0)
    {
      status = 0;

    }
  return status;
}


/**************************************************************
*
***************************************************************/
static void
slad_test_exit (void)
{

  unregister_chrdev (slad_test_major_nr, slad_test_module_name);

  printk (
  "SLAD Test Module - '%s' unloaded\n", slad_test_module_name);

}


module_init (slad_test_init);
module_exit (slad_test_exit);
