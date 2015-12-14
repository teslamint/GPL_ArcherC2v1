/*
 * (C) Copyright 2003
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <common.h>
#include <command.h>
#include <asm/addrspace.h>
//#include "LzmaDecode.h"

//#define MAX_SDRAM_SIZE	(64*1024*1024)
//#define MIN_SDRAM_SIZE	(8*1024*1024)
#define MAX_SDRAM_SIZE	(256*1024*1024)
#define MIN_SDRAM_SIZE	(8*1024*1024)

#ifdef SDRAM_CFG_USE_16BIT
#define MIN_RT2880_SDRAM_SIZE	(16*1024*1024)
#else
#define MIN_RT2880_SDRAM_SIZE	(32*1024*1024)
#endif


/*
 * Check memory range for valid RAM. A simple memory test determines
 * the actually available RAM size between addresses `base' and
 * `base + maxsize'.
 */
long get_ram_size(volatile long *base, long maxsize)
{
	volatile long *addr;
	long           save[32];
	long           cnt;
	long           val;
	long           size;
	int            i = 0;

	for (cnt = (maxsize / sizeof (long)) >> 1; cnt > 0; cnt >>= 1) {
		addr = base + cnt;	/* pointer arith! */
		save[i++] = *addr;
		
		*addr = ~cnt;

		
	}

	addr = base;
	save[i] = *addr;

	*addr = 0;

	
	if ((val = *addr) != 0) {
		/* Restore the original data before leaving the function.
		 */
		*addr = save[i];
		for (cnt = 1; cnt < maxsize / sizeof(long); cnt <<= 1) {
			addr  = base + cnt;
			*addr = save[--i];
		}
		return (0);
	}

	for (cnt = 1; cnt < maxsize / sizeof (long); cnt <<= 1) {
		addr = base + cnt;	/* pointer arith! */

	//	printf("\n retrieve addr=%08X \n",addr);
			val = *addr;
		*addr = save[--i];
		if (val != ~cnt) {
			size = cnt * sizeof (long);
			
		//	printf("\n The Addr[%08X],do back ring  \n",addr);
			
			/* Restore the original data before leaving the function.
			 */
			for (cnt <<= 1; cnt < maxsize / sizeof (long); cnt <<= 1) {
				addr  = base + cnt;
				*addr = save[--i];
			}
			return (size);
		}
	}

	return (maxsize);
}



long int initdram(int board_type)
{
	ulong size, max_size       = MAX_SDRAM_SIZE;
	ulong our_address;
  
	asm volatile ("move %0, $25" : "=r" (our_address) :);

	/* Can't probe for RAM size unless we are running from Flash.
	 */
#if 0	 
	#if defined(CFG_RUN_CODE_IN_RAM)

	printf("\n In RAM run \n"); 
    return MIN_SDRAM_SIZE;
	#else

	printf("\n In FLASH run \n"); 
    return MIN_RT2880_SDRAM_SIZE;
	#endif
#endif 
    
#if defined (RT2880_FPGA_BOARD) || defined (RT2880_ASIC_BOARD)
	if (PHYSADDR(our_address) < PHYSADDR(PHYS_FLASH_1))
	{
	    
		//return MIN_SDRAM_SIZE;
		//fixed to 32MB
		printf("\n In RAM run \n");
		return MIN_SDRAM_SIZE;
	}
#endif
	 


	size = get_ram_size((ulong *)CFG_SDRAM_BASE, MAX_SDRAM_SIZE);
	if (size > max_size)
	{
		max_size = size;
	//	printf("\n Return MAX size!! \n");
		return max_size;
	}
//	printf("\n Return Real size =%d !! \n",size);
	return size;
	
}

int checkboard (void)
{
	puts ("Board: Ralink APSoC ");
	return 0;
}
#include <rt_mmap.h>

#define u32 u_long

int setGpioData(u32 gpio, u32 data)
{
	u32 bit = 0;
	u32 reg = 0;
	u32 tmp = 0;
	/* Get reg and bit of the reg */
	if (gpio > 72)
	{
		puts("Boot: setGpioData() Unsupport GPIO\n");
		return -1;
	}
	if (gpio <= 23)
	{
		/* RALINK_REG_PIODATA for GPIO 0~23 */
		reg = RALINK_PIO_BASE + 0x20;
		bit = (1 << gpio);
	}
	else if (gpio <= 39)
	{
		/* RALINK_REG_PIO3924DATA for GPIO 24~39 */
		reg = RALINK_PIO_BASE + 0x48;
		bit = (1 << (gpio - 24));
	}
	else if (gpio <= 71)
	{
		/* RALINK_REG_PIO7140DATA for GPIO 40~71 */
		reg = RALINK_PIO_BASE + 0x70;
		bit = (1 << (gpio - 40));
	}
	else /* gpio 72 */
	{
		/* RALINK_REG_PIO72DATA for GPIO 72 */
		reg = RALINK_PIO_BASE + 0x98;
		bit = 1;
	}

	/* Set to reg base on bit and data */
	tmp = le32_to_cpu(*(volatile u32 *)(reg));
	if (0 == data)
	{
		tmp &= ~bit;
	}
	else
	{
		tmp |= bit;
	}
	*(volatile u32 *)(reg) = tmp;
	return 0;
}


int initTpProduct(void)
{
	u32 gpiomode;
	u32 tmp;
#ifdef TP_MODEL_C2V1
	printf("------------------\n"
		   " Archer C2 v1.0.0 \n"
		   "------------------\n");
#elif TP_MODEL_C20iV1
	printf("------------------\n"
		   "Archer C20i v1.0.0\n"
		   "------------------\n");
#else
	/* NOP */
#endif
	/* GPIO Mode */
	gpiomode = le32_to_cpu(*(volatile u32 *)(RALINK_SYSCTL_BASE + 0x60));

	gpiomode |= (0x01) | (0x1C) | (0x8000) | (0x2000);
	*(volatile u32 *)(RALINK_SYSCTL_BASE + 0x60) = cpu_to_le32(gpiomode);

	/* OUTPUT GPIO
	 * GPIO1: LAN
	 * GPIO11:USB
	 * GPIO39:WPS
	 * GPIO40:WAN
	 * GPIO41:RESET Switch 
	 * GPIO72:WLAN(2.4G)
	 */
	/* Set Direction to output */
	/* RALINK_REG_PIODIR for GPIO 0~23 */
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_PIO_BASE + 0x24));
	tmp |= ((1 << 1) | (1 << 11));
	*(volatile u32 *)(RALINK_PIO_BASE + 0x24) = tmp;

	/* RALINK_REG_PIO3924DIR for GPIO 24~39 */
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_PIO_BASE + 0x4C));
	tmp |= (1 << (39-24));
	*(volatile u32 *)(RALINK_PIO_BASE + 0x4C) = tmp;
#ifdef TP_MODEL_C2V1
	/* RALINK_REG_PIO7140DIR for GPIO 40~71 */
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_PIO_BASE + 0x74));
	tmp |= ((1 << (40-40)) | (1 << (41-40)));
	*(volatile u32 *)(RALINK_PIO_BASE + 0x74) = tmp;
#else
	/* RALINK_REG_PIO7140DIR for GPIO 40~71 */
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_PIO_BASE + 0x74));
	tmp |= (1 << (40-40));
	*(volatile u32 *)(RALINK_PIO_BASE + 0x74) = tmp;
#endif

	/* RALINK_REG_PIO72DIR for GPIO 72 */
	*(volatile u32 *)(RALINK_PIO_BASE + 0x9C) = 0x1;

	/* Led */
#ifdef TP_MODEL_C2V1
	setGpioData(41, 0);
#endif
	setGpioData(1, 0);
	setGpioData(11, 0);
	setGpioData(39, 0);
	setGpioData(40, 0);
	setGpioData(72, 0);
	udelay (1000 * 100 * 10);/* 1s */
	setGpioData(1, 1);
	setGpioData(11, 1);
	setGpioData(39, 1);
	setGpioData(40, 1);
	setGpioData(72, 1);
#ifdef TP_MODEL_C2V1
	setGpioData(41, 1);	
#endif

	return 0;
}

/* port from kernel by wanghao  */
#define RALINK_PRGIO_ADDR		RALINK_PIO_BASE // Programmable I/O
#define RALINK_REG_PIODIR		(RALINK_PRGIO_ADDR + 0x24)
#define RALINK_REG_PIODATA		(RALINK_PRGIO_ADDR + 0x20)
int getGpioData(u32 gpio, u32 *data)
{
	u32 bit = 0;
	u32 reg = 0;
	u32 tmp = 0;

	/* INPUT GPIO
	 * GPIO2: WIFI
	 * GPIO13:RESET/WPS
	 * GPIO42:Switch IRQ
	 */
	/* Set Direction to input */
	/* RALINK_REG_PIODIR for GPIO 0~23 */
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
	tmp &= ~((1 << 2) | (1 << 13));
	*(volatile u32 *)(RALINK_REG_PIODIR) = tmp;	
	
	/* Get reg and bit of the reg */
	if (gpio > 72)
	{
		printf(": %s, Unsupport GPIO(%d)\n", __FUNCTION__, gpio);
		return -1;
	}
	if (gpio <= 23)
	{
		/* RALINK_REG_PIODATA for GPIO 0~23 */
		reg = RALINK_REG_PIODATA;
		bit = (1 << gpio);
	}

	/* Get to reg base on bit */
	tmp = le32_to_cpu(*(volatile u32 *)(reg));
	if (bit & tmp)
	{
		*data = 1;
	}
	else
	{
		*data = 0;
	}
	return 0;
}
/* port end  */

#if 0
value = le32_to_cpu(*(volatile u_long *)(RALINK_SYSCTL_BASE + 0x0034));
u32 gpiomode;
	gpiomode = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOMODE));
	
	/* C2, yuanshang, 2013-11-14
	 * GPIO1,GPIO2: I2C GPIO Mode(bit0)
	 * GPIO11,GPIO13:	UART Full(bit4:2)
	 * GPIO39:	SPI GPIO(bit11) & SPI Ref(bit12) [no need to set bit 1] 
	 * GPIO40,GPIO41,GPIO42:	EPHY LED(bit15)
	 * GPIO72:	WLED GPIO(bit13)
	 */
	/*gpiomode |= RALINK_GPIOMODE_DFT;*/
	gpiomode |= (RALINK_GPIOMODE_I2C) | (RALINK_GPIOMODE_UARTF) | (RALINK_GPIOMODE_EPHY) | (RALINK_GPIOMODE_WLED);
	*(volatile u32 *)(RALINK_REG_GPIOMODE) = cpu_to_le32(gpiomode);


#endif

