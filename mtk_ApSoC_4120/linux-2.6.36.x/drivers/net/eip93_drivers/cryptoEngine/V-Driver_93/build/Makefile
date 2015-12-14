#############################################################################
#
#    Copyright (c) 2008-2009 SafeNet Inc. All Rights Reserved.
#
# This confidential and proprietary software may be used only as authorized
# by a licensing agreement from SafeNet.
#
# The entire notice above must be reproduced on all authorized copies that
# may only be made to the extent permitted by a licensing agreement from
# SafeNet.
#
# For more information or support, please go to our online support system at
# https://oemsupport.safenet-inc.com or e-mail to oemsupport@safenet-inc.com
#
##############################################################################

##############################################################################
##  Makefile for the V-Driver_93 Example Application
##  How to use :
##  i)    $ make
##  ii)   For cleaning : $ make clean
##############################################################################

#### User Edit Section : Variables to be set by the User
##   User may not need to modify anything other than this section

  ##-->: { Here follow the variables to be set by the User
  
	# Set KERNEL_DIR to the path to the Kernel Source directory for which you
	# wish to compile.
	#KERNEL_DIR:=

	# Set ARCH according to the target architecture
	# supported values: x86 and ppc
	#ARCH:=x86
	#ARCH:=ppc

	# Set CROSS_COMPILE to the path to the cross compiler binutils
	# concatenated with the prefix they have before normal binutils name
	# For example :
	# If we have cross compiler for Power-PC in /opt/eldk/target/usr/bin/
	# by the file name ppc_4xxFP-gcc, we set it as below :
	#CROSS_COMPILE:=/opt/eldk/target/usr/bin/

  ##<--:  } End of User Edit Section

#### User should not need to modify anything below this line
##############################################################################

# Make sure that ARCH, KERNEL_DIR and CROSS_COMPILE are set

ifndef KERNEL_DIR
  ERROR_KERNEL_DIR_NOT_SET:=YES
endif

#ifeq (${ARCH},x86)
#  HOST_COMPILER:=gcc
#  COMPILER:=gcc
#  # cs_*.h files respond to ARCH_X86
#  EXTRA_CFLAGS += -DARCH_X86
#else ifeq (${ARCH},ppc)
#  ifndef CROSS_COMPILE
#    ERROR_CROSS_COMPILE_NOT_SET:=YES
#  endif
#  HOST_COMPILER:=gcc
#  COMPILER:=${CROSS_COMPILE}gcc
#else
#  ERROR_ARCH_NOT_SET:=YES
#endif

  COMPILER:=mips-linux-uclibc-gcc -mips32r2 -msoft-float
  HOST_COMPILER:=gcc
ifndef ARCH
  ERROR_ARCH_NOT_SET:=YES
endif

#ifeq ($(KERNELRELEASE),)
#   PWD:=$(shell pwd)
#endif
PWD :=drivers/net/eip93_drivers/cryptoEngine/V-Driver_93/build

SRC_APP=..
SRC_KIT=../../Kit

PATH_BUILD=$(PWD)
PATH_APP=$(PWD)/..
PATH_KIT=$(PWD)/../../Kit


# Include Paths
INCLUDE_APP_CONFIG:= -I$(PATH_BUILD)

INCLUDE_APP:= \
 -I$(PATH_APP)/incl \
 -I$(PATH_APP)/src

INCLUDE_KIT:= \
 -I$(PATH_KIT)/DriverFramework/incl \
 -I$(PATH_KIT)/EIP93_SL/incl \
 -I$(PATH_KIT)/Log/incl \
 -I$(PATH_KIT)/Log/src/printk \
 -I$(PATH_KIT)/RingHelper/incl \
 -I$(PATH_KIT)/DMABuf/incl \
 -I$(PATH_KIT)/AddrTrans/incl

INCLUDE_FLAGS_ALL:= \
  $(INCLUDE_APP_CONFIG) \
  $(INCLUDE_APP) \
  $(INCLUDE_KIT)

ifeq (${ARCH},ppc)
   INCLUDE_FLAGS_ALL += -I$(strip $(KERNEL_DIR))/arch/ppc
   INCLUDE_FLAGS_ALL += -I$(strip $(KERNEL_DIR))/arch/ppc/include
   INCLUDE_FLAGS_ALL += -I$(strip $(KERNEL_DIR))/include
endif

# Compiler Flags
WARNING_FLAGS=
DEBUG_FLAGS=-g
CODE_COVERAGE_FLAGS=
PROFILING_FLAGS=
BACKWARD_COMPATIBILITY_FLAGS=

EXTRA_CFLAGS += $(BACKWARD_COMPATIBILITY_FLAGS)
EXTRA_CFLAGS += $(INCLUDE_FLAGS_ALL)
EXTRA_CFLAGS += $(WARNING_FLAGS)
EXTRA_CFLAGS += $(DEBUG_FLAGS)
EXTRA_CFLAGS += $(CODE_COVERAGE_FLAGS)
EXTRA_CFLAGS += $(PROFILING_FLAGS)
EXTRA_CFLAGS += -DRT_EIP93_DRIVER
#EXTRA_CFLAGS += -DRT_EIP93_DRIVER_DEBUG

.PHONY = clean clean_module

default:	vdriver_93_k

obj-m	:= vdriver_93_k.o

# relative paths required here!
vdriver_93_k-objs:= \
  $(SRC_KIT)/EIP93_SL/src/eip93_sl.o \
  $(SRC_KIT)/EIP93_SL/src/eip93_arm.o \
  $(SRC_KIT)/EIP93_SL/src/eip93_dhm.o \
  $(SRC_KIT)/Log/src/log.o \
  $(SRC_KIT)/RingHelper/src/ringhelper.o \
  $(SRC_KIT)/DriverFramework/src/LinuxKernel_PCI/hwpal_device.o \
  $(SRC_KIT)/DriverFramework/src/LinuxKernel_PCI/hwpal_dma_resource.o \
  $(SRC_KIT)/DMABuf/src/kmalloc/adapter_dmabuf.o \
  $(SRC_APP)/src/adapter_linuxkernelmodule.o \
  $(SRC_APP)/src/adapter_addrtrans.o \
  $(SRC_APP)/src/adapter_eip93.o \
  $(SRC_APP)/src/adapter_global.o \
  $(SRC_APP)/src/adapter_pec_eip93_dhm.o \
  $(SRC_APP)/src/adapter_pec_eip93_arm.o \
  $(SRC_APP)/src/adapter_interrupts_km.o


vdriver_93_k:
	@if [ "$(ERROR_ARCH_NOT_SET)" == "YES" ]; then \
	  echo "ARCH not set or unsupported"; \
	  exit 1; \
	fi
	@if [ "$(ERROR_KERNEL_DIR_NOT_SET)" == "YES" ]; then \
	  echo "KERNEL_DIR not set"; \
	  exit 1; \
	fi
	@if [ "$(ERROR_CROSS_COMPILE_NOT_SET)" == "YES" ]; then \
	  echo "CROSS_COMPILE not set"; \
	  exit 1; \
	fi
	
#	@echo "EXTRA_CFLAGS: $(EXTRA_CFLAGS)";
	make ARCH=$(ARCH) CROSS_COMPILE=$(strip $(CROSS_COMPILE)) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:	clean_module

clean_module:
	# this is run in $PATH_BUILD where the Makefile resides
	find $(PATH_APP) \( -name "*.o" -o -name ".*.cmd" \) -type f -print | xargs rm -f
	find $(PATH_KIT) \( -name "*.o" -o -name ".*.cmd" \) -type f -print | xargs rm -f
	rm -rf .tmp_versions
	rm -f *.o  .*.cmd  .*.flags  *.mod.c  *.ko  *.symvers  *.markers  *.order

# end of file
