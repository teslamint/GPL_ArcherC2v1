ifeq ($(PATH_DRIVER_SYMVERS),)
PATH_DRIVER_SYMVERS:=$(KERNEL_DIR)
endif
EXTRA_CFLAGS += -DRT_EIP93_DRIVER -DSLAD_PLATFORM_LINUX
	
obj-m	:= slad_test_k.o

PWD :=drivers/net/eip93_drivers/slad_test_k
SRC_TOOL:=./src
SRC_KIT:=../cryptoEngine/Kit
PATH_BASE :=drivers/net/eip93_drivers/slad_test_k
PATH_KIT :=../cryptoEngine/Kit
PATH_DRIVER_API := ../cryptoEngine/V-Driver_93/incl

INCLUDE_KIT:= \
	-I$(PATH_BASE)/$(PATH_KIT)/DriverFramework/incl \
	-I$(PATH_BASE)/$(PATH_KIT)/Log/incl \
	-I$(PATH_BASE)/$(PATH_KIT)/DMABuf/incl

INCLUDE_TOOL:= \
	-I$(PATH_BASE)/src/incl \
	-I$(PATH_BASE)/src/shared \
	-I$(PWD)

INCLUDE_DRIVER_API:= \
	-I$(PATH_BASE)/$(PATH_DRIVER_API)

INCLUDE_ALL:= \
	$(INCLUDE_KIT) \
	$(INCLUDE_DRIVER_API) \
	$(INCLUDE_TOOL)

INCLUDE_KERNEL:= \
	-I$(PATH_BASE)/$(PATH_KIT)/Log/src/printk
    
EXTRA_CFLAGS += $(INCLUDE_ALL) $(INCLUDE_KERNEL)

# lkm
# relative paths required here!
slad_test_k-objs:= \
	$(SRC_TOOL)/lkm/slad_test_init_pe_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_benchmark_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_debug.o \
	$(SRC_TOOL)/lkm/slad_test_pe_device_specifics.o \
	$(SRC_TOOL)/lkm/slad_test_pe_kat_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_int_coalescing_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_kat_newapi_ext.o \
	$(SRC_TOOL)/lkm/slad_test_pe_cmd_notify_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_stress_newapi.o \
	$(SRC_TOOL)/lkm/slad_test_pe_utils.o \
	$(SRC_TOOL)/lkm/slad_test_interface_to_parser.o \
	$(SRC_TOOL)/lkm/slad_test_sa_converter.o \
	$(SRC_TOOL)/lkm/slad_test_target.o \
	$(SRC_TOOL)/lkm/osal_linux.o \
	$(SRC_TOOL)/shared/slad_test_parser_op_print.o \
	$(SRC_KIT)/Log/src/log.o

# parser
slad_test_k:
	@if [ ! -f $(PATH_DRIVER_SYMVERS)/Module.symvers ]; then \
	  echo "Failed to locate $(PATH_DRIVER_SYMVERS)/Module.symvers"; \
	  echo "Please build the driver first"; \
	  exit 1; \
	fi
	@cp $(PATH_DRIVER_SYMVERS)/Module.symvers .
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
	@echo "EXTRA_CFLAGS = $(EXTRA_CFLAGS)";
	make ARCH=$(ARCH)  CROSS_COMPILE=$(strip $(CROSS_COMPILE)) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules