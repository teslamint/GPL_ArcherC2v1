#TRUNK_DIR=$(shell pwd)/../../../..
#QUICKSEC_SRCDIR=$(TRUNK_DIR)/modules/eip93_drivers/quickSec/src
#KDIR=$(TRUNK_DIR)/linux

KDIR=$(KERNEL_DIR)
QUICKSEC_SRCDIR=$(KERNEL_DIR)/drivers/net/eip93_drivers/quickSec/src

ARCH=mips
CROSS_COMPILE=mipsel-linux-uclibc-
QUICKSEC_HWACCEL=SAFENETPE


QUICKSEC_ABSSRC = $(shell cd $(QUICKSEC_SRCDIR); pwd)

all: initialize
	$(if $(KDIR),,\
	    $(eval KDIR := /lib/modules/$(shell uname -r)/build)\
	    $(warning defaulting KDIR to $(KDIR)))
	$(MAKE) -C "$(KDIR)" M="`pwd`" modules

initialize:
	rm -rf obj
	mkdir obj
	cd $(QUICKSEC_SRCDIR)
	( cd $(QUICKSEC_SRCDIR) && find * -type d ) | sort | \
	while read d; do mkdir "obj/$$d"; done
	( cd $(QUICKSEC_SRCDIR) && find * -type f -name '*.[chS]' ) | \
	while read f; do ln -s "$(QUICKSEC_ABSSRC)/$$f" "obj/$$f"; done
	touch $@

clean:
	rm -f initialize
	rm -rf obj quicksec* .quicksec* .tmp_versions [Mm]odule*

-include Makefile.inc
