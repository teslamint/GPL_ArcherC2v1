THISDIR := ./
QUICKSEC_SRCDIR := /home/user/socsw/treychen_hc/LinCVS_Crypto_63165/tclinux_phoenix/QuickSec-eip93/src

LDFLAGS += -L$(ELDK)/usr/lib -L$(ELDK)/lib -static -s

QUICKSEC_CFLAGS := \
	-I$(THISDIR) \
	-I$(ELDK)/usr/include \
	-I$(QUICKSEC_SRCDIR)/. \
	-I$(QUICKSEC_SRCDIR)/interceptor/include \
	-I$(QUICKSEC_SRCDIR)/interceptor/libkernelutil

QUICKSEC_FASTPATH :=

QUICKSEC_HWACCEL := SAFENETPE


