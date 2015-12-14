#**************************************************************************** 
# 
#  Copyright(c) 2010-2011 Shenzhen TP-LINK Technologies Co.Ltd. 
#  All Rights Reserved 
#  YangXv <yangxu@tp-link.com.cn> 
# 
#***************************************************************************

# Top-level Makefile for all linux platforms 

MODEL = C2V1

include config/$(MODEL).config

#wanghao added 2013-10-08 for Archer C2
ifeq ($(strip $(INCLUDE_CPU_MT7620A)),y)
CPU_TYPE=mt7620a
endif
#end--added

#define basic variable
TOP_PATH = $(shell pwd)/..
BUILD_PATH = $(TOP_PATH)/build
TOOLS_PATH = $(TOP_PATH)/host_tools
FAKEROOT_PATH = $(TOOLS_PATH)/fakeroot

TARGETS_PATH = $(TOP_PATH)/targets
PUBLIC_APPS_PATH = $(TOP_PATH)/apps/public
PRIVATE_APPS_PATH = $(TOP_PATH)/apps/private
CMM_APPS_PATH = $(PRIVATE_APPS_PATH)/user/
OS_LIB_PATH = $(PUBLIC_APPS_PATH)/os_libs
	
####################################################
#
#Get supplier         
#
####################################################	

#wanghao added 2013-10-8 for Archer C2
ifeq ($(strip $(CPU_TYPE)),mt7620a)
TOOLROOTPATH :=/opt/buildroot-gcc463/usr
export PATH :=$(TOOLROOTPATH)/bin:$(PATH)
SUPPLIER = mtk_ApSoC_4120
TOOLPREFIX = mipsel-linux-
HOST = mipsel-linux
KERNELVERSION = 2.6.36
OBJ_DIR = mtk_4.6.3
SLIB_PATH = /opt/buildroot-gcc463/usr/mipsel-buildroot-linux-uclibc/sysroot/lib
KERNELPATH = $(TOP_PATH)/$(SUPPLIER)/linux-2.6.36.x
ROOTFSTOOLS = $(SUPPLIER_TOOLS)/mksquashfs4.2

export CROSS_COMPILE=$(TOOLPREFIX)

unexport TC_CFLAGS
TC_CFLAGS += -DTCSUPPORT_IGMPSNOOPING_ENHANCE
export TC_CFLAGS

export KERNELVERSION
export INSTALL_WIRELESS = $(TOP_PATH)/$(SUPPLIER)/wireless
export MT7610E_DIR = $(TOP_PATH)/$(SUPPLIER)/linux-2.6.36.x/drivers/net/wireless/MT7610_ap
export MT7620_DIR = $(TOP_PATH)/$(SUPPLIER)/linux-2.6.36.x/drivers/net/wireless/rt2860v2_ap
export WIRELESSTOOLS =$(TOP_PATH)/$(SUPPLIER)/modules/public/wireless_tools.29
export WIRELESSTOOLSLIB = libiw.so.29
endif
#end--added

####################################################
#
#Supplier PATH variable        
#
####################################################	

INSTALL_MOD_PATH = $(KERNELPATH)/../
SUPPLIER_TOOLS = $(TOP_PATH)/$(SUPPLIER)/tools

#TG means target
BOOT_TG_PATH = $(TARGETS_PATH)/$(SUPPLIER)_boot
ifeq ($(strip $(CPU_TYPE)),mt7620a)
KERNEL_TG_PATH = $(TARGETS_PATH)/$(SUPPLIER)_$(CPU_TYPE)_kernel_$(MODEL)
MODULE_TG_PATH = $(TARGETS_PATH)/$(SUPPLIER)_$(CPU_TYPE)_modules_$(MODEL)
else
KERNEL_TG_PATH = $(TARGETS_PATH)/$(SUPPLIER)_$(CPU_TYPE)_kernel
MODULE_TG_PATH = $(TARGETS_PATH)/$(SUPPLIER)_$(CPU_TYPE)_modules
endif
MODEL_FS_PATH = $(TARGETS_PATH)/fs.$(MODEL)

####################################################
#
#Supplier compiler variable        
#
####################################################	

CC = $(TOOLPREFIX)gcc
LD = $(TOOLPREFIX)ld
AR = $(TOOLPREFIX)ar
STRIP = $(TOOLPREFIX)strip
RANLIB = $(TOOLPREFIX)ranlib

####################################################
#
#Function conditional compilation        
#
####################################################	

DFLAGS = 
WEBFLAGS = 
DF_FLAGS = 

ifeq ($(strip $(INCLUDE_SOCKET_LOCK)), y)
DFLAGS += -DINCLUDE_SOCKET_LOCK
export INCLUDE_SOCKET_LOCK=y
endif

ifeq ($(INCLUDE_SERBIA), y) 
DFLAGS += -DINCLUDE_SERBIA
endif 

ifeq ($(INCLUDE_WATCHDOG), y) 
DFLAGS += -DINCLUDE_WATCHDOG
endif 

ifeq ($(INCLUDE_PPA_ACCELERATE), y)
DFLAGS += -DINCLUDE_PPA_ACCELERATE
endif

ifeq ($(INCLUDE_MTD_TYPE1), y)
DFLAGS += -DINCLUDE_MTD_TYPE1
MTD_PART_TYPE = 1
endif

ifeq ($(INCLUDE_MTD_TYPE2), y)
DFLAGS += -DINCLUDE_MTD_TYPE2
MTD_PART_TYPE = 2
endif

ifeq ($(INCLUDE_CLI_FULL_FEATURE), y)
DFLAGS += -DINCLUDE_CLI_FULL_FEATURE
endif

ifeq ($(INCLUDE_USER_ACCOUNT ), y) 
DFLAGS += -DINCLUDE_USER_ACCOUNT
endif

ifeq ($(INCLUDE_CHGINIT_PWD), y) 
DFLAGS += -DINCLUDE_CHGINIT_PWD
endif

ifeq ($(INCLUDE_AUTH_PASSWORD), y) 
DFLAGS += -DINCLUDE_AUTH_PASSWORD
endif

#################### ETH Type ######################
ifeq ($(INCLUDE_ETH_LTQ), y) 
DFLAGS += -DINCLUDE_ETH_LTQ
endif 

ifeq ($(INCLUDE_ETH_RA), y) 
DFLAGS += -DINCLUDE_ETH_RA
endif 

###################### WIFI  ########################
ifeq ($(INCLUDE_LAN_WLAN), y) 
DFLAGS += -DINCLUDE_LAN_WLAN 
endif 

ifeq ($(INCLUDE_WLAN_RA), y) 
DFLAGS += -DINCLUDE_WLAN_RA
endif 

ifeq ($(INCLUDE_WLAN_RTL), y) 
DFLAGS += -DINCLUDE_WLAN_RTL
endif 

ifeq ($(INCLUDE_WLAN_ATH), y) 
DFLAGS += -DINCLUDE_WLAN_ATH
endif 

#added by wangbing 2013-10-22
ifeq ($(INCLUDE_WLAN_MTK_AC),y)
DFLAGS += -DINCLUDE_WLAN_MTK_AC
DFLAGS += -DINCLUDE_LAN_WLAN_AC
endif 

ifeq ($(INCLUDE_LAN_WLAN_MSSID), y) 
DFLAGS += -DINCLUDE_LAN_WLAN_MSSID 
endif 

ifeq ($(INCLUDE_LAN_WLAN_GUESTNETWORK), y) 
DFLAGS += -DINCLUDE_LAN_WLAN_GUESTNETWORK 
endif 

ifeq ($(INCLUDE_LAN_WLAN_WDS), y) 
DFLAGS += -DINCLUDE_LAN_WLAN_WDS
endif 

ifeq ($(INCLUDE_LAN_WLAN_DUALBAND),y)
DFLAGS += -DINCLUDE_LAN_WLAN_DUALBAND
endif

ifeq ($(INCLUDE_LAN_WLAN_DUALBAND_DIF_MAC),y)
DFLAGS += -DINCLUDE_LAN_WLAN_DUALBAND_DIF_MAC
endif

ifeq ($(INCLUDE_LAN_WLAN_DIFFERENT_CHIP),y)
DFLAGS += -DINCLUDE_LAN_WLAN_DIFFERENT_CHIP
endif

ifeq ($(INCLUDE_LAN_WLAN_8021X), y) 
DFLAGS += -DINCLUDE_LAN_WLAN_802_1X
endif 

ifeq ($(INCLUDE_LAN_WLAN_SCHEDULE), y)
DFLAGS += -DINCLUDE_LAN_WLAN_SCHEDULE
endif

ifeq ($(INCLUDE_LAN_WLAN_SCHEDULE_ONLY_FOR_GUEST), y)
DFLAGS += -DINCLUDE_LAN_WLAN_SCHEDULE_ONLY_FOR_GUEST
endif

ifeq ($(INCLUDE_LAN_WLAN_GUEST_TIMEOUT), y)
DFLAGS += -DINCLUDE_LAN_WLAN_GUEST_TIMEOUT
endif

#################### Function ######################

ifeq ($(INCLUDE_BRIDGING), y)
DFLAGS += -DINCLUDE_BRIDGING
endif

ifeq ($(INCLUDE_ADSLWAN), y)
DFLAGS += -DINCLUDE_ADSLWAN
endif

ifeq ($(INCLUDE_ADSL_RA), y)
DFLAGS += -DINCLUDE_ADSL_RA
endif

ifeq ($(INCLUDE_ADSL_RTL), y)
DFLAGS += -DINCLUDE_ADSL_RTL
endif

ifeq ($(INCLUDE_ADSL_LTQ), y)
DFLAGS += -DINCLUDE_ADSL_LTQ
endif

ifeq ($(INCLUDE_ETHERNET_WAN), y)
DFLAGS += -DINCLUDE_ETHERNET_WAN
endif

ifeq ($(INCLUDE_IGMP), y)
DFLAGS += -DINCLUDE_IGMP
endif

ifeq ($(INCLUDE_IPTV), y)
DFLAGS += -DINCLUDE_IPTV
endif

ifeq ($(INCLUDE_AUTO_PVC), y)
DFLAGS += -DINCLUDE_AUTO_PVC
endif

ifeq ($(INCLUDE_RIP), y)
DFLAGS += -DINCLUDE_RIP
endif

ifeq ($(INCLUDE_SNMP), y)
DFLAGS += -DINCLUDE_SNMP
endif

ifeq ($(INCLUDE_IPPING_DIAG), y)
DFLAGS += -DINCLUDE_IPPING_DIAG
endif

ifeq ($(INCLUDE_TRACEROUTE_DIAG), y)
DFLAGS += -DINCLUDE_TRACEROUTE_DIAG
endif

ifeq ($(INCLUDE_SSL), y)
DFLAGS += -DINCLUDE_SSL
endif

ifeq ($(INCLUDE_CWMP), y)
DFLAGS += -DINCLUDE_CWMP
endif

ifeq ($(INCLUDE_CWMP_SSL), y)
DFLAGS += -DINCLUDE_CWMP_SSL
export INCLUDE_CWMP_SSL
ifeq ($(INCLUDE_CWMP_SSL_VERIFY_PEER), y)
DFLAGS += -DINCLUDE_CWMP_SSL_VERIFY_PEER
export INCLUDE_CWMP_SSL_VERIFY_PEER
endif
endif

ifeq ($(INCLUDE_DIGITAL_SIGNATURE), y)
DFLAGS += -DINCLUDE_DIGITAL_SIGNATURE
endif

ifeq ($(INCLUDE_DDNS), y)
DFLAGS += -DINCLUDE_DDNS
endif

ifeq ($(INCLUDE_DDNS_PH), y)
DFLAGS += -DINCLUDE_DDNS_PH
endif

ifeq ($(INCLUDE_DYNDNS), y)
DFLAGS += -DINCLUDE_DYNDNS
endif

ifeq ($(INCLUDE_NOIPDNS), y)
DFLAGS += -DINCLUDE_NOIPDNS
endif

ifeq ($(INCLUDE_CMXDNS), y)
DFLAGS += -DINCLUDE_CMXDNS
endif

ifeq ($(INCLUDE_ALG), y)
DFLAGS += -DINCLUDE_ALG
endif

ifeq ($(INCLUDE_ALG_H323), y)
DFLAGS += -DINCLUDE_ALG_H323
endif

ifeq ($(INCLUDE_ALG_SIP), y)
DFLAGS += -DINCLUDE_ALG_SIP
endif

#NOTE:INCLUDE_VOIP in voip.mak
ifeq ($(INCLUDE_VOIP), y)
DFLAGS += $(VOIP_DFLAGS)
DF_FLAGS += $(VOIP_CFLAGS)
endif

ifeq ($(INCLUDE_IPV6), y)
DFLAGS += -DINCLUDE_IPV6

ifeq ($(INCLUDE_IPV6_MLD), y)
DFLAGS += -DINCLUDE_IPV6_MLD
endif

ifeq ($(INCLUDE_IPV6_SLAAC), y)
DFLAGS += -DINCLUDE_IPV6_SLAAC
endif

ifeq ($(INCLUDE_IPV6_HTTP), y)
DFLAGS += -DINCLUDE_IPV6_HTTP
endif

endif

ifeq ($(INCLUDE_USB), y)
DFLAGS += -DINCLUDE_USB
endif

ifeq ($(INCLUDE_USB_OVER_IP), y)
DFLAGS += -DINCLUDE_USB_OVER_IP
endif

ifeq ($(INCLUDE_USB_OVER_IP_TPLINK), y)
DFLAGS += -DINCLUDE_USB_OVER_IP_TPLINK
endif

ifeq ($(INCLUDE_USB_OVER_IP_KCODES), y)
DFLAGS += -DINCLUDE_USB_OVER_IP_KCODES
endif

ifeq ($(INCLUDE_USB_STORAGE), y)
DFLAGS += -DINCLUDE_USB_STORAGE
endif

ifeq ($(INCLUDE_USB_MEDIA_SERVER), y)
DFLAGS += -DINCLUDE_USB_MEDIA_SERVER
endif

ifeq ($(INCLUDE_USB_SAMBA_SERVER), y)
DFLAGS += -DINCLUDE_USB_SAMBA_SERVER
endif

ifeq ($(INCLUDE_USB_FTP_SERVER), y)
DFLAGS += -DINCLUDE_USB_FTP_SERVER
endif

ifeq ($(INCLUDE_USB_3G_DONGLE), y)
DFLAGS += -DINCLUDE_USB_3G_DONGLE
endif

ifeq ($(INCLUDE_IPSEC), y)
DFLAGS += -DINCLUDE_IPSEC
endif

ifeq ($(INCLUDE_WAN_MODE), y)
DFLAGS += -DINCLUDE_WAN_MODE
endif

ifeq ($(INCLUDE_QOS), y)
DFLAGS += -DINCLUDE_QOS
endif

ifeq ($(INCLUDE_ANNEXB), y)
DFLAGS += -DINCLUDE_ANNEXB
endif

ifeq ($(INCLUDE_POLICY_ROUTE), y)
DFLAGS += -DINCLUDE_POLICY_ROUTE
endif

ifeq ($(INCLUDE_DUAL_ACCESS), y)
DFLAGS += -DINCLUDE_DUAL_ACCESS
endif

ifeq ($(INCLUDE_L2TP), y)
DFLAGS += -DINCLUDE_L2TP
endif

ifeq ($(INCLUDE_PPTP), y)
DFLAGS += -DINCLUDE_PPTP
endif

ifeq ($(INCLUDE_ACL), y)
DFLAGS += -DINCLUDE_ACL
ifeq ($(INCLUDE_ACL_ADVANCE), y)
DFLAGS += -DINCLUDE_ACL_ADVANCE
endif
endif

ifeq ($(INCLUDE_WAN_TYPE_DETECT), y)
DFLAGS += -DINCLUDE_WAN_TYPE_DETECT
endif

ifeq ($(INCLUDE_BPA), y)
DFLAGS += -DINCLUDE_BPA
endif

DF_FLAGS += $(DFLAGS)


ifeq ($(PENNYTEL), y) 
DF_FLAGS += -DPENNYTEL
endif 


WEBFLAGS += WEB_INCLUDE_TEST=0

ifeq ($(WEB_INCLUDE_MULTI_EWAN), y)
WEBFLAGS += WEB_INCLUDE_MULTI_EWAN=1
else
WEBFLAGS += WEB_INCLUDE_MULTI_EWAN=0
endif

ifeq ($(WEB_INCLUDE_DST), y)
WEBFLAGS += WEB_INCLUDE_DST=1
else
WEBFLAGS += WEB_INCLUDE_DST=0
endif

ifeq ($(strip $(INCLUDE_ONLY_ONE_LOGIN)),y)
DFLAGS += -DINCLUDE_ONLY_ONE_LOGIN
endif

DFLAGS += -DINCLUDE_$(MODEL)

####################################################
#
#Export some variable        
#
####################################################	

export TOOLPREFIX
export HOST
#For modules build & br2684ctl build
export KERNELPATH
#For install kernel modules
export INSTALL_MOD_PATH
#For code control, placed different target file
export OBJ_DIR
#For function conditional compilation
export DF_FLAGS

export TOP_PATH

export CMM_APPS_PATH

export OS_LIB_PATH

#For complier
export CC
export LD
export AR
export STRIP
export RANLIB

####################################################
#
#Compilation environment         
#
####################################################
env_build:
ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
	@echo "Uncompressing toolchain..."
	@cp $(TOP_PATH)/$(SUPPLIER)/tools/toolchain/buildroot-gcc463.tar.bz2 /opt/
	@cd /opt/ && tar -jxf buildroot-gcc463.tar.bz2 && rm -f buildroot-gcc463.tar.bz2
endif

	@echo "env_build done!"

####################################################
#
#Menuconfig         
#
####################################################
menuconfig:
	cp $(BUILD_PATH)/config/$(MODEL).config $(BUILD_PATH)/.config
	$(BUILD_PATH)/scripts/config/mconf $(BUILD_PATH)/sysdeps/linux/Config.in
	cp $(BUILD_PATH)/.config $(BUILD_PATH)/config/$(MODEL).config
# wanghao added 2013-10-12 for Archer C2
	@if egrep "^INCLUDE_CPU_MT7620A=y" .config > /dev/null; then \
		echo "TODO" \
		#cd $(TOP_PATH)/mtk && $(MAKE) menuconfig; \
	fi
# add end
	
####################################################
#
#Build bootloader          
#
####################################################
boot_build:
	@echo "Make Boot Build"
ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
	@echo "Should build in Uboot folder with gcc342 by now!"
	cd $(TOP_PATH)/$(SUPPLIER)/Uboot && make 
	test -d $(BOOT_TG_PATH) || mkdir -p $(BOOT_TG_PATH)
	cp $(TOP_PATH)/$(SUPPLIER)/Uboot/uboot.bin $(BOOT_TG_PATH)/boot.bin
endif

####################################################
#
#Build linux kernel           
#
####################################################
kernel_prepare:
ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
#Port from RT288x_SDK 4.1.2.0, yuanshang, 2013-10-31
	cp $(KERNELPATH)/$(CPU_TYPE)_$(MODEL)_config $(KERNELPATH)/.config
	$(MAKE) -C $(KERNELPATH) prepare
	rm -fr $(KERNELPATH)/include/asm
	rm -fr $(KERNELPATH)/arch/mips/include/asm/rt2880
	rm -fr $(KERNELPATH)/include/linux/autoconf.h
	
	ln -sf ../arch/mips/include/asm $(KERNELPATH)/include/asm
	ln -sf ./mach-ralink $(KERNELPATH)/arch/mips/include/asm/rt2880
	ln -sf ../../include/generated/autoconf.h $(KERNELPATH)/include/linux/autoconf.h
	
	$(MAKE) -C $(KERNELPATH) dep
endif
		
kernel_build:kernel_prepare
	@echo "Make Kernel Build"
	cp $(KERNELPATH)/$(CPU_TYPE)_$(MODEL)_config $(KERNELPATH)/.config
	cd $(KERNELPATH) && $(MAKE) V=2 linux.7z
	test -d $(KERNEL_TG_PATH) || mkdir -p $(KERNEL_TG_PATH)
	cp $(KERNELPATH)/linux.7z $(KERNEL_TG_PATH)/
	cp $(KERNELPATH)/vmlinux $(KERNEL_TG_PATH)/

kernel_menuconfig:
	cp $(KERNELPATH)/$(CPU_TYPE)_$(MODEL)_config $(KERNELPATH)/.config
	cd $(KERNELPATH) && $(MAKE) menuconfig
	cp $(KERNELPATH)/.config $(KERNELPATH)/$(CPU_TYPE)_$(MODEL)_config
	@echo "Replace Kernel Config File"

####################################################
#
#Build all kernel modules
#
####################################################
modules_build:kernel_modules public_modules ipt_modules tp_domain

kernel_modules:
	@echo "Making Kernel Modules"
	cp $(KERNELPATH)/$(CPU_TYPE)_$(MODEL)_config $(KERNELPATH)/.config
	cd $(KERNELPATH) && $(MAKE) modules
	cd $(KERNELPATH) && $(MAKE) DEPMOD=true modules_install
	test -d $(MODULE_TG_PATH) || mkdir -p $(MODULE_TG_PATH) && mkdir -p $(MODULE_TG_PATH)/kmdir/
ifeq ($(strip $(CPU_TYPE)),mt7620a)
	test -d $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/MT7610_ap || \
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/MT7610_ap && \
	cp -p $(MT7610E_DIR)/MT7610_ap.ko $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/MT7610_ap
	test -d $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/rt2860v2_ap || \
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/rt2860v2_ap && \
	cp -p $(MT7620_DIR)/rt2860v2_ap.ko $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel/drivers/net/wireless/rt2860v2_ap
	cp -pR $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/kernel $(MODULE_TG_PATH)/kmdir/
else
	cp -pR $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVERSION)/* $(MODULE_TG_PATH)/kmdir/
endif
ifeq ($(INCLUDE_WLAN_RA), y) 
	cp -p $(MT7610E_DIR)/MT7610E-V10-FEM-1ANT.bin $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7610E_DIR)/RT2860AP5G.dat $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7610E_DIR)/SingleSKU_5G_FCC.dat $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7610E_DIR)/SingleSKU_5G_CE.dat $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7620_DIR)/RT2860AP.dat $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7620_DIR)/SingleSKU_CE.dat $(INSTALL_WIRELESS)/lib/firmware/	
	cp -p $(MT7620_DIR)/SingleSKU_FCC.dat $(INSTALL_WIRELESS)/lib/firmware/
	cp -p $(MT7620_DIR)/MT7620_AP_2T2R-4L_V15.BIN $(INSTALL_WIRELESS)/lib/firmware/

endif

public_modules:
	@echo "Making public modules"

ifeq ($(INCLUDE_USB_OVER_IP_TPLINK), y)
	cd $(TOP_PATH)/$(SUPPLIER)/modules/public/usbip-0.1.7 && $(MAKE)  
endif 
 
ifeq ($(INCLUDE_PPTP), y)
	cd $(TOP_PATH)/$(SUPPLIER)/modules/public/accel-pptp-0.8.5 && $(MAKE)  
endif 
 
ifeq ($(INCLUDE_L2TP), y) 
ifeq ($(KERNELVERSION), 2.6.22.15)
	@echo "Kernel version is lower than 2.6.23, use pppol2tp-kmod-0.17" 
	cd $(TOP_PATH)/$(SUPPLIER)/modules/public/pppol2tp-kmod-0.17 && $(MAKE)  
else
	@echo "Kernel version is not lower than 2.6.23, use pppol2tp v1.0 driver in kernel"
endif
endif

ipt_modules:
	@echo "Making ipt_STAT Modules"
	cd $(TOP_PATH)/$(SUPPLIER)/modules/private/ipt_STAT && cp ipt_STAT.ko $(MODULE_TG_PATH)/

tp_domain:
	@echo "Making tp_domain Modules"
	cd $(TOP_PATH)/$(SUPPLIER)/modules/private/tp_domain && cp tp_domain.ko $(MODULE_TG_PATH)/

####################################################
#
#Build libs
#
####################################################


####################################################
#
#Build wireless, include driver and tools
#
####################################################
wireless_tools:
	@echo making wireless_tools
	if test -n "$(WIRELESSTOOLS)"; then \
	cd $(TOP_PATH)/$(SUPPLIER)/modules/$(WIRELESSTOOLS); make clean; make; \
	cp -f $(WIRELESSTOOLSLIB) $(INSTALL_WIRELESS)/lib; \
	cp -f iwpriv $(INSTALL_WIRELESS)/sbin; \
	cp -f iwconfig $(INSTALL_WIRELESS)/sbin; \
	cp -f iwlist $(INSTALL_WIRELESS)/sbin; \
	cd $(TOP_PATH)/$(SUPPLIER)/modules/private/wlan/os/linux/tools && \
	make clean; \
	make wlanconfig BUILD_STATIC=$(BUILD_STATIC); \
	cp -f wlanconfig $(INSTALL_WIRELESS)/sbin; \
	fi

art_mod:
	@echo making art modules
	cd $(TOP_PATH)/$(SUPPLIER)/modules/art && make all

reg:
	cd $(TOP_PATH)/$(SUPPLIER)/modules/private/wlan/os/linux/tools && \
	make reg;
sar:
	@echo making sar
	cd ../apps/public/sysstat-6.0.1/ && rm -f sysstat.cron.daily && rm -f sysstat.cron.hourly && $(MAKE) CC=$(TOOLPREFIX)gcc 
	cd ../apps/public/sysstat-6.0.1/ && cp sar $(INSTALL_WIRELESS)/sbin
	cd ../apps/public/sysstat-6.0.1/ && cp sadc $(INSTALL_WIRELESS)/sbin

wpa2:wpa2_clean
	@echo Making wpa2 at 'date'
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2 && $(MAKE) \
		CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld
	@echo End Making wpa2 at 'date'
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2/common && \
	$(STRIP) *.so && cp *.so $(INSTALL_WIRELESS)/lib
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2/hostapd && \
	$(STRIP) hostapd && cp hostapd $(INSTALL_WIRELESS)/sbin
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2/wpa_supplicant && \
	$(STRIP) wpa_supplicant && cp wpa_supplicant $(INSTALL_WIRELESS)/sbin
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2/wpatalk && \
	$(STRIP) wpatalk && cp wpatalk $(INSTALL_WIRELESS)/sbin

wpa2_clean:
	cd $(TOP_PATH)/$(SUPPLIER)/modules/wpa2 && $(MAKE) clean

ifeq ($(strip $(SUPPLIER)),lantiq)
wlan_build: wireless_driver wireless_tools wpa2
endif

wlan_clean:wpa2_clean
	cd $(HAL)/linux && make TARGET=$(TARGETARCH) clean
	cd $(TOP_PATH)/$(SUPPLIER)/modules/private/wlan/os/linux && $(MAKEARCH) TARGET=$(TARGETARCH) clean
	make -C $(TOP_PATH)/$(SUPPLIER)/modules/art clean
	make -C $(TOP_PATH)/$(SUPPLIER)/modules/$(WIRELESSTOOLS) clean

####################################################
#
#Build apps
#
####################################################

#openssl should before pjsip case pjsip need it
#libusb&libcompat should before handle_card&usb_modeswitch
.PHONY: apps_build
apps_build: libusb libcompat openssl mtk_tools wirelesstool public_apps_build


####################################################
#
#Build public apps
#
####################################################

.PHONY: public_apps_build
public_apps_build: oslibs \
					busybox tc iptables ebtables pppd ripd \
					upnplib upnp flex radvd dhcpv6 samba ntfs-3g \
					usbip vsftp ffmpeg libdlna ushare ip ipsectools \
					chat usb_modeswitch xl2tpd bigpond ipping traceroute
.PHONY: mtk_tools
mtk_tools:
ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
	@echo Build MTK APP port from MTK_APSOC_4120
	@echo Builg reg
	cd $(TOP_PATH)/$(SUPPLIER)/apps/reg && $(MAKE)
	@echo Build hw_nat
	cd $(TOP_PATH)/$(SUPPLIER)/apps/hw_nat && $(MAKE)
endif

.PHONY: wirelesstool
wirelesstool:
ifeq ($(INCLUDE_LAN_WLAN), y) 
ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
	@echo "build wireless tools"
	cd $(WIRELESSTOOLS) && make all;\
	cp -f ated_tp $(INSTALL_WIRELESS)/sbin;\
	cp -f $(WIRELESSTOOLSLIB) $(INSTALL_WIRELESS)/lib;\
	cp -f iwpriv $(INSTALL_WIRELESS)/sbin;\
        cp -f wlNetlinkTool $(INSTALL_WIRELESS)/sbin
	
	@echo "build ated for QA"
	cd $(WIRELESSTOOLS)/../ated && \
	cp -f ated $(INSTALL_WIRELESS)/sbin

	echo "Build the rt2860apd for 802.1x"
	cd $(WIRELESSTOOLS)/../8021x &&  make clean && make all;\
	cp -f rt2860apd $(INSTALL_WIRELESS)/sbin/;\
	ln -sf rt2860apd $(INSTALL_WIRELESS)/sbin/rtinicapd
	
endif
else	#INCLUDE_LAN_WLAN
	@echo no wifi
endif	#INCLUDE_LAN_WLAN

.PHONY:oslibs
oslibs:
	cd $(PUBLIC_APPS_PATH)/os_libs && $(MAKE)
					
.PHONY: busybox
busybox:
	cd $(PUBLIC_APPS_PATH)/busybox-1.19.2 && $(MAKE)
	
.PHONY: tc
tc:
	cd $(PUBLIC_APPS_PATH)/iproute2-2.6.24-rc7 && $(MAKE)

.PHONY: iptables
iptables:
	cd $(PUBLIC_APPS_PATH)/iptables-1.4.17 && test -e Makefile || ./configure --host=mips-linux-uclibc --enable-static --disable-shared  
	cd $(PUBLIC_APPS_PATH)/iptables-1.4.17 && $(MAKE) AR=$(TOOLPREFIX)ar
	$(STRIP) $(PUBLIC_APPS_PATH)/iptables-1.4.17/iptables/xtables-multi

.PHONY: ebtables
ebtables:
	cd $(PUBLIC_APPS_PATH)/ebtables-v2.0.10-4 && $(MAKE) static
	
.PHONY: pppd
pppd:
	cd $(PUBLIC_APPS_PATH)/ppp-2.4.5/pppd && $(MAKE) #INCLUDE_IPV6_PPPV6=$(INCLUDE_IPV6_PPPV6)
	
	
.PHONY: upnplib
upnplib:
	$(MAKE) -C $(PUBLIC_APPS_PATH)/upnp_libs
	
.PHONY: upnp
upnp:
	$(MAKE) -C $(PUBLIC_APPS_PATH)/IGD

.PHONY: ripd
ripd:
ifeq ($(INCLUDE_RIP), y)
	$(MAKE) -C $(PUBLIC_APPS_PATH)/zebra-0.95a
else
	@echo no ripd
endif

.PHONY: usbip
usbip:
ifeq ($(INCLUDE_USB_OVER_IP_TPLINK), y)
	$(MAKE) -C $(PUBLIC_APPS_PATH)/usbip-0.1.7 clean
	cd $(PUBLIC_APPS_PATH)/usbip-0.1.7 && $(MAKE)
endif

.PHONY: vsftp
vsftp:
ifeq ($(INCLUDE_USB_FTP_SERVER), y)
	cd $(PUBLIC_APPS_PATH)/vsftpd-2.3.2 && $(MAKE)
else 
	@echo no vsftp
endif

.PHONY: flex
flex:
ifeq ($(INCLUDE_IPV6), y)
	cd $(PUBLIC_APPS_PATH)/flex-2.5.35 && test -e Makefile || ./configure --host=mips-linux 
	cd $(PUBLIC_APPS_PATH)/flex-2.5.35 && $(MAKE)
	mkdir -p $(PUBLIC_APPS_PATH)/lib
	cp -p $(PUBLIC_APPS_PATH)/flex-2.5.35/libfl.a $(PUBLIC_APPS_PATH)/lib
else 
	@echo no ipv6 flex
endif

.PHONY: radvd
radvd:
ifeq ($(INCLUDE_IPV6), y)
	cd $(PUBLIC_APPS_PATH)/radvd-1.5 && $(MAKE)
else 
	@echo no ipv6 radvd
endif

.PHONY: dhcpv6
dhcpv6:
ifeq ($(INCLUDE_IPV6), y)
	cd $(PUBLIC_APPS_PATH)/wide-dhcpv6-20080615 && $(MAKE)
else 
	@echo no ipv6 dhcpv6
endif

.PHONY: ip
ip: 
ifeq ($(INCLUDE_IPV6), y)
	cd $(PUBLIC_APPS_PATH)/iproute2-2.6.39 && $(MAKE)
else
	@echo no ipv6 ip
endif

#for samba and ntfs-3g, zjj, 20111129
.PHONY: samba
samba:
ifeq ($(INCLUDE_USB_SAMBA_SERVER), y)
	cd $(PUBLIC_APPS_PATH)/samba-3.0.14a/source && $(MAKE)
	$(STRIP) $(PUBLIC_APPS_PATH)/samba-3.0.14a/source/bin/*
else 
	@echo no samba
endif
	
.PHONY: ntfs-3g
ntfs-3g:
ifeq ($(INCLUDE_USB_STORAGE), y)
	cd $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15 && test -e Makefile || ./configure --build=i686-linux --host=$(HOST) --disable-nfconv
	cd $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15 && $(MAKE)
	$(STRIP) $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/libntfs-3g/.libs/libntfs-3g.so.83.0.0
	$(STRIP) $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/src/.libs/ntfs-3g
	$(STRIP) $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/src/.libs/lowntfs-3g
else 
	@echo no ntfs-3g+ntfsprogs
endif
#end by zjj

#for dlna, LI CHENGLONG
.PHONY: ffmpeg
ffmpeg:
ifeq ($(INCLUDE_USB_MEDIA_SERVER), y)
	$(MAKE) -C $(PUBLIC_APPS_PATH)/ffmpeg-0.6/
endif

.PHONY: libdlna
libdlna:
ifeq ($(INCLUDE_USB_MEDIA_SERVER), y)
	$(MAKE) -C $(PUBLIC_APPS_PATH)/libdlna-0.2.3/
endif

.PHONY: ushare
ushare:
ifeq ($(INCLUDE_USB_MEDIA_SERVER), y)
	$(MAKE) -C $(PUBLIC_APPS_PATH)/ushare-1.1a/
endif
#end by LI CHENGLONG

.PHONY: openssl
openssl:
ifeq ($(INCLUDE_SSL), y)
	cd $(PUBLIC_APPS_PATH)/openssl && test -e Makefile || ./Configure shared \
		no-threads no-zlib no-asm no-gmp no-krb5 no-hw no-cipher no-rfc3779 no-sse2 no-speed \
		no-md2 no-md4 no-mdc2 no-ripemd no-rc5 no-idea no-bf no-cast no-camellia \
		no-ec no-dsa no-ecdsa no-store linux-mips \
	&& sed -i 's/-O3/-Os -DGNU/g' Makefile
	
	cd $(PUBLIC_APPS_PATH)/openssl \
	&& $(MAKE) CC=$(CC) LD=$(LD) SHARED_LDFLAGS="-s"\
	&& mkdir -p ./lib \
	&& cp -p ./libcrypto.so.0.9.7 ./lib/ \
	&& cp -p ./libssl.so.0.9.7 ./lib/ \
	&& cd ./lib/ \
	&& ln -sf libcrypto.so.0.9.7 libcrypto.so.0 \
	&& ln -sf libcrypto.so.0.9.7 libcrypto.so \
	&& ln -sf libssl.so.0.9.7 libssl.so.0 \
	&& ln -sf libssl.so.0.9.7 libssl.so
endif

.PHONY: ipsectools
ipsectools:
ifeq ($(INCLUDE_IPSEC), y)
	cd $(PUBLIC_APPS_PATH)/ipsectools && test -e Makefile || ./configure --host=mips-linux --with-kernel-headers=$(KERNELPATH)/include \
	--with-openssl=$(PUBLIC_APPS_PATH)/openssl/ --enable-security-context=no --enable-shared=yes \
	--enable-dpd=yes CFLAGS="-Os -DGNU" 
	cd $(PUBLIC_APPS_PATH)/ipsectools && $(MAKE)
	$(STRIP) $(PUBLIC_APPS_PATH)/ipsectools/src/racoon/.libs/racoon
	$(STRIP) $(PUBLIC_APPS_PATH)/ipsectools/src/setkey/.libs/setkey
	$(STRIP) $(PUBLIC_APPS_PATH)/ipsectools/src/racoon/.libs/libracoon.so.0.0.0
	$(STRIP) $(PUBLIC_APPS_PATH)/ipsectools/src/libipsec/.libs/libipsec.so.0.0.1
endif

.PHONY: chat
chat:
ifeq ($(INCLUDE_USB_3G_DONGLE), y)
	@echo building chat...
	cd $(PUBLIC_APPS_PATH)/ppp-2.4.5/chat && $(MAKE)
	$(STRIP) $(PUBLIC_APPS_PATH)/ppp-2.4.5/chat/chat
else
	@echo no chat
endif

.PHONY: libusb
libusb:
ifeq ($(INCLUDE_USB_3G_DONGLE), y)
	echo "Building usb library"
	cd $(PUBLIC_APPS_PATH)/libusb-1.0.8 && test -e Makefile || ./configure --build=i686-linux --host=$(HOST) --prefix=$(PUBLIC_APPS_PATH)/libusb-1.0.8/install
	cd $(PUBLIC_APPS_PATH)/libusb-1.0.8 && $(MAKE) install
else
	@echo no libusb
endif

.PHONY: libcompat
libcompat:
ifeq ($(INCLUDE_USB_3G_DONGLE), y)
	echo "Building usb compat"
	cd $(PUBLIC_APPS_PATH)/libusb-compat-0.1.3 && test -e Makefile || ./configure --build=i686-linux --host=$(HOST) --prefix=$(PUBLIC_APPS_PATH)/libusb-compat-0.1.3/install LIBUSB_1_0_CFLAGS=-I$(PUBLIC_APPS_PATH)/libusb-1.0.8/install/include/libusb-1.0 LIBUSB_1_0_LIBS=-L$(PUBLIC_APPS_PATH)/libusb-1.0.8/install/lib\ -lusb-1.0
	cd $(PUBLIC_APPS_PATH)/libusb-compat-0.1.3 && $(MAKE) install
else
	@echo no libcompat
endif

.PHONY: usb_modeswitch
usb_modeswitch:
ifeq ($(INCLUDE_USB_3G_DONGLE), y)
	echo "Building usb_modeswitch"
	cd $(PUBLIC_APPS_PATH)/usb-modeswitch-1.2.3 && $(MAKE)
	$(STRIP) $(PUBLIC_APPS_PATH)/usb-modeswitch-1.2.3/usb_modeswitch
else
	@echo no usb_modeswitch
endif

.PHONY: xl2tpd
xl2tpd:
ifeq ($(INCLUDE_L2TP), y)
	cd $(PUBLIC_APPS_PATH)/xl2tpd-1.1.12 && $(MAKE)
endif

.PHONY: bigpond
bigpond:
ifeq ($(INCLUDE_BPA), y)
	cd $(PUBLIC_APPS_PATH)/bpalogin-2.0.2 && $(MAKE)
endif

.PHONY: ipping
ipping:
ifeq ($(INCLUDE_IPPING_DIAG), y)
	cd $(PUBLIC_APPS_PATH)/ipping && $(MAKE)
endif

.PHONY: traceroute
traceroute:
ifeq ($(INCLUDE_TRACEROUTE_DIAG), y)
	cd $(PUBLIC_APPS_PATH)/traceroute-2.0.3 && $(MAKE)
endif
####################################################
#
#Build filesystem, prepare basic fs first
#
####################################################
.PHONY: fs_build
fs_build: fs_clean fs_create fs_lib fs_bin fs_modules fs_rootfs

fs_clean:
	rm -rf $(MODEL_FS_PATH)/../rootfs.$(MODEL)
	rm -rf $(MODEL_FS_PATH)
	rm -rf $(MODEL_FS_PATH)/../reduced_data_model_plaintext_$(MODEL).xml
	
fakeroot_clean:    
	if [ -e $(FAKEROOT_PATH)/Makefile ];  then make -C $(FAKEROOT_PATH) distclean; fi
	rm -f $(FAKEROOT_PATH)/fakeroot
	rm -f $(FAKEROOT_PATH)/.configured
	
.PHONY: fs_create
fs_create: 
	cp -pR $(TOP_PATH)/targets/fs.dir $(MODEL_FS_PATH)
	find  $(MODEL_FS_PATH) -name ".svn" | xargs rm -rf
ifneq ($(INCLUDE_CWMP_SSL_VERIFY_PEER), y)
	@rm -fr $(MODEL_FS_PATH)/etc/cert
endif

	#for rcS, yuanshang, 20111026
	rm -fr $(MODEL_FS_PATH)/etc/init.d/*
	cp $(TOP_PATH)/targets/fs.dir/etc/init.d/rcS_$(MODEL) $(MODEL_FS_PATH)/etc/init.d/rcS

.PHONY: fs_lib
fs_lib:
	cp $(SLIB_PATH)/* $(MODEL_FS_PATH)/lib/
	cp $(PUBLIC_APPS_PATH)/upnp_libs/*.so $(MODEL_FS_PATH)/lib/
	cp $(OS_LIB_PATH)/libos.so $(MODEL_FS_PATH)/lib

ifeq ($(INCLUDE_SSL), y)
	cp -p $(PUBLIC_APPS_PATH)/openssl/libcrypto.so.0.9.7 $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libcrypto.so.0.9.7 libcrypto.so
	cp -p $(PUBLIC_APPS_PATH)/openssl/libssl.so.0.9.7 $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libssl.so.0.9.7 libssl.so
endif
	
ifneq ($(strip $(INCLUDE_USB_VOICEMAIL)),)
	cp $(APP_PJSIP_DIR)/usbvm/lib/libusbvmcommon.so $(MODEL_FS_PATH)/lib/
endif

	#for the libs of samba and ntfs-3g, zjj, 20111129
ifeq ($(INCLUDE_USB_STORAGE), y)
	cp -p $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/libntfs-3g/.libs/libntfs-3g.so.83.0.0 $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libntfs-3g.so.83.0.0 libntfs-3g.so.83
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libntfs-3g.so.83.0.0 libntfs-3g.so
ifeq ($(INCLUDE_USB_SAMBA_SERVER), y)
	cp -p $(PUBLIC_APPS_PATH)/samba-3.0.14a/source/bin/libbigballofmud.so $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libbigballofmud.so libbigballofmud.so.0
endif
endif
	#end by zjj
 
ifeq ($(INCLUDE_USB_3G_DONGLE),y)
	cp --no-dereference -p $(PUBLIC_APPS_PATH)/libusb-1.0.8/install/lib/libusb-1.0.so* $(MODEL_FS_PATH)/lib/
	cp --no-dereference -p $(PUBLIC_APPS_PATH)/libusb-compat-0.1.3/install/lib/libusb-0.1.so* $(MODEL_FS_PATH)/lib/
	cp --no-dereference -p $(PUBLIC_APPS_PATH)/libusb-compat-0.1.3/install/lib/libusb.so $(MODEL_FS_PATH)/lib/
endif #INCLUDE_USB_3G_DONGLE
 
ifeq ($(INCLUDE_IPSEC), y)	
	cp -p $(PUBLIC_APPS_PATH)/ipsectools/src/racoon/.libs/libracoon.so.0.0.0 $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libracoon.so.0.0.0 libracoon.so.0
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libracoon.so.0.0.0 libracoon.so
	cp -p $(PUBLIC_APPS_PATH)/ipsectools/src/libipsec/.libs/libipsec.so.0.0.1 $(MODEL_FS_PATH)/lib/
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libipsec.so.0.0.1 libipsec.so.0
	cd $(MODEL_FS_PATH)/lib/ && ln -sf libipsec.so.0.0.1 libipsec.so
endif


.PHONY:fs_bin
fs_bin:
	cd $(PUBLIC_APPS_PATH)/busybox-1.19.2 && $(MAKE) install CONFIG_PREFIX=$(MODEL_FS_PATH)
	cp -p $(PUBLIC_APPS_PATH)/iproute2-2.6.24-rc7/tc/tc $(MODEL_FS_PATH)/usr/bin
	
	cp -p $(PUBLIC_APPS_PATH)/iptables-1.4.17/iptables/xtables-multi $(MODEL_FS_PATH)/usr/bin
	cd $(MODEL_FS_PATH)/usr/bin && ln -s xtables-multi iptables
	
ifeq ($(INCLUDE_IPV6), y)
	cd $(MODEL_FS_PATH)/usr/bin && ln -s xtables-multi ip6tables
endif

ifeq ($(INCLUDE_ADSLWAN), y)
	cp -p $(PUBLIC_APPS_PATH)/br2684ctl/br2684ctl $(MODEL_FS_PATH)/usr/bin
endif
	cp -p $(PUBLIC_APPS_PATH)/ppp-2.4.5/pppd/pppd $(MODEL_FS_PATH)/usr/sbin
	cp -p $(PUBLIC_APPS_PATH)/ebtables-v2.0.10-4/ebtables $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/IGD/upnpd $(MODEL_FS_PATH)/usr/bin
ifeq ($(INCLUDE_ADSLWAN), y)
	cp -p $(PUBLIC_APPS_PATH)/linux-atm/arpd/atmarp $(MODEL_FS_PATH)/usr/sbin
	cp -p $(PUBLIC_APPS_PATH)/linux-atm/arpd/atmarpd $(MODEL_FS_PATH)/usr/sbin
endif
	
ifeq ($(INCLUDE_L2TP), y)
	cp -p $(PUBLIC_APPS_PATH)/xl2tpd-1.1.12/xl2tpd $(MODEL_FS_PATH)/usr/sbin
endif

ifeq ($(INCLUDE_BPA), y)
	cp -p $(PUBLIC_APPS_PATH)/bpalogin-2.0.2/bpalogin $(MODEL_FS_PATH)/usr/sbin
endif

ifeq ($(INCLUDE_USB_OVER_IP_TPLINK), y)
	cp -p $(PUBLIC_APPS_PATH)/usbip-0.1.7/usbipd $(MODEL_FS_PATH)/usr/bin
endif

ifeq ($(INCLUDE_USB_FTP_SERVER), y)
	cp -p $(PUBLIC_APPS_PATH)/vsftpd-2.3.2/vsftpd $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/vsftpd-2.3.2/vsftpd.conf $(MODEL_FS_PATH)/etc
	cp -p $(PUBLIC_APPS_PATH)/vsftpd-2.3.2/passwd $(MODEL_FS_PATH)/etc/vsftpd_passwd
endif
	
ifeq ($(INCLUDE_RIP), y)
	cp -p $(PUBLIC_APPS_PATH)/zebra-0.95a/ripd/ripd $(MODEL_FS_PATH)/usr/sbin
	cp -p $(PUBLIC_APPS_PATH)/zebra-0.95a/zebra/zebra $(MODEL_FS_PATH)/usr/sbin
endif

ifneq ($(strip $(INCLUDE_VOIP)),)
	cp $(APP_VOIP_DIR)/bin/$(MODEL)/* $(MODEL_FS_PATH)/usr/bin
	cp $(APP_PJSIP_DIR)/pjsip-apps/bin/pjsua $(MODEL_FS_PATH)/usr/bin
endif	

ifeq ($(INCLUDE_IPV6), y)
	cp -p $(PUBLIC_APPS_PATH)/radvd-1.5/radvd $(MODEL_FS_PATH)/usr/sbin
endif

ifeq ($(INCLUDE_IPV6), y)
	cp -p $(PUBLIC_APPS_PATH)/wide-dhcpv6-20080615/dhcp6s $(MODEL_FS_PATH)/usr/sbin
	cp -p $(PUBLIC_APPS_PATH)/wide-dhcpv6-20080615/dhcp6c $(MODEL_FS_PATH)/usr/sbin
endif	
	
ifeq ($(INCLUDE_IPV6), y)
	cp -p $(PUBLIC_APPS_PATH)/iproute2-2.6.39/ip/ip $(MODEL_FS_PATH)/usr/bin
endif	
	
ifeq ($(INCLUDE_USB_STORAGE),y)
	#for the bins of samba and ntfs-3g, zjj, 20111129
	cp -p $(PUBLIC_APPS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/src/.libs/ntfs-3g $(MODEL_FS_PATH)/usr/bin/ntfs-3g
ifeq ($(INCLUDE_USB_SAMBA_SERVER), y)
	cp -p $(PUBLIC_APPS_PATH)/samba-3.0.14a/source/bin/smbd $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/samba-3.0.14a/source/bin/smbpasswd $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/samba-3.0.14a/source/bin/smbcontrol $(MODEL_FS_PATH)/usr/bin
endif #INCLUDE_USB_SAMBA_SERVER
	#end by zjj

#for dlna ,LI CHENGLONG
ifeq ($(INCLUDE_USB_MEDIA_SERVER), y)
	cp -p $(PUBLIC_APPS_PATH)/ushare-1.1a/src/ushare $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/ushare-1.1a/scripts/ushare.conf $(MODEL_FS_PATH)/etc/ushare.conf
endif #INCLUDE_USB_MEDIA_SERVER
#end by LI CHENGLONG

#for ipping and traceroute, Zhu Haiming
ifeq ($(INCLUDE_IPPING_DIAG), y)
	cp -p $(PUBLIC_APPS_PATH)/ipping/ipping $(MODEL_FS_PATH)/usr/bin
endif #INCLUDE_IPPING_DIAG
ifeq ($(INCLUDE_TRACEROUTE_DIAG), y)
	cp -p $(PUBLIC_APPS_PATH)/traceroute-2.0.3/traceroute/traceroute $(MODEL_FS_PATH)/usr/bin
endif #INCLUDE_TRACEROUTE_DIAG
#end by Zhu Haiming
else
ifeq ($(INCLUDE_USB_3G_DONGLE),y)
	cp $(PRIVATE_APPS_PATH)/hotplug/hotplug $(MODEL_FS_PATH)/sbin
endif #INCLUDE_USB_3G_DONGLE
endif #INCLUDE_USB_STORAGE
	
ifeq ($(INCLUDE_USB_3G_DONGLE),y)
	cp $(PRIVATE_APPS_PATH)/handle_card/modswitch_conf/support_3g_list $(MODEL_FS_PATH)/etc
	cp $(PUBLIC_APPS_PATH)/usb-modeswitch-1.2.3/usb_modeswitch $(MODEL_FS_PATH)/usr/bin
	cp $(PUBLIC_APPS_PATH)/ppp-2.4.5/chat/chat $(MODEL_FS_PATH)/usr/bin
	cp -pR $(PRIVATE_APPS_PATH)/handle_card/source/handle_card $(MODEL_FS_PATH)/usr/sbin/
	cp -pR $(PRIVATE_APPS_PATH)/handle_card/modem_scan/modem_scan $(MODEL_FS_PATH)/usr/sbin/
	cp -pR $(PRIVATE_APPS_PATH)/handle_card/chat_script/* $(MODEL_FS_PATH)/etc/ppp/
	cp -pR $(PRIVATE_APPS_PATH)/handle_card/modswitch_conf/mode_switch.conf.bin $(MODEL_FS_PATH)/etc/
endif #INCLUDE_USB_3G_DONGLE
	
ifeq ($(INCLUDE_IPSEC),y)
	cp -p $(PUBLIC_APPS_PATH)/ipsectools/src/racoon/.libs/racoon $(MODEL_FS_PATH)/usr/bin
	cp -p $(PUBLIC_APPS_PATH)/ipsectools/src/setkey/.libs/setkey $(MODEL_FS_PATH)/usr/bin
	#copy ipsecVpn in user cmm Makefile
	#cp -p $(PRIVATE_APPS_PATH)/user/ipsecVpn/ipsecVpn $(MODEL_FS_PATH)/usr/sbin
endif

ifeq ($(strip $(SUPPLIER)),mtk_ApSoC_4120)
	cp $(TOP_PATH)/$(SUPPLIER)/apps/reg/reg $(MODEL_FS_PATH)/usr/bin
	cp $(TOP_PATH)/$(SUPPLIER)/apps/hw_nat/hw_nat $(MODEL_FS_PATH)/usr/bin
	cp $(TOP_PATH)/$(SUPPLIER)/apps/hw_nat/mtr $(MODEL_FS_PATH)/usr/bin
	cp $(TOP_PATH)/$(SUPPLIER)/apps/hw_nat/acl $(MODEL_FS_PATH)/usr/bin
	cp $(TOP_PATH)/$(SUPPLIER)/apps/hw_nat/ac $(MODEL_FS_PATH)/usr/bin

ifeq ($(INCLUDE_LAN_WLAN), y) 
	cp $(INSTALL_WIRELESS)/sbin/iwpriv $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/wlNetlinkTool $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/lib/libiw.so.29 $(MODEL_FS_PATH)/lib
	cp $(INSTALL_WIRELESS)/sbin/ated_tp $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/ated $(MODEL_FS_PATH)/usr/bin
	#cp $(INSTALL_WIRELESS)/sbin/mpstat $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/rt2860apd $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/rtinicapd $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/wscd $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/sbin/wscd_5G $(MODEL_FS_PATH)/usr/bin
	cp $(INSTALL_WIRELESS)/lib/firmware/MT7610E-V10-FEM-1ANT.bin $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/RT2860AP5G.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/SingleSKU_5G_FCC.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/SingleSKU_5G_CE.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/RT2860AP.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/SingleSKU_FCC.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/SingleSKU_CE.dat $(MODEL_FS_PATH)/etc/
	cp $(INSTALL_WIRELESS)/lib/firmware/MT7620_AP_2T2R-4L_V15.BIN $(MODEL_FS_PATH)/etc/
	#cp -p $(INSTALL_WIRELESS)/sbin/rt2860apd	$(MODEL_FS_PATH)/usr/bin
#Build wscd with wifi modules
	#cp $(TOP_PATH)/$(SUPPLIER)/filesystem/usr/bin/wscd $(MODEL_FS_PATH)/usr/bin
	chmod +x $(MODEL_FS_PATH)/usr/bin/*
else	#INCLUDE_LAN_WLAN
	@echo no wifi
endif	#INCLUDE_LAN_WLAN

endif	#SUPPLIER-mtk_ApSoC_4120

.PHONY:fs_modules
fs_modules:
	cp -pR $(MODULE_TG_PATH)/* $(MODEL_FS_PATH)/lib/modules
	#test -e $(TP_MODULES_PATH)/ko && cp -pR $(TP_MODULES_PATH)/ko/*.ko $(MODEL_FS_PATH)/lib/modules

ifeq ($(INCLUDE_USB_OVER_IP), y)
ifeq ($(INCLUDE_USB_OVER_IP_TPLINK), y)
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/public/usbip-0.1.7/usbip.ko $(MODEL_FS_PATH)/lib/modules
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/public/usbip-0.1.7/usbip_common_mod.ko $(MODEL_FS_PATH)/lib/modules
else   # INCLUDE_USB_OVER_IP_TPLINK
ifeq ($(INCLUDE_VOIP), y)
ifeq ($(strip $(CONFIG_NR_CPUS)), 2)
	cp -p $(TP_MODULES_PATH)/ko/kcode/NetUSB2_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/NetUSB.ko
	-cp -p $(TP_MODULES_PATH)/ko/kcode/GPL_NetUSB2_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/GPL_NetUSB.ko
else   # CONFIG_NR_CPUS
	cp -p $(TP_MODULES_PATH)/ko/kcode/NetUSB_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/NetUSB.ko
	-cp -p $(TP_MODULES_PATH)/ko/kcode/GPL_NetUSB_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/GPL_NetUSB.ko
endif  # CONFIG_NR_CPUS	
else   # INCLUDE_VOIP
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/private/kcode/NetUSB_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/NetUSB.ko
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/private/kcode/GPL_NetUSB_$(MODEL).ko $(MODEL_FS_PATH)/lib/modules/GPL_NetUSB.ko
endif  # INCLUDE_VOIP	
endif  # INCLUDE_USB_OVER_IP_TPLINK
endif  # INCLUDE_USB_OVER_IP

ifeq ($(INCLUDE_PPTP), y)
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/public/accel-pptp-0.8.5/pptp.ko $(MODEL_FS_PATH)/lib/modules
endif

ifeq ($(INCLUDE_L2TP), y)
ifeq ($(KERNELVERSION), 2.6.22.15)
	cp -p $(TOP_PATH)/$(SUPPLIER)/modules/public/pppol2tp-kmod-0.17/pppol2tp.ko $(MODEL_FS_PATH)/lib/modules
else
ifeq ($(KERNELVERSION), 2.6.36)
	cp -p $(KERNELPATH)/net/l2tp/l2tp_core.ko $(MODEL_FS_PATH)/lib/modules/pppol2tp.ko
	cp -p $(KERNELPATH)/net/l2tp/l2tp_ppp.ko $(MODEL_FS_PATH)/lib/modules/l2tp_ppp.ko
	rm $(MODEL_FS_PATH)/lib/modules/kmdir/kernel/net/l2tp/*.ko
else
	cp -p $(KERNELPATH)/drivers/net/pppol2tp.ko $(MODEL_FS_PATH)/lib/modules
endif
endif
endif
	
.PHONY:fs_rootfs
fs_rootfs: fakeroot
	find  $(MODEL_FS_PATH) -name ".svn" | xargs rm -rf
	cd $(TOOLS_PATH) && $(FAKEROOT_PATH)/fakeroot ./buildFs $(MODEL_FS_PATH) $(ROOTFSTOOLS) $(MODEL) $(SUPPLIER)

$(FAKEROOT_PATH)/.configured:
	(tar -jkxf fakeroot.tar.bz2 2> /dev/null || true)
	cd $(FAKEROOT_PATH); CFLAGS="-O2 -DGNU -I./" CC=gcc ./configure --prefix=/usr --disable-nls
	touch $@
	make -C $(FAKEROOT_PATH)

.PHONY:fakeroot
fakeroot: $(FAKEROOT_PATH)/.configured
	@sed -e 's,^PREFIX=.*,PREFIX=$(FAKEROOT_PATH),g' -e 's,^BINDIR=.*,BINDIR=$(FAKEROOT_PATH),g' -e 's,^PATHS=.*,PATHS=$(FAKEROOT_PATH)/.libs:/lib:/usr/lib,g' $(FAKEROOT_PATH)/scripts/fakeroot > $(FAKEROOT_PATH)/fakeroot
	@chmod u+x $(FAKEROOT_PATH)/fakeroot