.set project_name sshnet
.set project_type applib
.set project_platforms
.set project_guid E6E2CD1C-CBDD-39F7-8900-1B19140A1334
.set project_dir lib\\sshutil\\sshnet
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshutil \
	. \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\sshadt \
	lib\\sshutil\\ssheloop \
	lib\\sshutil\\sshstrutil \
	lib\\sshutil\\sshfsm \
	lib\\sshutil\\sshstream \
	lib\\sshutil\\sshsysutil \
	lib\\sshutil\\sshnet\\win32 \
	lib\\sshutil\\sshnet
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	sshdnserror.c \
	sshdnsnameserver.c \
	sshdnspacket.c \
	sshdnspacketrender.c \
	sshdnsquery.c \
	sshdnsrender.c \
	sshdnsresolver.c \
	sshdnsrrdataprint.c \
	sshdnsrrsetcache.c \
	sshdnsrrsetrender.c \
	sshdnsrrtype.c \
	sshdnstransport.c \
	sshdnstransporttcp.c \
	sshdnstransportudp.c \
	sshicmp-util.c \
	sshinet.c \
	sshinetbits.c \
	sshinetcalc.c \
	sshinetcompare.c \
	sshinetencode.c \
	sshinetether.c \
	sshinethash.c \
	sshinetmapped.c \
	sshinetmask.c \
	sshinetmerge.c \
	sshinetnetmask.c \
	sshinetparse.c \
	sshinetprint.c \
	sshinetproto.c \
	sshinetrender.c \
	sshinetscope.c \
	sshinetstrtobin.c \
	sshnameserver.c \
	sshnetconfig.c \
	sshsocks.c \
	sshtcp.c \
	sshudp-ip.c \
	sshudp-str.c \
	sshurl.c \
	sshwinlocalstream.c \
	sshwintcp2.c \
	sshwinudp2.c \
	sshwinutil2.c
.set dir_sshdnserror.c lib\\sshutil\\sshnet 
.set dir_sshdnsnameserver.c lib\\sshutil\\sshnet 
.set dir_sshdnspacket.c lib\\sshutil\\sshnet 
.set dir_sshdnspacketrender.c lib\\sshutil\\sshnet 
.set dir_sshdnsquery.c lib\\sshutil\\sshnet 
.set dir_sshdnsrender.c lib\\sshutil\\sshnet 
.set dir_sshdnsresolver.c lib\\sshutil\\sshnet 
.set dir_sshdnsrrdataprint.c lib\\sshutil\\sshnet 
.set dir_sshdnsrrsetcache.c lib\\sshutil\\sshnet 
.set dir_sshdnsrrsetrender.c lib\\sshutil\\sshnet 
.set dir_sshdnsrrtype.c lib\\sshutil\\sshnet 
.set dir_sshdnstransport.c lib\\sshutil\\sshnet 
.set dir_sshdnstransporttcp.c lib\\sshutil\\sshnet 
.set dir_sshdnstransportudp.c lib\\sshutil\\sshnet 
.set dir_sshicmp-util.c lib\\sshutil\\sshnet 
.set dir_sshinet.c lib\\sshutil\\sshnet 
.set dir_sshinetbits.c lib\\sshutil\\sshnet 
.set dir_sshinetcalc.c lib\\sshutil\\sshnet 
.set dir_sshinetcompare.c lib\\sshutil\\sshnet 
.set dir_sshinetencode.c lib\\sshutil\\sshnet 
.set dir_sshinetether.c lib\\sshutil\\sshnet 
.set dir_sshinethash.c lib\\sshutil\\sshnet 
.set dir_sshinetmapped.c lib\\sshutil\\sshnet 
.set dir_sshinetmask.c lib\\sshutil\\sshnet 
.set dir_sshinetmerge.c lib\\sshutil\\sshnet 
.set dir_sshinetnetmask.c lib\\sshutil\\sshnet 
.set dir_sshinetparse.c lib\\sshutil\\sshnet 
.set dir_sshinetprint.c lib\\sshutil\\sshnet 
.set dir_sshinetproto.c lib\\sshutil\\sshnet 
.set dir_sshinetrender.c lib\\sshutil\\sshnet 
.set dir_sshinetscope.c lib\\sshutil\\sshnet 
.set dir_sshinetstrtobin.c lib\\sshutil\\sshnet 
.set dir_sshnameserver.c lib\\sshutil\\sshnet 
.set dir_sshnetconfig.c lib\\sshutil\\sshnet 
.set dir_sshsocks.c lib\\sshutil\\sshnet 
.set dir_sshtcp.c lib\\sshutil\\sshnet 
.set dir_sshudp-ip.c lib\\sshutil\\sshnet 
.set dir_sshudp-str.c lib\\sshutil\\sshnet 
.set dir_sshurl.c lib\\sshutil\\sshnet 
.set dir_sshwinlocalstream.c lib\\sshutil\\sshnet\\win32 
.set dir_sshwintcp2.c lib\\sshutil\\sshnet\\win32 
.set dir_sshwinudp2.c lib\\sshutil\\sshnet\\win32 
.set dir_sshwinutil2.c lib\\sshutil\\sshnet\\win32 
.set custom_tags
.set rsrcs
.set hdrs \
	sshdns.h \
	sshdnsnameserver.h \
	sshdnspacket.h \
	sshdnsquery.h \
	sshdnsresolver.h \
	sshdnsrrsetcache.h \
	sshdnstransport.h \
	sshdnstransportimpl.h \
	sshether.h \
	sshicmp-util.h \
	sshinet.h \
	sshinetencode.h \
	sshlinuxnetconfig_i.h \
	sshlocalstream.h \
	sshnameserver.h \
	sshnetconfig.h \
	sshnetevent.h \
	sshnetmac.h \
	sshsocks.h \
	sshtcp.h \
	sshudp.h \
	sshurl.h
.set dir_sshdns.h lib\\sshutil\\sshnet 
.set dir_sshdnsnameserver.h lib\\sshutil\\sshnet 
.set dir_sshdnspacket.h lib\\sshutil\\sshnet 
.set dir_sshdnsquery.h lib\\sshutil\\sshnet 
.set dir_sshdnsresolver.h lib\\sshutil\\sshnet 
.set dir_sshdnsrrsetcache.h lib\\sshutil\\sshnet 
.set dir_sshdnstransport.h lib\\sshutil\\sshnet 
.set dir_sshdnstransportimpl.h lib\\sshutil\\sshnet 
.set dir_sshether.h lib\\sshutil\\sshnet 
.set dir_sshicmp-util.h lib\\sshutil\\sshnet 
.set dir_sshinet.h lib\\sshutil\\sshnet 
.set dir_sshinetencode.h lib\\sshutil\\sshnet 
.set dir_sshlinuxnetconfig_i.h lib\\sshutil\\sshnet 
.set dir_sshlocalstream.h lib\\sshutil\\sshnet 
.set dir_sshnameserver.h lib\\sshutil\\sshnet 
.set dir_sshnetconfig.h lib\\sshutil\\sshnet 
.set dir_sshnetevent.h lib\\sshutil\\sshnet 
.set dir_sshnetmac.h lib\\sshutil\\sshnet 
.set dir_sshsocks.h lib\\sshutil\\sshnet 
.set dir_sshtcp.h lib\\sshutil\\sshnet 
.set dir_sshudp.h lib\\sshutil\\sshnet 
.set dir_sshurl.h lib\\sshutil\\sshnet 
