
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# lib/sshutil/sshadt Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore 
LDADD = $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=tmo@ssh.com

EXTRA_DIST = 

noinst_LIBRARIES = libsshadt.a

libsshadt_a_SOURCES = \
	sshadt.c sshadt_assoc.c sshadt_list.c sshadt_map.c sshadt_array.c \
	sshadt_priority_heap.c sshadt_avltree.c sshadt_ranges.c sshadt_conv.c

public_headers += \
	sshadt.h sshadt_impls.h sshadt_shortcuts.h sshadt_structs.h \
	sshadt_list.h sshadt_map.h sshadt_xmap.h sshadt_bag.h \
	sshadt_strmap.h sshadt_intmap.h sshadt_conv.h \
	sshadt_array.h sshadt_priority_queue.h sshadt_priority_heap.h \
	sshadt_avltree.h sshadt_ranges.h \
	sshadt_assoc.h

private_headers += \
	sshadt_list_i.h sshadt_array_i.h sshadt_map_i.h sshadt_bag_i.h \
	sshadt_avltree_i.h sshadt_priority_heap_i.h \
	sshadt_i.h sshadt_std_i.h

GRANDLIB_OBJECTS =  $(libsshadt_a_OBJECTS) $(libsshadt_a_LIBADD)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
