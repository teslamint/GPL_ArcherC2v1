
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshcore.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir) 
LDADD = 

WINCONF_OPTIONS = maintainer=mtr@ssh.com,kivinen@ssh.com,tmo@ssh.fi

noinst_LIBRARIES = \
	libsshcore.a

CONFOBJS = @LIBOBJS@

libsshcore_a_SOURCES =          \
        sshdebug.c              \
        sshfatal.c              \
        sshutil.c               \
        sshglobals.c            \
        sshmemcmp.c             \
        sshbuffer.c             \
        sshxbuffer.c            \
        sshtime.c               \
        sshcalendar.c           \
        sshsnprintf.c           \
        sshmalloc.c             \
        sshrecalloc.c           \
        sshxmalloc.c            \
        sshfastalloc.c          \
        sshrand.c               \
        sshmatch.c              \
        sshenum.c               \
        sshenumcase.c           \
        sshbprintf.c            \
        sshgetopt.c             \
        sshtimemeasure.c        \
        sshobstack.c            \
        sshmempool.c            \
        sshmempoolgen.c         \
        sshustr.c               \
        sshdllist.c             \
        sshdlqueue.c            \
        sshsimplehashtable.c    





libsshcore_a_LIBADD = $(CONFOBJS)


libsshcore_a_LIBADD_windelta =  \
	-$(CONFOBJS)

libsshcore_a_SOURCES_windelta = \
	+sshwindebug.c          \
        +wince_util.c           \
	+random.c



public_headers +=               \
        sshdebug.h              \
        sshwindebug.h           \
        sshenum.h               \
        sshglobals.h            \
        sshrand.h               \
        sshmemcmp.h             \
        sshtime.h               \
        sshsnprintf.h           \
        sshdsprintf.h           \
        sshfastalloc.h          \
        sshbuffer.h             \
        sshmalloc.h             \
        sshmatch.h              \
        sshgetput.h             \
        sshasmidioms.h          \
        sshbprintf.h            \
        sshrefcnt.h             \
        sshgetopt.h             \
        sshtimemeasure.h        \
        sshobstack.h            \
        sshmempool.h            \
        sshmempoolgen.h         \
        sshdllist.h             \
        sshdlqueue.h            \
        sshsimplehashtable.h    






EXTRA_DIST =            \
        memmove.c       \
        memset.c        \
        putenv.c        \
	random.c        \
        remove.c        \
        strcasecmp.c    \
        strerror.c      \
        strncasecmp.c   \
        getopt.c        \
	crypt.c         \
        sshwindebug.c   \
	wince_util.c    \
	inet_ntoa.c





GRANDLIB_OBJECTS = $(libsshcore_a_OBJECTS) $(libsshcore_a_LIBADD)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
