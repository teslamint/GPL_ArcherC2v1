#
#   Copyright (c) 2000, 2001	    Dmitry K. Butskoj
#				    <buc@citadel.stu.neva.ru>
#   License:  GPL/LGPL		
#
#   See COPYING/COPYING.LIB for the status of this software.
#

#
#   Global Makefile.
#   Global rules, targets etc.
#
#   See Make.defines for specific configs.
#


srcdir = $(CURDIR)

override TARGET := .MAIN

dummy: all

include ./Make.rules


targets = $(EXEDIRS) $(LIBDIRS) $(MODDIRS)

# be happy, easy, perfomancy...
.PHONY: $(subdirs) dummy all force
.PHONY: depend syntax indent clean distclean libclean release store libs mods


allprereq := $(EXEDIRS)

ifneq ($(LIBDIRS),)
libs: $(LIBDIRS)
ifneq ($(EXEDIRS),)
$(EXEDIRS): libs
else
allprereq += libs
endif
endif

ifneq ($(MODDIRS),)
mods: $(MODDIRS)
ifneq ($(MODUSERS),)
$(MODUSERS): mods
else
allprereq += mods
endif
ifneq ($(LIBDIRS),)
$(MODDIRS): libs
endif
endif

all: $(allprereq)


ifneq ($(share),)
$(share): shared := shared
endif
ifneq ($(noshare),)
$(noshare): shared := 
endif


$(targets): mkfile = $(if $(wildcard $@/Makefile),,-f $(srcdir)/default.rules)

$(targets): force
	@$(MAKE) $(mkfile) shared=$(shared) -C $@ all TARGET=$@

force:


depend syntax:
	@for i in $(targets) ;\
	do           \
	    mkfile= ;\
	    [ -r $$i/Makefile ] || mkfile="-f $(srcdir)/default.rules" ;\
	    $(MAKE) $$mkfile shared=$(shared) -C $$i $@ ;\
	done

indent:
	find . -type f -name "*.[ch]" -print -exec $(INDENT) {} \;

clean:
	rm -f $(foreach exe, $(EXEDIRS), ./$(exe)/$(exe)) nohup.out
	rm -f `find . \( -name "*.[oa]" -o -name "*.[ls]o" \
		-o -name core -o -name "core.[0-9]*" -o -name a.out \) -print`

distclean: clean
	rm -f `find $(foreach dir, $(subdirs), $(dir)/.) \
		\( -name "*.[oa]" -o -name "*.[ls]o" \
		-o -name core -o -name "core.[0-9]*" -o -name a.out \
		-o -name .depend -o -name "_*" -o -name ".cross:*" \) \
		-print`


libclean:
	rm -f $(foreach lib, $(LIBDIRS), ./$(lib)/$(lib).a ./$(lib)/$(lib).so)


#  Rules to make whole-distributive operations.
#

STORE_DIR = $(HOME)/pub

release release1 release2 release3:
	@./chvers.sh $@
	@$(MAKE) store

store: distclean
	@./store.sh $(NAME) $(STORE_DIR)


#  Rules to install.

ifneq ($(filter install%,$(MAKECMDGOALS)),)

destdirs :=
instprereq :=

#  install path prefix addon...
ROOT =


ifneq ($(EXEDIRS),)

binsrc := $(filter-out test% $(SBINUSERS),$(EXEDIRS))
binsrc := $(foreach bin,$(binsrc),./$(bin)/$(bin))
binsrc := $(wildcard $(binsrc))
sbinsrc := $(foreach sbin,$(filter $(SBINUSERS),$(EXEDIRS)),./$(sbin)/$(sbin))
sbinsrc := $(wildcard $(sbinsrc))

ifneq ($(binsrc),)
destdirs += $(ROOT)$(bindir)
instprereq += install-bins
install-bins: $(ROOT)$(bindir)
	$(INSTALL) $(binsrc) $(ROOT)$(bindir)
endif

ifneq ($(sbinsrc),)
destdirs += $(ROOT)$(sbindir)
instprereq += install-sbins
install-sbins: $(ROOT)$(sbindir)
	$(INSTALL) $(sbinsrc) $(ROOT)$(sbindir)
endif
endif


ifneq ($(LIBDIRS),)

libarchs := $(wildcard $(foreach lib,$(LIBDIRS),./$(lib)/$(lib).a))
libshares := $(wildcard $(foreach lib,$(LIBDIRS),./$(lib)/$(lib).so))

ifneq ($(libarchs)$(libshares),)
destdirs += $(ROOT)$(libdir)
instprereq += install-libs
install-libs: $(ROOT)$(libdir)
	$(INSTALL) $(libarchs) $(libshares) $(ROOT)$(libdir)
endif
endif


ifneq ($(MODDIRS),)
modsrc := $(wildcard $(foreach mod,$(MODDIRS),$(mod)/*.so))

ifneq ($(modsrc),)
instprereq += install-mods

ifeq ($(words $(MODDIRS)),1)
destdirs += $(ROOT)$(libexecdir)
install-mods: $(ROOT)$(libexecdir)
	$(INSTALL) $(modsrc) $(ROOT)$(libexecdir)
else
libexecs := $(foreach mod,$(MODDIRS),$(ROOT)/$(libexecdir)/$(mod))
destdirs += $(libexecs)
define nl
@@@

endef
cmda := $(foreach src,$(modsrc),$(ROOT)/$(libexecdir)/$(dir $(src)))
cmdb := $(patsubst %,@@@%$(nl),$(cmda))
cmdc := $(join $(modsrc),$(cmdb))
cmdd := $(foreach cmd,$(cmdc),$(INSTALL) $(cmd))
cmdinst := $(subst @@@, ,$(cmdd))

install-mods: $(libexecs)
	$(cmdinst)
endif
endif

endif


ifneq ($(LIBDIRS)$(MODDIRS),)
list := $(LIBDIRS)
ifneq ($(MODDIRS),)
list += $(INCLUDEDIRS)
endif
includes := $(wildcard $(foreach dir,$(list),./$(dir)/*.h))
includes := $(filter-out %/version.h %/Version.h, $(includes))

ifneq ($(includes),)
destdirs += $(ROOT)$(includedir)
instprereq += install-includes
install-includes: $(ROOT)$(includedir)
	$(INSTALL) $(includes) $(ROOT)$(includedir)
endif
endif


.PHONY: install $(instprereq)

_post = $(POSTINSTALL)
ifeq ($(_post),)
_post = @true
endif

install: $(instprereq)
	$(_post)

ifneq ($(destdirs),)
$(destdirs):
	mkdir -p $@
endif

endif

