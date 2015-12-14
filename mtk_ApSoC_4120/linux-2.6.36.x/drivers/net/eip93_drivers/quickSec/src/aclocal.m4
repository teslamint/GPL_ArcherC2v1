dnl aclocal.m4 generated automatically by aclocal 1.4-p6

dnl Copyright (C) 1994, 1995-8, 1999, 2001 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

#
# acinclude.m4.head
#
# Author: Tero Kivinen <kivinen@ssh.fi>
# 	  Tatu Ylonen  <ylo@ssh.fi>
#	  Sami Lehtinen <sjl@ssh.fi>
#
# Copyright:
#         Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved.
#
#

dnl   Add argument to CFLAGS if using gcc.
AC_DEFUN([AC_ADD_GCC_CFLAGS],
[AC_REQUIRE([AC_PROG_CC])
 if test -n "$GCC"; then
    CFLAGS="$CFLAGS $1"
 fi
 ])

dnl Add argument to CFLAGS if supported by compiler.
dnl If not supported run second argument.
AC_DEFUN([AC_TRY_ADD_CFLAGS],
[ CFLAGS_store="$CFLAGS"
  CFLAGS="$CFLAGS $1"
  AC_MSG_CHECKING(whether compiler accepts $1)
  AC_TRY_LINK(,,AC_MSG_RESULT(yes),
                [AC_MSG_RESULT(no)
                 CFLAGS="$CFLAGS_store"
                 $2])
  unset CFLAGS_store
])

dnl   Check canonical host type; abort if environment changed.  $1 is
dnl   additional data that we guard from changing.
AC_DEFUN([AC_CANONICAL_HOST_CHECK],
[ AC_CANONICAL_HOST
  AC_MSG_CHECKING(cached information)
  hostcheck="$host"
  AC_CACHE_VAL(ac_cv_hostcheck, [ ac_cv_hostcheck="$hostcheck" ])
  if test "$ac_cv_hostcheck" != "$hostcheck"; then
    AC_MSG_RESULT(changed)
    AC_MSG_WARN(config.cache exists!)
    AC_MSG_ERROR(you must do 'make distclean' first to compile for different host or different parameters.)
  else
    AC_MSG_RESULT(ok)
  fi
])

# Based on autoconf.
AC_DEFUN([AC_SSH_BIGENDIAN],
[AC_CACHE_CHECK(whether byte ordering is bigendian, ac_cv_c_bigendian,
[ac_cv_c_bigendian=unknown
# See if sys/param.h defines the BYTE_ORDER macro.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
 bogus endian macros
#endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if BYTE_ORDER != BIG_ENDIAN
 not big endian
#endif], ac_cv_c_bigendian=yes, ac_cv_c_bigendian=no)])
if test $ac_cv_c_bigendian = unknown; then
AC_TRY_RUN([main () {
  /* Are we little or big endian?  From Harbison&Steele.  */
  union
  {
    long l;
    char c[sizeof (long)];
  } u;
  u.l = 1;
  exit (u.c[sizeof (long) - 1] == 1);
}], ac_cv_c_bigendian=no, ac_cv_c_bigendian=yes,
 AC_MSG_ERROR(Cannot cross-compile without BYTE_ORDER set in sys/param.h.))
fi])
if test $ac_cv_c_bigendian = yes; then
  AC_DEFINE(WORDS_BIGENDIAN, 1, "")
fi
])
])])

dnl ### Checking compiler characteristics
dnl ### This is copied from acgeneral.m4, but adopted to use a "prefix"
dnl ### specificator instad of fixed sizeof_

dnl AC_CHECK_SIZEOF_WITH_PREFIX(PREFIX, TYPE [, CROSS-SIZE])
AC_DEFUN([AC_CHECK_SIZEOF_WITH_PREFIX],
[changequote(<<, >>)dnl
dnl The name to #define.
define(<<AC_TYPE_NAME>>, translit($1_sizeof_$2, [a-z *], [A-Z_P]))dnl
dnl The "HAVE_" variable
define(<<AC_HAVE_TYPE_NAME>>, translit(have_$1_$2, [a-z *], [A-Z_P]))dnl
dnl The cache variable name.
define(<<AC_CV_NAME>>, translit(ac_cv_$1_sizeof_$2, [ *], [_p]))dnl
changequote([, ])dnl
AC_MSG_CHECKING(size of $1 $2)
AC_CACHE_VAL(AC_CV_NAME,
[AC_TRY_RUN([#include <stdio.h>
main()
{
  FILE *f=fopen("conftestval", "w");
  if (!f) exit(1);
  fprintf(f, "%d\n", sizeof($2));
  exit(0);
}], AC_CV_NAME=`cat conftestval`, AC_CV_NAME=0, ifelse([$3], , , AC_CV_NAME=$3))])dnl
AC_MSG_RESULT($AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_TYPE_NAME, $AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_HAVE_TYPE_NAME)
undefine([AC_TYPE_NAME])dnl
undefine([AC_CV_NAME])dnl
])

dnl Check if we are using GNU Make and can use GNU Make specific extension.

AC_DEFUN([AC_CHECK_GNU_MAKE],
[AC_MSG_CHECKING(whether ${MAKE-make} is GNU Make)
AC_CACHE_VAL(ac_cv_make_is_GNU_make,
[if eval "${MAKE-make} -f NONEXISTING-MAKE-FILE --version 2>&1 | grep 'GNU Make version' >/dev/null 2>&1"; then
  ac_cv_make_is_GNU_make=yes
else
  ac_cv_make_is_GNU_make=no
fi])
if test "$ac_cv_make_is_GNU_make" = "yes"; then
  AC_MSG_RESULT(yes)
  have_gnu_make=yes
else
  AC_MSG_RESULT(no)
  have_gnu_make=no
fi])


# Macros to add dynamically linked library paths into LIBS. This
# functionality is split into two parts: The first macro
# (AC_ADD_LIBDIR_PRE) checks whether the linker requires -R in
# addition to -L for link paths. The second macro (AC_ADD_LIBDIR)
# modifies LIBS.

# Check whether we must use -R, and also whether we need a space
# before -R or not.
dnl AC_ADD_LIBDIR_PRE()
AC_DEFUN([AC_ADD_LIBDIR_PRE],
[AC_CACHE_CHECK([if -R is also required when using -L to get programs to actually work],
ssh_cv_cc_R_require,
[case `(uname -sr) 2>/dev/null` in
  "SunOS 5"*)
    ssh_cv_cc_R_require=yes
    ;;
  *)
    ssh_cv_cc_R_require=no
    ;;
  esac])
if test "$ssh_cv_cc_R_require" = "yes"; then
  AC_CACHE_CHECK([if space is required after -R],
  ssh_cv_cc_R_space_require,
  [
    ssh_r_save_LIBS="$LIBS"; LIBS="$LIBS -R/usr/lib"
    AC_TRY_LINK(, , ssh_cc_R_nospace=yes, ssh_cc_R_nospace=no)
    if test $ssh_cc_R_nospace = yes; then
      ssh_cv_cc_R_space_require=no
    else
      LIBS="$ssh_r_save_LIBS -R $x_libraries"
      AC_TRY_LINK(, , ssh_cc_R_space=yes, ssh_cc_R_space=no)
      if test $ssh_cc_R_space = yes; then
        ssh_cv_cc_R_space_require=yes
      else
        ssh_cv_cc_R_space_require=unknown
      fi
    fi
    LIBS="$ssh_r_save_LIBS"
  ])
  if test "$ssh_cv_cc_R_space_require" = "yes"; then
    ssh_cc_R_space=" "
  else
    ssh_cc_R_space=""
  fi
  ssh_cc_R="yes"
fi])

# Note that AC_ADD_LIBDIR_PRE must have been called before this to
# determine whether -R is required in addition to -L.
dnl AC_ADD_LIBDIR(PATH)
AC_DEFUN([AC_ADD_LIBDIR],
[if test "$ssh_cv_cc_R_require" = ""; then
  AC_MSG_ERROR([prequisite macro has not been run])
fi
if test "$ssh_cc_R" = "yes"; then
  LDFLAGS="$LDFLAGS -R${ssh_cc_R_space}$1"
fi
LDFLAGS="$LDFLAGS -L$1"
])
#
# lib/acinclude.m4.inc
#
# Author: Tero Kivinen <kivinen@ssh.fi>
# 	  Tatu Ylonen  <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#
#
#
# acinclude.m4.tail
#
# Author: Santeri Paavolainen <santtu@ssh.com>
#
# Copyright:
#         Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved.
#

# Like AC_CONFIG_HEADER, but automatically create stamp file.

AC_DEFUN([AM_CONFIG_HEADER],
[AC_PREREQ([2.12])
AC_CONFIG_HEADER([$1])
dnl When config.status generates a header, we must update the stamp-h file.
dnl This file resides in the same directory as the config header
dnl that is generated.  We must strip everything past the first ":",
dnl and everything past the last "/".
AC_OUTPUT_COMMANDS(changequote(<<,>>)dnl
ifelse(patsubst(<<$1>>, <<[^ ]>>, <<>>), <<>>,
<<test -z "<<$>>CONFIG_HEADERS" || echo timestamp > patsubst(<<$1>>, <<^\([^:]*/\)?.*>>, <<\1>>)stamp-h<<>>dnl>>,
<<am_indx=1
for am_file in <<$1>>; do
  case " <<$>>CONFIG_HEADERS " in
  *" <<$>>am_file "*<<)>>
    echo timestamp > `echo <<$>>am_file | sed -e 's%:.*%%' -e 's%[^/]*$%%'`stamp-h$am_indx
    ;;
  esac
  am_indx=`expr "<<$>>am_indx" + 1`
done<<>>dnl>>)
changequote([,]))])

# Do all the work for Automake.  This macro actually does too much --
# some checks are only needed if your package does certain things.
# But this isn't really a big deal.

# serial 1

dnl Usage:
dnl AM_INIT_AUTOMAKE(package,version, [no-define])

AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
AC_REQUIRE([AC_PROG_INSTALL])
PACKAGE=[$1]
AC_SUBST(PACKAGE)
VERSION=[$2]
AC_SUBST(VERSION)
dnl test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" && test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi
ifelse([$3],,
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package]))
AC_REQUIRE([AM_SANITY_CHECK])
AC_REQUIRE([AC_ARG_PROGRAM])
dnl FIXME This is truly gross.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal-${am__api_version}, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake-${am__api_version}, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_REQUIRE([AC_PROG_MAKE_SET])])

# Copyright 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
AC_DEFUN([AM_AUTOMAKE_VERSION],[am__api_version="1.4"])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION so it can be traced.
# This function is AC_REQUIREd by AC_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
	 [AM_AUTOMAKE_VERSION([1.4-p6])])

#
# Check to make sure that the build environment is sane.
#

AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftestfile
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftestfile 2> /dev/null`
   if test "[$]*" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftestfile`
   fi
   if test "[$]*" != "X $srcdir/configure conftestfile" \
      && test "[$]*" != "X conftestfile $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "[$]2" = conftestfile
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
rm -f conftest*
AC_MSG_RESULT(yes)])

dnl AM_MISSING_PROG(NAME, PROGRAM, DIRECTORY)
dnl The program must properly implement --version.
AC_DEFUN([AM_MISSING_PROG],
[AC_MSG_CHECKING(for working $2)
# Run test in a subshell; some versions of sh will print an error if
# an executable is not found, even if stderr is redirected.
# Redirect stdin to placate older versions of autoconf.  Sigh.
if ($2 --version) < /dev/null > /dev/null 2>&1; then
   $1=$2
   AC_MSG_RESULT(found)
else
   $1="$3/missing $2"
   AC_MSG_RESULT(missing)
fi
AC_SUBST($1)])

# Define a conditional.

AC_DEFUN([AM_CONDITIONAL],
[AC_SUBST($1_TRUE)
AC_SUBST($1_FALSE)
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi])

