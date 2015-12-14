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

########################################################################

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
