dnl Process this file with autoconf to create configure.

AC_INIT([libnetfilter_queue], [1.0.0])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects dist-bzip2 1.6])

AC_PROG_CC
AC_EXEEXT
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL

AC_SUBST(LIBTOOL_DEPS)

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

dnl Dependencies
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 0.0.41])

dnl Output the makefiles
AC_OUTPUT(Makefile include/Makefile include/libnetfilter_queue/Makefile src/Makefile utils/Makefile libnetfilter_queue.pc doxygen.cfg)
