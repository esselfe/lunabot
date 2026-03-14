AC_INIT([lunabot], [0.5.6], [], [lunabot])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
AC_PROG_CC
LT_INIT([dlopen])

PKG_CHECK_MODULES([MICROHTTPD], [libmicrohttpd])
PKG_CHECK_MODULES([JANSSON], [jansson])
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0])

AX_PTHREAD([], [AC_MSG_ERROR([pthread is required])])
AC_SEARCH_LIBS([dlopen], [dl], [], [AC_MSG_ERROR([dlopen is required])])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
