AC_INIT([ssh-blocker], [0.1], [lekensteyn@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC

AC_CHECK_LIB([cap], [cap_set_proc])
PKG_CHECK_MODULES([ipset], [libipset]);
PKG_CHECK_MODULES([pcre], [libpcre]);

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
