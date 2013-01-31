AC_INIT([ssh-blocker], [0.1], [lekensteyn@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC

AM_CONDITIONAL(WITH_SYSTEMD, [test "x$have_manpages" = "xyes"])
AC_ARG_ENABLE([systemd], [AS_HELP_STRING([--enable-systemd],
	[Support for systemd as log provider (default: disabled)])],
	[], [enable_systemd=no]
)
AS_IF([test "x$enable_systemd" = "xyes"], [
	PKG_CHECK_MODULES([systemd], [libsystemd-journal])
	AC_DEFINE([HAVE_SYSTEMD], 1, [support for systemd as log provider])
])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$enable_systemd" = "xyes"])

AC_CHECK_LIB([cap], [cap_set_proc])
PKG_CHECK_MODULES([ipset], [libipset]);
PKG_CHECK_MODULES([pcre], [libpcre]);

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION

	log source systemd: $enable_systemd

	CFLAGS: $CFLAGS
	CPPFLAGS: $CPPFLAGS
	LDFLAGS: $LDFLAGS
])
