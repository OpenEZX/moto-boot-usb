AC_PREREQ(2.60)
AC_INIT([boot_usb], [0.3], [openezx-devel@lists.openezx.org])
AC_CONFIG_SRCDIR([boot_usb.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall foreign])

AC_ARG_WITH(kernel-dir,
	AC_HELP_STRING([--with-kernel-dir=DIR], [location of kernel sources]),
	[KERNEL_DIR=${withval}],
	[KERNEL_DIR=/usr/src/linux])
AC_SUBST(KERNEL_DIR)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES(USB, libusb,,
	AC_MSG_ERROR([*** Required libusb not installed ***]))
AC_CHECK_LIB([usb], [usb_init],,,-lusb)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h unistd.h string.h getopt.h errno.h])
AC_CHECK_HEADERS([sys/types.h sys/stat.h sys/mman.h fcntl.h arpa/inet.h usb.h])

# We need the setup.h for the 'arm' architecture
AC_MSG_CHECKING([for asm/setup.h])
CPPFLAGS="-I$KERNEL_DIR/arch/arm/include -I$KERNEL_DIR/include"
# Grepping for tag_mem32 should be safe, only 'arm' defines it
AC_EGREP_HEADER(tag_mem32, asm/setup.h,
	[AC_MSG_RESULT(yes)],
	[AC_MSG_FAILURE([Could not find kernel headers, use --with-kernel-dir=DIR option])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
