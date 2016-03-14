#
#
#

### Prerequisites
AC_INIT([cjose], [0.1.0])
AM_INIT_AUTOMAKE([foreign])
LT_PREREQ([2.2])
LT_INIT([dlopen])
AC_CONFIG_MACRO_DIR([m4])

### Basic program checks
AC_PROG_CC

### Check for Doxygen
DX_FEATURE_pdf([OFF])
DX_FEATURE_ps([OFF])
DX_INIT_DOXYGEN([CJOSE], [Doxyfile], [doc])

### Check for CHECK
AM_PATH_CHECK([0.9.4])

#### Find OpenSSL
AC_MSG_CHECKING([for --with-openssl])
AC_ARG_WITH(
    [openssl],
    [AS_HELP_STRING([--with-openssl],[Location where OpenSSL can be found])],
    [ LDFLAGS="$LDFLAGS -L$with_openssl/lib";
      CFLAGS="$CFLAGS -I$with_openssl/include/";
      AC_MSG_RESULT([$with_openssl])
    ],
    [ AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([crypto],
    [CRYPTO_new_ex_data],
    [],
    [AC_MSG_ERROR([OpenSSL is missing; it is required for this software])]
)

#### Find JSON-C
AC_MSG_CHECKING([for --with-json-c])
AC_ARG_WITH(
    [json-c],
    [AS_HELP_STRING([--with-json-c], [Location where JSON-C can be found])],
    [ LDFLAGS="$LDFLAGS -L$with_json_c/lib";
      CFLAGS="$CFLAGS -I$with_json_c/include/";
      AC_MSG_RESULT([$with_json_c])
    ],
    [ AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([json-c],
    [json_c_version],
    [],
    [AC_MSG_ERROR([json-c is missing; it is required for this software])]
)

AC_CONFIG_FILES([Makefile
                 include/Makefile include/cjose/version.h
                 src/Makefile
                 test/Makefile
                 doc/Makefile doc/Doxyfile])

AC_OUTPUT

echo "
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix.........: $prefix
  Using OpenSSL..: $with_openssl
  Using JSON-C...: $with_json_c
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
