PHP_ARG_ENABLE(ggssl, whether to enable ggssl, [ --enable-ggssl   Enable ggssl])

PHP_ARG_WITH(openssl-legacy, openssl legacy path,
[  --with-openssl-legacy=PATH     Legacy openssl: full path to libcrypto.a, or its build tree / install prefix], no, no)


if test "$PHP_GGSSL" = "yes"; then

  if test "$PHP_OPENSSL_LEGACY" != "no"; then
    OPENSSL=$PHP_OPENSSL_LEGACY

    dnl The shell does not expand ~ inside --opt=~/..., so do it here
    case "$OPENSSL" in
      "~") OPENSSL="$HOME" ;;
      "~/"*) OPENSSL="$HOME/${OPENSSL#\~/}" ;;
    esac

    dnl Prefer static libcrypto.a so the legacy OpenSSL is embedded into ggssl.so
    dnl and never resolved against the system OpenSSL already loaded by PHP.
    if test -f "$OPENSSL"; then
      OPENSSL_LIBCRYPTO="$OPENSSL"
      OPENSSL=`dirname "$OPENSSL"`
    elif test -f "$OPENSSL/libcrypto.a"; then
      OPENSSL_LIBCRYPTO="$OPENSSL/libcrypto.a"
    elif test -f "$OPENSSL/lib/libcrypto.a"; then
      OPENSSL_LIBCRYPTO="$OPENSSL/lib/libcrypto.a"
    else
      AC_MSG_ERROR([libcrypto.a not found at $OPENSSL, $OPENSSL/libcrypto.a or $OPENSSL/lib/libcrypto.a; build OpenSSL with no-shared -fPIC])
    fi

    dnl Headers sit next to the library (build tree) or one level up (prefix/lib)
    if test -f "$OPENSSL/include/openssl/opensslv.h"; then
      OPENSSL_INCDIR="$OPENSSL/include"
    elif test -f "$OPENSSL/../include/openssl/opensslv.h"; then
      OPENSSL_INCDIR="$OPENSSL/../include"
    else
      AC_MSG_ERROR([openssl/opensslv.h not found in $OPENSSL/include or $OPENSSL/../include])
    fi

    AC_MSG_NOTICE([legacy openssl library: $OPENSSL_LIBCRYPTO])
    AC_MSG_NOTICE([legacy openssl headers: $OPENSSL_INCDIR])

    PHP_ADD_INCLUDE($OPENSSL_INCDIR)
    GGSSL_SHARED_LIBADD="$GGSSL_SHARED_LIBADD $OPENSSL_LIBCRYPTO -ldl -Wl,--exclude-libs,ALL"
  else
    PHP_ADD_LIBRARY(crypto, 1, GGSSL_SHARED_LIBADD)
  fi

  PHP_SUBST(GGSSL_SHARED_LIBADD)
  AC_DEFINE(HAVE_GGSSL, 1, [Whether to enable ggssl])
  PHP_NEW_EXTENSION(ggssl, ggssl.c, $ext_shared)
fi
