PHP_ARG_ENABLE(ggssl, whether to enable ggssl, [ --enable-ggssl   Enable ggssl])

PHP_ARG_WITH(openssl-legacy, openssl legacy path,
[  --with-openssl-legacy=DIR      Location of legacy openssl (build tree or install prefix)], no, no)


if test "$PHP_GGSSL" = "yes"; then

  if test "$PHP_OPENSSL_LEGACY" != "no"; then
    OPENSSL=$PHP_OPENSSL_LEGACY

    dnl Prefer static libcrypto.a so the legacy OpenSSL is embedded into ggssl.so
    dnl and never resolved against the system OpenSSL already loaded by PHP.
    if test -f "$OPENSSL/libcrypto.a"; then
      OPENSSL_LIBCRYPTO="$OPENSSL/libcrypto.a"
    elif test -f "$OPENSSL/lib/libcrypto.a"; then
      OPENSSL_LIBCRYPTO="$OPENSSL/lib/libcrypto.a"
    else
      AC_MSG_ERROR([libcrypto.a not found in $OPENSSL or $OPENSSL/lib; build OpenSSL with no-shared -fPIC])
    fi

    PHP_ADD_INCLUDE($OPENSSL/include)
    GGSSL_SHARED_LIBADD="$GGSSL_SHARED_LIBADD $OPENSSL_LIBCRYPTO -ldl -Wl,--exclude-libs,ALL"
  else
    PHP_ADD_LIBRARY(crypto, 1, GGSSL_SHARED_LIBADD)
  fi

  PHP_SUBST(GGSSL_SHARED_LIBADD)
  AC_DEFINE(HAVE_GGSSL, 1, [Whether to enable ggssl])
  PHP_NEW_EXTENSION(ggssl, ggssl.c, $ext_shared)
fi
