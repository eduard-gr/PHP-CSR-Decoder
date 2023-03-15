PHP_ARG_ENABLE(ggssl, whether to enable ggssl, [ --enable-ggssl   Enable ggssl])

PHP_ARG_WITH(openssl-legacy, openssl legacy path,
[  --with-openssl-legacy=DIR      example: Location of legacy openssl], no, no)


if test "$PHP_GGSSL" = "yes"; then
  
  if test "$PHP_OPENSSL_LEGACY" != "no"; then
    OPENSSL=$PHP_OPENSSL_LEGACY
    PHP_ADD_INCLUDE($OPENSSL/include)
    PHP_SUBST(OPENSSL_SHARED_LIBADD)
    LDFLAGS="$LDFLAGS -L$OPENSSL -lcrypto -ldl"
  fi

  AC_DEFINE(HAVE_GGSSL, 1, [Цhether to enable ggssl])
  PHP_NEW_EXTENSION(ggssl, ggssl.c, $ext_shared)
fi

