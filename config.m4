PHP_ARG_ENABLE(ggssl, whether to enable ggssl, [ --enable-ggssl   Enable ggssl])

if test "$PHP_GGSSL" = "yes"; then
  AC_DEFINE(HAVE_GGSSL, 1, [Цhether to enable ggssl])
  PHP_NEW_EXTENSION(ggssl, ggssl.c, $ext_shared)
fi
