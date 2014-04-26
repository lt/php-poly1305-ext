PHP_ARG_ENABLE(poly1305, Whether to enable the "poly1305" extension,
	[  --enable-poly1305         Enable "php-poly1305" extension support])

if test $PHP_POLY1305 != "no"; then
	PHP_NEW_EXTENSION(poly1305, poly1305.c, $ext_shared)
fi
