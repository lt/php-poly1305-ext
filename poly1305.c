#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

PHP_MINFO_FUNCTION(poly1305)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "poly1305 support", "enabled");
	php_info_print_table_end();
}

zend_module_entry poly1305_module_entry = {
	STANDARD_MODULE_HEADER,
	"poly1305",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	PHP_MINFO(poly1305),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_POLY1305
ZEND_GET_MODULE(poly1305)
#endif
