#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "poly1305-donna.h"

PHP_FUNCTION(poly1305_authenticate)
{
	unsigned char *key;
	int key_len;

	unsigned char *message;
	int message_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &message, &message_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (key_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Key must be 32 bytes");
		RETURN_FALSE;
	}

	unsigned char authenticator[17];
	poly1305_auth(authenticator, message, message_len, key);

	RETURN_STRINGL(authenticator, 16, 1);
}

PHP_FUNCTION(poly1305_verify)
{
	unsigned char *authenticator;
	int authenticator_len;

	unsigned char *key;
	int key_len;

	unsigned char *message;
	int message_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &authenticator, &authenticator_len, &key, &key_len, &message, &message_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (authenticator_len != 16) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Authenticator must be 16 bytes");
		RETURN_FALSE;
	}

	if (key_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Key must be 32 bytes");
		RETURN_FALSE;
	}

	unsigned char authenticator2[17];
	poly1305_auth(authenticator2, message, message_len, key);

	if (poly1305_verify(authenticator, authenticator2)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_authenticate, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_verify, 0, 0, 1)
	ZEND_ARG_INFO(0, authenticator)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

const zend_function_entry poly1305_functions[] = {
	PHP_FE(poly1305_authenticate, arginfo_poly1305_authenticate)
	PHP_FE(poly1305_verify, arginfo_poly1305_verify)
	PHP_FE_END
};

PHP_MINFO_FUNCTION(poly1305)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "poly1305 support", "enabled");
	php_info_print_table_end();
}

zend_module_entry poly1305_module_entry = {
	STANDARD_MODULE_HEADER,
	"poly1305",
	poly1305_functions,
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
