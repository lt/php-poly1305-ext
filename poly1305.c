#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "poly1305-donna.h"
#include "ext/spl/spl_exceptions.h"

#define POLY1305_NS "Poly1305"

zend_class_entry *poly1305_ce;
zend_class_entry *poly1305_context_ce;

#define IS_CONTEXT(zval) \
	(Z_TYPE_P(zval) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zval), poly1305_context_ce TSRMLS_CC))

#define GET_CONTEXT_FROM_ZVAL(zval) \
	(((poly1305_context *) zend_object_store_get_object((zval) TSRMLS_CC))->context)

#define FETCH_CONTEXT_ZVAL(context, zval)  \
if (IS_CONTEXT(zval)) {                    \
	context = GET_CONTEXT_FROM_ZVAL(zval); \
} else {                                   \
	context = NULL;                        \
}

static void context_free_object_storage(poly1305_context *ctx TSRMLS_DC)
{
	efree(ctx);
}

static zend_object_value context_create_object(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	poly1305_context *ctx = emalloc(sizeof(poly1305_context));

	retval.handle = zend_objects_store_put(
		ctx, (zend_objects_store_dtor_t) zend_objects_destroy_object,
		(zend_objects_free_object_storage_t) context_free_object_storage,
		NULL TSRMLS_CC
	);
	retval.handlers = zend_get_std_object_handlers();

	return retval;
}

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

ZEND_METHOD(Poly1305, init) {
	zval *ctx;
	unsigned char *key;
	long key_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx, &key, &key_len) == FAILURE) {
		return;
	}

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 byte string", 0 TSRMLS_CC);
	}
}

ZEND_METHOD(Poly1305, blocks) {
	zval *ctx;
	unsigned char *msg;
	long msg_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx, &msg, &msg_len) == FAILURE) {
		return;
	}
}

ZEND_METHOD(Poly1305, finish) {
	zval *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &ctx) == FAILURE) {
		return;
	}
}

ZEND_METHOD(Poly1305, authenticate) {

}

ZEND_METHOD(Poly1305, verify) {

}

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_authenticate, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_verify, 0, 0, 3)
	ZEND_ARG_INFO(0, authenticator)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_init, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_blocks, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_finish, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
ZEND_END_ARG_INFO()

const zend_function_entry poly1305_functions[] = {
	ZEND_NS_FE(POLY1305_NS, poly1305_authenticate, arginfo_poly1305_authenticate)
	ZEND_NS_FE(POLY1305_NS, poly1305_verify, arginfo_poly1305_verify)
	ZEND_FE_END
};

const zend_function_entry poly1305_methods[] = {
	ZEND_ME(Poly1305, init, arginfo_poly1305_init, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, blocks, arginfo_poly1305_blocks, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, finish, arginfo_poly1305_finish, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, authenticate, arginfo_poly1305_authenticate, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, verify, arginfo_poly1305_verify, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

PHP_MINFO_FUNCTION(poly1305)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "poly1305 support", "enabled");
	php_info_print_table_end();
}

ZEND_MINIT_FUNCTION(poly1305)
{
	zend_class_entry tmp_ce;

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Poly1305", poly1305_methods);
	poly1305_ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Context", NULL);
	poly1305_context_ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);
	poly1305_context_ce->create_object = context_create_object;

	return SUCCESS;
}

zend_module_entry poly1305_module_entry = {
	STANDARD_MODULE_HEADER,
	"poly1305",
	poly1305_functions,
	ZEND_MODULE_STARTUP_N(poly1305),
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
