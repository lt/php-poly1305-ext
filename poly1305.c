#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "poly1305-donna.h"
#include "ext/spl/spl_exceptions.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"

#define POLY1305_NS "Poly1305"

zend_class_entry *poly1305_ce;
zend_class_entry *poly1305_context_ce;
zend_class_entry *poly1305_base_ce;

typedef struct _context_object {
	zend_object std;
	poly1305_context ctx;
	zend_bool initialised;
} context_object;

#define IS_CONTEXT(zval) \
	(Z_TYPE_P(zval) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zval), poly1305_context_ce TSRMLS_CC))

#define FETCH_CONTEXT_ZVAL(ctx, zval)                     \
if (IS_CONTEXT(zval)) {                                   \
	ctx = zend_object_store_get_object((zval) TSRMLS_CC); \
} else {                                                  \
	ctx = NULL;                                           \
}

static void context_free_object_storage(context_object *ctx TSRMLS_DC)
{
	zend_object_std_dtor(&ctx->std TSRMLS_CC);
	efree(ctx);
}

static zend_object_value context_create_object(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	context_object *ctx = emalloc(sizeof(context_object));
	ctx->initialised = 0;

	zend_object_std_init(&ctx->std, ce TSRMLS_CC);
	object_properties_init(&ctx->std, ce);

	retval.handle = zend_objects_store_put(
		ctx, (zend_objects_store_dtor_t) zend_objects_destroy_object,
		(zend_objects_free_object_storage_t) context_free_object_storage,
		NULL TSRMLS_CC
	);
	retval.handlers = zend_get_std_object_handlers();

	return retval;
}

ZEND_METHOD(Poly1305, init) {
	zval *ctx_arg;
	unsigned char *key;
	int key_len;
	context_object *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx_arg, &key, &key_len) == FAILURE) {
		return;
	}

	FETCH_CONTEXT_ZVAL(ctx, ctx_arg);

	if (!ctx) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid Context", 0 TSRMLS_CC);
	}

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 bytes", 0 TSRMLS_CC);
	}

	poly1305_init(&ctx->ctx, key);

	ctx->initialised = 1;
}

ZEND_METHOD(Poly1305, update) {
	zval *ctx_arg;
	unsigned char *msg;
	int msg_len;
	context_object *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx_arg, &msg, &msg_len) == FAILURE) {
		return;
	}

	FETCH_CONTEXT_ZVAL(ctx, ctx_arg);

	if (!ctx || !ctx->initialised) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid Context", 0 TSRMLS_CC);
	}

	poly1305_update(&ctx->ctx, msg, msg_len);
}

ZEND_METHOD(Poly1305, finish) {
	zval *ctx_arg;
	context_object *ctx;
	unsigned char *mac;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &ctx_arg) == FAILURE) {
		return;
	}

	FETCH_CONTEXT_ZVAL(ctx, ctx_arg);

	if (!ctx || !ctx->initialised) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid Context", 0 TSRMLS_CC);
	}

	mac = emalloc(17);
	poly1305_finish(&ctx->ctx, mac);
	mac[16] = '\0';

	ctx->initialised = 0;

	RETURN_STRINGL((char *)mac, 16, 0);
}

PHP_FUNCTION(auth)
{
	unsigned char *key;
	int key_len;

	unsigned char *message;
	int message_len;

	unsigned char *mac;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &message, &message_len) == FAILURE) {
		return;
	}

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 bytes", 0 TSRMLS_CC);
	}

	mac = emalloc(17);
	poly1305_auth(mac, message, message_len, key);
	mac[16] = '\0';

	RETURN_STRINGL((char *)mac, 16, 0);
}

PHP_FUNCTION(verify)
{
	unsigned char *mac;
	int mac_len;

	unsigned char *key;
	int key_len;

	unsigned char *message;
	int message_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &mac, &mac_len, &key, &key_len, &message, &message_len) == FAILURE) {
		return;
	}

	if (mac_len != 16) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "MAC must be a 16 bytes", 0 TSRMLS_CC);
	}

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 bytes", 0 TSRMLS_CC);
	}

	unsigned char mac2[17];
	poly1305_auth(mac2, message, message_len, key);

	if (poly1305_verify(mac, mac2)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_init, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_update, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_finish, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, ctx, Poly1305\\Context, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_auth, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_poly1305_verify, 0, 0, 3)
	ZEND_ARG_INFO(0, mac)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

const zend_function_entry poly1305_methods[] = {
	ZEND_ME(Poly1305, init, arginfo_poly1305_init, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, update, arginfo_poly1305_update, ZEND_ACC_PUBLIC)
	ZEND_ME(Poly1305, finish, arginfo_poly1305_finish, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

const zend_function_entry poly1305_base_methods[] = {
	ZEND_ABSTRACT_ME(Base, init, arginfo_poly1305_init)
	ZEND_ABSTRACT_ME(Base, update, arginfo_poly1305_update)
	ZEND_ABSTRACT_ME(Base, finish, arginfo_poly1305_finish)
	ZEND_FE_END
};

const zend_function_entry poly1305_functions[] = {
	ZEND_NS_FE(POLY1305_NS, auth, arginfo_poly1305_auth)
	ZEND_NS_FE(POLY1305_NS, verify, arginfo_poly1305_verify)
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

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Base", poly1305_base_methods);
	poly1305_base_ce = zend_register_internal_interface(&tmp_ce TSRMLS_CC);

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Poly1305", poly1305_methods);
	poly1305_ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);
	zend_class_implements(poly1305_ce TSRMLS_CC, 1, poly1305_base_ce);

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
