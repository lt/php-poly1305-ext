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

static zend_object_handlers context_object_handlers;

typedef struct _context_object {
#if PHP_VERSION_ID >= 70000
	poly1305_context ctx;
	zend_bool initialised;
	zend_object std;
#else
	zend_object std;
	poly1305_context ctx;
	zend_bool initialised;
#endif
} context_object;

#define IS_CONTEXT(zval) \
	(Z_TYPE_P(zval) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zval), poly1305_context_ce TSRMLS_CC))

#if PHP_VERSION_ID >= 70000
#define FETCH_CONTEXT_ZVAL(ctx, zval) \
if (IS_CONTEXT(zval)) { \
	ctx = ((context_object *) ((char *) (Z_OBJ_P(zval)) - XtOffsetOf(context_object, std))); \
} else {                                                  \
	ctx = NULL;                                           \
}
#else
#define FETCH_CONTEXT_ZVAL(ctx, zval) \
if (IS_CONTEXT(zval)) {           \
	ctx = zend_object_store_get_object((zval) TSRMLS_CC); \
} else {                                                  \
	ctx = NULL;                                           \
}
#endif


#if PHP_VERSION_ID >= 70000
static void context_free_object_storage(zend_object *std)
{
	zend_object_std_dtor(std);
}
#else
static void context_free_object_storage(context_object *ctx TSRMLS_DC)
{
	zend_object_std_dtor(&ctx->std TSRMLS_CC);
	efree(ctx);
}
#endif

#if PHP_VERSION_ID >= 70000
static zend_object *context_create_object(zend_class_entry *ce)
{
	context_object *ctx = ecalloc(1, sizeof(context_object) + zend_object_properties_size(ce));

	zend_object_std_init(&ctx->std, ce);
	object_properties_init(&ctx->std, ce);

	ctx->initialised = 0;
	ctx->std.handlers = &context_object_handlers;
	return &ctx->std;
}
#else
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
#endif

ZEND_METHOD(Poly1305, init) {
	zval *ctx_arg;
	char *key;
#if PHP_VERSION_ID >= 70000
	size_t key_len;
#else
	int key_len;
#endif
	context_object *ctx;

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx_arg, &key, &key_len) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_ZVAL(ctx_arg)
		Z_PARAM_STRING(key, key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

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
	char *msg;
#if PHP_VERSION_ID >= 70000
	size_t msg_len;
#else
	int msg_len;
#endif
	context_object *ctx;

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &ctx_arg, &msg, &msg_len) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_ZVAL(ctx_arg)
		Z_PARAM_STRING(msg, msg_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	FETCH_CONTEXT_ZVAL(ctx, ctx_arg);

	if (!ctx || !ctx->initialised) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid Context", 0 TSRMLS_CC);
	}

	poly1305_update(&ctx->ctx, msg, msg_len);
}

ZEND_METHOD(Poly1305, finish) {
	zval *ctx_arg;
	context_object *ctx;
	char mac[16];

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &ctx_arg) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_ZVAL(ctx_arg)
	ZEND_PARSE_PARAMETERS_END();
#endif

	FETCH_CONTEXT_ZVAL(ctx, ctx_arg);

	if (!ctx || !ctx->initialised) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid Context", 0 TSRMLS_CC);
	}

	poly1305_finish(&ctx->ctx, mac);
	ctx->initialised = 0;

#if PHP_VERSION_ID >= 70000
	RETURN_STRINGL(mac, 16);
#else
	RETURN_STRINGL(mac, 16, 1);
#endif
}

PHP_FUNCTION(auth)
{
	char *key;
	char *message;
#if PHP_VERSION_ID >= 70000
	size_t key_len;
	size_t message_len;
#else
	int key_len;
	int message_len;
#endif
	char mac[16];

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &message, &message_len) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(key, key_len)
		Z_PARAM_STRING(message, message_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 bytes", 0 TSRMLS_CC);
	}

	poly1305_auth(mac, message, message_len, key);
 
#if PHP_VERSION_ID >= 70000
	RETURN_STRINGL(mac, 16);
#else
	RETURN_STRINGL(mac, 16, 1);
#endif
}

PHP_FUNCTION(verify)
{
	char *mac;
	char *key;
	char *message;
#if PHP_VERSION_ID >= 70000
	size_t mac_len;
	size_t key_len;
	size_t message_len;
#else
	int mac_len;
	int key_len;
	int message_len;
#endif
	char mac2[16];

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &mac, &mac_len, &key, &key_len, &message, &message_len) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(mac, mac_len)
		Z_PARAM_STRING(key, key_len)
		Z_PARAM_STRING(message, message_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	if (mac_len != 16) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "MAC must be a 16 bytes", 0 TSRMLS_CC);
	}

	if (key_len != 32) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Key must be a 32 bytes", 0 TSRMLS_CC);
	}

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

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Poly1305", poly1305_methods);
	poly1305_ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);

	INIT_NS_CLASS_ENTRY(tmp_ce, POLY1305_NS, "Context", NULL);
	poly1305_context_ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);
	poly1305_context_ce->create_object = context_create_object;

#if PHP_VERSION_ID >= 70000
	memcpy(&context_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	context_object_handlers.offset = XtOffsetOf(context_object, std);
	context_object_handlers.free_obj = context_free_object_storage;
#endif

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
