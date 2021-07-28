#pragma once

#include <lua.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include "compat.h"

typedef struct {
    mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;

    int inited;
} context;

API int luaopen_tls_context(lua_State *L);
