#include <lua.h>
#include <lauxlib.h>
#include <string.h>

#include "context.h"

static void cleanup(context* ctx) {
    if (!ctx->inited == 0) {
        return;
    }

    if (ctx->inited > 0) {
        mbedtls_ssl_free(&ctx->ssl);
        mbedtls_ssl_config_free(&ctx->conf);
        mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
        mbedtls_entropy_free(&ctx->entropy);
    }
    if (ctx->inited == 2) {
        mbedtls_x509_crt_free(&ctx->cert);
        mbedtls_pk_free(&ctx->key);
    }
    if (ctx->inited == 3) {
        mbedtls_x509_crt_free(&ctx->cert);
    }

    ctx->inited = 0;
}

void* testudata(lua_State *L, int ud, const char *tname) {
    void *p = lua_touserdata(L, ud);
    if (p != NULL) {
        if (lua_getmetatable(L, ud)) {
            luaL_getmetatable(L, tname);
            if (!lua_rawequal(L, -1, -2)) {
                p = NULL;
            }
            lua_pop(L, 2);
            return p;
        }
    }
    return NULL;
}

// [endpoint, auth, ...]
// if endpoint is server ... - [key, cert, ca]
// if endpoint is client ... - [ca, hostname?]
static int create(lua_State *L) {
    #define FAIL_AND_CLEANUP(s) do { cleanup(ctx); lua_pop(L, -1); lua_pushstring(L, s); lua_error(L); return 1; } while (0)

    int n_args = lua_gettop(L);
    context* ctx = lua_newuserdata(L, sizeof(context));
    memset(ctx, 0, sizeof(ctx));

    mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);

    ctx->inited = 1;

    int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    if (ret != 0) {
		FAIL_AND_CLEANUP("Seed initialize failed");
	}

    int endpoint; // read from lua
    const char* endpoint_str = lua_tostring(L, 1);
    if (strcmp(endpoint_str, "client") == 0) {
        endpoint = MBEDTLS_SSL_IS_CLIENT;
    } else if (strcmp(endpoint_str, "server") == 0) {
        endpoint = MBEDTLS_SSL_IS_SERVER;
    } else {
        FAIL_AND_CLEANUP("wrong mode - should be client or server");
    }

    if (mbedtls_ssl_config_defaults(&ctx->conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        FAIL_AND_CLEANUP("Initialize failed with defaults");
    }

    int auth; // read from lua
    const char* auth_str = lua_tostring(L, 2);

    if (strcmp(auth_str, "none") == 0) {
        auth = MBEDTLS_SSL_VERIFY_NONE;
    } else if (strcmp(auth_str, "optional") == 0) {
        auth = MBEDTLS_SSL_VERIFY_OPTIONAL;
    } else if (strcmp(auth_str, "required") == 0) {
        auth = MBEDTLS_SSL_VERIFY_REQUIRED;
    } else {
        FAIL_AND_CLEANUP("Wrong auth mode - should be one of none, optional, required");
    }

    mbedtls_ssl_conf_authmode(&ctx->conf, auth);
	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        size_t key_len = 0;
        const char* key = lua_tolstring(L, 3, &key_len);

        size_t cert_len = 0;
        const char* cert = lua_tolstring(L, 4, &cert_len);

        size_t ca_len = 0;
        const char* ca = lua_tolstring(L, 5, &ca_len);

        mbedtls_x509_crt_init(&ctx->cert);
        mbedtls_pk_init(&ctx->key);
        ctx->inited = 2;

        if ((ret = mbedtls_x509_crt_parse(&ctx->cert, cert, cert_len+1)) != 0) {
            FAIL_AND_CLEANUP("Certificate parse error");
        }

        if ((ret = mbedtls_x509_crt_parse(&ctx->cert, ca, ca_len+1)) != 0) {
            FAIL_AND_CLEANUP("CA parse error");
        }

        // TODO: NULL, 0 - is a password, implement password
        if ((ret = mbedtls_pk_parse_key(&ctx->key, key, key_len+1, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) != 0) {
            FAIL_AND_CLEANUP("Key parse error");
        }

        mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->cert.MBEDTLS_PRIVATE(next), NULL);
        if ((ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->key)) != 0) {
            FAIL_AND_CLEANUP("Failed to set certificate");
        }
    } else {
        size_t ca_len = 0;
        const char* ca = lua_tolstring(L, 3, &ca_len);

        mbedtls_x509_crt_init(&ctx->cert);
        ctx->inited = 3;

        if ((ret = mbedtls_x509_crt_parse(&ctx->cert, ca, ca_len+1)) != 0) {
            FAIL_AND_CLEANUP("CA parse error");
        }
        mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cert, NULL);
    }

    if (mbedtls_ssl_setup(&ctx->ssl, &ctx->conf) != 0) {
        FAIL_AND_CLEANUP("Failed to setup context");
    }

    if (n_args == 4 && endpoint == MBEDTLS_SSL_IS_CLIENT) {
        const char* hostname = lua_tostring(L, 2);
        mbedtls_ssl_set_hostname(&ctx->ssl, hostname);
    }

    luaL_getmetatable(L, "TLS:Context");
    lua_setmetatable(L, -2);
    return 1;

    #undef FAIL_AND_CLEANUP
}

static luaL_Reg funcs[] = {
    { "create", create },
    { NULL, NULL }
};

static int meth_destroy(lua_State *L) {
    context* ctx = luaL_checkudata(L, 1, "TLS:Context");
    cleanup(ctx);
    return 0;
}

static int meth_tostring(lua_State *L) {
    context* ctx = luaL_checkudata(L, 1, "TLS:Context");
    lua_pushfstring(L, "TLS context: %p", ctx);
    return 1;
}

static luaL_Reg meta[] = {
    { "__close",    meth_destroy },
    { "__gc",       meth_destroy },
    { "__tostring", meth_tostring },
    { NULL, NULL }
};

API int luaopen_tls_context(lua_State *L) {
    luaL_newmetatable(L, "TLS:Context");
    setfuncs(L, meta);

    luaL_newlib(L, funcs);
    return 1;
}
