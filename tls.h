#pragma once

#include <lua.h>
#include <mbedtls/net_sockets.h>

#include "compat.h"
#include "context.h"

typedef struct {
    mbedtls_net_context net;
    context* ctx;
    char buffer[8192];
    size_t first, last;
} tls;

API int luaopen_tls_core(lua_State *L);
