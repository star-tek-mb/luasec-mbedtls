#include <lua.h>
#include <lauxlib.h>
#include <string.h>

#include "tls.h"

#ifndef MIN
    #define MIN(x, y) ((x) < (y) ? x : y)
#endif
#ifndef MAX
    #define MAX(x, y) ((x) > (y) ? x : y)
#endif

static inline const char* want_str(int ret) {
    if (ret > 0) {
        return "nothing";
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return "wantwrite";
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return "wantread";
    }
    return "error";
}

static int bufget(tls* conn, const char **data, size_t *count) {
    int err = 1;
    if (conn->first >= conn->last) {
        size_t got = 0;
        err = mbedtls_ssl_read(&conn->ctx->ssl, (unsigned char*) conn->buffer, sizeof(conn->buffer));
        if (err > 0) {
            got = err;
        }

        conn->first = 0;
        conn->last = got;
    }
    *count = conn->last - conn->first;
    *data = conn->buffer + conn->first;
    return err;
}

static void bufskip(tls* conn, size_t count) {
    conn->first += count;
    if (conn->first >= conn->last) 
        conn->first = conn->last = 0;
}

static size_t recvraw(tls* conn, size_t wanted, luaL_Buffer *b) {
    int err = 1;
    size_t total = 0;
    while (err > 0) {
        size_t count;
        const char *data;
        err = bufget(conn, &data, &count);
        count = MIN(count, wanted - total);
        luaL_addlstring(b, data, count);
        bufskip(conn, count);
        total += count;
        if (total >= wanted) break;
    }
    return err;
}

static size_t recvall(tls* conn, luaL_Buffer *b) {
    int err = 1;
    size_t total = 0;
    while (err > 0) {
        const char *data;
        size_t count;
        err = bufget(conn, &data, &count);
        total += count;
        luaL_addlstring(b, data, count);
        bufskip(conn, count);
    }
    if (err == 0) {
        if (total > 0) return total;
        else return 0;
    } else return err;
}

static size_t recvline(tls* conn, luaL_Buffer *b) {
    int err = 1;
    while (err > 0) {
        size_t count, pos;
        const char *data;

        err = bufget(conn, &data, &count);
        pos = 0;
        while (pos < count && data[pos] != '\n') {
            if (data[pos] != '\r') {
                luaL_addchar(b, data[pos]);
            }
            pos++;
        }
        if (pos < count) {
            bufskip(conn, pos + 1);
            break;
        } else {
            bufskip(conn, pos);
        }
    }
    return err;
}

static size_t sendraw(tls* conn, const char *data, size_t count, size_t *sent) {
    size_t total = 0;
    int err = 1;
    while (total < count && err > 0) {
        size_t done;
        size_t step = (count - total <= 8192) ? count - total : 8192;
        err = mbedtls_ssl_write(&conn->ctx->ssl, data + total, step);
        if (err > 0) {
            done = err;
        }
        total += done;
    }
    *sent = total;
    return err;
}

static int meth_create(lua_State* L) {
    tls* conn = lua_newuserdata(L, sizeof(tls));
    memset(conn, 0, sizeof(tls));
    conn->last_ret = 1;

    mbedtls_net_init(&conn->net);
    conn->ctx = luaL_testudata(L, 1, "TLS:Context");
    mbedtls_ssl_set_bio(&conn->ctx->ssl, &conn->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    luaL_getmetatable(L, "TLS:Connection");
    lua_setmetatable(L, -2);
    return 1;
}

static int meth_setfd(lua_State* L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    conn->net.MBEDTLS_PRIVATE(fd) = (int) lua_tointeger(L, 2);
    return 0;
}

static int meth_close(lua_State* L) {
    return meth_destroy(L);
}

static int meth_getfd(lua_State* L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    lua_pushinteger(L, conn->net.MBEDTLS_PRIVATE(fd));
    return 1;
}

static int meth_handshake(lua_State* L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    conn->last_ret = mbedtls_ssl_handshake(&conn->ctx->ssl);
    lua_pushstring(L, want_str(conn->last_ret));
    return 1;
}

static int meth_receive(lua_State* L) {
    size_t err = 1, top = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    if (!lua_isnumber(L, 2)) {
        const char* p = luaL_optstring(L, 2, "*l");
        if (p[0] == '*' && p[1] == 'l') err = recvline(conn, &b);
        else if (p[0] == '*' && p[1] == 'a') err = recvall(conn, &b); 
        else luaL_argcheck(L, 0, 2, "invalid receive pattern");
    } else {
        err = recvraw(conn, (size_t) lua_tonumber(L, 2), &b);
    }

    if (err < 0) {
        luaL_pushresult(&b);
        lua_pushstring(L, want_str(err));
        lua_pushvalue(L, -2); 
        lua_pushnil(L);
        lua_replace(L, -4);
    } else {
        luaL_pushresult(&b);
        lua_pushnil(L);
        lua_pushnil(L);
    }
    conn->last_ret = err;
    return lua_gettop(L) - top;
}

static int meth_send(lua_State* L) {
    size_t err = 1, top = lua_gettop(L);
    size_t size = 0, sent = 0;
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    const char *data = luaL_checklstring(L, 2, &size);
    long start = (long) luaL_optnumber(L, 3, 1);
    long end = (long) luaL_optnumber(L, 4, -1);

    if (start < 0) start = (long) (size+start+1);
    if (end < 0) end = (long) (size+end+1);
    if (start < 1) start = (long) 1;
    if (end > (long) size) end = (long) size;
    if (start <= end) err = sendraw(conn, data+start-1, end-start+1, &sent);

    if (err < 0) {
        lua_pushnil(L);
        lua_pushstring(L, want_str(err));
        lua_pushnumber(L, sent+start-1);
    } else {
        lua_pushnumber(L, sent+start-1);
        lua_pushnil(L);
        lua_pushnil(L);
    }
    conn->last_ret = err;
    return lua_gettop(L) - top;
}

static int meth_want(lua_State *L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    lua_pushstring(L, want_str(conn->last_ret));
    return 1;
}

static int meth_destroy(lua_State *L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    mbedtls_ssl_close_notify(&conn->ctx->ssl);
    mbedtls_net_free(&conn->net);
    return 0;
}

static int meth_tostring(lua_State *L) {
    tls* conn = luaL_checkudata(L, 1, "TLS:Connection");
    lua_pushfstring(L, "TLS connection: %p", conn);
    return 1;
}

static luaL_Reg methods[] = {
    { "close",       meth_close },
    { "getfd",       meth_getfd },
    { "dohandshake", meth_handshake },
    { "receive",     meth_receive },
    { "send",        meth_send },
    { "want",        meth_want },
    { NULL, NULL}
};

static luaL_Reg meta[] = {
    { "__close",    meth_destroy },
    { "__gc",       meth_destroy },
    { "__tostring", meth_tostring },
    { NULL, NULL }
};

static luaL_Reg funcs[] = {
    { "create", meth_create },
    { "setfd",  meth_setfd },
    { NULL, NULL }
};

API int luaopen_tls_core(lua_State *L)
{
    luaL_newmetatable(L, "TLS:Connection");
    setfuncs(L, meta);

    luaL_newlib(L, methods);
    lua_setfield(L, -2, "__index");

    luaL_newlib(L, funcs);
    return 1;
}
