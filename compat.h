#pragma once

#if defined(_WIN32)
    #define API __declspec(dllexport) 
#else
    #define API extern
#endif

#if (LUA_VERSION_NUM == 501)

    void* testudata(lua_State *L, int ud, const char *tname);
    #define luaL_testudata(L, ud, tname) testudata(L, ud, tname)
    #define setfuncs(L, R)    luaL_register(L, NULL, R)
    #define lua_rawlen(L, i)  lua_objlen(L, i)

    #ifndef luaL_newlib
    #define luaL_newlib(L, R) do { lua_newtable(L); luaL_register(L, NULL, R); } while(0)
    #endif

#else

    #define setfuncs(L, R) luaL_setfuncs(L, R, 0)

#endif
