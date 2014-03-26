#include "gjoll.h"

#include "lauxlib.h"
#include "lualib.h"

static int gjoll__lua_add_friend(lua_State *L) {
    int len;
    gjoll_daemon_t *d;
    gjoll_node_t id;
    const char *secret;

    lua_getfield(L, 1, "__daemon");
    d = lua_touserdata(L, -1);
    lua_pop(L, 1);

    id = luaL_checkint(L, 2);
    secret = luaL_checkstring(L, 3);
    len = lua_rawlen(L, 3);

    if(gjoll_daemon_add_friend(d, id, secret, len) == NULL) {
        luaL_error(L, "gjoll_daemon_add_friend failed");
    }

    return 0;
}

static int gjoll__lua_add_rule(lua_State *L) {
    gjoll_service_t service;
    int port;
    const char *addr;
    struct sockaddr_in laddr;
    gjoll_daemon_t *d;

    lua_getfield(L, 1, "__daemon");
    d = lua_touserdata(L, -1);
    lua_pop(L, 1);

    service = luaL_checkint(L, 2);
    addr = luaL_checkstring(L, 3);
    port = luaL_checkint(L, 4);

    if(uv_ip4_addr(addr, port, &laddr)) {
        luaL_error(L, "bad addr %s:%d", addr, port);
    }

    if(gjoll_daemon_add_rule(d, service, laddr) == NULL) {
        luaL_error(L, "gjoll_daemon_add_rule failed");
    }

    return 0;
}

static int gjoll__lua_add_route(lua_State *L) {
    gjoll_node_t id;
    gjoll_service_t service;
    int port;
    const char *addr;
    struct sockaddr_in gaddr;
    struct sockaddr_in laddr;
    gjoll_daemon_t *d;

    lua_getfield(L, 1, "__daemon");
    d = lua_touserdata(L, -1);
    lua_pop(L, 1);

    id = luaL_checkint(L, 2);
    service = luaL_checkint(L, 3);
    addr = luaL_checkstring(L, 4);
    port = luaL_checkint(L, 5);

    if(uv_ip4_addr(addr, port, &gaddr)) {
        luaL_error(L, "bad addr %s:%d", addr, port);
    }

    addr = luaL_checkstring(L, 6);
    port = luaL_checkint(L, 7);

    if(uv_ip4_addr(addr, port, &laddr)) {
        luaL_error(L, "bad addr %s:%d", addr, port);
    }

    if(gjoll_daemon_add_route(d, id, service, gaddr, laddr)) {
        luaL_error(L, "gjoll_daemon_add_route failed");
    }

    return 0;
}

static int gjoll__lua_new_daemon(lua_State *L) {
    gjoll_node_t id;
    const char *addr;
    int port;
    size_t i;
    struct sockaddr_in saddr;
    gjoll_daemon_t *d = malloc(sizeof(gjoll_daemon_t));
    gjoll_loop_t *loop;
    static const struct luaL_Reg methods [] = {
        {"add_friend", gjoll__lua_add_friend},
        {"add_rule", gjoll__lua_add_rule},
        {"add_route", gjoll__lua_add_route},
        {NULL, NULL}
    };

    id = luaL_checkint(L, 1);
    addr = luaL_checkstring(L, 2);
    port = luaL_checkint(L, 3);

    luaL_argcheck(L, port > 0 && port < 65535, 3, "bad port");

    lua_getfield(L, LUA_REGISTRYINDEX, "gjoll_loop");
    loop = lua_touserdata(L, -1);

    lua_getfield(L, LUA_REGISTRYINDEX, "gjoll_daemons");
    i = lua_rawlen(L, -1);

    lua_pushlightuserdata(L, d);
    lua_rawseti(L, -2, i+1);

    if(uv_ip4_addr(addr, port, &saddr)) {
        luaL_error(L, "bad addr: %s:%d", addr, port);
    }

    if(gjoll_daemon_init(*loop, d, id, saddr)) {
        luaL_error(L, "gjoll_daemon_init failed");
    }

    lua_newtable(L);
    lua_rawgeti(L, -2, i+1);
    lua_setfield(L, -2, "__daemon");
    luaL_setfuncs(L, methods, 0);

    lua_remove(L, -2);
    lua_remove(L, -2);
    return 1;
}

static void gjoll__lua_clean_daemons(lua_State *L) {
    int i;
    size_t len;
    gjoll_daemon_t *d;

    lua_getfield(L, LUA_REGISTRYINDEX, "gjoll_daemons");
    len = lua_rawlen(L, -1);
    for(i=0; i < (int) len; i++) {
        lua_rawgeti(L, -1, i+1);
        d = lua_touserdata(L, -1);
        gjoll_daemon_clean(d);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

static void gjoll__lua_delete_daemons(lua_State *L) {
    int i;
    size_t len;
    gjoll_daemon_t *d;

    lua_getfield(L, LUA_REGISTRYINDEX, "gjoll_daemons");
    len = lua_rawlen(L, -1);
    for(i=0; i < (int) len; i++) {
        lua_rawgeti(L, -1, i+1);
        d = lua_touserdata(L, -1);
        free(d);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

static void gjoll__lua_init(lua_State *l, gjoll_loop_t *loop) {
    static const struct luaL_Reg gjolllib_f [] = {
        {"new", gjoll__lua_new_daemon},
        {NULL, NULL}
    };

    lua_pushlightuserdata(l, loop);
    lua_setfield(l, LUA_REGISTRYINDEX, "gjoll_loop");

    lua_newtable(l);
    luaL_setfuncs(l, gjolllib_f, 0);
    lua_pushvalue(l, -1);
    lua_setglobal(l, "gjoll");
    lua_pop(l, 2);

    lua_newtable(l);
    lua_setfield(l, LUA_REGISTRYINDEX, "gjoll_daemons");

    luaopen_base(l);
}

lua_State *gjoll_lua_new(gjoll_loop_t *loop) {
    lua_State *res = luaL_newstate();
    gjoll__lua_init(res, loop);
    return res;
}

void gjoll_lua_clean(lua_State *l) {
    gjoll__lua_clean_daemons(l);
}

void gjoll_lua_delete(lua_State *l) {
    gjoll__lua_delete_daemons(l);
    lua_close(l);
}

int gjoll_lua_load(lua_State *l, const char *filename) {
    return luaL_dofile(l, filename);
}

const char *gjoll_lua_geterror(lua_State *l) {
    return lua_tostring(l, -1);
}
