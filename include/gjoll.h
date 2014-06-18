/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#ifndef GJOLL_H
#define GJOLL_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(BUILDING_GJOLL)
    #if defined(GJOLL_EXPORTS)
        #define BUILD_SHARED
    #endif
#else
    #if !defined(GJOLL_STATIC_LIB)
        #define USING_SHARED
    #endif
#endif

#if defined(__MINGW32__) || defined(_MSC_VER)
    #if defined(BUILD_SHARED)
        #define GJOLL_EXTERN __declspec(dllexport)
    #elif defined(USING_SHARED)
        #define GJOLL_EXTERN __declspec(dllimport)
    #else
        #define GJOLL_EXTERN
    #endif
#elif defined(__clang__) || defined(__GNUC__)
    #if defined(BUILD_SHARED)
        #define GJOLL_EXTERN __attribute__((visibility("default")))
    #elif defined(USING_SHARED)
        #define GJOLL_EXTERN __attribute__((visibility("default")))
    #else
        #define GJOLL_EXTERN
    #endif
#else
    #error "Unsupported compiler!"
#endif

#undef BUILD_SHARED
#undef USING_SHARED

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "uv.h"
#include "ordo.h"
#include "uthash.h"
#include "lua.h"

#define GJOLL_NONCE_SIZE 8
#define GJOLL_IDENTIFIER_SIZE 8
#define GJOLL_FINGERPRINT_SIZE 16
#define GJOLL_SERVICE_SIZE 2
#define GJOLL_LEN_SIZE 2

#define GJOLL_HEADER_LENGTH 42
#define GJOLL_DATA_MIN_LENGTH 18

#define GJOLL_ALLOC_MAX 65536

/*
 * Length of a gjoll shared secret, in bytes.
 */
#define GJOLL_SECRET_LEN 32

#define OFFSET(p, i) ((unsigned char *)p + i)
#define OFFSET_INC(p, i) (p = (unsigned char *)p + i)

enum gjoll__conn_type_s {
    GJOLL_CLIENT,
    GJOLL_SERVER
};

/* types */
typedef uint64_t gjoll_node_t;
typedef uint16_t gjoll_service_t;
typedef uint16_t gjoll_len_t;

typedef struct gjoll_buf_s gjoll_buf_t;
typedef struct gjoll_secret_s gjoll_secret_t;
typedef struct gjoll_header_s gjoll_header_t;
typedef struct gjoll_loop_s gjoll_loop_t;
typedef struct gjoll__context_s gjoll__context_t;
typedef struct gjoll__parser_s gjoll__parser_t;

typedef enum gjoll__conn_type_s gjoll__conn_type_t;

typedef struct gjoll_listener_s gjoll_listener_t;
typedef struct gjoll_connection_s gjoll_connection_t;
typedef struct gjoll_send_s gjoll_send_t;

typedef struct gjoll_slistener_s gjoll_slistener_t;
typedef struct gjoll_sconnection_s gjoll_sconnection_t;
typedef struct gjoll_ssend_s gjoll_ssend_t;

typedef struct gjoll_rule_s gjoll_rule_t;
typedef struct gjoll_friend_s gjoll_friend_t;
typedef struct gjoll__conn_context_s gjoll__conn_context_t;
typedef struct gjoll__listener_context_s gjoll__listener_context_t;
typedef struct gjoll_daemon_s gjoll_daemon_t;

/* gjoll_listener_t callback */
typedef int (*gjoll_accept_cb) (gjoll_listener_t *);
typedef void (*gjoll_l_close_cb) (gjoll_listener_t *);

/* gjoll_slistener_t callback */
typedef int (*gjoll_saccept_cb) (gjoll_slistener_t *);
typedef void (*gjoll_sl_close_cb) (gjoll_slistener_t *);

/* gjoll_connection_t callback */
typedef void (*gjoll_connect_cb) (gjoll_connection_t *, int);
typedef void (*gjoll_recv_cb) (gjoll_connection_t *,
                               gjoll_buf_t);
typedef void (*gjoll_close_cb) (gjoll_connection_t *);

/* gjoll_sconnection_t callback */
typedef void (*gjoll_sconnect_cb) (gjoll_sconnection_t *, int);
typedef void (*gjoll_srecv_cb) (gjoll_sconnection_t *,
                                      gjoll_buf_t);
typedef int (*gjoll_session_cb) (gjoll_sconnection_t *,
                                 gjoll_node_t);
typedef int (*gjoll_header_cb) (gjoll_sconnection_t *,
                                gjoll_header_t);
typedef void (*gjoll_sclose_cb) (gjoll_sconnection_t *);

/* if status != 0, error */
typedef void (*gjoll_send_cb) (gjoll_send_t *req, int status);
typedef void (*gjoll_ssend_cb) (gjoll_ssend_t *req, int status);

/*
 * Contains a shared secret of fixed length - it is preferred to use this to
 * store shared secrets as it's more efficient than a general purpose buffer
 * such as gjoll_buf_t (as the shared secret is accessed for every packet).
 */
struct gjoll_secret_s {
    unsigned char secret[GJOLL_SECRET_LEN];
};

struct gjoll_buf_s {
    void *base;
    size_t len;
};

struct gjoll_header_s {
    gjoll_node_t src, dst;
    gjoll_service_t id;
};

struct gjoll_loop_s {
    uv_loop_t* loop;
};

struct gjoll__context_s {
    struct ENC_BLOCK_CTX ctx;
    unsigned char key[32];
};

struct gjoll__parser_s {
    int state;
    size_t i;
    char hbuf[GJOLL_HEADER_LENGTH];
    gjoll_len_t lenbuff;
    char data[GJOLL_ALLOC_MAX+GJOLL_LEN_SIZE+GJOLL_FINGERPRINT_SIZE];
    size_t datalen;
};

/* allocates a gjoll_buf_t */
GJOLL_EXTERN gjoll_buf_t gjoll_buf_init(void *, size_t);

/* frees a gjoll_buf_t */
GJOLL_EXTERN void gjoll_buf_free(gjoll_buf_t *buf);

GJOLL_EXTERN int gjoll_init(gjoll_loop_t *);

GJOLL_EXTERN void gjoll_delete(gjoll_loop_t *);

GJOLL_EXTERN int gjoll_run_once(gjoll_loop_t);

GJOLL_EXTERN int gjoll_run(gjoll_loop_t);


/* NETWORK */

struct gjoll_listener_s {
    void *data;
    gjoll_loop_t gloop;
    uv_tcp_t server;
    gjoll_accept_cb accept_cb;
    gjoll_l_close_cb close_cb;
};

GJOLL_EXTERN int gjoll_listener_init(gjoll_loop_t,
                                     gjoll_listener_t *);

GJOLL_EXTERN void gjoll_listener_close(gjoll_listener_t *,
                                       gjoll_l_close_cb);

GJOLL_EXTERN int gjoll_listener_bind(gjoll_listener_t *,
                                     const struct sockaddr *);

GJOLL_EXTERN int gjoll_listener_listen(gjoll_listener_t *,
                                       gjoll_accept_cb);

struct gjoll_connection_s {
    void *data;
    gjoll_loop_t gloop;
    uv_tcp_t client;
    int readlen;
    char buffer[GJOLL_ALLOC_MAX];
    gjoll__conn_type_t type;
    gjoll_recv_cb recv_cb;
    gjoll_close_cb close_cb;
};

GJOLL_EXTERN int gjoll_accept(gjoll_listener_t *,
                              gjoll_connection_t *,
                              gjoll_close_cb);

GJOLL_EXTERN int gjoll_connect(gjoll_loop_t,
                               gjoll_connection_t *,
                               const struct sockaddr *,
                               gjoll_connect_cb,
                               gjoll_close_cb);

GJOLL_EXTERN int gjoll_connection_init(gjoll_connection_t *,
                                       gjoll_recv_cb);

GJOLL_EXTERN int gjoll_connection_getpeername(gjoll_connection_t *,
                                              struct sockaddr *,
                                              int *);

GJOLL_EXTERN void gjoll_connection_readlen(gjoll_connection_t *conn,
                                           int readlen);

GJOLL_EXTERN void gjoll_connection_close(gjoll_connection_t *);

GJOLL_EXTERN void gjoll_connection_clean(gjoll_connection_t *);

GJOLL_EXTERN int gjoll_connection_closed(gjoll_connection_t *);

struct gjoll_send_s {
    void *data;
    uv_write_t req;
    uv_buf_t buffer;
    gjoll_send_cb cb;
};

GJOLL_EXTERN int gjoll_send(gjoll_send_t *,
                            gjoll_connection_t *,
                            void *data,
                            size_t len,
                            gjoll_send_cb cb);

/* SECURE CONNECTION */

struct gjoll_slistener_s {
    void *data;
    gjoll_listener_t listener;
    gjoll_node_t identifier;
    gjoll_saccept_cb accept_cb;
    gjoll_sl_close_cb close_cb;
};

GJOLL_EXTERN int gjoll_slistener_init(gjoll_loop_t,
                                      gjoll_slistener_t *,
                                      gjoll_node_t);

GJOLL_EXTERN void gjoll_slistener_close(gjoll_slistener_t *,
                                        gjoll_sl_close_cb);

GJOLL_EXTERN int gjoll_slistener_bind(gjoll_slistener_t *,
                                      const struct sockaddr *);

GJOLL_EXTERN int gjoll_slistener_listen(gjoll_slistener_t *,
                                        gjoll_saccept_cb);

struct gjoll_sconnection_s {
    void *data;
    gjoll_connection_t conn;
    gjoll_header_t header;
    gjoll_secret_t secret;
    gjoll__parser_t parser;
    gjoll__context_t cin;
    gjoll__context_t cout;
    gjoll_sconnect_cb connect_cb;
    gjoll_session_cb session_cb;
    gjoll_header_cb header_cb;
    gjoll_srecv_cb recv_cb;
    gjoll_sclose_cb close_cb;
};

GJOLL_EXTERN int gjoll_saccept(gjoll_slistener_t *,
                               gjoll_sconnection_t *,
                               gjoll_session_cb,
                               gjoll_header_cb,
                               gjoll_sclose_cb);

GJOLL_EXTERN int gjoll_sconnect(gjoll_loop_t,
                                gjoll_sconnection_t *,
                                const struct sockaddr *,
                                gjoll_header_t,
                                gjoll_sconnect_cb,
                                gjoll_header_cb,
                                gjoll_sclose_cb);

GJOLL_EXTERN int gjoll_sconnection_init(gjoll_sconnection_t *,
                                        const void *shared,
                                        const size_t shared_len,
                                        gjoll_srecv_cb);

GJOLL_EXTERN int gjoll_sconnection_getpeername(gjoll_sconnection_t *,
                                               struct sockaddr *,
                                               int *);

GJOLL_EXTERN void gjoll_sconnection_readlen(gjoll_sconnection_t *conn,
                                            int readlen);

GJOLL_EXTERN void gjoll_sconnection_close(gjoll_sconnection_t *);

GJOLL_EXTERN void gjoll_sconnection_clean(gjoll_sconnection_t *);

GJOLL_EXTERN int gjoll_sconnection_closed(gjoll_sconnection_t *);

struct gjoll_ssend_s {
    void *data;
    gjoll_send_t req;
    gjoll_buf_t buffer;
    gjoll_ssend_cb cb;
};

GJOLL_EXTERN int gjoll_ssend(gjoll_ssend_t *,
                             gjoll_sconnection_t *,
                             void *data,
                             size_t len,
                             gjoll_ssend_cb cb);


/* DAEMON */

struct gjoll_rule_s {
    gjoll_service_t id;
    struct sockaddr_in laddr;

    UT_hash_handle hh;
};

struct gjoll_friend_s {
    gjoll_node_t id;
    const void *shared;
    size_t shared_len;

    UT_hash_handle hh;
};

struct gjoll__conn_context_s {
    gjoll_daemon_t *d;
    gjoll_sconnection_t gconn;
    gjoll_connection_t lconn;

    gjoll__conn_context_t *next, *prev;
};

struct gjoll__listener_context_s {
    gjoll_daemon_t *d;
    gjoll_listener_t listener;
    gjoll_node_t node;
    gjoll_service_t service;
    struct sockaddr_in addr;

    gjoll__listener_context_t *next, *prev;
};

struct gjoll_daemon_s {
    gjoll_rule_t *rules;
    gjoll_friend_t *friends;
    gjoll__conn_context_t *ccs;
    gjoll__listener_context_t *lcs;

    gjoll_loop_t gloop;
    gjoll_slistener_t listener;
    gjoll_node_t id;
};

GJOLL_EXTERN int gjoll_daemon_init(gjoll_loop_t loop,
                                   gjoll_daemon_t *d,
                                   gjoll_node_t id,
                                   const struct sockaddr_in addr);

GJOLL_EXTERN void gjoll_daemon_clean(gjoll_daemon_t *d);

GJOLL_EXTERN gjoll_friend_t *gjoll_daemon_add_friend(gjoll_daemon_t *d,
                                                     gjoll_node_t id,
                                                     const void *shared,
                                                     const size_t shared_len);

GJOLL_EXTERN gjoll_friend_t *gjoll_daemon_get_friend(gjoll_daemon_t *d,
                                                     gjoll_node_t id);

GJOLL_EXTERN gjoll_rule_t *gjoll_daemon_add_rule(gjoll_daemon_t *d,
                                                 gjoll_service_t service,
                                                 const struct sockaddr_in laddr);

GJOLL_EXTERN gjoll_rule_t *gjoll_daemon_get_rule(gjoll_daemon_t *d,
                                                 gjoll_service_t id);

GJOLL_EXTERN int gjoll_daemon_add_route(gjoll_daemon_t *d, gjoll_node_t node,
                                        gjoll_service_t service,
                                        const struct sockaddr_in addr,
                                        const struct sockaddr_in laddr);

/* LUA */

GJOLL_EXTERN lua_State *gjoll_lua_new(gjoll_loop_t *loop);

GJOLL_EXTERN void gjoll_lua_clean(lua_State *l);

GJOLL_EXTERN void gjoll_lua_delete(lua_State *l);

GJOLL_EXTERN int gjoll_lua_load(lua_State *l, const char *filename);

GJOLL_EXTERN const char *gjoll_lua_geterror(lua_State *l);

#ifdef __cplusplus
}
#endif

#endif
