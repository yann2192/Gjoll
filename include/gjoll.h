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

#include "uv.h"

#define GJOLL_NONCE_SIZE 8
#define GJOLL_IDENTIFIER_SIZE 8
#define GJOLL_FINGERPRINT_SIZE 16
#define GJOLL_SERVICE_SIZE 2

#define GJOLL_HEADER_MIN_LENGTH 42
#define GJOLL_MAX_DATA_LENGTH (536 - 42)

/*
 * Length of a gjoll shared secret, in bytes.
 */
#define GJOLL_SECRET_LEN 32

#define OFFSET(p, i) ((unsigned char *)p + i)

/* types */
typedef uint64_t gjoll_node_t;
typedef uint16_t gjoll_service_t;

/*
 * Contains a shared secret of fixed length - it is preferred to use this to
 * store shared secrets as it's more efficient than a general purpose buffer
 * such as gjoll_buf_t (as the shared secret is accessed for every packet).
 */
typedef struct {
    unsigned char secret[GJOLL_SECRET_LEN];
} gjoll_secret_t;

typedef struct {
    void *base;
    size_t len;
} gjoll_buf_t;

typedef struct {
    gjoll_node_t src, dst;
    gjoll_service_t id;
} gjoll_header_t;

// allocates a gjoll_buf_t
GJOLL_EXTERN gjoll_buf_t gjoll_buf_init(void *, size_t);

// frees a gjoll_buf_t
GJOLL_EXTERN void gjoll_free_buf(gjoll_buf_t *buf);

typedef struct {
    uv_loop_t* loop;
} gjoll_loop_t;

GJOLL_EXTERN int gjoll_init(gjoll_loop_t *gloop);

GJOLL_EXTERN void gjoll_delete(gjoll_loop_t *gloop);

GJOLL_EXTERN int gjoll_run(gjoll_loop_t gloop);

typedef struct gjoll_connection_s gjoll_connection_t;
typedef struct gjoll_session_s gjoll_session_t;
typedef struct gjoll_send_s gjoll_send_t;

typedef gjoll_session_t* (*gjoll_session_cb) (gjoll_connection_t *gconn,
                                              const gjoll_node_t *identifier,
                                              const struct sockaddr *addr);

struct gjoll_connection_s {
    void *data;
    gjoll_loop_t gloop;
    uv_udp_t sock;
    gjoll_session_cb gs_cb;
};

GJOLL_EXTERN int gjoll_new_connection(gjoll_loop_t gloop,
                                      gjoll_connection_t *gconn);

GJOLL_EXTERN void gjoll_close_connection(gjoll_connection_t *gconn);

GJOLL_EXTERN int gjoll_bind_connection(gjoll_connection_t *gconn,
                                       const struct sockaddr *addr,
                                       int namelen);

GJOLL_EXTERN int gjoll_up_connection(gjoll_connection_t *gconn,
                                     gjoll_session_cb gs_cb);

typedef void (*gjoll_recv_cb) (const gjoll_session_t *session,
                               gjoll_service_t service,
                               gjoll_buf_t buf);

struct gjoll_session_s {
    void *data;
    gjoll_connection_t *conn;
    const struct sockaddr *addr;
    gjoll_node_t identifier;
    gjoll_secret_t secret;
    gjoll_recv_cb recv_cb;
};

GJOLL_EXTERN int gjoll_new_session(gjoll_connection_t *gconn,
                                   gjoll_session_t *session,
                                   const struct sockaddr *addr,
                                   gjoll_node_t identifier,
                                   const void *shared,
                                   const size_t shared_len,
                                   gjoll_recv_cb recv_cb);

/* if status != 0, error */
typedef void (*gjoll_send_cb) (gjoll_send_t *req, int status);

struct gjoll_send_s {
    void *data;
    uv_udp_send_t req;
    gjoll_buf_t buf;
    gjoll_buf_t ciphertext;
    gjoll_send_cb cb;
    int status;
};

GJOLL_EXTERN int gjoll_send(gjoll_send_t *req,
                            const gjoll_session_t *session,
                            const gjoll_service_t service,
                            void *data,
                            size_t len,
                            gjoll_send_cb cb);

#ifdef __cplusplus
}
#endif

#endif
