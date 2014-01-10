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

#define GJOLL_NONCE_SIZE 8
#define GJOLL_IDENTIFIER_SIZE 8
#define GJOLL_FINGERPRINT_SIZE 16
#define GJOLL_SERVICE_SIZE 2
#define GJOLL_SHARED_SIZE 32

#define GJOLL_HEADER_MIN_LENGTH 42
#define GJOLL_MAX_DATA_LENGTH (536 - 42)

/* types */
typedef uint64_t gjoll_node_t;
typedef uint16_t gjoll_service_t;

typedef struct {
    void *data;
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

// encrypts a header + data into a gjoll_buf_t
GJOLL_EXTERN int gjoll_encrypt_packet(gjoll_header_t *header,
                                      gjoll_buf_t data,
                                      const void *shared_secret,
                                      gjoll_buf_t *buf);

// decrypts a data buffer containing a packet and extracts the header
// *ctx will contain an encryption context to pass to gjoll_decrypt_data
GJOLL_EXTERN int gjoll_decrypt_header(gjoll_buf_t buf,
                                      gjoll_header_t *header,
                                      const void *shared_secret,
                                      void **ctx);

// decrypts a data buffer containing a packet and extracts the data
// needs the ctx acquired from gjoll_decrypt_header
// if data is 0, just frees the ctx
GJOLL_EXTERN int gjoll_decrypt_data(gjoll_buf_t buf,
                                    gjoll_buf_t *data,
                                    void *ctx);

#ifdef __cplusplus
}
#endif

#endif
