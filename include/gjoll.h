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

#define GJOLL_HEADER_MIN_LENGTH 42

/* types */
typedef uint16_t gjoll_service_t;

typedef struct {
    void* data;
    size_t len;
} gjoll_buf_t;

typedef struct {
    char nonce[GJOLL_NONCE_SIZE];
    char src[GJOLL_IDENTIFIER_SIZE];
    char dst[GJOLL_IDENTIFIER_SIZE];
    gjoll_service_t service;
    char fingerprint[GJOLL_FINGERPRINT_SIZE];
    gjoll_buf_t buf;
} gjoll_header_t;

GJOLL_EXTERN gjoll_buf_t gjoll_buf_init(void*, size_t);

GJOLL_EXTERN gjoll_header_t* gjoll_parse_header(const gjoll_buf_t buf);

GJOLL_EXTERN int gjoll_header_len(const gjoll_header_t* h);

GJOLL_EXTERN gjoll_buf_t gjoll_header_compute(const gjoll_header_t* h);

#endif /* end of include guard: GJOLL_H */
