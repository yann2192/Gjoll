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
#define GJOLL_MAX_DATA_LENGTH (536 - 42)

/* types */
typedef uint16_t gjoll_service_t;

typedef struct {
    void *data;
    size_t len;
} gjoll_buf_t;

typedef struct {
    char nonce[GJOLL_NONCE_SIZE];
    char src[GJOLL_IDENTIFIER_SIZE];
    char dst[GJOLL_IDENTIFIER_SIZE];
    char service[GJOLL_SERVICE_SIZE];
    char fingerprint[GJOLL_FINGERPRINT_SIZE];
    char data[GJOLL_MAX_DATA_LENGTH];
    size_t data_len;
} gjoll_packet_t;

// allocates a gjoll_buf_t
GJOLL_EXTERN gjoll_buf_t gjoll_buf_init(void *, size_t);

// frees a gjoll_buf_t
GJOLL_EXTERN void gjoll_free_buf(gjoll_buf_t *buf);

// encrypts data in a gjoll_buf_t into a gjoll_packet_t
// for instance: encrypt("hello world", &packet)
#if 0
GJOLL_EXTERN int gjoll_encode_packet(gjoll_buf_t buf, gjoll_packet_t *packet);
#endif

// decrypts a gjoll_packet_t into a (non-allocated) gjoll_buf_t
// for instance: decrypt(&packet) -> "hello world"
#if 0
GJOLL_EXTERN int gjoll_decode_packet(const gjoll_packet_t *packet, gjoll_buf_t *buf);
#endif

// encodes a header directly from a gjoll_buf_t
// for instance: encode(udp_recv(), &packet)
GJOLL_EXTERN int gjoll_encode_packet(gjoll_buf_t buf, gjoll_packet_t *packet);

// decodes a gjoll_packet_t into a gjoll_buf_t
// for instance: decode(&packet, &buf) udp_send(buf)
GJOLL_EXTERN int gjoll_decode_packet(const gjoll_packet_t *packet, gjoll_buf_t *buf);

// returns the total length of a gjoll_packet_t (header + data)
GJOLL_EXTERN int gjoll_packet_len(const gjoll_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif
