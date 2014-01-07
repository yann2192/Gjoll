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

#ifdef _WIN32
    /* Windows - set up dll import/export decorators. */
# if defined(BUILD_SHARED)
    /* Building shared library. */
#   define GJOLL_EXTERN __declspec(dllexport)
# elif defined(USING_SHARED)
    /* Using shared library. */
#   define GJOLL_EXTERN __declspec(dllimport)
# else
    /* Building static library. */
#   define GJOLL_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define GJOLL_EXTERN __attribute__((visibility("default")))
#else
# define GJOLL_EXTERN /* nothing */
#endif

#include <stdint.h>

#define GJOLL_NONCE_SIZE 8
#define GJOLL_IDENTIFIER_SIZE 8
#define GJOLL_FINGERPRINT_SIZE 16
#define GJOLL_SERVICE_SIZE 2

#define GJOLL_HEADER_MIN_LENGTH 42

/* types */
typedef uint16_t gjoll_service_t;
typedef struct gjoll_header_s gjoll_header_t;
typedef struct gjoll_buf_s gjoll_buf_t;

struct gjoll_buf_s {
    char *data;
    int len;
};

struct gjoll_header_s {
    char nonce[GJOLL_NONCE_SIZE];
    char src[GJOLL_IDENTIFIER_SIZE];
    char dst[GJOLL_IDENTIFIER_SIZE];
    gjoll_service_t service;
    char fingerprint[GJOLL_FINGERPRINT_SIZE];
    gjoll_buf_t* buf;
};

GJOLL_EXTERN gjoll_header_t* gjoll_parse_header(const gjoll_buf_t *buf);

GJOLL_EXTERN int gjoll_header_len(const gjoll_header_t* h);

GJOLL_EXTERN gjoll_buf_t* gjoll_header_compute(const gjoll_header_t* h);

#endif /* end of include guard: GJOLL_H */
