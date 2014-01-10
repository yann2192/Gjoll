/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "gjoll.h"

// for endianness
#include "ordo/internal/sys.h"

#define OFFSET(p, i) ((char *)p + i)


GJOLL_EXTERN gjoll_buf_t gjoll_buf_init(void* data, size_t len) {
    gjoll_buf_t buf;
    buf.data = data;
    buf.len = len;
    return buf;
}

GJOLL_EXTERN void gjoll_free_buf(gjoll_buf_t* buf) {
    if(buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
}

GJOLL_EXTERN void gjoll_free_header(gjoll_header_t* h) {
    if(h->buf.data != NULL) {
        free(h->buf.data);
        h->buf.data = NULL;
        h->buf.len = 0;
    }
    free(h);
}

GJOLL_EXTERN gjoll_header_t* gjoll_parse_header(const gjoll_buf_t buf) {
    int data_size;
    unsigned int i = 0;
    uint16_t service;
    gjoll_header_t *h = NULL;

    if(buf.len < GJOLL_HEADER_MIN_LENGTH) {
        /* Packet too small */
        goto error;
    }

    h = malloc(sizeof(gjoll_header_t));
    if(h == NULL)
        goto error;
    h->buf = gjoll_buf_init(NULL, 0);

    memcpy(h->nonce, OFFSET(buf.data, i), GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(h->src, OFFSET(buf.data, i), GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(h->dst, OFFSET(buf.data, i), GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(&service, OFFSET(buf.data, i), GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;
    h->service = htobe16_(service);

    memcpy(h->fingerprint, OFFSET(buf.data, i), GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    data_size = buf.len-i;
    if(data_size > 0) {
        h->buf.len = data_size;
        h->buf.data = malloc(data_size);
        if(h->buf.data == NULL)
            goto error;
        memcpy((char *)h->buf.data, OFFSET(buf.data, i), data_size);
    }

    return h;

error:
    if(h != NULL)
        free(h);
    return NULL;
}

GJOLL_EXTERN int gjoll_header_len(const gjoll_header_t* h) {
    return h->buf.len+GJOLL_HEADER_MIN_LENGTH;
}

GJOLL_EXTERN gjoll_buf_t gjoll_compute_header(const gjoll_header_t* h) {
    unsigned int i = 0;
    uint16_t service;
    gjoll_buf_t buf;
    buf.len = gjoll_header_len(h);
    buf.data = malloc(buf.len);
    if(buf.data == NULL) {
        buf.len = 0;
        return buf;
    }

    memcpy(OFFSET(buf.data, i), h->nonce, GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(OFFSET(buf.data, i), h->src, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(OFFSET(buf.data, i), h->dst, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    service = be16toh_(h->service);
    memcpy(OFFSET(buf.data, i), &service, GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;

    memcpy(OFFSET(buf.data, i), h->fingerprint, GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    if(h->buf.data != NULL) {
        memcpy(OFFSET(buf.data, i), (char*)h->buf.data, h->buf.len);
    }

    return buf;
}
