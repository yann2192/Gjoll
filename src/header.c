/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "gjoll.h"


GJOLL_EXTERN gjoll_header_t* gjoll_parse_header(const gjoll_buf_t *buf) {
    int data_size;
    unsigned int i = 0;
    uint16_t service;
    gjoll_header_t *h = NULL;

    if(buf->len < GJOLL_HEADER_MIN_LENGTH) {
        /* Packet too small */
        return h;
    }

    h = malloc(sizeof(gjoll_service_t));

    memcpy(h->nonce, buf->data, GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(h->src, buf->data+i, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(h->dst, buf->data+i, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(&service, buf->data+i, GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;
    h->service = service; /* TODO: need ntohs */

    memcpy(h->fingerprint, buf->data+i, GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    data_size = buf->len-i;
    h->buf->len = data_size;
    h->buf->data = malloc(data_size);
    memcpy(h->buf->data, buf->data+i, data_size);

    return h;
}

GJOLL_EXTERN int gjoll_header_len(const gjoll_header_t* h) {
    return h->buf->len+GJOLL_HEADER_MIN_LENGTH;
}

GJOLL_EXTERN gjoll_buf_t* gjoll_header_compute(const gjoll_header_t* h) {
    unsigned int i = 0;
    uint16_t service;
    gjoll_buf_t* buf = malloc(sizeof(gjoll_buf_t));
    buf->len = gjoll_header_len(h);
    buf->data = malloc(buf->len);

    memcpy(buf->data, h->nonce, GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(buf->data+i, h->src, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(buf->data+i, h->dst, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    service = h->service; /* TODO: need htons */
    memcpy(buf->data+i, &service, GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;

    memcpy(buf->data+i, h->fingerprint, GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    memcpy(buf->data+i, h->buf->data, h->buf->len);

    return buf;
}
