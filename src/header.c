/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "gjoll.h"

gjoll_buf_t gjoll_buf_init(void* data, size_t len) {
    gjoll_buf_t buf;
    buf.data = data;
    buf.len = len;
    return buf;
}

void gjoll_free_buf(gjoll_buf_t* buf) {
    if(buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
}

#if 0

int gjoll_encode_packet(gjoll_buf_t buf, gjoll_packet_t *packet) {
    int data_size;
    unsigned int i = 0;

    if(buf.len < GJOLL_HEADER_MIN_LENGTH) {
        /* Packet too small */
        goto error;
    }

    memcpy(packet->nonce, OFFSET(buf.data, i), GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(packet->src, OFFSET(buf.data, i), GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(packet->dst, OFFSET(buf.data, i), GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(packet->service, OFFSET(buf.data, i), GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;

    memcpy(packet->fingerprint, OFFSET(buf.data, i), GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    data_size = buf.len-i;
    if(data_size > 0) {
        packet->data_len = data_size;
        memcpy(packet->data, OFFSET(buf.data, i), data_size);
    }

    return 0;

error:
    return 1;
}

int gjoll_packet_len(const gjoll_packet_t *packet) {
    return packet->data_len + GJOLL_HEADER_MIN_LENGTH;
}

int gjoll_decode_packet(const gjoll_packet_t *packet, gjoll_buf_t *buf) {
    unsigned int i = 0;
    buf->len = gjoll_packet_len(packet);
    buf->data = malloc(buf->len);
    if(buf->data == NULL) {
        buf->len = 0;
        goto error;
    }

    memcpy(OFFSET(buf->data, i), packet->nonce, GJOLL_NONCE_SIZE);
    i += GJOLL_NONCE_SIZE;

    memcpy(OFFSET(buf->data, i), packet->src, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(OFFSET(buf->data, i), packet->dst, GJOLL_IDENTIFIER_SIZE);
    i += GJOLL_IDENTIFIER_SIZE;

    memcpy(OFFSET(buf->data, i), packet->service, GJOLL_SERVICE_SIZE);
    i += GJOLL_SERVICE_SIZE;

    memcpy(OFFSET(buf->data, i), packet->fingerprint, GJOLL_FINGERPRINT_SIZE);
    i += GJOLL_FINGERPRINT_SIZE;

    memcpy(OFFSET(buf->data, i), packet->data, packet->data_len);

    return 0;

error:
    return 1;
}

#endif
