/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <stdio.h>
#include <string.h>

#include "test.h"
#include "gjoll.h"


static char* test__gjoll_buf_init() {
    gjoll_buf_t b = gjoll_buf_init(NULL, 0);
    mu_assert("error: gjoll_buf_t.data != NULL", b.data == NULL);
    mu_assert("error: gjoll_buf_t.len != 0", b.len == 0);
    char *buf_test = malloc(1024);
    b = gjoll_buf_init(buf_test, 1024);
    mu_assert("error: gjoll_buf_t.data != buf_test", b.data == buf_test);
    mu_assert("error: gjoll_buf_t.len != 1024", b.len == 1024);
    free(buf_test);
    return 0;
}

static char* test__gjoll_parse_compute_header() {
    gjoll_header_t h;
    memcpy(h.nonce, "=\x00;\xa1\xe8Yg\xcd", GJOLL_NONCE_SIZE);
    memcpy(h.src, "\x16\xfe^\x16\x08\x93\xb4L", GJOLL_IDENTIFIER_SIZE);
    memcpy(h.dst, "v\x95\x8a\x0e\x11\x02\xc9\xc5", GJOLL_IDENTIFIER_SIZE);
    h.service = 666;
    memcpy(h.fingerprint,
           "\xd4\xc1\x98\xd6\xea\x8eN\xb5\x8a\xe2\xf5\xf4\x95\x00\xa9\xf5",
           GJOLL_FINGERPRINT_SIZE);
    h.buf = gjoll_buf_init(NULL, 0);
    gjoll_buf_t buf = gjoll_compute_header(&h);
    mu_assert("error: gjoll_compute_header failed", buf.data != NULL);
    mu_assert("error: gjoll_compute_header failed",
              buf.len == GJOLL_HEADER_MIN_LENGTH);
    gjoll_header_t* h2 = gjoll_parse_header(buf);
    mu_assert("error: gjoll_parse_header failed", h2 != NULL);
    mu_assert("error: gjoll_parse_compute bad nonce",
              memcmp(h2->nonce, h.nonce, GJOLL_NONCE_SIZE) == 0);
    mu_assert("error: gjoll_parse_compute bad src",
              memcmp(h2->src, h.src, GJOLL_IDENTIFIER_SIZE) == 0);
    mu_assert("error: gjoll_parse_compute bad dst",
              memcmp(h2->dst, h.dst, GJOLL_IDENTIFIER_SIZE) == 0);
    mu_assert("error: gjoll_parse_compute bad service",
              h2->service == h.service);
    mu_assert("error: gjoll_parse_compute bad fingerprint",
              memcmp(h2->fingerprint, h.fingerprint, GJOLL_FINGERPRINT_SIZE) == 0);
    mu_assert("error: gjoll_parse_header error data",
              h2->buf.data == NULL && h2->buf.len == 0);
    gjoll_free_buf(&buf);
    gjoll_free_header(h2);
    return 0;
}

char* header_tests() {
    mu_run_test(test__gjoll_buf_init);
    mu_run_test(test__gjoll_parse_compute_header);
    return 0;
}
