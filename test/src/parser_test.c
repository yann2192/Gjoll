/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "test.h"
#include "gjoll.h"

#include "../src/parser.h"


static char* test__gjoll__parser_init() {
    gjoll__parser_t parser;
    gjoll__parser_init(&parser);
    mu_assert("test__gjoll__parser_init: parser.i != 0", parser.i == 0);
    mu_assert("test__gjoll__parser_init: parser.state != GJOLL_PARSE_HEADER",
              parser.state == GJOLL_PARSE_HEADER);
    mu_assert("test__gjoll__parser_init: parser.data.base != NULL",
              parser.data.base == NULL);
    mu_assert("test__gjoll__parser_init: parser.data.len != 0",
              parser.data.len == 0);
    return 0;
}

static char* test__gjoll__parser_alloc() {
    int res;
    gjoll__parser_t parser;

    gjoll__parser_init(&parser);
    mu_assert("test__gjoll__parser_init: parser.data.base != NULL",
              parser.data.base == NULL);
    mu_assert("test__gjoll__parser_init: parser.data.len != 0",
              parser.data.len == 0);

    gjoll__parser_free_data(&parser);
    mu_assert("test__gjoll__parser_init: parser.data.base != NULL",
              parser.data.base == NULL);
    mu_assert("test__gjoll__parser_init: parser.data.len != 0",
              parser.data.len == 0);

    res = gjoll__parser_alloc_data(&parser, 4);
    mu_assert("test__gjoll__parser_init: gjoll__parser_alloc_data != 0",
              !res);
    mu_assert("test__gjoll__parser_init: parser.data.base == NULL",
              parser.data.base != NULL);
    mu_assert("test__gjoll__parser_init: parser.data.len != 4",
              parser.data.len == 4);

    gjoll__parser_free_data(&parser);
    mu_assert("test__gjoll__parser_init: parser.data.base != NULL",
              parser.data.base == NULL);
    mu_assert("test__gjoll__parser_init: parser.data.len != 0",
              parser.data.len == 0);
    return 0;
}

static char* test__gjoll__parser_parse_header() {
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    char buffer[GJOLL_HEADER_LENGTH]; /* buffer length == header length */

    buf.len = GJOLL_HEADER_LENGTH;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    i = gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_header: parser i != GJOLL_HEADER_LENGTH",
              i == GJOLL_HEADER_LENGTH);
    mu_assert("test__gjoll__parser_parse_header: parser action != GJOLL_HEADER_ACTION",
              action == GJOLL_HEADER_ACTION);
    mu_assert("test__gjoll__parser_parse_header: parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);
    return 0;
}

static char* test__gjoll__parser_parse_header2() {
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    /* buffer length < header length: two passes */
    char *buffer[GJOLL_HEADER_LENGTH];

    buf.len = GJOLL_HEADER_LENGTH;
    buf.base = buffer;
    gjoll__parser_init(&parser);

    buf.len = buf.len - 10;
    i = gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_header2: 1. parser i != GJOLL_HEADER_LENGTH",
              i == GJOLL_HEADER_LENGTH - 10);
    mu_assert("test__gjoll__parser_parse_header2: 1. parser action != GJOLL_NONE_ACTION",
              action == GJOLL_NONE_ACTION);
    mu_assert("test__gjoll__parser_parse_header2: 1. parser state != GJOLL_PARSE_HEADER",
              parser.state == GJOLL_PARSE_HEADER);

    buf.base = OFFSET(buf.base, buf.len - 10);
    buf.len = 10;
    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_header2: 2. parser i != GJOLL_HEADER_LENGTH",
              i == GJOLL_HEADER_LENGTH);
    mu_assert("test__gjoll__parser_parse_header2: 2. parser action != GJOLL_HEADER_ACTION",
              action == GJOLL_HEADER_ACTION);
    mu_assert("test__gjoll__parser_parse_header2: 2. parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);

    return 0;
}

static char* test__gjoll__parser_parse_header3() {
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    /* buffer length > header length */
    char buffer[GJOLL_HEADER_LENGTH + 1];

    buf.len = GJOLL_HEADER_LENGTH + 1;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    i = gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_header3: parser i != GJOLL_HEADER_LENGTH",
              i == GJOLL_HEADER_LENGTH);
    mu_assert("test__gjoll__parser_parse_header3: parser action != GJOLL_HEADER_ACTION",
              action == GJOLL_HEADER_ACTION);
    mu_assert("test__gjoll__parser_parse_header3: parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);

    return 0;
}

static char* test__gjoll__parser_parse_size() {
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    /* buffer length == header length + size len */
    char buffer[GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE];

    buf.len = GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    /* parse the header */
    i = gjoll__parser_parse(&parser, &action, buf);
    buf.len -= i;
    buf.base = OFFSET(buf.base, i);
    /* parse the size */
    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_size: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE);
    mu_assert("test__gjoll__parser_parse_size: parser action != GJOLL_SIZE_ACTION",
              action == GJOLL_SIZE_ACTION);
    mu_assert("test__gjoll__parser_parse_size: parser state != GJOLL_PARSE_DATA",
              parser.state == GJOLL_PARSE_DATA);

    return 0;
}

static char* test__gjoll__parser_parse_data() {
    int res;
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    char buffer[GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE];

    buf.len = GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    /* parse the header */
    i = gjoll__parser_parse(&parser, &action, buf);
    buf.len -= i;
    buf.base = OFFSET(buf.base, i);
    /* parse the size */
    i += gjoll__parser_parse(&parser, &action, buf);

    res = gjoll__parser_alloc_data(&parser, 4);
    mu_assert("test__gjoll__parser_parse_data: gjoll__parser_alloc_data != 0",
              !res);

    buf.len = 4 + GJOLL_FINGERPRINT_SIZE;
    buf.base = buffer;

    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_data: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE);
    mu_assert("test__gjoll__parser_parse_data: parser action != GJOLL_DATA_ACTION",
              action == GJOLL_DATA_ACTION);
    mu_assert("test__gjoll__parser_parse_data: parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);


    gjoll__parser_free_data(&parser);
    return 0;
}

static char* test__gjoll__parser_parse_data2() {
    int res;
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    char buffer[GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE];

    buf.len = GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    /* parse the header */
    i = gjoll__parser_parse(&parser, &action, buf);
    buf.len -= i;
    buf.base = OFFSET(buf.base, i);
    /* parse the size */
    i += gjoll__parser_parse(&parser, &action, buf);

    res = gjoll__parser_alloc_data(&parser, 4);
    mu_assert("test__gjoll__parser_parse_data: gjoll__parser_alloc_data != 0",
              !res);

    buf.len = 4;
    buf.base = buffer;

    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_data2: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4);
    mu_assert("test__gjoll__parser_parse_data2: parser action != GJOLL_NONE_ACTION",
              action == GJOLL_NONE_ACTION);
    mu_assert("test__gjoll__parser_parse_data2: parser state != GJOLL_PARSE_DATA",
              parser.state == GJOLL_PARSE_DATA);

    buf.len = GJOLL_FINGERPRINT_SIZE;

    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_data2: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE);
    mu_assert("test__gjoll__parser_parse_data2: parser action != GJOLL_DATA_ACTION",
              action == GJOLL_DATA_ACTION);
    mu_assert("test__gjoll__parser_parse_data2: parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);


    gjoll__parser_free_data(&parser);
    return 0;
}

static char* test__gjoll__parser_parse_data3() {
    int res;
    size_t i = 0;
    gjoll__parser_t parser;
    gjoll__parse_action_t action;
    gjoll_buf_t buf;
    char buffer[GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE];

    buf.len = GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE;
    buf.base = buffer;

    gjoll__parser_init(&parser);

    /* parse the header */
    i = gjoll__parser_parse(&parser, &action, buf);
    buf.len -= i;
    buf.base = OFFSET(buf.base, i);
    /* parse the size */
    i += gjoll__parser_parse(&parser, &action, buf);

    res = gjoll__parser_alloc_data(&parser, 4);
    mu_assert("test__gjoll__parser_parse_data: gjoll__parser_alloc_data != 0",
              !res);

    buf.len = 4 + GJOLL_FINGERPRINT_SIZE + 2;
    buf.base = buffer;

    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_data3: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE);
    mu_assert("test__gjoll__parser_parse_data3: parser action != GJOLL_DATA_ACTION",
              action == GJOLL_DATA_ACTION);
    mu_assert("test__gjoll__parser_parse_data3: parser state != GJOLL_PARSE_SIZE",
              parser.state == GJOLL_PARSE_SIZE);

    buf.len -= i;

    i += gjoll__parser_parse(&parser, &action, buf);
    mu_assert("test__gjoll__parser_parse_data3: parser i != GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE + GJOLL_LEN_SIZE",
              i == GJOLL_HEADER_LENGTH + GJOLL_LEN_SIZE + 4 + GJOLL_FINGERPRINT_SIZE + GJOLL_LEN_SIZE);
    mu_assert("test__gjoll__parser_parse_data3: parser action != GJOLL_SIZE_ACTION",
              action == GJOLL_SIZE_ACTION);
    mu_assert("test__gjoll__parser_parse_data3: parser state != GJOLL_PARSE_DATA",
              parser.state == GJOLL_PARSE_DATA);


    gjoll__parser_free_data(&parser);
    return 0;
}

char* parser_tests() {
    mu_run_test(test__gjoll__parser_init);
    mu_run_test(test__gjoll__parser_alloc);
    mu_run_test(test__gjoll__parser_parse_header);
    mu_run_test(test__gjoll__parser_parse_header2);
    mu_run_test(test__gjoll__parser_parse_header3);
    mu_run_test(test__gjoll__parser_parse_size);
    mu_run_test(test__gjoll__parser_parse_data);
    mu_run_test(test__gjoll__parser_parse_data2);
    mu_run_test(test__gjoll__parser_parse_data3);
    return 0;
}
