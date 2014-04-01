/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "parser.h"

#define FREEDATA(parser) do { \
        free(parser->data.base); \
        parser->data.base = NULL; \
        parser->data.len = 0; \
    }while(0);


void gjoll__parser_init(gjoll__parser_t *parser) {
    parser->i = 0;
    parser->state = GJOLL_PARSE_HEADER;
    parser->datalen = 0;
}

size_t gjoll__parser_parse(gjoll__parser_t *parser,
                           gjoll__parse_action_t *action,
                           gjoll_buf_t buf) {
    size_t i, needed;
    *action = GJOLL_NONE_ACTION;

    switch(parser->state) {
        case GJOLL_PARSE_HEADER:
            needed = GJOLL_HEADER_LENGTH - parser->i;
            if(buf.len > needed) {
                i = needed;
            } else {
                i = buf.len;
            }
            memcpy(OFFSET(parser->hbuf, parser->i), buf.base, i);
            parser->i += i;
            if(parser->i == GJOLL_HEADER_LENGTH) {
                parser->i = 0;
                parser->state = GJOLL_PARSE_SIZE;
                *action = GJOLL_HEADER_ACTION;
            }
            break;
        case GJOLL_PARSE_SIZE:
            needed = GJOLL_LEN_SIZE - parser->i;
            if(buf.len > needed) {
                i = needed;
            } else {
                i = buf.len;
            }
            memcpy(OFFSET(&(parser->lenbuff), parser->i), buf.base, i);
            parser->i += i;
            if(parser->i == GJOLL_LEN_SIZE) {
                parser->i = 0;
                parser->state = GJOLL_PARSE_DATA;
                *action = GJOLL_SIZE_ACTION;
            }
            break;
        case GJOLL_PARSE_DATA:
            if(parser->i == 0) {
                memcpy(parser->data, &(parser->lenbuff), GJOLL_LEN_SIZE);
                parser->i += GJOLL_LEN_SIZE;
            }
            needed = parser->datalen + GJOLL_FINGERPRINT_SIZE -
                     parser->i + GJOLL_LEN_SIZE;
            if(buf.len > needed) {
                i = needed;
            } else {
                i = buf.len;
            }
            memcpy(OFFSET(parser->data, parser->i), buf.base, i);
            parser->i += i;
            if(parser->i == parser->datalen + GJOLL_FINGERPRINT_SIZE +
                            GJOLL_LEN_SIZE) {
                parser->i = 0;
                parser->datalen = 0;
                parser->state = GJOLL_PARSE_SIZE;
                *action = GJOLL_DATA_ACTION;
            }
            break;
    }

    return i;
}

int gjoll__parser_set_datalen(gjoll__parser_t *parser, size_t len) {
    if(len > GJOLL_ALLOC_MAX) {
        return -1;
    }
    parser->datalen = len;
    return 0;
}
