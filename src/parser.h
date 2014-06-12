#ifndef GJOLL_PARSER_H
#define GJOLL_PARSER_H

#include <string.h>

#include "gjoll.h"

#include "ordo/misc/endianness.h"

#define GJOLL_PARSE_HEADER 0
#define GJOLL_PARSE_SIZE 1
#define GJOLL_PARSE_DATA 2

typedef enum {
    GJOLL_NONE_ACTION,
    GJOLL_HEADER_ACTION,
    GJOLL_SIZE_ACTION,
    GJOLL_DATA_ACTION
} gjoll__parse_action_t;

void gjoll__parser_init(gjoll__parser_t *parser);

size_t gjoll__parser_parse(gjoll__parser_t *parser,
                           gjoll__parse_action_t *action,
                           gjoll_buf_t buf);

int gjoll__parser_set_datalen(gjoll__parser_t *parser, size_t len);

#endif
