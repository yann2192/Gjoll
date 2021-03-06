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
    char *buf_test = malloc(1024);

    mu_assert("error: gjoll_buf_t.base != NULL", b.base == NULL);
    mu_assert("error: gjoll_buf_t.len != 0", b.len == 0);
    b = gjoll_buf_init(buf_test, 1024);
    mu_assert("error: gjoll_buf_t.base != buf_test", b.base == buf_test);
    mu_assert("error: gjoll_buf_t.len != 1024", b.len == 1024);
    free(buf_test);
    return 0;
}

char* buf_tests() {
    mu_run_test(test__gjoll_buf_init);
    return 0;
}
