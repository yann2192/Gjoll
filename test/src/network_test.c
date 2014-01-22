/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "test.h"
#include "gjoll.h"

static char * test__gjoll_init() {
    gjoll_loop_t loop;
    mu_assert("error: goll_init returns -1", gjoll_init(&loop) == 0);
    mu_assert("error: loop == NULL", loop.loop != NULL);
    gjoll_run(loop);
    gjoll_delete(&loop);
    mu_assert("error: loop != NULL", loop.loop == NULL);
    return 0;
}

char * network_tests() {
    mu_run_test(test__gjoll_init);
    return 0;
}
