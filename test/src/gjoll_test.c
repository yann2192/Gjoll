/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "test.h"


static char* all_tests() {
    srand(time(0));
    mu_run(buf_tests);
    mu_run(crypto_tests);
    mu_run(parser_tests);
    //mu_run(network_tests);
    return 0;
}

int main(int argc, char **argv) {
     char *result = all_tests();
     if (result != 0) {
         printf("> %s\n", result);
     }
     else {
         printf("> ALL TESTS PASSED\n");
     }
     printf("Tests run: %d\n", tests_run);

     return result != 0;
}
