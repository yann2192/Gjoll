#include <stdio.h>

#include "ordo.h"
#include "uv.h"

int main(int argc, char **argv) {
    uv_loop_t *loop = uv_loop_new();
    printf("hello world\n");
    ordo_init();
    return 0;
}
