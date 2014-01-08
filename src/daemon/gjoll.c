#include <stdio.h>

#include "ordo.h"
#include "uv.h"

int main(int argc, char **argv) {
    uv_loop_t *loop = uv_loop_new();
    printf("hello world\n");
    ordo_init();
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
