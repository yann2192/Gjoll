#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "gjoll.h"
#include "uv.h"

gjoll_service_t service = 1234;
gjoll_node_t myid = 888;

void signal_handler(uv_signal_t *s, int signum) {
    uv_stop(s->data);
}

int main(int argc, char **argv) {
    uv_signal_t s1;
    gjoll_loop_t loop;
    lua_State *l;

    if(gjoll_init(&loop)) {
        fprintf(stderr, "gjoll_init failed\n");
        return 1;
    }

    s1.data = loop.loop;
    uv_signal_init(loop.loop, &s1);
    uv_signal_start(&s1, signal_handler, SIGINT);

    l = gjoll_lua_new(&loop);

    if(argc > 1) {
        if(gjoll_lua_load(l, argv[1])) {
            fprintf(stderr, "%s", gjoll_lua_geterror(l));
            goto err;
        }
    }

    gjoll_run(loop);

    uv_signal_stop(&s1);
    uv_close((uv_handle_t *) &s1, NULL);
    gjoll_lua_clean(l);
    gjoll_delete(&loop);
    gjoll_lua_delete(l);
    return 0;

err:
    uv_signal_stop(&s1);
    uv_close((uv_handle_t *) &s1, NULL);
    gjoll_lua_clean(l);
    gjoll_delete(&loop);
    gjoll_lua_delete(l);
    return 1;
}
