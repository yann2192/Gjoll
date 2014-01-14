#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ordo.h"
#include "gjoll.h"
#include "uv.h"

gjoll_session_t *session_cb(const gjoll_connection_t *gconn,
                const gjoll_node_t *identifier,
                const struct sockaddr *addr) {
    printf("%s\n", (char *)identifier);
    return NULL;
}

int main(int argc, char **argv) {
    ordo_init();
    gjoll_loop_t loop;
    if(gjoll_init(&loop)) {
        fprintf(stderr, "gjoll_init failed\n");
        return 1;
    }
    gjoll_connection_t conn;
    if(gjoll_new_connection(loop, &conn)) {
        fprintf(stderr, "gjoll_new_connection failed\n");
        return 1;
    }
    struct sockaddr_in bind_addr;
    if(uv_ip4_addr("0.0.0.0", 9999, &bind_addr)) {
        fprintf(stderr, "uv_ip4_addr failed\n");
        return 1;
    }
    if(gjoll_bind_connection(&conn, (const struct sockaddr*) &bind_addr, 0)) {
        fprintf(stderr, "gjoll_bind_connection failed\n");
        return 1;
    }
    if(gjoll_up_connection(&conn, session_cb)) {
        fprintf(stderr, "gjoll_ready_connection failed\n");
        return 1;
    }
    gjoll_run(loop);
    return 0;
}
