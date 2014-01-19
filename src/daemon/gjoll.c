#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "ordo.h"
#include "gjoll.h"
#include "uv.h"

gjoll_session_t *session = NULL;

void recv_cb(const gjoll_session_t *session,
             gjoll_buf_t buf) {
    printf("%s\n", (char *)buf.data);
    free(buf.data);
}

gjoll_session_t *session_cb(gjoll_connection_t *gconn,
                const gjoll_node_t *identifier,
                const gjoll_service_t *service_id,
                const struct sockaddr *addr) {
    printf("%d\n", (int)*identifier);
    if(session == NULL) {
        session = malloc(sizeof(gjoll_session_t));
        if(session == NULL)
            return NULL;
        if(gjoll_new_session(gconn, session, addr, *identifier, *service_id,
                             "secretkey", 9, recv_cb)) {
            free(session);
            session = NULL;
            return NULL;
        }
    }
    return session;
}

void signal_handler(uv_signal_t *s, int signum) {
    uv_stop(s->data);
}

int main(int argc, char **argv) {
    uv_signal_t s1;
    gjoll_connection_t conn;
    gjoll_loop_t loop;
    struct sockaddr_in bind_addr;

    ordo_init();
    if(gjoll_init(&loop)) {
        fprintf(stderr, "gjoll_init failed\n");
        return 1;
    }

    s1.data = loop.loop;
    uv_signal_init(loop.loop, &s1);
    uv_signal_start(&s1, signal_handler, SIGINT);

    if(gjoll_new_connection(loop, &conn)) {
        fprintf(stderr, "gjoll_new_connection failed\n");
        return 1;
    }
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
    gjoll_delete(&loop);
    if(session != NULL)
        free(session);
    return 0;
}
