#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "gjoll.h"
#include "uv.h"

gjoll_service_t service = 1234;
gjoll_node_t myid = 888;
gjoll_node_t id2 = 666;

void signal_handler(uv_signal_t *s, int signum) {
    uv_stop(s->data);
}

int main(int argc, char **argv) {
    uv_signal_t s1;
    gjoll_loop_t loop;
    gjoll_daemon_t d;
    struct sockaddr_in bind_addr;
    struct sockaddr_in laddr;
    struct sockaddr_in laddr2;

    if(gjoll_init(&loop)) {
        fprintf(stderr, "gjoll_init failed\n");
        return 1;
    }

    s1.data = loop.loop;
    uv_signal_init(loop.loop, &s1);
    uv_signal_start(&s1, signal_handler, SIGINT);

    if(uv_ip4_addr("0.0.0.0", 9999, &bind_addr)) {
        fprintf(stderr, "uv_ip4_addr failed\n");
        return 1;
    }

    if(uv_ip4_addr("127.0.0.1", 8888, &laddr)) {
        fprintf(stderr, "uv_ip4_addr failed\n");
        return 1;
    }

    if(uv_ip4_addr("127.0.0.1", 7777, &laddr2)) {
        fprintf(stderr, "uv_ip4_addr failed\n");
        return 1;
    }

    if(gjoll_daemon_init(loop, &d, myid,
                         (const struct sockaddr *) &bind_addr)) {
        fprintf(stderr, "gjoll_daemon_init failed\n");
        return 1;
    }
    if(gjoll_daemon_add_friend(&d, myid, "secretkey", 9) == NULL) {
        fprintf(stderr, "gjoll_daemon_add_friend failed\n");
        return 1;
    }
    if(gjoll_daemon_add_rule(&d, service,
                             (const struct sockaddr *) &laddr) == NULL) {
        fprintf(stderr, "gjoll_daemon_add_rule failed\n");
        return 1;
    }
    /*
    if(gjoll_daemon_connect(&d, myid, 1234,
                            (const struct sockaddr*) &bind_addr)) {
        fprintf(stderr, "gjoll_daemon_connect failed\n");
        return 1;
    }
    */
    if(gjoll_daemon_add_route(&d, myid, service,
                              (const struct sockaddr *) &bind_addr,
                              (const struct sockaddr *) &laddr2)) {
        fprintf(stderr, "gjoll_daemon_service failed\n");
        return 1;
    }

    gjoll_run(loop);

    uv_signal_stop(&s1);
    uv_close((uv_handle_t *) &s1, NULL);
    gjoll_daemon_clean(&d);
    gjoll_delete(&loop);
    return 0;
}
