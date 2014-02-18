#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "ordo.h"
#include "gjoll.h"
#include "uv.h"

gjoll_service_t service = 1234;
gjoll_node_t myid = 888;
gjoll_node_t id2 = 666;

gjoll_connection_t *conn = NULL;

void close_cb(gjoll_connection_t *c) {
    printf("connection closed\n");
    gjoll_connection_clean(c);
    free(c);
    conn = NULL;
}

void close_cb2(gjoll_connection_t *c) {
    gjoll_connection_clean(c);
}

void send_cb(gjoll_send_t *req, int status) {
    free(req);
}

void recv_cb(gjoll_connection_t *conn,
             gjoll_buf_t buf) {
    char str[buf.len+1];
    memcpy(str, buf.base, buf.len);
    str[buf.len] = 0;
    printf("data: %s\n", str);
    free(buf.base);
}

void connect_cb(gjoll_connection_t *conn, int status) {
    gjoll_connection_init(conn, "secretkey", 9, NULL);
}

int header_cb2(gjoll_connection_t *conn, gjoll_header_t header) {
    gjoll_send_t *req = malloc(sizeof(gjoll_send_t));
    req->data = conn;

    gjoll_send(req, conn, "test", 4, send_cb);

    return -1;
}

int header_cb(gjoll_connection_t *conn, gjoll_header_t header) {
    printf("header.id: %d\n", header.id);
    printf("header.src: %ld\n", header.src);
    printf("header.dst: %ld\n", header.dst);
    return 0;
}

int session_cb(gjoll_connection_t *conn, gjoll_node_t src) {
    printf("src: %ld\n", src);
    if(gjoll_connection_init(conn, "secretkey", 9, recv_cb)) {
        free(conn);
        conn = NULL;
        return -1;
    }
    return 0;
}

int accept_cb(gjoll_listener_t *listener) {
    if(conn == NULL) {
        conn = malloc(sizeof(gjoll_connection_t));
        if(gjoll_accept(listener, conn, session_cb, header_cb, close_cb))
            goto error;
        return 0;
    }
    return -1;

error:
    free(conn);
    conn = NULL;
    return -1;
}

void signal_handler(uv_signal_t *s, int signum) {
    uv_stop(s->data);
}

int main(int argc, char **argv) {
    uv_signal_t s1;
    gjoll_listener_t listener;
    gjoll_loop_t loop;
    struct sockaddr_in bind_addr;
    /* --- send test */
    gjoll_connection_t tconn;
    gjoll_header_t header;
    /* --- */

    if(gjoll_init(&loop)) {
        fprintf(stderr, "gjoll_init failed\n");
        return 1;
    }

    s1.data = loop.loop;
    uv_signal_init(loop.loop, &s1);
    uv_signal_start(&s1, signal_handler, SIGINT);

    if(gjoll_listener_init(loop, &listener, myid)) {
        fprintf(stderr, "gjoll_listener_init failed\n");
        return 1;
    }
    if(uv_ip4_addr("0.0.0.0", 9999, &bind_addr)) {
        fprintf(stderr, "uv_ip4_addr failed\n");
        return 1;
    }
    if(gjoll_listener_bind(&listener, (const struct sockaddr*) &bind_addr)) {
        fprintf(stderr, "gjoll_bind_listener failed\n");
        return 1;
    }
    if(gjoll_listener_listen(&listener, accept_cb)) {
        fprintf(stderr, "gjoll_ready_listener failed\n");
        return 1;
    }
    /* --- send test */
    header.src = id2;
    header.dst = myid;
    header.id = service;
    gjoll_connect(loop, &tconn, (const struct sockaddr*) &bind_addr, header,
                  connect_cb, header_cb2, close_cb2);
    /* --- */
    gjoll_run(loop);
    gjoll_delete(&loop);
    gjoll_connection_clean(&tconn);
    if(conn != NULL) {
        gjoll_connection_clean(conn);
        free(conn);
    }
    return 0;
}
