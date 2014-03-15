/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "test.h"
#include "gjoll.h"
#include "uv.h"

#include "../src/network.c"

static char *test__gjoll_init() {
    gjoll_loop_t loop;
    mu_assert("test__gjoll_init: goll_init returns -1",
              gjoll_init(&loop) == 0);
    mu_assert("test__gjoll_init: loop == NULL", loop.loop != NULL);
    gjoll_run(loop);
    gjoll_delete(&loop);
    mu_assert("test__gjoll_init: loop != NULL", loop.loop == NULL);
    return 0;
}

static char *test__gjoll__alloc_cb() {
    uv_buf_t buf;
    uv_handle_t h;
    memset(&buf, 0, sizeof(uv_buf_t));
    gjoll__alloc_cb(&h, 1024, &buf);
    mu_assert("test__gjoll__alloc_cb: buf.base == NULL", buf.base != NULL);
    mu_assert("test__gjoll__alloc_cb: buf.len != 1024", buf.len == 1024);
    free(buf.base);
    return 0;
}

static int accept_cb(gjoll_slistener_t *l) {
    l->data = (void *) 1;
    return -1;
}

static void recv_cb(uv_stream_t *client, ssize_t nread,
                           const uv_buf_t* buf) {
    if(nread < 0 && !client->data) {
        client->data = (void *) 2;
    } else {
        client->data = (void *) 1;
    }
    free(buf->base);
}

static void connect_cb(uv_connect_t *req, int status) {
    uv_tcp_t *sock = (uv_tcp_t *) req->data;
    uv_read_start((uv_stream_t *)sock, gjoll__alloc_cb, recv_cb);
}

static char *test__gjoll_slistener1() {
    int res;
    struct sockaddr_in bind_addr;
    gjoll_loop_t lo;
    gjoll_slistener_t li;
    uv_tcp_t sock;
    uv_connect_t c;

    gjoll_init(&lo);
    res = gjoll_slistener_init(lo, &li, 0);
    mu_assert("test__gjoll_slistener1: gjoll_slistener_init returns failed",
              !res);
    uv_ip4_addr("127.0.0.1", 9999, &bind_addr);

    res = gjoll_slistener_bind(&li, (const struct sockaddr*) &bind_addr);
    mu_assert("test__gjoll_slistener1: gjoll_slistener_bind failed", !res);

    res = gjoll_slistener_listen(&li, accept_cb);
    mu_assert("test__gjoll_slistener1: gjoll_slistener_listen failed", !res);

    uv_tcp_init(lo.loop, &sock);
    uv_tcp_connect(&c, &sock, (const struct sockaddr*) &bind_addr,
                   connect_cb);
    sock.data = 0;
    li.data = 0;
    c.data = &sock;

    uv_run(lo.loop, UV_RUN_NOWAIT);
    /* two passe to check if sock received rst */
    uv_run(lo.loop, UV_RUN_NOWAIT);

    mu_assert("test__gjoll_slistener1: sock.data != 2", sock.data == (void *) 2);
    mu_assert("test__gjoll_slistener1: li.data == 0", li.data != 0);

    gjoll_delete(&lo);
    return 0;
}

static int accept_cb2(gjoll_slistener_t *l) {
    l->data = (void *) 1;
    return 0;
}

static void recv_cb2(uv_stream_t *client, ssize_t nread,
                     const uv_buf_t* buf) {
    client->data = (void *) 2;
    free(buf->base);
}

static void connect_cb2(uv_connect_t *req, int status) {
    uv_tcp_t *sock = (uv_tcp_t *) req->data;
    sock->data = (void *) 1;
    uv_read_start((uv_stream_t *)sock, gjoll__alloc_cb, recv_cb2);
}

static char *test__gjoll_slistener2() {
    int res;
    struct sockaddr_in bind_addr;
    gjoll_loop_t lo;
    gjoll_slistener_t li;
    uv_tcp_t sock;
    uv_connect_t c;

    gjoll_init(&lo);
    res = gjoll_slistener_init(lo, &li, 0);
    mu_assert("test__gjoll_slistener2: gjoll_slistener_init returns failed",
              !res);
    uv_ip4_addr("127.0.0.1", 10000, &bind_addr);

    res = gjoll_slistener_bind(&li, (const struct sockaddr*) &bind_addr);
    mu_assert("test__gjoll_slistener2: gjoll_slistener_bind failed", !res);

    res = gjoll_slistener_listen(&li, accept_cb2);
    mu_assert("test__gjoll_slistener2: gjoll_slistener_listen failed", !res);

    uv_tcp_init(lo.loop, &sock);
    uv_tcp_connect(&c, &sock, (const struct sockaddr*) &bind_addr,
                   connect_cb2);
    sock.data = 0;
    li.data = 0;
    c.data = &sock;

    uv_run(lo.loop, UV_RUN_NOWAIT);
    /* two passe to check if sock received rst */
    uv_run(lo.loop, UV_RUN_NOWAIT);

    mu_assert("test__gjoll_slistener2: sock.data != 1",
              sock.data == (void *) 1);
    mu_assert("test__gjoll_slistener2: li.data == 0", li.data != 0);

    gjoll_delete(&lo);
    return 0;
}

char *network_tests() {
    mu_run_test(test__gjoll_init);
    mu_run_test(test__gjoll__alloc_cb);
    mu_run_test(test__gjoll_slistener1);
    mu_run_test(test__gjoll_slistener2);
    return 0;
}
