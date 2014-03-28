/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <string.h>

#include "gjoll.h"
#include "buf.h"

#include "ordo/misc/endianness.h"


int gjoll_init(gjoll_loop_t *gloop) {
    gloop->loop = malloc(sizeof(uv_loop_t));
    if(gloop->loop == NULL) {
        return -1;
    }
    return uv_loop_init(gloop->loop);
}

void gjoll_delete(gjoll_loop_t *gloop) {
    while(uv_run(gloop->loop, UV_RUN_NOWAIT));
    uv_loop_close(gloop->loop);
    free(gloop->loop);
    gloop->loop = NULL;
}


int gjoll_run_once(gjoll_loop_t gloop) {
    return uv_run(gloop.loop, UV_RUN_ONCE);
}

int gjoll_run(gjoll_loop_t gloop) {
    return uv_run(gloop.loop, UV_RUN_DEFAULT);
}

static void gjoll__alloc_cb(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf) {
    /*
     * NOTE: maybe create a static buffer for eatch gjoll_connection_t to
     * limit allocation.
     */

    char *buff;
    gjoll_connection_t *conn = (gjoll_connection_t *)handle->data;
    if(conn->readlen >= 0) {
        suggested_size = conn->readlen;
    }
    buff = malloc(suggested_size);
    if(buff != NULL) {
        memset(buff, 0, suggested_size);
        buf->base = buff;
        buf->len = suggested_size;
    }
}

int gjoll_listener_init(gjoll_loop_t gloop,
                        gjoll_listener_t *listener) {
    listener->server.data = NULL;
    listener->gloop = gloop;
    return uv_tcp_init(gloop.loop, &(listener->server));
}

static void gjoll__l_close_cb(uv_handle_t *handle) {
    gjoll_listener_t *l = (gjoll_listener_t *)handle->data;
    if(l->close_cb != NULL) {
        l->close_cb(l);
    }
}

void gjoll_listener_close(gjoll_listener_t *listener,
                          gjoll_l_close_cb close_cb) {
    listener->close_cb = close_cb;
    uv_close((uv_handle_t *)&(listener->server), gjoll__l_close_cb);
}

int gjoll_listener_bind(gjoll_listener_t *listener,
                        const struct sockaddr *addr) {
    return uv_tcp_bind(&(listener->server), addr, 0);
}

static void gjoll__close_tcp(uv_handle_t *handle) {
    free(handle);
}

static void gjoll__accept_cb(uv_stream_t *server, int status) {
    gjoll_listener_t *listener = (gjoll_listener_t *)server->data;
    uv_tcp_t *client;
    if(status < 0)
        return;

    if(listener->accept_cb(listener)) {
        if(!(client = malloc(sizeof(uv_tcp_t))))
            return;
        uv_tcp_init(listener->gloop.loop, client);
        if(!uv_accept(server, (uv_stream_t *)client)) {
            uv_close((uv_handle_t *)client, gjoll__close_tcp);
        }
    }
}

int gjoll_listener_listen(gjoll_listener_t *listener,
                          gjoll_accept_cb accept_cb) {
    listener->accept_cb = accept_cb;
    listener->server.data = listener;
    if(uv_listen((uv_stream_t *) &(listener->server), 128,
                 gjoll__accept_cb)) {
        return -1;
    }
    return 0;
}

static void gjoll__recv_cb(uv_stream_t *client, ssize_t nread,
                           const uv_buf_t* buf) {
    gjoll_connection_t *conn = (gjoll_connection_t *)client->data;
    gjoll_buf_t gbuf = uv_to_gjoll(*buf);

    if(nread < 0) {
        if(nread == UV_ENOBUFS) {
            goto skip;
        } else {
            goto err;
        }
    }
    gbuf.len = nread;

    if(conn->recv_cb != NULL) {
        conn->recv_cb(conn, gbuf);
    }

    free(buf->base);
    return;

skip:
    if(buf->base != NULL) free(buf->base);
    return;

err:
    if(buf->base != NULL) free(buf->base);
    gjoll_connection_close(conn);
    return;
}

typedef struct {
    uv_connect_t req;
    gjoll_connection_t *conn;
    gjoll_connect_cb connect_cb;
} gjoll__connect_t;

static void gjoll__connect_cb(uv_connect_t *req, int status) {
    gjoll__connect_t *gct = (gjoll__connect_t *)req->data;
    gct->connect_cb(gct->conn, status);
    free(gct);
}

int gjoll_accept(gjoll_listener_t *listener,
                 gjoll_connection_t *conn,
                 gjoll_close_cb close_cb) {
    memset(conn, 0, sizeof(gjoll_connection_t));
    conn->gloop = listener->gloop;
    conn->close_cb = close_cb;
    conn->type = GJOLL_SERVER;
    conn->readlen = -1;

    uv_tcp_init(listener->gloop.loop, &(conn->client));
    conn->client.data = conn;
    if(uv_accept((uv_stream_t *)&(listener->server),
                 (uv_stream_t *)&(conn->client))) {
        return -1;
    }

    return 0;
}

int gjoll_connect(gjoll_loop_t gloop,
                  gjoll_connection_t *conn,
                  const struct sockaddr *addr,
                  gjoll_connect_cb connect_cb,
                  gjoll_close_cb close_cb) {
    gjoll__connect_t *gct = NULL;

    memset(conn, 0, sizeof(gjoll_connection_t));
    conn->gloop = gloop;
    conn->type = GJOLL_CLIENT;
    conn->close_cb = close_cb;
    conn->readlen = -1;
    uv_tcp_init(gloop.loop, &(conn->client));
    conn->client.data = conn;

    gct = malloc(sizeof(gjoll__connect_t));
    if(gct == NULL)
        return -1;

    gct->req.data = gct;
    gct->connect_cb = connect_cb;
    gct->conn = conn;

    return uv_tcp_connect(&(gct->req), (uv_tcp_t *)&(conn->client), addr,
                          gjoll__connect_cb);
}

int gjoll_connection_init(gjoll_connection_t *conn,
                          gjoll_recv_cb recv_cb) {
    conn->recv_cb = recv_cb;
    return uv_read_start((uv_stream_t *)&(conn->client), gjoll__alloc_cb,
                         gjoll__recv_cb);
}

void gjoll_connection_readlen(gjoll_connection_t *conn, int readlen) {
    conn->readlen = readlen;
}

int gjoll_connection_getpeername(gjoll_connection_t *conn,
                                 struct sockaddr *name,
                                 int *namelen) {
    return uv_tcp_getpeername(&(conn->client), name, namelen);
}

static void gjoll__close_cb(uv_handle_t *handle) {
    gjoll_connection_t *conn = (gjoll_connection_t *)handle->data;
    conn->close_cb(conn);
}

void gjoll_connection_close(gjoll_connection_t *conn) {
    if(!uv_is_closing((uv_handle_t *)&(conn->client))) {
        uv_close((uv_handle_t *)&(conn->client), gjoll__close_cb);
    }
}

void gjoll_connection_clean(gjoll_connection_t *conn) {
}

int gjoll_connection_closed(gjoll_connection_t *conn) {
    return uv_is_closing((uv_handle_t *)&(conn->client));
}

static void gjoll__send_cb(uv_write_t *req, int status) {
    gjoll_send_t *greq = (gjoll_send_t *)req->data;

    if(greq->cb != NULL) {
        greq->cb(greq, status);
    }
}

int gjoll_send(gjoll_send_t *greq, gjoll_connection_t *conn, void *data,
               size_t len, gjoll_send_cb cb) {
    gjoll_buf_t buffer;

    buffer.base = data;
    buffer.len = len;

    greq->cb = cb;
    greq->req.data = greq;
    greq->buffer = gjoll_to_uv(buffer);

    return uv_write(&(greq->req), (uv_stream_t *)&(conn->client),
            &(greq->buffer), 1, gjoll__send_cb);
}
