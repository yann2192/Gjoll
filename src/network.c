/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <string.h>

#include "gjoll.h"


int gjoll_init(gjoll_loop_t *gloop) {
    gloop->loop = uv_loop_new();
    return gloop->loop == NULL ? -1:0;
}

void gjoll_delete(gjoll_loop_t *gloop) {
    uv_loop_delete(gloop->loop);
    gloop->loop = NULL;
}

int gjoll_run(gjoll_loop_t gloop) {
    return uv_run(gloop.loop, UV_RUN_DEFAULT);
}

void gjoll__alloc_cb(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf) {
    char *buff = malloc(suggested_size);
    if(buff != NULL) {
        memset(buff, 0, suggested_size);
        buf->base = buff;
        buf->len = suggested_size;
    }
}

void gjoll__recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t* buf,
                    const struct sockaddr *addr, unsigned flag) {
    if(nread < 0) {
        /* error */
        return;
    }
    /* buf->len = nread; */
    gjoll_connection_t *gconn = (gjoll_connection_t *)handle->data;
    /* NOTE: maybe launch this in threadpool */
    gconn->gs_cb(gconn, buf->base, addr);
    /* TODO: lot of work here */
}

int gjoll_new_connection(gjoll_loop_t gloop,
                         gjoll_connection_t *gconn) {
    gconn->sock.data = NULL;
    return uv_udp_init(gloop.loop, &(gconn->sock));
}

void gjoll_close_connection(gjoll_connection_t *gconn) {
    uv_close((uv_handle_t *)&(gconn->sock), NULL);
}

int gjoll_bind_connection(gjoll_connection_t *gconn,
                          const struct sockaddr *addr,
                          int namelen) {
    return uv_udp_bind(&(gconn->sock), addr, namelen);
}

int gjoll_up_connection(gjoll_connection_t *gconn,
                           gjoll_session_cb gs_cb) {
    gconn->gs_cb = gs_cb;
    gconn->sock.data = gconn;
    if(uv_udp_recv_start(&(gconn->sock), gjoll__alloc_cb, gjoll__recv_cb)) {
        return -2;
    }
    return 0;
}

int gjoll_new_session(gjoll_connection_t *gconn,
                      gjoll_session_t *session,
                      const struct sockaddr *addr,
                      const void *identifier,
                      const void *shared,
                      const size_t shared_len,
                      gjoll_recv_cb recv_cb) {
    session->conn = gconn;
    session->addr = addr;
    session->identifier = identifier; /* NOTE: need copy ? */
    session->shared = NULL; /* NOTE: need process shared now ?
                               May be in the loop thread ... */
    session->recv_cb = recv_cb;
    return 0;
}

int gjoll_send(const gjoll_session_t *session, void *data, size_t len) {
    uv_udp_send_t req;
    uv_buf_t *buf = malloc(sizeof(uv_buf_t));
    buf->base = data;
    buf->len = len;
    /* NOTE: add send_cb to release memory */
    return uv_udp_send(&req, &(session->conn->sock), buf, 1, session->addr,
                       NULL);
}
