/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <string.h>

#include "gjoll.h"
#include "crypto.h"
#include "buf.h"


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

typedef struct {
    uv_work_t req;
    gjoll_connection_t *gconn;
    uv_buf_t buf;
    const struct sockaddr *addr;
    gjoll_session_t *session;
} gjoll__work_session_t;

/* Launch in threadpool */
void gjoll__pre_session_cb(uv_work_t *req) {
    gjoll__work_session_t *ws = (gjoll__work_session_t *)req->data;
    /* TODO: parse ws->buf to retrieve gjoll_node_t */
    /* TODO: parse ws->buf to retrieve gjoll_service_t */
    ws->session = ws->gconn->gs_cb(ws->gconn,
                                   (gjoll_node_t*) ws->buf.base,
                                   (gjoll_service_t*) ws->buf.base,
                                   ws->addr);
    /* TODO: decrypt here */
}

void gjoll__post_session_cb(uv_work_t *req, int status) {
    gjoll__work_session_t *ws = (gjoll__work_session_t *)req->data;
    if(ws->session != NULL) {
        ws->session->recv_cb(ws->session, uv_to_gjoll(ws->buf));
    } else {
        free(ws->buf.base);
    }
    free(ws);
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
    gjoll__work_session_t *ws;

    if(nread <= 0) {
        /* error */
        free(buf->base);
        return;
    }
    /* TODO: Reject packet if nread < GJOLL_HEADER_MIN_LENGTH */
    ws = malloc(sizeof(gjoll__work_session_t));
    if(ws == NULL) {
        /* error */
        free(buf->base);
        return;
    }
    ws->gconn = (gjoll_connection_t *)handle->data;
    ws->buf = *buf; /* buf is realease after this, so copie it */
    ws->buf.len = nread;
    ws->addr = addr;
    ws->req.data = ws;
    ws->session = NULL;
    uv_queue_work(ws->gconn->gloop.loop, &(ws->req),
                  gjoll__pre_session_cb, gjoll__post_session_cb);
}

int gjoll_new_connection(gjoll_loop_t gloop,
                         gjoll_connection_t *gconn) {
    gconn->sock.data = NULL;
    gconn->gloop = gloop;
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
                      gjoll_node_t identifier,
                      gjoll_service_t service_id,
                      const void *shared,
                      const size_t shared_len,
                      gjoll_recv_cb recv_cb) {
    session->conn = gconn;
    session->addr = addr;
    session->identifier = identifier;
    session->service_id = service_id;
    if(gjoll_preprocess_secret(shared, shared_len, &(session->secret))) {
        return -1;
    }
    session->recv_cb = recv_cb;
    return 0;
}

int gjoll_send(const gjoll_session_t *session, void *data, size_t len) {
    uv_udp_send_t req;
    uv_buf_t *buf = malloc(sizeof(uv_buf_t));
    if(buf == NULL) {
        return -1;
    }
    buf->base = data;
    buf->len = len;
    /* NOTE: add send_cb to release memory */
    /* TODO: encrypt in threadpool */
    return uv_udp_send(&req, &(session->conn->sock), buf, 1, session->addr,
                       NULL);
}
