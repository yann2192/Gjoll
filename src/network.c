/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <string.h>

#include "gjoll.h"
#include "crypto.h"
#include "buf.h"

#include "ordo/misc/endianness.h"


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
    gjoll_header_t header;
    gjoll_buf_t buf;
    const struct sockaddr *addr;
    gjoll_session_t *session;
    int status;
} gjoll__work_session_t;

/* Launch in threadpool */
void gjoll__pre_session_cb(uv_work_t *req) {
    void *ctx;
    gjoll_buf_t plaintext;
    gjoll_header_t header;
    gjoll_node_t src;
    gjoll__work_session_t *ws = (gjoll__work_session_t *)req->data;

    src = *(gjoll_node_t *)(((char *)ws->buf.base)+8);
    src = fmbe64(src);
    ws->session = ws->gconn->gs_cb(ws->gconn, src, ws->addr);
    if(ws->session != NULL) {
        /* TODO: merge decrypt_header and decrypt_data */
        if(gjoll_decrypt_header(ws->session->secret,
                                ws->buf,
                                &header,
                                &ctx)) {
            /* error */
            goto err;
        }
        if(gjoll_decrypt_data(ws->session->secret,
                              ws->buf,
                              &plaintext,
                              ctx)) {
            /* error */
            goto err;
        }
        free(ws->buf.base);
        ws->buf = plaintext;
        ws->header = header;
    }
    return;
err:
    free(ws->buf.base);
    ws->status = -1;
}

void gjoll__post_session_cb(uv_work_t *req, int status) {
    gjoll__work_session_t *ws = (gjoll__work_session_t *)req->data;
    if(!ws->status) {
        if(ws->session != NULL) {
            ws->session->recv_cb(ws->session,
                                ws->header,
                                ws->buf);
        } else {
            free(ws->buf.base);
        }
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
    ws->buf = uv_to_gjoll(*buf); /* buf is realease after this, so copie it */
    ws->buf.len = nread;
    ws->addr = addr;
    ws->req.data = ws;
    ws->session = NULL;
    ws->status = 0;
    uv_queue_work(ws->gconn->gloop.loop, &(ws->req),
                  gjoll__pre_session_cb, gjoll__post_session_cb);
}

int gjoll_new_connection(gjoll_loop_t gloop,
                         gjoll_node_t id,
                         gjoll_connection_t *gconn) {
    gconn->sock.data = NULL;
    gconn->gloop = gloop;
    gconn->identifier = id;
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
                      const void *shared,
                      const size_t shared_len,
                      gjoll_recv_cb recv_cb) {
    session->conn = gconn;
    session->addr = addr;
    session->identifier = identifier;
    if(gjoll_preprocess_secret(shared, shared_len, &(session->secret))) {
        return -1;
    }
    session->recv_cb = recv_cb;
    return 0;
}

void gjoll__send_cb(uv_udp_send_t *req, int status) {
    gjoll_send_t *greq = (gjoll_send_t *)req->data;
    if(status == 0)
        free(greq->ciphertext.base);
    if(greq->cb != NULL) {
        greq->cb(greq, greq->status);
    }
}

typedef struct {
    uv_work_t req;
    gjoll_send_t *greq;
    const gjoll_session_t *session;
    gjoll_service_t service;
} gjoll__work_encrypt_t;

/* Launch in threadpool */
void gjoll__pre_encrypt_cb(uv_work_t *req) {
    gjoll_header_t header;
    gjoll_buf_t ciphertext;
    gjoll__work_encrypt_t *we = (gjoll__work_encrypt_t *)req->data;
    header.src = we->session->conn->identifier;
    header.dst = we->session->identifier;
    header.id = we->service;
    if(gjoll_encrypt_packet(we->session->secret, header, we->greq->buf,
                            &ciphertext, NULL)) {
        /* error */
        we->greq->status = -1;
    }
    we->greq->ciphertext = gjoll_to_uv(ciphertext);
}

void gjoll__post_encrypt_cb(uv_work_t *req, int status) {
    gjoll__work_encrypt_t *we = (gjoll__work_encrypt_t *)req->data;
    if(we->greq->status) {
        we->greq->cb(we->greq, we->greq->status);
    } else {
        uv_udp_send(&(we->greq->req), &(we->session->conn->sock),
                    &(we->greq->ciphertext), 1,
                    we->session->addr, gjoll__send_cb);
    }
    free(we);
}

int gjoll_send(gjoll_send_t *req, const gjoll_session_t *session,
               const gjoll_service_t service, void *data, size_t len,
               gjoll_send_cb cb) {
    gjoll__work_encrypt_t *we = malloc(sizeof(gjoll__work_encrypt_t));
    if(we == NULL)
        return -1;
    req->buf.base = data;
    req->buf.len = len;
    req->cb = cb;
    req->status = 0;
    req->req.data = req;
    we->greq = req;
    we->session = session;
    we->service = service;
    we->req.data = we;
    uv_queue_work(session->conn->gloop.loop, &(we->req),
                  gjoll__pre_encrypt_cb,
                  gjoll__post_encrypt_cb);
    return 0;
}
