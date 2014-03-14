/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "gjoll.h"
#include "log.h"

#include "utlist.h"

static void close_cb(gjoll_sconnection_t *conn) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_log("connection closed\n");
    gjoll_sconnection_clean(conn);
    DL_DELETE(cc->d->ccs, cc);
    free(cc);
}

static void send_cb(gjoll_ssend_t *req, int status) {
    free(req);
}

static void recv_cb(gjoll_sconnection_t *conn,
                    gjoll_buf_t buf) {
    gjoll_ssend_t *req;
    char str[buf.len+1];
    memcpy(str, buf.base, buf.len);
    str[buf.len] = 0;
    gjoll_log("data: %s\n", str);
    free(buf.base);
    if(conn->conn.type == GJOLL_SERVER) {
        req = malloc(sizeof(gjoll_ssend_t));
        if(req != NULL) {
            gjoll_ssend(req, conn, "Hello client!", 13, send_cb);
        }
    }
}

static int header_cb(gjoll_sconnection_t *conn, gjoll_header_t header) {
    gjoll_ssend_t *req;
    gjoll_log("header.id: %d\n", header.id);
    gjoll_log("header.src: %ld\n", header.src);
    gjoll_log("header.dst: %ld\n", header.dst);
    if(conn->conn.type == GJOLL_CLIENT) {
        req = malloc(sizeof(gjoll_ssend_t));
        if(req != NULL) {
            gjoll_ssend(req, conn, "Hello server!", 13, send_cb);
        }
    }
    return 0;
}

static int session_cb(gjoll_sconnection_t *conn, gjoll_node_t src) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_friend_t *f = gjoll_daemon_get_friend(cc->d, src);
    gjoll_log("src: %ld\n", src);
    if(f == NULL) {
        return -1;
    }
    if(gjoll_sconnection_init(conn, f->shared, f->shared_len, recv_cb)) {
        free(conn);
        return -1;
    }
    return 0;
}

static int accept_cb(gjoll_slistener_t *listener) {
    gjoll__conn_context_t *cc = malloc(sizeof(gjoll__conn_context_t));
    if(cc == NULL) {
        return -1;
    }
    if(gjoll_saccept(listener, &(cc->conn), session_cb, header_cb, close_cb)) {
        free(cc);
        return -1;
    }
    cc->d = listener->data;
    cc->conn.data = cc;
    DL_APPEND(cc->d->ccs, cc);
    return 0;
}

static void connect_cb(gjoll_sconnection_t *conn, int status) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_friend_t *f = gjoll_daemon_get_friend(cc->d, cc->conn.header.dst);
    if(f == NULL) {
        gjoll_sconnection_close(conn);
    } else {
        gjoll_sconnection_init(conn, f->shared, f->shared_len, recv_cb);
    }
}

int gjoll_daemon_init(gjoll_loop_t loop, gjoll_daemon_t *d, gjoll_node_t id,
                      const struct sockaddr *addr) {
    d->rules = NULL;
    d->friends = NULL;
    d->ccs = NULL;
    d->gloop = loop;
    d->id = id;
    d->listener.data = d;

    if(gjoll_slistener_init(loop, &(d->listener), id)) {
        gjoll_logerr("gjoll_slistener_init failed\n");
        return -1;
    }

    if(gjoll_slistener_bind(&(d->listener), addr)) {
        gjoll_logerr("gjoll_bind_listener failed\n");
        return -2;
    }

    if(gjoll_slistener_listen(&(d->listener), accept_cb)) {
        gjoll_logerr("gjoll_ready_listener failed\n");
        return -3;
    }

    return 0;
}

void gjoll_daemon_clean(gjoll_daemon_t *d) {
    gjoll_friend_t *fcurrent, *ftmp;
    gjoll__conn_context_t *ccurrent, *ctmp;

    gjoll_slistener_close(&(d->listener), NULL);

    DL_FOREACH_SAFE(d->ccs, ccurrent, ctmp) {
        //DL_DELETE(d->ccs, ccurrent);
        /* close_cb will clean */
        gjoll_sconnection_close(&(ccurrent->conn));
        //free(ccurrent);
    }

    HASH_ITER(hh, d->friends, fcurrent, ftmp) {
        HASH_DEL(d->friends, fcurrent);
        free(fcurrent);
    }
}

gjoll_friend_t *gjoll_daemon_add_friend(gjoll_daemon_t *d, gjoll_node_t id,
                                        const void *shared,
                                        const size_t shared_len) {
    gjoll_friend_t *f = malloc(sizeof(gjoll_friend_t));
    if(f == NULL) {
        return NULL;
    }
    f->id = id;
    f->shared = shared;
    f->shared_len = shared_len;

    HASH_ADD(hh, d->friends, id, sizeof(gjoll_node_t), f);
    return f;
}

gjoll_friend_t *gjoll_daemon_get_friend(gjoll_daemon_t *d, gjoll_node_t id) {
    gjoll_friend_t *f = NULL;
    HASH_FIND(hh, d->friends, &id, sizeof(gjoll_node_t), f);
    return f;
}

int gjoll_daemon_connect(gjoll_daemon_t *d, gjoll_node_t dst,
                         gjoll_service_t service,
                         const struct sockaddr *addr) {
    gjoll_header_t header;
    gjoll__conn_context_t *cc = malloc(sizeof(gjoll__conn_context_t));
    if(cc == NULL) {
        return -1;
    }
    header.src = d->id;
    header.dst = dst;
    header.id = service;
    if(gjoll_sconnect(d->gloop, &(cc->conn), addr, header, connect_cb,
                      header_cb, close_cb)) {
        free(cc);
        return -1;
    }
    cc->d = d;
    cc->conn.data = cc;
    DL_APPEND(d->ccs, cc);
    return 0;
}
