/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include "gjoll.h"
#include "log.h"

#include "utlist.h"


static void close_cb(gjoll_connection_t *conn) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_log("local connection closed\n");
    gjoll_connection_clean(conn);
    if(gjoll_sconnection_closed(&(cc->gconn))) {
        DL_DELETE(cc->d->ccs, cc);
        free(cc);
    } else {
        gjoll_sconnection_close(&(cc->gconn));
    }
}

static void sclose_cb(gjoll_sconnection_t *conn) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_log("connection closed\n");
    gjoll_sconnection_clean(conn);
    if(gjoll_connection_closed(&(cc->lconn))) {
        DL_DELETE(cc->d->ccs, cc);
        free(cc);
    } else {
        gjoll_connection_close(&(cc->lconn));
    }
}

static void sclose_cb2(gjoll_sconnection_t *conn) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_log("connection closed\n");
    gjoll_sconnection_clean(conn);
    DL_DELETE(cc->d->ccs, cc);
    free(cc);
}

static void close_l_cb(gjoll_listener_t *l) {
    gjoll__listener_context_t *cl = (gjoll__listener_context_t *)l->data;
    free(cl);
}

static void send_cb(gjoll_send_t *req, int status) {
    free(req);
}

static void ssend_cb(gjoll_ssend_t *req, int status) {
    free(req);
}

static void recv_cb(gjoll_connection_t *conn,
                    gjoll_buf_t buf) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_ssend_t *req = malloc(sizeof(gjoll_ssend_t));
    if(req != NULL) {
        if(gjoll_ssend(req, &(cc->gconn), buf.base, buf.len, ssend_cb)) {
            /* Fail to send */
            free(req);
        }
    }
    //free(buf.base);
}

static void srecv_cb(gjoll_sconnection_t *conn,
                     gjoll_buf_t buf) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_send_t *req = malloc(sizeof(gjoll_send_t));
    if(req != NULL) {
        if(gjoll_send(req, &(cc->lconn), buf.base, buf.len, send_cb)) {
            /* Fail to send */
            free(req);
        }
    }
    free(buf.base);
}

static void connect_cb(gjoll_connection_t *conn, int status) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    if(status) {
        gjoll_connection_close(conn);
        return;
    }
    /* Reactivate reading */
    gjoll_sconnection_readlen(&(cc->gconn), -1);
    if(gjoll_connection_init(conn, recv_cb)) {
        gjoll_connection_close(conn);
    }
}

static void sconnect_cb(gjoll_sconnection_t *conn, int status) {
    gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
    gjoll_friend_t *f = NULL;

    if(status) {
        gjoll_sconnection_close(conn);
        return;
    }

    f = gjoll_daemon_get_friend(cc->d, cc->gconn.header.dst);
    if(f == NULL) {
        gjoll_sconnection_close(conn);
    } else {
        if(gjoll_sconnection_init(conn, f->shared, f->shared_len, srecv_cb)) {
            gjoll_sconnection_close(conn);
        }
        if(gjoll_connection_init(&(cc->lconn), recv_cb)) {
            gjoll_connection_close(&(cc->lconn));
        }
    }
}

static int header_cb(gjoll_sconnection_t *conn, gjoll_header_t header) {
    gjoll_log("header.id: %d\n", header.id);
    gjoll_log("header.src: %ld\n", header.src);
    gjoll_log("header.dst: %ld\n", header.dst);

    if(conn->conn.type == GJOLL_SERVER) {
        gjoll__conn_context_t *cc = (gjoll__conn_context_t *)conn->data;
        gjoll_rule_t *rule = gjoll_daemon_get_rule(cc->d, header.id);

        if(rule == NULL) {
            return -1;
        }
        /* Stop reading during local connection */
        gjoll_sconnection_readlen(conn, 0);
        if(gjoll_connect(cc->d->gloop, &(cc->lconn),
                         (const struct sockaddr *) &(rule->laddr), connect_cb,
                         close_cb)) {
            return -1;
        }
        cc->lconn.data = cc;
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
    if(gjoll_sconnection_init(conn, f->shared, f->shared_len, srecv_cb)) {
        return -1;
    }
    return 0;
}

static int accept_cb(gjoll_listener_t *listener) {
    gjoll_header_t header;
    gjoll__listener_context_t *lc = (gjoll__listener_context_t *)listener->data;
    gjoll__conn_context_t *cc = malloc(sizeof(gjoll__conn_context_t));
    if(cc == NULL) {
        return -1;
    }

    if(gjoll_accept(listener, &(cc->lconn), close_cb)) {
        free(cc);
        return -1;
    }

    header.src = lc->d->id;
    header.dst = lc->node;
    header.id = lc->service;

    if(gjoll_sconnect(lc->d->gloop, &(cc->gconn),
                      (const struct sockaddr *) &(lc->addr), header,
                      sconnect_cb, header_cb, sclose_cb)) {
        gjoll_connection_close(&(cc->lconn));
        return -1;
    }

    cc->d = lc->d;
    cc->gconn.data = cc;
    cc->lconn.data = cc;

    DL_APPEND(cc->d->ccs, cc);
    return 0;
}

static int saccept_cb(gjoll_slistener_t *listener) {
    gjoll__conn_context_t *cc = malloc(sizeof(gjoll__conn_context_t));
    if(cc == NULL) {
        return -1;
    }
    if(gjoll_saccept(listener, &(cc->gconn), session_cb, header_cb,
                     sclose_cb)) {
        free(cc);
        return -1;
    }

    cc->d = listener->data;
    cc->gconn.data = cc;
    cc->lconn.data = cc;

    DL_APPEND(cc->d->ccs, cc);
    return 0;
}

int gjoll_daemon_init(gjoll_loop_t loop, gjoll_daemon_t *d, gjoll_node_t id,
                      const struct sockaddr_in addr) {
    d->rules = NULL;
    d->friends = NULL;
    d->ccs = NULL;
    d->lcs = NULL;
    d->gloop = loop;
    d->id = id;
    d->listener.data = d;

    if(gjoll_slistener_init(loop, &(d->listener), id)) {
        gjoll_logerr("gjoll_slistener_init failed\n");
        return -1;
    }

    if(gjoll_slistener_bind(&(d->listener),
                            (const struct sockaddr *) &addr)) {
        gjoll_logerr("gjoll_bind_listener failed\n");
        return -2;
    }

    if(gjoll_slistener_listen(&(d->listener), saccept_cb)) {
        gjoll_logerr("gjoll_ready_listener failed\n");
        return -3;
    }

    return 0;
}

void gjoll_daemon_clean(gjoll_daemon_t *d) {
    gjoll_friend_t *fcurrent, *ftmp;
    gjoll_rule_t *rcurrent, *rtmp;
    gjoll__conn_context_t *ccurrent, *ctmp;
    gjoll__listener_context_t *lcurrent, *ltmp;

    gjoll_slistener_close(&(d->listener), NULL);

    DL_FOREACH_SAFE(d->lcs, lcurrent, ltmp) {
        DL_DELETE(d->lcs, lcurrent);
        /* close_l_cb will free */
        gjoll_listener_close(&(lcurrent->listener), close_l_cb);
    }

    DL_FOREACH_SAFE(d->ccs, ccurrent, ctmp) {
        DL_DELETE(d->ccs, ccurrent);
        /* sclose_cb will clean and free */
        gjoll_sconnection_close(&(ccurrent->gconn));
    }

    HASH_ITER(hh, d->friends, fcurrent, ftmp) {
        HASH_DEL(d->friends, fcurrent);
        free(fcurrent);
    }

    HASH_ITER(hh, d->rules, rcurrent, rtmp) {
        HASH_DEL(d->rules, rcurrent);
        free(rcurrent);
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

gjoll_rule_t *gjoll_daemon_add_rule(gjoll_daemon_t *d,
                                    gjoll_service_t service,
                                    const struct sockaddr_in laddr) {
    gjoll_rule_t *f = malloc(sizeof(gjoll_rule_t));
    if(f == NULL) {
        return NULL;
    }
    f->id = service;
    f->laddr = laddr;

    HASH_ADD(hh, d->rules, id, sizeof(gjoll_service_t), f);
    return f;
}

gjoll_rule_t *gjoll_daemon_get_rule(gjoll_daemon_t *d, gjoll_service_t id) {
    gjoll_rule_t *f = NULL;
    HASH_FIND(hh, d->rules, &id, sizeof(gjoll_service_t), f);
    return f;
}

/* Deprecated */
int gjoll_daemon_connect(gjoll_daemon_t *d, gjoll_node_t dst,
                         gjoll_service_t service,
                         const struct sockaddr_in addr) {
    gjoll_header_t header;
    gjoll__conn_context_t *cc = malloc(sizeof(gjoll__conn_context_t));
    if(cc == NULL) {
        return -1;
    }
    header.src = d->id;
    header.dst = dst;
    header.id = service;
    if(gjoll_sconnect(d->gloop, &(cc->gconn), (const struct sockaddr *) &addr,
                      header, sconnect_cb, header_cb, sclose_cb2)) {
        free(cc);
        return -1;
    }
    cc->d = d;
    cc->gconn.data = cc;
    DL_APPEND(d->ccs, cc);
    return 0;
}

int gjoll_daemon_add_route(gjoll_daemon_t *d, gjoll_node_t node,
                           gjoll_service_t service,
                           const struct sockaddr_in addr,
                           const struct sockaddr_in laddr) {
    gjoll__listener_context_t *lc = malloc(sizeof(gjoll__listener_context_t));

    if(gjoll_listener_init(d->gloop, &(lc->listener))) {
        free(lc);
        return -1;
    }
    if(gjoll_listener_bind(&(lc->listener),
                           (const struct sockaddr *) &laddr)) {
        free(lc);
        return -2;
    }
    if(gjoll_listener_listen(&(lc->listener), accept_cb)) {
        free(lc);
        return -3;
    }

    lc->d = d;
    lc->addr = addr;
    lc->node = node;
    lc->service = service;
    lc->listener.data = lc;
    DL_APPEND(d->lcs, lc);
    return 0;
}
