/**
  Copyright (C) 2013 Yann GUIBET <yannguibet@gmail.com>
  and Thomas BENETEAU <thomas.beneteau@yahoo.fr>.

  See LICENSE for details.
 **/

#include <string.h>

#include "gjoll.h"
#include "crypto.h"
#include "parser.h"
#include "buf.h"

#include "ordo/misc/endianness.h"


int gjoll_slistener_init(gjoll_loop_t gloop,
                         gjoll_slistener_t *listener,
                         gjoll_node_t identifier) {
    listener->identifier = identifier;
    listener->listener.data = listener;
    return gjoll_listener_init(gloop, &(listener->listener));
}

static void gjoll__sl_close_cb(gjoll_listener_t *l) {
    gjoll_slistener_t *sl = (gjoll_slistener_t *)l->data;
    if(sl->close_cb != NULL) {
        sl->close_cb(sl);
    }
}

void gjoll_slistener_close(gjoll_slistener_t *listener,
                           gjoll_sl_close_cb close_cb) {
    listener->close_cb = close_cb;
    gjoll_listener_close(&(listener->listener), gjoll__sl_close_cb);
}

int gjoll_slistener_bind(gjoll_slistener_t *listener,
                         const struct sockaddr *addr) {
    return gjoll_listener_bind(&(listener->listener), addr);
}

static int gjoll__accept_cb(gjoll_listener_t *l) {
    gjoll_slistener_t *listener = (gjoll_slistener_t *)l->data;

    if(listener->accept_cb != NULL) {
        return listener->accept_cb(listener);
    }
    return -1;
}

int gjoll_slistener_listen(gjoll_slistener_t *listener,
                           gjoll_saccept_cb accept_cb) {
    listener->accept_cb = accept_cb;
    return gjoll_listener_listen(&(listener->listener), gjoll__accept_cb);
}

static void gjoll__send_header_cb(gjoll_send_t *req, int status) {
    free(req->data);
    free(req);
}

static int gjoll__send_header(gjoll_sconnection_t *conn) {
    gjoll_buf_t packet;
    gjoll_send_t *greq;

    if(!(greq = malloc(sizeof(gjoll_send_t))))
        return -1;

    if(gjoll_encrypt_header(&(conn->cout), conn->secret, conn->header, &packet,
                            NULL))
        goto err;

    greq->data = packet.base;
    return gjoll_send(greq, &(conn->conn), packet.base, packet.len,
                      gjoll__send_header_cb);

err:
    if(greq) free(greq);
    return -1;
}

static void gjoll__recv_cb(gjoll_connection_t *conn, gjoll_buf_t buf) {
    size_t i = 0;
    int nread = buf.len;
    gjoll_len_t len;
    gjoll_sconnection_t *sconn = (gjoll_sconnection_t *)conn->data;
    gjoll_buf_t gbuf;
    gjoll_buf_t hbuf, data;
    gjoll_header_t header;
    gjoll_node_t src;
    gjoll__parse_action_t action;

    gbuf.base = buf.base;
    gbuf.len = buf.len;
    hbuf.base = sconn->parser.hbuf;
    hbuf.len = GJOLL_HEADER_LENGTH;

    if(nread < 0) goto err;

    while(i < (size_t) nread) {
        i += gjoll__parser_parse(&(sconn->parser), &action, gbuf);

        switch(action) {
            case GJOLL_HEADER_ACTION:
                /* Remove reading limit */
                gjoll_connection_readlen(conn, -1);

                src = *(gjoll_node_t *)OFFSET(sconn->parser.hbuf, 8);
                src = fmbe64(src);
                if(conn->type == GJOLL_SERVER && sconn->session_cb != NULL) {
                    if(sconn->session_cb(sconn, src)) {
                        goto err;
                    }
                }
                if(gjoll_decrypt_header(&(sconn->cin), sconn->secret,
                                        hbuf, &header)) {
                    goto err;
                }

                if(sconn->header_cb != NULL && sconn->header_cb(sconn, header))
                    goto err;

                if(conn->type == GJOLL_SERVER) {
                    sconn->header.id = header.id;
                    sconn->header.src = header.dst;
                    sconn->header.dst = header.src;
                }
                if(conn->type == GJOLL_SERVER && gjoll__send_header(sconn))
                    goto err;
                action = GJOLL_NONE_ACTION;
                break;
            case GJOLL_SIZE_ACTION:
                if(gjoll_decrypt_size(&(sconn->cin), sconn->parser.lenbuff,
                                      &len)) {
                    goto err;
                }
                if(gjoll__parser_alloc_data(&(sconn->parser), len))
                    goto err;
                action = GJOLL_NONE_ACTION;
                break;
            case GJOLL_DATA_ACTION:
                memset(&data, 0, sizeof(gjoll_buf_t));
                if(gjoll_decrypt_data(&(sconn->cin), len,
                                      sconn->parser.data, &data)) {
                    goto err;
                }
                gjoll__parser_free_data(&(sconn->parser));
                if(sconn->recv_cb != NULL) {
                    sconn->recv_cb(sconn, data);
                } else {
                    free(data.base);
                }
                action = GJOLL_NONE_ACTION;
                break;
            default:
                break;
        }

        gbuf.base = OFFSET(buf.base, i);
        gbuf.len -= i;
    }

    return;

err:
    gjoll__parser_free_data(&(sconn->parser));
    gjoll_sconnection_close(sconn);
    return;
}

typedef struct {
    uv_connect_t req;
    gjoll_connection_t *conn;
    gjoll_connect_cb connect_cb;
} gjoll__connect_t;

static void gjoll__close_cb(gjoll_connection_t *conn) {
    gjoll_sconnection_t *sconn = (gjoll_sconnection_t *)conn->data;
    if(sconn->close_cb) {
        sconn->close_cb(sconn);
    }
}

static void gjoll__connect_cb(gjoll_connection_t *conn, int status) {
    gjoll_sconnection_t *sconn = (gjoll_sconnection_t *)conn->data;
    if(sconn->connect_cb != NULL) {
        sconn->connect_cb(sconn, status);
    }
}

int gjoll_saccept(gjoll_slistener_t *listener,
                  gjoll_sconnection_t *conn,
                  gjoll_session_cb session_cb,
                  gjoll_header_cb header_cb,
                  gjoll_sclose_cb close_cb) {
    int res;
    memset(conn, 0, sizeof(gjoll_sconnection_t));
    conn->header.src = listener->identifier;
    conn->session_cb = session_cb;
    conn->header_cb = header_cb;
    conn->close_cb = close_cb;

    gjoll__parser_init(&(conn->parser));

    res = gjoll_accept(&(listener->listener), &(conn->conn), gjoll__close_cb);

    conn->conn.data = conn;
    if(!res) {
        gjoll_connection_readlen(&(conn->conn), GJOLL_HEADER_LENGTH);
        return gjoll_connection_init(&(conn->conn), gjoll__recv_cb);
    }
    return res;
}

int gjoll_sconnect(gjoll_loop_t gloop,
                   gjoll_sconnection_t *conn,
                   const struct sockaddr *addr,
                   gjoll_header_t header,
                   gjoll_sconnect_cb connect_cb,
                   gjoll_header_cb header_cb,
                   gjoll_sclose_cb close_cb) {
    int res;
    memset(conn, 0, sizeof(gjoll_sconnection_t));
    conn->header = header;
    conn->header_cb = header_cb;
    conn->close_cb = close_cb;
    conn->connect_cb = connect_cb;

    gjoll__parser_init(&(conn->parser));

    res = gjoll_connect(gloop, &(conn->conn), addr, gjoll__connect_cb,
                        gjoll__close_cb);

    conn->conn.data = conn;
    if(!res) {
        gjoll_connection_readlen(&(conn->conn), GJOLL_HEADER_LENGTH);
        return gjoll_connection_init(&(conn->conn), gjoll__recv_cb);
    }
    return res;
}

int gjoll_sconnection_init(gjoll_sconnection_t *conn,
                           const void *shared,
                           const size_t shared_len,
                           gjoll_srecv_cb recv_cb) {
    conn->recv_cb = recv_cb;
    if(gjoll_preprocess_secret(shared, shared_len, &(conn->secret)))
        return -1;

    if(conn->conn.type == GJOLL_CLIENT) {
        return gjoll__send_header(conn);
    }
    return 0;
}

int gjoll_sconnection_getpeername(gjoll_sconnection_t *conn,
                                  struct sockaddr *name,
                                  int *namelen) {
    return gjoll_connection_getpeername(&(conn->conn), name, namelen);
}

void gjoll_sconnection_readlen(gjoll_sconnection_t *conn, int readlen) {
    gjoll_connection_readlen(&(conn->conn), readlen);
}

void gjoll_sconnection_close(gjoll_sconnection_t *conn) {
    gjoll_connection_close(&(conn->conn));
}

void gjoll_sconnection_clean(gjoll_sconnection_t *conn) {
    gjoll_crypto_clean(&(conn->cin));
    gjoll_crypto_clean(&(conn->cout));
    gjoll__parser_free_data(&(conn->parser));
    gjoll_connection_clean(&(conn->conn));
}

int gjoll_sconnection_closed(gjoll_sconnection_t *conn) {
    return gjoll_connection_closed(&(conn->conn));
}

static void gjoll__send_cb(gjoll_send_t *req, int status) {
    gjoll_ssend_t *sreq = (gjoll_ssend_t *)req->data;

    free(sreq->buffer.base);
    if(sreq->cb != NULL) {
        sreq->cb(sreq, status);
    }
}

int gjoll_ssend(gjoll_ssend_t *sreq,
                gjoll_sconnection_t *conn,
                void *data, size_t len, gjoll_ssend_cb cb) {
    gjoll_buf_t plaintext, ciphertext;

    plaintext.base = data;
    plaintext.len = len;

    if(gjoll_encrypt_data(&(conn->cout), plaintext, &ciphertext))
        return -1;

    sreq->buffer = ciphertext;
    sreq->req.data = sreq;
    sreq->cb = cb;

    return gjoll_send(&(sreq->req), &(conn->conn), ciphertext.base,
                      ciphertext.len, gjoll__send_cb);
}
