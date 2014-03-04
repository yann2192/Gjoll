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


int gjoll_init(gjoll_loop_t *gloop) {
    gloop->loop = malloc(sizeof(uv_loop_t));
    if(gloop->loop == NULL) {
        return -1;
    }
    return uv_loop_init(gloop->loop);
}

void gjoll_delete(gjoll_loop_t *gloop) {
    uv_run(gloop->loop, UV_RUN_NOWAIT);
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
    char *buff = malloc(suggested_size);
    if(buff != NULL) {
        memset(buff, 0, suggested_size);
        buf->base = buff;
        buf->len = suggested_size;
    }
}

int gjoll_listener_init(gjoll_loop_t gloop,
                        gjoll_listener_t *listener,
                        gjoll_node_t identifier) {
    listener->server.data = NULL;
    listener->gloop = gloop;
    listener->identifier = identifier;
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

static void gjoll__send_cb(uv_write_t *req, int status) {
    gjoll_send_t *greq = (gjoll_send_t *)req->data;

    free(greq->ciphertext.base);
    if(greq->cb != NULL) {
        greq->cb(greq, status);
    }
}

static void gjoll__send_header_cb(gjoll_send_t *req, int status) {
    free(req);
}

static int gjoll__send_header(gjoll_connection_t *conn) {
    gjoll_buf_t packet;
    gjoll_send_t *greq;

    if(!(greq = malloc(sizeof(gjoll_send_t))))
        return -1;

    if(gjoll_encrypt_header(&(conn->cout), conn->secret, conn->header, &packet,
                            NULL))
        goto err;

    greq->ciphertext = gjoll_to_uv(packet);
    greq->req.data = greq;
    greq->cb = gjoll__send_header_cb;

    uv_write(&(greq->req), (uv_stream_t *)&(conn->client),
             &(greq->ciphertext), 1, gjoll__send_cb);
    return 0;

err:
    if(greq) free(greq);
    return -1;
}

static void gjoll__recv_cb(uv_stream_t *client, ssize_t nread,
                           const uv_buf_t* buf) {
    size_t i = 0;
    gjoll_len_t len;
    gjoll_connection_t *conn = (gjoll_connection_t *)client->data;
    gjoll_buf_t gbuf = uv_to_gjoll(*buf);
    gjoll_buf_t hbuf, data;
    gjoll_header_t header;
    gjoll_node_t src;
    gjoll__parse_action_t action;

    hbuf.base = conn->parser.hbuf;
    hbuf.len = GJOLL_HEADER_LENGTH;

    gbuf.len = nread;

    if(nread < 0) goto err;

    while(i < (size_t) nread) {
        i += gjoll__parser_parse(&(conn->parser), &action, gbuf);

        switch(action) {
            case GJOLL_HEADER_ACTION:
                src = *(gjoll_node_t *)OFFSET(conn->parser.hbuf, 8);
                src = fmbe64(src);
                if(conn->type == GJOLL_SERVER && conn->session_cb != NULL) {
                    if(conn->session_cb(conn, src)) {
                        goto err;
                    }
                }
                if(gjoll_decrypt_header(&(conn->cin), conn->secret,
                                        hbuf, &header)) {
                    goto err;
                }

                if(conn->header_cb != NULL && conn->header_cb(conn, header))
                    goto err;

                if(conn->type == GJOLL_SERVER) {
                    conn->header.id = header.id;
                    conn->header.src = header.dst;
                    conn->header.dst = header.src;
                }

                if(conn->type == GJOLL_SERVER && gjoll__send_header(conn))
                    goto err;
                action = GJOLL_NONE_ACTION;
                break;
            case GJOLL_SIZE_ACTION:
                if(gjoll_decrypt_size(&(conn->cin), conn->parser.lenbuff,
                                      &len)) {
                    goto err;
                }
                if(gjoll__parser_alloc_data(&(conn->parser), len))
                    goto err;
                action = GJOLL_NONE_ACTION;
                break;
            case GJOLL_DATA_ACTION:
                memset(&data, 0, sizeof(gjoll_buf_t));
                if(gjoll_decrypt_data(&(conn->cin), len,
                                      conn->parser.data, &data)) {
                    goto err;
                }
                gjoll__parser_free_data(&(conn->parser));
                if(conn->recv_cb != NULL) {
                    conn->recv_cb(conn, data);
                } else {
                    free(data.base);
                }
                action = GJOLL_NONE_ACTION;
                break;
            default:
                break;
        }

        gbuf.base = OFFSET(buf->base, i);
        gbuf.len -= i;
    }

    free(buf->base);
    return;

err:
    free(buf->base);
    gjoll__parser_free_data(&(conn->parser));
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
    uv_read_start((uv_stream_t *)&(gct->conn->client), gjoll__alloc_cb,
                  gjoll__recv_cb);
    free(gct);
}

int gjoll_accept(gjoll_listener_t *listener,
                 gjoll_connection_t *conn,
                 gjoll_session_cb session_cb,
                 gjoll_header_cb header_cb,
                 gjoll_close_cb close_cb) {
    memset(conn, 0, sizeof(gjoll_connection_t));
    conn->gloop = listener->gloop;
    conn->header.src = listener->identifier;
    conn->session_cb = session_cb;
    conn->header_cb = header_cb;
    conn->close_cb = close_cb;
    conn->type = GJOLL_SERVER;

    gjoll__parser_init(&(conn->parser));

    uv_tcp_init(listener->gloop.loop, &(conn->client));
    conn->client.data = conn;
    if(uv_accept((uv_stream_t *)&(listener->server),
                 (uv_stream_t *)&(conn->client))) {
        return -1;
    }

    return uv_read_start((uv_stream_t *)&(conn->client), gjoll__alloc_cb,
                         gjoll__recv_cb);
}

int gjoll_connect(gjoll_loop_t gloop,
                  gjoll_connection_t *conn,
                  const struct sockaddr *addr,
                  gjoll_header_t header,
                  gjoll_connect_cb connect_cb,
                  gjoll_header_cb header_cb,
                  gjoll_close_cb close_cb) {
    gjoll__connect_t *gct = NULL;

    memset(conn, 0, sizeof(gjoll_connection_t));
    conn->gloop = gloop;
    conn->type = GJOLL_CLIENT;
    conn->header = header;
    conn->header_cb = header_cb;
    conn->close_cb = close_cb;
    uv_tcp_init(gloop.loop, &(conn->client));
    conn->client.data = conn;

    gjoll__parser_init(&(conn->parser));

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
                          const void *shared,
                          const size_t shared_len,
                          gjoll_recv_cb recv_cb) {
    conn->recv_cb = recv_cb;
    if(gjoll_preprocess_secret(shared, shared_len, &(conn->secret)))
        return -1;

    if(conn->type == GJOLL_CLIENT) {
        return gjoll__send_header(conn);
    }
    return 0;
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
    gjoll_crypto_clean(&(conn->cin));
    gjoll_crypto_clean(&(conn->cout));
    gjoll__parser_free_data(&(conn->parser));
}

int gjoll_send(gjoll_send_t *greq, gjoll_connection_t *conn, void *data,
               size_t len, gjoll_send_cb cb) {
    gjoll_buf_t plaintext, ciphertext;

    plaintext.base = data;
    plaintext.len = len;

    greq->cb = cb;
    greq->req.data = greq;

    if(gjoll_encrypt_data(&(conn->cout), plaintext, &ciphertext))
        return -1;
    greq->ciphertext = gjoll_to_uv(ciphertext);

    uv_write(&(greq->req), (uv_stream_t *)&(conn->client),
             &(greq->ciphertext), 1, gjoll__send_cb);
    return 0;
}
