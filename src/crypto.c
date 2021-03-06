#include "../src/crypto.h"

#include <string.h>
#include <stdlib.h>

#include "ordo.h"
#include "ordo/misc/endianness.h"

/* This is thread-safe, since it is read-only. */
static const unsigned char zero_iv[GJOLL_IV_LEN];

int gjoll_preprocess_secret(const void *buffer, size_t len,
                            gjoll_secret_t *secret)
{
    return ordo_digest(HASH_SHA256, 0, buffer, len, secret->secret);
}

int gjoll_encrypt_header(gjoll__context_t *gctx,
                         gjoll_secret_t secret,
                         gjoll_header_t header,
                         gjoll_buf_t   *packet,
                         const void *nonce)
{
    unsigned char fingerprint[32];
    struct HMAC_CTX h_ctx;
    unsigned char session_nonce[8];

    /* Generate a new nonce as needed, or use the provided one. */
    if (!nonce) os_random(session_nonce, sizeof(session_nonce));
    else memcpy(session_nonce, nonce, sizeof(session_nonce));

    if (ordo_hmac(HASH_SHA256, 0, secret.secret, GJOLL_SECRET_LEN, session_nonce,
                  sizeof(session_nonce), gctx->key)) goto error;

    /* Convert the header fields to big endian for transport. */
    header.src = tobe64(header.src);
    header.dst = tobe64(header.dst);
    header.id  = tobe16(header.id);

    packet->len = GJOLL_HEADER_LENGTH;

    /* Copy the session nonce and the source node into the packet. */
    memcpy(OFFSET(packet->base, 0), session_nonce, sizeof(session_nonce));
    memcpy(OFFSET(packet->base, 8), &header.src,   sizeof(header.src));

    if (enc_block_init(&gctx->ctx, gctx->key, 32, zero_iv, GJOLL_IV_LEN, 1,
                       BLOCK_THREEFISH256, 0, BLOCK_MODE_CTR, 0)) goto error;

    /* Encrypt the dst node and the serviceID into the right packet offset. */
    enc_block_update(&gctx->ctx, &header.dst,        8, OFFSET(packet->base, 16), 0);
    enc_block_update(&gctx->ctx, &header.id ,        2, OFFSET(packet->base, 24), 0);

    /* Calculate the packet fingerprint. */
    if (hmac_init(&h_ctx, gctx->key, sizeof(gctx->key), HASH_SHA256, 0)) goto error;
    hmac_update(&h_ctx, OFFSET(packet->base,  0), 26);
    hmac_final(&h_ctx,  fingerprint);
    memcpy(OFFSET(packet->base, 26), fingerprint, 16); /* truncate fingerprint */

    return 0;

error:
    return 1;
}

int gjoll_encrypt_data(gjoll__context_t *gctx,
                       gjoll_buf_t data,
                       gjoll_buf_t *packet)
{
    gjoll_len_t size;
    unsigned char fingerprint[32];
    struct HMAC_CTX h_ctx;

    size = tobe16((gjoll_len_t)data.len);

    packet->len = GJOLL_DATA_MIN_LENGTH + data.len;

    /* Encrypt the dst node and the serviceID into the right packet offset. */
    enc_block_update(&gctx->ctx, &size, sizeof(gjoll_len_t),
                     OFFSET(packet->base, 0), 0);
    enc_block_update(&gctx->ctx, data.base, data.len,
                     OFFSET(packet->base, 2), 0);

    /* Calculate the packet fingerprint. */
    if (hmac_init(&h_ctx, gctx->key, sizeof(gctx->key), HASH_SHA256, 0)) goto error;
    hmac_update(&h_ctx, OFFSET(packet->base, 0), data.len+2);
    hmac_final(&h_ctx, fingerprint);
    memcpy(OFFSET(packet->base, data.len+2), fingerprint, 16); /* truncate fingerprint */

    return 0;

error:
    return 1;
}

int gjoll_decrypt_header(gjoll__context_t *gctx,
                         gjoll_secret_t secret,
                         gjoll_buf_t     packet,
                         gjoll_header_t *header)
{
    struct HMAC_CTX h_ctx;
    unsigned char nonce[8];
    unsigned char fingerprint[32];

    memcpy(nonce, OFFSET(packet.base, 0), sizeof(nonce));
    memcpy(&header->src, OFFSET(packet.base, 8), sizeof(header->src));

    if (ordo_hmac(HASH_SHA256, 0, secret.secret, GJOLL_SECRET_LEN,
                  nonce, sizeof(nonce), gctx->key)) goto error;

    if (hmac_init(&h_ctx, gctx->key, sizeof(gctx->key), HASH_SHA256, 0)) goto error;
    hmac_update(&h_ctx, OFFSET(packet.base,  0), 26);
    hmac_final(&h_ctx,  fingerprint);

    if (memcmp(fingerprint, OFFSET(packet.base, 26), 16) != 0) goto error;

    if (enc_block_init(&gctx->ctx, gctx->key, 32, zero_iv, GJOLL_IV_LEN, 1,
                       BLOCK_THREEFISH256, 0, BLOCK_MODE_CTR, 0)) goto error;
    enc_block_update(&gctx->ctx, OFFSET(packet.base, 16),  8, &header->dst, 0);
    enc_block_update(&gctx->ctx, OFFSET(packet.base, 24) , 2, &header->id, 0);

    /* src/dst/id back to host */
    header->src = fmbe64(header->src);
    header->dst = fmbe64(header->dst);
    header->id  = fmbe16(header->id);

    return 0;

error:
    return 1;
}

int gjoll_decrypt_size(gjoll__context_t *gctx,
                       gjoll_len_t elen,
                       gjoll_len_t *plen)
{
    enc_block_update(&gctx->ctx, OFFSET(&elen, 0), sizeof(gjoll_len_t),
                     plen, 0);
    *plen = fmbe16(*plen);

    return 0;
}

int gjoll_decrypt_data(gjoll__context_t *gctx,
                       gjoll_len_t    size,
                       gjoll_buf_t    packet,
                       gjoll_buf_t    *data)
{
    unsigned char fingerprint[32];
    struct HMAC_CTX h_ctx;

    /* Calculate the packet fingerprint. */
    if (hmac_init(&h_ctx, gctx->key, sizeof(gctx->key), HASH_SHA256, 0)) goto error;
    /* hmac_update(h_ctx, OFFSET(&size, 0), 2); */
    hmac_update(&h_ctx, OFFSET(packet.base, 0), size+GJOLL_LEN_SIZE);
    hmac_final(&h_ctx, fingerprint);

    if (memcmp(fingerprint, OFFSET(packet.base, size+GJOLL_LEN_SIZE),
               16) != 0) goto error;

    data->len = size;

    enc_block_update(&gctx->ctx, OFFSET(packet.base, GJOLL_LEN_SIZE), size,
                     data->base, 0);

    return 0;

error:
    return -1;
}

void gjoll_crypto_clean(gjoll__context_t *gctx) {
    enc_block_final(&gctx->ctx, 0, 0);
}
