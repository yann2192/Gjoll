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
    return ordo_digest(sha256(), 0, buffer, len, secret->secret);
}

int gjoll_encrypt_packet(gjoll_secret_t secret,
                         gjoll_header_t header,
                         gjoll_buf_t    data,
                         gjoll_buf_t   *packet,
                         const void    *nonce)
{
    unsigned char transit_nonce[8];
    unsigned char fingerprint[32];
    struct HMAC_CTX      *h_ctx;
    struct ENC_BLOCK_CTX *ctx;
    unsigned char key[32];

    /* Convert the header fields to big endian for transport. */
    header.src = tobe64(header.src);
    header.dst = tobe64(header.dst);
    header.id  = tobe16(header.id);

    /* Allocate the packet buffer as large as required. */
    packet->len = GJOLL_HEADER_MIN_LENGTH + data.len;
    if (!(packet->base = malloc(packet->len))) goto error;

    /* Generate a new nonce as needed, or use the provided one. */
    if (!nonce) os_random(transit_nonce, sizeof(transit_nonce));
    else memcpy(transit_nonce, nonce, sizeof(transit_nonce));

    /* HMAC the secret with the transit nonce to get the encryption key. */
    if (ordo_hmac(sha256(), 0, secret.secret, GJOLL_SECRET_LEN,
                  transit_nonce, sizeof(transit_nonce), key)) goto error;

    /* Prepare the encryption context using the key and the all-zeroes IV */
    if (!(ctx = enc_block_alloc(threefish256(), ctr()))) goto error;
    if (enc_block_init(ctx, key, 32, zero_iv, GJOLL_IV_LEN, 1, 0, 0))
        goto error;

    /* Copy the transit nonce and the source node into the packet. */
    memcpy(OFFSET(packet->base, 0), transit_nonce, sizeof(transit_nonce));
    memcpy(OFFSET(packet->base, 8), &header.src,   sizeof(header.src));

    /* Encrypt the dst node and the serviceID into the right packet offset. */
    enc_block_update(ctx, &header.dst,        8, OFFSET(packet->base, 16), 0);
    enc_block_update(ctx, &header.id ,        2, OFFSET(packet->base, 24), 0);
    enc_block_update(ctx,  data.base , data.len, OFFSET(packet->base, 42), 0);
    enc_block_final(ctx, 0, 0);
    enc_block_free(ctx);

    /* Calculate the packet fingerprint. */
    if (!(h_ctx = hmac_alloc(sha256()))) goto error;
    if (hmac_init(h_ctx, key, sizeof(key), 0)) goto error;
    hmac_update(h_ctx, OFFSET(packet->base,  0), 26);
    hmac_update(h_ctx, OFFSET(packet->base, 42), packet->len - 42);
    hmac_final(h_ctx,  fingerprint);
    memcpy(OFFSET(packet->base, 26), fingerprint, 16); // truncate fingerprint
    hmac_free(h_ctx);

    return 0;

error:
    if (packet->base) free(packet->base);
    if (ctx) enc_block_free(ctx);
    if (h_ctx) hmac_free(h_ctx);
    return 1;
}

int gjoll_decrypt_packet(gjoll_secret_t  secret,
                         gjoll_buf_t     packet,
                         gjoll_header_t *header,
                         gjoll_buf_t    *data)
{
    struct HMAC_CTX      *h_ctx;
    struct ENC_BLOCK_CTX *ctx;
    unsigned char nonce[8];
    unsigned char fingerprint[32];
    unsigned char key[32];

    if(packet.len < 42) return 1;

    memcpy(nonce, OFFSET(packet.base, 0), sizeof(nonce));
    memcpy(&header->src, OFFSET(packet.base, 8), sizeof(header->src));

    if (ordo_hmac(sha256(), 0, secret.secret, GJOLL_SECRET_LEN,
                  nonce, sizeof(nonce), key)) goto error;

    if (!(h_ctx = hmac_alloc(sha256()))) goto error;
    if (hmac_init(h_ctx, key, sizeof(key), 0)) goto error;
    hmac_update(h_ctx, OFFSET(packet.base,  0), 26);
    hmac_update(h_ctx, OFFSET(packet.base, 42), packet.len - 42);
    hmac_final(h_ctx,  fingerprint);
    hmac_free(h_ctx);

    if (memcmp(fingerprint, OFFSET(packet.base, 26), 16) != 0) return 1; // invalid fingerprint

    if (!data) goto error;
    data->len = packet.len - 42;
    data->base = malloc(data->len);
    if (!data->base) goto error;

    if (!(ctx = enc_block_alloc(threefish256(), ctr()))) goto error;
    if (enc_block_init(ctx, key, 32, zero_iv, GJOLL_IV_LEN, 1, 0, 0))
        goto error;
    enc_block_update(ctx, OFFSET(packet.base, 16),        8, &header->dst, 0);
    enc_block_update(ctx, OFFSET(packet.base, 24) ,        2, &header->id, 0);
    enc_block_update(ctx, OFFSET(packet.base, 42), data->len, data->base, 0);
    enc_block_final(ctx, 0, 0);

    enc_block_free(ctx);

    // src/dst/id back to host
    header->src = fmbe64(header->src);
    header->dst = fmbe64(header->dst);
    header->id  = fmbe16(header->id);

    return 0;

error:
    enc_block_free(ctx);
    hmac_free(h_ctx);
    return 1;
}
