#ifndef GJOLL_CRYPTO_H
#define GJOLL_CRYPTO_H

// private header

#include "gjoll.h"
#include "ordo.h"

/*
 * Length of a gjoll initialization vector, in bytes.
 */
#define GJOLL_IV_LEN 32

/*
 * Length of a gjoll fingerprint, in bytes.
 */
 #define GJOLL_FINGERPRINT_LEN 16

/*
 * Length of a gjoll nonce, in bytes.
 */
#define GJOLL_NONCE_LEN 8

/*
 * Preprocesses an arbitrary long shared secret in a gjoll secret, of finite
 * length, for use in the gjoll cryptography layer.
 *
 * Arguments:
 *  buffer    The user-provided buffer containing the shared secret.
 *  len       The length of the buffer.
 *  secret    The buffer in which the gjoll secret will be written.
 *
 * Returns:
 *  0 on success, or an error code on failure.
 */
int gjoll_preprocess_secret(const void *buffer, size_t len,
                            gjoll_secret_t *secret);

/*
 * Encrypts a header and a data buffer into a packet.
 *
 * Arguments:
 *  secret    The secret shared between the local node (you) and the router.
 *  header    The header to associate with the data buffer.
 *  data      The data buffer to write into the packet.
 *  packet    A buffer in which the packet will be written.
 *  nonce     An optional nonce.
 *
 * Returns:
 *  0 on success, or an error code on failure.
 *
 * If nonce is zero, one is automatically generated, making the function non
 * pure. To avoid this you can pass a pointer to a buffer of length equal to
 * GJOLL_NONCE_LEN in order to make the function deterministic.
 */
int gjoll_encrypt_header(gjoll__context_t *gctx,
                         gjoll_secret_t secret,
                         gjoll_header_t header,
                         gjoll_buf_t   *packet,
                         const void    *nonce);

/*
 * Decrypts the header contained in a packet.
 *
 * Arguments:
 *  secret    The secret shared between the local node (you) and the router.
 *  packet    A buffer which contains the raw packet bytes.
 *  header    A buffer in which the header in the packet will be written.
 *  enc_ctx   An encryption context to pass to gjoll_decrypt_data().
 *
 * Returns:
 *  0 on success, or an error code on failure.
 */
int gjoll_decrypt_header(gjoll__context_t *gctx,
                         gjoll_secret_t  secret,
                         gjoll_buf_t     packet,
                         gjoll_header_t *header);

int gjoll_encrypt_data(gjoll__context_t *gctx,
                       gjoll_buf_t data,
                       gjoll_buf_t *packet);

int gjoll_decrypt_size(gjoll__context_t *,
                       gjoll_len_t,
                       gjoll_len_t *);

/*
 * Decrypts the data contained in a packet.
 *
 * Arguments:
 *  secret    The secret shared between the local node (you) and the router.
 *  packet    A buffer which contains the raw packet bytes.
 *  data      A buffer in which the data in the packet will be written.
 *  enc_ctx   An encryption context to obtain from gjoll_decrypt_header().
 *
 * Returns:
 *  0 on success, or an error code on failure.
 *
 * This will reuse the encryption context from gjoll_decrypt_header in order
 * to complete decryption of the data. If data is zero, the context is freed
 * without decrypting anything (so you need to call it anyway).
 */
int gjoll_decrypt_data(gjoll__context_t *gctx,
                       gjoll_len_t      size,
                       gjoll_buf_t    packet,
                       gjoll_buf_t   *data);

void gjoll_crypto_clean(gjoll__context_t *gctx);

#endif
