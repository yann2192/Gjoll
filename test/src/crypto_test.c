#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "test.h"
#include "gjoll.h"

#include "../src/crypto.h"

static gjoll_secret_t secret = { { 0xc1, 0xf9, 0x32, 0x06, 0x92, 0x03, 0x76, 0x91,
                                   0x8c, 0xc0, 0x7f, 0xe0, 0x15, 0x8f, 0x6a, 0x81,
                                   0x01, 0x09, 0xb9, 0x91, 0x59, 0x2f, 0x18, 0x93,
                                   0x13, 0x04, 0x00, 0x00, 0x44, 0x4b, 0x94, 0x30 } };

// according to the initial specification (= using AES-256)
static unsigned char valid_packet[42 + 4] = { 0xbc, 0x46, 0x54, 0xef, 0xb2, 0x26, 0xc6,
                                              0xf6, 0x7b, 0x8b, 0x57, 0x66, 0x93, 0x15,
                                              0x29, 0xe6, 0xd5, 0xac, 0xd5, 0xd9, 0xae,
                                              0xac, 0x5a, 0x52, 0x3c, 0x58, 0xe5, 0x28,
                                              0xbd, 0xd0, 0x4d, 0x56, 0x81, 0x05, 0x00,
                                              0x1c, 0x4b, 0x3e, 0x50, 0xcf, 0x16, 0xbc,
                                              0x0c, 0x5a, 0xdf, 0xc5 };

static char* test__gjoll_encrypt_packet() {
    unsigned char nonce[GJOLL_NONCE_LEN] = { 0xbc, 0x46, 0x54, 0xef, 0xb2, 0x26, 0xc6, 0xf6 };

    gjoll_header_t header;
    header.src = 0x7b8b5766931529e6ULL;
    header.dst = 0xa5010113eb0a809bULL;
    header.id = 2000;

    gjoll_buf_t data = { "test", 4 };

    gjoll_buf_t packet;

    int err = gjoll_encrypt_packet(secret, header, data, &packet, nonce);

    mu_assert("error: misc. crypto error", err == 0);
    mu_assert("error: invalid packet", memcmp(packet.base, valid_packet, 46) == 0);

    return 0;
}

static char* test__gjoll_decrypt_packet() {
    gjoll_header_t header;
    gjoll_buf_t data;

    gjoll_buf_t packet;
    packet.base = valid_packet;
    packet.len = sizeof(valid_packet);

    int err = gjoll_decrypt_packet(secret, packet, &header, &data);
    mu_assert("error: misc. crypto error", err == 0);

    mu_assert("error: src incorrect", header.src == 0x7b8b5766931529e6ULL);
    mu_assert("error: dst incorrect", header.dst == 0xa5010113eb0a809bULL);
    mu_assert("error: id incorrect", header.id == 2000);

    return 0;
}

char* crypto_tests() {
    mu_run_test(test__gjoll_encrypt_packet);
    mu_run_test(test__gjoll_decrypt_packet);
    return 0;
}
