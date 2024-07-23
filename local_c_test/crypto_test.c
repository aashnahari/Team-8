#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

//RUN THIS C CODE IN TERMINAL: gcc -o crypto_test ./local_c_test/crypto_test.c -I/home/hacker/Team-8/lib/wolfssl  -L/home/hacker/Team-8/lib/wolfssl -lwolfssl

#define KEY_SIZE 32  // SHA-256 HMAC key size
#define MSG_SIZE  16  // Example message size
#define HMAC_SIZE 32  // SHA-256 HMAC output size

void print_hex(const char *title, const uint8_t *data, size_t len) {
    printf("%s: ", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

bool verify_hmac(const uint8_t *key, const uint8_t *message, size_t message_len, const uint8_t *expected_hmac) {
    uint8_t computed_hmac[HMAC_SIZE];
    Hmac hmac;

    // Initialize HMAC context
    wc_HmacInit(&hmac);
    if (wc_HmacSetKey(&hmac, WC_SHA256, key, KEY_SIZE) != 0) {
        perror("wc_HmacSetKey failed");
        return false;
    }
    if (wc_HmacUpdate(&hmac, message, message_len) != 0) {
        perror("wc_HmacUpdate failed");
        return false;
    }
    if (wc_HmacFinal(&hmac, computed_hmac) != 0) {
        perror("wc_HmacFinal failed");
        return false;
    }

    // Verify the HMAC
    if (memcmp(computed_hmac, expected_hmac, HMAC_SIZE) != 0) {
        return false;
    }

    return true;
}

int main(void) {
    // Define key, message, and expected HMAC
    uint8_t key[KEY_SIZE] = "this_is_a_secret_key_for_hmac";
    uint8_t message[MSG_SIZE] = "test message";
    uint8_t expected_hmac[HMAC_SIZE] = {
        // Fill with the expected HMAC value for the above key and message
        0x5d, 0xe3, 0x0d, 0xd6, 0x23, 0x0f, 0x8f, 0xb7,
        0x6c, 0xa1, 0x67, 0x79, 0x8b, 0x71, 0x8d, 0x71,
        0x6e, 0x77, 0x62, 0x70, 0xa4, 0xe0, 0x7f, 0x2c,
        0xc3, 0x36, 0x9a, 0xe0, 0x30, 0x47
    };

    // Verify HMAC
    if (verify_hmac(key, message, MSG_SIZE, expected_hmac)) {
        printf("HMAC verification succeeded.\n");
    } else {
        printf("HMAC verification failed.\n");
    }

    return 0;
}
