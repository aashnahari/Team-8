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

bool verify_hmac(uint8_t *sig, uint8_t *ky, uint8_t *msg){   //function for hmac verifying
    uint8_t hmac_result[32];
    size_t msg_len = sizeof(msg)
    Hmac hmac;
    
    // Initialize HMAC
    wc_HmacInit(&hmac, NULL, 0);

    // Set HMAC key
    if (wc_HmacSetKey(&hmac, WC_SHA256, ky, 32) != 0) {
        perror("wc_HmacSetKey failed");
        return false;
    }
    
    // Update HMAC with message
    if (wc_HmacUpdate(&hmac, msg, msg_len) != 0) {
        perror("wc_HmacUpdate failed");
        wc_HmacFree(&hmac);
        return false;
    }

    // Finalize HMAC calculation
    if (wc_HmacFinal(&hmac, hmac_result) != 0) {
        perror("wc_HmacFinal failed");
        wc_HmacFree(&hmac);
        return false;
    }

    // Free HMAC context  
    wc_HmacFree(&hmac);

    // Compare calculated HMAC with provided signature
    if (32 != wc_HmacGetSize(&hmac) || memcmp(hmac_result, sig, 32) != 0) {
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
    if (verify_hmac(expected_hmac, key, message)) {
        printf("HMAC verification succeeded.\n");
    } else {
        printf("HMAC verification failed.\n");
    }

    return 0;
}
