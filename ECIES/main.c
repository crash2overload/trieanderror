#include "../Source/uECC_vli.h"
#include "../Source/uECC.h"
#include "../Source/types.h"
#include "../Source/sha256.h"
#include "../Source/keys.h"
#include "../Source/aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int RNG(uint8_t *dest, unsigned size) {

  while (size) {
    uint8_t val = 0;
    val = rand() % 255 + 1;
    *dest = val;
    ++dest;
    --size;
  }
  return 1;
}


int main()
{

    time_t t;
    srand((unsigned) time(&t));
    uECC_set_rng(&RNG);

    const struct uECC_Curve_t * curve = uECC_secp192r1();

    uint8_t hash[32] = {0};
    uint8_t hash2[32] = {0};

    uint8_t keyAliceEnc[16] = {0};
    uint8_t keyAliceMac[16] = {0};
    uint8_t ivAlice[16] = {0};
    uint8_t keyBobEnc[16] = {0};
    uint8_t keyBobMac[16] = {0};
    uint8_t ivBob[16] = {0};

    uint8_t message[32] = {0};
    uint8_t messageBob[32] = {0};

    uint8_t ciphertext[32];

    uint8_t tag[16] = {0};
    uint8_t tagBob[16] = {0};

    uint8_t pointAlice1[48];
    uint8_t pointBob1[48];

    uECC_shared_secret2(publicBob1, privateAlice1, pointAlice1, curve);

    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, publicAlice1, sizeof(publicAlice1));
    sha256_final(&ctx, hash);

    memcpy(keyAliceEnc, hash, sizeof(keyAliceEnc));
    memcpy(keyAliceMac, hash + 16, sizeof(keyAliceMac));

    int any;
    aes_key_setup(keyAliceEnc, any, 128);
    increment_iv(ivAlice, 128);
    aes_encrypt_ctr(message, sizeof(message), ciphertext, any, sizeof(keyAliceEnc), ivAlice);


    /*ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
    ctraes128.setIV(ivAlice, ctraes128.keySize());
    ctraes128.encrypt(ciphertext, message, sizeof(message));

    sha256.resetHMAC(keyAliceMac, sizeof(keyAliceMac));
    sha256.update(message, sizeof(message));
    sha256.finalizeHMAC(keyAliceMac, sizeof(keyAliceMac), tag, sizeof(tag));*/

    printf("Hello world!\n");
    return 0;
}
