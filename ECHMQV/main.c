#include "uECC_vli.h"
#include "uECC.h"
#include "types.h"
#include "stdio.h"
#include "sha256.h"

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
  uint8_t privateCA[25];
  uint8_t private1[25];
  uint8_t private2[25];

  uint8_t publicCA[48];
  uint8_t public1[48];
  uint8_t public2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};
  uint8_t sig[48] = {0};
  uint8_t sig2[48] = {0};

  uint8_t key1[48];
  uint8_t key2[48];

  unsigned long a,b,c,d, clockcycle, clockcycle2;

  uint8_t privateEph1[25];
  uint8_t privateEph2[25];

  uint8_t publicEph1[48];
  uint8_t publicEph2[48];

  uint8_t hashD[24] = {0};
  uint8_t hashE[24] = {0};

  SHA256_CTX ctx;

  uECC_make_key(publicCA, privateCA, curve);

  uECC_make_key(public1, private1, curve);
  uECC_make_key(public2, private2, curve);

  sha256_init(&ctx);
  sha256_update(&ctx, public1, sizeof(public1));
  sha256_final(&ctx, hash);

  sha256_init(&ctx);
  sha256_update(&ctx, public2, sizeof(public2));
  sha256_final(&ctx, hash2);

//  memcpy(hash, public1, sizeof(hash));
//  memcpy(hash2, public2, sizeof(hash2));

  if (!uECC_sign(privateCA, hash, sizeof(hash), sig, curve)) {
     printf("uECC_sign() failed\n");
  }

  if (!uECC_sign(privateCA, hash2, sizeof(hash2), sig2, curve)) {
     printf("uECC_sign() failed\n");
  }


  if (!uECC_verify(publicCA, hash, sizeof(hash), sig, curve)) {
     printf("uECC_verify() failed\n");
  }
  printf("CA signature is verified\n");

  if (!uECC_verify(publicCA, hash2, sizeof(hash2), sig2, curve)) {
     printf("uECC_verify() failed\n");
  }
  printf("CA signature is verified\n");

  uECC_make_key(publicEph1, privateEph1, curve);

  sha256_init(&ctx);
  sha256_update(&ctx, publicEph1, sizeof(publicEph1));
  sha256_final(&ctx, hashD);

  sha256_init(&ctx);
  sha256_update(&ctx, publicEph2, sizeof(publicEph2));
  sha256_final(&ctx, hashE);

  uECC_make_key(publicEph2, privateEph2, curve);

  sha256_init(&ctx);
  sha256_update(&ctx, publicEph1, sizeof(publicEph1));
  sha256_final(&ctx, hashD);

  sha256_init(&ctx);
  sha256_update(&ctx, publicEph2, sizeof(publicEph2));
  sha256_final(&ctx, hashE);

//  memcpy(hashD, publicEph1, sizeof(hashD));
//  memcpy(hashE, publicEph2, sizeof(hashE));

  int r = uECC_shared_secret2(public2, hashE, key1, curve);

  EllipticAdd(key1, publicEph2, key1, curve);

  modularMultAdd(hashD, private1, privateEph1, privateEph1, curve);
  r = uECC_shared_secret2(key1, privateEph1, key1, curve);

  r = uECC_shared_secret2(public1, hashD, key2, curve);

  EllipticAdd(key2, publicEph1, key2, curve);
  modularMultAdd(hashE, private2, privateEph2, privateEph2, curve);

  r = uECC_shared_secret2(key2, privateEph2, key2, curve);
    for (int j = 0; j < 48; ++j) {
        printf("0x"); printf("%x", key1[j]); printf(", ");
        printf("0x"); printf("%x", key2[j]); printf("\n ");
    }

  if (memcmp(key1, key2, 24) != 0) {
    printf("Shared secrets are not identical!\n");
  } else {
    printf("Shared secrets are identical\n");
  }

    return 0;
}
