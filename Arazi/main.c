#include "uECC_vli.h"
#include <uECC.h>
#include "types.h"
#include "stdio.h"
#include "Crypto/SHA256.h"
//#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
//#include <avr/pgmspace.h>



static int RNG(uint8_t *dest, unsigned size) {

  while (size) {
    uint8_t val = 0;
    val = rand() % 256;
    *dest = val;
    ++dest;
    --size;
  }
  //SHA256_CTX ctx;
  // SHA256_Init(&ctx);
  // SHA256_Update(&ctx, dest, sizeof(dest));
  // SHA256_Final(dest, &ctx);
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}


int main()
{

  time_t t;
  srand((unsigned) time(&t));
  uECC_set_rng(&RNG);
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  uint8_t privateCA[24];
  uint8_t publicCA[48];

  uint8_t privateAlice1[24];
  uint8_t privateAlice2[24];

  uint8_t privateBob1[24];
  uint8_t privateBob2[24];

  uint8_t publicAlice1[48];
  uint8_t publicAlice2[48];

  uint8_t publicBob1[48];
  uint8_t publicBob2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};
  uint8_t hash3[32] = {0};
  uint8_t hash4[32] = {0};

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];

  uint8_t pointAlice2[48];
  uint8_t pointBob2[48];

  unsigned long a,b,c,d;


      uECC_make_key(publicCA, privateCA, curve);
      uECC_make_key(publicAlice1, privateAlice1, curve);
      uECC_make_key(publicBob1, privateBob1, curve);
    SHA256 sha256;
    sha256.reset();
    sha256.update(publicBob1, sizeof(publicBob1));
    sha256.finalize(hash2, sizeof(hash2));
    sha256.reset();
    sha256.update(publicAlice1, sizeof(publicAlice1));
    sha256.finalize(hash, sizeof(hash));

//    SHA256_CTX ctx, ctx2;
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, publicAlice1, sizeof(publicAlice1));
//    SHA256_Final(hash, &ctx);
//    //memcpy (hash3, hash, sizeof(hash3));
////
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, publicBob1, sizeof(publicBob1));
//    SHA256_Final(hash2, &ctx);
//     //memcpy (hash4, hash2, sizeof(hash4));

    modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
    modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);

    //modularAdd2(privateAlice1, privateCA, privateAlice1, curve);
    //modularAdd2(privateBob1, privateCA, privateBob1, curve);

    //modularMult2(privateAlice1, hash, privateAlice1, curve);
    //modularMult2(privateBob1, hash2, privateBob1, curve);

    int r = uECC_shared_secret2(publicBob1, privateAlice1, pointAlice2, curve);
    r = uECC_shared_secret2(publicAlice1, privateBob1, pointBob2, curve);

    uECC_make_key(publicAlice2, privateAlice2, curve);
    uECC_make_key(publicBob2, privateBob2, curve);

    r = uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);
    r = uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
    EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);
    r = uECC_shared_secret2(pointAlice1, privateAlice1, pointAlice1, curve);
    EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);

    r = uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
    r = uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
    EllipticAdd(pointBob1, publicCA, pointBob1, curve);
    r = uECC_shared_secret2(pointBob1, privateBob1, pointBob1, curve);
    EllipticAdd(pointBob1, pointBob2, pointBob1, curve);

  printf("Arazi in: ");
  for (int j = 0; j < 52; ++j) {
    printf("0x"); printf("%x", pointAlice1[j]); printf(", ");
    printf("0x"); printf("%x", pointBob1[j]); printf("\n ");
  }

  if (memcmp(pointAlice1, pointBob1, 24) != 0) {
    printf("Shared secrets are not identical!\n");
  } else {
    printf("Shared secrets are identical\n");
  }

    return 1;
}
