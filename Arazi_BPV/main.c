#include "uECC_vli.h"
#include <uECC.h>
#include "BPV.h"
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
    //uECC_set_rng(&RNG);

    const struct uECC_Curve_t * curve = uECC_secp192r1();


    uint8_t privateAlice2[24];
    uint8_t privateBob2[24];

    uint8_t publicAlice2[48];
    uint8_t publicBob2[48];

    uint8_t hash[24] = {0};
    uint8_t hash2[24] = {0};

    uint8_t pointAlice1[48];
    uint8_t pointBob1[48];

    uint8_t pointAlice2[48];
    uint8_t pointBob2[48];

    //Random Point on the Curve
    uint8_t publicCA[] = {0x5e, 0x8c, 0x6b, 0x93, 0xe2, 0x98, 0xf6, 0x4, 0xc5, 0x2, 0x70, 0xbf, 0xa7, 0x9, 0x42, 0x9a, 0xc4, 0xdc, 0x43, 0x71, 0xe8, 0xd6, 0xca, 0x4d, 0x41, 0xe8, 0xb1, 0xa9, 0x36, 0xd8, 0x1a, 0x9c, 0x22, 0xb3, 0x66, 0xa7, 0x43, 0x4, 0x7, 0x4e, 0x14, 0x5, 0xc5, 0xcd, 0xbb, 0x50, 0x13, 0x4d};
    uint8_t privateCA[] = {0x60, 0x21, 0x71, 0x89, 0x42, 0xb1, 0x7d, 0xb0, 0xd9, 0xa8, 0x6, 0xbc, 0x2e, 0xf0, 0xf4, 0xe, 0x38, 0xce, 0xb4, 0x13, 0x40, 0xe3, 0xc2, 0x6e};

    uint8_t publicAlice1[] = {0xf3, 0xf1, 0xd5, 0x88, 0x99, 0x5c, 0xaa, 0xc8, 0xcf, 0xa0, 0x5e, 0x3d, 0x29, 0x93, 0x18, 0xce, 0x1, 0x4, 0x9a, 0xf6, 0x5a, 0x39, 0x3f, 0x36, 0xc6, 0x87, 0xaa, 0x38, 0xf5, 0xc2, 0xad, 0xa7, 0xd8, 0x3a, 0xdf, 0xa1, 0x9c, 0x32, 0x7d, 0xd5, 0x7b, 0xa7, 0x59, 0x1a, 0x24, 0x8d, 0x99, 0x57};
    uint8_t privateAlice1[] = {0x25, 0xcc, 0xa2, 0x86, 0xe8, 0x14, 0xb6, 0x73, 0xe7, 0x8f, 0x4e, 0x58, 0xcf, 0x77, 0x85, 0xcd, 0xb7, 0xae, 0xa4, 0xa0, 0x29, 0x30, 0x1c, 0x3};

    uint8_t publicBob1[] = {0x16, 0xe4, 0xb4, 0x64, 0xbe, 0xaf, 0x40, 0x14, 0xee, 0x41, 0xc8, 0x4e, 0x8c, 0xb8, 0x53, 0xb4, 0x7d, 0x68, 0xca, 0x21, 0xf6, 0xe7, 0x2f, 0xe4, 0xf3, 0x51, 0x9f, 0xfa, 0x83, 0xb6, 0x4c, 0xc3, 0xfb, 0xd5, 0xc2, 0x9e, 0xd8, 0xfa, 0xcc, 0xd3, 0xfc, 0xdb, 0x66, 0xa1, 0x61, 0xb0, 0x55, 0x33};
    uint8_t privateBob1[] = {0x1, 0x26, 0xe0, 0xf7, 0x8, 0x2, 0xa6, 0x9d, 0xf0, 0x17, 0x36, 0xd5, 0xa0, 0x1a, 0x33, 0x99, 0x8a, 0x3a, 0x9, 0xa, 0x7e, 0x9b, 0x68, 0x7};

    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, publicBob1, sizeof(publicBob1));
    sha256_final(&ctx, hash2);

    sha256_init(&ctx);
    sha256_update(&ctx, publicAlice1, sizeof(publicAlice1));
    sha256_final(&ctx, hash);

    //Calculation of of ID, U, E
    modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
    modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);


    uECC_make_key(publicAlice2, privateAlice2, curve);
    uECC_make_key(publicBob2, privateBob2, curve);

    int r = uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);

    r = uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);

    EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);

    r = uECC_shared_secret2(pointAlice1, privateAlice1, pointAlice1, curve);

    uint8_t Table[48] = {0};
//    get_BPV_Table(privateAlice1, publicBob1, hash2, publicCA, Table);

    EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);
    EllipticAdd(Table, pointAlice2, Table, curve);

    get_BPV_Table(privateBob1, publicAlice1, hash, publicCA, Table);



    r = uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
    for (int j = 0; j < 48; ++j) {
        printf("0x"); printf("%x", pointBob1[j]); printf(", ");
    }
    printf("\n");
    r = uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
        for (int j = 0; j < 48; ++j) {
        printf("0x"); printf("%x", pointBob1[j]); printf(", ");
    }
    printf("\n");

    EllipticAdd(pointBob1, publicCA, pointBob1, curve);

    r = uECC_shared_secret2(pointBob1, privateBob1, pointBob1, curve);

    r = uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
    EllipticAdd(pointBob1, pointBob2, pointBob1, curve);

  printf("Arazi in: ");
  //for (int j = 0; j < 48; ++j) {
  //  printf("0x"); printf("%x", Table[j]); printf(", ");
  //  printf("0x"); printf("%x", Table[j+48]); printf("\n ");
  //}

  if (memcmp(&pointAlice1[24], &pointBob1[24], 24) != 0) {
    printf("Shared secrets are not identical!\n");
  } else {
    printf("Shared secrets are identical\n");
  }

    return 1;
}
