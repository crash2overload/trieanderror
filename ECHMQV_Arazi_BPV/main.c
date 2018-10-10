#include "../Source/uECC_vli.h"
#include "../Source/uECC.h"
#include "../Source/types.h"
#include "../Source/sha256.h"
#include "../Source/keys.h"
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


    uint8_t privateAlice2[24] = {0};
    uint8_t privateBob2[24] = {0};

    uint8_t publicAlice2[48] = {0};
    uint8_t publicBob2[48] = {0};

    uint8_t hash[24] = {0};
    uint8_t hash2[24] = {0};

    uint8_t pointAlice1[48] = {0};
    uint8_t pointBob1[48] = {0};

    uint8_t pointAlice2[48] = {0};
    uint8_t pointBob2[48] = {0};

    uint8_t hashD[24] = {0};
    uint8_t hashE[24] = {0};

    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, publicBob1, sizeof(publicBob1));
    sha256_final(&ctx, hash2);

    sha256_init(&ctx);
    sha256_update(&ctx, publicAlice1, sizeof(publicAlice1));
    sha256_final(&ctx, hash);

    modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
    modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);

    uint8_t tempPriv[28];
    uint8_t tempPub[48];
    uint8_t randNummer = rand() % 160;
    memcpy(tempPriv, &Tab_Alice[(72*randNummer)+24], sizeof(tempPriv));
    memcpy(tempPub, &Tab_Alice[(72*randNummer)+24], sizeof(tempPub));
    randNummer = rand() % 160;
    memcpy(privateAlice2, &Tab_Alice[72*randNummer], sizeof(privateAlice2));
    memcpy(publicAlice2, &Tab_Alice[(72*randNummer)+24], sizeof(publicAlice2));

    EllipticAdd(publicAlice2, tempPub, publicAlice2, curve);
    modularAdd2(privateAlice2, tempPriv, privateAlice2, curve);

    randNummer = rand() % 160;
    memcpy(tempPriv, &Tab_Bob[(72*randNummer)+24], sizeof(tempPriv));
    memcpy(tempPub, &Tab_Bob[(72*randNummer)+24], sizeof(tempPub));
    randNummer = rand() % 160;
    memcpy(privateBob2, &Tab_Bob[72*randNummer], sizeof(privateBob2));
    memcpy(publicBob2, &Tab_Bob[(72*randNummer)+24], sizeof(publicBob2));

    EllipticAdd(publicBob2,tempPub,publicBob2,curve);
    modularAdd2(privateBob2, tempPriv, privateBob2, curve);

    uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
    EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);

    uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
    EllipticAdd(pointBob1, publicCA, pointBob1, curve);

    sha256_init(&ctx);
    sha256_update(&ctx, publicBob2, sizeof(publicBob2));
    sha256_final(&ctx, hashE);

    sha256_init(&ctx);
    sha256_update(&ctx, publicAlice2, sizeof(publicAlice2));
    sha256_final(&ctx, hashD);

    uECC_shared_secret2(pointAlice1, hashE, pointAlice1, curve);
    EllipticAdd(pointAlice1, publicBob2, pointAlice1, curve);
    modularMultAdd(privateAlice1, hashD, privateAlice2, privateAlice2, curve);

    uECC_shared_secret2(pointAlice1, privateAlice2, pointAlice1, curve);

    sha256_init(&ctx);
    sha256_update(&ctx, publicBob2, sizeof(publicBob2));
    sha256_final(&ctx, hashE);

    sha256_init(&ctx);
    sha256_update(&ctx, publicAlice2, sizeof(publicAlice2));
    sha256_final(&ctx, hashD);

    uECC_shared_secret2(pointBob1, hashD, pointBob1, curve);

    EllipticAdd(pointBob1, publicAlice2, pointBob1, curve);
    modularMultAdd(privateBob1, hashE, privateBob2, privateBob2, curve);

    uECC_shared_secret2(pointBob1, privateBob2, pointBob1, curve);

    printf("EHMQV_Arazi_BPV in: ");
    for (int j = 0; j < 48; ++j) {
        printf("0x"); printf("%x", pointAlice1[j]); printf(", ");
        printf("0x"); printf("%x", pointBob1[j]); printf("\n ");
    }

    if (memcmp(&pointAlice1[24], &pointBob1[24], 24) != 0) {
        printf("Shared secrets are not identical!\n");
    } else {
        printf("Shared secrets are identical\n");
    }

    return 0;
}
