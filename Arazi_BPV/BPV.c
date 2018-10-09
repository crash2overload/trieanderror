#include "uECC_vli.h"
#include <uECC.h>
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
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

void get_BPV_Table(const uint8_t *privateAlice, const uint8_t *publicBob, const uint8_t *IDBob, const uint8_t *publicCA, uint8_t *Table) {

  time_t t;
  srand((unsigned) time(&t));
  //uECC_set_rng(&RNG);

  const struct uECC_Curve_t * curve = uECC_secp192r1();

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];

  if (! uECC_shared_secret2(publicBob, IDBob, pointAlice1, curve))
    printf("fail");

  EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);
//  for (int j = 0; j < 48; ++j) {
//    printf("0x"); printf("%x", pointAlice1[j]); printf(", ");
//    }
//    printf("\n");

  uECC_shared_secret2(pointAlice1, privateAlice, Table, curve);

}
