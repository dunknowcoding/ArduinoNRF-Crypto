/*
  Random.h - convenience forwarder for the random-number API of NiusCrypto.

      #include <Random.h>
      Crypto.begin();
      uint8_t nonce[16];
      Crypto.random(nonce, sizeof(nonce));   // CC310 TRNG-seeded CTR-DRBG

  This is just <NiusCrypto.h> under a topic name; the whole API is still on the
  `Crypto` object.
*/
#ifndef NIUSCRYPTO_PUBLIC_RANDOM_H
#define NIUSCRYPTO_PUBLIC_RANDOM_H
#include "NiusCrypto.h"
#endif
