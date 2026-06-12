/*
  Ecc.h - convenience forwarder for the elliptic-curve API of NiusCrypto.

      #include <Ecc.h>

      EcdsaMessage ecdsa;
      ecdsa.payload = msg;  ecdsa.payloadLen = len;
      Crypto.ecdsaGenerateKey(ecdsa);
      Crypto.ecdsaSign(ecdsa);
      Crypto.ecdsaVerify(ecdsa);
      ecdsa.reset();

      Ed25519Message ed;
      Crypto.ed25519GenerateKey(ed);
      Crypto.ed25519Sign(ed);
      ed.useSeed = true;  // advanced: sign from ed.seed[32] only

  Low-level APIs (pre-hashed ECDSA, raw secret bytes, etc.) remain on CryptoEngine.
  Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_ECC_H
#define NIUSCRYPTO_PUBLIC_ECC_H
#include "NiusCrypto.h"
#endif
