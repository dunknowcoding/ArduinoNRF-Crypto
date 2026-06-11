/*
  Ecc.h - convenience forwarder for the elliptic-curve API of NiusCrypto.

      #include <Ecc.h>
      uint8_t priv[32], pub[64], sig[64];
      Crypto.ecdsaGenerateKey(priv, pub);
      Crypto.ecdsaSign(priv, hash32, sig);
      Crypto.ecdsaVerify(pub, hash32, sig);
      Crypto.ecdhShared(priv, peerPub, shared32);

  ECDSA / ECDH on NIST P-256 require the vendored backend (CC310 + Oberon); on
  the on-chip fallback they return CryptoStatus::Unsupported. Same library as
  <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_ECC_H
#define NIUSCRYPTO_PUBLIC_ECC_H
#include "NiusCrypto.h"
#endif
