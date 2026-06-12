/*
  Ecc.h - convenience forwarder for the elliptic-curve API of NiusCrypto.

      #include <Ecc.h>
      uint8_t priv[32], pub[64], sig[64];
      Crypto.ecdsaGenerateKey(priv, pub);
      Crypto.ecdsaSign(priv, hash32, sig);
      Crypto.ecdsaVerify(pub, hash32, sig);
      Crypto.ecdhShared(priv, peerPub, shared32);
      Crypto.x25519GenerateKey(priv32, pub32);
      Crypto.x25519Shared(priv32, peerPub32, shared32);
      Crypto.ed25519GenerateKey(secret64, pub32);
      Crypto.ed25519Sign(secret64, msg, msgLen, sig64);

  ECDSA / ECDH P-256, X25519 and Ed25519 require the vendored CC310 backend;
  RSA-2048 PKCS#1 v1.5 + SHA-256 likewise. On the on-chip fallback they return
  CryptoStatus::Unsupported. Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_ECC_H
#define NIUSCRYPTO_PUBLIC_ECC_H
#include "NiusCrypto.h"
#endif
