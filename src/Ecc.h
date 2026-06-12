/*
  Ecc.h - convenience forwarder for the elliptic-curve API of NiusCrypto.

      #include <Ecc.h>
      uint8_t priv[NIUS_P256_PRIV], pub[NIUS_P256_PUB], sig[NIUS_P256_SIG];
      Crypto.ecdsaGenerateKey(priv, pub);
      Crypto.ecdsaSignMessage(priv, msg, msgLen, sig);   // hash + sign
      Crypto.ecdsaVerifyMessage(pub, msg, msgLen, sig);

      uint8_t xPub[NIUS_X25519_KEY];
      Crypto.x25519GenerateKey(priv32, xPub);
      Crypto.x25519Shared(priv32, peerPub32, shared32);

      uint8_t edSecret[NIUS_ED25519_SECRET], edPub[NIUS_ED25519_PUB];
      Crypto.ed25519GenerateKey(edSecret, edPub);
      Crypto.ed25519SignFromSeed(seed32, msg, msgLen, sig64);

  ECDSA / ECDH P-256, X25519 and Ed25519 require the vendored CC310 backend.
  On the on-chip fallback they return CryptoStatus::Unsupported.
  Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_ECC_H
#define NIUSCRYPTO_PUBLIC_ECC_H
#include "NiusCrypto.h"
#endif
