/*
  NiusCrypto.h - the one header most sketches include.

      #include <NiusCrypto.h>

      void setup() {
        Crypto.begin();
        uint8_t digest[NIUS_SHA256_BYTES];
        Crypto.sha256((const uint8_t*)"hi", 2, digest);
      }

  Packet-style API (grouped fields, seal/open naming):
      AesGcmMessage gcm;
      gcm.input = plaintext;  gcm.output = ciphertextBuffer;
      Crypto.aesGcmSeal(gcm);

  Buffer sizes — use NIUS_* macros in uint8_t buf[...] declarations.
  Check results with NIUS_OK(...) or cryptoOk(...).
*/
#ifndef NIUSCRYPTO_PUBLIC_H
#define NIUSCRYPTO_PUBLIC_H

#include "ArduinoNRF_Crypto.h"

// ---- Buffer size cheatsheet (match ncrypto::k* constants) ----
#define NIUS_SHA256_BYTES     32
#define NIUS_SHA384_BYTES     48
#define NIUS_SHA512_BYTES     64
#define NIUS_AES128_KEY       16
#define NIUS_AES_BLOCK        16
#define NIUS_GCM_IV           12
#define NIUS_GCM_TAG          16
#define NIUS_CHACHA_KEY       32
#define NIUS_CHACHA_NONCE     12
#define NIUS_CHACHA_TAG       16
#define NIUS_P256_PRIV        32
#define NIUS_P256_PUB         64
#define NIUS_P256_SIG         64
#define NIUS_P256_SHARED      32
#define NIUS_X25519_KEY       32
#define NIUS_ED25519_SEED     32
#define NIUS_ED25519_PUB      32
#define NIUS_ED25519_SECRET   64
#define NIUS_ED25519_SIG      64
#define NIUS_RSA2048_MOD      256
#define NIUS_RSA2048_SIG      256
#define NIUS_RSA_MAX_EXP      4

/** True when a CryptoStatus is CryptoStatus::Ok. */
#define NIUS_OK(status) ((status) == CryptoStatus::Ok)

using ncrypto::CryptoEngine;
using ncrypto::CryptoStatus;
using ncrypto::cryptoStatusName;
using ncrypto::RsaPublicKey;
using ncrypto::RsaKeyPair;
using ncrypto::AesGcmMessage;
using ncrypto::AesCbcMessage;
using ncrypto::AesCtrMessage;
using ncrypto::ChaChaPolyMessage;
using ncrypto::HmacMessage;
using ncrypto::Sha256Message;

inline bool cryptoOk(CryptoStatus s) { return s == CryptoStatus::Ok; }

#endif  // NIUSCRYPTO_PUBLIC_H
