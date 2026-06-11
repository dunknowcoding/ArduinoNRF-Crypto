/*
  ArduinoNRF_Crypto.h - framework umbrella for the NiusCrypto library.

  Include this only if you want the building blocks (status type, the backend
  interface, the engine) without the ready-made global - for instance when
  writing your own backend. Most sketches include <NiusCrypto.h> instead, which
  also gives you the global `Crypto` object.
*/
#ifndef ARDUINONRF_CRYPTO_H
#define ARDUINONRF_CRYPTO_H

#define ARDUINONRF_CRYPTO_VERSION_MAJOR 0
#define ARDUINONRF_CRYPTO_VERSION_MINOR 1
#define ARDUINONRF_CRYPTO_VERSION_PATCH 0
#define ARDUINONRF_CRYPTO_VERSION "0.1.0"

#include "crypto/CryptoTypes.h"
#include "crypto/CryptoBackend.h"
#include "crypto/CryptoEngine.h"

#endif  // ARDUINONRF_CRYPTO_H
