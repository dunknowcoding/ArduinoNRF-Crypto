/*
  NiusCrypto.h - the one header most sketches include.

      #include <NiusCrypto.h>

      void setup() {
        Crypto.begin();                       // CC310 if vendored, else on-chip
        uint8_t digest[32];
        Crypto.sha256((const uint8_t*)"hi", 2, digest);
      }

  It pulls in the engine and the ready-made global `Crypto`, and lifts the
  common names out of the ncrypto namespace so you can write CryptoStatus
  directly. For the framework pieces alone, include <ArduinoNRF_Crypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_H
#define NIUSCRYPTO_PUBLIC_H

#include "ArduinoNRF_Crypto.h"

using ncrypto::CryptoEngine;
using ncrypto::CryptoStatus;
using ncrypto::cryptoStatusName;

#endif  // NIUSCRYPTO_PUBLIC_H
