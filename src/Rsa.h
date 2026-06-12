/*
  Rsa.h - convenience forwarder for RSA PKCS#1 v1.5 + SHA-256 (2048-bit).

      #include <Rsa.h>
      Crypto.rsa2048GenerateKey();
      Crypto.rsaPkcs1Sha256Sign(msg, msgLen, sig256);
      Crypto.rsaPkcs1Sha256Verify(msg, msgLen, sig256);

  CC310 only; rsa2048GenerateKey stores the key pair inside the backend until
  the next generate call. Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_RSA_H
#define NIUSCRYPTO_PUBLIC_RSA_H
#include "NiusCrypto.h"
#endif
