/*
  Rsa.h - convenience forwarder for RSA PKCS#1 v1.5 + SHA-256 (2048-bit).

      #include <Rsa.h>

      RsaKeyPair key;
      Crypto.rsaGenerate(&key);
      Crypto.rsaSign(&key, msg, msgLen, sig256);
      Crypto.rsaVerifyWithPubKey(&key.pub, msg, msgLen, sig256);

  Legacy (implicit key in slot 0):
      Crypto.rsa2048GenerateKey();
      Crypto.rsaPkcs1Sha256Sign(msg, msgLen, sig256);

  CC310 only. Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_RSA_H
#define NIUSCRYPTO_PUBLIC_RSA_H
#include "NiusCrypto.h"
#endif
