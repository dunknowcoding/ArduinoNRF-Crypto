/*
  Rsa.h - convenience forwarder for RSA PKCS#1 v1.5 + SHA-256 (2048-bit).

      #include <Rsa.h>

      RsaKeyPair key;
      Crypto.rsaGenerate(&key);
      Crypto.rsaSign(&key, msg, msgLen, sig256);
      Crypto.rsaVerifyWithPubKey(&key.pub, msg, msgLen, sig256);
      Crypto.rsaRelease(&key);   // free the backend slot when finished

  CC310 only. Same library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_RSA_H
#define NIUSCRYPTO_PUBLIC_RSA_H
#include "NiusCrypto.h"
#endif
