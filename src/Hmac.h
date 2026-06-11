/*
  Hmac.h - convenience forwarder for the HMAC API of NiusCrypto.

      #include <Hmac.h>
      uint8_t mac[32];
      Crypto.hmacSha256(key, keyLen, msg, msgLen, mac);

  HMAC-SHA-256 works on every backend (it is built on SHA-256). Same library as
  <NiusCrypto.h>, named by topic.
*/
#ifndef NIUSCRYPTO_PUBLIC_HMAC_H
#define NIUSCRYPTO_PUBLIC_HMAC_H
#include "NiusCrypto.h"
#endif
