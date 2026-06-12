/*
  Aes.h - convenience forwarder for the AES API of NiusCrypto.

      #include <Aes.h>
      Crypto.aesCbcEncrypt(key, iv, in, out, len);   // len % 16 == 0
      Crypto.aesCtr(key, iv, in, out, len);          // any length, enc == dec
      Crypto.aesGcmEncrypt(key, iv, aad, aadLen, in, out, len, tag);

  Note: OnChip provides CBC encrypt/decrypt, CTR, and GCM (software). Same
  library as <NiusCrypto.h>.
*/
#ifndef NIUSCRYPTO_PUBLIC_AES_H
#define NIUSCRYPTO_PUBLIC_AES_H
#include "NiusCrypto.h"
#endif
