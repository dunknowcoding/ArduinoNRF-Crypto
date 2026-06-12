#ifndef NIUSCRYPTO_SOFTAESGCM_H
#define NIUSCRYPTO_SOFTAESGCM_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/CryptoTypes.h"

namespace ncrypto {

/** Software AES-128-GCM (NIST SP 800-38D, 96-bit IV). */
class SoftAesGcm {
 public:
  static bool encrypt(const uint8_t key[kAes128KeyLen],
                      const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                      size_t aadLen, const uint8_t* in, uint8_t* out,
                      size_t len, uint8_t tag[kGcmTagLen]);

  /** Returns false when the authentication tag does not match. */
  static bool decrypt(const uint8_t key[kAes128KeyLen],
                      const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                      size_t aadLen, const uint8_t* in, uint8_t* out,
                      size_t len, const uint8_t tag[kGcmTagLen]);
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTAESGCM_H
