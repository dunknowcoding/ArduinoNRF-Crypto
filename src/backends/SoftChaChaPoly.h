#ifndef NIUSCRYPTO_SOFTCHACHAPOLY_H
#define NIUSCRYPTO_SOFTCHACHAPOLY_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/CryptoTypes.h"

namespace ncrypto {

/** Software ChaCha20-Poly1305 AEAD (RFC 8439). */
class SoftChaChaPoly {
 public:
  static bool encrypt(const uint8_t key[kChaPolyKeyLen],
                      const uint8_t nonce[kChaPolyNonceLen],
                      const uint8_t* aad, size_t aadLen, const uint8_t* in,
                      uint8_t* out, size_t len, uint8_t tag[kChaPolyTagLen]);

  /** Returns false when the authentication tag does not match. */
  static bool decrypt(const uint8_t key[kChaPolyKeyLen],
                      const uint8_t nonce[kChaPolyNonceLen],
                      const uint8_t* aad, size_t aadLen, const uint8_t* in,
                      uint8_t* out, size_t len,
                      const uint8_t tag[kChaPolyTagLen]);
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTCHACHAPOLY_H
