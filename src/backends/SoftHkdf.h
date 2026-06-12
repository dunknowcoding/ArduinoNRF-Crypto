#ifndef NIUSCRYPTO_SOFTHKDF_H
#define NIUSCRYPTO_SOFTHKDF_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/CryptoTypes.h"

namespace ncrypto {

/** RFC 5869 HKDF-SHA-256 (software). */
class SoftHkdf {
 public:
  static void hkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt,
                         size_t saltLen, const uint8_t* info, size_t infoLen,
                         uint8_t* okm, size_t okmLen);
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTHKDF_H
