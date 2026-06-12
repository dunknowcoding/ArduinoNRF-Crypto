#ifndef NIUSCRYPTO_SOFTAES128_H
#define NIUSCRYPTO_SOFTAES128_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/CryptoTypes.h"

namespace ncrypto {

/** Software AES-128 block cipher (for OnChip CBC decrypt). */
class SoftAes128 {
 public:
  static void encryptBlock(const uint8_t key[kAes128KeyLen],
                           const uint8_t in[kAesBlockLen],
                           uint8_t out[kAesBlockLen]);
  static void decryptBlock(const uint8_t key[kAes128KeyLen],
                           const uint8_t in[kAesBlockLen],
                           uint8_t out[kAesBlockLen]);
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTAES128_H
