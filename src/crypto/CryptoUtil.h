#ifndef NIUSCRYPTO_CRYPTOUTIL_H
#define NIUSCRYPTO_CRYPTOUTIL_H

#include <stddef.h>
#include <stdint.h>

namespace ncrypto {

/** Constant-time compare; returns true when a and b match over len bytes. */
bool secureEqual(const uint8_t* a, const uint8_t* b, size_t len);

/** Best-effort zeroization of sensitive buffer contents. */
void wipe(volatile uint8_t* buf, size_t len);

/**
 * PKCS#7 pad in-place. out must hold at least plainLen + blockSize bytes.
 * Returns padded length or 0 on BadParam (buffer too small / blockSize invalid).
 */
size_t pkcs7Pad(const uint8_t* plain, size_t plainLen, uint8_t* out,
                size_t outCap, size_t blockSize = 16);

/**
 * PKCS#7 unpad in-place. Returns unpadded length or 0 when padding is invalid.
 */
size_t pkcs7Unpad(uint8_t* buf, size_t len, size_t blockSize = 16);

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOUTIL_H
