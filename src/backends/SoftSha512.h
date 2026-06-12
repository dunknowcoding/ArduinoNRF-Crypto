/*
  SoftSha512.h - a tiny, self-contained SHA-512 / SHA-384 (FIPS 180-4).

  Software fallback for backends without hardware SHA-512 (e.g. OnChip). Same
  incremental (reset/update/finish) shape as SoftSha256 for engine use.

  Implementation is the standard public-domain construction; no heap, no
  globals, ~200 bytes of state per instance.
*/
#ifndef NIUSCRYPTO_SOFTSHA512_H
#define NIUSCRYPTO_SOFTSHA512_H

#include "../crypto/CryptoTypes.h"

#include <stddef.h>
#include <stdint.h>

namespace ncrypto {

class SoftSha512 {
 public:
  static constexpr size_t kDigestLen = kSha512Len;
  static constexpr size_t kBlockLen = 128;

  SoftSha512() { reset(); }

  /** Reset for SHA-512 (64-byte digest). */
  void reset();
  /** Reset for SHA-384 (48-byte digest). */
  void reset384();
  void update(const uint8_t* data, size_t len);
  /** Finish using the variant selected by reset() / reset384(). */
  void finish(uint8_t* out);

  /** One-shot SHA-512: hash(in,len) -> out. */
  static void hash(const uint8_t* in, size_t len, uint8_t out[kSha512Len]);
  static void hash384(const uint8_t* in, size_t len, uint8_t out[kSha384Len]);
  static void hash512(const uint8_t* in, size_t len, uint8_t out[kSha512Len]);

 private:
  void processBlock(const uint8_t* p);

  uint64_t state_[8];
  uint64_t bitLen_;
  uint8_t buffer_[kBlockLen];
  size_t bufferLen_;
  size_t digestLen_;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTSHA512_H
