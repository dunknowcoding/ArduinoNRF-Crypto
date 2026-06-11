/*
  SoftSha256.h - a tiny, self-contained SHA-256 (FIPS 180-4).

  Two jobs in this library:
    1. It is the hash for OnChipBackend (the nRF52840 has no hardware SHA - only
       the CryptoCell 310 does, which lives behind the vendored blob).
    2. It backs CryptoEngine's HMAC-SHA-256 with an incremental (init/update/
       finish) interface, so HMAC works on any backend and on inputs of any
       length without buffering the whole message.

  Implementation is the standard public-domain construction; no heap, no
  globals, ~200 bytes of state per instance.
*/
#ifndef NIUSCRYPTO_SOFTSHA256_H
#define NIUSCRYPTO_SOFTSHA256_H

#include <stddef.h>
#include <stdint.h>

namespace ncrypto {

class SoftSha256 {
 public:
  static constexpr size_t kDigestLen = 32;
  static constexpr size_t kBlockLen = 64;

  SoftSha256() { reset(); }

  void reset();
  void update(const uint8_t* data, size_t len);
  void finish(uint8_t out[kDigestLen]);

  /** One-shot convenience: hash(in,len) -> out. */
  static void hash(const uint8_t* in, size_t len, uint8_t out[kDigestLen]);

 private:
  void processBlock(const uint8_t* p);

  uint32_t state_[8];
  uint64_t bitLen_;
  uint8_t buffer_[kBlockLen];
  size_t bufferLen_;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_SOFTSHA256_H
