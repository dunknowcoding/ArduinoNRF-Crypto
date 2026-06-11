// OnChipBackend.cpp - AES via the ECB peripheral, random via the RNG TRNG,
// SHA-256 in software. See OnChipBackend.h for the capability rationale.

#include "OnChipBackend.h"

#include <NrfCrypto.h>       // NrfEcb (core)
#include <NrfPeripherals.h>  // NrfRng (core)

#include "SoftSha256.h"

namespace ncrypto {

namespace {
inline void xorBlock(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  for (size_t i = 0; i < kAesBlockLen; ++i) dst[i] = uint8_t(a[i] ^ b[i]);
}
// Big-endian +1 over the whole 16-byte counter block (AES-CTR convention).
inline void incrementCounter(uint8_t ctr[kAesBlockLen]) {
  for (int i = int(kAesBlockLen) - 1; i >= 0; --i) {
    if (++ctr[i] != 0) break;
  }
}
}  // namespace

bool OnChipBackend::begin() {
  // The ECB peripheral is always present; selfTest() confirms it actually
  // produces the FIPS-197 known answer before we rely on it.
  started_ = NrfEcb::selfTest();
  return started_;
}

CryptoStatus OnChipBackend::randomBytes(uint8_t* buf, size_t len) {
  NrfRng::randomBytes(buf, len);
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::sha256(const uint8_t* in, size_t len,
                                   uint8_t out[kSha256Len]) {
  SoftSha256::hash(in, len, out);
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::aes128CbcEncrypt(const uint8_t key[kAes128KeyLen],
                                             const uint8_t iv[kAesBlockLen],
                                             const uint8_t* in, uint8_t* out,
                                             size_t len) {
  uint8_t prev[kAesBlockLen];
  for (size_t i = 0; i < kAesBlockLen; ++i) prev[i] = iv[i];

  for (size_t off = 0; off < len; off += kAesBlockLen) {
    uint8_t x[kAesBlockLen];
    xorBlock(x, in + off, prev);          // P_i XOR C_{i-1}
    if (!NrfEcb::encrypt(key, x, out + off)) return CryptoStatus::InternalError;
    for (size_t i = 0; i < kAesBlockLen; ++i) prev[i] = out[off + i];  // C_i
  }
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::aes128Ctr(const uint8_t key[kAes128KeyLen],
                                      const uint8_t iv[kAesBlockLen],
                                      const uint8_t* in, uint8_t* out,
                                      size_t len) {
  uint8_t ctr[kAesBlockLen];
  for (size_t i = 0; i < kAesBlockLen; ++i) ctr[i] = iv[i];

  uint8_t ks[kAesBlockLen];
  size_t off = 0;
  while (off < len) {
    if (!NrfEcb::encrypt(key, ctr, ks)) return CryptoStatus::InternalError;
    size_t n = len - off;
    if (n > kAesBlockLen) n = kAesBlockLen;
    for (size_t i = 0; i < n; ++i) out[off + i] = uint8_t(in[off + i] ^ ks[i]);
    incrementCounter(ctr);
    off += n;
  }
  return CryptoStatus::Ok;
}

}  // namespace ncrypto
