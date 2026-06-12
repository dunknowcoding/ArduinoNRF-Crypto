// OnChipBackend.cpp - AES via the ECB peripheral, random via the RNG TRNG,
// SHA-256 in software. See OnChipBackend.h for the capability rationale.

#include "OnChipBackend.h"

#include <NrfCrypto.h>       // NrfEcb (core)
#include <NrfPeripherals.h>  // NrfRng (core)

#include "SoftAes128.h"
#include "SoftAesGcm.h"
#include "SoftChaChaPoly.h"
#include "SoftHkdf.h"
#include "SoftSha256.h"
#include "SoftSha512.h"

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

bool OnChipBackend::supportsCapability(CryptoCapability cap) const {
  if (!started_) return false;
  switch (cap) {
    case CryptoCapability::Random:
    case CryptoCapability::Sha256:
    case CryptoCapability::Sha384:
    case CryptoCapability::Sha512:
    case CryptoCapability::HmacSha256:
    case CryptoCapability::HkdfSha256:
    case CryptoCapability::AesCbcEncrypt:
    case CryptoCapability::AesCbcDecrypt:
    case CryptoCapability::AesCtr:
    case CryptoCapability::AesGcm:
    case CryptoCapability::ChaChaPoly:
    case CryptoCapability::Sha256Stream:
    case CryptoCapability::Sha384Stream:
    case CryptoCapability::Sha512Stream:
      return true;
    default:
      return false;
  }
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

CryptoStatus OnChipBackend::sha384(const uint8_t* in, size_t len,
                                   uint8_t out[kSha384Len]) {
  SoftSha512::hash384(in, len, out);
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::sha512(const uint8_t* in, size_t len,
                                   uint8_t out[kSha512Len]) {
  SoftSha512::hash512(in, len, out);
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                                         const uint8_t* salt, size_t saltLen,
                                         const uint8_t* info, size_t infoLen,
                                         uint8_t* okm, size_t okmLen) {
  SoftHkdf::hkdfSha256(ikm, ikmLen, salt, saltLen, info, infoLen, okm, okmLen);
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

CryptoStatus OnChipBackend::aes128CbcDecrypt(const uint8_t key[kAes128KeyLen],
                                             const uint8_t iv[kAesBlockLen],
                                             const uint8_t* in, uint8_t* out,
                                             size_t len) {
  uint8_t prev[kAesBlockLen];
  for (size_t i = 0; i < kAesBlockLen; ++i) prev[i] = iv[i];

  for (size_t off = 0; off < len; off += kAesBlockLen) {
    uint8_t block[kAesBlockLen];
    SoftAes128::decryptBlock(key, in + off, block);
    xorBlock(out + off, block, prev);
    for (size_t i = 0; i < kAesBlockLen; ++i) prev[i] = in[off + i];
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

CryptoStatus OnChipBackend::aes128GcmEncrypt(const uint8_t key[kAes128KeyLen],
                                             const uint8_t iv[kGcmIvLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len, uint8_t tag[kGcmTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!SoftAesGcm::encrypt(key, iv, aad, aadLen, in, out, len, tag))
    return CryptoStatus::BadParam;
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::aes128GcmDecrypt(const uint8_t key[kAes128KeyLen],
                                             const uint8_t iv[kGcmIvLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len,
                                             const uint8_t tag[kGcmTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!SoftAesGcm::decrypt(key, iv, aad, aadLen, in, out, len, tag))
    return CryptoStatus::AuthFailed;
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::chachaPolyEncrypt(
    const uint8_t key[kChaPolyKeyLen], const uint8_t nonce[kChaPolyNonceLen],
    const uint8_t* aad, size_t aadLen, const uint8_t* in, uint8_t* out,
    size_t len, uint8_t tag[kChaPolyTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!SoftChaChaPoly::encrypt(key, nonce, aad, aadLen, in, out, len, tag))
    return CryptoStatus::BadParam;
  return CryptoStatus::Ok;
}

CryptoStatus OnChipBackend::chachaPolyDecrypt(
    const uint8_t key[kChaPolyKeyLen], const uint8_t nonce[kChaPolyNonceLen],
    const uint8_t* aad, size_t aadLen, const uint8_t* in, uint8_t* out,
    size_t len, const uint8_t tag[kChaPolyTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!SoftChaChaPoly::decrypt(key, nonce, aad, aadLen, in, out, len, tag))
    return CryptoStatus::AuthFailed;
  return CryptoStatus::Ok;
}

}  // namespace ncrypto
