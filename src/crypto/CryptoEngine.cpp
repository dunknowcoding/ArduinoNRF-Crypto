/*
  CryptoEngine.cpp - backend selection and forwarding.

  The two backends are static singletons: there is no heap use, and which one
  is active is just a pointer. CC310Backend self-disables (its begin() returns
  false) when the nrf_cc310 binary was not vendored, so Prefer::Auto cleanly
  falls through to the on-chip backend.
*/
#include "CryptoEngine.h"

#include "../backends/CC310Backend.h"
#include "../backends/OnChipBackend.h"
#include "../backends/SoftSha256.h"

namespace ncrypto {

namespace {
CC310Backend g_cc310;
OnChipBackend g_onchip;
}  // namespace

bool CryptoEngine::begin(Prefer prefer) {
  end();

  switch (prefer) {
    case Prefer::CC310:
      if (g_cc310.begin()) backend_ = &g_cc310;
      break;
    case Prefer::OnChip:
      if (g_onchip.begin()) backend_ = &g_onchip;
      break;
    case Prefer::Auto:
    default:
      if (g_cc310.begin()) {
        backend_ = &g_cc310;
      } else if (g_onchip.begin()) {
        backend_ = &g_onchip;
      }
      break;
  }
  return backend_ != nullptr;
}

void CryptoEngine::end() {
  if (backend_ != nullptr) {
    backend_->end();
    backend_ = nullptr;
  }
}

const char* CryptoEngine::backendName() const {
  return backend_ ? backend_->name() : "none";
}

bool CryptoEngine::isHardwareAccelerated() const {
  return backend_ && backend_->hardwareAccelerated();
}

// Forward to the active backend, guarding the not-started case.
#define NC_GUARD()                                   \
  do {                                               \
    if (backend_ == nullptr) return CryptoStatus::NotStarted; \
  } while (0)

CryptoStatus CryptoEngine::random(uint8_t* buf, size_t len) {
  NC_GUARD();
  if (buf == nullptr || len == 0) return CryptoStatus::BadParam;
  return backend_->randomBytes(buf, len);
}

CryptoStatus CryptoEngine::sha256(const uint8_t* in, size_t len,
                                  uint8_t out[kSha256Len]) {
  NC_GUARD();
  if (out == nullptr || (in == nullptr && len != 0)) return CryptoStatus::BadParam;
  return backend_->sha256(in, len, out);
}

CryptoStatus CryptoEngine::sha384(const uint8_t* in, size_t len,
                                  uint8_t out[kSha384Len]) {
  NC_GUARD();
  if (out == nullptr || (in == nullptr && len != 0)) return CryptoStatus::BadParam;
  return backend_->sha384(in, len, out);
}

CryptoStatus CryptoEngine::sha512(const uint8_t* in, size_t len,
                                  uint8_t out[kSha512Len]) {
  NC_GUARD();
  if (out == nullptr || (in == nullptr && len != 0)) return CryptoStatus::BadParam;
  return backend_->sha512(in, len, out);
}

CryptoStatus CryptoEngine::hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                                      const uint8_t* salt, size_t saltLen,
                                      const uint8_t* info, size_t infoLen,
                                      uint8_t* okm, size_t okmLen) {
  NC_GUARD();
  if (okm == nullptr || okmLen == 0) return CryptoStatus::BadParam;
  if (ikm == nullptr && ikmLen != 0) return CryptoStatus::BadParam;
  if (salt == nullptr && saltLen != 0) return CryptoStatus::BadParam;
  if (info == nullptr && infoLen != 0) return CryptoStatus::BadParam;
  return backend_->hkdfSha256(ikm, ikmLen, salt, saltLen, info, infoLen, okm,
                              okmLen);
}

CryptoStatus CryptoEngine::hmacSha256(const uint8_t* key, size_t keyLen,
                                      const uint8_t* msg, size_t msgLen,
                                      uint8_t out[kSha256Len]) {
  NC_GUARD();
  if (out == nullptr) return CryptoStatus::BadParam;
  if (key == nullptr && keyLen != 0) return CryptoStatus::BadParam;
  if (msg == nullptr && msgLen != 0) return CryptoStatus::BadParam;

  CryptoStatus hw = backend_->hmacSha256(key, keyLen, msg, msgLen, out);
  if (hw != CryptoStatus::Unsupported) return hw;

  SoftSha256::hmacSha256(key, keyLen, msg, msgLen, out);
  return CryptoStatus::Ok;
}

CryptoStatus CryptoEngine::aesCbcEncrypt(const uint8_t key[kAes128KeyLen],
                                         const uint8_t iv[kAesBlockLen],
                                         const uint8_t* in, uint8_t* out,
                                         size_t len) {
  NC_GUARD();
  if (!key || !iv || !in || !out) return CryptoStatus::BadParam;
  if ((len & 0xFU) != 0U) return CryptoStatus::BadParam;
  return backend_->aes128CbcEncrypt(key, iv, in, out, len);
}

CryptoStatus CryptoEngine::aesCbcDecrypt(const uint8_t key[kAes128KeyLen],
                                         const uint8_t iv[kAesBlockLen],
                                         const uint8_t* in, uint8_t* out,
                                         size_t len) {
  NC_GUARD();
  if (!key || !iv || !in || !out) return CryptoStatus::BadParam;
  if ((len & 0xFU) != 0U) return CryptoStatus::BadParam;
  return backend_->aes128CbcDecrypt(key, iv, in, out, len);
}

CryptoStatus CryptoEngine::aesCtr(const uint8_t key[kAes128KeyLen],
                                  const uint8_t iv[kAesBlockLen],
                                  const uint8_t* in, uint8_t* out, size_t len) {
  NC_GUARD();
  if (!key || !iv || !in || !out) return CryptoStatus::BadParam;
  return backend_->aes128Ctr(key, iv, in, out, len);
}

CryptoStatus CryptoEngine::aesGcmEncrypt(const uint8_t key[kAes128KeyLen],
                                         const uint8_t iv[kGcmIvLen],
                                         const uint8_t* aad, size_t aadLen,
                                         const uint8_t* in, uint8_t* out,
                                         size_t len, uint8_t tag[kGcmTagLen]) {
  NC_GUARD();
  if (!key || !iv || !tag) return CryptoStatus::BadParam;
  return backend_->aes128GcmEncrypt(key, iv, aad, aadLen, in, out, len, tag);
}

CryptoStatus CryptoEngine::aesGcmDecrypt(const uint8_t key[kAes128KeyLen],
                                         const uint8_t iv[kGcmIvLen],
                                         const uint8_t* aad, size_t aadLen,
                                         const uint8_t* in, uint8_t* out,
                                         size_t len,
                                         const uint8_t tag[kGcmTagLen]) {
  NC_GUARD();
  if (!key || !iv || !tag) return CryptoStatus::BadParam;
  return backend_->aes128GcmDecrypt(key, iv, aad, aadLen, in, out, len, tag);
}

CryptoStatus CryptoEngine::ecdsaGenerateKey(uint8_t priv[kP256PrivLen],
                                            uint8_t pub[kP256PubLen]) {
  NC_GUARD();
  if (!priv || !pub) return CryptoStatus::BadParam;
  return backend_->ecdsaP256GenerateKey(priv, pub);
}

CryptoStatus CryptoEngine::ecdsaSign(const uint8_t priv[kP256PrivLen],
                                     const uint8_t hash[kSha256Len],
                                     uint8_t sig[kP256SigLen]) {
  NC_GUARD();
  if (!priv || !hash || !sig) return CryptoStatus::BadParam;
  return backend_->ecdsaP256Sign(priv, hash, sig);
}

CryptoStatus CryptoEngine::ecdsaVerify(const uint8_t pub[kP256PubLen],
                                       const uint8_t hash[kSha256Len],
                                       const uint8_t sig[kP256SigLen]) {
  NC_GUARD();
  if (!pub || !hash || !sig) return CryptoStatus::BadParam;
  return backend_->ecdsaP256Verify(pub, hash, sig);
}

CryptoStatus CryptoEngine::ecdhShared(const uint8_t priv[kP256PrivLen],
                                      const uint8_t peerPub[kP256PubLen],
                                      uint8_t shared[kP256SharedLen]) {
  NC_GUARD();
  if (!priv || !peerPub || !shared) return CryptoStatus::BadParam;
  return backend_->ecdhP256Shared(priv, peerPub, shared);
}

}  // namespace ncrypto

ncrypto::CryptoEngine Crypto;
