/*
  CryptoEngine.cpp - backend selection and forwarding.

  The two backends are static singletons: there is no heap use, and which one
  is active is just a pointer. CC310Backend self-disables (its begin() returns
  false) when the nrf_cc310 binary was not vendored, so Prefer::Auto cleanly
  falls through to the on-chip backend.
*/
#include "CryptoEngine.h"

#include <string.h>

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

CryptoStatus CryptoEngine::chachaPolyEncrypt(const uint8_t key[kChaPolyKeyLen],
                                             const uint8_t nonce[kChaPolyNonceLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len, uint8_t tag[kChaPolyTagLen]) {
  NC_GUARD();
  if (!key || !nonce || !tag) return CryptoStatus::BadParam;
  if (len != 0 && (!in || !out)) return CryptoStatus::BadParam;
  if (aadLen != 0 && aad == nullptr) return CryptoStatus::BadParam;
  return backend_->chachaPolyEncrypt(key, nonce, aad, aadLen, in, out, len,
                                     tag);
}

CryptoStatus CryptoEngine::chachaPolyDecrypt(const uint8_t key[kChaPolyKeyLen],
                                             const uint8_t nonce[kChaPolyNonceLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len,
                                             const uint8_t tag[kChaPolyTagLen]) {
  NC_GUARD();
  if (!key || !nonce || !tag) return CryptoStatus::BadParam;
  if (len != 0 && (!in || !out)) return CryptoStatus::BadParam;
  if (aadLen != 0 && aad == nullptr) return CryptoStatus::BadParam;
  return backend_->chachaPolyDecrypt(key, nonce, aad, aadLen, in, out, len,
                                     tag);
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

CryptoStatus CryptoEngine::x25519GenerateKey(uint8_t priv[kX25519KeyLen],
                                             uint8_t pub[kX25519KeyLen]) {
  NC_GUARD();
  if (!priv || !pub) return CryptoStatus::BadParam;
  return backend_->x25519GenerateKey(priv, pub);
}

CryptoStatus CryptoEngine::x25519Shared(const uint8_t priv[kX25519KeyLen],
                                        const uint8_t peerPub[kX25519KeyLen],
                                        uint8_t shared[kX25519KeyLen]) {
  NC_GUARD();
  if (!priv || !peerPub || !shared) return CryptoStatus::BadParam;
  return backend_->x25519Shared(priv, peerPub, shared);
}

CryptoStatus CryptoEngine::rsaGenerateKeyPair(RsaKeyPair* key) {
  NC_GUARD();
  if (!key) return CryptoStatus::BadParam;
  key->clear();
  CryptoStatus s = backend_->rsaGenerateKeyPair(key);
  return s;
}

CryptoStatus CryptoEngine::rsaSignWithKeyPair(const RsaKeyPair* key,
                                               const uint8_t* msg, size_t msgLen,
                                               uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!key || !key->valid() || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  return backend_->rsaSignWithKeyPair(key, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::rsaVerifyWithKeyPair(const RsaKeyPair* key,
                                                const uint8_t* msg, size_t msgLen,
                                                const uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!key || !key->valid() || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  return backend_->rsaVerifyWithKeyPair(key, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::rsaVerifyWithPublicKey(
    const RsaPublicKey* pub, const uint8_t* msg, size_t msgLen,
    const uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!pub || !sig || pub->modLen == 0 || pub->expLen == 0)
    return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  return backend_->rsaVerifyWithPublicKey(pub, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::rsaExportPublicKey(const RsaKeyPair* key,
                                              RsaPublicKey* out) {
  NC_GUARD();
  if (!key || !key->valid() || !out) return CryptoStatus::BadParam;
  return backend_->rsaExportPublicKey(key, out);
}

CryptoStatus CryptoEngine::rsa2048GenerateKey() {
  NC_GUARD();
  legacyRsa_.clear();
  CryptoStatus s = backend_->rsa2048GenerateKey();
  if (s != CryptoStatus::Ok) return s;
  legacyRsa_.slot = 0;
  return backend_->rsaExportPublicKey(&legacyRsa_, &legacyRsa_.pub);
}

CryptoStatus CryptoEngine::rsaPkcs1Sha256Sign(const uint8_t* msg, size_t msgLen,
                                               uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  if (legacyRsa_.valid())
    return backend_->rsaSignWithKeyPair(&legacyRsa_, msg, msgLen, sig);
  return backend_->rsaPkcs1Sha256Sign(msg, msgLen, sig);
}

CryptoStatus CryptoEngine::rsaPkcs1Sha256Verify(const uint8_t* msg, size_t msgLen,
                                                const uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  if (legacyRsa_.valid())
    return backend_->rsaVerifyWithKeyPair(&legacyRsa_, msg, msgLen, sig);
  return backend_->rsaPkcs1Sha256Verify(msg, msgLen, sig);
}

CryptoStatus CryptoEngine::rsa2048ExportPubKey(uint8_t mod[kRsa2048ModLen],
                                               uint16_t* modLen,
                                               uint8_t* pubExp,
                                               uint16_t* pubExpLen) {
  NC_GUARD();
  if (!mod || !modLen || !pubExp || !pubExpLen) return CryptoStatus::BadParam;
  if (legacyRsa_.valid()) {
    if (*pubExpLen < legacyRsa_.pub.expLen) return CryptoStatus::BadParam;
    memcpy(mod, legacyRsa_.pub.modulus, legacyRsa_.pub.modLen);
    memcpy(pubExp, legacyRsa_.pub.exponent, legacyRsa_.pub.expLen);
    *modLen = legacyRsa_.pub.modLen;
    *pubExpLen = legacyRsa_.pub.expLen;
    return CryptoStatus::Ok;
  }
  return backend_->rsa2048ExportPubKey(mod, modLen, pubExp, pubExpLen);
}

CryptoStatus CryptoEngine::rsaPkcs1Sha256VerifyPub(
    const uint8_t* mod, uint16_t modLen, const uint8_t* pubExp,
    uint16_t pubExpLen, const uint8_t* msg, size_t msgLen,
    const uint8_t sig[kRsa2048SigLen]) {
  NC_GUARD();
  if (!mod || !pubExp || !sig || modLen == 0 || pubExpLen == 0)
    return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  RsaPublicKey pub;
  if (modLen > kRsa2048ModLen || pubExpLen > kRsaMaxExpLen)
    return CryptoStatus::BadParam;
  memcpy(pub.modulus, mod, modLen);
  memcpy(pub.exponent, pubExp, pubExpLen);
  pub.modLen = modLen;
  pub.expLen = pubExpLen;
  return backend_->rsaVerifyWithPublicKey(&pub, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::ecdsaSignMessage(const uint8_t priv[kP256PrivLen],
                                            const uint8_t* msg, size_t msgLen,
                                            uint8_t sig[kP256SigLen]) {
  NC_GUARD();
  if (!priv || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  uint8_t hash[kSha256Len];
  CryptoStatus hs = sha256(msg, msgLen, hash);
  if (hs != CryptoStatus::Ok) return hs;
  return ecdsaSign(priv, hash, sig);
}

CryptoStatus CryptoEngine::ecdsaVerifyMessage(const uint8_t pub[kP256PubLen],
                                              const uint8_t* msg, size_t msgLen,
                                              const uint8_t sig[kP256SigLen]) {
  NC_GUARD();
  if (!pub || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  uint8_t hash[kSha256Len];
  CryptoStatus hs = sha256(msg, msgLen, hash);
  if (hs != CryptoStatus::Ok) return hs;
  return ecdsaVerify(pub, hash, sig);
}

CryptoStatus CryptoEngine::ed25519SignFromSeed(const uint8_t seed[kEd25519SeedLen],
                                               const uint8_t* msg, size_t msgLen,
                                               uint8_t sig[kEd25519SigLen]) {
  NC_GUARD();
  if (!seed || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  uint8_t secret[kEd25519SecLen], pub[kEd25519PubLen];
  CryptoStatus ds = ed25519DeriveFromSeed(seed, secret, pub);
  if (ds != CryptoStatus::Ok) return ds;
  return ed25519Sign(secret, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::ed25519GenerateKey(uint8_t secret[kEd25519SecLen],
                                            uint8_t pub[kEd25519PubLen]) {
  NC_GUARD();
  if (!secret || !pub) return CryptoStatus::BadParam;
  return backend_->ed25519GenerateKey(secret, pub);
}

CryptoStatus CryptoEngine::ed25519DeriveFromSeed(const uint8_t seed[32],
                                                 uint8_t secret[kEd25519SecLen],
                                                 uint8_t pub[kEd25519PubLen]) {
  NC_GUARD();
  if (!seed || !secret || !pub) return CryptoStatus::BadParam;
  return backend_->ed25519DeriveFromSeed(seed, secret, pub);
}

CryptoStatus CryptoEngine::ed25519Sign(const uint8_t secret[kEd25519SecLen],
                                       const uint8_t* msg, size_t msgLen,
                                       uint8_t sig[kEd25519SigLen]) {
  NC_GUARD();
  if (!secret || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  return backend_->ed25519Sign(secret, msg, msgLen, sig);
}

CryptoStatus CryptoEngine::ed25519Verify(const uint8_t pub[kEd25519PubLen],
                                         const uint8_t* msg, size_t msgLen,
                                         const uint8_t sig[kEd25519SigLen]) {
  NC_GUARD();
  if (!pub || !sig) return CryptoStatus::BadParam;
  if (msgLen != 0 && msg == nullptr) return CryptoStatus::BadParam;
  return backend_->ed25519Verify(pub, msg, msgLen, sig);
}

}  // namespace ncrypto

ncrypto::CryptoEngine Crypto;
