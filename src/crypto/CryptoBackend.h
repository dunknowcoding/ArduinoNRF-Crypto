/*
  CryptoBackend.h - The one surface every crypto implementation provides.

  Just like ArduinoNRF-IMU funnels all chip traffic through a single IMUBus,
  NiusCrypto funnels every primitive through one CryptoBackend. A backend is a
  swappable implementation of the same operations:

    * CC310Backend  - the real Arm CryptoCell 310 hardware (needs the vendored
                      nrf_cc310 binary). Does everything below in hardware.
    * OnChipBackend - nRF52840 RNG + ECB AES (via core NrfCrypto), software
                      SHA/HMAC/HKDF, SoftAesGcm, SoftChaChaPoly. ECC/RSA
                      return Unsupported.

  CryptoEngine picks the best available backend at begin() and forwards to it,
  so a sketch never names a backend directly.

  Every operation has a default that returns Unsupported, so a backend only
  overrides what it can actually do. Implementations must assume begin() has
  already succeeded; CryptoEngine guards the not-started case.
*/
#ifndef NIUSCRYPTO_CRYPTOBACKEND_H
#define NIUSCRYPTO_CRYPTOBACKEND_H

#include "CryptoTypes.h"
#include "CryptoCapability.h"

namespace ncrypto {

class CryptoBackend {
 public:
  virtual ~CryptoBackend() = default;

  // ---- identity / lifecycle ----

  /** Short backend name, e.g. "CC310" or "OnChip". */
  virtual const char* name() const = 0;

  /** Bring the backend up. Returns false if its hardware is absent. */
  virtual bool begin() = 0;

  /** Release any resources. Safe to call when not started. */
  virtual void end() {}

  /** True if the work is done by a dedicated hardware accelerator. */
  virtual bool hardwareAccelerated() const = 0;

  /** True when this backend implements the given capability on this build. */
  virtual bool supportsCapability(CryptoCapability cap) const {
    (void)cap;
    return false;
  }

  // ---- random ----

  virtual CryptoStatus randomBytes(uint8_t* buf, size_t len) {
    (void)buf; (void)len; return CryptoStatus::Unsupported;
  }

  // ---- hash ----

  virtual CryptoStatus sha256(const uint8_t* in, size_t len,
                              uint8_t out[kSha256Len]) {
    (void)in; (void)len; (void)out; return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus sha384(const uint8_t* in, size_t len,
                              uint8_t out[kSha384Len]) {
    (void)in; (void)len; (void)out; return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus sha512(const uint8_t* in, size_t len,
                              uint8_t out[kSha512Len]) {
    (void)in; (void)len; (void)out; return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                                  const uint8_t* salt, size_t saltLen,
                                  const uint8_t* info, size_t infoLen,
                                  uint8_t* okm, size_t okmLen) {
    (void)ikm; (void)ikmLen; (void)salt; (void)saltLen;
    (void)info; (void)infoLen; (void)okm; (void)okmLen;
    return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus hmacSha256(const uint8_t* key, size_t keyLen,
                                  const uint8_t* msg, size_t msgLen,
                                  uint8_t out[kSha256Len]) {
    (void)key; (void)keyLen; (void)msg; (void)msgLen; (void)out;
    return CryptoStatus::Unsupported;
  }

  // ---- AES-128 (CBC / CTR) ----
  // CBC requires len to be a multiple of 16. CTR is a stream (any length) and
  // the same call both encrypts and decrypts.

  virtual CryptoStatus aes128CbcEncrypt(const uint8_t key[kAes128KeyLen],
                                        const uint8_t iv[kAesBlockLen],
                                        const uint8_t* in, uint8_t* out,
                                        size_t len) {
    (void)key; (void)iv; (void)in; (void)out; (void)len;
    return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus aes128CbcDecrypt(const uint8_t key[kAes128KeyLen],
                                        const uint8_t iv[kAesBlockLen],
                                        const uint8_t* in, uint8_t* out,
                                        size_t len) {
    (void)key; (void)iv; (void)in; (void)out; (void)len;
    return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus aes128Ctr(const uint8_t key[kAes128KeyLen],
                                 const uint8_t iv[kAesBlockLen],
                                 const uint8_t* in, uint8_t* out, size_t len) {
    (void)key; (void)iv; (void)in; (void)out; (void)len;
    return CryptoStatus::Unsupported;
  }

  // ---- AES-128-GCM (authenticated) ----

  virtual CryptoStatus aes128GcmEncrypt(const uint8_t key[kAes128KeyLen],
                                        const uint8_t iv[kGcmIvLen],
                                        const uint8_t* aad, size_t aadLen,
                                        const uint8_t* in, uint8_t* out,
                                        size_t len, uint8_t tag[kGcmTagLen]) {
    (void)key; (void)iv; (void)aad; (void)aadLen;
    (void)in; (void)out; (void)len; (void)tag;
    return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus aes128GcmDecrypt(const uint8_t key[kAes128KeyLen],
                                        const uint8_t iv[kGcmIvLen],
                                        const uint8_t* aad, size_t aadLen,
                                        const uint8_t* in, uint8_t* out,
                                        size_t len,
                                        const uint8_t tag[kGcmTagLen]) {
    (void)key; (void)iv; (void)aad; (void)aadLen;
    (void)in; (void)out; (void)len; (void)tag;
    return CryptoStatus::Unsupported;
  }

  // ---- ChaCha20-Poly1305 (authenticated) ----

  virtual CryptoStatus chachaPolyEncrypt(const uint8_t key[kChaPolyKeyLen],
                                         const uint8_t nonce[kChaPolyNonceLen],
                                         const uint8_t* aad, size_t aadLen,
                                         const uint8_t* in, uint8_t* out,
                                         size_t len,
                                         uint8_t tag[kChaPolyTagLen]) {
    (void)key; (void)nonce; (void)aad; (void)aadLen;
    (void)in; (void)out; (void)len; (void)tag;
    return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus chachaPolyDecrypt(const uint8_t key[kChaPolyKeyLen],
                                         const uint8_t nonce[kChaPolyNonceLen],
                                         const uint8_t* aad, size_t aadLen,
                                         const uint8_t* in, uint8_t* out,
                                         size_t len,
                                         const uint8_t tag[kChaPolyTagLen]) {
    (void)key; (void)nonce; (void)aad; (void)aadLen;
    (void)in; (void)out; (void)len; (void)tag;
    return CryptoStatus::Unsupported;
  }

  // ---- ECDSA / ECDH on NIST P-256 ----
  // Public keys are 64 bytes (X||Y), signatures 64 bytes (R||S), private
  // scalars 32 bytes, all big-endian. ecdsaP256Sign takes a 32-byte message
  // hash (typically SHA-256), not the raw message.

  virtual CryptoStatus ecdsaP256Sign(const uint8_t priv[kP256PrivLen],
                                     const uint8_t hash[kSha256Len],
                                     uint8_t sig[kP256SigLen]) {
    (void)priv; (void)hash; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus ecdsaP256Verify(const uint8_t pub[kP256PubLen],
                                       const uint8_t hash[kSha256Len],
                                       const uint8_t sig[kP256SigLen]) {
    (void)pub; (void)hash; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus ecdhP256Shared(const uint8_t priv[kP256PrivLen],
                                      const uint8_t peerPub[kP256PubLen],
                                      uint8_t shared[kP256SharedLen]) {
    (void)priv; (void)peerPub; (void)shared; return CryptoStatus::Unsupported;
  }

  /** Derive a fresh P-256 key pair (random scalar + its public point). */
  virtual CryptoStatus ecdsaP256GenerateKey(uint8_t priv[kP256PrivLen],
                                            uint8_t pub[kP256PubLen]) {
    (void)priv; (void)pub; return CryptoStatus::Unsupported;
  }

  // ---- X25519 (Curve25519 ECDH, CC310) ----

  virtual CryptoStatus x25519GenerateKey(uint8_t priv[kX25519KeyLen],
                                         uint8_t pub[kX25519KeyLen]) {
    (void)priv; (void)pub; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus x25519Shared(const uint8_t priv[kX25519KeyLen],
                                    const uint8_t peerPub[kX25519KeyLen],
                                    uint8_t shared[kX25519KeyLen]) {
    (void)priv; (void)peerPub; (void)shared; return CryptoStatus::Unsupported;
  }

  // ---- RSA-2048 PKCS#1 v1.5 + SHA-256 (CC310) ----
  // Use rsaGenerateKeyPair() for an explicit RsaKeyPair handle.

  virtual CryptoStatus rsaGenerateKeyPair(RsaKeyPair* key) {
    (void)key; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus rsaSignWithKeyPair(const RsaKeyPair* key,
                                          const uint8_t* msg, size_t msgLen,
                                          uint8_t sig[kRsa2048SigLen]) {
    (void)key; (void)msg; (void)msgLen; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus rsaVerifyWithKeyPair(const RsaKeyPair* key,
                                            const uint8_t* msg, size_t msgLen,
                                            const uint8_t sig[kRsa2048SigLen]) {
    (void)key; (void)msg; (void)msgLen; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus rsaVerifyWithPublicKey(const RsaPublicKey* pub,
                                              const uint8_t* msg, size_t msgLen,
                                              const uint8_t sig[kRsa2048SigLen]) {
    (void)pub; (void)msg; (void)msgLen; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus rsaExportPublicKey(const RsaKeyPair* key,
                                          RsaPublicKey* out) {
    (void)key; (void)out; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus rsaReleaseKeyPair(RsaKeyPair* key) {
    if (!key || !key->valid()) return CryptoStatus::BadParam;
    key->clear();
    return CryptoStatus::Ok;
  }

  /** Load an existing RSA-2048 private key into a backend slot (CC310 only). */
  virtual CryptoStatus rsaImportKeyPair(RsaKeyPair* key,
                                        const RsaPrivateKeyImport* material) {
    (void)key; (void)material;
    return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus rsaPssSignWithKeyPair(const RsaKeyPair* key,
                                             const uint8_t* msg, size_t msgLen,
                                             uint8_t sig[kRsa2048SigLen]) {
    (void)key; (void)msg; (void)msgLen; (void)sig;
    return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus rsaPssVerifyWithKeyPair(const RsaKeyPair* key,
                                               const uint8_t* msg, size_t msgLen,
                                               const uint8_t sig[kRsa2048SigLen]) {
    (void)key; (void)msg; (void)msgLen; (void)sig;
    return CryptoStatus::Unsupported;
  }

  virtual CryptoStatus rsaPssVerifyWithPublicKey(
      const RsaPublicKey* pub, const uint8_t* msg, size_t msgLen,
      const uint8_t sig[kRsa2048SigLen]) {
    (void)pub; (void)msg; (void)msgLen; (void)sig;
    return CryptoStatus::Unsupported;
  }

  // ---- Ed25519 (CC310) ----

  virtual CryptoStatus ed25519GenerateKey(uint8_t secret[kEd25519SecLen],
                                          uint8_t pub[kEd25519PubLen]) {
    (void)secret; (void)pub; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus ed25519DeriveFromSeed(const uint8_t seed[32],
                                             uint8_t secret[kEd25519SecLen],
                                             uint8_t pub[kEd25519PubLen]) {
    (void)seed; (void)secret; (void)pub; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus ed25519Sign(const uint8_t secret[kEd25519SecLen],
                                   const uint8_t* msg, size_t msgLen,
                                   uint8_t sig[kEd25519SigLen]) {
    (void)secret; (void)msg; (void)msgLen; (void)sig; return CryptoStatus::Unsupported;
  }
  virtual CryptoStatus ed25519Verify(const uint8_t pub[kEd25519PubLen],
                                     const uint8_t* msg, size_t msgLen,
                                     const uint8_t sig[kEd25519SigLen]) {
    (void)pub; (void)msg; (void)msgLen; (void)sig; return CryptoStatus::Unsupported;
  }
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOBACKEND_H
