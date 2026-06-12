/*
  CC310Backend.h - the real Arm CryptoCell 310 hardware backend.

  This backend drives the nRF52840's CryptoCell 310 accelerator through
  Nordic's CRYS runtime (libnrf_cc310.a from the nRF5 SDK). That binary is NOT
  bundled; run vendor/tools/setup_vendored.py — see docs/VENDORING.md.

  Auto-detection: the .cpp compiles in real-hardware mode only when the
  vendored headers are present (checked with __has_include). Until then it
  compiles as a stub whose begin() returns false, so CryptoEngine's Prefer::Auto
  simply falls back to the on-chip backend and the whole library still builds.

  When active it provides the full CC310 feature set used by this library:
  hardware TRNG, SHA-256/384/512, HKDF-SHA-256, AES-128 (CBC / CTR / GCM),
  ChaCha20-Poly1305, X25519, RSA-2048, and ECDSA / ECDH on NIST P-256.
*/
#ifndef NIUSCRYPTO_CC310BACKEND_H
#define NIUSCRYPTO_CC310BACKEND_H

#include "../crypto/CryptoBackend.h"

namespace ncrypto {

class CC310Backend : public CryptoBackend {
 public:
  const char* name() const override { return "CC310"; }
  bool begin() override;
  void end() override;
  bool hardwareAccelerated() const override { return true; }
  bool supportsCapability(CryptoCapability cap) const override;

  CryptoStatus randomBytes(uint8_t* buf, size_t len) override;
  CryptoStatus sha256(const uint8_t* in, size_t len,
                      uint8_t out[kSha256Len]) override;
  CryptoStatus sha384(const uint8_t* in, size_t len,
                      uint8_t out[kSha384Len]) override;
  CryptoStatus sha512(const uint8_t* in, size_t len,
                      uint8_t out[kSha512Len]) override;
  CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen) override;
  CryptoStatus hmacSha256(const uint8_t* key, size_t keyLen,
                          const uint8_t* msg, size_t msgLen,
                          uint8_t out[kSha256Len]) override;

  CryptoStatus aes128CbcEncrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kAesBlockLen],
                                const uint8_t* in, uint8_t* out,
                                size_t len) override;
  CryptoStatus aes128CbcDecrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kAesBlockLen],
                                const uint8_t* in, uint8_t* out,
                                size_t len) override;
  CryptoStatus aes128Ctr(const uint8_t key[kAes128KeyLen],
                         const uint8_t iv[kAesBlockLen],
                         const uint8_t* in, uint8_t* out, size_t len) override;

  CryptoStatus aes128GcmEncrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kGcmIvLen],
                                const uint8_t* aad, size_t aadLen,
                                const uint8_t* in, uint8_t* out, size_t len,
                                uint8_t tag[kGcmTagLen]) override;
  CryptoStatus aes128GcmDecrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kGcmIvLen],
                                const uint8_t* aad, size_t aadLen,
                                const uint8_t* in, uint8_t* out, size_t len,
                                const uint8_t tag[kGcmTagLen]) override;

  CryptoStatus chachaPolyEncrypt(const uint8_t key[kChaPolyKeyLen],
                                 const uint8_t nonce[kChaPolyNonceLen],
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, uint8_t* out, size_t len,
                                 uint8_t tag[kChaPolyTagLen]) override;
  CryptoStatus chachaPolyDecrypt(const uint8_t key[kChaPolyKeyLen],
                                 const uint8_t nonce[kChaPolyNonceLen],
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, uint8_t* out, size_t len,
                                 const uint8_t tag[kChaPolyTagLen]) override;

  CryptoStatus ecdsaP256GenerateKey(uint8_t priv[kP256PrivLen],
                                    uint8_t pub[kP256PubLen]) override;
  CryptoStatus ecdsaP256Sign(const uint8_t priv[kP256PrivLen],
                             const uint8_t hash[kSha256Len],
                             uint8_t sig[kP256SigLen]) override;
  CryptoStatus ecdsaP256Verify(const uint8_t pub[kP256PubLen],
                               const uint8_t hash[kSha256Len],
                               const uint8_t sig[kP256SigLen]) override;
  CryptoStatus ecdhP256Shared(const uint8_t priv[kP256PrivLen],
                              const uint8_t peerPub[kP256PubLen],
                              uint8_t shared[kP256SharedLen]) override;

  CryptoStatus x25519GenerateKey(uint8_t priv[kX25519KeyLen],
                                 uint8_t pub[kX25519KeyLen]) override;
  CryptoStatus x25519Shared(const uint8_t priv[kX25519KeyLen],
                            const uint8_t peerPub[kX25519KeyLen],
                            uint8_t shared[kX25519KeyLen]) override;

  CryptoStatus rsaGenerateKeyPair(RsaKeyPair* key) override;
  CryptoStatus rsaSignWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                  size_t msgLen,
                                  uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaVerifyWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                    size_t msgLen,
                                    const uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaVerifyWithPublicKey(const RsaPublicKey* pub,
                                      const uint8_t* msg, size_t msgLen,
                                      const uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaExportPublicKey(const RsaKeyPair* key,
                                  RsaPublicKey* out) override;
  CryptoStatus rsaReleaseKeyPair(RsaKeyPair* key) override;
  CryptoStatus rsaImportKeyPair(RsaKeyPair* key,
                                const RsaPrivateKeyImport* material) override;
  CryptoStatus rsaPssSignWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                     size_t msgLen,
                                     uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaPssVerifyWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                       size_t msgLen,
                                       const uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaPssVerifyWithPublicKey(
      const RsaPublicKey* pub, const uint8_t* msg, size_t msgLen,
      const uint8_t sig[kRsa2048SigLen]) override;

  CryptoStatus rsa2048GenerateKey() override;
  CryptoStatus rsaPkcs1Sha256Sign(const uint8_t* msg, size_t msgLen,
                                  uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsaPkcs1Sha256Verify(const uint8_t* msg, size_t msgLen,
                                    const uint8_t sig[kRsa2048SigLen]) override;
  CryptoStatus rsa2048ExportPubKey(uint8_t mod[kRsa2048ModLen], uint16_t* modLen,
                                   uint8_t* pubExp, uint16_t* pubExpLen) override;
  CryptoStatus rsaPkcs1Sha256VerifyPub(const uint8_t* mod, uint16_t modLen,
                                       const uint8_t* pubExp, uint16_t pubExpLen,
                                       const uint8_t* msg, size_t msgLen,
                                       const uint8_t sig[kRsa2048SigLen]) override;

  CryptoStatus ed25519GenerateKey(uint8_t secret[kEd25519SecLen],
                                  uint8_t pub[kEd25519PubLen]) override;
  CryptoStatus ed25519DeriveFromSeed(const uint8_t seed[32],
                                     uint8_t secret[kEd25519SecLen],
                                     uint8_t pub[kEd25519PubLen]) override;
  CryptoStatus ed25519Sign(const uint8_t secret[kEd25519SecLen],
                           const uint8_t* msg, size_t msgLen,
                           uint8_t sig[kEd25519SigLen]) override;
  CryptoStatus ed25519Verify(const uint8_t pub[kEd25519PubLen],
                             const uint8_t* msg, size_t msgLen,
                             const uint8_t sig[kEd25519SigLen]) override;

 private:
  bool started_ = false;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CC310BACKEND_H
