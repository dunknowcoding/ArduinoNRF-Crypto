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
  hardware TRNG, SHA-256, SHA-512, AES-128 (CBC / CTR / GCM) and ECDSA / ECDH on
  NIST P-256.
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

  CryptoStatus randomBytes(uint8_t* buf, size_t len) override;
  CryptoStatus sha256(const uint8_t* in, size_t len,
                      uint8_t out[kSha256Len]) override;
  CryptoStatus sha512(const uint8_t* in, size_t len,
                      uint8_t out[kSha512Len]) override;
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

 private:
  bool started_ = false;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CC310BACKEND_H
