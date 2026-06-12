/*
  OnChipBackend.h - the no-blob fallback backend.

  Uses peripherals from the ArduinoNRF core plus compact software fallbacks:

    * AES        - ECB peripheral for CTR/CBC encrypt; SoftAes128 for CBC decrypt
    * AEAD       - SoftAesGcm, SoftChaChaPoly (software)
    * random     - nRF52840 RNG
    * SHA/HMAC/HKDF - software (SoftSha256, SoftSha512, SoftHkdf)

  P-256 / X25519 / Ed25519 / RSA require CC310 and report Unsupported here.
*/
#ifndef NIUSCRYPTO_ONCHIPBACKEND_H
#define NIUSCRYPTO_ONCHIPBACKEND_H

#include "../crypto/CryptoBackend.h"
#include "../crypto/CryptoCapability.h"

namespace ncrypto {

class OnChipBackend : public CryptoBackend {
 public:
  const char* name() const override { return "OnChip"; }
  bool begin() override;
  bool hardwareAccelerated() const override { return false; }

  CryptoStatus randomBytes(uint8_t* buf, size_t len) override;
  CryptoStatus sha256(const uint8_t* in, size_t len,
                      uint8_t out[kSha256Len]) override;

  CryptoStatus aes128CbcEncrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kAesBlockLen],
                                const uint8_t* in, uint8_t* out,
                                size_t len) override;
  CryptoStatus aes128Ctr(const uint8_t key[kAes128KeyLen],
                         const uint8_t iv[kAesBlockLen],
                         const uint8_t* in, uint8_t* out, size_t len) override;
  CryptoStatus aes128CbcDecrypt(const uint8_t key[kAes128KeyLen],
                                const uint8_t iv[kAesBlockLen],
                                const uint8_t* in, uint8_t* out,
                                size_t len) override;
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
  CryptoStatus sha384(const uint8_t* in, size_t len,
                      uint8_t out[kSha384Len]) override;
  CryptoStatus sha512(const uint8_t* in, size_t len,
                      uint8_t out[kSha512Len]) override;
  CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen) override;
  bool supportsCapability(CryptoCapability cap) const override;

 private:
  bool started_ = false;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_ONCHIPBACKEND_H
