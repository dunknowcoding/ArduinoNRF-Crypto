/*
  OnChipBackend.h - the no-blob fallback backend.

  Uses only peripherals that ship in the ArduinoNRF core, so it works on every
  build with nothing vendored:

    * AES        - the ECB hardware peripheral (core NrfEcb), an encrypt-only
                   AES-128 block engine. From it this backend builds CTR (a
                   symmetric stream cipher - encrypt and decrypt are the same)
                   and CBC *encryption*. CBC *decryption* needs the AES inverse
                   cipher, which the ECB peripheral does not provide, so it
                   reports Unsupported here - use CTR, or the CC310 backend.
    * random     - the RNG hardware TRNG (core NrfRng).
    * SHA-256    - software (SoftSha256); the nRF52840 has no hardware SHA
                   outside the CryptoCell 310.

  GCM and the P-256 ECC operations need the CryptoCell 310 and report
  Unsupported on this backend.
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
  CryptoStatus sha384(const uint8_t* in, size_t len,
                      uint8_t out[kSha384Len]) override;
  CryptoStatus sha512(const uint8_t* in, size_t len,
                      uint8_t out[kSha512Len]) override;
  CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen) override;
  bool supportsCapability(CryptoCapability cap) const override;
  // GCM / ECC fall through to the base "Unsupported".

 private:
  bool started_ = false;
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_ONCHIPBACKEND_H
