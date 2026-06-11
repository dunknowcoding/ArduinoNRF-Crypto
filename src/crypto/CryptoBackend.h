/*
  CryptoBackend.h - The one surface every crypto implementation provides.

  Just like ArduinoNRF-IMU funnels all chip traffic through a single IMUBus,
  NiusCrypto funnels every primitive through one CryptoBackend. A backend is a
  swappable implementation of the same operations:

    * CC310Backend  - the real Arm CryptoCell 310 hardware (needs the vendored
                      nrf_cc310 binary). Does everything below in hardware.
    * OnChipBackend - the nRF52840's on-chip ECB AES peripheral (via the core's
                      NrfCrypto.h) and the RNG peripheral, plus a software
                      SHA-256. AES + hash + random only; ECC / GCM report
                      Unsupported.

  CryptoEngine picks the best available backend at begin() and forwards to it,
  so a sketch never names a backend directly.

  Every operation has a default that returns Unsupported, so a backend only
  overrides what it can actually do. Implementations must assume begin() has
  already succeeded; CryptoEngine guards the not-started case.
*/
#ifndef NIUSCRYPTO_CRYPTOBACKEND_H
#define NIUSCRYPTO_CRYPTOBACKEND_H

#include "CryptoTypes.h"

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

  // ---- random ----

  virtual CryptoStatus randomBytes(uint8_t* buf, size_t len) {
    (void)buf; (void)len; return CryptoStatus::Unsupported;
  }

  // ---- hash ----

  virtual CryptoStatus sha256(const uint8_t* in, size_t len,
                              uint8_t out[kSha256Len]) {
    (void)in; (void)len; (void)out; return CryptoStatus::Unsupported;
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
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOBACKEND_H
