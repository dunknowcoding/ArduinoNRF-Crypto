/*
  CryptoEngine.h - The friendly front door of NiusCrypto.

  A sketch talks only to a CryptoEngine (the library ships a ready-made global
  named `Crypto`). begin() brings up the best backend available on this build:

      CC310 hardware  -> if the nrf_cc310 binary was vendored and the
                         CryptoCell powers up (full AES + SHA + ECC + TRNG).
      On-chip / sw    -> otherwise the nRF52840's ECB AES + RNG peripherals
                         plus a software SHA-256 (AES + hash + random only).

  Every call returns a CryptoStatus. Operations a backend cannot do return
  CryptoStatus::Unsupported (e.g. ECDSA on the on-chip fallback) rather than
  failing silently, so a sketch can branch on capability.
*/
#ifndef NIUSCRYPTO_CRYPTOENGINE_H
#define NIUSCRYPTO_CRYPTOENGINE_H

#include "CryptoBackend.h"
#include "CryptoTypes.h"

namespace ncrypto {

class CryptoEngine {
 public:
  /** Backend preference passed to begin(). */
  enum class Prefer : uint8_t {
    Auto = 0,   // CC310 if present, else on-chip (default)
    CC310,      // force CC310; begin() fails if the blob is absent
    OnChip,     // force the on-chip / software fallback
  };

  CryptoEngine() = default;

  /**
   * Bring up a backend. Returns true once one is running. With Prefer::Auto
   * this is essentially always true (the on-chip fallback needs no blob).
   */
  bool begin(Prefer prefer = Prefer::Auto);
  void end();

  /** True after a successful begin(). */
  bool started() const { return backend_ != nullptr; }

  /** Name of the active backend ("CC310", "OnChip") or "none". */
  const char* backendName() const;

  /** True if the active backend is a hardware accelerator (CC310). */
  bool isHardwareAccelerated() const;

  // ---- random ----
  CryptoStatus random(uint8_t* buf, size_t len);

  // ---- hash ----
  CryptoStatus sha256(const uint8_t* in, size_t len, uint8_t out[kSha256Len]);
  CryptoStatus sha512(const uint8_t* in, size_t len, uint8_t out[kSha512Len]);

  /**
   * HMAC-SHA-256 (RFC 2104). Uses the backend's hardware HMAC when available
   * (CC310), otherwise the software SoftSha256 path (always available).
   */
  CryptoStatus hmacSha256(const uint8_t* key, size_t keyLen,
                          const uint8_t* msg, size_t msgLen,
                          uint8_t out[kSha256Len]);

  // ---- AES-128 ----
  CryptoStatus aesCbcEncrypt(const uint8_t key[kAes128KeyLen],
                             const uint8_t iv[kAesBlockLen],
                             const uint8_t* in, uint8_t* out, size_t len);
  CryptoStatus aesCbcDecrypt(const uint8_t key[kAes128KeyLen],
                             const uint8_t iv[kAesBlockLen],
                             const uint8_t* in, uint8_t* out, size_t len);
  CryptoStatus aesCtr(const uint8_t key[kAes128KeyLen],
                      const uint8_t iv[kAesBlockLen],
                      const uint8_t* in, uint8_t* out, size_t len);

  // ---- AES-128-GCM (CC310 only) ----
  CryptoStatus aesGcmEncrypt(const uint8_t key[kAes128KeyLen],
                             const uint8_t iv[kGcmIvLen],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, uint8_t* out, size_t len,
                             uint8_t tag[kGcmTagLen]);
  CryptoStatus aesGcmDecrypt(const uint8_t key[kAes128KeyLen],
                             const uint8_t iv[kGcmIvLen],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, uint8_t* out, size_t len,
                             const uint8_t tag[kGcmTagLen]);

  // ---- ECDSA / ECDH P-256 (CC310 only) ----
  CryptoStatus ecdsaGenerateKey(uint8_t priv[kP256PrivLen],
                                uint8_t pub[kP256PubLen]);
  CryptoStatus ecdsaSign(const uint8_t priv[kP256PrivLen],
                         const uint8_t hash[kSha256Len],
                         uint8_t sig[kP256SigLen]);
  CryptoStatus ecdsaVerify(const uint8_t pub[kP256PubLen],
                           const uint8_t hash[kSha256Len],
                           const uint8_t sig[kP256SigLen]);
  CryptoStatus ecdhShared(const uint8_t priv[kP256PrivLen],
                          const uint8_t peerPub[kP256PubLen],
                          uint8_t shared[kP256SharedLen]);

  /** The active backend, or nullptr if not started (advanced use). */
  CryptoBackend* backend() const { return backend_; }

 private:
  CryptoBackend* backend_ = nullptr;
};

}  // namespace ncrypto

// A ready-to-use global instance, in the spirit of Arduino's Wire / SPI.
extern ncrypto::CryptoEngine Crypto;

#endif  // NIUSCRYPTO_CRYPTOENGINE_H
