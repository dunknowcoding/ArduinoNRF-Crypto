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
#include "CryptoCapability.h"
#include "CryptoBackendError.h"
#include "CryptoHash.h"
#include "CryptoTypes.h"
#include "CryptoPackets.h"
#include "CryptoUtil.h"

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

  /** True when the active backend implements cap (false if not started). */
  bool supports(CryptoCapability cap) const;

  /** Last backend error code (e.g. CRYS return value). Zero if none. */
  int32_t lastBackendError() const { return ncrypto::lastBackendError(); }

  // ---- utilities ----
  static bool secureEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    return ncrypto::secureEqual(a, b, len);
  }
  static void wipe(volatile uint8_t* buf, size_t len) { ncrypto::wipe(buf, len); }
  static size_t pkcs7Pad(const uint8_t* plain, size_t plainLen, uint8_t* out,
                         size_t outCap, size_t blockSize = kAesBlockLen) {
    return ncrypto::pkcs7Pad(plain, plainLen, out, outCap, blockSize);
  }
  static size_t pkcs7Unpad(uint8_t* buf, size_t len,
                           size_t blockSize = kAesBlockLen) {
    return ncrypto::pkcs7Unpad(buf, len, blockSize);
  }

  // ---- random ----
  CryptoStatus random(uint8_t* buf, size_t len);

  // ---- hash ----
  CryptoStatus sha256(const uint8_t* in, size_t len, uint8_t out[kSha256Len]);
  CryptoStatus sha384(const uint8_t* in, size_t len, uint8_t out[kSha384Len]);
  CryptoStatus sha512(const uint8_t* in, size_t len, uint8_t out[kSha512Len]);

  CryptoStatus sha256Begin(Sha256Context& ctx);
  CryptoStatus sha256Update(Sha256Context& ctx, const uint8_t* data, size_t len);
  CryptoStatus sha256Finish(Sha256Context& ctx, uint8_t out[kSha256Len]);
  CryptoStatus sha384Begin(Sha384Context& ctx);
  CryptoStatus sha384Update(Sha384Context& ctx, const uint8_t* data, size_t len);
  CryptoStatus sha384Finish(Sha384Context& ctx, uint8_t out[kSha384Len]);
  CryptoStatus sha512Begin(Sha512Context& ctx);
  CryptoStatus sha512Update(Sha512Context& ctx, const uint8_t* data, size_t len);
  CryptoStatus sha512Finish(Sha512Context& ctx, uint8_t out[kSha512Len]);

  /** HKDF-SHA-256 (RFC 5869). Software fallback on OnChip when needed. */
  CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen);

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

  // ---- AES-128-GCM ----
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

  /** Packet-style AES-GCM: encrypt plaintext into output + authenticationTag. */
  CryptoStatus aesGcmSeal(AesGcmMessage& msg);
  /** Packet-style AES-GCM: decrypt and verify authenticationTag. */
  CryptoStatus aesGcmOpen(AesGcmMessage& msg);

  CryptoStatus aesCbcSeal(AesCbcMessage& msg);
  CryptoStatus aesCbcOpen(AesCbcMessage& msg);
  CryptoStatus aesCtrTransform(AesCtrMessage& msg);

  /** ChaCha20-Poly1305 AEAD (RFC 8439). CC310/Oberon only; 12-byte nonce. */
  CryptoStatus chachaPolyEncrypt(const uint8_t key[kChaPolyKeyLen],
                                 const uint8_t nonce[kChaPolyNonceLen],
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, uint8_t* out, size_t len,
                                 uint8_t tag[kChaPolyTagLen]);
  CryptoStatus chachaPolyDecrypt(const uint8_t key[kChaPolyKeyLen],
                                 const uint8_t nonce[kChaPolyNonceLen],
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, uint8_t* out, size_t len,
                                 const uint8_t tag[kChaPolyTagLen]);

  CryptoStatus chachaPolySeal(ChaChaPolyMessage& msg);
  CryptoStatus chachaPolyOpen(ChaChaPolyMessage& msg);

  /** Convenience wrappers that fill HmacMessage.mac / Sha256Message.digest. */
  CryptoStatus hmacSha256(HmacMessage& msg);
  CryptoStatus sha256(Sha256Message& msg);
  CryptoStatus sha384(Sha384Message& msg);
  CryptoStatus sha512(Sha512Message& msg);
  CryptoStatus hkdfSha256(HkdfMessage& msg);

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

  /** Fill privateKey and publicKey inside msg (CC310 only). */
  CryptoStatus ecdsaGenerateKey(EcdsaMessage& msg);
  /** Sign msg.payload (SHA-256 + ECDSA) or msg.hashOverride (advanced). */
  CryptoStatus ecdsaSign(EcdsaMessage& msg);
  /** Verify msg.signature against msg.payload or msg.hashOverride. */
  CryptoStatus ecdsaVerify(EcdsaMessage& msg);

  /** X25519 (Curve25519 ECDH). CC310 only; 32-byte keys, LE byte order. */
  CryptoStatus x25519GenerateKey(uint8_t priv[kX25519KeyLen],
                                 uint8_t pub[kX25519KeyLen]);
  CryptoStatus x25519Shared(const uint8_t priv[kX25519KeyLen],
                           const uint8_t peerPub[kX25519KeyLen],
                           uint8_t shared[kX25519KeyLen]);

  CryptoStatus x25519GenerateKey(X25519Message& msg);
  CryptoStatus x25519Shared(X25519Message& msg);

  // ---- RSA-2048 (explicit key handle; CC310 only) ----
  CryptoStatus rsaGenerateKeyPair(RsaKeyPair* key);
  CryptoStatus rsaSignWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                  size_t msgLen, uint8_t sig[kRsa2048SigLen]);
  CryptoStatus rsaVerifyWithKeyPair(const RsaKeyPair* key, const uint8_t* msg,
                                    size_t msgLen,
                                    const uint8_t sig[kRsa2048SigLen]);
  CryptoStatus rsaVerifyWithPublicKey(const RsaPublicKey* pub,
                                      const uint8_t* msg, size_t msgLen,
                                      const uint8_t sig[kRsa2048SigLen]);
  CryptoStatus rsaExportPublicKey(const RsaKeyPair* key, RsaPublicKey* out);

  /**
   * Return an RSA backend slot held by key. Safe to call on an already-cleared
   * handle (returns BadParam). After success, key->valid() is false.
   */
  CryptoStatus rsaReleaseKeyPair(RsaKeyPair* key);

  /** Import RSA-2048 private key (modulus + exponents) into a backend slot. */
  CryptoStatus rsaImportKeyPair(RsaKeyPair* key,
                                const RsaPrivateKeyImport* material);

  CryptoStatus rsaPssSign(const RsaKeyPair* key, const uint8_t* msg,
                          size_t msgLen, uint8_t sig[kRsa2048SigLen]);
  CryptoStatus rsaPssVerify(const RsaKeyPair* key, const uint8_t* msg,
                            size_t msgLen, const uint8_t sig[kRsa2048SigLen]);
  CryptoStatus rsaPssVerifyWithPubKey(const RsaPublicKey* pub,
                                      const uint8_t* msg, size_t msgLen,
                                      const uint8_t sig[kRsa2048SigLen]);

  /** Friendly aliases (same behavior as the names above). */
  inline CryptoStatus rsaGenerate(RsaKeyPair* key) { return rsaGenerateKeyPair(key); }
  inline CryptoStatus rsaSign(const RsaKeyPair* key, const uint8_t* msg,
                              size_t msgLen, uint8_t sig[kRsa2048SigLen]) {
    return rsaSignWithKeyPair(key, msg, msgLen, sig);
  }
  inline CryptoStatus rsaVerify(const RsaKeyPair* key, const uint8_t* msg,
                                size_t msgLen, const uint8_t sig[kRsa2048SigLen]) {
    return rsaVerifyWithKeyPair(key, msg, msgLen, sig);
  }
  inline CryptoStatus rsaVerifyWithPubKey(const RsaPublicKey* pub,
                                          const uint8_t* msg, size_t msgLen,
                                          const uint8_t sig[kRsa2048SigLen]) {
    return rsaVerifyWithPublicKey(pub, msg, msgLen, sig);
  }
  inline CryptoStatus rsaExportPublic(const RsaKeyPair* key, RsaPublicKey* out) {
    return rsaExportPublicKey(key, out);
  }
  inline CryptoStatus rsaRelease(RsaKeyPair* key) { return rsaReleaseKeyPair(key); }
  inline CryptoStatus rsaImport(RsaKeyPair* key, const RsaPrivateKeyImport* mat) {
    return rsaImportKeyPair(key, mat);
  }

  /** Ed25519 sign/verify (CC310). secret is 64 bytes (CRYS seed||pub layout). */
  CryptoStatus ed25519GenerateKey(uint8_t secret[kEd25519SecLen],
                                  uint8_t pub[kEd25519PubLen]);
  CryptoStatus ed25519DeriveFromSeed(const uint8_t seed[32],
                                     uint8_t secret[kEd25519SecLen],
                                     uint8_t pub[kEd25519PubLen]);
  CryptoStatus ed25519Sign(const uint8_t secret[kEd25519SecLen],
                           const uint8_t* msg, size_t msgLen,
                           uint8_t sig[kEd25519SigLen]);
  CryptoStatus ed25519Verify(const uint8_t pub[kEd25519PubLen],
                             const uint8_t* msg, size_t msgLen,
                             const uint8_t sig[kEd25519SigLen]);

  /** Fill secret[] and publicKey[] inside msg (CC310 only). */
  CryptoStatus ed25519GenerateKey(Ed25519Message& msg);
  /** Sign msg.payload using secret[] or seed[] when msg.useSeed is true. */
  CryptoStatus ed25519Sign(Ed25519Message& msg);
  /** Verify msg.signature against msg.publicKey and msg.payload. */
  CryptoStatus ed25519Verify(Ed25519Message& msg);

  /** Hash message with SHA-256 then ECDSA P-256 sign (CC310 only). */
  CryptoStatus ecdsaSignMessage(const uint8_t priv[kP256PrivLen],
                                const uint8_t* msg, size_t msgLen,
                                uint8_t sig[kP256SigLen]);
  /** Hash message with SHA-256 then ECDSA P-256 verify (CC310 only). */
  CryptoStatus ecdsaVerifyMessage(const uint8_t pub[kP256PubLen],
                                  const uint8_t* msg, size_t msgLen,
                                  const uint8_t sig[kP256SigLen]);

  /** Derive Ed25519 key from 32-byte seed, then sign (CC310 only). */
  CryptoStatus ed25519SignFromSeed(const uint8_t seed[kEd25519SeedLen],
                                   const uint8_t* msg, size_t msgLen,
                                   uint8_t sig[kEd25519SigLen]);

  /** AEAD aliases (RFC 8439). */
  inline CryptoStatus chacha20Poly1305Seal(ChaChaPolyMessage& msg) {
    return chachaPolySeal(msg);
  }
  inline CryptoStatus chacha20Poly1305Open(ChaChaPolyMessage& msg) {
    return chachaPolyOpen(msg);
  }
  inline CryptoStatus chacha20Poly1305Encrypt(
      const uint8_t key[kChaPolyKeyLen], const uint8_t nonce[kChaPolyNonceLen],
      const uint8_t* aad, size_t aadLen, const uint8_t* in, uint8_t* out,
      size_t len, uint8_t tag[kChaPolyTagLen]) {
    return chachaPolyEncrypt(key, nonce, aad, aadLen, in, out, len, tag);
  }
  inline CryptoStatus chacha20Poly1305Decrypt(
      const uint8_t key[kChaPolyKeyLen], const uint8_t nonce[kChaPolyNonceLen],
      const uint8_t* aad, size_t aadLen, const uint8_t* in, uint8_t* out,
      size_t len, const uint8_t tag[kChaPolyTagLen]) {
    return chachaPolyDecrypt(key, nonce, aad, aadLen, in, out, len, tag);
  }

  /** Run built-in known-answer tests (same coverage as examples/CryptoSelfTest). */
  SelfTestReport runSelfTest();

  /** The active backend, or nullptr if not started (advanced use). */
  CryptoBackend* backend() const { return backend_; }

 private:
  CryptoBackend* backend_ = nullptr;
};

}  // namespace ncrypto

// A ready-to-use global instance, in the spirit of Arduino's Wire / SPI.
extern ncrypto::CryptoEngine Crypto;

#endif  // NIUSCRYPTO_CRYPTOENGINE_H
