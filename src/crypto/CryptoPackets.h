/*
  CryptoPackets.h - grouped parameter structs for common crypto operations.

  Each struct bundles the inputs and outputs of one logical operation so a
  sketch reads like plain English: fill in the message, call seal() or open(),
  inspect the result. Pointer fields may be null only when the matching length
  is zero.

  These types are views: they never own heap memory. The caller supplies all
  buffers (plaintext, ciphertext, tags, digests).

  Every struct provides reset() to zero all fields before reuse. Low-level
  CryptoEngine methods (ecdsaSign with a raw hash, aesGcmEncrypt with separate
  pointers, etc.) remain available for advanced control.
*/
#ifndef NIUSCRYPTO_CRYPTOPACKETS_H
#define NIUSCRYPTO_CRYPTOPACKETS_H

#include "CryptoTypes.h"

namespace ncrypto {

/**
 * AES-128-GCM authenticated encryption (NIST SP 800-38D).
 *
 * Typical seal (encrypt) flow:
 *   msg.input  = plaintext;  msg.output = ciphertext buffer;
 *   Crypto.aesGcmSeal(msg)  -> fills msg.output and msg.authenticationTag
 *
 * Typical open (decrypt) flow:
 *   msg.input  = ciphertext;  msg.output = plaintext buffer;
 *   copy the received tag into msg.authenticationTag first;
 *   Crypto.aesGcmOpen(msg)  -> AuthFailed if the tag does not match
 */
struct AesGcmMessage {
  uint8_t key[kAes128KeyLen] = {};
  uint8_t nonce[kGcmIvLen] = {};

  /** Extra bytes authenticated but not encrypted (e.g. packet headers). */
  const uint8_t* authenticatedData = nullptr;
  size_t authenticatedDataLen = 0;

  /** Plaintext when sealing; ciphertext when opening. */
  const uint8_t* input = nullptr;
  size_t inputLen = 0;

  /** Ciphertext when sealing; recovered plaintext when opening. */
  uint8_t* output = nullptr;

  /** Written by seal(); must be supplied unchanged to open(). */
  uint8_t authenticationTag[kGcmTagLen] = {};

  /** Zero every field so the struct can be filled again for a new operation. */
  void reset() { *this = AesGcmMessage{}; }
};

/**
 * AES-128-CBC (length must be a multiple of 16 — no automatic padding).
 * Prefer AES-GCM or ChaCha20-Poly1305 for arbitrary-length payloads.
 */
struct AesCbcMessage {
  uint8_t key[kAes128KeyLen] = {};
  uint8_t iv[kAesBlockLen] = {};

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;

  void reset() { *this = AesCbcMessage{}; }
};

/** AES-128-CTR stream cipher (encrypt and decrypt are the same transform). */
struct AesCtrMessage {
  uint8_t key[kAes128KeyLen] = {};
  uint8_t iv[kAesBlockLen] = {};

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;

  void reset() { *this = AesCtrMessage{}; }
};

/** ChaCha20-Poly1305 AEAD (RFC 8439). Same seal/open pattern as AesGcmMessage. */
struct ChaChaPolyMessage {
  uint8_t key[kChaPolyKeyLen] = {};
  uint8_t nonce[kChaPolyNonceLen] = {};

  const uint8_t* authenticatedData = nullptr;
  size_t authenticatedDataLen = 0;

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;

  uint8_t authenticationTag[kChaPolyTagLen] = {};

  void reset() { *this = ChaChaPolyMessage{}; }
};

/** HMAC-SHA-256 (RFC 2104). The mac[] field receives the 32-byte result. */
struct HmacMessage {
  const uint8_t* key = nullptr;
  size_t keyLen = 0;
  const uint8_t* message = nullptr;
  size_t messageLen = 0;
  uint8_t mac[kSha256Len] = {};

  void reset() { *this = HmacMessage{}; }
};

/** SHA-256 digest. The digest[] field receives the 32-byte hash. */
struct Sha256Message {
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  uint8_t digest[kSha256Len] = {};

  void reset() { *this = Sha256Message{}; }
};

/**
 * ECDSA over NIST P-256 with SHA-256 message hashing (CC310 only).
 *
 * Sign:
 *   Crypto.ecdsaGenerateKey(msg);          // fills privateKey + publicKey
 *   msg.payload = bytes;  msg.payloadLen = len;
 *   Crypto.ecdsaSign(msg);                 // fills signature[]
 *
 * Verify:
 *   msg.publicKey = peer key;  msg.payload = bytes;  copy signature in;
 *   Crypto.ecdsaVerify(msg);
 *
 * Advanced — sign or verify a precomputed 32-byte digest (skips SHA-256):
 *   msg.hashOverride = digest32;
 *   Crypto.ecdsaSign(msg) / Crypto.ecdsaVerify(msg);
 *
 * Raw hash API still available: Crypto.ecdsaSign(priv, hash, sig).
 */
struct EcdsaMessage {
  uint8_t privateKey[kP256PrivLen] = {};
  uint8_t publicKey[kP256PubLen] = {};

  /** Bytes to hash with SHA-256 before sign/verify. Ignored when hashOverride is set. */
  const uint8_t* payload = nullptr;
  size_t payloadLen = 0;

  /**
   * Optional advanced path: 32-byte digest to sign/verify directly.
   * When non-null, payload is ignored and no internal SHA-256 is performed.
   */
  const uint8_t* hashOverride = nullptr;

  uint8_t signature[kP256SigLen] = {};

  void reset() { *this = EcdsaMessage{}; }
};

/**
 * Ed25519 sign/verify (CC310 only).
 *
 * Sign (random key):
 *   Crypto.ed25519GenerateKey(msg);   // fills secret[] + publicKey[]
 *   msg.payload = bytes;
 *   Crypto.ed25519Sign(msg);
 *
 * Sign (from 32-byte seed):
 *   msg.useSeed = true;  memcpy(msg.seed, ...);
 *   Crypto.ed25519Sign(msg);
 *
 * Verify:
 *   msg.publicKey = signer;  msg.payload = bytes;  copy signature in;
 *   Crypto.ed25519Verify(msg);
 *
 * Low-level API: Crypto.ed25519Sign(secret64, msg, len, sig).
 */
struct Ed25519Message {
  /** Full 64-byte secret (seed || public key) after generate or derive. */
  uint8_t secret[kEd25519SecLen] = {};
  uint8_t publicKey[kEd25519PubLen] = {};

  /**
   * When true, ed25519Sign() uses seed[] only (32 bytes) and ignores secret[].
   * Useful for deterministic keys from a stored seed.
   */
  bool useSeed = false;
  uint8_t seed[kEd25519SeedLen] = {};

  const uint8_t* payload = nullptr;
  size_t payloadLen = 0;

  uint8_t signature[kEd25519SigLen] = {};

  void reset() { *this = Ed25519Message{}; }
};

/** SHA-384 digest packet. */
struct Sha384Message {
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  uint8_t digest[kSha384Len] = {};
  void reset() { *this = Sha384Message{}; }
};

/** SHA-512 digest packet. */
struct Sha512Message {
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  uint8_t digest[kSha512Len] = {};
  void reset() { *this = Sha512Message{}; }
};

/** HKDF-SHA-256 (RFC 5869) key derivation packet. */
struct HkdfMessage {
  const uint8_t* ikm = nullptr;
  size_t ikmLen = 0;
  const uint8_t* salt = nullptr;
  size_t saltLen = 0;
  const uint8_t* info = nullptr;
  size_t infoLen = 0;
  uint8_t* okm = nullptr;
  size_t okmLen = 0;
  void reset() { *this = HkdfMessage{}; }
};

/**
 * X25519 key agreement (CC310 only). Keys are 32 bytes, little-endian.
 *
 *   Crypto.x25519GenerateKey(msg);
 *   msg.peerPublicKey = remotePub;
 *   Crypto.x25519Shared(msg);
 */
struct X25519Message {
  uint8_t privateKey[kX25519KeyLen] = {};
  uint8_t publicKey[kX25519KeyLen] = {};
  uint8_t peerPublicKey[kX25519KeyLen] = {};
  uint8_t sharedSecret[kX25519KeyLen] = {};
  void reset() { *this = X25519Message{}; }
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOPACKETS_H
