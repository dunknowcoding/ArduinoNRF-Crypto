/*
  CryptoPackets.h - grouped parameter structs for common crypto operations.

  Each struct bundles the inputs and outputs of one logical operation so a
  sketch reads like plain English: fill in the message, call seal() or open(),
  inspect the result. Pointer fields may be null only when the matching length
  is zero.

  These types are views: they never own heap memory. The caller supplies all
  buffers (plaintext, ciphertext, tags, digests).
*/
#ifndef NIUSCRYPTO_CRYPTOPACKETS_H
#define NIUSCRYPTO_CRYPTOPACKETS_H

#include "CryptoTypes.h"

namespace ncrypto {

/**
 * AES-128-GCM authenticated encryption (NIST SP 800-38D).
 *
 * Typical seal (encrypt) flow:
 *   msg.input      = plaintext bytes
 *   msg.output     = buffer at least as large as msg.inputLen
 *   Crypto.aesGcmSeal(msg)  -> fills msg.output and msg.authenticationTag
 *
 * Typical open (decrypt) flow:
 *   msg.input      = ciphertext (same length as original plaintext)
 *   msg.output     = buffer for recovered plaintext
 *   memcpy(msg.authenticationTag, receivedTag, ...) before open
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
};

/**
 * AES-128-CBC encryption (no built-in padding — length must be a multiple of 16).
 *
 * Use aesCbcSeal to encrypt and aesCbcOpen to decrypt. For arbitrary-length
 * payloads, pad before sealing or prefer AES-GCM / ChaCha20-Poly1305.
 */
struct AesCbcMessage {
  uint8_t key[kAes128KeyLen] = {};
  uint8_t iv[kAesBlockLen] = {};

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;
};

/**
 * AES-128-CTR stream cipher (encrypt and decrypt are the same operation).
 *
 * Any byte length is allowed. Call aesCtrTransform once to encrypt and again
 * with the same key/nonce to decrypt.
 */
struct AesCtrMessage {
  uint8_t key[kAes128KeyLen] = {};
  uint8_t iv[kAesBlockLen] = {};

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;
};

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * Same seal/open pattern as AesGcmMessage. Requires the CC310/Oberon backend.
 */
struct ChaChaPolyMessage {
  uint8_t key[kChaPolyKeyLen] = {};
  uint8_t nonce[kChaPolyNonceLen] = {};

  const uint8_t* authenticatedData = nullptr;
  size_t authenticatedDataLen = 0;

  const uint8_t* input = nullptr;
  size_t inputLen = 0;
  uint8_t* output = nullptr;

  uint8_t authenticationTag[kChaPolyTagLen] = {};
};

/** HMAC-SHA-256 (RFC 2104). The mac[] field receives the 32-byte result. */
struct HmacMessage {
  const uint8_t* key = nullptr;
  size_t keyLen = 0;
  const uint8_t* message = nullptr;
  size_t messageLen = 0;
  uint8_t mac[kSha256Len] = {};
};

/** SHA-256 digest. The digest[] field receives the 32-byte hash. */
struct Sha256Message {
  const uint8_t* data = nullptr;
  size_t dataLen = 0;
  uint8_t digest[kSha256Len] = {};
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOPACKETS_H
