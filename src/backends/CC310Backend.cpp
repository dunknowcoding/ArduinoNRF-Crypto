/*
  CC310Backend.cpp - Arm CryptoCell 310 hardware backend (CRYS runtime).

  This backend drives the nRF52840's CryptoCell 310 through Nordic's classic
  CRYS runtime library (libnrf_cc310, from the nRF5 SDK). Unlike the nrfxlib
  "platform" library - which only exposes the TRNG and SHA-256 - the CRYS
  runtime runs the FULL suite on the hardware accelerator:

    random   -> CC310 CTR-DRBG seeded by the CryptoCell TRNG (CRYS_RND).
    sha256   -> CC310 SHA-256 engine (CRYS_HASH).
    AES      -> CC310 AES engine, CBC / CTR (SaSi_Aes).
    ECDSA    -> CC310 PKA: P-256 keygen / sign / verify (CRYS_ECDSA, CRYS_ECPKI).
    ECDH     -> CC310 PKA: P-256 shared secret (CRYS_ECDH_SVDP_DH).
    AES-GCM  -> Nordic Oberon (the CRYS runtime ships AES-CCM, not GCM).

  Auto-detection: the .cpp compiles in real-hardware mode only when the vendored
  CRYS headers are present (checked with __has_include). Run
  vendor/tools/import_cc310_sdk.py to vendor them from a local nRF5 SDK. Until
  then this compiles as a stub whose begin() returns false, so the engine's
  Prefer::Auto falls back to the on-chip backend and the library still builds.

  The CryptoCell DMAs from RAM only, so flash-resident inputs (e.g. const test
  vectors) are bounced through a RAM scratch buffer before being fed to the
  engine. Key/IV/hash/signature byte arrays are likewise copied to the stack.
*/
#include "CC310Backend.h"

#if __has_include("../cc310/sns_silib.h")
#define NIUS_CRYPTO_HAS_CC310 1
#else
#define NIUS_CRYPTO_HAS_CC310 0
#endif

#if NIUS_CRYPTO_HAS_CC310
#include <string.h>
#if __has_include(<nrf.h>)
#include <nrf.h>
#endif
#include "../cc310/sns_silib.h"
#include "../cc310/crys_rnd.h"
#include "../cc310/crys_hash.h"
#include "../cc310/crys_hmac.h"
#include "../cc310/crys_hkdf.h"
#include "../cc310/ssi_aes.h"
#include "../cc310/crys_ecpki_types.h"
#include "../cc310/crys_ecpki_domain.h"
#include "../cc310/crys_ecpki_build.h"
#include "../cc310/crys_ecpki_kg.h"
#include "../cc310/crys_ecpki_ecdsa.h"
#include "../cc310/crys_ecpki_dh.h"
#include "../cc310/ocrypto_aes_gcm.h"
#include "../cc310/ocrypto_sha384.h"
#endif

namespace ncrypto {

#if NIUS_CRYPTO_HAS_CC310

namespace {

// CC310 runtime random state (CTR-DRBG). Instantiated once in begin().
CRYS_RND_State_t g_rndState;

// Shared word-aligned scratch. During begin() it is the RND work buffer; after
// that it is reused as the DMA bounce buffer for hashing / AES of flash data
// (the two uses never overlap in time). Sized by the RND work buffer, which is
// the largest of the two.
uint32_t g_scratch[CRYS_RND_WORK_BUFFER_SIZE_WORDS];

inline uint8_t* scratchBytes() { return reinterpret_cast<uint8_t*>(g_scratch); }
constexpr size_t kScratchBytes = sizeof(g_scratch);

// Adapter: CRYS_RND_GenerateVector matches the work-function prototype the
// ECPKI primitives expect (CRYSError_t and uint32_t are the same type).
const SaSiRndGenerateVectWorkFunc_t kRndFunc =
    reinterpret_cast<SaSiRndGenerateVectWorkFunc_t>(CRYS_RND_GenerateVector);

inline const CRYS_ECPKI_Domain_t* p256() {
  return CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
}

CryptoStatus hashDigest(CRYS_HASH_OperationMode_t mode, size_t digestLen,
                        size_t blockBytes,
                        const uint8_t* in, size_t len, uint8_t* out) {
  CRYS_HASHUserContext_t ctx;
  if (CRYS_HASH_Init(&ctx, mode) != CRYS_OK)
    return CryptoStatus::InternalError;
  const size_t step =
      blockBytes > 0 ? (kScratchBytes / blockBytes) * blockBytes : kScratchBytes;
  uint8_t* bounce = scratchBytes();
  size_t off = 0;
  while (off < len) {
    size_t chunk = len - off;
    if (step > 0 && chunk > step) chunk = step;
    memcpy(bounce, in + off, chunk);
    if (CRYS_HASH_Update(&ctx, bounce, chunk) != CRYS_OK)
      return CryptoStatus::InternalError;
    off += chunk;
  }
  CRYS_HASH_Result_t res;
  if (CRYS_HASH_Finish(&ctx, res) != CRYS_OK) return CryptoStatus::InternalError;
  memcpy(out, res, digestLen);
  return CryptoStatus::Ok;
}

// AES via the CC310 engine, bouncing (possibly flash) input through RAM.
// CTR tolerates a non-block-multiple tail (zero-padded, extra output dropped);
// CBC requires a block-multiple length and is rejected otherwise upstream.
CryptoStatus aesRun(SaSiAesEncryptMode_t dir, SaSiAesOperationMode_t mode,
                    const uint8_t* key, const uint8_t* iv, const uint8_t* in,
                    uint8_t* out, size_t len) {
  uint8_t keyRam[kAes128KeyLen];
  uint8_t ivRam[kAesBlockLen];
  memcpy(keyRam, key, sizeof(keyRam));
  memcpy(ivRam, iv, sizeof(ivRam));

  SaSiAesUserContext_t ctx;
  if (SaSi_AesInit(&ctx, dir, mode, SASI_AES_PADDING_NONE) != 0)
    return CryptoStatus::InternalError;
  SaSiAesUserKeyData_t keyData;
  keyData.pKey = keyRam;
  keyData.keySize = kAes128KeyLen;
  if (SaSi_AesSetKey(&ctx, SASI_AES_USER_KEY, &keyData, sizeof(keyData)) != 0)
    return CryptoStatus::InternalError;
  if (SaSi_AesSetIv(&ctx, ivRam) != 0) return CryptoStatus::InternalError;

  // Split the scratch into an input and an output half (both block-aligned).
  const size_t half = ((kScratchBytes / 2) / kAesBlockLen) * kAesBlockLen;
  uint8_t* inBuf = scratchBytes();
  uint8_t* outBuf = scratchBytes() + half;

  CryptoStatus rc = CryptoStatus::Ok;
  size_t off = 0;
  while (off < len) {
    size_t real = len - off;
    if (real > half) real = half;
    size_t padded = (real + kAesBlockLen - 1) / kAesBlockLen * kAesBlockLen;
    memcpy(inBuf, in + off, real);
    if (padded > real) memset(inBuf + real, 0, padded - real);
    if (SaSi_AesBlock(&ctx, inBuf, padded, outBuf) != 0) {
      rc = CryptoStatus::InternalError;
      break;
    }
    memcpy(out + off, outBuf, real);
    off += real;
  }

  size_t outSize = kAesBlockLen;
  uint8_t fin[kAesBlockLen];
  SaSi_AesFinish(&ctx, 0, inBuf, 0, fin, &outSize);
  SaSi_AesFree(&ctx);
  return rc;
}

}  // namespace

bool CC310Backend::begin() {
  if (started_) return true;
#ifdef NRF_CRYPTOCELL
  NRF_CRYPTOCELL->ENABLE = 1;  // power up the CryptoCell wrapper
#endif
  if (SaSi_LibInit() != SA_SILIB_RET_OK) return false;
  CRYS_RND_WorkBuff_t* work = reinterpret_cast<CRYS_RND_WorkBuff_t*>(g_scratch);
  if (CRYS_RndInit(&g_rndState, work) != CRYS_OK) {
    SaSi_LibFini();
    return false;
  }
  started_ = true;
  return true;
}

void CC310Backend::end() {
  if (started_) {
    CRYS_RND_UnInstantiation(&g_rndState);
    SaSi_LibFini();
    started_ = false;
  }
}

CryptoStatus CC310Backend::randomBytes(uint8_t* buf, size_t len) {
  if (!started_) return CryptoStatus::NotStarted;
  while (len > 0) {
    uint16_t chunk = len > 0xFFFFu ? 0xFFFFu : static_cast<uint16_t>(len);
    if (CRYS_RND_GenerateVector(&g_rndState, chunk, buf) != CRYS_OK)
      return CryptoStatus::InternalError;
    buf += chunk;
    len -= chunk;
  }
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::sha256(const uint8_t* in, size_t len,
                                  uint8_t out[kSha256Len]) {
  if (!started_) return CryptoStatus::NotStarted;
  return hashDigest(CRYS_HASH_SHA256_mode, kSha256Len,
                    CRYS_HASH_BLOCK_SIZE_IN_BYTES, in, len, out);
}

CryptoStatus CC310Backend::sha384(const uint8_t* in, size_t len,
                                  uint8_t out[kSha384Len]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (out == nullptr || (in == nullptr && len != 0)) return CryptoStatus::BadParam;
  // CRYS SHA-384 is unreliable on nRF52840 (Nordic's nrf_crypto CC310 backend
  // omits it); use Oberon software, same library as AES-GCM.
  uint8_t* bounce = scratchBytes();
  size_t off = 0;
  ocrypto_sha384_ctx ctx;
  ocrypto_sha384_init(&ctx);
  while (off < len) {
    size_t chunk = len - off;
    if (chunk > kScratchBytes) chunk = kScratchBytes;
    memcpy(bounce, in + off, chunk);
    ocrypto_sha384_update(&ctx, bounce, chunk);
    off += chunk;
  }
  ocrypto_sha384_final(&ctx, out);
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::sha512(const uint8_t* in, size_t len,
                                  uint8_t out[kSha512Len]) {
  if (!started_) return CryptoStatus::NotStarted;
  return hashDigest(CRYS_HASH_SHA512_mode, kSha512Len,
                    CRYS_HASH_SHA512_BLOCK_SIZE_IN_BYTES, in, len, out);
}

CryptoStatus CC310Backend::hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                                      const uint8_t* salt, size_t saltLen,
                                      const uint8_t* info, size_t infoLen,
                                      uint8_t* okm, size_t okmLen) {
  if (!started_) return CryptoStatus::NotStarted;
  if (okm == nullptr || okmLen == 0) return CryptoStatus::BadParam;
  if (ikm == nullptr && ikmLen != 0) return CryptoStatus::BadParam;
  if (salt == nullptr && saltLen != 0) return CryptoStatus::BadParam;
  if (info == nullptr && infoLen != 0) return CryptoStatus::BadParam;
  if (okmLen > 255U * kSha256Len) return CryptoStatus::BadParam;
  if (ikmLen > 0xFFFFFFFFu) return CryptoStatus::BadParam;

  uint8_t ikmRam[CRYS_HKDF_MAX_HASH_KEY_SIZE_IN_BYTES];
  uint8_t* ikmPtr = ikmRam;
  if (ikmLen <= sizeof(ikmRam)) {
    if (ikmLen > 0) memcpy(ikmRam, ikm, ikmLen);
  } else {
    if (ikmLen > kScratchBytes) return CryptoStatus::BadParam;
    ikmPtr = scratchBytes();
    memcpy(ikmPtr, ikm, ikmLen);
  }

  uint8_t saltRam[CRYS_HKDF_MAX_HASH_KEY_SIZE_IN_BYTES];
  uint8_t* saltPtr = nullptr;
  if (saltLen > 0) {
    if (saltLen <= sizeof(saltRam)) {
      memcpy(saltRam, salt, saltLen);
      saltPtr = saltRam;
    } else {
      if (saltLen > kScratchBytes) return CryptoStatus::BadParam;
      saltPtr = scratchBytes();
      memcpy(saltPtr, salt, saltLen);
    }
  }

  uint8_t infoRam[CRYS_HKDF_MAX_HASH_KEY_SIZE_IN_BYTES];
  uint8_t* infoPtr = nullptr;
  if (infoLen > 0) {
    if (infoLen <= sizeof(infoRam)) {
      memcpy(infoRam, info, infoLen);
      infoPtr = infoRam;
    } else {
      if (infoLen > kScratchBytes) return CryptoStatus::BadParam;
      infoPtr = scratchBytes();
      memcpy(infoPtr, info, infoLen);
    }
  }

  if (CRYS_HKDF_KeyDerivFunc(CRYS_HKDF_HASH_SHA256_mode, saltPtr, saltLen,
                             ikmPtr, static_cast<uint32_t>(ikmLen), infoPtr,
                             static_cast<uint32_t>(infoLen), okm,
                             static_cast<uint32_t>(okmLen),
                             SASI_FALSE) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::hmacSha256(const uint8_t* key, size_t keyLen,
                                      const uint8_t* msg, size_t msgLen,
                                      uint8_t out[kSha256Len]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (out == nullptr) return CryptoStatus::BadParam;
  if (key == nullptr && keyLen != 0) return CryptoStatus::BadParam;
  if (msg == nullptr && msgLen != 0) return CryptoStatus::BadParam;
  if (keyLen > 0xFFFFu) return CryptoStatus::BadParam;

  uint8_t keyRam[CRYS_HMAC_KEY_SIZE_IN_BYTES];
  uint8_t* keyPtr = keyRam;
  uint16_t keySize = static_cast<uint16_t>(keyLen);
  if (keyLen <= sizeof(keyRam)) {
    memset(keyRam, 0, sizeof(keyRam));
    memcpy(keyRam, key, keyLen);
  } else {
    keyPtr = scratchBytes();
    memcpy(keyPtr, key, keyLen);
  }

  CRYS_HMACUserContext_t ctx;
  if (CRYS_HMAC_Init(&ctx, CRYS_HASH_SHA256_mode, keyPtr, keySize) != CRYS_OK)
    return CryptoStatus::InternalError;

  uint8_t* bounce = scratchBytes();
  size_t off = 0;
  while (off < msgLen) {
    size_t chunk = msgLen - off;
    if (chunk > kScratchBytes) chunk = kScratchBytes;
    memcpy(bounce, msg + off, chunk);
    if (CRYS_HMAC_Update(&ctx, bounce, chunk) != CRYS_OK)
      return CryptoStatus::InternalError;
    off += chunk;
  }

  CRYS_HASH_Result_t res;
  if (CRYS_HMAC_Finish(&ctx, res) != CRYS_OK) return CryptoStatus::InternalError;
  memcpy(out, res, kSha256Len);
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::aes128CbcEncrypt(const uint8_t key[kAes128KeyLen],
                                            const uint8_t iv[kAesBlockLen],
                                            const uint8_t* in, uint8_t* out,
                                            size_t len) {
  if (!started_) return CryptoStatus::NotStarted;
  if (len % kAesBlockLen) return CryptoStatus::BadParam;
  return aesRun(SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, key, iv, in, out, len);
}

CryptoStatus CC310Backend::aes128CbcDecrypt(const uint8_t key[kAes128KeyLen],
                                            const uint8_t iv[kAesBlockLen],
                                            const uint8_t* in, uint8_t* out,
                                            size_t len) {
  if (!started_) return CryptoStatus::NotStarted;
  if (len % kAesBlockLen) return CryptoStatus::BadParam;
  return aesRun(SASI_AES_DECRYPT, SASI_AES_MODE_CBC, key, iv, in, out, len);
}

CryptoStatus CC310Backend::aes128Ctr(const uint8_t key[kAes128KeyLen],
                                     const uint8_t iv[kAesBlockLen],
                                     const uint8_t* in, uint8_t* out,
                                     size_t len) {
  if (!started_) return CryptoStatus::NotStarted;
  return aesRun(SASI_AES_ENCRYPT, SASI_AES_MODE_CTR, key, iv, in, out, len);
}

CryptoStatus CC310Backend::aes128GcmEncrypt(const uint8_t key[kAes128KeyLen],
                                            const uint8_t iv[kGcmIvLen],
                                            const uint8_t* aad, size_t aadLen,
                                            const uint8_t* in, uint8_t* out,
                                            size_t len, uint8_t tag[kGcmTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  ocrypto_aes_gcm_encrypt(out, tag, kGcmTagLen, in, len, key, kAes128KeyLen, iv,
                          aad, aadLen);
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::aes128GcmDecrypt(const uint8_t key[kAes128KeyLen],
                                            const uint8_t iv[kGcmIvLen],
                                            const uint8_t* aad, size_t aadLen,
                                            const uint8_t* in, uint8_t* out,
                                            size_t len,
                                            const uint8_t tag[kGcmTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  int r = ocrypto_aes_gcm_decrypt(out, tag, kGcmTagLen, in, len, key,
                                  kAes128KeyLen, iv, aad, aadLen);
  return r == 0 ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::ecdsaP256GenerateKey(uint8_t priv[kP256PrivLen],
                                                uint8_t pub[kP256PubLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  static CRYS_ECPKI_UserPrivKey_t uPriv;
  static CRYS_ECPKI_UserPublKey_t uPub;
  static CRYS_ECPKI_KG_TempData_t kgTmp;
  if (CRYS_ECPKI_GenKeyPair(&g_rndState, kRndFunc, p256(), &uPriv, &uPub, &kgTmp,
                            NULL) != CRYS_OK)
    return CryptoStatus::InternalError;
  uint32_t privLen = kP256PrivLen;
  if (CRYS_ECPKI_ExportPrivKey(&uPriv, priv, &privLen) != CRYS_OK)
    return CryptoStatus::InternalError;
  uint8_t raw[1 + kP256PubLen];
  uint32_t rawLen = sizeof(raw);
  if (CRYS_ECPKI_ExportPublKey(&uPub, CRYS_EC_PointUncompressed, raw, &rawLen) !=
      CRYS_OK)
    return CryptoStatus::InternalError;
  memcpy(pub, raw + 1, kP256PubLen);  // strip the 0x04 prefix
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ecdsaP256Sign(const uint8_t priv[kP256PrivLen],
                                         const uint8_t hash[kSha256Len],
                                         uint8_t sig[kP256SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t privRam[kP256PrivLen];
  uint8_t hashRam[kSha256Len];
  memcpy(privRam, priv, sizeof(privRam));
  memcpy(hashRam, hash, sizeof(hashRam));
  static CRYS_ECPKI_UserPrivKey_t uPriv;
  if (CRYS_ECPKI_BuildPrivKey(p256(), privRam, kP256PrivLen, &uPriv) != CRYS_OK)
    return CryptoStatus::BadParam;
  static CRYS_ECDSA_SignUserContext_t sctx;
  uint32_t sigLen = kP256SigLen;
  if (CRYS_ECDSA_Sign(&g_rndState, kRndFunc, &sctx, &uPriv,
                      CRYS_ECPKI_AFTER_HASH_SHA256_mode, hashRam, kSha256Len,
                      sig, &sigLen) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ecdsaP256Verify(const uint8_t pub[kP256PubLen],
                                           const uint8_t hash[kSha256Len],
                                           const uint8_t sig[kP256SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t raw[1 + kP256PubLen];
  raw[0] = CRYS_EC_PointUncompressed;  // 0x04
  memcpy(raw + 1, pub, kP256PubLen);
  uint8_t hashRam[kSha256Len];
  uint8_t sigRam[kP256SigLen];
  memcpy(hashRam, hash, sizeof(hashRam));
  memcpy(sigRam, sig, sizeof(sigRam));
  static CRYS_ECPKI_UserPublKey_t uPub;
  if (CRYS_ECPKI_BuildPublKey(p256(), raw, sizeof(raw), &uPub) != CRYS_OK)
    return CryptoStatus::BadParam;
  static CRYS_ECDSA_VerifyUserContext_t vctx;
  CRYSError_t e =
      CRYS_ECDSA_Verify(&vctx, &uPub, CRYS_ECPKI_AFTER_HASH_SHA256_mode, sigRam,
                        kP256SigLen, hashRam, kSha256Len);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::ecdhP256Shared(const uint8_t priv[kP256PrivLen],
                                          const uint8_t peerPub[kP256PubLen],
                                          uint8_t shared[kP256SharedLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t raw[1 + kP256PubLen];
  raw[0] = CRYS_EC_PointUncompressed;
  memcpy(raw + 1, peerPub, kP256PubLen);
  uint8_t privRam[kP256PrivLen];
  memcpy(privRam, priv, sizeof(privRam));
  static CRYS_ECPKI_UserPublKey_t uPub;
  static CRYS_ECPKI_BUILD_TempData_t bTmp;
  if (CRYS_ECPKI_BuildPublKeyPartlyCheck(p256(), raw, sizeof(raw), &uPub,
                                         &bTmp) != CRYS_OK)
    return CryptoStatus::BadParam;
  static CRYS_ECPKI_UserPrivKey_t uPriv;
  if (CRYS_ECPKI_BuildPrivKey(p256(), privRam, kP256PrivLen, &uPriv) != CRYS_OK)
    return CryptoStatus::BadParam;
  static CRYS_ECDH_TempData_t dTmp;
  uint32_t sharedLen = kP256SharedLen;
  if (CRYS_ECDH_SVDP_DH(&uPub, &uPriv, shared, &sharedLen, &dTmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

#else  // ---- stub: vendored CRYS binaries absent ----

bool CC310Backend::begin() { return false; }
void CC310Backend::end() {}
CryptoStatus CC310Backend::randomBytes(uint8_t*, size_t) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::sha256(const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::sha384(const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::sha512(const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::hkdfSha256(const uint8_t*, size_t, const uint8_t*, size_t,
                                      const uint8_t*, size_t, uint8_t*, size_t) {
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::hmacSha256(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::aes128CbcEncrypt(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*, size_t) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::aes128CbcDecrypt(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*, size_t) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::aes128Ctr(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*, size_t) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::aes128GcmEncrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::aes128GcmDecrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, uint8_t*, size_t, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256GenerateKey(uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256Sign(const uint8_t*, const uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256Verify(const uint8_t*, const uint8_t*, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdhP256Shared(const uint8_t*, const uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }

#endif  // NIUS_CRYPTO_HAS_CC310

}  // namespace ncrypto
