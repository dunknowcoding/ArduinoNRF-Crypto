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
    X25519   -> CC310 PKA: Curve25519 scalar mult (CRYS_ECMONT).
    RSA      -> CC310 PKA: RSA-2048 PKCS#1 v1.5 + SHA-256 (CRYS_RSA).
    AES-GCM  -> Nordic Oberon (the CRYS runtime ships AES-CCM, not GCM).
    ChaPoly  -> Nordic Oberon (RFC 8439 ChaCha20-Poly1305).

  Auto-detection: the .cpp compiles in real-hardware mode only when the vendored
  CRYS headers **and** precompiled archives (libnrf_cc310.a / liboberon.a) are
  both present under src/cc310/ and src/cortex-m4/. Run
  vendor/tools/setup_vendored.py to vendor them from a local nRF5 SDK. If only
  headers exist (OnChip-only library.properties), this compiles as a stub whose
  begin() returns false, so the engine's Prefer::Auto falls back to OnChip.

  The CryptoCell DMAs from RAM only, so flash-resident inputs (e.g. const test
  vectors) are bounced through a RAM scratch buffer before being fed to the
  engine. Key/IV/hash/signature byte arrays are likewise copied to the stack.
*/
#include "CC310Backend.h"

#include "../internal/BuildProfile.h"

#if NIUS_CRYPTO_ONCHIP_ONLY
#define NIUS_CRYPTO_HAS_CC310 0
#elif __has_include("../cc310/sns_silib.h") && \
    __has_include("../cortex-m4/libnrf_cc310.a") && \
    __has_include("../cortex-m4/liboberon.a")
#define NIUS_CRYPTO_HAS_CC310 1
#else
#define NIUS_CRYPTO_HAS_CC310 0
#endif

#if NIUS_CRYPTO_HAS_CC310
#include <string.h>
#if defined(NRF52840_XXAA) || defined(NRF52840_XXAA_ENXA) || __has_include(<nrf52840.h>)
#include <nrf52840.h>
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
#include "../cc310/crys_ec_mont_api.h"
#include "../cc310/crys_rsa_schemes.h"
#include "../cc310/crys_rsa_kg.h"
#include "../cc310/crys_rsa_build.h"
#include "../cc310/crys_ec_edw_api.h"
#include "../cc310/ocrypto_aes_gcm.h"
#include "../cc310/ocrypto_chacha20_poly1305.h"
#include "../cc310/ocrypto_sha384.h"
#include "../crypto/CryptoBackendError.h"
#include "../crypto/CryptoCapability.h"
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

inline void recordCrys(CRYSError_t e) {
  if (e != CRYS_OK) detail::setBackendError(static_cast<int32_t>(e));
}

static constexpr uint16_t kRsaPssSaltLen = kSha256Len;

static CRYS_RSAPrivUserContext_t g_rsaSignCtx;
static CRYS_RSAPubUserContext_t g_rsaVerifyCtx;
static CRYS_ECMONT_TempBuff_t g_ecMontTmp;
static CRYS_ECEDW_TempBuff_t g_ed25519Tmp;

struct RsaSlot {
  CRYS_RSAUserPrivKey_t priv;
  CRYS_RSAUserPubKey_t pub;
  CRYS_RSAKGData_t kg;
  bool ready = false;
};

static constexpr int kRsaSlotCount = 2;
static RsaSlot g_rsaSlots[kRsaSlotCount];

static bool rsaSlotValid(uint8_t slot) {
  return slot < kRsaSlotCount && g_rsaSlots[slot].ready;
}

static int rsaAllocSlot() {
  for (int i = 0; i < kRsaSlotCount; ++i)
    if (!g_rsaSlots[i].ready) return i;
  return -1;
}

static void rsaFreeSlot(uint8_t slot) {
  if (slot >= kRsaSlotCount) return;
  memset(&g_rsaSlots[slot], 0, sizeof(RsaSlot));
  g_rsaSlots[slot].ready = false;
}

static void rsaFreeAllSlots() {
  for (int i = 0; i < kRsaSlotCount; ++i) rsaFreeSlot(static_cast<uint8_t>(i));
}

static CryptoStatus rsaExportSlotPub(uint8_t slot, RsaPublicKey* out) {
  if (!out || !rsaSlotValid(slot)) return CryptoStatus::BadParam;
  uint16_t modLen = kRsa2048ModLen;
  uint16_t expLen = kRsaMaxExpLen;
  if (CRYS_RSA_Get_PubKey(&g_rsaSlots[slot].pub, out->exponent, &expLen,
                          out->modulus, &modLen) != CRYS_OK)
    return CryptoStatus::InternalError;
  out->modLen = modLen;
  out->expLen = expLen;
  return CryptoStatus::Ok;
}

CryptoStatus bounceMsg(const uint8_t* in, size_t len, uint8_t** out) {
  if (len == 0) {
    *out = scratchBytes();
    return CryptoStatus::Ok;
  }
  if (in == nullptr) return CryptoStatus::BadParam;
  uint8_t* bounce = scratchBytes();
  if (len > kScratchBytes) return CryptoStatus::BadParam;
  memcpy(bounce, in, len);
  *out = bounce;
  return CryptoStatus::Ok;
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
    rsaFreeAllSlots();
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

CryptoStatus CC310Backend::chachaPolyEncrypt(const uint8_t key[kChaPolyKeyLen],
                                             const uint8_t nonce[kChaPolyNonceLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len, uint8_t tag[kChaPolyTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  ocrypto_chacha20_poly1305_encrypt(tag, out, in, len, aad, aadLen, nonce,
                                    kChaPolyNonceLen, key);
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::chachaPolyDecrypt(const uint8_t key[kChaPolyKeyLen],
                                             const uint8_t nonce[kChaPolyNonceLen],
                                             const uint8_t* aad, size_t aadLen,
                                             const uint8_t* in, uint8_t* out,
                                             size_t len,
                                             const uint8_t tag[kChaPolyTagLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  int r = ocrypto_chacha20_poly1305_decrypt(tag, out, in, len, aad, aadLen,
                                            nonce, kChaPolyNonceLen, key);
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

CryptoStatus CC310Backend::x25519GenerateKey(uint8_t priv[kX25519KeyLen],
                                             uint8_t pub[kX25519KeyLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  size_t privLen = kX25519KeyLen;
  size_t pubLen = kX25519KeyLen;
  if (CRYS_ECMONT_KeyPair(pub, &pubLen, priv, &privLen, &g_rndState, kRndFunc,
                          &g_ecMontTmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::x25519Shared(const uint8_t priv[kX25519KeyLen],
                                        const uint8_t peerPub[kX25519KeyLen],
                                        uint8_t shared[kX25519KeyLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t privRam[kX25519KeyLen];
  uint8_t peerRam[kX25519KeyLen];
  memcpy(privRam, priv, sizeof(privRam));
  memcpy(peerRam, peerPub, sizeof(peerRam));
  size_t outLen = kX25519KeyLen;
  if (CRYS_ECMONT_Scalarmult(shared, &outLen, privRam, sizeof(privRam), peerRam,
                             sizeof(peerRam), &g_ecMontTmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

bool CC310Backend::supportsCapability(CryptoCapability cap) const {
  if (!started_) return false;
  switch (cap) {
    case CryptoCapability::Random:
    case CryptoCapability::Sha256:
    case CryptoCapability::Sha384:
    case CryptoCapability::Sha512:
    case CryptoCapability::HmacSha256:
    case CryptoCapability::HkdfSha256:
    case CryptoCapability::AesCbcEncrypt:
    case CryptoCapability::AesCbcDecrypt:
    case CryptoCapability::AesCtr:
    case CryptoCapability::AesGcm:
    case CryptoCapability::ChaChaPoly:
    case CryptoCapability::Ecdsa:
    case CryptoCapability::Ecdh:
    case CryptoCapability::X25519:
    case CryptoCapability::Ed25519:
    case CryptoCapability::RsaPkcs1:
    case CryptoCapability::RsaPss:
      return true;
    default:
      return false;
  }
}

CryptoStatus CC310Backend::rsaGenerateKeyPair(RsaKeyPair* key) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key) return CryptoStatus::BadParam;
  int slot = rsaAllocSlot();
  if (slot < 0) return CryptoStatus::InternalError;
  g_rsaSlots[slot].ready = false;
  static const uint8_t kPubExp[] = {0x01, 0x00, 0x01};
  if (CRYS_RSA_KG_GenerateKeyPair(
          &g_rndState, kRndFunc, const_cast<uint8_t*>(kPubExp),
          sizeof(kPubExp), 2048, &g_rsaSlots[slot].priv, &g_rsaSlots[slot].pub,
          &g_rsaSlots[slot].kg, NULL) != CRYS_OK)
    return CryptoStatus::InternalError;
  g_rsaSlots[slot].ready = true;
  key->slot = static_cast<uint8_t>(slot);
  return rsaExportSlotPub(key->slot, &key->pub);
}

CryptoStatus CC310Backend::rsaSignWithKeyPair(const RsaKeyPair* key,
                                              const uint8_t* msg, size_t msgLen,
                                              uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !sig || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint16_t sigLen = kRsa2048SigLen;
  if (CRYS_RSA_PKCS1v15_Sign(&g_rndState, kRndFunc, &g_rsaSignCtx,
                             &g_rsaSlots[key->slot].priv,
                             CRYS_RSA_HASH_SHA256_mode, bounce,
                             static_cast<uint32_t>(msgLen), sig,
                             &sigLen) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::rsaImportKeyPair(RsaKeyPair* key,
                                              const RsaPrivateKeyImport* material) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !material || material->modLen == 0 || material->privExpLen == 0 ||
      material->pubExpLen == 0)
    return CryptoStatus::BadParam;
  if (material->modLen > kRsa2048ModLen ||
      material->privExpLen > kRsa2048ModLen ||
      material->pubExpLen > kRsaMaxExpLen)
    return CryptoStatus::BadParam;
  int slot = rsaAllocSlot();
  if (slot < 0) return CryptoStatus::InternalError;
  g_rsaSlots[slot].ready = false;
  uint8_t modRam[kRsa2048ModLen];
  uint8_t privRam[kRsa2048ModLen];
  uint8_t expRam[kRsaMaxExpLen];
  memcpy(modRam, material->modulus, material->modLen);
  memcpy(privRam, material->privateExponent, material->privExpLen);
  memcpy(expRam, material->publicExponent, material->pubExpLen);
  CRYSError_t e1 = CRYS_RSA_Build_PrivKey(
      &g_rsaSlots[slot].priv, privRam, material->privExpLen, expRam,
      material->pubExpLen, modRam, material->modLen);
  CRYSError_t e2 = CRYS_RSA_Build_PubKey(&g_rsaSlots[slot].pub, expRam,
                                         material->pubExpLen, modRam,
                                         material->modLen);
  if (e1 != CRYS_OK || e2 != CRYS_OK) {
    recordCrys(e1 != CRYS_OK ? e1 : e2);
    rsaFreeSlot(static_cast<uint8_t>(slot));
    return CryptoStatus::BadParam;
  }
  g_rsaSlots[slot].ready = true;
  key->slot = static_cast<uint8_t>(slot);
  return rsaExportSlotPub(key->slot, &key->pub);
}

CryptoStatus CC310Backend::rsaPssSignWithKeyPair(const RsaKeyPair* key,
                                                 const uint8_t* msg, size_t msgLen,
                                                 uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !sig || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint16_t sigLen = kRsa2048SigLen;
  CRYSError_t e = CRYS_RSA_PSS_Sign(
      &g_rndState, kRndFunc, &g_rsaSignCtx, &g_rsaSlots[key->slot].priv,
      CRYS_RSA_HASH_SHA256_mode, CRYS_PKCS1_MGF1, kRsaPssSaltLen, bounce,
      static_cast<uint32_t>(msgLen), sig, &sigLen);
  if (e != CRYS_OK) {
    recordCrys(e);
    return CryptoStatus::InternalError;
  }
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::rsaPssVerifyWithKeyPair(const RsaKeyPair* key,
                                                   const uint8_t* msg,
                                                   size_t msgLen,
                                                   const uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !sig || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint8_t sigRam[kRsa2048SigLen];
  memcpy(sigRam, sig, sizeof(sigRam));
  CRYSError_t e = CRYS_RSA_PSS_Verify(
      &g_rsaVerifyCtx, &g_rsaSlots[key->slot].pub, CRYS_RSA_HASH_SHA256_mode,
      CRYS_PKCS1_MGF1, kRsaPssSaltLen, bounce, static_cast<uint32_t>(msgLen),
      sigRam);
  if (e != CRYS_OK) recordCrys(e);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::rsaPssVerifyWithPublicKey(
    const RsaPublicKey* pub, const uint8_t* msg, size_t msgLen,
    const uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!pub || !sig || pub->modLen == 0 || pub->expLen == 0)
    return CryptoStatus::BadParam;
  if (pub->modLen > kRsa2048ModLen || pub->expLen > kRsaMaxExpLen)
    return CryptoStatus::BadParam;
  uint8_t modRam[kRsa2048ModLen];
  uint8_t expRam[kRsaMaxExpLen];
  memcpy(modRam, pub->modulus, pub->modLen);
  memcpy(expRam, pub->exponent, pub->expLen);
  static CRYS_RSAUserPubKey_t crysPub;
  CRYSError_t b = CRYS_RSA_Build_PubKey(&crysPub, expRam, pub->expLen, modRam,
                                        pub->modLen);
  if (b != CRYS_OK) {
    recordCrys(b);
    return CryptoStatus::BadParam;
  }
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint8_t sigRam[kRsa2048SigLen];
  memcpy(sigRam, sig, sizeof(sigRam));
  CRYSError_t e = CRYS_RSA_PSS_Verify(
      &g_rsaVerifyCtx, &crysPub, CRYS_RSA_HASH_SHA256_mode, CRYS_PKCS1_MGF1,
      kRsaPssSaltLen, bounce, static_cast<uint32_t>(msgLen), sigRam);
  if (e != CRYS_OK) recordCrys(e);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::rsaVerifyWithKeyPair(const RsaKeyPair* key,
                                                const uint8_t* msg,
                                                size_t msgLen,
                                                const uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !sig || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint8_t sigRam[kRsa2048SigLen];
  memcpy(sigRam, sig, sizeof(sigRam));
  CRYSError_t e = CRYS_RSA_PKCS1v15_Verify(
      &g_rsaVerifyCtx, &g_rsaSlots[key->slot].pub, CRYS_RSA_HASH_SHA256_mode,
      bounce, static_cast<uint32_t>(msgLen), sigRam);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::rsaVerifyWithPublicKey(
    const RsaPublicKey* pub, const uint8_t* msg, size_t msgLen,
    const uint8_t sig[kRsa2048SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!pub || !sig || pub->modLen == 0 || pub->expLen == 0)
    return CryptoStatus::BadParam;
  if (pub->modLen > kRsa2048ModLen || pub->expLen > kRsaMaxExpLen)
    return CryptoStatus::BadParam;
  uint8_t modRam[kRsa2048ModLen];
  uint8_t expRam[4];
  memcpy(modRam, pub->modulus, pub->modLen);
  memcpy(expRam, pub->exponent, pub->expLen);
  static CRYS_RSAUserPubKey_t crysPub;
  if (CRYS_RSA_Build_PubKey(&crysPub, expRam, pub->expLen, modRam, pub->modLen) !=
      CRYS_OK)
    return CryptoStatus::BadParam;
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  uint8_t sigRam[kRsa2048SigLen];
  memcpy(sigRam, sig, sizeof(sigRam));
  CRYSError_t e = CRYS_RSA_PKCS1v15_Verify(
      &g_rsaVerifyCtx, &crysPub, CRYS_RSA_HASH_SHA256_mode, bounce,
      static_cast<uint32_t>(msgLen), sigRam);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
}

CryptoStatus CC310Backend::rsaExportPublicKey(const RsaKeyPair* key,
                                              RsaPublicKey* out) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!key || !out || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  CryptoStatus fresh = rsaExportSlotPub(key->slot, out);
  if (fresh != CryptoStatus::Ok) return fresh;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::rsaReleaseKeyPair(RsaKeyPair* key) {
  if (!key || !rsaSlotValid(key->slot)) return CryptoStatus::BadParam;
  rsaFreeSlot(key->slot);
  key->clear();
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ed25519GenerateKey(uint8_t secret[kEd25519SecLen],
                                              uint8_t pub[kEd25519PubLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  size_t secLen = kEd25519SecLen;
  size_t pubLen = kEd25519PubLen;
  if (CRYS_ECEDW_KeyPair(secret, &secLen, pub, &pubLen, &g_rndState, kRndFunc,
                         &g_ed25519Tmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ed25519DeriveFromSeed(const uint8_t seed[32],
                                                 uint8_t secret[kEd25519SecLen],
                                                 uint8_t pub[kEd25519PubLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t seedRam[32];
  memcpy(seedRam, seed, 32);
  size_t secLen = kEd25519SecLen;
  size_t pubLen = kEd25519PubLen;
  if (CRYS_ECEDW_SeedKeyPair(seedRam, 32, secret, &secLen, pub, &pubLen,
                             &g_ed25519Tmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ed25519Sign(const uint8_t secret[kEd25519SecLen],
                                       const uint8_t* msg, size_t msgLen,
                                       uint8_t sig[kEd25519SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  if (!sig) return CryptoStatus::BadParam;
  uint8_t secRam[kEd25519SecLen];
  memcpy(secRam, secret, sizeof(secRam));
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  size_t sigLen = kEd25519SigLen;
  if (CRYS_ECEDW_Sign(sig, &sigLen, bounce, msgLen, secRam, kEd25519SecLen,
                      &g_ed25519Tmp) != CRYS_OK)
    return CryptoStatus::InternalError;
  return CryptoStatus::Ok;
}

CryptoStatus CC310Backend::ed25519Verify(const uint8_t pub[kEd25519PubLen],
                                         const uint8_t* msg, size_t msgLen,
                                         const uint8_t sig[kEd25519SigLen]) {
  if (!started_) return CryptoStatus::NotStarted;
  uint8_t pubRam[kEd25519PubLen];
  uint8_t sigRam[kEd25519SigLen];
  memcpy(pubRam, pub, sizeof(pubRam));
  memcpy(sigRam, sig, sizeof(sigRam));
  uint8_t* bounce = nullptr;
  CryptoStatus bs = bounceMsg(msg, msgLen, &bounce);
  if (bs != CryptoStatus::Ok) return bs;
  CRYSError_t e =
      CRYS_ECEDW_Verify(sigRam, kEd25519SigLen, pubRam, kEd25519PubLen, bounce,
                        msgLen, &g_ed25519Tmp);
  return e == CRYS_OK ? CryptoStatus::Ok : CryptoStatus::AuthFailed;
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
CryptoStatus CC310Backend::chachaPolyEncrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::chachaPolyDecrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, uint8_t*, size_t, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256GenerateKey(uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256Sign(const uint8_t*, const uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdsaP256Verify(const uint8_t*, const uint8_t*, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ecdhP256Shared(const uint8_t*, const uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::x25519GenerateKey(uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::x25519Shared(const uint8_t*, const uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
bool CC310Backend::supportsCapability(CryptoCapability) const { return false; }
CryptoStatus CC310Backend::rsaGenerateKeyPair(RsaKeyPair*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::rsaImportKeyPair(RsaKeyPair*, const RsaPrivateKeyImport*) {
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::rsaPssSignWithKeyPair(const RsaKeyPair*, const uint8_t*, size_t,
                                                 uint8_t*) {
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::rsaPssVerifyWithKeyPair(const RsaKeyPair*, const uint8_t*, size_t,
                                                   const uint8_t*) {
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::rsaPssVerifyWithPublicKey(const RsaPublicKey*, const uint8_t*, size_t,
                                                     const uint8_t*) {
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::rsaSignWithKeyPair(const RsaKeyPair*, const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::rsaVerifyWithKeyPair(const RsaKeyPair*, const uint8_t*, size_t, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::rsaVerifyWithPublicKey(const RsaPublicKey*, const uint8_t*, size_t, const uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::rsaExportPublicKey(const RsaKeyPair*, RsaPublicKey*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::rsaReleaseKeyPair(RsaKeyPair* key) {
  if (!key || !key->valid()) return CryptoStatus::BadParam;
  key->clear();
  return CryptoStatus::HardwareMissing;
}
CryptoStatus CC310Backend::ed25519GenerateKey(uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ed25519DeriveFromSeed(const uint8_t*, uint8_t*, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ed25519Sign(const uint8_t*, const uint8_t*, size_t, uint8_t*) { return CryptoStatus::HardwareMissing; }
CryptoStatus CC310Backend::ed25519Verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*) { return CryptoStatus::HardwareMissing; }

#endif  // NIUS_CRYPTO_HAS_CC310

}  // namespace ncrypto
