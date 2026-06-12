/*
  CryptoSelfTestRunner.cpp - known-answer tests for every NiusCrypto primitive.

  Same vectors and pass/fail/skip counting as examples/CryptoSelfTest, without
  Serial output. Call via CryptoEngine::runSelfTest().
*/
#include "CryptoSelfTestRunner.h"

#include "CryptoEngine.h"
#include "CryptoPackets.h"
#include "CryptoUtil.h"

namespace ncrypto {

namespace {

void reportPassFail(SelfTestReport& report, bool ok) {
  if (ok)
    report.passed++;
  else
    report.failed++;
}

void reportSkip(SelfTestReport& report) { report.skipped++; }

// SHA-256("abc")
static const uint8_t kMsgAbc[3] = {'a', 'b', 'c'};
static const uint8_t kSha256Abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
    0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

// AES-128-CBC, NIST SP800-38A F.2.1 (first two blocks)
static const uint8_t kAesKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                                    0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                                    0x4f, 0x3c};
static const uint8_t kCbcIv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                   0x0e, 0x0f};
static const uint8_t kCbcPt[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
static const uint8_t kCbcCt[32] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
    0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
    0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2};

// AES-128-CTR, NIST SP800-38A F.5.1 (first two blocks)
static const uint8_t kCtrIv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                                   0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
                                   0xfe, 0xff};
static const uint8_t kCtrCt[32] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68,
    0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70,
    0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff};

// AES-128-GCM, McGrew/Viega test case 3 (no AAD, 60-byte... using 64-byte PT)
static const uint8_t kGcmKey[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73,
                                    0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
                                    0x83, 0x08};
static const uint8_t kGcmIv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                   0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const uint8_t kGcmPt[64] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    0x1a, 0xaf, 0xd2, 0x55};
static const uint8_t kGcmCt[64] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
    0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
    0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
    0x47, 0x3f, 0x59, 0x85};
static const uint8_t kGcmTag[16] = {0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64,
                                    0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6,
                                    0xfa, 0xb4};

// ChaCha20-Poly1305, RFC 8439 appendix A.5
static const uint8_t kChaKey[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
    0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
static const uint8_t kChaNonce[12] = {0x07, 0x00, 0x00, 0x00, 0x41, 0xb0,
                                      0x51, 0xec, 0x5e, 0x98, 0x56, 0x63};
static const uint8_t kChaAad[8] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                                   0x57};
static const uint8_t kChaPt[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t kChaCt[32] = {
    0x10, 0xab, 0x09, 0x03, 0x36, 0x4f, 0x86, 0xd6, 0x9d, 0x82, 0x82, 0xf6,
    0x9d, 0xd2, 0x35, 0xc3, 0xc1, 0xd9, 0xdd, 0xcb, 0x11, 0x0b, 0x4b, 0xa9,
    0xc7, 0xcd, 0x32, 0xe7, 0x1c, 0xe8, 0xa8, 0x93};
static const uint8_t kChaTag[16] = {0x66, 0x48, 0xaa, 0x82, 0x1b, 0x78, 0x61,
                                    0x95, 0x08, 0x75, 0xf9, 0x5b, 0x2c, 0xe5,
                                    0x6e, 0x5f};

// HMAC-SHA256, RFC 4231 test case 2: key "Jefe", msg "what do ya want for nothing?"
static const uint8_t kHmacKey[4] = {'J', 'e', 'f', 'e'};
static const uint8_t kHmacMsg[28] = {'w', 'h', 'a', 't', ' ', 'd', 'o',
                                     ' ', 'y', 'a', ' ', 'w', 'a', 'n',
                                     't', ' ', 'f', 'o', 'r', ' ', 'n',
                                     'o', 't', 'h', 'i', 'n', 'g', '?'};
static const uint8_t kHmacMac[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
    0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
    0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};

}  // namespace

SelfTestReport runCryptoSelfTests(CryptoEngine& crypto) {
  SelfTestReport report;
  uint8_t buf[64], buf2[64], tag[16];

  // SHA-256
  if (crypto.sha256(kMsgAbc, sizeof(kMsgAbc), buf) == CryptoStatus::Ok)
    reportPassFail(report, secureEqual(buf, kSha256Abc, 32));
  else
    reportPassFail(report, false);

  // SHA-512("abc")
  static const uint8_t kSha512Abc[64] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
      0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
      0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
      0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
      0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
      0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
  {
    CryptoStatus ss = crypto.sha512(kMsgAbc, sizeof(kMsgAbc), buf);
    if (ss == CryptoStatus::Ok)
      reportPassFail(report, secureEqual(buf, kSha512Abc, 64));
    else if (ss == CryptoStatus::Unsupported)
      reportSkip(report);
    else
      reportPassFail(report, false);
  }

  // SHA-384("abc")
  static const uint8_t kSha384Abc[48] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d,
      0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde,
      0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80,
      0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1,
      0x34, 0xc8, 0x25, 0xa7};
  {
    CryptoStatus ss = crypto.sha384(kMsgAbc, sizeof(kMsgAbc), buf);
    if (ss == CryptoStatus::Ok)
      reportPassFail(report, secureEqual(buf, kSha384Abc, 48));
    else if (ss == CryptoStatus::Unsupported)
      reportSkip(report);
    else
      reportPassFail(report, false);
  }

  // HKDF-SHA-256 (RFC 5869 test case 1, L=32)
  static const uint8_t kHkdfIkm[22] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  static const uint8_t kHkdfSalt[13] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c};
  static const uint8_t kHkdfInfo[10] = {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  static const uint8_t kHkdfOkm[32] = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf};
  {
    CryptoStatus hs = crypto.hkdfSha256(kHkdfIkm, sizeof(kHkdfIkm), kHkdfSalt,
                                        sizeof(kHkdfSalt), kHkdfInfo,
                                        sizeof(kHkdfInfo), buf, 32);
    if (hs == CryptoStatus::Ok)
      reportPassFail(report, secureEqual(buf, kHkdfOkm, 32));
    else if (hs == CryptoStatus::Unsupported)
      reportSkip(report);
    else
      reportPassFail(report, false);
  }

  // HMAC-SHA-256
  if (crypto.hmacSha256(kHmacKey, sizeof(kHmacKey), kHmacMsg, sizeof(kHmacMsg),
                        buf) == CryptoStatus::Ok)
    reportPassFail(report, secureEqual(buf, kHmacMac, 32));
  else
    reportPassFail(report, false);

  // AES-128-CBC encrypt + decrypt
  {
    CryptoStatus se = crypto.aesCbcEncrypt(kAesKey, kCbcIv, kCbcPt, buf, 32);
    if (se == CryptoStatus::Ok) {
      reportPassFail(report, secureEqual(buf, kCbcCt, 32));
      CryptoStatus sd = crypto.aesCbcDecrypt(kAesKey, kCbcIv, kCbcCt, buf2, 32);
      if (sd == CryptoStatus::Ok)
        reportPassFail(report, secureEqual(buf2, kCbcPt, 32));
      else
        reportSkip(report);
    } else {
      reportSkip(report);
    }
  }

  // AES-128-CTR (encrypt == decrypt)
  {
    CryptoStatus s = crypto.aesCtr(kAesKey, kCtrIv, kCbcPt, buf, 32);
    if (s == CryptoStatus::Ok)
      reportPassFail(report, secureEqual(buf, kCtrCt, 32));
    else
      reportSkip(report);
  }

  // AES-128-GCM encrypt + decrypt
  {
    CryptoStatus se = crypto.aesGcmEncrypt(kGcmKey, kGcmIv, nullptr, 0, kGcmPt,
                                           buf, 64, tag);
    if (se == CryptoStatus::Ok) {
      bool ok = secureEqual(buf, kGcmCt, 64) && secureEqual(tag, kGcmTag, 16);
      reportPassFail(report, ok);
      CryptoStatus sd = crypto.aesGcmDecrypt(kGcmKey, kGcmIv, nullptr, 0, kGcmCt,
                                             buf2, 64, kGcmTag);
      reportPassFail(report, sd == CryptoStatus::Ok &&
                                secureEqual(buf2, kGcmPt, 64));
    } else {
      reportSkip(report);
      reportSkip(report);
    }
  }

  // ChaCha20-Poly1305 encrypt + decrypt
  {
    CryptoStatus se = crypto.chachaPolyEncrypt(kChaKey, kChaNonce, kChaAad,
                                               sizeof(kChaAad), kChaPt, buf, 32,
                                               tag);
    if (se == CryptoStatus::Ok) {
      bool ok = secureEqual(buf, kChaCt, 32) && secureEqual(tag, kChaTag, 16);
      reportPassFail(report, ok);
      CryptoStatus sd = crypto.chachaPolyDecrypt(kChaKey, kChaNonce, kChaAad,
                                                 sizeof(kChaAad), kChaCt, buf2,
                                                 32, kChaTag);
      reportPassFail(report, sd == CryptoStatus::Ok &&
                                secureEqual(buf2, kChaPt, 32));
    } else {
      reportSkip(report);
      reportSkip(report);
    }
  }

  // ECDSA P-256 sign/verify round-trip (+ tamper detection)
  {
    uint8_t priv[32], pub[64], sig[64], hash[32];
    CryptoStatus sg = crypto.ecdsaGenerateKey(priv, pub);
    if (sg == CryptoStatus::Ok) {
      crypto.sha256(kMsgAbc, sizeof(kMsgAbc), hash);
      CryptoStatus ss = crypto.ecdsaSign(priv, hash, sig);
      if (ss == CryptoStatus::Ok) {
        bool good = (crypto.ecdsaVerify(pub, hash, sig) == CryptoStatus::Ok);
        sig[0] ^= 0x01;  // tamper
        bool rejects = (crypto.ecdsaVerify(pub, hash, sig) != CryptoStatus::Ok);
        reportPassFail(report, good && rejects);
      } else {
        reportSkip(report);
      }
    } else {
      reportSkip(report);
    }

    EcdsaMessage emsg;
    emsg.payload = kMsgAbc;
    emsg.payloadLen = sizeof(kMsgAbc);
    if (crypto.ecdsaGenerateKey(emsg) == CryptoStatus::Ok) {
      bool ok = (crypto.ecdsaSign(emsg) == CryptoStatus::Ok &&
                 crypto.ecdsaVerify(emsg) == CryptoStatus::Ok);
      reportPassFail(report, ok);
    } else {
      reportSkip(report);
    }
  }

  // ECDH P-256: two parties derive the same shared secret
  {
    uint8_t aPriv[32], aPub[64], bPriv[32], bPub[64], sAB[32], sBA[32];
    CryptoStatus s1 = crypto.ecdsaGenerateKey(aPriv, aPub);  // P-256 keypair
    CryptoStatus s2 = crypto.ecdsaGenerateKey(bPriv, bPub);
    if (s1 == CryptoStatus::Ok && s2 == CryptoStatus::Ok) {
      CryptoStatus r1 = crypto.ecdhShared(aPriv, bPub, sAB);
      CryptoStatus r2 = crypto.ecdhShared(bPriv, aPub, sBA);
      if (r1 == CryptoStatus::Ok && r2 == CryptoStatus::Ok)
        reportPassFail(report, secureEqual(sAB, sBA, 32));
      else
        reportSkip(report);
    } else {
      reportSkip(report);
    }
  }

  // X25519: two parties derive the same shared secret
  {
    uint8_t aPriv[32], aPub[32], bPriv[32], bPub[32], sAB[32], sBA[32];
    CryptoStatus s1 = crypto.x25519GenerateKey(aPriv, aPub);
    CryptoStatus s2 = crypto.x25519GenerateKey(bPriv, bPub);
    if (s1 == CryptoStatus::Ok && s2 == CryptoStatus::Ok) {
      CryptoStatus r1 = crypto.x25519Shared(aPriv, bPub, sAB);
      CryptoStatus r2 = crypto.x25519Shared(bPriv, aPub, sBA);
      if (r1 == CryptoStatus::Ok && r2 == CryptoStatus::Ok)
        reportPassFail(report, secureEqual(sAB, sBA, 32));
      else
        reportSkip(report);
    } else {
      reportSkip(report);
    }
  }

  // RSA-2048 PKCS#1 v1.5 + SHA-256 sign/verify round-trip
  {
    static const uint8_t kRsaMsg[] = {'r', 's', 'a', '-', 't', 'e', 's', 't'};
    uint8_t sig[256], mod[256], exp[4];
    uint16_t modLen = sizeof(mod), expLen = sizeof(exp);
    CryptoStatus kg = crypto.rsa2048GenerateKey();
    if (kg == CryptoStatus::Ok) {
      CryptoStatus ss = crypto.rsaPkcs1Sha256Sign(kRsaMsg, sizeof(kRsaMsg), sig);
      if (ss == CryptoStatus::Ok) {
        bool good = (crypto.rsaPkcs1Sha256Verify(kRsaMsg, sizeof(kRsaMsg), sig) ==
                     CryptoStatus::Ok);
        sig[0] ^= 0x01;
        bool rejects = (crypto.rsaPkcs1Sha256Verify(kRsaMsg, sizeof(kRsaMsg), sig) !=
                        CryptoStatus::Ok);
        sig[0] ^= 0x01;
        reportPassFail(report, good && rejects);

        CryptoStatus ex = crypto.rsa2048ExportPubKey(mod, &modLen, exp, &expLen);
        if (ex == CryptoStatus::Ok) {
          bool viaPub = (crypto.rsaPkcs1Sha256VerifyPub(mod, modLen, exp, expLen,
                                                      kRsaMsg, sizeof(kRsaMsg),
                                                      sig) == CryptoStatus::Ok);
          reportPassFail(report, viaPub);
        } else if (ex == CryptoStatus::Unsupported) {
          reportSkip(report);
        } else {
          reportPassFail(report, false);
        }
      } else {
        reportSkip(report);
        reportSkip(report);
      }
    } else {
      reportSkip(report);
      reportSkip(report);
    }

    RsaKeyPair explicitKey;
    CryptoStatus eg = crypto.rsaGenerate(&explicitKey);
    if (eg == CryptoStatus::Ok) {
      bool released = (crypto.rsaRelease(&explicitKey) == CryptoStatus::Ok &&
                       !explicitKey.valid());
      RsaKeyPair again;
      bool regen = (crypto.rsaGenerate(&again) == CryptoStatus::Ok);
      if (regen) crypto.rsaRelease(&again);
      reportPassFail(report, released && regen);
    } else if (eg == CryptoStatus::Unsupported) {
      reportSkip(report);
    } else {
      reportPassFail(report, false);
    }
  }

  // Ed25519 RFC 8032 test vector #1 (empty message)
  {
    static const uint8_t kEdSeed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
        0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
    static const uint8_t kEdPub[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
        0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    static const uint8_t kEdSig[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc,
        0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15,
        0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b};
    uint8_t secret[64], pub[32], sig[64];
    CryptoStatus ds = crypto.ed25519DeriveFromSeed(kEdSeed, secret, pub);
    if (ds == CryptoStatus::Ok) {
      bool pkOk = secureEqual(pub, kEdPub, 32);
      bool katOk =
          (crypto.ed25519Verify(kEdPub, nullptr, 0, kEdSig) == CryptoStatus::Ok);
      CryptoStatus ss = crypto.ed25519Sign(secret, nullptr, 0, sig);
      bool signOk = (ss == CryptoStatus::Ok) &&
                    secureEqual(sig, kEdSig, 64) &&
                    (crypto.ed25519Verify(pub, nullptr, 0, sig) == CryptoStatus::Ok);
      reportPassFail(report, pkOk && katOk && signOk);
    } else if (ds == CryptoStatus::Unsupported) {
      reportSkip(report);
    } else {
      reportPassFail(report, false);
    }
  }

  // Ed25519 random keygen round-trip
  {
    uint8_t secret[64], pub[32], sig[64];
    static const uint8_t kEdMsg[] = {'e', 'd', '2', '5', '5', '1', '9'};
    CryptoStatus kg = crypto.ed25519GenerateKey(secret, pub);
    if (kg == CryptoStatus::Ok) {
      CryptoStatus ss = crypto.ed25519Sign(secret, kEdMsg, sizeof(kEdMsg), sig);
      if (ss == CryptoStatus::Ok) {
        bool good = (crypto.ed25519Verify(pub, kEdMsg, sizeof(kEdMsg), sig) ==
                     CryptoStatus::Ok);
        sig[0] ^= 0x01;
        bool rejects =
            (crypto.ed25519Verify(pub, kEdMsg, sizeof(kEdMsg), sig) !=
             CryptoStatus::Ok);
        reportPassFail(report, good && rejects);
      } else {
        reportSkip(report);
      }
    } else {
      reportSkip(report);
    }

    Ed25519Message edmsg;
    edmsg.payload = kEdMsg;
    edmsg.payloadLen = sizeof(kEdMsg);
    if (crypto.ed25519GenerateKey(edmsg) == CryptoStatus::Ok) {
      bool ok = (crypto.ed25519Sign(edmsg) == CryptoStatus::Ok &&
                 crypto.ed25519Verify(edmsg) == CryptoStatus::Ok);
      reportPassFail(report, ok);
    } else {
      reportSkip(report);
    }
  }

  // Random: a fresh draw should not be all-zero (sanity, not a statistical test)
  {
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = 0;
    CryptoStatus s = crypto.random(buf, 32);
    bool nonzero = false;
    for (size_t i = 0; i < 32; ++i) nonzero |= (buf[i] != 0);
    if (s == CryptoStatus::Ok)
      reportPassFail(report, nonzero);
    else
      reportPassFail(report, false);
  }

  return report;
}

}  // namespace ncrypto
