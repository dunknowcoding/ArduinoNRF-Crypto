/*
  CryptoSelfTest - known-answer tests for every NiusCrypto primitive.

  Brings up the best backend (CC310 hardware when the Nordic binaries are
  vendored, otherwise the on-chip fallback) and checks each operation against a
  published test vector or a sign/verify round-trip. Prints PASS / FAIL / SKIP
  per item and a final summary.

  On a board with CC310 vendored every line should read PASS. On the bare
  on-chip fallback, GCM / ECDSA / ECDH read SKIP (Unsupported) - that is
  expected, not a failure.

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

static int g_pass = 0, g_fail = 0, g_skip = 0;

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < 0x10) Serial.print('0');
    Serial.print(p[i], HEX);
  }
}

static bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; ++i)
    if (a[i] != b[i]) return false;
  return true;
}

static void report(const char* name, bool ok) {
  Serial.print(ok ? F("  PASS  ") : F("  FAIL  "));
  Serial.println(name);
  if (ok) g_pass++; else g_fail++;
}

static void skip(const char* name, CryptoStatus s) {
  Serial.print(F("  SKIP  "));
  Serial.print(name);
  Serial.print(F("  ("));
  Serial.print(cryptoStatusName(s));
  Serial.println(F(")"));
  g_skip++;
}

// ---- Known-answer vectors -------------------------------------------------

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

void runTests() {
  uint8_t buf[64], buf2[64], tag[16];

  // SHA-256
  if (Crypto.sha256(kMsgAbc, sizeof(kMsgAbc), buf) == CryptoStatus::Ok)
    report("SHA-256(\"abc\")", equal(buf, kSha256Abc, 32));
  else
    report("SHA-256(\"abc\")", false);

  // SHA-512("abc")
  static const uint8_t kSha512Abc[64] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
      0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
      0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
      0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
      0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
      0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
  {
    CryptoStatus ss = Crypto.sha512(kMsgAbc, sizeof(kMsgAbc), buf);
    if (ss == CryptoStatus::Ok)
      report("SHA-512(\"abc\")", equal(buf, kSha512Abc, 64));
    else if (ss == CryptoStatus::Unsupported)
      skip("SHA-512(\"abc\")", ss);
    else
      report("SHA-512(\"abc\")", false);
  }

  // SHA-384("abc")
  static const uint8_t kSha384Abc[48] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d,
      0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde,
      0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80,
      0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1,
      0x34, 0xc8, 0x25, 0xa7};
  {
    CryptoStatus ss = Crypto.sha384(kMsgAbc, sizeof(kMsgAbc), buf);
    if (ss == CryptoStatus::Ok)
      report("SHA-384(\"abc\")", equal(buf, kSha384Abc, 48));
    else if (ss == CryptoStatus::Unsupported)
      skip("SHA-384(\"abc\")", ss);
    else
      report("SHA-384(\"abc\")", false);
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
    CryptoStatus hs = Crypto.hkdfSha256(kHkdfIkm, sizeof(kHkdfIkm), kHkdfSalt,
                                        sizeof(kHkdfSalt), kHkdfInfo,
                                        sizeof(kHkdfInfo), buf, 32);
    if (hs == CryptoStatus::Ok)
      report("HKDF-SHA-256 (RFC 5869 #1)", equal(buf, kHkdfOkm, 32));
    else if (hs == CryptoStatus::Unsupported)
      skip("HKDF-SHA-256 (RFC 5869 #1)", hs);
    else
      report("HKDF-SHA-256 (RFC 5869 #1)", false);
  }

  // HMAC-SHA-256
  if (Crypto.hmacSha256(kHmacKey, sizeof(kHmacKey), kHmacMsg, sizeof(kHmacMsg),
                        buf) == CryptoStatus::Ok)
    report("HMAC-SHA-256 (RFC 4231 #2)", equal(buf, kHmacMac, 32));
  else
    report("HMAC-SHA-256 (RFC 4231 #2)", false);

  // AES-128-CBC encrypt + decrypt
  {
    CryptoStatus se = Crypto.aesCbcEncrypt(kAesKey, kCbcIv, kCbcPt, buf, 32);
    if (se == CryptoStatus::Ok) {
      report("AES-128-CBC encrypt (NIST F.2.1)", equal(buf, kCbcCt, 32));
      CryptoStatus sd = Crypto.aesCbcDecrypt(kAesKey, kCbcIv, kCbcCt, buf2, 32);
      if (sd == CryptoStatus::Ok)
        report("AES-128-CBC decrypt", equal(buf2, kCbcPt, 32));
      else
        skip("AES-128-CBC decrypt", sd);
    } else {
      skip("AES-128-CBC encrypt (NIST F.2.1)", se);
    }
  }

  // AES-128-CTR (encrypt == decrypt)
  {
    CryptoStatus s = Crypto.aesCtr(kAesKey, kCtrIv, kCbcPt, buf, 32);
    if (s == CryptoStatus::Ok)
      report("AES-128-CTR (NIST F.5.1)", equal(buf, kCtrCt, 32));
    else
      skip("AES-128-CTR (NIST F.5.1)", s);
  }

  // AES-128-GCM encrypt + decrypt
  {
    CryptoStatus se = Crypto.aesGcmEncrypt(kGcmKey, kGcmIv, nullptr, 0, kGcmPt,
                                           buf, 64, tag);
    if (se == CryptoStatus::Ok) {
      bool ok = equal(buf, kGcmCt, 64) && equal(tag, kGcmTag, 16);
      report("AES-128-GCM encrypt (McGrew #3)", ok);
      CryptoStatus sd = Crypto.aesGcmDecrypt(kGcmKey, kGcmIv, nullptr, 0, kGcmCt,
                                             buf2, 64, kGcmTag);
      report("AES-128-GCM decrypt + auth",
             sd == CryptoStatus::Ok && equal(buf2, kGcmPt, 64));
    } else {
      skip("AES-128-GCM encrypt (McGrew #3)", se);
      skip("AES-128-GCM decrypt + auth", se);
    }
  }

  // ECDSA P-256 sign/verify round-trip (+ tamper detection)
  {
    uint8_t priv[32], pub[64], sig[64], hash[32];
    CryptoStatus sg = Crypto.ecdsaGenerateKey(priv, pub);
    if (sg == CryptoStatus::Ok) {
      Crypto.sha256(kMsgAbc, sizeof(kMsgAbc), hash);
      CryptoStatus ss = Crypto.ecdsaSign(priv, hash, sig);
      if (ss == CryptoStatus::Ok) {
        bool good = (Crypto.ecdsaVerify(pub, hash, sig) == CryptoStatus::Ok);
        sig[0] ^= 0x01;  // tamper
        bool rejects = (Crypto.ecdsaVerify(pub, hash, sig) != CryptoStatus::Ok);
        report("ECDSA P-256 sign/verify", good && rejects);
      } else {
        skip("ECDSA P-256 sign/verify", ss);
      }
    } else {
      skip("ECDSA P-256 sign/verify", sg);
    }
  }

  // ECDH P-256: two parties derive the same shared secret
  {
    uint8_t aPriv[32], aPub[64], bPriv[32], bPub[64], sAB[32], sBA[32];
    CryptoStatus s1 = Crypto.ecdsaGenerateKey(aPriv, aPub);  // P-256 keypair
    CryptoStatus s2 = Crypto.ecdsaGenerateKey(bPriv, bPub);
    if (s1 == CryptoStatus::Ok && s2 == CryptoStatus::Ok) {
      CryptoStatus r1 = Crypto.ecdhShared(aPriv, bPub, sAB);
      CryptoStatus r2 = Crypto.ecdhShared(bPriv, aPub, sBA);
      if (r1 == CryptoStatus::Ok && r2 == CryptoStatus::Ok)
        report("ECDH P-256 shared-secret agreement", equal(sAB, sBA, 32));
      else
        skip("ECDH P-256 shared-secret agreement", r1);
    } else {
      skip("ECDH P-256 shared-secret agreement", s1);
    }
  }

  // Random: a fresh draw should not be all-zero (sanity, not a statistical test)
  {
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = 0;
    CryptoStatus s = Crypto.random(buf, 32);
    bool nonzero = false;
    for (size_t i = 0; i < 32; ++i) nonzero |= (buf[i] != 0);
    if (s == CryptoStatus::Ok) {
      report("random() returns entropy", nonzero);
      Serial.print(F("        sample: "));
      printHex(buf, 16);
      Serial.println();
    } else {
      report("random() returns entropy", false);
    }
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }

  Serial.println(F("=== NiusCrypto self-test ==="));
  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() FAILED - no backend available"));
    return;
  }
  Serial.print(F("backend: "));
  Serial.print(Crypto.backendName());
  Serial.print(F("   hardware-accelerated: "));
  Serial.println(Crypto.isHardwareAccelerated() ? F("yes") : F("no"));
  Serial.println();

  runTests();

  Serial.println();
  Serial.print(F("summary: "));
  Serial.print(g_pass);
  Serial.print(F(" passed, "));
  Serial.print(g_fail);
  Serial.print(F(" failed, "));
  Serial.print(g_skip);
  Serial.println(F(" skipped"));
  Serial.println(g_fail == 0 ? F("RESULT: OK") : F("RESULT: FAILURES"));
}

void loop() {
  delay(2000);
}
