/*
  HkdfSha256 - derive key material with HKDF-SHA-256 (RFC 5869).

  Uses test case 1 (L=32) on startup so you can compare against the known OKM
  without typing anything. Requires the CC310 backend (OnChip returns
  Unsupported).

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < 0x10) Serial.print('0');
    Serial.print(p[i], HEX);
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000UL) {}

  Serial.println(F("=== HkdfSha256 (RFC 5869 #1) ==="));
  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() failed"));
    return;
  }
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  static const uint8_t kIkm[22] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  static const uint8_t kSalt[13] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c};
  static const uint8_t kInfo[10] = {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  static const uint8_t kExpect[32] = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf};

  uint8_t okm[32];
  CryptoStatus st = Crypto.hkdfSha256(kIkm, sizeof(kIkm), kSalt, sizeof(kSalt),
                                      kInfo, sizeof(kInfo), okm, sizeof(okm));
  if (st == CryptoStatus::Ok) {
    Serial.print(F("HKDF OKM: "));
    printHex(okm, sizeof(okm));
    Serial.println();
    bool match = true;
    for (size_t i = 0; i < sizeof(okm); ++i) match &= (okm[i] == kExpect[i]);
    Serial.print(F("RFC 5869 #1 match: "));
    Serial.println(match ? F("PASS") : F("FAIL"));
  } else {
    Serial.print(F("hkdfSha256() "));
    Serial.println(cryptoStatusName(st));
  }
}

void loop() {
  delay(2000);
}
