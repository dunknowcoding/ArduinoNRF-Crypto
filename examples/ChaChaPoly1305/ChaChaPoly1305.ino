/*
  ChaChaPoly1305 - AEAD encrypt/decrypt with ChaCha20-Poly1305 (RFC 8439).

  Runs appendix A.5 on startup (32-byte PT, 8-byte AAD). Requires the CC310
  backend with Oberon (OnChip returns Unsupported).

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

  Serial.println(F("=== ChaCha20-Poly1305 (RFC 8439 A.5) ==="));
  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() failed"));
    return;
  }
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  static const uint8_t kKey[32] = {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
      0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
  static const uint8_t kNonce[12] = {0x07, 0x00, 0x00, 0x00, 0x41, 0xb0,
                                       0x51, 0xec, 0x5e, 0x98, 0x56, 0x63};
  static const uint8_t kAad[8] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                                0x57};
  static const uint8_t kPt[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t kExpectCt[32] = {
      0x10, 0xab, 0x09, 0x03, 0x36, 0x4f, 0x86, 0xd6, 0x9d, 0x82, 0x82, 0xf6,
      0x9d, 0xd2, 0x35, 0xc3, 0xc1, 0xd9, 0xdd, 0xcb, 0x11, 0x0b, 0x4b, 0xa9,
      0xc7, 0xcd, 0x32, 0xe7, 0x1c, 0xe8, 0xa8, 0x93};
  static const uint8_t kExpectTag[16] = {
      0x66, 0x48, 0xaa, 0x82, 0x1b, 0x78, 0x61, 0x95, 0x08, 0x75, 0xf9, 0x5b,
      0x2c, 0xe5, 0x6e, 0x5f};

  uint8_t ct[32], pt[32], tag[16];
  CryptoStatus st = Crypto.chachaPolyEncrypt(kKey, kNonce, kAad, sizeof(kAad),
                                             kPt, ct, sizeof(kPt), tag);
  if (st != CryptoStatus::Ok) {
    Serial.print(F("chachaPolyEncrypt() "));
    Serial.println(cryptoStatusName(st));
    return;
  }

  Serial.print(F("ciphertext: "));
  printHex(ct, sizeof(ct));
  Serial.println();
  Serial.print(F("tag:        "));
  printHex(tag, sizeof(tag));
  Serial.println();

  bool encOk = true;
  for (size_t i = 0; i < sizeof(ct); ++i) encOk &= (ct[i] == kExpectCt[i]);
  for (size_t i = 0; i < sizeof(tag); ++i) encOk &= (tag[i] == kExpectTag[i]);
  Serial.print(F("RFC 8439 A.5 encrypt: "));
  Serial.println(encOk ? F("PASS") : F("FAIL"));

  st = Crypto.chachaPolyDecrypt(kKey, kNonce, kAad, sizeof(kAad), ct, pt,
                                sizeof(ct), tag);
  Serial.print(F("decrypt:    "));
  Serial.println(cryptoStatusName(st));
  if (st == CryptoStatus::Ok) {
    bool decOk = true;
    for (size_t i = 0; i < sizeof(pt); ++i) decOk &= (pt[i] == kPt[i]);
    Serial.print(F("plaintext match: "));
    Serial.println(decOk ? F("PASS") : F("FAIL"));
  }
}

void loop() {
  delay(2000);
}
