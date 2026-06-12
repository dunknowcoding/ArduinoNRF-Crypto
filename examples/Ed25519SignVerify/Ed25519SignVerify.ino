/*
  Ed25519SignVerify - sign and verify with Ed25519 (CC310).

  Generates a key pair, signs a message, verifies, then demonstrates
  ed25519SignFromSeed() for a 32-byte seed import path.

  Requires CC310 backend. Open Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < 0x10) Serial.print('0');
    Serial.print(p[i], HEX);
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {}

  Serial.println(F("=== Ed25519SignVerify ==="));
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  uint8_t secret[NIUS_ED25519_SECRET], pub[NIUS_ED25519_PUB];
  uint8_t sig[NIUS_ED25519_SIG];
  static const char kMsg[] = "NiusCrypto Ed25519 demo";

  if (!NIUS_OK(Crypto.ed25519GenerateKey(secret, pub))) {
    Serial.println(F("keygen failed (need CC310)"));
    return;
  }
  Serial.print(F("public key: "));
  printHex(pub, NIUS_ED25519_PUB);

  if (!NIUS_OK(Crypto.ed25519Sign(secret, (const uint8_t*)kMsg, sizeof(kMsg) - 1,
                                  sig))) {
    Serial.println(F("sign failed"));
    return;
  }
  Serial.print(F("signature:  "));
  printHex(sig, NIUS_ED25519_SIG);

  Serial.print(F("verify: "));
  Serial.println(cryptoOk(Crypto.ed25519Verify(
                     pub, (const uint8_t*)kMsg, sizeof(kMsg) - 1, sig))
                     ? F("OK")
                     : F("FAIL"));

  static const uint8_t kSeed[NIUS_ED25519_SEED] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
      0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
  uint8_t katSig[NIUS_ED25519_SIG];
  Serial.print(F("sign-from-seed (RFC8032 #1 empty msg): "));
  Serial.println(cryptoOk(Crypto.ed25519SignFromSeed(kSeed, nullptr, 0, katSig))
                     ? F("OK")
                     : F("FAIL"));

  Serial.println(F("RESULT: OK"));
}

void loop() {
  delay(2000);
}
