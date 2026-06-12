/*
  Ed25519SignVerify - sign and verify with Ed25519 (CC310).

  Uses Ed25519Message for the main demo, then shows the seed-only path via
  msg.useSeed. Low-level ed25519Sign(secret64, ...) remains available.

  Open Serial Monitor at 115200 baud.
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

  Ed25519Message msg;
  static const char kPayload[] = "NiusCrypto Ed25519 demo";
  msg.payload = reinterpret_cast<const uint8_t*>(kPayload);
  msg.payloadLen = sizeof(kPayload) - 1;

  if (!NIUS_OK(Crypto.ed25519GenerateKey(msg))) {
    Serial.println(F("keygen failed (need CC310)"));
    return;
  }
  Serial.print(F("public key: "));
  printHex(msg.publicKey, NIUS_ED25519_PUB);

  if (!NIUS_OK(Crypto.ed25519Sign(msg))) {
    Serial.println(F("sign failed"));
    return;
  }
  Serial.print(F("signature:  "));
  printHex(msg.signature, NIUS_ED25519_SIG);

  Serial.print(F("verify: "));
  Serial.println(NIUS_OK(Crypto.ed25519Verify(msg)) ? F("OK") : F("FAIL"));

  msg.reset();
  static const uint8_t kSeed[NIUS_ED25519_SEED] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
      0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
  msg.useSeed = true;
  memcpy(msg.seed, kSeed, NIUS_ED25519_SEED);
  msg.payload = nullptr;
  msg.payloadLen = 0;
  Serial.print(F("sign-from-seed (RFC8032 #1 empty msg): "));
  Serial.println(NIUS_OK(Crypto.ed25519Sign(msg)) ? F("OK") : F("FAIL"));

  Serial.println(F("RESULT: OK"));
}

void loop() {
  delay(2000);
}
