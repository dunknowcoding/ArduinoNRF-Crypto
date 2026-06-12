/*
  EcdsaSignVerify - sign and verify with ECDSA P-256 (CC310).

  Uses the EcdsaMessage packet API (payload in, signature out). The low-level
  ecdsaSign(priv, hash32, sig) API remains available for pre-hashed messages.

  Open the Serial Monitor at 115200 baud.
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

  Serial.println(F("=== EcdsaSignVerify ==="));
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  EcdsaMessage msg;
  static const char kPayload[] = "Sign me with NiusCrypto";
  msg.payload = reinterpret_cast<const uint8_t*>(kPayload);
  msg.payloadLen = sizeof(kPayload) - 1;

  if (!NIUS_OK(Crypto.ecdsaGenerateKey(msg))) {
    Serial.println(F("keygen failed (need CC310)"));
    return;
  }
  Serial.print(F("public key: "));
  printHex(msg.publicKey, NIUS_P256_PUB);

  if (!NIUS_OK(Crypto.ecdsaSign(msg))) {
    Serial.println(F("sign failed"));
    return;
  }
  Serial.print(F("signature:  "));
  printHex(msg.signature, NIUS_P256_SIG);

  Serial.print(F("verify (valid):   "));
  Serial.println(NIUS_OK(Crypto.ecdsaVerify(msg)) ? F("OK") : F("FAIL"));

  msg.signature[10] ^= 0x80;
  Serial.print(F("verify (tampered): "));
  Serial.println(NIUS_OK(Crypto.ecdsaVerify(msg)) ? F("FAIL (should reject)")
                                                  : F("OK (rejected)"));

  Serial.println(F("RESULT: OK"));
}

void loop() {
  delay(2000);
}
