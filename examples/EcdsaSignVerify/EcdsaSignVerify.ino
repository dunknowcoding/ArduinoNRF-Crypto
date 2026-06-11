/*
  EcdsaSignVerify - sign a message and verify the signature (NIST P-256).

  Generates a key pair, hashes a message with SHA-256, signs the hash, and
  verifies it with the public key. Then it tampers with the signature to show
  that verification rejects it.

  Requires the CC310/Oberon backend (ECDSA is Unsupported on the on-chip
  fallback). Open the Serial Monitor at 115200 baud.
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
  while (!Serial && millis() < 4000UL) {
  }
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  uint8_t priv[32], pub[64], sig[64], hash[32];

  CryptoStatus s = Crypto.ecdsaGenerateKey(priv, pub);
  if (s != CryptoStatus::Ok) {
    Serial.print(F("keygen: "));
    Serial.println(cryptoStatusName(s));
    return;
  }
  Serial.print(F("public key: "));
  printHex(pub, 64);

  const char* msg = "Sign me with NiusCrypto";
  Crypto.sha256((const uint8_t*)msg, strlen(msg), hash);

  if (Crypto.ecdsaSign(priv, hash, sig) != CryptoStatus::Ok) {
    Serial.println(F("sign failed"));
    return;
  }
  Serial.print(F("signature:  "));
  printHex(sig, 64);

  Serial.print(F("verify (valid):   "));
  Serial.println(cryptoStatusName(Crypto.ecdsaVerify(pub, hash, sig)));

  sig[10] ^= 0x80;  // tamper
  Serial.print(F("verify (tampered): "));
  Serial.println(cryptoStatusName(Crypto.ecdsaVerify(pub, hash, sig)));
}

void loop() {
  delay(2000);
}
