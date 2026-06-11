/*
  Backends - see which backend you get and what it can do.

  Crypto.begin() picks the best backend automatically, but you can also force
  one. This sketch prints the auto choice, then probes each backend's
  capabilities by trying one operation from each family and reporting whether it
  is supported.

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

static void tryBackend(CryptoEngine::Prefer prefer, const char* label) {
  Serial.print(F("--- "));
  Serial.print(label);
  Serial.println(F(" ---"));
  if (!Crypto.begin(prefer)) {
    Serial.println(F("  begin() failed (backend unavailable)"));
    return;
  }
  Serial.print(F("  backend: "));
  Serial.print(Crypto.backendName());
  Serial.print(F("  hw-accel: "));
  Serial.println(Crypto.isHardwareAccelerated() ? F("yes") : F("no"));

  uint8_t key[16] = {0}, iv[16] = {0}, in[16] = {0}, out[16], tag[16];
  uint8_t hash[32], priv[32], pub[64], sig[64], shared[32];

  Serial.print(F("  random   : "));
  Serial.println(cryptoStatusName(Crypto.random(out, 16)));
  Serial.print(F("  sha256   : "));
  Serial.println(cryptoStatusName(Crypto.sha256(in, 16, hash)));
  Serial.print(F("  aes-cbc  : "));
  Serial.println(cryptoStatusName(Crypto.aesCbcEncrypt(key, iv, in, out, 16)));
  Serial.print(F("  aes-ctr  : "));
  Serial.println(cryptoStatusName(Crypto.aesCtr(key, iv, in, out, 16)));
  Serial.print(F("  aes-gcm  : "));
  Serial.println(
      cryptoStatusName(Crypto.aesGcmEncrypt(key, iv, nullptr, 0, in, out, 16, tag)));
  Serial.print(F("  ecdsa kg : "));
  Serial.println(cryptoStatusName(Crypto.ecdsaGenerateKey(priv, pub)));
  Serial.print(F("  ecdh     : "));
  Serial.println(cryptoStatusName(Crypto.ecdhShared(priv, pub, shared)));
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }

  Serial.println(F("=== NiusCrypto backends ==="));
  tryBackend(CryptoEngine::Prefer::Auto, "Auto (default)");
  tryBackend(CryptoEngine::Prefer::CC310, "Force CC310");
  tryBackend(CryptoEngine::Prefer::OnChip, "Force on-chip fallback");
}

void loop() {
  delay(2000);
}
