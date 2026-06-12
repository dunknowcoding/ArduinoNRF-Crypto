/*
  RsaSignExport - RSA-2048 with explicit RsaKeyPair handle (CC310).

  Uses the v0.5 API:
    Crypto.rsaGenerate(&key);
    Crypto.rsaSign(&key, msg, len, sig);
    Crypto.rsaVerifyWithPubKey(&key.pub, msg, len, sig);

  Legacy rsa2048GenerateKey() still works but stores keys implicitly.
  Open Serial Monitor at 115200 baud (~5 s for keygen).
*/
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {}

  Serial.println(F("=== RsaSignExport ==="));
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  RsaKeyPair key;
  uint8_t sig[NIUS_RSA2048_SIG];
  static const char kMsg[] = "RSA explicit key demo";

  Serial.println(F("generating RSA-2048 key pair..."));
  if (!NIUS_OK(Crypto.rsaGenerate(&key))) {
    Serial.println(F("rsaGenerate failed (need CC310)"));
    return;
  }
  Serial.print(F("public modulus bytes: "));
  Serial.println(key.pub.modLen);
  Serial.print(F("public exponent bytes: "));
  Serial.println(key.pub.expLen);

  if (!NIUS_OK(Crypto.rsaSign(&key, (const uint8_t*)kMsg, sizeof(kMsg) - 1,
                              sig))) {
    Serial.println(F("sign failed"));
    return;
  }

  Serial.print(F("verify (own key): "));
  Serial.println(cryptoOk(Crypto.rsaVerify(
                     &key, (const uint8_t*)kMsg, sizeof(kMsg) - 1, sig))
                     ? F("OK")
                     : F("FAIL"));

  RsaPublicKey exported;
  if (!NIUS_OK(Crypto.rsaExportPublic(&key, &exported))) {
    Serial.println(F("export failed"));
    return;
  }

  Serial.print(F("verify (exported pub): "));
  Serial.println(
      cryptoOk(Crypto.rsaVerifyWithPubKey(
          &exported, (const uint8_t*)kMsg, sizeof(kMsg) - 1, sig))
          ? F("OK")
          : F("FAIL"));

  sig[0] ^= 0x01;
  Serial.print(F("verify (tampered sig): "));
  Serial.println(
      cryptoOk(Crypto.rsaVerifyWithPubKey(
          &exported, (const uint8_t*)kMsg, sizeof(kMsg) - 1, sig))
          ? F("FAIL (should reject)")
          : F("OK (rejected)"));

  Crypto.rsaRelease(&key);
  Serial.println(F("rsaRelease: slot freed"));

  Serial.println(F("RESULT: OK"));
}

void loop() {
  delay(2000);
}
