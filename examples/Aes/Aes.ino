/*
  Aes - encrypt and decrypt a message three ways.

  Shows AES-128 in CBC, CTR and GCM modes with a random key and IV, printing the
  ciphertext and verifying that decryption recovers the plaintext. GCM also
  authenticates: tampering with the ciphertext makes decryption report
  AuthFailed.

  CBC-decrypt, GCM, and ChaPoly run on both backends (OnChip uses software AEAD
  and ECB+inverse for CBC decrypt). ECC/RSA still need CC310.

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
  while (!Serial && millis() < 4000UL) {
  }
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  uint8_t key[16], iv[16];
  Crypto.random(key, sizeof(key));
  Crypto.random(iv, sizeof(iv));

  const char* msg = "NiusCrypto on CC310!";  // 20 bytes
  uint8_t pt[32] = {0};
  size_t mlen = strlen(msg);
  memcpy(pt, msg, mlen);
  size_t padded = 32;  // CBC needs a 16-byte multiple; we pad with zeros here

  uint8_t ct[32], rt[32];

  Serial.println(F("\n[AES-128-CBC]"));
  if (Crypto.aesCbcEncrypt(key, iv, pt, ct, padded) == CryptoStatus::Ok) {
    Serial.print(F("  ct: ")); printHex(ct, padded);
    CryptoStatus d = Crypto.aesCbcDecrypt(key, iv, ct, rt, padded);
    if (d == CryptoStatus::Ok)
      Serial.println(memcmp(rt, pt, padded) == 0 ? F("  decrypt OK")
                                                 : F("  decrypt MISMATCH"));
    else { Serial.print(F("  decrypt: ")); Serial.println(cryptoStatusName(d)); }
  }

  Serial.println(F("\n[AES-128-CTR]"));
  if (Crypto.aesCtr(key, iv, pt, ct, padded) == CryptoStatus::Ok) {
    Serial.print(F("  ct: ")); printHex(ct, padded);
    Crypto.aesCtr(key, iv, ct, rt, padded);  // CTR: same call decrypts
    Serial.println(memcmp(rt, pt, padded) == 0 ? F("  decrypt OK")
                                               : F("  decrypt MISMATCH"));
  }

  Serial.println(F("\n[AES-128-GCM — packet API]"));
  uint8_t iv12[NIUS_GCM_IV];
  memcpy(iv12, iv, sizeof(iv12));
  AesGcmMessage pkt;
  memcpy(pkt.key, key, sizeof(pkt.key));
  memcpy(pkt.nonce, iv12, sizeof(pkt.nonce));
  pkt.input = pt;
  pkt.inputLen = padded;
  pkt.output = ct;
  if (NIUS_OK(Crypto.aesGcmSeal(pkt))) {
    Serial.print(F("  ct:  ")); printHex(ct, padded);
    Serial.print(F("  tag: ")); printHex(pkt.authenticationTag, NIUS_GCM_TAG);
    pkt.input = ct;
    pkt.output = rt;
    Serial.println(NIUS_OK(Crypto.aesGcmOpen(pkt)) && memcmp(rt, pt, padded) == 0
                       ? F("  open OK")
                       : F("  open FAILED"));
  }

  Serial.println(F("\n[AES-128-GCM — classic API]"));
  uint8_t iv12b[NIUS_GCM_IV];
  memcpy(iv12b, iv, sizeof(iv12b));
  uint8_t tag[16];
  CryptoStatus e = Crypto.aesGcmEncrypt(key, iv12b, nullptr, 0, pt, ct, padded, tag);
  if (e == CryptoStatus::Ok) {
    Serial.print(F("  ct:  ")); printHex(ct, padded);
    Serial.print(F("  tag: ")); printHex(tag, 16);
    CryptoStatus d = Crypto.aesGcmDecrypt(key, iv12b, nullptr, 0, ct, rt, padded, tag);
    Serial.println(d == CryptoStatus::Ok && memcmp(rt, pt, padded) == 0
                       ? F("  decrypt + auth OK")
                       : F("  decrypt/auth FAILED"));
    ct[0] ^= 0x01;  // tamper
    Serial.print(F("  tamper -> "));
    Serial.println(cryptoStatusName(
        Crypto.aesGcmDecrypt(key, iv12b, nullptr, 0, ct, rt, padded, tag)));
  } else {
    Serial.print(F("  encrypt: "));
    Serial.println(cryptoStatusName(e));
  }
}

void loop() {
  delay(2000);
}
