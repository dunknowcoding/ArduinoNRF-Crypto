/*
  EcdhKeyExchange - two parties agree on a shared secret (NIST P-256).

  Alice and Bob each generate a key pair, exchange public keys, and compute the
  same shared secret from their own private key and the peer's public key. The
  two secrets must match - that shared value is what you would feed into a KDF
  to derive a session key.

  Requires the CC310/Oberon backend (ECDH is Unsupported on the on-chip
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

  uint8_t aPriv[32], aPub[64], bPriv[32], bPub[64];
  if (Crypto.ecdsaGenerateKey(aPriv, aPub) != CryptoStatus::Ok ||
      Crypto.ecdsaGenerateKey(bPriv, bPub) != CryptoStatus::Ok) {
    Serial.println(F("keygen failed (need CC310/Oberon backend)"));
    return;
  }

  uint8_t sAB[32], sBA[32];
  CryptoStatus r1 = Crypto.ecdhShared(aPriv, bPub, sAB);  // Alice's view
  CryptoStatus r2 = Crypto.ecdhShared(bPriv, aPub, sBA);  // Bob's view
  if (r1 != CryptoStatus::Ok || r2 != CryptoStatus::Ok) {
    Serial.println(F("ecdh failed"));
    return;
  }

  Serial.print(F("Alice secret: "));
  printHex(sAB, 32);
  Serial.print(F("Bob   secret: "));
  printHex(sBA, 32);
  Serial.println(memcmp(sAB, sBA, 32) == 0 ? F("MATCH - shared secret agreed")
                                           : F("MISMATCH"));
}

void loop() {
  delay(2000);
}
