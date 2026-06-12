/*
  X25519KeyExchange - Curve25519 ECDH with X25519Message packet API.

  Requires CC310 backend. Open Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }

  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() failed"));
    return;
  }

  if (!Crypto.supports(CryptoCapability::X25519)) {
    Serial.println(F("X25519 unsupported on this backend"));
    return;
  }

  X25519Message alice;
  X25519Message bob;
  if (!NIUS_OK(Crypto.x25519GenerateKey(alice)) ||
      !NIUS_OK(Crypto.x25519GenerateKey(bob))) {
    Serial.println(F("keygen failed"));
    return;
  }

  alice.peerPublicKey = bob.publicKey;
  bob.peerPublicKey = alice.publicKey;

  if (!NIUS_OK(Crypto.x25519Shared(alice)) ||
      !NIUS_OK(Crypto.x25519Shared(bob))) {
    Serial.println(F("shared secret failed"));
    return;
  }

  bool match = Crypto.secureEqual(alice.sharedSecret, bob.sharedSecret,
                                  NIUS_X25519_KEY);
  Serial.println(match ? F("X25519 shared secrets match") : F("mismatch"));
  alice.reset();
  bob.reset();
}

void loop() {
  delay(2000);
}
