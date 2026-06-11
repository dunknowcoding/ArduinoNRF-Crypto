/*
  RandomBytes - stream true random numbers from the hardware RNG.

  On the CC310 backend this is a CTR-DRBG seeded by the CryptoCell's TRNG; on
  the on-chip fallback it is the nRF52840 RNG peripheral. Either way the bytes
  are suitable for keys, nonces and IVs.

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
  while (!Serial && millis() < 4000UL) {
  }
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());
}

void loop() {
  uint8_t buf[16];
  if (Crypto.random(buf, sizeof(buf)) == CryptoStatus::Ok) {
    printHex(buf, sizeof(buf));
    Serial.println();
  } else {
    Serial.println(F("random() failed"));
  }
  delay(1000);
}
