/*
  Sha256 - hash a string and print the digest.

  Open the Serial Monitor at 115200 baud and type a line; its SHA-256 is printed
  back. With nothing typed it hashes "abc" so you can compare against the known
  digest ba7816bf...15ad.

  Open the Serial Monitor at 115200 baud (line ending: Newline).
*/
#include <NiusCrypto.h>

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < 0x10) Serial.print('0');
    Serial.print(p[i], HEX);
  }
}

static void hashAndPrint(const uint8_t* data, size_t len) {
  uint8_t digest[32];
  if (Crypto.sha256(data, len, digest) == CryptoStatus::Ok) {
    Serial.print(F("SHA-256: "));
    printHex(digest, 32);
    Serial.println();
  } else {
    Serial.println(F("sha256() failed"));
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  const char* abc = "abc";
  Serial.println(F("hashing \"abc\":"));
  hashAndPrint((const uint8_t*)abc, 3);
  Serial.println(F("type a line to hash it:"));
}

void loop() {
  static char line[128];
  static size_t n = 0;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (n > 0) {
        hashAndPrint((const uint8_t*)line, n);
        n = 0;
      }
    } else if (n < sizeof(line)) {
      line[n++] = c;
    }
  }
}
