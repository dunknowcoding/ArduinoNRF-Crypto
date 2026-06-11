/*
  HmacSha256 - compute HMAC-SHA-256 over a message.

  Uses RFC 4231 test case 2 on startup ("Jefe" / "what do ya want for nothing?")
  so you can compare against 5bdcc146...3843 without typing anything.

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < 0x10) Serial.print('0');
    Serial.print(p[i], HEX);
  }
}

static void hmacAndPrint(const uint8_t* key, size_t keyLen,
                         const uint8_t* msg, size_t msgLen) {
  uint8_t mac[32];
  if (Crypto.hmacSha256(key, keyLen, msg, msgLen, mac) == CryptoStatus::Ok) {
    Serial.print(F("HMAC-SHA-256: "));
    printHex(mac, 32);
    Serial.println();
  } else {
    Serial.println(F("hmacSha256() failed"));
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  static const uint8_t kKey[] = {'J', 'e', 'f', 'e'};
  static const uint8_t kMsg[] = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ',
                                 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
                                 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h',
                                 'i', 'n', 'g', '?'};
  Serial.println(F("RFC 4231 test case 2:"));
  hmacAndPrint(kKey, sizeof(kKey), kMsg, sizeof(kMsg));
  Serial.println(F("(interactive HMAC from typed key/msg not implemented)"));
}

void loop() {
  delay(1000);
}
