/*
  SdCryptoSmoke - CC310 crypto while SoftDevice layout is active.

  Every S140 ArduinoNRF sketch runs with the SoftDevice in flash below
  __nrf_app_start. This smoke test prints that address, runs SHA-256 + HMAC in
  setup(), prints RESULT: OK, then keeps hashing in loop() while USB serial
  stays up.

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

extern "C" uint32_t __nrf_app_start;

static bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000UL) {}

  Serial.println(F("=== SdCryptoSmoke ==="));
  Serial.print(F("__nrf_app_start=0x"));
  Serial.println(__nrf_app_start, HEX);

  bool pass = (__nrf_app_start >= 0x26000UL);
  Crypto.begin();
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  static const uint8_t kAbc[] = {'a', 'b', 'c'};
  static const uint8_t kShaAbc[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  uint8_t digest[32];
  pass &= (Crypto.sha256(kAbc, sizeof(kAbc), digest) == CryptoStatus::Ok);
  pass &= equal(digest, kShaAbc, 32);

  static const uint8_t kKey[] = {'J', 'e', 'f', 'e'};
  static const uint8_t kMsg[] = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ',
                                 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
                                 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h',
                                 'i', 'n', 'g', '?'};
  static const uint8_t kMac[32] = {
      0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
      0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
      0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
  uint8_t mac[32];
  pass &= (Crypto.hmacSha256(kKey, sizeof(kKey), kMsg, sizeof(kMsg), mac) ==
           CryptoStatus::Ok);
  pass &= equal(mac, kMac, 32);

  Serial.print(F("RESULT: "));
  Serial.println(pass ? F("OK") : F("CHECK"));
  Serial.flush();
}

void loop() {
  static const uint8_t kTick[] = {'s', 'd', '-', 'l', 'o', 'o', 'p'};
  uint8_t d[32];
  Crypto.sha256(kTick, sizeof(kTick), d);
  delay(250);
}
