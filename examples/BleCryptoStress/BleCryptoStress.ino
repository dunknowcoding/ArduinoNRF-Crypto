/*
  BleCryptoStress - NimBLE advertising + CC310 crypto in loop().

  Pumps NimBLE::poll() continuously while running SHA-256 + HMAC-SHA-256 on a
  timer. Confirms CC310 CRYS calls coexist with the bare-metal NimBLE stack on
  board1 (no SoftDevice required for this library's NimBLE port).

  Open Serial Monitor at 115200 baud; wait for RESULT: OK (~1 min).
*/
#include <NiusCrypto.h>
#include <NimBLE.h>

static const char kMsg[] = "ble-crypto-stress";
static uint32_t g_iters = 0;
static uint32_t g_errors = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {}

  Serial.println(F("=== BleCryptoStress ==="));
  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() failed"));
    return;
  }
  Serial.print(F("crypto backend: "));
  Serial.println(Crypto.backendName());

  if (NimBLE::begin("NiusCrypto-BLE") != NimBLE::NIMBLE_OK) {
    Serial.println(F("NimBLE::begin() failed"));
    return;
  }
  NimBLE::startAdvertising();
  Serial.println(F("NimBLE advertising; starting crypto loop..."));
}

void loop() {
  NimBLE::poll();

  static uint32_t lastMs = 0;
  const uint32_t now = millis();
  if (now - lastMs < 10U) return;
  lastMs = now;

  uint8_t digest[32], mac[32];
  static const uint8_t kKey[8] = {'s', 't', 'r', 'e', 's', 's', '-', 'k'};
  CryptoStatus s1 = Crypto.sha256(reinterpret_cast<const uint8_t*>(kMsg),
                                  sizeof(kMsg) - 1, digest);
  CryptoStatus s2 = Crypto.hmacSha256(kKey, sizeof(kKey),
                                      reinterpret_cast<const uint8_t*>(kMsg),
                                      sizeof(kMsg) - 1, mac);
  if (s1 != CryptoStatus::Ok || s2 != CryptoStatus::Ok) g_errors++;

  g_iters++;
  if ((g_iters % 500U) == 0U) {
    Serial.print(F("iter="));
    Serial.print(g_iters);
    Serial.print(F(" err="));
    Serial.println(g_errors);
  }

  if (g_iters >= 3000U) {
    Serial.println(g_errors == 0 ? F("RESULT: OK") : F("RESULT: FAIL"));
    while (true) {
      NimBLE::poll();
      delay(1);
    }
  }
}
