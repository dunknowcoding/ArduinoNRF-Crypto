/*
  BleCryptoStress - NimBLE advertising + CC310 crypto in loop().

  Pumps NimBLE::poll() continuously while running SHA-256 + HMAC-SHA-256 on a
  timer. When a central connects and enables NUS notifications, also exercises
  NimBLE::write() / onReceive() with live crypto on the GATT path.

  Open Serial Monitor at 115200 baud; wait for RESULT: OK (~1 min).
*/
#include <NiusCrypto.h>
#include <NimBLE.h>

static const char kMsg[] = "ble-crypto-stress";
static uint32_t g_iters = 0;
static uint32_t g_errors = 0;
static uint32_t g_nusTx = 0;
static uint32_t g_nusRx = 0;
static bool g_wasConnected = false;

static void onNusRx(const uint8_t* data, size_t len) {
  if (len == 0) return;
  uint8_t mac[32];
  static const uint8_t kKey[8] = {'n', 'u', 's', '-', 'r', 'x', '-', 'k'};
  if (Crypto.hmacSha256(kKey, sizeof(kKey), data, len, mac) != CryptoStatus::Ok)
    g_errors++;
  else
    g_nusRx++;
}

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
  NimBLE::onReceive(onNusRx);
  NimBLE::startAdvertising();
  Serial.println(F("NimBLE advertising; starting crypto loop..."));
}

void loop() {
  NimBLE::poll();

  const bool connected = NimBLE::isConnected();
  if (connected && !g_wasConnected)
    Serial.println(F("NUS connected (GATT crypto active when central writes)"));
  g_wasConnected = connected;

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

  if (connected && (g_iters % 50U) == 0U) {
    if (NimBLE::write(digest, 16) > 0) g_nusTx++;
  }

  g_iters++;
  if ((g_iters % 500U) == 0U) {
    Serial.print(F("iter="));
    Serial.print(g_iters);
    Serial.print(F(" err="));
    Serial.print(g_errors);
    Serial.print(F(" nusTx="));
    Serial.print(g_nusTx);
    Serial.print(F(" nusRx="));
    Serial.println(g_nusRx);
  }

  if (g_iters >= 3000U) {
    Serial.println(g_errors == 0 ? F("RESULT: OK") : F("RESULT: FAIL"));
    while (true) {
      NimBLE::poll();
      delay(1);
    }
  }
}
