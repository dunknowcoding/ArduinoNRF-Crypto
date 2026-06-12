/*
  CryptoSelfTest - known-answer tests for every NiusCrypto primitive.

  Brings up the best backend (CC310 hardware when the Nordic binaries are
  vendored, otherwise the on-chip fallback) and checks each operation against a
  published test vector or a sign/verify round-trip. Prints PASS / FAIL / SKIP
  per item and a final summary.

  Define NIUS_FORCE_ONCHIP_SELFTEST at compile time to call
  Crypto.begin(CryptoEngine::Prefer::OnChip) for OnChip-only validation.

  On a board with CC310 vendored every line should read PASS. On the bare
  on-chip fallback, ECC/RSA and related tests read SKIP (Unsupported) — that is
  expected, not a failure. GCM and ChaCha20-Poly1305 run in software on OnChip.

  Open the Serial Monitor at 115200 baud.
*/
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }

  Serial.println(F("=== NiusCrypto self-test ==="));
#if defined(NIUS_FORCE_ONCHIP_SELFTEST)
  const bool began = Crypto.begin(CryptoEngine::Prefer::OnChip);
#else
  const bool began = Crypto.begin();
#endif
  if (!began) {
    Serial.println(F("Crypto.begin() FAILED - no backend available"));
    return;
  }
  Serial.print(F("backend: "));
  Serial.print(Crypto.backendName());
  Serial.print(F("   hardware-accelerated: "));
  Serial.println(Crypto.isHardwareAccelerated() ? F("yes") : F("no"));
  Serial.println();

  SelfTestReport result = Crypto.runSelfTest();

  Serial.println();
  Serial.print(F("summary: "));
  Serial.print(result.passed);
  Serial.print(F(" passed, "));
  Serial.print(result.failed);
  Serial.print(F(" failed, "));
  Serial.print(result.skipped);
  Serial.println(F(" skipped"));
  Serial.println(result.ok() ? F("RESULT: OK") : F("RESULT: FAILURES"));
}

void loop() {
  delay(2000);
}
