/*
  KeyStorage - patterns for persisting Ed25519 seed and RSA public key.

  Demonstrates wipe() after use and packet-style APIs. No real flash driver —
  replace the stub store/load with your NVS or EEPROM layer.

  CC310 required for Ed25519; RSA export needs CC310 as well.
*/
#include <NiusCrypto.h>

static uint8_t g_nvsSeed[NIUS_ED25519_SEED];
static RsaPublicKey g_storedRsaPub;

static void storeSeed(const uint8_t seed[NIUS_ED25519_SEED]) {
  memcpy(g_nvsSeed, seed, NIUS_ED25519_SEED);
}

static void loadSeed(uint8_t seed[NIUS_ED25519_SEED]) {
  memcpy(seed, g_nvsSeed, NIUS_ED25519_SEED);
}

static void storeRsaPub(const RsaPublicKey& pub) {
  g_storedRsaPub = pub;
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000UL) {
  }

  if (!Crypto.begin()) {
    Serial.println(F("Crypto.begin() failed"));
    return;
  }

  // --- Ed25519: generate once, store seed, reload later ---
  if (Crypto.supports(CryptoCapability::Ed25519)) {
    Ed25519Message msg;
    static const uint8_t kPayload[] = "stored-key-demo";
    msg.payload = kPayload;
    msg.payloadLen = sizeof(kPayload) - 1;

    if (NIUS_OK(Crypto.ed25519GenerateKey(msg))) {
      memcpy(g_nvsSeed, msg.secret, NIUS_ED25519_SEED);
      storeSeed(g_nvsSeed);
      Crypto.wipe(msg.secret, sizeof(msg.secret));
      msg.reset();

      uint8_t reloadedSeed[NIUS_ED25519_SEED];
      loadSeed(reloadedSeed);
      msg.useSeed = true;
      memcpy(msg.seed, reloadedSeed, NIUS_ED25519_SEED);
      msg.payload = kPayload;
      msg.payloadLen = sizeof(kPayload) - 1;

      if (NIUS_OK(Crypto.ed25519Sign(msg))) {
        Serial.println(F("Ed25519 sign-from-stored-seed OK"));
      }
      Crypto.wipe(reloadedSeed, sizeof(reloadedSeed));
      msg.reset();
    }
  }

  // --- RSA: export public half for offline verify ---
  if (Crypto.supports(CryptoCapability::RsaPkcs1)) {
    RsaKeyPair key;
    if (NIUS_OK(Crypto.rsaGenerate(&key))) {
      RsaPublicKey exported;
      if (NIUS_OK(Crypto.rsaExportPublic(&key, &exported))) {
        storeRsaPub(exported);
        Serial.println(F("RSA public key exported to RAM stub"));
      }
      Crypto.rsaRelease(&key);
    }
  }
}

void loop() {
  delay(5000);
}
