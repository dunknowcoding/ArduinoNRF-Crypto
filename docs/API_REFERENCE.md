# NiusCrypto API Reference

Complete reference for the public API shipped in **v0.6.0**. All symbols live
in the global `Crypto` object (`ncrypto::CryptoEngine`) unless noted.

**Primary header:** `#include <NiusCrypto.h>`

Topic shortcuts (same library, narrower includes):

| Header | Use when |
|--------|----------|
| `<NiusCrypto.h>` | Everything (recommended) |
| `<Aes.h>` | AES-CBC / CTR / GCM only |
| `<Sha.h>` | SHA-256 / 384 / 512, HKDF |
| `<Hmac.h>` | HMAC-SHA-256 |
| `<Random.h>` | `random()` |
| `<Ecc.h>` | ECDSA, ECDH, X25519, Ed25519 |
| `<Rsa.h>` | RSA-2048 |

See also: [ARCHITECTURE.md](ARCHITECTURE.md) (layers and backends),
[VENDORING.md](VENDORING.md) (CC310 binaries), [VALIDATION.md](VALIDATION.md)
(hardware test log).

---

## Table of contents

1. [Quick start](#1-quick-start)
2. [Types, constants, and helpers](#2-types-constants-and-helpers)
3. [Lifecycle and backend selection](#3-lifecycle-and-backend-selection)
4. [Backend capability matrix](#4-backend-capability-matrix)
5. [Global limitations](#5-global-limitations)
6. [Random number generation](#6-random-number-generation)
7. [Hashing (SHA-256 / SHA-384 / SHA-512)](#7-hashing-sha-256--sha-384--sha-512)
8. [HMAC-SHA-256](#8-hmac-sha-256)
9. [HKDF-SHA-256](#9-hkdf-sha-256)
10. [AES-128 (CBC, CTR, GCM)](#10-aes-128-cbc-ctr-gcm)
11. [ChaCha20-Poly1305 AEAD](#11-chacha20-poly1305-aead)
12. [ECDSA and ECDH (NIST P-256)](#12-ecdsa-and-ecdh-nist-p-256)
13. [X25519 (Curve25519 ECDH)](#13-x25519-curve25519-ecdh)
14. [Ed25519](#14-ed25519)
15. [RSA-2048 PKCS#1 v1.5 + SHA-256](#15-rsa-2048-pkcs1-v15--sha-256)
16. [Packet structs and reset()](#16-packet-structs-and-reset)
17. [Deprecated and alias APIs](#17-deprecated-and-alias-apis)
18. [Advanced: direct backend access](#18-advanced-direct-backend-access)
19. [Error handling patterns](#19-error-handling-patterns)

---

## 1. Quick start

```cpp
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }

  if (!Crypto.begin()) {
    Serial.println(F("Crypto backend failed"));
    return;
  }
  Serial.print(F("backend: "));
  Serial.println(Crypto.backendName());

  uint8_t digest[NIUS_SHA256_BYTES];
  CryptoStatus s = Crypto.sha256((const uint8_t*)"hello", 5, digest);
  if (NIUS_OK(s)) {
    Serial.println(F("SHA-256 OK"));
  } else {
    Serial.print(F("error: "));
    Serial.println(cryptoStatusName(s));
  }
}

void loop() {}
```

Every operation returns `CryptoStatus`. Check with `NIUS_OK(status)` or
`cryptoOk(status)`.

---

## 2. Types, constants, and helpers

### CryptoStatus

| Value | Meaning |
|-------|---------|
| `Ok` | Operation succeeded |
| `HardwareMissing` | No backend could be started (rare with `Prefer::Auto`) |
| `NotStarted` | `Crypto.begin()` was not called or failed |
| `BadParam` | Null pointer, zero length where forbidden, wrong block size, invalid RSA handle, … |
| `InternalError` | Backend or hardware reported failure |
| `Unsupported` | Active backend cannot perform this primitive |
| `AuthFailed` | AEAD tag mismatch or signature verification failed |

```cpp
CryptoStatus s = Crypto.sha256(data, len, out);
if (s == CryptoStatus::AuthFailed) { /* AEAD open or verify */ }
Serial.println(cryptoStatusName(s));
```

### Buffer size macros

Use these in `uint8_t buf[...]` declarations (from `<NiusCrypto.h>`):

| Macro | Bytes | Used for |
|-------|-------|----------|
| `NIUS_SHA256_BYTES` | 32 | SHA-256 digest, HMAC output, P-256 ECDSA hash input |
| `NIUS_SHA384_BYTES` | 48 | SHA-384 digest |
| `NIUS_SHA512_BYTES` | 64 | SHA-512 digest |
| `NIUS_AES128_KEY` | 16 | AES-128 key |
| `NIUS_AES_BLOCK` | 16 | AES block / CBC IV |
| `NIUS_GCM_IV` | 12 | AES-GCM nonce (NIST SP 800-38D) |
| `NIUS_GCM_TAG` | 16 | AES-GCM authentication tag |
| `NIUS_CHACHA_KEY` | 32 | ChaCha20-Poly1305 key |
| `NIUS_CHACHA_NONCE` | 12 | ChaCha20-Poly1305 nonce (RFC 8439) |
| `NIUS_CHACHA_TAG` | 16 | Poly1305 tag |
| `NIUS_P256_PRIV` | 32 | P-256 private scalar *d* |
| `NIUS_P256_PUB` | 64 | P-256 public point *X‖Y* (uncompressed, no `0x04` prefix) |
| `NIUS_P256_SIG` | 64 | ECDSA signature *R‖S* |
| `NIUS_P256_SHARED` | 32 | ECDH shared secret |
| `NIUS_X25519_KEY` | 32 | X25519 private or public key |
| `NIUS_ED25519_SEED` | 32 | Ed25519 seed |
| `NIUS_ED25519_PUB` | 32 | Ed25519 public key |
| `NIUS_ED25519_SECRET` | 64 | Ed25519 secret (CC310 layout: seed ‖ pub) |
| `NIUS_ED25519_SIG` | 64 | Ed25519 signature |
| `NIUS_RSA2048_MOD` | 256 | RSA-2048 modulus buffer |
| `NIUS_RSA2048_SIG` | 256 | RSA-2048 signature |
| `NIUS_RSA_MAX_EXP` | 4 | RSA public exponent buffer |

All multi-byte integer fields for P-256 and RSA are **big-endian** unless noted.
X25519 and Ed25519 keys use **little-endian** byte order (RFC 7748 / RFC 8032).

### Result helpers

```cpp
#define NIUS_OK(status)   /* true when status == CryptoStatus::Ok */
bool cryptoOk(CryptoStatus s);
const char* cryptoStatusName(CryptoStatus s);
```

### RsaKeyPair and RsaPublicKey

```cpp
struct RsaPublicKey {
  uint8_t modulus[NIUS_RSA2048_MOD];
  uint8_t exponent[NIUS_RSA_MAX_EXP];
  uint16_t modLen;   // actual modulus length (typically 256)
  uint16_t expLen;   // actual exponent length (typically 3 for 65537)
};

struct RsaKeyPair {
  uint8_t slot;           // backend slot id; kRsaInvalidSlot when cleared
  RsaPublicKey pub;       // exported public half
  bool valid() const;
  void clear();           // invalidate handle locally
  void reset();           // alias for clear()
};
```

Private RSA key material never leaves the CC310 backend slot. The sketch only
holds a slot index plus the exported public key.

---

## 3. Lifecycle and backend selection

### begin / end

```cpp
enum class Prefer : uint8_t { Auto, CC310, OnChip };

bool begin(Prefer prefer = Prefer::Auto);
void end();
bool started() const;
const char* backendName() const;      // "CC310", "OnChip", or "none"
bool isHardwareAccelerated() const;   // true for CC310
```

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `begin` | `prefer` — backend preference | `true` if a backend started | Brings up CC310 and/or OnChip backend |
| `end` | — | — | Shuts down backend; clears legacy RSA slot |
| `started` | — | `true` after successful `begin` | |
| `backendName` | — | C string | Active backend name |
| `isHardwareAccelerated` | — | `true` when CC310 is active | |

**Basic usage:**

```cpp
Crypto.begin();                                    // Prefer::Auto (default)
Crypto.begin(CryptoEngine::Prefer::CC310);         // fail if no vendored blob
Crypto.begin(CryptoEngine::Prefer::OnChip);        // software / peripheral only
```

**Limitations:**

- `Prefer::CC310` returns `false` when Nordic binaries are not vendored or
  CryptoCell does not power up.
- `Prefer::Auto` almost always succeeds because the OnChip fallback needs no blob.
- All crypto calls except none return `NotStarted` if `begin()` was not successful.

---

## 4. Backend capability matrix

| API group | CC310 backend | OnChip fallback |
|-----------|---------------|-----------------|
| `random` | CC310 TRNG (hardware) | nRF52840 RNG peripheral |
| `sha256` | CC310 SHA-256 (hardware) | `SoftSha256` (software) |
| `sha384` | Oberon software (CC310 path) | Software (`SoftSha512`) |
| `sha512` | CC310 SHA-512 (hardware) | Software (`SoftSha512`) |
| `hmacSha256` | CC310 HMAC (hardware) | Software (`SoftSha256`) |
| `hkdfSha256` | CC310 HKDF (hardware) | Software (`SoftHkdf`) |
| `aesCbcEncrypt` | CC310 AES-CBC (hardware) | ECB peripheral (encrypt path) |
| `aesCbcDecrypt` | CC310 AES-CBC (hardware) | ECB peripheral + software inverse |
| `aesCtr` | CC310 AES-CTR (hardware) | ECB peripheral |
| `sha256Stream` / `sha384Stream` / `sha512Stream` | Software streaming contexts | Software streaming contexts |
| `aesGcm*` | Oberon software | **Unsupported** |
| `chachaPoly*` | Oberon software | **Unsupported** |
| `ecdsa*` / `ecdh*` | CC310 ECC P-256 (hardware) | **Unsupported** |
| `x25519*` | CC310 Curve25519 (hardware) | **Unsupported** |
| `ed25519*` | CC310 Ed25519 (hardware) | **Unsupported** |
| `rsa*` | CC310 RSA-2048 (hardware) | **Unsupported** |

On the CC310 path, AES-GCM and ChaCha20-Poly1305 run in Nordic's compact
`nrf_oberon` library because the classic CRYS runtime does not expose those
AEAD primitives. Everything else listed as CC310 hardware uses the CryptoCell
310 accelerator via `libnrf_cc310.a`.

---

## 5. Global limitations

### Platform and build

- **Target:** nRF52840 only (`architectures=nrf52` in `library.properties`).
- **Board package:** Requires [ArduinoNRF](https://github.com/dunknowcoding/ArduinoNRF).
- **CC310 binaries:** Not redistributed; each developer runs
  `vendor/tools/setup_vendored.py` locally. Without them, link may fail unless
  `precompiled` / `ldflags` lines are removed from `library.properties`.
- **Float ABI:** Vendored archives must be **soft-float** to match the ArduinoNRF
  core. Hard-float archives will not link or will fault at runtime.

### Memory and concurrency

- Backends are **static singletons** — no heap allocation inside the library.
- Packet structs are **non-owning views**; the caller supplies all buffers.
- Call crypto from `setup()` / `loop()` or your own threads at application level.
  Do not call from ISRs above SoftDevice priority without external locking.
- RSA: at most **two live `RsaKeyPair` handles** (two CC310 backend slots).
  Call `rsaRelease()` when done.

### Cryptographic scope

- **AES-128 only** (no AES-256 in this library).
- **RSA-2048 only**, PKCS#1 v1.5 padding with SHA-256 message digest.
- **P-256 only** for ECDSA/ECDH (no secp256k1 or other curves).
- **No built-in padding** for AES-CBC — input length must be a multiple of 16.
  Prefer AES-GCM or ChaCha20-Poly1305 for arbitrary-length authenticated data.
- **Nonce / IV uniqueness** is the caller's responsibility. Reusing a
  (key, nonce) pair under GCM or ChaCha20-Poly1305 breaks confidentiality.

### Nordic license

Vendored `libnrf_cc310.a` and `liboberon.a` are covered by Nordic's 5-clause
license. They cannot be committed to git or shipped via Library Manager source
installs.

---

## 6. Random number generation

### random

```cpp
CryptoStatus random(uint8_t* buf, size_t len);
```

| Parameter | Direction | Description |
|-----------|-----------|-------------|
| `buf` | out | Receives `len` random bytes |
| `len` | in | Number of bytes requested |

**Returns:** `Ok`, `NotStarted`, `BadParam` (null `buf` or `len == 0`), `Unsupported`,
`InternalError`.

**Example:**

```cpp
uint8_t nonce[NIUS_GCM_IV];
if (NIUS_OK(Crypto.random(nonce, sizeof(nonce)))) {
  // use nonce — must be unique per (key, message) under GCM
}
```

**Limitations:** Entropy source depends on backend (TRNG vs RNG peripheral).
This API does not block waiting for health tests beyond what the backend performs.

---

## 7. Hashing (SHA-256 / SHA-384 / SHA-512)

### Low-level (pointer) API

```cpp
CryptoStatus sha256(const uint8_t* in, size_t len, uint8_t out[NIUS_SHA256_BYTES]);
CryptoStatus sha384(const uint8_t* in, size_t len, uint8_t out[NIUS_SHA384_BYTES]);
CryptoStatus sha512(const uint8_t* in, size_t len, uint8_t out[NIUS_SHA512_BYTES]);
```

| Parameter | Description |
|-----------|-------------|
| `in` | Message bytes (`nullptr` allowed only when `len == 0`) |
| `len` | Message length |
| `out` | Receives fixed-size digest |

### Packet API (v0.5.1+)

```cpp
struct Sha256Message {
  const uint8_t* data;
  size_t dataLen;
  uint8_t digest[NIUS_SHA256_BYTES];
  void reset();
};

CryptoStatus sha256(Sha256Message& msg);
```

**Example (basic):**

```cpp
uint8_t digest[NIUS_SHA256_BYTES];
Crypto.sha256((const uint8_t*)"abc", 3, digest);
```

**Example (packet):**

```cpp
Sha256Message msg;
msg.data = (const uint8_t*)"abc";
msg.dataLen = 3;
Crypto.sha256(msg);
// msg.digest[] holds result
msg.reset();
```

**Limitations:** On the CC310 path, `sha384` uses Oberon software while
`sha256`/`sha512` use the CryptoCell hash engine. On OnChip (v0.6+), all three
one-shot and streaming digest APIs are available via software implementations.

---

## 8. HMAC-SHA-256

### Low-level API

```cpp
CryptoStatus hmacSha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* msg, size_t msgLen,
                        uint8_t out[NIUS_SHA256_BYTES]);
```

| Parameter | Description |
|-----------|-------------|
| `key`, `keyLen` | HMAC key (any length; `nullptr` only if `keyLen == 0`) |
| `msg`, `msgLen` | Message |
| `out` | 32-byte MAC |

### Packet API

```cpp
struct HmacMessage {
  const uint8_t* key;
  size_t keyLen;
  const uint8_t* message;
  size_t messageLen;
  uint8_t mac[NIUS_SHA256_BYTES];
  void reset();
};

CryptoStatus hmacSha256(HmacMessage& msg);
```

**Example:**

```cpp
static const uint8_t kKey[] = { /* ... */ };
static const uint8_t kMsg[] = "Test Using Larger Than Block-Size Key - Hash Key First";

HmacMessage mac;
mac.key = kKey;
mac.keyLen = sizeof(kKey);
mac.message = kMsg;
mac.messageLen = sizeof(kMsg) - 1;  // exclude NUL if C string
Crypto.hmacSha256(mac);
```

**Limitations:** When CC310 returns `Unsupported` for HMAC, `CryptoEngine`
automatically falls back to software HMAC via `SoftSha256`.

---

## 9. HKDF-SHA-256

```cpp
CryptoStatus hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                        const uint8_t* salt, size_t saltLen,
                        const uint8_t* info, size_t infoLen,
                        uint8_t* okm, size_t okmLen);
```

| Parameter | Description |
|-----------|-------------|
| `ikm` | Input keying material |
| `salt` | Optional salt (`nullptr` if `saltLen == 0`) |
| `info` | Optional context/application info (`nullptr` if `infoLen == 0`) |
| `okm` | Output keying material buffer |
| `okmLen` | Length of OKM to derive (must be > 0) |

**Example (RFC 5869 test case 1):**

```cpp
static const uint8_t ikm[] = {0x0b, 0x0b, /* ... 22 bytes total */};
static const uint8_t salt[] = {0x00, 0x01, /* ... 13 bytes */};
static const uint8_t info[] = {0xf0, 0xf1, /* ... 10 bytes */};
uint8_t okm[42];

Crypto.hkdfSha256(ikm, sizeof(ikm), salt, sizeof(salt),
                  info, sizeof(info), okm, sizeof(okm));
```

**Limitations:** CC310 only. RFC 5869 limits OKM length; extremely large
`okmLen` may fail with `InternalError` depending on backend limits.

---

## 10. AES-128 (CBC, CTR, GCM)

### AES-CBC — low-level

```cpp
CryptoStatus aesCbcEncrypt(const uint8_t key[NIUS_AES128_KEY],
                           const uint8_t iv[NIUS_AES_BLOCK],
                           const uint8_t* in, uint8_t* out, size_t len);
CryptoStatus aesCbcDecrypt(const uint8_t key[NIUS_AES128_KEY],
                           const uint8_t iv[NIUS_AES_BLOCK],
                           const uint8_t* in, uint8_t* out, size_t len);
```

**Requirements:** `len` must be a **multiple of 16**. No PKCS#7 padding is applied.

### AES-CBC — packet API

```cpp
struct AesCbcMessage {
  uint8_t key[NIUS_AES128_KEY];
  uint8_t iv[NIUS_AES_BLOCK];
  const uint8_t* input;
  size_t inputLen;
  uint8_t* output;
  void reset();
};

CryptoStatus aesCbcSeal(AesCbcMessage& msg);   // encrypt
CryptoStatus aesCbcOpen(AesCbcMessage& msg);   // decrypt
```

### AES-CTR — low-level

```cpp
CryptoStatus aesCtr(const uint8_t key[NIUS_AES128_KEY],
                    const uint8_t iv[NIUS_AES_BLOCK],
                    const uint8_t* in, uint8_t* out, size_t len);
```

Encrypt and decrypt are the same operation. `len` may be any value ≥ 0.

### AES-CTR — packet API

```cpp
struct AesCtrMessage { /* key, iv, input, inputLen, output */ void reset(); };
CryptoStatus aesCtrTransform(AesCtrMessage& msg);
```

### AES-GCM — low-level

```cpp
CryptoStatus aesGcmEncrypt(const uint8_t key[NIUS_AES128_KEY],
                           const uint8_t iv[NIUS_GCM_IV],
                           const uint8_t* aad, size_t aadLen,
                           const uint8_t* in, uint8_t* out, size_t len,
                           uint8_t tag[NIUS_GCM_TAG]);

CryptoStatus aesGcmDecrypt(const uint8_t key[NIUS_AES128_KEY],
                           const uint8_t iv[NIUS_GCM_IV],
                           const uint8_t* aad, size_t aadLen,
                           const uint8_t* in, uint8_t* out, size_t len,
                           const uint8_t tag[NIUS_GCM_TAG]);
```

| Parameter | Description |
|-----------|-------------|
| `iv` | 12-byte nonce — must be unique per key |
| `aad` | Additional authenticated data (not encrypted) |
| `tag` | 16-byte authentication tag (output on encrypt, input on decrypt) |

**Returns on decrypt:** `AuthFailed` when the tag does not match.

### AES-GCM — packet API (recommended)

```cpp
struct AesGcmMessage {
  uint8_t key[NIUS_AES128_KEY];
  uint8_t nonce[NIUS_GCM_IV];
  const uint8_t* authenticatedData;
  size_t authenticatedDataLen;
  const uint8_t* input;
  size_t inputLen;
  uint8_t* output;
  uint8_t authenticationTag[NIUS_GCM_TAG];
  void reset();
};

CryptoStatus aesGcmSeal(AesGcmMessage& msg);   // encrypt + tag
CryptoStatus aesGcmOpen(AesGcmMessage& msg);   // decrypt + verify tag
```

**Example (seal then open):**

```cpp
AesGcmMessage gcm;
memcpy(gcm.key, myKey, NIUS_AES128_KEY);
Crypto.random(gcm.nonce, NIUS_GCM_IV);

gcm.input = plaintext;
gcm.inputLen = plainLen;
gcm.output = ciphertext;
Crypto.aesGcmSeal(gcm);   // gcm.authenticationTag filled

gcm.input = ciphertext;
gcm.output = recovered;
CryptoStatus s = Crypto.aesGcmOpen(gcm);
if (s == CryptoStatus::AuthFailed) { /* tampered */ }

gcm.reset();
```

**Limitations:**

| Topic | Detail |
|-------|--------|
| GCM on CC310 | Oberon software, not CRYS hardware |
| GCM on OnChip | **Unsupported** — vendoring required |
| CBC decrypt on OnChip | Supported (v0.6+) via ECB peripheral + software inverse |
| Empty plaintext | Allowed (`len == 0`); `in`/`out` may be null |
| In-place | Caller must ensure `out` does not overlap `in` unless backend allows it; use separate buffers to be safe |

---

## 11. ChaCha20-Poly1305 AEAD

Same semantics as AES-GCM but with RFC 8439 parameters.

### Low-level

```cpp
CryptoStatus chachaPolyEncrypt(
    const uint8_t key[NIUS_CHACHA_KEY],
    const uint8_t nonce[NIUS_CHACHA_NONCE],
    const uint8_t* aad, size_t aadLen,
    const uint8_t* in, uint8_t* out, size_t len,
    uint8_t tag[NIUS_CHACHA_TAG]);

CryptoStatus chachaPolyDecrypt(/* same parameters; tag is const on decrypt */);
```

### Packet API

```cpp
struct ChaChaPolyMessage { /* key, nonce, aad, input, output, tag */ void reset(); };

CryptoStatus chachaPolySeal(ChaChaPolyMessage& msg);
CryptoStatus chachaPolyOpen(ChaChaPolyMessage& msg);
```

### Aliases

```cpp
chacha20Poly1305Encrypt(...)   // same as chachaPolyEncrypt
chacha20Poly1305Decrypt(...)
chacha20Poly1305Seal(ChaChaPolyMessage&)
chacha20Poly1305Open(ChaChaPolyMessage&)
```

**Limitations:** CC310/Oberon only. OnChip returns `Unsupported`. Nonce must be
unique per key.

---

## 12. ECDSA and ECDH (NIST P-256)

**CC310 only.** All P-256 integers are 32-byte big-endian scalars/points.

### Key generation

```cpp
CryptoStatus ecdsaGenerateKey(uint8_t priv[NIUS_P256_PRIV],
                              uint8_t pub[NIUS_P256_PUB]);
```

### Sign / verify — pre-hashed (advanced)

```cpp
CryptoStatus ecdsaSign(const uint8_t priv[NIUS_P256_PRIV],
                       const uint8_t hash[NIUS_SHA256_BYTES],
                       uint8_t sig[NIUS_P256_SIG]);

CryptoStatus ecdsaVerify(const uint8_t pub[NIUS_P256_PUB],
                         const uint8_t hash[NIUS_SHA256_BYTES],
                         const uint8_t sig[NIUS_P256_SIG]);
```

`hash` must be exactly 32 bytes (typically SHA-256 of the message).

### Sign / verify — message level (basic)

```cpp
CryptoStatus ecdsaSignMessage(const uint8_t priv[NIUS_P256_PRIV],
                              const uint8_t* msg, size_t msgLen,
                              uint8_t sig[NIUS_P256_SIG]);

CryptoStatus ecdsaVerifyMessage(const uint8_t pub[NIUS_P256_PUB],
                                const uint8_t* msg, size_t msgLen,
                                const uint8_t sig[NIUS_P256_SIG]);
```

Internally hashes with SHA-256 then signs/verifies.

### Packet API — EcdsaMessage (v0.5.2, recommended)

```cpp
struct EcdsaMessage {
  uint8_t privateKey[NIUS_P256_PRIV];
  uint8_t publicKey[NIUS_P256_PUB];
  const uint8_t* payload;       // message bytes
  size_t payloadLen;
  const uint8_t* hashOverride;  // advanced: skip SHA-256 when non-null
  uint8_t signature[NIUS_P256_SIG];
  void reset();
};

CryptoStatus ecdsaGenerateKey(EcdsaMessage& msg);
CryptoStatus ecdsaSign(EcdsaMessage& msg);
CryptoStatus ecdsaVerify(EcdsaMessage& msg);
```

**Basic example:**

```cpp
EcdsaMessage ecdsa;
ecdsa.payload = message;
ecdsa.payloadLen = messageLen;
Crypto.ecdsaGenerateKey(ecdsa);
Crypto.ecdsaSign(ecdsa);
Crypto.ecdsaVerify(ecdsa);
ecdsa.reset();
```

**Advanced — sign a precomputed digest:**

```cpp
uint8_t digest[NIUS_SHA256_BYTES];
Crypto.sha256(message, messageLen, digest);

EcdsaMessage ecdsa;
memcpy(ecdsa.privateKey, priv, NIUS_P256_PRIV);
ecdsa.hashOverride = digest;
Crypto.ecdsaSign(ecdsa);
```

### ECDH shared secret

```cpp
CryptoStatus ecdhShared(const uint8_t priv[NIUS_P256_PRIV],
                        const uint8_t peerPub[NIUS_P256_PUB],
                        uint8_t shared[NIUS_P256_SHARED]);
```

**Example (two-party key agreement):**

```cpp
uint8_t aPriv[NIUS_P256_PRIV], aPub[NIUS_P256_PUB];
uint8_t bPriv[NIUS_P256_PRIV], bPub[NIUS_P256_PUB];
uint8_t sAB[NIUS_P256_SHARED], sBA[NIUS_P256_SHARED];

Crypto.ecdsaGenerateKey(aPriv, aPub);
Crypto.ecdsaGenerateKey(bPriv, bPub);
Crypto.ecdhShared(aPriv, bPub, sAB);
Crypto.ecdhShared(bPriv, aPub, sBA);
// sAB and sBA are identical
```

**Limitations:**

- OnChip: all P-256 APIs return `Unsupported`.
- Verification failure returns `AuthFailed` (invalid signature).
- No key validation (point on curve) beyond what CRYS performs internally.

---

## 13. X25519 (Curve25519 ECDH)

**CC310 only.** 32-byte keys, **little-endian**.

```cpp
CryptoStatus x25519GenerateKey(uint8_t priv[NIUS_X25519_KEY],
                               uint8_t pub[NIUS_X25519_KEY]);

CryptoStatus x25519Shared(const uint8_t priv[NIUS_X25519_KEY],
                          const uint8_t peerPub[NIUS_X25519_KEY],
                          uint8_t shared[NIUS_X25519_KEY]);
```

**Example:**

```cpp
uint8_t alicePriv[NIUS_X25519_KEY], alicePub[NIUS_X25519_KEY];
uint8_t bobPriv[NIUS_X25519_KEY], bobPub[NIUS_X25519_KEY];
uint8_t s1[NIUS_X25519_KEY], s2[NIUS_X25519_KEY];

Crypto.x25519GenerateKey(alicePriv, alicePub);
Crypto.x25519GenerateKey(bobPriv, bobPub);
Crypto.x25519Shared(alicePriv, bobPub, s1);
Crypto.x25519Shared(bobPriv, alicePub, s2);
```

**Limitations:** OnChip returns `Unsupported`. Caller should hash `shared`
(e.g. with HKDF) before using as an application key.

---

## 14. Ed25519

**CC310 only.**

### Key formats

| Buffer | Size | Content |
|--------|------|---------|
| `seed` | 32 | Random or deterministic seed |
| `pub` | 32 | Public key |
| `secret` | 64 | CRYS layout: `seed ‖ publicKey` |
| `sig` | 64 | Signature |

### Low-level API

```cpp
CryptoStatus ed25519GenerateKey(uint8_t secret[NIUS_ED25519_SECRET],
                                uint8_t pub[NIUS_ED25519_PUB]);

CryptoStatus ed25519DeriveFromSeed(const uint8_t seed[NIUS_ED25519_SEED],
                                   uint8_t secret[NIUS_ED25519_SECRET],
                                   uint8_t pub[NIUS_ED25519_PUB]);

CryptoStatus ed25519Sign(const uint8_t secret[NIUS_ED25519_SECRET],
                         const uint8_t* msg, size_t msgLen,
                         uint8_t sig[NIUS_ED25519_SIG]);

CryptoStatus ed25519Verify(const uint8_t pub[NIUS_ED25519_PUB],
                           const uint8_t* msg, size_t msgLen,
                           const uint8_t sig[NIUS_ED25519_SIG]);

CryptoStatus ed25519SignFromSeed(const uint8_t seed[NIUS_ED25519_SEED],
                                 const uint8_t* msg, size_t msgLen,
                                 uint8_t sig[NIUS_ED25519_SIG]);
```

`ed25519SignFromSeed` derives the full secret internally, then signs.

### Packet API — Ed25519Message (v0.5.2, recommended)

```cpp
struct Ed25519Message {
  uint8_t secret[NIUS_ED25519_SECRET];
  uint8_t publicKey[NIUS_ED25519_PUB];
  bool useSeed;                          // advanced path
  uint8_t seed[NIUS_ED25519_SEED];
  const uint8_t* payload;
  size_t payloadLen;
  uint8_t signature[NIUS_ED25519_SIG];
  void reset();
};

CryptoStatus ed25519GenerateKey(Ed25519Message& msg);
CryptoStatus ed25519Sign(Ed25519Message& msg);
CryptoStatus ed25519Verify(Ed25519Message& msg);
```

**Basic example:**

```cpp
Ed25519Message ed;
ed.payload = message;
ed.payloadLen = messageLen;
Crypto.ed25519GenerateKey(ed);
Crypto.ed25519Sign(ed);
Crypto.ed25519Verify(ed);
ed.reset();
```

**Advanced — sign from stored seed only:**

```cpp
Ed25519Message ed;
memcpy(ed.seed, storedSeed, NIUS_ED25519_SEED);
ed.useSeed = true;
ed.payload = message;
ed.payloadLen = messageLen;
Crypto.ed25519Sign(ed);
// ed.publicKey is NOT filled by sign-from-seed; set it for verify
```

**Limitations:** OnChip returns `Unsupported`. When using `useSeed`, you must
supply the correct `publicKey` for verification (derive with
`ed25519DeriveFromSeed` if needed).

---

## 15. RSA-2048 PKCS#1 v1.5 + SHA-256

**CC310 only.** Signatures are 256 bytes. Message is hashed with SHA-256 inside
the backend (PKCS#1 DigestInfo for SHA-256).

### Explicit key handle (recommended, v0.5+)

```cpp
CryptoStatus rsaGenerateKeyPair(RsaKeyPair* key);   // alias: rsaGenerate
CryptoStatus rsaSignWithKeyPair(const RsaKeyPair* key,
                                const uint8_t* msg, size_t msgLen,
                                uint8_t sig[NIUS_RSA2048_SIG]);  // alias: rsaSign
CryptoStatus rsaVerifyWithKeyPair(const RsaKeyPair* key, ...);   // alias: rsaVerify
CryptoStatus rsaVerifyWithPublicKey(const RsaPublicKey* pub, ...); // alias: rsaVerifyWithPubKey
CryptoStatus rsaExportPublicKey(const RsaKeyPair* key, RsaPublicKey* out); // alias: rsaExportPublic
CryptoStatus rsaReleaseKeyPair(RsaKeyPair* key);                   // alias: rsaRelease
```

**Example:**

```cpp
RsaKeyPair key;
Crypto.rsaGenerate(&key);

uint8_t sig[NIUS_RSA2048_SIG];
Crypto.rsaSign(&key, message, messageLen, sig);
Crypto.rsaVerify(&key, message, messageLen, sig);

RsaPublicKey exported;
Crypto.rsaExportPublic(&key, &exported);
Crypto.rsaVerifyWithPubKey(&exported, message, messageLen, sig);

Crypto.rsaRelease(&key);   // free backend slot
```

### Legacy implicit key (deprecated)

Uses internal slot 0 inside `CryptoEngine`:

```cpp
CryptoStatus rsa2048GenerateKey();
CryptoStatus rsaPkcs1Sha256Sign(const uint8_t* msg, size_t msgLen,
                                uint8_t sig[NIUS_RSA2048_SIG]);
CryptoStatus rsaPkcs1Sha256Verify(...);
CryptoStatus rsa2048ExportPubKey(uint8_t mod[NIUS_RSA2048_MOD], uint16_t* modLen,
                                 uint8_t* pubExp, uint16_t* pubExpLen);
CryptoStatus rsaPkcs1Sha256VerifyPub(const uint8_t* mod, uint16_t modLen,
                                     const uint8_t* pubExp, uint16_t pubExpLen,
                                     const uint8_t* msg, size_t msgLen,
                                     const uint8_t sig[NIUS_RSA2048_SIG]);
```

Prefer explicit `RsaKeyPair` for multi-key sketches and predictable slot usage.

**Limitations:**

| Topic | Detail |
|-------|--------|
| Key size | 2048-bit modulus only |
| Padding | PKCS#1 v1.5 with SHA-256 |
| Live keys | Maximum **2** concurrent `RsaKeyPair` handles |
| Private key export | Not supported — material stays in CC310 slot |
| OnChip | All RSA APIs return `Unsupported` |
| Verify failure | Returns `AuthFailed` |

---

## 16. Packet structs and reset()

All packet structs in `CryptoPackets.h` are non-owning views. Each provides:

```cpp
void reset();   // *this = Struct{};  zeroes all fields
```

| Struct | Seal / transform | Open / verify | Other operations |
|--------|------------------|---------------|------------------|
| `AesGcmMessage` | `aesGcmSeal` | `aesGcmOpen` | |
| `AesCbcMessage` | `aesCbcSeal` | `aesCbcOpen` | |
| `AesCtrMessage` | `aesCtrTransform` | (same) | |
| `ChaChaPolyMessage` | `chachaPolySeal` | `chachaPolyOpen` | |
| `HmacMessage` | — | — | `hmacSha256(msg)` |
| `Sha256Message` | — | — | `sha256(msg)` |
| `EcdsaMessage` | — | — | `ecdsaGenerateKey`, `ecdsaSign`, `ecdsaVerify` |
| `Ed25519Message` | — | — | `ed25519GenerateKey`, `ed25519Sign`, `ed25519Verify` |

`RsaKeyPair::reset()` clears the handle locally (does **not** free the backend
slot — use `rsaRelease()` for that).

**When to call reset():**

- Before reusing a struct for a different operation
- After handling sensitive intermediate state (best-effort zeroing; not guaranteed
  secure wipe of backend-internal key material)

---

## 17. Deprecated and alias APIs

| Preferred | Alias / deprecated |
|-----------|-------------------|
| `rsaGenerateKeyPair` | `rsaGenerate` |
| `rsaSignWithKeyPair` | `rsaSign` |
| `rsaVerifyWithKeyPair` | `rsaVerify` |
| `rsaVerifyWithPublicKey` | `rsaVerifyWithPubKey` |
| `rsaExportPublicKey` | `rsaExportPublic` |
| `rsaReleaseKeyPair` | `rsaRelease` |
| `chachaPolySeal` / `Open` | `chacha20Poly1305Seal` / `Open` |
| `chachaPolyEncrypt` / `Decrypt` | `chacha20Poly1305Encrypt` / `Decrypt` |
| Explicit `RsaKeyPair` | `rsa2048GenerateKey`, `rsaPkcs1Sha256Sign`, … |

Message-level helpers remain available alongside packet structs:

- `ecdsaSignMessage` / `ecdsaVerifyMessage`
- `ed25519SignFromSeed`

---

## 18. Advanced: direct backend access

```cpp
CryptoBackend* Crypto.backend() const;
```

Returns the active backend pointer, or `nullptr` if not started. Intended for
capability probes or future extensions — most sketches should use `CryptoEngine`
methods only.

Do not delete or replace the backend pointer.

---

## 19. Error handling patterns

### Capability probe before calling

```cpp
if (!Crypto.isHardwareAccelerated()) {
  // ECDSA, RSA, GCM, etc. will return Unsupported
}
```

### Branch on status

```cpp
CryptoStatus s = Crypto.aesGcmOpen(gcm);
switch (s) {
  case CryptoStatus::Ok:
    break;
  case CryptoStatus::AuthFailed:
    Serial.println(F("tag mismatch"));
    break;
  case CryptoStatus::Unsupported:
    Serial.println(F("need CC310 backend"));
    break;
  default:
    Serial.println(cryptoStatusName(s));
    break;
}
```

### Serial debug helper

```cpp
void logCrypto(const __FlashStringHelper* op, CryptoStatus s) {
  Serial.print(op);
  Serial.print(F(": "));
  Serial.println(cryptoStatusName(s));
}
```

---

## Related examples

| Sketch | APIs demonstrated |
|--------|-------------------|
| `CryptoSelfTest` | All primitives, KAT vectors |
| `Backends` | `begin`, capability differences |
| `RandomBytes` | `random` |
| `Sha256`, `HmacSha256`, `HkdfSha256` | Hash and MAC |
| `Aes`, `ChaChaPoly1305` | Symmetric AEAD |
| `EcdsaSignVerify` | `EcdsaMessage` |
| `Ed25519SignVerify` | `Ed25519Message`, seed path |
| `EcdhKeyExchange` | `ecdhShared` |
| `RsaSignExport` | `RsaKeyPair`, export, release |
| `BleCryptoStress` | CC310 under NimBLE load |
| `SdCryptoSmoke` | CC310 with USB CDC active |
| `X25519KeyExchange` | `X25519Message` |
| `KeyStorage` | seed / RSA pub persistence patterns |

---

## Appendix A — v0.6 API additions

### Runtime capability query

```cpp
if (Crypto.supports(CryptoCapability::AesGcm)) { /* ... */ }
cryptoCapabilityName(CryptoCapability::HkdfSha256);
```

Streaming hash (software, all backends):

```cpp
Sha256Context ctx;
Crypto.sha256Begin(ctx);
Crypto.sha256Update(ctx, chunk, len);
Crypto.sha256Finish(ctx, digest);
ctx.reset();
```

### Utilities

```cpp
Crypto.secureEqual(tagA, tagB, 16);
Crypto.wipe(secretBuf, secretLen);
size_t padded = Crypto.pkcs7Pad(plain, plainLen, out, outCap);
size_t unpadded = Crypto.pkcs7Unpad(buf, paddedLen);
```

### RSA import and PSS (CC310)

```cpp
RsaPrivateKeyImport material;
// fill material.modulus, privateExponent, publicExponent + lengths
RsaKeyPair key;
Crypto.rsaImport(&key, &material);
Crypto.rsaPssSign(&key, msg, msgLen, sig);
Crypto.rsaPssVerifyWithPubKey(&exportedPub, msg, msgLen, sig);
```

### Callable self-test

```cpp
SelfTestReport r = Crypto.runSelfTest();
// r.passed, r.failed, r.skipped, r.ok()
```

### New packet structs

`Sha384Message`, `Sha512Message`, `HkdfMessage`, `X25519Message` — same
`reset()` pattern as existing packets.

### Backend error debug

```cpp
if (st == CryptoStatus::InternalError) {
  int32_t crys = Crypto.lastBackendError();
}
```

### OnChip-only builds

See [ONCHIP_BUILD.md](ONCHIP_BUILD.md) and `library.properties.onchip`.

---

*Document version: v0.6.0 — matches `library.properties` version.*
