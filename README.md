# NiusCrypto

Hardware-accelerated cryptography for the [ArduinoNRF](../ArduinoNRF) board
package (nRF52840 / ProMicro). One friendly API — `random`, SHA-256/384/512,
HMAC, HKDF, AES-128 (CBC / CTR / GCM), ChaCha20-Poly1305, ECDSA / ECDH P-256,
X25519, Ed25519, and RSA-2048 — backed by the chip's **Arm CryptoCell 310**
hardware accelerator, with an automatic on-chip fallback when the Nordic binary
is not present.

The library mirrors the layered design of `ArduinoNRF-IMU`: a single front-end
object (`Crypto`) talks to a swappable **backend**, exactly like `NiusIMU` talks
to an `IMUBus`.

```cpp
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  Crypto.begin();                       // picks the best backend
  Serial.println(Crypto.backendName()); // "CC310" or "OnChip"

  uint8_t digest[NIUS_SHA256_BYTES];
  if (NIUS_OK(Crypto.sha256((const uint8_t*)"abc", 3, digest))) {
    // use digest
  }
}
```

## Backends

| Primitive | `CC310` backend | `OnChip` fallback |
|-----------|-----------------|-------------------|
| `random`  | **CC310 TRNG (hardware)**        | RNG peripheral (hardware) |
| `sha256`  | **CC310 SHA-256 (hardware)**     | software (`SoftSha256`)   |
| `sha384`  | Oberon software (via `nrf_oberon`)² | *Unsupported*             |
| `sha512`  | **CC310 SHA-512 (hardware)**     | *Unsupported*             |
| `hmacSha256` | **CC310 HMAC-SHA-256 (CRYS hardware)** | software (`SoftSha256`) |
| `hkdfSha256` | **CC310 HKDF-SHA-256 (CRYS hardware)** | *Unsupported*         |
| `aesCbcEncrypt` | **CC310 AES-CBC (hardware)** | ECB peripheral (hardware) |
| `aesCbcDecrypt` | **CC310 AES-CBC (hardware)** | *Unsupported*¹            |
| `aesCtr`  | **CC310 AES-CTR (hardware)**     | ECB peripheral (hardware) |
| `aesGcm*` | `nrf_oberon` (software²)         | *Unsupported*             |
| `chachaPoly*` | `nrf_oberon` (software²)     | *Unsupported*             |
| `ecdsa*` / `ecdh*` | **CC310 ECC P-256 (hardware)** | *Unsupported*        |
| `x25519*` | **CC310 Curve25519 (hardware)** | *Unsupported*             |
| `ed25519*` | **CC310 Ed25519 (hardware)** | *Unsupported*             |
| `rsa*` | **CC310 RSA-2048 PKCS#1 SHA-256 (hardware)** | *Unsupported*      |

¹ The nRF52840 ECB peripheral only *encrypts*; CBC decryption needs the AES
inverse, so use CTR on the fallback or enable the CC310 backend.
² The classic CryptoCell runtime (CRYS) does not expose AES-GCM or
ChaCha20-Poly1305, so those AEAD primitives run in Nordic's compact
`nrf_oberon` software library instead of on the accelerator. Everything else
on the `CC310` backend runs on the CryptoCell hardware.

`Crypto.begin()` selects `CC310` if the Nordic binaries were vendored and the
CryptoCell powers up, otherwise `OnChip`. You can force a choice with
`Crypto.begin(CryptoEngine::Prefer::CC310 | ::OnChip | ::Auto)`. Operations a
backend cannot do return `CryptoStatus::Unsupported` rather than failing
silently, so a sketch can branch on capability.

> **CC310 = the real CRYS runtime.** NiusCrypto links Nordic's original
> `libnrf_cc310.a` (the self-contained CRYS API) so SHA-256, AES-CBC/CTR, ECDSA
> and ECDH P-256, and the TRNG all execute on the Arm CryptoCell 310 hardware.
> CRYS ships only inside Nordic's nRF5 SDK (not in public nrfxlib), so it is
> imported from a local SDK install rather than auto-downloaded — see
> [docs/VENDORING.md](docs/VENDORING.md). AES-GCM and ChaCha20-Poly1305, which
> CRYS lacks, are provided by the compact `nrf_oberon` library.

## Hardware verification

Verified on real hardware (ProMicro nRF52840, board flashed over SEGGER J-Link /
UF2). `examples/CryptoSelfTest` reports, reading `backend: CC310 /
hardware-accelerated: yes`:

```
PASS  SHA-256("abc")                        PASS  ECDSA P-256 sign/verify
PASS  SHA-384("abc")                        PASS  ECDH P-256 shared-secret
PASS  SHA-512("abc")                        PASS  random() (TRNG, fresh each run)
PASS  HKDF-SHA-256 (RFC 5869 #1)            PASS  AES-128-GCM encrypt + decrypt+auth
PASS  HMAC-SHA-256 (RFC 4231 #2)            PASS  ChaCha20-Poly1305 (RFC 8439 A.5)
PASS  AES-128-CBC/CTR/GCM                    PASS  X25519 + RSA + Ed25519
summary: 20 passed, 0 failed, 0 skipped     RESULT: OK
```

## Installing the library

### Arduino Library Manager

Search **NiusCrypto** in **Sketch → Include Library → Manage Libraries…** or:

```sh
arduino-cli lib install NiusCrypto
```

Indexed via [arduino/library-registry](https://github.com/arduino/library-registry) (PR [#8517](https://github.com/arduino/library-registry/pull/8517)). New releases are picked up automatically when you push a new semver tag with an updated `library.properties` `version`.

**Library Manager installs source only** — CC310 hardware acceleration still requires
running `vendor/tools/setup_vendored.py` locally (Nordic license). Without vendored
blobs, `library.properties` still lists `precompiled=true`; if linking fails with
*cannot find -lnrf_cc310*, comment out the `precompiled` and `ldflags` lines and
rebuild for the OnChip fallback.

### Manual install (GitHub)

1. Clone into your sketchbook libraries folder (or any path passed to
   `--library`):

   ```sh
   git clone https://github.com/dunknowcoding/ArduinoNRF-Crypto.git
   ```

2. Install the [ArduinoNRF](https://github.com/dunknowcoding/ArduinoNRF) board
   package (Boards Manager or local `hardware/arduinonrf/nrf52/`).

3. Vendor the Nordic binaries once per machine (see
   [Enabling the CC310 backend](#enabling-the-cc310-backend)).

4. In Arduino IDE 2: **Sketch → Include Library → Add .ZIP Library…** is not
   required when the folder is already under `~/Documents/Arduino/libraries/`.
   Restart the IDE so `#include <NiusCrypto.h>` resolves.

The in-package `libraries/CC310/` shim in ArduinoNRF declares
`depends=NiusCrypto`; install NiusCrypto before building `#include <NrfCC310.h>`
sketches.

## Enabling the CC310 backend

The Nordic binaries are not bundled. One command populates `src/cortex-m4/`
(archives) and `src/cc310/` (headers):

```sh
python vendor/tools/setup_vendored.py        # CRYS from local nRF5 SDK + Oberon from nrfxlib
```

Or run the steps separately:

```sh
python vendor/tools/import_cc310_sdk.py        # point at your nRF5 SDK 17.x
python vendor/tools/fetch_cc310.py             # Oberon for AES-GCM (default)
```

Both place the soft-float archives, copy headers, and the `precompiled=true` /
`ldflags=-Wl,--start-group -lnrf_cc310 -loberon -Wl,--end-group` lines are
already in `library.properties`. Rebuild and `Crypto.begin()` reports `CC310`.
Without these archives the library still compiles and runs on the `OnChip`
fallback (remove the two `library.properties` lines in that case).

## What to commit

This repository ships **source, examples, and tooling only**. Nordic's binary
license forbids redistributing the CC310/Oberon archives, and local bring-up
scratch is not part of the library.

**Do commit:** `src/` (except the git-ignored vendored folders below), `examples/`,
`docs/`, `vendor/tools/*.py`, `library.properties`, `keywords.txt`, `LICENSE`.

**Do not commit** (already listed in `.gitignore`; each developer generates these
locally):

| Path | Why |
|------|-----|
| `src/cortex-m4/` | `libnrf_cc310.a`, `liboberon.a` — imported/fetched Nordic binaries |
| `src/cc310/` | CRYS + Oberon headers copied by the import/fetch scripts |
| `vendor/nRF5SDK/` | Your local nRF5 SDK tree (only needed as the CRYS import source) |
| `vendor/MANIFEST*.txt`, `vendor/LICENSE-Nordic*.txt` | Generated manifests and license copies |
| `vendor/hwverify/` | **Local only** — J-Link scripts, build output, `arduino-cli.yaml` (git-ignored) |
| `build/`, `_build/`, `*.elf`, `*.hex`, `*.uf2`, `*.map` | Arduino / arduino-cli build artifacts anywhere in the tree |

After cloning, run the two vendoring steps in [Enabling the CC310 backend](#enabling-the-cc310-backend) once on your machine. Board1 J-Link bring-up lives under `vendor/hwverify/` on your machine only — see [docs/VALIDATION.md](docs/VALIDATION.md).

## API

All calls return a `CryptoStatus` (`Ok`, `Unsupported`, `AuthFailed`, …).
Use `NIUS_OK(...)` or `cryptoOk(...)` for quick checks; `cryptoStatusName()`
turns a status into a string.

### Buffer sizes

Declare stack buffers with the `NIUS_*_BYTES` macros from `<NiusCrypto.h>`
(e.g. `uint8_t hash[NIUS_SHA256_BYTES]`, `uint8_t sig[NIUS_RSA2048_SIG]`).

### Core

```cpp
bool        Crypto.begin(Prefer = Auto);
const char* Crypto.backendName();
bool        Crypto.isHardwareAccelerated();

CryptoStatus Crypto.random(uint8_t* buf, size_t len);
CryptoStatus Crypto.sha256(in, len, out);   // out[NIUS_SHA256_BYTES]
CryptoStatus Crypto.hmacSha256(key, keyLen, msg, msgLen, out);
CryptoStatus Crypto.hkdfSha256(ikm, ikmLen, salt, saltLen, info, infoLen, okm, okmLen);
CryptoStatus Crypto.aesCbcEncrypt / aesCbcDecrypt / aesCtr / aesGcm* / chachaPoly*;
CryptoStatus Crypto.chacha20Poly1305Encrypt(...);  // alias
```

### Elliptic curve (CC310 only)

```cpp
CryptoStatus Crypto.ecdsaGenerateKey(priv, pub);
CryptoStatus Crypto.ecdsaSignMessage(priv, msg, msgLen, sig);   // SHA-256 + sign
CryptoStatus Crypto.ecdsaVerifyMessage(pub, msg, msgLen, sig);
CryptoStatus Crypto.ecdhShared(priv, peerPub, shared);

CryptoStatus Crypto.x25519GenerateKey(priv, pub);
CryptoStatus Crypto.x25519Shared(priv, peerPub, shared);

CryptoStatus Crypto.ed25519GenerateKey(secret64, pub32);
CryptoStatus Crypto.ed25519SignFromSeed(seed32, msg, msgLen, sig64);
CryptoStatus Crypto.ed25519Sign / ed25519Verify;
```

`ed25519` **secret** is 64 bytes on CC310 (seed ‖ public key). Use
`ed25519SignFromSeed()` when you only have a 32-byte seed.

### RSA-2048 (CC310 only) — explicit key handle (v0.5+)

```cpp
RsaKeyPair key;
Crypto.rsaGenerate(&key);                    // or rsaGenerateKeyPair(&key)
Crypto.rsaSign(&key, msg, msgLen, sig256);
Crypto.rsaVerify(&key, msg, msgLen, sig256);
Crypto.rsaVerifyWithPubKey(&key.pub, msg, msgLen, sig256);

RsaPublicKey exported;
Crypto.rsaExportPublic(&key, &exported);
```

Legacy implicit key (slot 0, still supported):

```cpp
Crypto.rsa2048GenerateKey();
Crypto.rsaPkcs1Sha256Sign(msg, msgLen, sig256);
```

P-256 public keys are 64 bytes (`X‖Y`), signatures 64 bytes (`R‖S`), private
scalars 32 bytes, all big-endian.

## Examples

| Sketch | What it shows |
|--------|---------------|
| `CryptoSelfTest` | Known-answer tests for every primitive (main verification) |
| `SdCryptoSmoke` | CC310 + SoftDevice layout smoke (`__nrf_app_start`, loop hash) |
| `Backends` | Which backend you get and what each one supports |
| `RandomBytes` | Streaming hardware random numbers |
| `Sha256` | Hashing strings (interactive) |
| `HmacSha256` | RFC 4231 HMAC-SHA-256 known-answer demo |
| `Aes` | CBC / CTR / GCM encrypt-decrypt round-trips |
| `ChaChaPoly1305` | RFC 8439 AEAD encrypt/decrypt known-answer demo |
| `BleCryptoStress` | NimBLE advertising + CC310 SHA/HMAC loop; NUS GATT when connected |
| `HkdfSha256` | HKDF-SHA-256 key derivation (RFC 5869) |
| `EcdsaSignVerify` | P-256 key gen, sign, verify, tamper-detect |
| `Ed25519SignVerify` | Ed25519 sign/verify + sign-from-seed |
| `RsaSignExport` | RSA-2048 with explicit `RsaKeyPair` handle |
| `EcdhKeyExchange` | P-256 shared-secret agreement between two parties |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layers, backend selection, ABI notes
- [docs/ROADMAP.md](docs/ROADMAP.md) — shipped vs planned CRYS capabilities
- [docs/SOFTDEVICE_COEXISTENCE.md](docs/SOFTDEVICE_COEXISTENCE.md) — CC310 + S140 notes
- [docs/MULTI_BOARD.md](docs/MULTI_BOARD.md) — multi-board compile notes and HW status
- [docs/VENDORING.md](docs/VENDORING.md) — vendoring scripts and Nordic binary sources
- [docs/VALIDATION.md](docs/VALIDATION.md) — hardware verification log (ProMicro / board1)
- [docs/BOARD_BRINGUP.md](docs/BOARD_BRINGUP.md) — compile, UF2 flash, J-Link recovery

## License

Apache-2.0 (see `LICENSE`). The vendored Nordic binaries are covered by the
Nordic 5-clause license (`vendor/LICENSE-Nordic*.txt` after fetching/importing)
and are not redistributed in this repository.
