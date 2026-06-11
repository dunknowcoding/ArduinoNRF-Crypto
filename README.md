# NiusCrypto

Hardware-accelerated cryptography for the [ArduinoNRF](../ArduinoNRF) board
package (nRF52840 / ProMicro). One friendly API — `random`, `SHA-256`, `HMAC`,
`AES-128` (CBC / CTR / GCM) and `ECDSA` / `ECDH` on NIST P-256 — backed by the
chip's **Arm CryptoCell 310** hardware accelerator, with an automatic on-chip
fallback when the Nordic binary is not present.

The library mirrors the layered design of `ArduinoNRF-IMU`: a single front-end
object (`Crypto`) talks to a swappable **backend**, exactly like `NiusIMU` talks
to an `IMUBus`.

```cpp
#include <NiusCrypto.h>

void setup() {
  Serial.begin(115200);
  Crypto.begin();                       // picks the best backend
  Serial.println(Crypto.backendName()); // "CC310" or "OnChip"

  uint8_t digest[32];
  Crypto.sha256((const uint8_t*)"abc", 3, digest);   // hardware SHA-256
}
```

## Backends

| Primitive | `CC310` backend | `OnChip` fallback |
|-----------|-----------------|-------------------|
| `random`  | **CC310 TRNG (hardware)**        | RNG peripheral (hardware) |
| `sha256`  | **CC310 SHA-256 (hardware)**     | software (`SoftSha256`)   |
| `sha512`  | **CC310 SHA-512 (hardware)**     | *Unsupported*             |
| `hmacSha256` | **CC310 HMAC-SHA-256 (CRYS hardware)** | software (`SoftSha256`) |
| `aesCbcEncrypt` | **CC310 AES-CBC (hardware)** | ECB peripheral (hardware) |
| `aesCbcDecrypt` | **CC310 AES-CBC (hardware)** | *Unsupported*¹            |
| `aesCtr`  | **CC310 AES-CTR (hardware)**     | ECB peripheral (hardware) |
| `aesGcm*` | `nrf_oberon` (software²)         | *Unsupported*             |
| `ecdsa*` / `ecdh*` | **CC310 ECC P-256 (hardware)** | *Unsupported*        |

¹ The nRF52840 ECB peripheral only *encrypts*; CBC decryption needs the AES
inverse, so use CTR on the fallback or enable the CC310 backend.
² The classic CryptoCell runtime (CRYS) does not expose AES-GCM, so GCM is the
one primitive that runs in Nordic's compact `nrf_oberon` software library
instead of on the accelerator. Everything else on the `CC310` backend runs on
the CryptoCell hardware.

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
> [docs/VENDORING.md](docs/VENDORING.md). AES-GCM, which CRYS lacks, is provided
> by the compact `nrf_oberon` library.

## Hardware verification

Verified on real hardware (ProMicro nRF52840, board flashed over SEGGER J-Link /
UF2). `examples/CryptoSelfTest` reports, reading `backend: CC310 /
hardware-accelerated: yes`:

```
PASS  SHA-256("abc")                        PASS  ECDSA P-256 sign/verify
PASS  HMAC-SHA-256 (RFC 4231 #2)            PASS  ECDH P-256 shared-secret
PASS  AES-128-CBC encrypt + decrypt (NIST)  PASS  random() (TRNG, fresh each run)
PASS  AES-128-CTR (NIST F.5.1)              PASS  AES-128-GCM encrypt + decrypt+auth
summary: 10 passed, 0 failed, 0 skipped     RESULT: OK
```

## Installing the library

NiusCrypto is **not** in the Arduino Library Manager yet (Nordic binaries cannot
be bundled). Install manually:

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
| `vendor/hwverify/` | Temporary J-Link scripts, throwaway verification sketches, UF2/hex build output |
| `build/`, `_build/`, `*.elf`, `*.hex`, `*.uf2`, `*.map` | Arduino / arduino-cli build artifacts anywhere in the tree |

After cloning, run the two vendoring steps in [Enabling the CC310 backend](#enabling-the-cc310-backend) once on your machine. If you use `vendor/hwverify/` for board bring-up, treat it as disposable — nothing in that folder should be pushed.

## API

All calls return a `CryptoStatus` (`Ok`, `Unsupported`, `AuthFailed`, ...);
`cryptoStatusName()` turns it into a string.

```cpp
bool        Crypto.begin(Prefer = Auto);
const char* Crypto.backendName();
bool        Crypto.isHardwareAccelerated();

CryptoStatus Crypto.random(uint8_t* buf, size_t len);
CryptoStatus Crypto.sha256(const uint8_t* in, size_t len, uint8_t out[32]);
CryptoStatus Crypto.sha512(const uint8_t* in, size_t len, uint8_t out[64]);
CryptoStatus Crypto.hmacSha256(const uint8_t* key, size_t keyLen,
                               const uint8_t* msg, size_t msgLen, uint8_t out[32]);

CryptoStatus Crypto.aesCbcEncrypt(key16, iv16, in, out, len /*%16*/);
CryptoStatus Crypto.aesCbcDecrypt(key16, iv16, in, out, len /*%16*/);
CryptoStatus Crypto.aesCtr(key16, iv16, in, out, len);   // enc == dec
CryptoStatus Crypto.aesGcmEncrypt(key16, iv12, aad, aadLen, in, out, len, tag16);
CryptoStatus Crypto.aesGcmDecrypt(key16, iv12, aad, aadLen, in, out, len, tag16);

CryptoStatus Crypto.ecdsaGenerateKey(priv32, pub64);
CryptoStatus Crypto.ecdsaSign(priv32, hash32, sig64);
CryptoStatus Crypto.ecdsaVerify(pub64, hash32, sig64);
CryptoStatus Crypto.ecdhShared(priv32, peerPub64, shared32);
```

Public keys are 64 bytes (`X‖Y`), signatures 64 bytes (`R‖S`), private scalars
32 bytes, all big-endian. `ecdsaSign` takes a 32-byte message **hash**.

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
| `EcdsaSignVerify` | P-256 key gen, sign, verify, tamper-detect |
| `EcdhKeyExchange` | P-256 shared-secret agreement between two parties |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layers, backend selection, ABI notes
- [docs/ROADMAP.md](docs/ROADMAP.md) — shipped vs planned CRYS capabilities
- [docs/SOFTDEVICE_COEXISTENCE.md](docs/SOFTDEVICE_COEXISTENCE.md) — CC310 + S140 notes
- [docs/MULTI_BOARD.md](docs/MULTI_BOARD.md) — CI matrix and HW status per board
- [docs/VENDORING.md](docs/VENDORING.md) — vendoring scripts and Nordic binary sources
- [docs/VALIDATION.md](docs/VALIDATION.md) — hardware verification log (ProMicro / board1)
- [docs/BOARD_BRINGUP.md](docs/BOARD_BRINGUP.md) — compile, UF2 flash, J-Link recovery

## License

Apache-2.0 (see `LICENSE`). The vendored Nordic binaries are covered by the
Nordic 5-clause license (`vendor/LICENSE-Nordic*.txt` after fetching/importing)
and are not redistributed in this repository.
