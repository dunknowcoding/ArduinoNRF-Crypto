# Architecture

NiusCrypto copies the shape of `ArduinoNRF-IMU`: a thin, friendly front object
delegates to a swappable implementation.

```
            sketch
              |
        Crypto (CryptoEngine)          <- facade, the global object
              |
        CryptoBackend (interface)      <- one surface, many implementations
         /          \
   CC310Backend   OnChipBackend
   (CRYS runtime   (ECB peripheral +
    + Oberon GCM)   RNG + SoftSha256)
```

The `CC310Backend` drives the real Arm CryptoCell 310 through Nordic's CRYS
runtime (`libnrf_cc310.a`): SHA-256, AES-CBC/CTR, ECDSA/ECDH P-256 and the TRNG
all run on the accelerator. AES-GCM — which CRYS does not expose — is the only
primitive that runs in the compact `nrf_oberon` software library.

| IMU library | Crypto library |
|-------------|----------------|
| `IMUSensor` (façade) | `CryptoEngine` / `Crypto` |
| `IMUBus` (abstract)  | `CryptoBackend` (abstract) |
| `I2CBus`, `SPIBus`   | `CC310Backend`, `OnChipBackend` |

## Files

```
src/
  NiusCrypto.h            public umbrella + global `Crypto`
  ArduinoNRF_Crypto.h     framework umbrella (types/backend/engine, no global)
  Aes.h Sha.h Hmac.h Ecc.h Random.h   topic forwarders (all include NiusCrypto.h)
  crypto/
    CryptoTypes.h         CryptoStatus + size constants
    CryptoBackend.h       the abstract backend (all ops default to Unsupported)
    CryptoEngine.h/.cpp   facade: backend selection, arg checks, HMAC
  backends/
    OnChipBackend.h/.cpp  ECB-peripheral AES + RNG + software SHA
    SoftSha256.h/.cpp     incremental FIPS 180-4 SHA-256
    CC310Backend.h/.cpp   CRYS runtime (RNG/SHA/AES/ECC) + Oberon GCM, __has_include-gated
  cc310/                  vendored Nordic headers (CRYS + Oberon, git-ignored)
  cortex-m4/              vendored Nordic .a archives (libnrf_cc310.a + liboberon.a, git-ignored)
vendor/tools/import_cc310_sdk.py   imports libnrf_cc310.a (CRYS) from a local nRF5 SDK
vendor/tools/fetch_cc310.py        fetches liboberon.a (GCM) from public nrfxlib
```

HMAC-SHA-256 is routed through the active backend first: `CC310Backend`
implements it with CRYS `CRYS_HMAC_*` on the CryptoCell hardware; when the
CC310 backend is absent or returns `Unsupported`, `CryptoEngine` falls back to
`SoftSha256::hmacSha256()` so the on-chip path still works without hardware
HMAC.

## Backend selection

`CryptoEngine::begin(Prefer)`:

- `Prefer::Auto` (default): try `CC310Backend::begin()`; if it returns false
  (binaries not vendored, or CryptoCell did not power up) fall back to
  `OnChipBackend::begin()`.
- `Prefer::CC310` / `Prefer::OnChip`: use exactly that one; `begin()` returns
  false if it is unavailable.

Both backends are static singletons inside `CryptoEngine.cpp` — no heap, the
active backend is just a pointer.

## Capability model

Every operation on `CryptoBackend` has a default that returns
`CryptoStatus::Unsupported`; a backend overrides only what it can do. So the
on-chip fallback simply does not override GCM/ECDSA/ECDH and those calls report
`Unsupported`, while `CryptoEngine` still type-checks arguments and guards the
not-started case uniformly.

## Conditional compilation

`CC310Backend.cpp` is gated on `__has_include("../cc310/sns_silib.h")` (the CRYS
SaSi library header). Before the binaries are imported that header does not
exist, so the file compiles as a harmless stub (`CC310Backend::begin()` returns
false) and the library builds against the on-chip fallback only. After importing
the CRYS runtime + Oberon, the real implementation compiles and
`library.properties` carries the `precompiled`/`ldflags` directives that link the
archives.

## Float ABI (important)

The ArduinoNRF core compiles Cortex-M4 code with `-mcpu=cortex-m4 -mthumb` and
**no** `-mfloat-abi=hard` / `-mfpu`, i.e. the **soft-float ABI**. The vendored
archives must therefore be the `cortex-m4/soft-float` variants — both
`import_cc310_sdk.py` (CRYS, the `soft-float/no-interrupts` build) and
`fetch_cc310.py` (Oberon) select exactly those. Mixing a hard-float archive with
this soft-float core fails to link or faults at runtime.

## Build-system note

Linking a precompiled (`.a`) Arduino library needs the platform's link recipe to
honour `compiler.libraries.ldflags`. The ArduinoNRF `platform.txt`
`recipe.c.combine.pattern` includes `{compiler.libraries.ldflags}` (default
empty) so a sketch that links no precompiled library is unaffected, while
NiusCrypto's `ldflags` pull in the two archives via a `--start-group/--end-group`
pair.
