# OnChip-only build (no Nordic binaries)

Use this path when **Library Manager** or a fresh clone has no vendored
`libnrf_cc310.a` / `liboberon.a`.

## Quick fix (recommended)

From the repo root:

```powershell
powershell -File tools\use_onchip_build.ps1
```

This copies `library.properties.onchip` and sets `src/internal/BuildProfile.h`
to force the CC310 backend stub (`NIUS_CRYPTO_ONCHIP_ONLY=1`), even when
`src/cc310/` headers and `src/cortex-m4/` archives exist from a prior vendoring
run.

Restore the CC310 profile later:

```powershell
powershell -File tools\use_cc310_build.ps1
```

Manual equivalent:

```powershell
Copy-Item library.properties.onchip library.properties -Force
Copy-Item configs/BuildProfile.onchip.h src/internal/BuildProfile.h -Force
```

Then rebuild. `Crypto.begin()` selects the **OnChip** backend when CC310 is
stubbed or absent.

## Fresh install (no vendored files)

If neither `src/cc310/` nor `src/cortex-m4/` exist, the default
`BuildProfile.h` already auto-stubs CC310 — copying `library.properties.onchip`
(removing `precompiled` / `ldflags`) is enough.

## What works on OnChip

| Capability | Backend |
|------------|---------|
| `random` | nRF52840 RNG |
| `sha256` / streaming SHA-256 | Software |
| `sha384` / `sha512` | Software (`SoftSha512`) |
| `hmacSha256` | Software fallback |
| `hkdfSha256` | Software fallback |
| `aesCbcEncrypt` / `aesCbcDecrypt` | ECB peripheral + software inverse |
| `aesCtr` | ECB peripheral |
| `aesGcm*` | Software (`SoftAesGcm`, 96-bit IV) |
| `chachaPoly*` | Software (`SoftChaChaPoly`, RFC 8439) |
| P-256, X25519, Ed25519, RSA | **Unsupported** — vendoring required |

Probe at runtime:

```cpp
if (Crypto.supports(CryptoCapability::AesGcm)) {
  // CC310 + Oberon available
}
```

## Restore CC310 acceleration

1. Run `powershell -File tools\use_cc310_build.ps1` (or `git checkout -- library.properties src/internal/BuildProfile.h`).
2. Run `python vendor/tools/setup_vendored.py` if archives are missing.
3. Rebuild — `Crypto.backendName()` should report `CC310`.

See [VENDORING.md](VENDORING.md) for import details.

## Hardware validation

On board1, compile with `-DNIUS_FORCE_ONCHIP_SELFTEST` and expect
**13 passed, 10 skipped, RESULT: OK**. See [VALIDATION.md](VALIDATION.md).
