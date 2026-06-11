# Vendoring the Nordic binaries

`Crypto.begin()` runs on the on-chip fallback out of the box. The `CC310`
backend links two Nordic archives into `src/cortex-m4/` and their headers into
`src/cc310/` (both folders are git-ignored — binaries are vendored locally, not
committed):

| Archive | Provides | Source | Imported by |
|---------|----------|--------|-------------|
| `libnrf_cc310.a` | CRYS runtime: SHA-256, AES-CBC/CTR, ECDSA/ECDH P-256, TRNG — **on CC310 hardware** | local **nRF5 SDK 17.x** | `vendor/tools/import_cc310_sdk.py` |
| `liboberon.a` | AES-128-**GCM** only (CRYS has no GCM) | public **nrfxlib** (no login) | `vendor/tools/fetch_cc310.py --oberon-only` |

`library.properties` already carries the matching link directives:

```
precompiled=true
ldflags=-Wl,--start-group -lnrf_cc310 -loberon -Wl,--end-group
```

## 1. Import the CRYS runtime from a local nRF5 SDK

The classic self-contained CryptoCell library (`nrf_cc310`, the CRYS API) is the
only Nordic binary that runs **AES + ECC + hashing on the CC310 hardware**. It
ships **only inside the nRF5 SDK** (never in public nrfxlib), so it is copied
from a local SDK install rather than downloaded:

```sh
# point the script at your nRF5 SDK 17.x (it also searches common install dirs)
python vendor/tools/import_cc310_sdk.py
```

It copies the **soft-float / no-interrupts** `libnrf_cc310.a` plus the full CRYS
header tree (`crys_*.h`, `nrf_cc310_*`, `ssi_*`, ...) and writes a manifest. The
nRF5 SDK 17.1.0 used for this library lives under `vendor/` locally and is
git-ignored.

## 2. Fetch Oberon for AES-GCM

```sh
# any Python 3; standard library only; no login required
python vendor/tools/fetch_cc310.py --oberon-only
```

This downloads the soft-float `liboberon.a` and its headers from the public
[`nrfconnect/sdk-nrfxlib`](https://github.com/nrfconnect/sdk-nrfxlib) repo and
leaves `library.properties` untouched. Set `GITHUB_TOKEN` to raise the API rate
limit if needed.

After both steps, rebuild — `Crypto.begin()` reports `CC310` and
`isHardwareAccelerated()` returns `true`.

## Why CRYS (and not the nrfxlib-only combination)

Three CC310 options exist; only CRYS runs the full primitive set on hardware:

1. **`nrf_cc310` (CRYS API)** — self-contained, does AES + ECC + hashing on the
   CryptoCell. nRF5-SDK-only. **What NiusCrypto uses.**
2. **`nrf_cc310_mbedcrypto` (PSA driver)** — runs AES/ECC on CC310 but needs the
   whole mbedTLS/PSA header tree — too heavy to vendor into an Arduino library.
3. **`nrf_cc310_platform` + `nrf_oberon`** — public/scriptable, but only RNG +
   SHA-256 run on CC310; AES/ECC fall back to Oberon software. This is the
   **legacy fallback** path (see below).

## Legacy fallback (no local nRF5 SDK)

If you cannot install the nRF5 SDK, run `fetch_cc310.py` with **no flags**. It
downloads `nrf_cc310_platform` + `nrf_oberon` from public nrfxlib and patches
`library.properties` with the legacy ldflags
`-lnrf_cc310_platform -loberon`. In this mode RNG and SHA-256 run on the CC310
hardware while AES and P-256 ECC run in Oberon software. Replace the imported
`libnrf_cc310.a` setup accordingly.

## Soft-float only

The ArduinoNRF core builds with the **soft-float ABI** (see
[ARCHITECTURE.md](ARCHITECTURE.md#float-abi-important)). Both importers select
the `cortex-m4/soft-float` variants. Do not substitute hard-float archives — the
mix fails to link or faults at runtime.

## Reverting

Delete `src/cortex-m4/` and `src/cc310/`, and remove the `precompiled` /
`ldflags` lines from `library.properties`. The library returns to on-chip-only.
