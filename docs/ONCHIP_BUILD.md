# OnChip-only build (no Nordic binaries)

Use this path when **Library Manager** or a fresh clone has no vendored
`libnrf_cc310.a` / `liboberon.a` and linking fails with *cannot find
-lnrf_cc310*.

## Quick fix

Replace `library.properties` with the OnChip template (no `precompiled` /
`ldflags` lines):

```powershell
Copy-Item library.properties.onchip library.properties -Force
```

Then rebuild. `Crypto.begin()` selects the **OnChip** backend automatically
when CC310 is absent.

## What works on OnChip (v0.6+)

| Capability | Backend |
|------------|---------|
| `random` | nRF52840 RNG |
| `sha256` / streaming SHA-256 | Software |
| `sha384` / `sha512` | Software (`SoftSha512`) |
| `hmacSha256` | Software fallback |
| `hkdfSha256` | Software fallback |
| `aesCbcEncrypt` / `aesCbcDecrypt` | ECB peripheral + software inverse |
| `aesCtr` | ECB peripheral |
| GCM, ChaCha, P-256, X25519, Ed25519, RSA | **Unsupported** — vendoring required |

Probe at runtime:

```cpp
if (Crypto.supports(CryptoCapability::AesGcm)) {
  // CC310 + Oberon available
}
```

## Restore CC310 acceleration

1. Run `python vendor/tools/setup_vendored.py` (local Nordic SDK license).
2. Restore the default `library.properties` from git (includes `precompiled=true`
   and `ldflags=...`).
3. Rebuild — `Crypto.backendName()` should report `CC310`.

See [VENDORING.md](VENDORING.md) for import details.
