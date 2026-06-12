# NiusCrypto / CC310 roadmap

Status as of **v0.7.1**. Hardware verification on **board1** (ProMicro clone,
app @ **`0x1000`**, J-Link + COM18) unless noted.

## Done (shipped)

| Area | Delivered |
|------|-----------|
| **Core API** | `random`, SHA-256/384/512, HMAC, HKDF, AES, ChaCha20-Poly1305, P-256, X25519, Ed25519, RSA-2048 |
| **UX (v0.5–v0.6)** | `NIUS_*` macros, packet structs, `supports()`, streaming hash, OnChip fallbacks, RSA import/PSS, `runSelfTest()` |
| **UX (v0.7)** | OnChip link fix (headers without archives), removed legacy implicit RSA APIs, hwverify script templates |
| **OnChip AEAD (v0.7.1)** | `SoftAesGcm`, `SoftChaChaPoly` — board1 **13/13 PASS, 10 SKIP** |
| **Docs** | [API_REFERENCE.md](API_REFERENCE.md), [ONCHIP_BUILD.md](ONCHIP_BUILD.md), [VALIDATION.md](VALIDATION.md), [LIBRARY_MANAGER.md](LIBRARY_MANAGER.md) |
| **Backends** | `CC310Backend` (2-slot RSA pool), `OnChipBackend` fallback |
| **Examples** | 16 sketches incl. `X25519KeyExchange`, `KeyStorage` |
| **Bring-up** | `tools/hwverify/` templates + local `vendor/hwverify/` (git-ignored) |

## Deferred

| Item | Notes |
|------|-------|
| **XIAO HW smoke** | Compile-only until hardware available (out of scope for now) |
| **OnChip ECC/RSA** | Requires CC310 or large software port (GCM/ChaPoly on OnChip since v0.7.1) |

## Explicit non-goals

- Redistributing Nordic binaries in git or Library Manager
- GitHub Actions / remote CI automation
- Replacing SoftDevice crypto inside the BLE stack

## Version tags

| Tag | Highlights |
|-----|------------|
| v0.6.0 | `supports()`, streaming hash, OnChip fallbacks, RSA import/PSS, `runSelfTest()` |
| v0.7.0 | OnChip-only link fix, legacy RSA removal, capture_serial improvements, doc consolidation |
| v0.7.1 | OnChip software AES-GCM + ChaCha20-Poly1305 |
