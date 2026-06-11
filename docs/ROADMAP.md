# NiusCrypto / CC310 roadmap

Status as of **v0.3.0**. Hardware verification on **board1** (ProMicro nRF52840,
S140 @ `0x26000`, J-Link + COM11) unless noted.

## Done (shipped)

| Area | Delivered |
|------|-----------|
| **Core API** | `random`, SHA-256, HMAC-SHA-256, AES-CBC/CTR/GCM, ECDSA/ECDH P-256 |
| **Backends** | `CC310Backend` (CRYS + Oberon GCM), `OnChipBackend` fallback |
| **ArduinoNRF shim** | `libraries/CC310/` → NiusCrypto (`depends=NiusCrypto`) |
| **Vendoring** | `setup_vendored.py`, soft-float CRYS + Oberon |
| **Examples** | 9 sketches incl. `CryptoSelfTest`, `HmacSha256`, `SdCryptoSmoke` |
| **CI** | GitHub Actions compile (on-chip stub + multi-board matrix) |
| **Bring-up** | `verify_board1.ps1`, `docs/BOARD_BRINGUP.md`, `docs/VALIDATION.md` |

## In progress / next

| Priority | Item | Notes |
|----------|------|-------|
| P11+ | **SHA-512** | ✅ CRYS hardware + KAT in `CryptoSelfTest` (v0.3.0) |
| Medium | **SHA-384** | Same CRYS hash API as SHA-512 |
| Medium | **HKDF** | CRYS exposes `CRYS_HKDF_*`; needs API + KAT |
| Low | **ChaCha20-Poly1305** | CRYS has module; not wired in NiusCrypto yet |
| Low | **RSA** | CRYS RSA; large surface, defer until needed |
| Low | **Curve25519 / Ed25519** | CRYS ECP types exist; separate from P-256 path |
| Ops | **Self-hosted CI + blobs** | Full CC310 link test on a runner with local SDK import |
| Ops | **XIAO HW smoke** | CI compile-only today; HW when board available |

## Explicit non-goals (for now)

- Redistributing Nordic binaries in git or Library Manager
- ARM TrustZone-M (nRF52840 is Cortex-M4, no TZ-M)
- Replacing SoftDevice crypto with CC310 inside the BLE stack itself

## Version tags

| Tag | Highlights |
|-----|------------|
| v0.2.0 | Initial NiusCrypto release, CC310 shim P0 |
| v0.2.1 | Shim API expansion, HmacSha256, board1 verify scripts |
| v0.3.0 | SHA-512, SdCryptoSmoke, multi-board CI, roadmap |
