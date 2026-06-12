# NiusCrypto / CC310 roadmap

Status as of **v0.3.4**. Hardware verification on **board1** (ProMicro clone,
app @ **`0x1000`**, J-Link + COM11) unless noted. **Seeed XIAO nRF52840**: CI
compile-only until HW is available.

## Done (shipped)

| Area | Delivered |
|------|-----------|
| **Core API** | `random`, SHA-256/384/512, HMAC-SHA-256, HKDF-SHA-256, AES-CBC/CTR/GCM, ChaCha20-Poly1305, ECDSA/ECDH P-256, **X25519**, **RSA-2048 PKCS#1 SHA-256** |
| **Backends** | `CC310Backend` (CRYS + Oberon GCM), `OnChipBackend` fallback |
| **ArduinoNRF shim** | `libraries/CC310/` → NiusCrypto (`depends=NiusCrypto`); SHA-512 forwarded |
| **Vendoring** | `setup_vendored.py`, soft-float CRYS + Oberon |
| **Examples** | 12 sketches incl. `CryptoSelfTest`, `BleCryptoStress`, `ChaChaPoly1305`, `HkdfSha256` |
| **CI** | GitHub Actions compile matrix (ProMicro + XIAO compile-only) + `arduino-lint` |
| **Bring-up** | Local `vendor/hwverify/` (git-ignored), `docs/BOARD_BRINGUP.md`, `docs/VALIDATION.md` |
| **Library Manager** | Indexed as **NiusCrypto** ([registry PR #8517](https://github.com/arduino/library-registry/pull/8517)) |

## In progress / next

| Priority | Item | Notes |
|----------|------|-------|
| Low | **Ed25519** | CRYS EC Edwards API; separate from X25519 |
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
| v0.3.1 | Library Manager indexing, SHA-512 KAT fix |
| v0.3.2 | SHA-384, HKDF-SHA-256, shim SHA-512, arduino-lint, doc sync |
| v0.3.3 | ChaCha20-Poly1305 (Oberon), RFC 8439 KAT, example sketch |
| v0.3.4 | X25519, RSA-2048 PKCS#1 SHA-256, BleCryptoStress (NimBLE + CC310) |
