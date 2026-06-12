# NiusCrypto / CC310 roadmap

Status as of **v0.5.1**. Hardware verification on **board1** (ProMicro clone,
app @ **`0x1000`**, J-Link + COM18) unless noted.

## Done (shipped)

| Area | Delivered |
|------|-----------|
| **Core API** | `random`, SHA-256/384/512, HMAC, HKDF, AES, ChaCha20-Poly1305, P-256, X25519, Ed25519, RSA-2048 |
| **UX (v0.5)** | `NIUS_*_BYTES` buffer macros, `NIUS_OK` / `cryptoOk`, `RsaKeyPair` explicit handle, message-level ECDSA/Ed25519 helpers, friendly aliases |
| **UX (v0.5.1)** | `rsaRelease`, packet structs (`AesGcmMessage`, seal/open), grouped hash/HMAC messages |
| **Backends** | `CC310Backend` (2-slot RSA pool), `OnChipBackend` fallback |
| **Examples** | 14 sketches incl. `Ed25519SignVerify`, `RsaSignExport` |
| **Bring-up** | Local `vendor/hwverify/` (git-ignored) |

## In progress / next

| Priority | Item | Notes |
|----------|------|-------|
| Ops | **XIAO HW smoke** | Local compile-only until HW available |

## Explicit non-goals

- Redistributing Nordic binaries in git or Library Manager
- GitHub Actions / remote CI automation
- Replacing SoftDevice crypto inside the BLE stack

## Version tags

| Tag | Highlights |
|-----|------------|
| v0.4.0 | Ed25519, RSA pub export/VerifyPub, BleCryptoStress NUS GATT |
| v0.5.0 | `RsaKeyPair` handle, `NIUS_*` macros, ECDSA/Ed25519 message helpers, docs + examples |
| v0.5.1 | `rsaRelease`, packet structs (`AesGcmMessage`, seal/open), `Sha256Message` / `HmacMessage` |
