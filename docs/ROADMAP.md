# NiusCrypto / CC310 roadmap

Status as of **v0.6.0**. Hardware verification on **board1** (ProMicro clone,
app @ **`0x1000`**, J-Link + COM18) unless noted.

## Done (shipped)

| Area | Delivered |
|------|-----------|
| **Core API** | `random`, SHA-256/384/512, HMAC, HKDF, AES, ChaCha20-Poly1305, P-256, X25519, Ed25519, RSA-2048 |
| **UX (v0.5)** | `NIUS_*_BYTES` buffer macros, `NIUS_OK` / `cryptoOk`, `RsaKeyPair` explicit handle, message-level ECDSA/Ed25519 helpers, friendly aliases |
| **UX (v0.5.1)** | `rsaRelease`, packet structs (`AesGcmMessage`, seal/open), grouped hash/HMAC messages |
| **UX (v0.5.2)** | `EcdsaMessage` / `Ed25519Message` packet sign/verify, `reset()` on all packet structs + `RsaKeyPair` |
| **UX (v0.6)** | `supports()`, streaming hash, OnChip HKDF/SHA-384/CBC-decrypt, RSA import/PSS, `runSelfTest()`, utilities |
| **Docs** | [API_REFERENCE.md](API_REFERENCE.md), [ONCHIP_BUILD.md](ONCHIP_BUILD.md) |
| **Backends** | `CC310Backend` (2-slot RSA pool), `OnChipBackend` fallback |
| **Examples** | 16 sketches incl. `X25519KeyExchange`, `KeyStorage` |
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
| v0.5.2 | `EcdsaMessage` / `Ed25519Message`, `reset()` helpers, [API_REFERENCE.md](API_REFERENCE.md) |
| v0.6.0 | `supports()`, streaming hash, OnChip fallbacks, RSA import/PSS, `runSelfTest()`, [ONCHIP_BUILD.md](ONCHIP_BUILD.md) |
