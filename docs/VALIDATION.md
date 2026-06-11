# Hardware validation — NiusCrypto

What has been verified on real hardware, and how to reproduce it. Reference
board: **AliExpress ProMicro nRF52840** (nice!nano bootloader `0x239A:0x00B3`,
UF2 label `NICENANO`, SoftDevice s140, app start `0x26000`). board1 in the lab
also has a SEGGER J-Link on SWD for recovery.

## Verified (board1, CC310 backend) — 2026-06-11 (P1–P4)

| Test | Result | Notes |
|------|--------|-------|
| `examples/CryptoSelfTest` | **10/10 PASS** | SHA-256, HMAC-SHA-256, AES-CBC/CTR, ECDSA, ECDH, TRNG, AES-GCM (KAT vectors) |
| `CC310Smoke` (expanded shim) | **PASS** | TRNG, SHA-256, HMAC, AES-CTR, ECDSA keygen/sign/verify; `RESULT: OK` |
| `backend: CC310` | **yes** | `hardware-accelerated: yes` on every run |
| UF2 flash + USB serial | **PASS** | 1200-bps touch → NICENANO drive → copy `.uf2` → COM10/COM11 enumerate |
| Full factory recovery | **PASS** | J-Link erase + `nice_nano_bootloader-0.6.0_s140_6.1.1.hex` when SoftDevice was missing |

Expected `CryptoSelfTest` tail:

```
summary: 10 passed, 0 failed, 0 skipped
RESULT: OK
```

## CC310 compatibility shim (board1)

After P0–P4, `libraries/CC310/examples/CC310Smoke` forwards to NiusCrypto and
checks TRNG, SHA-256, HMAC-SHA-256 (RFC 4231 #2), AES-128-CTR (NIST F.5.1), and
ECDSA P-256 keygen/sign/verify. With binaries vendored it should print
`RESULT: OK`.

| Check | Expected |
|-------|----------|
| `begin` / `isAvailable` | OK / true |
| `randomBytes` | OK + hex sample |
| `sha256("abc")` | NIST match PASS |
| `hmacSha256` | RFC 4231 #2 PASS |
| `aes128Ctr` | NIST F.5.1 PASS |
| `ecdsaP256GenerateKey/Sign/Verify` | all OK |
| `ecdhP256ComputeShared` (A↔B) | shared secret match PASS |

## How to reproduce

### 1. Vendor binaries (once per machine)

```sh
python vendor/tools/setup_vendored.py
```

### 2. Compile

```powershell
arduino-cli compile `
  --fqbn arduinonrf:nrf52:promicro_nrf52840 `
  --library F:\path\to\ArduinoNRF-Crypto `
  --build-path F:\path\to\_build `
  F:\path\to\ArduinoNRF-Crypto\examples\CryptoSelfTest
```

### 3. Flash over UF2

See [BOARD_BRINGUP.md](BOARD_BRINGUP.md). Quick path: 1200-bps touch on the app
COM → copy `.uf2` to `NICENANO` → open data COM at 115200.

### 4. CC310 shim smoke

```powershell
arduino-cli compile `
  --fqbn arduinonrf:nrf52:promicro_nrf52840 `
  --library F:\path\to\ArduinoNRF-Crypto `
  F:\path\to\ArduinoNRF\hardware\arduinonrf\nrf52\libraries\CC310\examples\CC310Smoke
```

## Known bring-up gotcha

If the SoftDevice is missing or flash is corrupted, the app can HardFault before
USB enumerates (symptoms: no COM ports, no UF2). **Fix:** J-Link full erase +
reflash the factory combined bootloader image (MBR + s140 + UF2 bootloader).
See [BOARD_BRINGUP.md](BOARD_BRINGUP.md#4-recover-a-non-enumerating-board-j-link).

An early GCM HardFault in that bad state was **not** a library bug; after SoftDevice
recovery all 10 self-test vectors pass including AES-GCM.
