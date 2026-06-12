# Hardware validation — NiusCrypto

What has been verified on real hardware, and how to reproduce it. Reference
board: **AliExpress ProMicro nRF52840 clone** (app @ **`0x1000`**, MBR-only
UF2/DFU). board1 in the lab has a SEGGER J-Link on SWD for J-Link upload at
the correct link address.

**Seeed XIAO nRF52840** is compile-only in CI until hardware is available.

## Verified (board1, CC310 backend) — v0.3.2

| Test | Result | Notes |
|------|--------|-------|
| `examples/CryptoSelfTest` | **13/13 PASS** | FQBN `bootloader=autonosd` (app @ `0x1000`) |
| `SdCryptoSmoke` | **PASS** | `layout: no SoftDevice (MBR-only / 0x1000)`, `RESULT: OK` |
| `CC310Smoke` (expanded shim) | **PASS** | incl. SHA-512 KAT; `RESULT: OK` |
| J-Link upload | **PASS** | hex linked @ `0x1000`; wrong `0x26000` layout kills USB serial |
| `backend: CC310` | **yes** | `hardware-accelerated: yes` on every run |
| UF2 flash + USB serial | **PASS** | 1200-bps touch → NICENANO drive → copy `.uf2` → COM10/COM11 enumerate |
| Full factory recovery | **PASS** | J-Link erase + `nice_nano_bootloader-0.6.0_s140_6.1.1.hex` when SoftDevice was missing |

Expected `CryptoSelfTest` tail:

```
summary: 13 passed, 0 failed, 0 skipped
RESULT: OK
```

## CC310 compatibility shim (board1)

`libraries/CC310/examples/CC310Smoke` forwards to NiusCrypto and checks TRNG,
SHA-256/512, HMAC-SHA-256 (RFC 4231 #2), AES-128-CTR (NIST F.5.1), ECDSA P-256
keygen/sign/verify, and ECDH shared-secret agreement. With binaries vendored it
should print `RESULT: OK`.

| Check | Expected |
|-------|----------|
| `begin` / `isAvailable` | OK / true |
| `randomBytes` | OK + hex sample |
| `sha256("abc")` | NIST match PASS |
| `sha512("abc")` | NIST match PASS |
| `hmacSha256` | RFC 4231 #2 PASS |
| `aes128Ctr` | NIST F.5.1 PASS |
| `ecdsaP256GenerateKey/Sign/Verify` | all OK |
| `ecdhP256ComputeShared` (A↔B) | shared secret match PASS |

## How to reproduce

### One-shot (board1, J-Link)

Scripts and J-Link helpers live in `vendor/hwverify/`:

| File | Purpose |
|------|---------|
| `verify_board1.ps1` | Compile + J-Link flash + serial capture (full regression) |
| `capture_serial.py` | J-Link reset + read until `RESULT: OK` |
| `capture_selftest.py` | Same, fixed for `CryptoSelfTest` only |
| `arduino-cli.yaml` | Local core path for bring-up |
| `justreset.jlink`, `flashbl.jlink`, … | J-Link commander snippets |

Build output goes to `vendor/hwverify/_verify_board1/` (git-ignored).

```powershell
powershell -File vendor\hwverify\verify_board1.ps1
```

Set `NIUS_BOARD1_COM` if the data port is not COM11 (e.g. `COM18` after re-enumeration).

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

If compile fails with **cannot find -lnrf_cc310** after a Library Manager install,
run `setup_vendored.py` or remove the `precompiled` / `ldflags` lines from
`library.properties` for OnChip-only builds.
