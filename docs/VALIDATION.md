# Hardware validation — NiusCrypto

What has been verified on real hardware, and how to reproduce it. Reference
board: **AliExpress ProMicro nRF52840 clone** (app @ **`0x1000`**, MBR-only
UF2/DFU). board1 in the lab has a SEGGER J-Link on SWD for J-Link upload at
the correct link address.

**Seeed XIAO nRF52840** is compile-only locally until hardware is available.

## Verified (board1, CC310 backend)

### v0.7.1 (latest)

| Test | Result | Notes |
|------|--------|-------|
| `examples/CryptoSelfTest` | **23/23 PASS** | CC310 Auto; explicit `RsaKeyPair` RSA tests |
| OnChip (`NIUS_FORCE_ONCHIP_SELFTEST`) | **13/13 PASS, 10 SKIP** | GCM + ChaPoly software (OnChip AEAD) |
| `examples/BleCryptoStress` | **RESULT: OK** | NimBLE + 3000× SHA-256/HMAC |
| `SdCryptoSmoke` | **RESULT: OK** | MBR-only @ `0x1000` |

### v0.7.0

Same CC310 **23/23 PASS**; OnChip was **9/9 PASS, 14 SKIP** (no software GCM/ChaPoly yet).

Expected CC310 `CryptoSelfTest` tail:

```
summary: 23 passed, 0 failed, 0 skipped
RESULT: OK
```

### OnChip backend (board1, runtime `Prefer::OnChip`)

Forces the software / peripheral fallback while CC310 blobs remain linked
(same firmware as the CC310 run, different backend selection):

| Test | Result | Notes |
|------|--------|-------|
| `CryptoSelfTest` + `-DNIUS_FORCE_ONCHIP_SELFTEST` | **13/13 PASS, 10 SKIP** | SHA/HMAC/HKDF, AES-CBC/CTR/GCM, ChaPoly, RNG; ECC/RSA skipped |

Expected tail:

```
backend: OnChip   hardware-accelerated: no
summary: 13 passed, 0 failed, 10 skipped
RESULT: OK
```

Reproduce (J-Link upload, serial capture **without** a second J-Link reset — the
upload soft-reset is enough):

```powershell
$Repo = 'F:\path\to\ArduinoNRF-Crypto'
$Cli  = Join-Path $Repo 'vendor\hwverify\arduino-cli.yaml'
$Build = Join-Path $Repo 'vendor\hwverify\_verify_onchip'
$Fqbn = 'arduinonrf:nrf52:promicro_nrf52840:uploadmode=jlink,bootloader=autonosd,usbcdc=enabled'
arduino-cli --config-file $Cli compile --fqbn $Fqbn --library $Repo `
  --build-path $Build `
  --build-property compiler.cpp.extra_flags=-DNIUS_FORCE_ONCHIP_SELFTEST `
  (Join-Path $Repo 'examples\CryptoSelfTest')
arduino-cli --config-file $Cli upload --fqbn $Fqbn --input-dir $Build
# Open COM18 @ 115200 — expect RESULT: OK within ~15 s
```

**Note:** A second J-Link reset immediately after upload (default in older
`capture_serial.py`) can delay USB CDC re-enumeration. Prefer
`tools/hwverify/capture_serial.py --no-jlink-reset` after `arduino-cli upload`,
or copy the script from `tools/hwverify/` into your local `vendor/hwverify/`.

### Earlier releases

| Version | CryptoSelfTest | Notes |
|---------|----------------|-------|
| v0.7.1 | 23/23 PASS (CC310); 13/13 OnChip | OnChip software GCM + ChaPoly |
| v0.7.0 | 23/23 PASS (CC310); 9/9 OnChip | OnChip link fix, legacy RSA removal |
| v0.5.2 | 23/23 PASS | `EcdsaMessage` / `Ed25519Message`, `reset()` |
| v0.5.1 | 21/21 PASS | packet structs, `rsaRelease` |
| v0.4.0 | 20/20 PASS | Ed25519, RSA export/VerifyPub |

See [API_REFERENCE.md](API_REFERENCE.md) for the APIs exercised by each test.

## Local bring-up (`vendor/hwverify/` — not in git)

J-Link scripts, build output, and machine-specific `arduino-cli.yaml` live under
**`vendor/hwverify/`** on your machine. That entire folder is **git-ignored and
must not be pushed**.

Typical contents (create/maintain locally):

| File | Purpose |
|------|---------|
| `verify_board1.ps1` | Compile + J-Link flash + serial capture |
| `capture_serial.py` | J-Link reset + read until `RESULT: OK` |
| `arduino-cli.yaml` | Local core path (`directories.user` → ArduinoNRF) |
| `justreset.jlink`, `flashbl.jlink`, … | J-Link commander snippets |
| `_verify_board1/` | arduino-cli build output (disposable) |

Example one-shot (after vendoring CC310 blobs and creating the scripts locally):

```powershell
$env:NIUS_BOARD1_COM = 'COM18'   # your data CDC port
powershell -File vendor\hwverify\verify_board1.ps1
```

Default FQBN inside the script: `uploadmode=jlink,bootloader=autonosd` (app @ **0x1000**).

## How to reproduce (manual)

### 1. Vendor binaries (once per machine)

```sh
python vendor/tools/setup_vendored.py
```

### 2. Compile

```powershell
arduino-cli compile `
  --fqbn arduinonrf:nrf52:promicro_nrf52840:bootloader=autonosd,usbcdc=enabled `
  --library F:\path\to\ArduinoNRF-Crypto `
  --build-path F:\path\to\_build `
  F:\path\to\ArduinoNRF-Crypto\examples\CryptoSelfTest
```

### 3. Flash over UF2

See [BOARD_BRINGUP.md](BOARD_BRINGUP.md). Quick path: 1200-bps touch on the app
COM → copy `.uf2` to the bootloader drive → open data COM at 115200.

### 4. CC310 shim smoke

```powershell
arduino-cli compile `
  --fqbn arduinonrf:nrf52:promicro_nrf52840:bootloader=autonosd `
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

If USB serial vanished after a J-Link session, you likely flashed a **0x26000**
hex onto a **0x1000** board — recompile with `bootloader=autonosd` before blaming
hardware.
