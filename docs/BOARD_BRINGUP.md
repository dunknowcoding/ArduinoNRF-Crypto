# Board bring-up: compile, flash, read the self-test, recover

How to build NiusCrypto, flash it onto a ProMicro nRF52840, read the
known-answer self-test over USB serial, and recover the board with a SEGGER
J-Link if it ever stops enumerating.

## Two common ProMicro layouts

Pick the **Bootloader / DFU** menu option that matches your board before
compile **and** upload (including J-Link `loadfile` — the hex address comes from
the link script, not from J-Link itself).

| Profile | App start | Typical board | Bootloader menu |
|---------|-----------|---------------|-----------------|
| **board1 (lab clone)** | `0x1000` | AliExpress ProMicro clone, MBR-only UF2/DFU | `autonosd` or `promicronosduf2` |
| **nice!nano / S140** | `0x26000` | nice!nano v2, many Adafruit-fork clones with SoftDevice | `auto` or `promicro` |

**board1** in this repo is the **0x1000** clone. Flashing a sketch linked at
`0x26000` onto it (J-Link or UF2) leaves the bootloader with no valid app at
`0x1000` and USB serial disappears — wiring is fine; the layout was wrong.

### Flash map — board1 clone (MBR-only, `0x1000`)

| Region | Address | Notes |
|--------|---------|-------|
| MBR | `0x00000` | Nordic master boot record |
| Application | `0x1000` | where NiusCrypto sketches link on board1 |
| UF2 bootloader | top of flash | vendor-specific; do not overwrite casually |

### Flash map — nice!nano / S140 (`0x26000`)

| Region | Address | Notes |
|--------|---------|-------|
| MBR | `0x00000` | Nordic master boot record |
| SoftDevice S140 | `0x01000` | BLE stack; **must be present** or the app HardFaults early |
| Application | `0x26000` | sketches with `bootloader=auto` / `promicro` |
| UF2 bootloader | `0xF4000` | Adafruit/nice!nano bootloader |
| DFU settings page | `0xFF000` | bootloader app-validity metadata |

> On S140 boards the app boots through the bootloader, which validates the app
> against the DFU settings page. On MBR-only clones the app at `0x1000` runs
> directly after reset through the MBR vector table.

## 1. Compile

**board1 (clone, app @ `0x1000`):**

```sh
arduino-cli compile \
  --fqbn arduinonrf:nrf52:promicro_nrf52840:bootloader=autonosd,usbcdc=enabled \
  --library /path/to/ArduinoNRF-Crypto \
  --build-path ./_build \
  /path/to/ArduinoNRF-Crypto/examples/CryptoSelfTest
```

**nice!nano / S140 (`0x26000`):** omit the bootloader option or use `bootloader=auto`.

All ten examples (`Aes`, `Backends`, `CryptoSelfTest`, `EcdhKeyExchange`,
`EcdsaSignVerify`, `HkdfSha256`, `HmacSha256`, `RandomBytes`, `SdCryptoSmoke`,
`Sha256`) build clean at ~13–15% flash on board1 (`bootloader=autonosd`).

## 2. Flash over UF2 (normal path, no J-Link)

This is the supported, lowest-risk path.

1. **Enter DFU.** Double-tap the reset button, **or** open the app's USB CDC
   port at **1200 baud** and close it. The board reboots into the bootloader and
   a `NICENANO` USB mass-storage drive appears.

   ```powershell
   # 1200-bps "touch" on the app port (Windows / PowerShell)
   $p = New-Object System.IO.Ports.SerialPort('COM10',1200); $p.Open(); Start-Sleep -m 200; $p.Close()
   ```

2. **Convert the hex to UF2** and copy it onto the drive:

   ```sh
   python <core>/tools/niusrobotlab/build_uf2.py \
     --input-hex ./_build/CryptoSelfTest.ino.hex \
     --output-uf2 ./CryptoSelfTest.uf2 \
     --family-id 0xADA52840
   # then copy CryptoSelfTest.uf2 onto the NICENANO drive
   ```

   The bootloader writes the app, updates the settings page, and reboots into it.
   `arduino-cli upload ... -p <port>` automates the whole 1200-touch + copy.

## 3. Read the self-test over USB serial

After boot the board enumerates two CDC ports (e.g. `COM10`/`COM11`). Open the
data port at **115200** baud. `examples/CryptoSelfTest` prints the result once;
the bring-up loop variant prints continuously, bracketed by
`--- HWVERIFY-END ---`.

Expected output on a board with the CC310 backend enabled:

```
=== NiusCrypto self-test ===
backend: CC310   hardware-accelerated: yes
  PASS  SHA-256("abc")
  PASS  HMAC-SHA-256 (RFC 4231 #2)
  PASS  AES-128-CBC encrypt (NIST F.2.1)
  PASS  AES-128-CBC decrypt
  PASS  AES-128-CTR (NIST F.5.1)
  PASS  ECDSA P-256 sign/verify
  PASS  ECDH P-256 shared-secret agreement
  PASS  random() returns entropy
        sample: 8917003F44410FE4338ECBB31F60B13F
  PASS  AES-128-GCM encrypt (McGrew #3)
  PASS  AES-128-GCM decrypt + auth
summary: 11 passed, 0 failed, 0 skipped
RESULT: OK
```

This is the verified bring-up state of this library on real hardware.

### One-shot board1 verify (J-Link + COM11)

When board1 has a SEGGER J-Link on SWD and the data port on `COM11`:

```powershell
cd F:\path\to\ArduinoNRF-Crypto
powershell -NoProfile -ExecutionPolicy Bypass -File vendor\hwverify\verify_board1.ps1
```

Default FQBN: `uploadmode=jlink,bootloader=autonosd` (app @ **0x1000**). This
compiles and flashes `CC310Smoke`, `SdCryptoSmoke`, and `CryptoSelfTest`, resets
via J-Link, and fails unless each sketch prints `RESULT: OK`. Override the port
with `$env:NIUS_BOARD1_COM='COM11'`.

If USB serial vanished after a J-Link session, you likely flashed a **0x26000**
hex onto a **0x1000** board — re-run this script (or recompile with
`bootloader=autonosd`) before blaming hardware.

## 4. Recover a non-enumerating board (J-Link)

If a bad flash leaves the board without USB (no `NICENANO` drive, no CDC ports),
restore the factory bootloader + SoftDevice with a J-Link. **This is the
catch-all fix** — it rewrites MBR + S140 + bootloader.

```sh
# full chip erase, then flash the factory combined image, then reset
JLink.exe -device nRF52840_xxAA -if SWD -speed 4000 -autoconnect 1 -CommanderScript flashbl.jlink
```

`flashbl.jlink`:

```
si SWD
speed 4000
connect
r
h
erase
loadfile nice_nano_bootloader-0.6.0_s140_6.1.1.hex
r
g
qc
```

To only force DFU mode (app present but settings page stale), erase the settings
page instead of a full reflash:

```
h
erase 0xFF000 0x100000
r
g
qc
```

Ready-made J-Link scripts live in `vendor/hwverify/` (`flashbl.jlink`,
`erasesettings.jlink`, `flash.jlink`, `read_results.jlink`). That folder and its
build artifacts are git-ignored.

## Gotcha seen during bring-up

A board left **without a valid SoftDevice** can launch the app into a corrupted
memory/boot state. In that state AES-GCM (the Oberon software path) HardFaulted
deep in the GHASH `gf32_mul` routine, even though the code is correct. A full
factory reflash (step 4) restored the SoftDevice and every primitive — including
AES-GCM — then passed. If you see early crashes or no USB, reflash the
bootloader image before debugging the sketch.
