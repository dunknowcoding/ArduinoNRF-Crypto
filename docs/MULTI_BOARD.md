# Multi-board compile matrix

NiusCrypto targets all `nrf52` boards in the ArduinoNRF package. CI compiles
every example against at least:

| FQBN | Role |
|------|------|
| `arduinonrf:nrf52:promicro_nrf52840:bootloader=autonosd` | **HW reference (board1)** — clone @ `0x1000`, J-Link + COM11 |
| `arduinonrf:nrf52:xiao_nrf52840` | Different UF2 layout (`0x27000` S140 v7); compile-only in CI |

## Local compile (any board)

```sh
arduino-cli compile \
  --fqbn arduinonrf:nrf52:xiao_nrf52840 \
  --library /path/to/ArduinoNRF-Crypto \
  examples/CryptoSelfTest
```

CC310 hardware tests require vendored blobs on the build machine (`setup_vendored.py`).

## Hardware validation status

| Board | CryptoSelfTest | CC310Smoke | Notes |
|-------|----------------|------------|-------|
| ProMicro nRF52840 (board1) | **13/13 PASS** | **OK** | MBR-only clone @ `0x1000` |
| Seeed XIAO nRF52840 | compile-only | compile-only | Awaiting HW in lab |

When a second board is available, run:

```powershell
powershell -File extras\hwverify\verify_board1.ps1 -Fqbn 'arduinonrf:nrf52:xiao_nrf52840:uploadmode=jlink'
```

(adjust `-ComPort` for that board's data CDC).
