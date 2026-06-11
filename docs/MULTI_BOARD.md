# Multi-board compile matrix

NiusCrypto targets all `nrf52` boards in the ArduinoNRF package. CI compiles
every example against at least:

| FQBN | Role |
|------|------|
| `arduinonrf:nrf52:promicro_nrf52840` | **HW reference (board1)** — J-Link + COM11 validation |
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
| ProMicro nRF52840 (board1) | **10/10 PASS** | **OK** | S140 v6 @ `0x26000` |
| Seeed XIAO nRF52840 | compile-only | compile-only | Awaiting HW in lab |

When a second board is available, run:

```powershell
powershell -File vendor\tools\verify_board1.ps1 -Fqbn 'arduinonrf:nrf52:xiao_nrf52840:uploadmode=jlink'
```

(adjust `-ComPort` for that board's data CDC).
