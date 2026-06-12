# SoftDevice coexistence with CC310

Every normal ArduinoNRF sketch on S140 boards **already runs with the
SoftDevice present**: the application links at `__nrf_app_start` (typically
`0x26000` for S140 v6 / nice!nano-class bootloaders), and Nordic's MBR +
SoftDevice occupy flash below that address.

NiusCrypto does **not** replace or disable the SoftDevice. It uses the Arm
CryptoCell 310 through Nordic's CRYS runtime (`libnrf_cc310.a`, **no-interrupts**
soft-float build).

## What we verified (board1)

board1 is an MBR-only clone (`__nrf_app_start == 0x1000`). CC310 CRYS calls
succeed with the same USB CDC stack active — no S140 SoftDevice on this board.

| Scenario | Result |
|----------|--------|
| `CryptoSelfTest` @ `0x1000` | **23/23 PASS**, `backend: CC310` |
| `CC310Smoke` (shim) | **RESULT: OK** |
| `SdCryptoSmoke` — crypto loop while USB CDC active | **RESULT: OK**, prints layout |

For S140 boards (`__nrf_app_start >= 0x26000`), the same sketches apply; pick
the matching **Bootloader / DFU** menu before compile/upload.

`examples/SdCryptoSmoke` prints `__nrf_app_start`, runs SHA-256 + HMAC in
`setup()`, then repeats hashing in `loop()` while the USB serial port stays up.
That demonstrates CC310 CRYS calls succeeding in the same runtime environment
the SoftDevice USB stack uses (shared NVIC, HFCLK, etc.).

## CRYS `no-interrupts` variant

The vendored archive is the **no-interrupts** CRYS build. It does not assume
Nordic's RTOS or SDH crypto glue. In practice:

- Call crypto from the main thread / `loop()` (same as other Arduino code).
- Avoid calling `Crypto` from a **higher-priority ISR** than the SoftDevice
  event handler unless you add your own locking (not provided by this library).
- BLE + crypto in one sketch is fine at the **application** level (e.g. hash
  in `loop()` while NimBLE events run on the main stack). See
  `examples/BleCryptoStress` for a CC310 + NimBLE advertising stress sketch on
  board1.

Threading and ISR guidance is also summarized in
[API_REFERENCE.md §5](API_REFERENCE.md#5-global-limitations).

## If the app HardFaults before USB enumerates

This is usually **missing or corrupt SoftDevice**, not a CC310 bug. Recovery:
full J-Link reflash of the factory combined bootloader + S140 image. See
[BOARD_BRINGUP.md](BOARD_BRINGUP.md#4-recover-a-non-enumerating-board-j-link).
