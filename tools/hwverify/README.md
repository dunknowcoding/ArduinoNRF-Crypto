# Hardware verify scripts (templates)

Copy these files into **`vendor/hwverify/`** on your machine (that folder is
git-ignored — see [docs/VALIDATION.md](../../docs/VALIDATION.md)).

| File | Purpose |
|------|---------|
| `capture_serial.py` | Read COM until `RESULT: OK` |
| `justreset.jlink` | J-Link commander snippet (create locally) |
| `verify_board1.ps1` | Full board1 regression (create locally) |

## capture_serial.py

After **arduino-cli upload** (which already soft-resets the board), prefer:

```powershell
python vendor\hwverify\capture_serial.py --port COM18 --no-jlink-reset
```

Use J-Link reset only when the board was not just flashed:

```powershell
python vendor\hwverify\capture_serial.py --port COM18 --post-reset-wait 3
```

OnChip self-test (`-DNIUS_FORCE_ONCHIP_SELFTEST`) is reliable with
`--no-jlink-reset` because a second J-Link reset can delay USB CDC
re-enumeration.
