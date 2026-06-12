#!/usr/bin/env python3
"""Open COM, J-Link reset board1, capture CryptoSelfTest setup() output once."""
import glob
import os
import subprocess
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial required: conda install pyserial")

HERE = os.path.dirname(os.path.abspath(__file__))
JLINK_SCRIPT = os.path.join(HERE, "justreset.jlink")
PORT = os.environ.get("NIUS_BOARD1_COM", "COM11")
BAUD = 115200
TIMEOUT_S = 25.0


def find_jlink():
    for p in (
        os.environ.get("NIUS_JLINK_PATH"),
        r"C:\Program Files\SEGGER\JLink\JLink.exe",
    ):
        if p and os.path.isfile(p):
            return p
    hits = glob.glob(r"C:\Program Files*\SEGGER\*\JLink.exe")
    return sorted(hits)[-1] if hits else None


def main():
    jlink = find_jlink()
    if not jlink:
        sys.exit("JLink.exe not found")

    print(f"serial={PORT} jlink={jlink}", flush=True)

    proc = subprocess.run(
        [
            jlink,
            "-device",
            "nRF52840_xxAA",
            "-if",
            "SWD",
            "-speed",
            "4000",
            "-autoconnect",
            "1",
            "-CommanderScript",
            JLINK_SCRIPT,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)

    # Re-open after reset: keep this short so setup() output is not missed.
    lines = []
    deadline = time.monotonic() + TIMEOUT_S
    opened = False
    while time.monotonic() < deadline and not opened:
        try:
            ser = serial.Serial(PORT, BAUD, timeout=0.25)
        except serial.SerialException:
            time.sleep(0.15)
            continue
        opened = True
        with ser:
            ser.dtr = True
            ser.rts = True
            time.sleep(0.05)
            ser.reset_input_buffer()
            while time.monotonic() < deadline:
                raw = ser.readline()
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    print(line, flush=True)
                    lines.append(line)
                    if line.startswith("RESULT:"):
                        break

    if not any(l.startswith("RESULT:") for l in lines):
        sys.exit("timed out waiting for RESULT (no full self-test capture)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
