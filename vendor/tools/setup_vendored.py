#!/usr/bin/env python3
"""One-shot vendoring for NiusCrypto's CC310 backend.

Runs, in order:
  1. import_cc310_sdk.py  — CRYS runtime (libnrf_cc310.a + headers) from nRF5 SDK
  2. fetch_cc310.py       — Oberon (liboberon.a + GCM headers) from public nrfxlib

Usage (from anywhere):

    python vendor/tools/setup_vendored.py [path-to-nRF5_SDK_root]

If no SDK path is given, import_cc310_sdk.py searches vendor/nRF5SDK/.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, extra_args=None):
    cmd = [sys.executable, os.path.join(HERE, script)]
    if extra_args:
        cmd.extend(extra_args)
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    sdk_args = sys.argv[1:]
    print("NiusCrypto :: setup_vendored (CRYS + Oberon, soft-float)")
    if sdk_args:
        run("import_cc310_sdk.py", sdk_args)
    else:
        run("import_cc310_sdk.py")
    run("fetch_cc310.py")
    print("done. Rebuild; Crypto.begin() should report backend: CC310.")


if __name__ == "__main__":
    main()
