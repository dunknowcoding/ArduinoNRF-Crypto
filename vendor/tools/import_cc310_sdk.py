#!/usr/bin/env python3
"""Import the classic CRYS nrf_cc310 library from a local nRF5 SDK.

Unlike nrfxlib (which only ships nrf_cc310_platform + a PSA driver), the nRF5
SDK contains the self-contained CRYS library `libnrf_cc310` that runs the FULL
crypto suite - RNG, SHA, AES, ECDSA, ECDH - on the CryptoCell 310 hardware.
This binary is not downloadable (the SDK is login-gated), so this script copies
it from an already-installed SDK tree on this machine.

It vendors the soft-float / no-interrupts variant (matching the ArduinoNRF core
ABI; polling mode needs no CRYPTOCELL IRQ handler) plus all CRYS/SaSi headers.

    python vendor/tools/import_cc310_sdk.py [path-to-nRF5_SDK_root]

If no path is given it searches under vendor/nRF5SDK for an nRF5_SDK_* folder.
Oberon (used only for AES-GCM, which CRYS lacks) is fetched separately by
fetch_cc310.py.
"""

import glob
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))  # ArduinoNRF-Crypto/
DST_LIB = os.path.join(LIB_ROOT, "src", "cortex-m4")
DST_INC = os.path.join(LIB_ROOT, "src", "cc310")
VENDOR = os.path.join(LIB_ROOT, "vendor")

LIB_REL = os.path.join("external", "nrf_cc310", "lib", "cortex-m4",
                       "soft-float", "no-interrupts")
INC_REL = os.path.join("external", "nrf_cc310", "include")


def find_sdk():
    if len(sys.argv) > 1:
        return sys.argv[1]
    pat = os.path.join(VENDOR, "nRF5SDK", "nRF5_SDK_*")
    hits = [p for p in glob.glob(pat) if os.path.isdir(p)]
    if not hits:
        # maybe the given path already is the SDK root
        pat2 = os.path.join(VENDOR, "nRF5SDK", "**", "external", "nrf_cc310")
        for p in glob.glob(pat2, recursive=True):
            return os.path.dirname(os.path.dirname(p))  # .../<root>
    if not hits:
        sys.exit("nRF5 SDK not found under vendor/nRF5SDK; pass its path as arg")
    return sorted(hits)[-1]


def main():
    sdk = find_sdk()
    lib_dir = os.path.join(sdk, LIB_REL)
    inc_dir = os.path.join(sdk, INC_REL)
    if not os.path.isdir(lib_dir) or not os.path.isdir(inc_dir):
        sys.exit("CRYS lib/include not found in SDK: " + sdk)

    archives = [f for f in os.listdir(lib_dir) if f.endswith(".a")]
    if not archives:
        sys.exit("no .a archive under " + lib_dir)
    src_a = os.path.join(lib_dir, sorted(archives)[-1])

    os.makedirs(DST_LIB, exist_ok=True)
    os.makedirs(DST_INC, exist_ok=True)

    dst_a = os.path.join(DST_LIB, "libnrf_cc310.a")
    shutil.copyfile(src_a, dst_a)
    print("CRYS lib: {} -> src/cortex-m4/libnrf_cc310.a ({} bytes)".format(
        os.path.basename(src_a), os.path.getsize(dst_a)))

    n = 0
    manifest = ["CRYS nrf_cc310 imported from local nRF5 SDK:", sdk, "",
                "libnrf_cc310.a  <-  " + os.path.basename(src_a), "", "headers:"]
    for h in sorted(os.listdir(inc_dir)):
        if h.endswith(".h"):
            shutil.copyfile(os.path.join(inc_dir, h), os.path.join(DST_INC, h))
            manifest.append("  " + h)
            n += 1
    print("CRYS headers: {} -> src/cc310/".format(n))

    # Nordic SDK license note for the CC310 binary.
    lic = os.path.join(sdk, "external", "nrf_cc310", "license.txt")
    if os.path.isfile(lic):
        shutil.copyfile(lic, os.path.join(VENDOR, "LICENSE-Nordic-cc310.txt"))

    os.makedirs(VENDOR, exist_ok=True)
    with open(os.path.join(VENDOR, "MANIFEST-cc310.txt"), "w") as f:
        f.write("\n".join(manifest) + "\n")
    print("done. Rebuild to activate the CRYS CC310 backend.")


if __name__ == "__main__":
    main()
