#!/usr/bin/env python3
"""Download Nordic's Oberon (and optionally CC310-platform) crypto binaries.

NiusCrypto's primary hardware backend links the classic CRYS runtime
`libnrf_cc310.a`, imported from a local nRF5 SDK by
`vendor/tools/import_cc310_sdk.py`. That runtime runs SHA-256, AES-CBC/CTR,
ECDSA/ECDH P-256 and the TRNG on the Arm CryptoCell 310 hardware, but it does
NOT expose AES-GCM. This script supplies the one missing piece:

  * nrf_oberon - Nordic's compact, self-contained crypto library, fetched from
        the public nrfconnect/sdk-nrfxlib repository (no login). NiusCrypto uses
        it for AES-128-GCM only.

Typical use (CRYS backend already imported):

    python vendor/tools/fetch_cc310.py --oberon-only

Legacy use (no local nRF5 SDK; build the platform+Oberon combination that runs
RNG + SHA-256 on CC310 and the rest in Oberon software): run with no flags. In
that mode it also fetches `nrf_cc310_platform` and patches `library.properties`
with the legacy `-lnrf_cc310_platform -loberon` ldflags.

  (The classic self-contained CRYS "nrf_cc310" library that does ECC/GCM on
   CC310 hardware ships ONLY inside the nRF5 SDK, so it is imported locally by
   import_cc310_sdk.py rather than downloaded here. See docs/VENDORING.md.)

IMPORTANT - float ABI:
  The ArduinoNRF core compiles with `-mcpu=cortex-m4 -mthumb` and no
  `-mfloat-abi=hard` / `-mfpu`, i.e. the SOFT-FLOAT ABI. We therefore take the
  `cortex-m4/soft-float` library variant of each. Linking a hard-float archive
  against this soft-float core would fail to link or fault at runtime.

What it does:
  1. Downloads the soft-float archives to
       src/cortex-m4/libnrf_cc310_platform.a
       src/cortex-m4/liboberon.a
  2. Downloads both include/ trees (flattened) to  src/cc310/
  3. Appends `precompiled=true` + `ldflags=...` to library.properties.
  4. Writes vendor/MANIFEST.txt.

Run from anywhere (paths resolve relative to this file). Standard library only.

    python vendor/tools/fetch_cc310.py
"""

import json
import os
import re
import sys
import urllib.request

REPO = "nrfconnect/sdk-nrfxlib"
REF = "main"
API = "https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"

# name -> (archive directory, include directory, output archive basename)
LIBS = {
    "nrf_cc310_platform": (
        "crypto/nrf_cc310_platform/lib/cortex-m4/soft-float/no-interrupts",
        "crypto/nrf_cc310_platform/include",
        "libnrf_cc310_platform.a",
    ),
    "oberon": (
        "crypto/nrf_oberon/lib/cortex-m4/soft-float",
        "crypto/nrf_oberon/include",
        "liboberon.a",
    ),
}

HERE = os.path.dirname(os.path.abspath(__file__))
LIB_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))  # ArduinoNRF-Crypto/
DST_LIB = os.path.join(LIB_ROOT, "src", "cortex-m4")
DST_INC = os.path.join(LIB_ROOT, "src", "cc310")
VENDOR = os.path.join(LIB_ROOT, "vendor")


def gh_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "niuscrypto-fetch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "token " + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def gh_list(path):
    return json.loads(gh_get(API.format(repo=REPO, path=path, ref=REF)).decode())


def download_to(url, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    data = gh_get(url)
    with open(dst, "wb") as f:
        f.write(data)
    return len(data)


def pick_archive(entries):
    cands = [e for e in entries if e["name"].endswith(".a")]
    if not cands:
        return None

    def ver_key(e):
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", e["name"])
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    return sorted(cands, key=ver_key)[-1]


def fetch_includes(path, manifest):
    count = 0
    for e in gh_list(path):
        if e["type"] == "dir":
            count += fetch_includes(e["path"], manifest)
        elif e["name"].endswith(".h"):
            dst = os.path.join(DST_INC, e["name"])
            n = download_to(e["download_url"], dst)
            manifest.append("  include/{}  ({} bytes)".format(e["name"], n))
            count += 1
    return count


def main():
    oberon_only = "--oberon-only" in sys.argv[1:]
    libs = {"oberon": LIBS["oberon"]} if oberon_only else LIBS
    mode = "Oberon only (GCM)" if oberon_only else "CC310 platform + Oberon"
    print("NiusCrypto :: fetching {} (soft-float)".format(mode))
    manifest = ["Vendored from {}@{}".format(REPO, REF), ""]

    for name, (lib_dir, _inc_dir, out_name) in libs.items():
        print("  listing", lib_dir)
        archive = pick_archive(gh_list(lib_dir))
        if not archive:
            print("    !! no .a found under", lib_dir)
            sys.exit(1)
        dst = os.path.join(DST_LIB, out_name)
        n = download_to(archive["download_url"], dst)
        print("    {} -> src/cortex-m4/{} ({} bytes)".format(
            archive["name"], out_name, n))
        manifest.append("{}  <-  {}  ({} bytes)".format(
            out_name, archive["name"], n))

    manifest.append("")
    print("  downloading headers ...")
    total = 0
    for name, (_lib_dir, inc_dir, _out) in libs.items():
        total += fetch_includes(inc_dir, manifest)
    print("    {} headers -> src/cc310/".format(total))

    try:
        for e in gh_list("crypto"):
            if e["name"].upper().startswith("LICENSE"):
                download_to(e["download_url"],
                            os.path.join(VENDOR, "LICENSE-Nordic.txt"))
                print("    license -> vendor/LICENSE-Nordic.txt")
                break
    except Exception as exc:  # noqa: BLE001
        print("    (license note skipped:", exc, ")")

    os.makedirs(VENDOR, exist_ok=True)
    with open(os.path.join(VENDOR, "MANIFEST.txt"), "w") as f:
        f.write("\n".join(manifest) + "\n")

    if oberon_only:
        print("  --oberon-only: leaving library.properties untouched "
              "(CRYS ldflags from import_cc310_sdk.py are kept)")
    else:
        patch_library_properties()
    print("done. Rebuild and the CC310 backend will activate automatically.")


def patch_library_properties():
    path = os.path.join(LIB_ROOT, "library.properties")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    ldflags = ("ldflags=-Wl,--start-group -lnrf_cc310_platform -loberon "
               "-Wl,--end-group")
    lines = text.splitlines()

    def has_key(key):
        # Match a real directive line (not a comment) starting with key.
        return any(ln.lstrip().startswith(key) and not ln.lstrip().startswith("#")
                   for ln in lines)

    changed = False
    if not has_key("precompiled="):
        text = text.rstrip("\n") + "\nprecompiled=true\n"
        changed = True
    if not has_key("ldflags="):
        text = text.rstrip("\n") + "\n" + ldflags + "\n"
        changed = True

    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print("  patched library.properties (precompiled + ldflags)")
    else:
        print("  library.properties already has precompiled/ldflags")


if __name__ == "__main__":
    main()
