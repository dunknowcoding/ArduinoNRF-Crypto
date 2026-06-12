# Arduino Library Manager

NiusCrypto is indexed in the [Arduino Library Registry](https://github.com/arduino/library-registry)
(PR [#8517](https://github.com/arduino/library-registry/pull/8517)).

## How releases appear

1. Bump `version` in `library.properties` (and `library.properties.onchip`).
2. Commit, push, and tag (e.g. `v0.7.0`).
3. The registry bot picks up the new tag within ~24 h (no manual PR per release).

Users install via **Sketch → Include Library → Manage Libraries…** or:

```sh
arduino-cli lib install NiusCrypto
```

## What Library Manager ships

- **Source only** — no Nordic `libnrf_cc310.a` / `liboberon.a` (license).
- Default `library.properties` lists `precompiled=true`; if linking fails with
  *cannot find -lnrf_cc310*, use [ONCHIP_BUILD.md](ONCHIP_BUILD.md) (copy
  `library.properties.onchip` or run `setup_vendored.py` locally).

## CC310 acceleration after install

```sh
python vendor/tools/setup_vendored.py
```

Restore the default `library.properties` from git (with `precompiled` lines),
rebuild — `Crypto.backendName()` should report `CC310`.

See [VENDORING.md](VENDORING.md) for Nordic SDK requirements.
