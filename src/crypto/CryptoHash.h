/*
  CryptoHash.h - incremental SHA-256 / SHA-384 / SHA-512 contexts.

  Streaming uses the portable software implementations (SoftSha256 / SoftSha512)
  so behaviour is identical on every backend. One-shot sha256() / sha384() /
  sha512() still route through the active backend when hardware is available.
*/
#ifndef NIUSCRYPTO_CRYPTOHASH_H
#define NIUSCRYPTO_CRYPTOHASH_H

#include "../backends/SoftSha256.h"
#include "../backends/SoftSha512.h"

namespace ncrypto {

struct Sha256Context {
  SoftSha256 hasher;
  bool active = false;
  void reset() {
    hasher.reset();
    active = false;
  }
};

struct Sha384Context {
  SoftSha512 hasher;
  bool active = false;
  void reset() {
    hasher.reset384();
    active = false;
  }
};

struct Sha512Context {
  SoftSha512 hasher;
  bool active = false;
  void reset() {
    hasher.reset();
    active = false;
  }
};

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOHASH_H
