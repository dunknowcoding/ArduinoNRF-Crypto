/*
  CryptoTypes.h - Shared types for the NiusCrypto library.

  One status enum and a few size constants are all the unified layer needs.
  Everything else (keys, IVs, buffers) is passed as plain pointers + lengths,
  matching the on-chip crypto peripherals and the Nordic nrf_cc310 API so no
  copying is forced on the caller.

  Note on naming: Arduino.h #define-s short ALL-CAPS macros (INPUT, OUTPUT,
  HIGH, DEFAULT, INTERNAL...). A bare enumerator with one of those names would
  be textually replaced by the preprocessor before the compiler sees it, so the
  enumerators here deliberately avoid every such word.
*/
#ifndef NIUSCRYPTO_CRYPTOTYPES_H
#define NIUSCRYPTO_CRYPTOTYPES_H

#include <stddef.h>
#include <stdint.h>

namespace ncrypto {

// Result of every operation. Scoped enum: refer to it as CryptoStatus::Ok.
enum class CryptoStatus : int8_t {
  Ok = 0,
  HardwareMissing = -1,  // no backend could be brought up at all
  NotStarted = -2,       // begin() not called / failed
  BadParam = -3,         // null pointer, wrong length, ...
  InternalError = -4,    // backend/hardware raised an error
  Unsupported = -5,      // this backend cannot do this operation
  AuthFailed = -6,       // AEAD tag / signature did not verify
};

// Fixed sizes used across the unified API (AES-128 + SHA-256 + NIST P-256).
static constexpr size_t kAes128KeyLen = 16;
static constexpr size_t kAesBlockLen = 16;
static constexpr size_t kGcmIvLen = 12;
static constexpr size_t kGcmTagLen = 16;
static constexpr size_t kSha256Len = 32;
static constexpr size_t kSha384Len = 48;
static constexpr size_t kSha512Len = 64;
static constexpr size_t kP256PrivLen = 32;  // scalar d
static constexpr size_t kP256PubLen = 64;   // X||Y uncompressed, no 0x04 prefix
static constexpr size_t kP256SigLen = 64;   // R||S
static constexpr size_t kP256SharedLen = 32;

// Human-readable name for a status, handy in sketches and tests.
inline const char* cryptoStatusName(CryptoStatus s) {
  switch (s) {
    case CryptoStatus::Ok:              return "Ok";
    case CryptoStatus::HardwareMissing: return "HardwareMissing";
    case CryptoStatus::NotStarted:      return "NotStarted";
    case CryptoStatus::BadParam:        return "BadParam";
    case CryptoStatus::InternalError:   return "InternalError";
    case CryptoStatus::Unsupported:     return "Unsupported";
    case CryptoStatus::AuthFailed:      return "AuthFailed";
    default:                            return "(unknown)";
  }
}

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOTYPES_H
