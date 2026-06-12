#ifndef NIUSCRYPTO_CRYPTOCAPABILITY_H
#define NIUSCRYPTO_CRYPTOCAPABILITY_H

#include <stdint.h>

namespace ncrypto {

/** Runtime capability tags for CryptoEngine::supports(). */
enum class CryptoCapability : uint8_t {
  Random = 0,
  Sha256,
  Sha384,
  Sha512,
  HmacSha256,
  HkdfSha256,
  AesCbcEncrypt,
  AesCbcDecrypt,
  AesCtr,
  AesGcm,
  ChaChaPoly,
  Ecdsa,
  Ecdh,
  X25519,
  Ed25519,
  RsaPkcs1,
  RsaPss,
  Sha256Stream,
  Sha384Stream,
  Sha512Stream,
  Count
};

inline const char* cryptoCapabilityName(CryptoCapability cap) {
  switch (cap) {
    case CryptoCapability::Random: return "Random";
    case CryptoCapability::Sha256: return "Sha256";
    case CryptoCapability::Sha384: return "Sha384";
    case CryptoCapability::Sha512: return "Sha512";
    case CryptoCapability::HmacSha256: return "HmacSha256";
    case CryptoCapability::HkdfSha256: return "HkdfSha256";
    case CryptoCapability::AesCbcEncrypt: return "AesCbcEncrypt";
    case CryptoCapability::AesCbcDecrypt: return "AesCbcDecrypt";
    case CryptoCapability::AesCtr: return "AesCtr";
    case CryptoCapability::AesGcm: return "AesGcm";
    case CryptoCapability::ChaChaPoly: return "ChaChaPoly";
    case CryptoCapability::Ecdsa: return "Ecdsa";
    case CryptoCapability::Ecdh: return "Ecdh";
    case CryptoCapability::X25519: return "X25519";
    case CryptoCapability::Ed25519: return "Ed25519";
    case CryptoCapability::RsaPkcs1: return "RsaPkcs1";
    case CryptoCapability::RsaPss: return "RsaPss";
    case CryptoCapability::Sha256Stream: return "Sha256Stream";
    case CryptoCapability::Sha384Stream: return "Sha384Stream";
    case CryptoCapability::Sha512Stream: return "Sha512Stream";
    default: return "(unknown)";
  }
}

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOCAPABILITY_H
