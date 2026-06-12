#include "SoftHkdf.h"

#include "SoftSha256.h"

namespace ncrypto {

namespace {

void hmacSha256Parts(const uint8_t key[kSha256Len], const uint8_t* a, size_t aLen,
                     const uint8_t* b, size_t bLen, uint8_t counter,
                     uint8_t out[kSha256Len]) {
  uint8_t k0[SoftSha256::kBlockLen] = {0};
  for (size_t i = 0; i < kSha256Len; ++i) k0[i] = key[i];
  uint8_t ipad[SoftSha256::kBlockLen], opad[SoftSha256::kBlockLen];
  for (size_t i = 0; i < SoftSha256::kBlockLen; ++i) {
    ipad[i] = uint8_t(k0[i] ^ 0x36);
    opad[i] = uint8_t(k0[i] ^ 0x5c);
  }
  SoftSha256 inner;
  inner.update(ipad, SoftSha256::kBlockLen);
  if (a != nullptr && aLen > 0) inner.update(a, aLen);
  if (b != nullptr && bLen > 0) inner.update(b, bLen);
  inner.update(&counter, 1);
  uint8_t innerDigest[kSha256Len];
  inner.finish(innerDigest);

  SoftSha256 outer;
  outer.update(opad, SoftSha256::kBlockLen);
  outer.update(innerDigest, kSha256Len);
  outer.finish(out);
}

}  // namespace

void SoftHkdf::hkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt,
                          size_t saltLen, const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen) {
  uint8_t prk[kSha256Len];
  if (saltLen == 0) {
    uint8_t zeroSalt[kSha256Len] = {0};
    SoftSha256::hmacSha256(zeroSalt, kSha256Len, ikm, ikmLen, prk);
  } else {
    SoftSha256::hmacSha256(salt, saltLen, ikm, ikmLen, prk);
  }

  uint8_t t[kSha256Len];
  size_t tLen = 0;
  size_t outOff = 0;
  uint8_t counter = 1;

  while (outOff < okmLen) {
    hmacSha256Parts(prk, tLen > 0 ? t : nullptr, tLen, info, infoLen, counter,
                    t);
    tLen = kSha256Len;

    size_t take = okmLen - outOff;
    if (take > kSha256Len) take = kSha256Len;
    for (size_t i = 0; i < take; ++i) okm[outOff + i] = t[i];
    outOff += take;
    ++counter;
  }
}

}  // namespace ncrypto
