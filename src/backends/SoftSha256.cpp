// SoftSha256.cpp - standard FIPS 180-4 SHA-256. Public-domain construction.

#include "SoftSha256.h"

namespace ncrypto {

namespace {

inline uint32_t ror(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace

void SoftSha256::reset() {
  state_[0] = 0x6a09e667;
  state_[1] = 0xbb67ae85;
  state_[2] = 0x3c6ef372;
  state_[3] = 0xa54ff53a;
  state_[4] = 0x510e527f;
  state_[5] = 0x9b05688c;
  state_[6] = 0x1f83d9ab;
  state_[7] = 0x5be0cd19;
  bitLen_ = 0;
  bufferLen_ = 0;
}

void SoftSha256::processBlock(const uint8_t* p) {
  uint32_t w[64];
  for (uint32_t i = 0; i < 16; ++i) {
    w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
           (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
  }
  for (uint32_t i = 16; i < 64; ++i) {
    uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
  uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

  for (uint32_t i = 0; i < 64; ++i) {
    uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + K[i] + w[i];
    uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
  state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void SoftSha256::update(const uint8_t* data, size_t len) {
  if (data == nullptr) return;
  bitLen_ += uint64_t(len) * 8U;
  while (len > 0) {
    size_t take = kBlockLen - bufferLen_;
    if (take > len) take = len;
    for (size_t i = 0; i < take; ++i) buffer_[bufferLen_ + i] = data[i];
    bufferLen_ += take;
    data += take;
    len -= take;
    if (bufferLen_ == kBlockLen) {
      processBlock(buffer_);
      bufferLen_ = 0;
    }
  }
}

void SoftSha256::finish(uint8_t out[kDigestLen]) {
  // Append 0x80, pad with zeros, then the 64-bit big-endian bit length.
  uint8_t pad = 0x80;
  uint64_t lenBits = bitLen_;
  update(&pad, 1);
  uint8_t zero = 0x00;
  while (bufferLen_ != 56) update(&zero, 1);

  uint8_t lenBytes[8];
  for (int i = 7; i >= 0; --i) {
    lenBytes[i] = uint8_t(lenBits & 0xFFU);
    lenBits >>= 8;
  }
  // update() would re-add to bitLen_; write the length block directly instead.
  for (size_t i = 0; i < 8; ++i) buffer_[bufferLen_ + i] = lenBytes[i];
  processBlock(buffer_);

  for (uint32_t i = 0; i < 8; ++i) {
    out[i * 4] = uint8_t(state_[i] >> 24);
    out[i * 4 + 1] = uint8_t(state_[i] >> 16);
    out[i * 4 + 2] = uint8_t(state_[i] >> 8);
    out[i * 4 + 3] = uint8_t(state_[i]);
  }
  reset();
}

void SoftSha256::hash(const uint8_t* in, size_t len, uint8_t out[kDigestLen]) {
  SoftSha256 h;
  h.update(in, len);
  h.finish(out);
}

void SoftSha256::hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg,
                              size_t msgLen, uint8_t out[kDigestLen]) {
  uint8_t k0[kBlockLen] = {0};
  if (keyLen > kBlockLen) {
    hash(key, keyLen, k0);
  } else {
    for (size_t i = 0; i < keyLen; ++i) k0[i] = key[i];
  }

  uint8_t ipad[kBlockLen], opad[kBlockLen];
  for (size_t i = 0; i < kBlockLen; ++i) {
    ipad[i] = uint8_t(k0[i] ^ 0x36);
    opad[i] = uint8_t(k0[i] ^ 0x5C);
  }

  uint8_t inner[kDigestLen];
  SoftSha256 h;
  h.update(ipad, kBlockLen);
  h.update(msg, msgLen);
  h.finish(inner);

  h.update(opad, kBlockLen);
  h.update(inner, kDigestLen);
  h.finish(out);
}

}  // namespace ncrypto
