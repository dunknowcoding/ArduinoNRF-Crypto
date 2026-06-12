// ChaCha20-Poly1305 AEAD (RFC 8439) for OnChip.

#include "SoftChaChaPoly.h"

#include <string.h>

namespace ncrypto {

namespace {

inline uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

inline void quarterRound(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
  *a += *b;
  *d ^= *a;
  *d = rotl32(*d, 16);
  *c += *d;
  *b ^= *c;
  *b = rotl32(*b, 12);
  *a += *b;
  *d ^= *a;
  *d = rotl32(*d, 8);
  *c += *d;
  *b ^= *c;
  *b = rotl32(*b, 7);
}

void chachaBlock(const uint8_t key[kChaPolyKeyLen],
                 const uint8_t nonce[kChaPolyNonceLen], uint32_t counter,
                 uint8_t out[64]) {
  static const uint32_t kSigma[4] = {0x61707865, 0x3320646e, 0x79622d32,
                                     0x6b206574};
  uint32_t state[16];
  state[0] = kSigma[0];
  state[1] = kSigma[1];
  state[2] = kSigma[2];
  state[3] = kSigma[3];
  for (int i = 0; i < 8; ++i) {
    state[4 + i] = uint32_t(key[i * 4]) | (uint32_t(key[i * 4 + 1]) << 8) |
                   (uint32_t(key[i * 4 + 2]) << 16) |
                   (uint32_t(key[i * 4 + 3]) << 24);
  }
  state[12] = counter;
  for (int i = 0; i < 3; ++i) {
    state[13 + i] =
        uint32_t(nonce[i * 4]) | (uint32_t(nonce[i * 4 + 1]) << 8) |
        (uint32_t(nonce[i * 4 + 2]) << 16) | (uint32_t(nonce[i * 4 + 3]) << 24);
  }

  uint32_t working[16];
  memcpy(working, state, sizeof(working));
  for (int i = 0; i < 10; ++i) {
    quarterRound(&working[0], &working[4], &working[8], &working[12]);
    quarterRound(&working[1], &working[5], &working[9], &working[13]);
    quarterRound(&working[2], &working[6], &working[10], &working[14]);
    quarterRound(&working[3], &working[7], &working[11], &working[15]);
    quarterRound(&working[0], &working[5], &working[10], &working[15]);
    quarterRound(&working[1], &working[6], &working[11], &working[12]);
    quarterRound(&working[2], &working[7], &working[8], &working[13]);
    quarterRound(&working[3], &working[4], &working[9], &working[14]);
  }
  for (int i = 0; i < 16; ++i) {
    uint32_t w = working[i] + state[i];
    out[i * 4] = uint8_t(w);
    out[i * 4 + 1] = uint8_t(w >> 8);
    out[i * 4 + 2] = uint8_t(w >> 16);
    out[i * 4 + 3] = uint8_t(w >> 24);
  }
}

void chachaXor(const uint8_t key[kChaPolyKeyLen],
               const uint8_t nonce[kChaPolyNonceLen], uint32_t counter,
               const uint8_t* in, uint8_t* out, size_t len) {
  uint8_t block[64];
  size_t off = 0;
  while (off < len) {
    chachaBlock(key, nonce, counter++, block);
    size_t n = len - off;
    if (n > 64) n = 64;
    for (size_t i = 0; i < n; ++i) out[off + i] = uint8_t(in[off + i] ^ block[i]);
    off += n;
  }
}

void poly1305Init(uint32_t r[5], uint32_t h[5], const uint8_t key[32]) {
  r[0] = (uint32_t(key[0]) | (uint32_t(key[1]) << 8) |
          (uint32_t(key[2]) << 16) | (uint32_t(key[3]) << 24)) & 0x3ffffff;
  r[1] = (uint32_t(key[3]) >> 2 | (uint32_t(key[4]) << 6) |
          (uint32_t(key[5]) << 14) | (uint32_t(key[6]) << 22)) & 0x3ffff03;
  r[2] = (uint32_t(key[6]) >> 4 | (uint32_t(key[7]) << 4) |
          (uint32_t(key[8]) << 12) | (uint32_t(key[9]) << 20)) & 0x3ffc0ff;
  r[3] = (uint32_t(key[9]) >> 6 | (uint32_t(key[10]) << 2) |
          (uint32_t(key[11]) << 10) | (uint32_t(key[12]) << 18)) & 0x3f03fff;
  r[4] = (uint32_t(key[13]) | (uint32_t(key[14]) << 8) |
          (uint32_t(key[15]) << 16) | (uint32_t(key[16]) << 24)) & 0x00fffff;
  for (int i = 0; i < 5; ++i) h[i] = 0;
}

void poly1305Blocks(uint32_t h[5], const uint32_t r[5], const uint8_t* data,
                    size_t len, bool padBit) {
  const uint32_t s1 = r[1] * 5;
  const uint32_t s2 = r[2] * 5;
  const uint32_t s3 = r[3] * 5;
  const uint32_t s4 = r[4] * 5;

  while (len >= 16) {
    uint32_t t0 = uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
                  (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
    uint32_t t1 = uint32_t(data[4]) | (uint32_t(data[5]) << 8) |
                  (uint32_t(data[6]) << 16) | (uint32_t(data[7]) << 24);
    uint32_t t2 = uint32_t(data[8]) | (uint32_t(data[9]) << 8) |
                  (uint32_t(data[10]) << 16) | (uint32_t(data[11]) << 24);
    uint32_t t3 = uint32_t(data[12]) | (uint32_t(data[13]) << 8) |
                  (uint32_t(data[14]) << 16) | (uint32_t(data[15]) << 24);

    h[0] += t0 & 0x3ffffff;
    h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    h[4] += (t3 >> 8) | (padBit ? (1U << 24) : 0);

    uint64_t d0 = uint64_t(h[0]) * r[0] + uint64_t(h[1]) * s4 +
                  uint64_t(h[2]) * s3 + uint64_t(h[3]) * s2 +
                  uint64_t(h[4]) * s1;
    uint64_t d1 = uint64_t(h[0]) * r[1] + uint64_t(h[1]) * r[0] +
                  uint64_t(h[2]) * s4 + uint64_t(h[3]) * s3 +
                  uint64_t(h[4]) * s2;
    uint64_t d2 = uint64_t(h[0]) * r[2] + uint64_t(h[1]) * r[1] +
                  uint64_t(h[2]) * r[0] + uint64_t(h[3]) * s4 +
                  uint64_t(h[4]) * s3;
    uint64_t d3 = uint64_t(h[0]) * r[3] + uint64_t(h[1]) * r[2] +
                  uint64_t(h[2]) * r[1] + uint64_t(h[3]) * r[0] +
                  uint64_t(h[4]) * s4;
    uint64_t d4 = uint64_t(h[0]) * r[4] + uint64_t(h[1]) * r[3] +
                  uint64_t(h[2]) * r[2] + uint64_t(h[3]) * r[1] +
                  uint64_t(h[4]) * r[0];

    uint32_t c = uint32_t(d0 >> 26);
    h[0] = uint32_t(d0) & 0x3ffffff;
    d1 += c;
    c = uint32_t(d1 >> 26);
    h[1] = uint32_t(d1) & 0x3ffffff;
    d2 += c;
    c = uint32_t(d2 >> 26);
    h[2] = uint32_t(d2) & 0x3ffffff;
    d3 += c;
    c = uint32_t(d3 >> 26);
    h[3] = uint32_t(d3) & 0x3ffffff;
    d4 += c;
    c = uint32_t(d4 >> 26);
    h[4] = uint32_t(d4) & 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    data += 16;
    len -= 16;
  }
}

void poly1305Finish(uint8_t mac[16], uint32_t h[5], const uint32_t r[5],
                    const uint8_t key[32]) {
  (void)r;

  uint32_t c = h[1] >> 26;
  h[1] &= 0x3ffffff;
  h[2] += c;
  c = h[2] >> 26;
  h[2] &= 0x3ffffff;
  h[3] += c;
  c = h[3] >> 26;
  h[3] &= 0x3ffffff;
  h[4] += c;
  c = h[4] >> 26;
  h[4] &= 0x3ffffff;
  h[0] += c * 5;
  c = h[0] >> 26;
  h[0] &= 0x3ffffff;
  h[1] += c;

  uint32_t g0 = h[0] + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  uint32_t g1 = h[1] + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;
  uint32_t g2 = h[2] + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;
  uint32_t g3 = h[3] + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  uint32_t g4 = h[4] + c - (1U << 26);

  uint32_t mask = (g4 >> 31) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h[0] = (h[0] & mask) | g0;
  h[1] = (h[1] & mask) | g1;
  h[2] = (h[2] & mask) | g2;
  h[3] = (h[3] & mask) | g3;
  h[4] = (h[4] & mask) | g4;

  uint32_t t0 = h[0] | (h[1] << 26);
  uint32_t t1 = (h[1] >> 6) | (h[2] << 20);
  uint32_t t2 = (h[2] >> 12) | (h[3] << 14);
  uint32_t t3 = (h[3] >> 18) | (h[4] << 8);

  uint32_t n0 = uint32_t(key[16]) | (uint32_t(key[17]) << 8) |
                (uint32_t(key[18]) << 16) | (uint32_t(key[19]) << 24);
  uint32_t n1 = uint32_t(key[20]) | (uint32_t(key[21]) << 8) |
                (uint32_t(key[22]) << 16) | (uint32_t(key[23]) << 24);
  uint32_t n2 = uint32_t(key[24]) | (uint32_t(key[25]) << 8) |
                (uint32_t(key[26]) << 16) | (uint32_t(key[27]) << 24);
  uint32_t n3 = uint32_t(key[28]) | (uint32_t(key[29]) << 8) |
                (uint32_t(key[30]) << 16) | (uint32_t(key[31]) << 24);

  uint64_t f = uint64_t(t0) + n0;
  t0 = uint32_t(f);
  f = uint64_t(t1) + n1 + (f >> 32);
  t1 = uint32_t(f);
  f = uint64_t(t2) + n2 + (f >> 32);
  t2 = uint32_t(f);
  f = uint64_t(t3) + n3 + (f >> 32);
  t3 = uint32_t(f);

  mac[0] = uint8_t(t0);
  mac[1] = uint8_t(t0 >> 8);
  mac[2] = uint8_t(t0 >> 16);
  mac[3] = uint8_t(t0 >> 24);
  mac[4] = uint8_t(t1);
  mac[5] = uint8_t(t1 >> 8);
  mac[6] = uint8_t(t1 >> 16);
  mac[7] = uint8_t(t1 >> 24);
  mac[8] = uint8_t(t2);
  mac[9] = uint8_t(t2 >> 8);
  mac[10] = uint8_t(t2 >> 16);
  mac[11] = uint8_t(t2 >> 24);
  mac[12] = uint8_t(t3);
  mac[13] = uint8_t(t3 >> 8);
  mac[14] = uint8_t(t3 >> 16);
  mac[15] = uint8_t(t3 >> 24);
}

void poly1305Auth(uint8_t mac[16], const uint8_t* msg, size_t msgLen,
                  const uint8_t key[32]) {
  uint32_t r[5], h[5];
  poly1305Init(r, h, key);
  size_t full = msgLen - (msgLen % 16);
  if (full > 0) poly1305Blocks(h, r, msg, full, true);
  if (msgLen % 16 != 0) {
    uint8_t tmp[16] = {0};
    size_t rem = msgLen % 16;
    memcpy(tmp, msg + full, rem);
    tmp[rem] = 1;
    poly1305Blocks(h, r, tmp, 16, false);
  }
  poly1305Finish(mac, h, r, key);
}

void aeadPoly1305(uint8_t tag[kChaPolyTagLen],
                  const uint8_t key[kChaPolyKeyLen],
                  const uint8_t nonce[kChaPolyNonceLen], const uint8_t* aad,
                  size_t aadLen, const uint8_t* ct, size_t ctLen) {
  uint8_t block0[64];
  chachaBlock(key, nonce, 0, block0);
  uint8_t polyKey[32];
  memcpy(polyKey, block0, 32);

  uint8_t pad[16];
  size_t aadPad = (16 - (aadLen % 16)) % 16;
  size_t ctPad = (16 - (ctLen % 16)) % 16;
  size_t bufLen = aadLen + aadPad + ctLen + ctPad + 16;
  uint8_t stackBuf[512];
  uint8_t* buf = stackBuf;
  if (bufLen > sizeof(stackBuf)) return;

  size_t off = 0;
  if (aadLen > 0) {
    memcpy(buf + off, aad, aadLen);
    off += aadLen;
  }
  if (aadPad > 0) {
    memset(buf + off, 0, aadPad);
    off += aadPad;
  }
  if (ctLen > 0) {
    memcpy(buf + off, ct, ctLen);
    off += ctLen;
  }
  if (ctPad > 0) {
    memset(buf + off, 0, ctPad);
    off += ctPad;
  }
  uint64_t al = aadLen;
  uint64_t cl = ctLen;
  for (int i = 0; i < 8; ++i) {
    buf[off + i] = uint8_t(al);
    buf[off + 8 + i] = uint8_t(cl);
    al >>= 8;
    cl >>= 8;
  }
  off += 16;

  poly1305Auth(tag, buf, off, polyKey);
}

bool tagsEqual(const uint8_t a[kChaPolyTagLen],
               const uint8_t b[kChaPolyTagLen]) {
  uint8_t diff = 0;
  for (size_t i = 0; i < kChaPolyTagLen; ++i) diff |= uint8_t(a[i] ^ b[i]);
  return diff == 0;
}

}  // namespace

bool SoftChaChaPoly::encrypt(const uint8_t key[kChaPolyKeyLen],
                             const uint8_t nonce[kChaPolyNonceLen],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, uint8_t* out, size_t len,
                             uint8_t tag[kChaPolyTagLen]) {
  if (!key || !nonce || !tag) return false;
  if (len != 0 && (!in || !out)) return false;

  if (len > 0) chachaXor(key, nonce, 1, in, out, len);
  aeadPoly1305(tag, key, nonce, aad, aadLen, out, len);
  return true;
}

bool SoftChaChaPoly::decrypt(const uint8_t key[kChaPolyKeyLen],
                             const uint8_t nonce[kChaPolyNonceLen],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, uint8_t* out, size_t len,
                             const uint8_t tag[kChaPolyTagLen]) {
  if (!key || !nonce || !tag) return false;
  if (len != 0 && (!in || !out)) return false;

  uint8_t expected[kChaPolyTagLen];
  aeadPoly1305(expected, key, nonce, aad, aadLen, in, len);
  if (!tagsEqual(tag, expected)) return false;

  if (len > 0) chachaXor(key, nonce, 1, in, out, len);
  return true;
}

}  // namespace ncrypto
