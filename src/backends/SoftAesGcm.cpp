// AES-128-GCM (96-bit IV) for OnChip — uses SoftAes128 for block cipher.

#include "SoftAesGcm.h"

#include <string.h>

#include "SoftAes128.h"

namespace ncrypto {

namespace {

inline void xorBlock(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  for (size_t i = 0; i < kAesBlockLen; ++i) dst[i] = uint8_t(a[i] ^ b[i]);
}

void incCounter(uint8_t ctr[kAesBlockLen]) {
  for (int i = 15; i >= 12; --i) {
    if (++ctr[i] != 0) break;
  }
}

void gf128Mul(uint8_t out[16], const uint8_t x[16], const uint8_t h[16]) {
  uint8_t z[16] = {0};
  uint8_t v[16];
  memcpy(v, h, 16);
  for (int i = 0; i < 16; ++i) {
    for (int bit = 7; bit >= 0; --bit) {
      if (x[i] & (1 << bit)) {
        for (int j = 0; j < 16; ++j) z[j] ^= v[j];
      }
      const uint8_t carry = v[15] & 1;
      for (int j = 15; j > 0; --j) v[j] = uint8_t((v[j] >> 1) | (v[j - 1] << 7));
      v[0] >>= 1;
      if (carry) v[0] ^= 0xe1;
    }
  }
  memcpy(out, z, 16);
}

void ghashBlock(uint8_t y[16], const uint8_t h[16], const uint8_t block[16]) {
  xorBlock(y, y, block);
  uint8_t t[16];
  gf128Mul(t, y, h);
  memcpy(y, t, 16);
}

void ghashPadded(uint8_t y[16], const uint8_t h[16], const uint8_t* data,
                 size_t len) {
  uint8_t block[16];
  size_t off = 0;
  while (off < len) {
    memset(block, 0, 16);
    size_t n = len - off;
    if (n > 16) n = 16;
    memcpy(block, data + off, n);
    ghashBlock(y, h, block);
    off += n;
  }
}

void makeJ0(const uint8_t iv[kGcmIvLen], uint8_t j0[16]) {
  memcpy(j0, iv, kGcmIvLen);
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;
}

void gctr(const uint8_t key[kAes128KeyLen], uint8_t ctr[16],
          const uint8_t* in, uint8_t* out, size_t len) {
  uint8_t ks[16];
  size_t off = 0;
  while (off < len) {
    incCounter(ctr);
    SoftAes128::encryptBlock(key, ctr, ks);
    size_t n = len - off;
    if (n > 16) n = 16;
    for (size_t i = 0; i < n; ++i) out[off + i] = uint8_t(in[off + i] ^ ks[i]);
    off += n;
  }
}

void computeTag(const uint8_t key[kAes128KeyLen], const uint8_t iv[kGcmIvLen],
                const uint8_t* aad, size_t aadLen, const uint8_t* ct,
                size_t ctLen, uint8_t tag[kGcmTagLen]) {
  uint8_t h[16] = {0};
  SoftAes128::encryptBlock(key, h, h);

  uint8_t y[16] = {0};
  ghashPadded(y, h, aad, aadLen);
  ghashPadded(y, h, ct, ctLen);

  uint8_t lenBlock[16] = {0};
  uint64_t aadBits = uint64_t(aadLen) * 8;
  uint64_t ctBits = uint64_t(ctLen) * 8;
  for (int i = 0; i < 8; ++i) {
    lenBlock[7 - i] = uint8_t(aadBits >> (i * 8));
    lenBlock[15 - i] = uint8_t(ctBits >> (i * 8));
  }
  ghashBlock(y, h, lenBlock);

  uint8_t j0[16];
  makeJ0(iv, j0);
  uint8_t mask[16];
  SoftAes128::encryptBlock(key, j0, mask);
  xorBlock(tag, y, mask);
}

}  // namespace

bool SoftAesGcm::encrypt(const uint8_t key[kAes128KeyLen],
                         const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                         size_t aadLen, const uint8_t* in, uint8_t* out,
                         size_t len, uint8_t tag[kGcmTagLen]) {
  if (!key || !iv || !tag) return false;
  if (len != 0 && (!in || !out)) return false;

  uint8_t ctr[16];
  makeJ0(iv, ctr);
  if (len > 0) gctr(key, ctr, in, out, len);

  uint8_t ctBuf[1];
  const uint8_t* ct = out;
  if (len == 0) {
    ct = ctBuf;
    ctBuf[0] = 0;
  }
  computeTag(key, iv, aad, aadLen, ct, len, tag);
  return true;
}

bool SoftAesGcm::decrypt(const uint8_t key[kAes128KeyLen],
                         const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                         size_t aadLen, const uint8_t* in, uint8_t* out,
                         size_t len, const uint8_t tag[kGcmTagLen]) {
  if (!key || !iv || !tag) return false;
  if (len != 0 && (!in || !out)) return false;

  uint8_t expected[kGcmTagLen];
  computeTag(key, iv, aad, aadLen, in, len, expected);

  uint8_t diff = 0;
  for (size_t i = 0; i < kGcmTagLen; ++i) diff |= uint8_t(tag[i] ^ expected[i]);
  if (diff != 0) return false;

  uint8_t ctr[16];
  makeJ0(iv, ctr);
  if (len > 0) gctr(key, ctr, in, out, len);
  return true;
}

}  // namespace ncrypto
