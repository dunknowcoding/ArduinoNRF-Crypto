#include "CryptoUtil.h"

namespace ncrypto {

bool secureEqual(const uint8_t* a, const uint8_t* b, size_t len) {
  if (a == nullptr || b == nullptr) return len == 0;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= uint8_t(a[i] ^ b[i]);
  return diff == 0;
}

void wipe(volatile uint8_t* buf, size_t len) {
  if (buf == nullptr) return;
  while (len-- > 0) buf[len] = 0;
}

size_t pkcs7Pad(const uint8_t* plain, size_t plainLen, uint8_t* out,
                size_t outCap, size_t blockSize) {
  if (blockSize == 0 || blockSize > 255) return 0;
  if (plain == nullptr && plainLen != 0) return 0;
  if (out == nullptr) return 0;
  size_t padLen = blockSize - (plainLen % blockSize);
  if (padLen == 0) padLen = blockSize;
  size_t total = plainLen + padLen;
  if (total > outCap) return 0;
  for (size_t i = 0; i < plainLen; ++i) out[i] = plain[i];
  for (size_t i = 0; i < padLen; ++i) out[plainLen + i] = uint8_t(padLen);
  return total;
}

size_t pkcs7Unpad(uint8_t* buf, size_t len, size_t blockSize) {
  if (len == 0 || len % blockSize != 0 || buf == nullptr) return 0;
  uint8_t padLen = buf[len - 1];
  if (padLen == 0 || padLen > blockSize || padLen > len) return 0;
  for (size_t i = 0; i < padLen; ++i) {
    if (buf[len - 1 - i] != padLen) return 0;
  }
  return len - padLen;
}

}  // namespace ncrypto
