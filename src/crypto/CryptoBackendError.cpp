#include "CryptoBackendError.h"

namespace ncrypto {

namespace {
int32_t g_lastBackendError = 0;
}

int32_t lastBackendError() { return g_lastBackendError; }

void clearBackendError() { g_lastBackendError = 0; }

namespace detail {
void setBackendError(int32_t code) { g_lastBackendError = code; }
}  // namespace detail

}  // namespace ncrypto
