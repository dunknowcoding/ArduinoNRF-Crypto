#ifndef NIUSCRYPTO_CRYPTOBACKENDERROR_H
#define NIUSCRYPTO_CRYPTOBACKENDERROR_H

#include <stdint.h>

namespace ncrypto {

/** Last backend-specific error (e.g. CRYS return code). Zero when none recorded. */
int32_t lastBackendError();

/** Clear the stored backend error. */
void clearBackendError();

namespace detail {
void setBackendError(int32_t code);
}

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOBACKENDERROR_H
