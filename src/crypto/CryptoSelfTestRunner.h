#ifndef NIUSCRYPTO_CRYPTOSELFTESTRUNNER_H
#define NIUSCRYPTO_CRYPTOSELFTESTRUNNER_H

#include "CryptoTypes.h"

namespace ncrypto {

class CryptoEngine;

SelfTestReport runCryptoSelfTests(CryptoEngine& crypto);

}  // namespace ncrypto

#endif  // NIUSCRYPTO_CRYPTOSELFTESTRUNNER_H
