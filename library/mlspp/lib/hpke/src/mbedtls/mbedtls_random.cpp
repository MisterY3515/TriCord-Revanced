#include <hpke/random.h>
#include <namespace.h>

#include "mbedtls_common.h"

#include <mbedtls/ctr_drbg.h>

namespace MLS_NAMESPACE::hpke {

bytes
random_bytes(size_t size)
{
  auto out = bytes(size);
  if (size == 0) {
    return out;
  }

  if (mbedtls_ctr_drbg_random(&sharedDrbg(), out.data(), size) != 0) {
    throw std::runtime_error("mbedtls_ctr_drbg_random failed");
  }
  return out;
}

} // namespace MLS_NAMESPACE::hpke
