#include "mbedtls_common.h"
#include <namespace.h>

#include <cstring>
#include <mutex>

#include <mbedtls/error.h>

namespace MLS_NAMESPACE::hpke {

std::runtime_error
mbedtls_error(int errnum)
{
  char buf[256];
  mbedtls_strerror(errnum, buf, sizeof(buf));
  return std::runtime_error(std::string("mbedTLS error: ") + buf);
}

mbedtls_ctr_drbg_context&
sharedDrbg()
{
  static mbedtls_entropy_context entropy;
  static mbedtls_ctr_drbg_context drbg;
  static std::once_flag initialized;

  std::call_once(initialized, [] {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    static const char personalization[] = "tricord-dave-hpke";
    if (mbedtls_ctr_drbg_seed(&drbg,
                              mbedtls_entropy_func,
                              &entropy,
                              reinterpret_cast<const unsigned char*>(personalization),
                              sizeof(personalization) - 1) != 0) {
      throw std::runtime_error("Failed to seed mbedTLS DRBG for HPKE backend");
    }
  });

  return drbg;
}

} // namespace MLS_NAMESPACE::hpke
