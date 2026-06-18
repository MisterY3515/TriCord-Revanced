#include "cryptor.h"

// Replaces upstream's WITH_BORINGSSL/openssl_cryptor.h dispatch with TriCord's
// mbedTLS-backed implementation (same reason as the mlspp HPKE backend: OpenSSL/
// BoringSSL aren't practical to port to devkitARM, mbedTLS already is linked).
#include "mbedtls/mbedtls_cryptor.h"

namespace discord {
namespace dave {

std::unique_ptr<ICryptor> CreateCryptor(const EncryptionKey& encryptionKey)
{
    auto cryptor = std::make_unique<MbedTLSCryptor>(encryptionKey);
    return cryptor->IsValid() ? std::move(cryptor) : nullptr;
}

} // namespace dave
} // namespace discord
