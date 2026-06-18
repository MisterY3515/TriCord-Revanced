#pragma once

#include <mbedtls/gcm.h>

#include "cryptor.h"

// TriCord-authored replacement for upstream's openssl_cryptor.h/boringssl_cryptor.h:
// implements ICryptor (the per-generation SFrame AES-128-GCM cryptor) using
// mbedTLS instead of OpenSSL/BoringSSL, the same reason and pattern as
// library/mlspp/lib/hpke/src/mbedtls/mbedtls_aead_cipher.cpp. DAVE only ever
// uses an 8-byte truncated tag (kAesGcm128TruncatedTagBytes); mbedTLS's GCM API
// takes the tag length as an explicit parameter, so no manual truncation is
// needed (unlike OpenSSL, which always produces a full 16-byte tag via
// EVP_CTRL_GCM_GET_TAG/SET_TAG with an explicit length).

namespace discord {
namespace dave {

class MbedTLSCryptor : public ICryptor {
public:
    explicit MbedTLSCryptor(const EncryptionKey& encryptionKey);
    ~MbedTLSCryptor() override;

    bool IsValid() const { return isValid_; }

    bool Encrypt(ArrayView<uint8_t> ciphertextBufferOut,
                 ArrayView<const uint8_t> plaintextBuffer,
                 ArrayView<const uint8_t> nonceBuffer,
                 ArrayView<const uint8_t> additionalData,
                 ArrayView<uint8_t> tagBufferOut) override;
    bool Decrypt(ArrayView<uint8_t> plaintextBufferOut,
                 ArrayView<const uint8_t> ciphertextBuffer,
                 ArrayView<const uint8_t> tagBuffer,
                 ArrayView<const uint8_t> nonceBuffer,
                 ArrayView<const uint8_t> additionalData) override;

private:
    MbedTLSCryptor(const MbedTLSCryptor&) = delete;
    MbedTLSCryptor& operator=(const MbedTLSCryptor&) = delete;

    mbedtls_gcm_context gcmCtx_;
    bool isValid_{false};
};

} // namespace dave
} // namespace discord
