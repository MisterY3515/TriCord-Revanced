#include "mbedtls_cryptor.h"

#include <bytes/bytes.h>
#include <dave/logger.h>

#include "common.h"

namespace discord {
namespace dave {

MbedTLSCryptor::MbedTLSCryptor(const EncryptionKey& encryptionKey)
{
    mbedtls_gcm_init(&gcmCtx_);

    auto rc = mbedtls_gcm_setkey(&gcmCtx_,
                                 MBEDTLS_CIPHER_ID_AES,
                                 encryptionKey.data(),
                                 static_cast<unsigned>(kAesGcm128KeyBytes * 8));
    if (rc != 0) {
        DISCORD_LOG(LS_ERROR) << "Failed to initialize AEAD context, mbedtls error: " << rc;
        return;
    }

    isValid_ = true;
}

MbedTLSCryptor::~MbedTLSCryptor()
{
    mbedtls_gcm_free(&gcmCtx_);
}

bool MbedTLSCryptor::Encrypt(ArrayView<uint8_t> ciphertextBufferOut,
                             ArrayView<const uint8_t> plaintextBuffer,
                             ArrayView<const uint8_t> nonceBuffer,
                             ArrayView<const uint8_t> additionalData,
                             ArrayView<uint8_t> tagBufferOut)
{
    if (!isValid_) {
        DISCORD_LOG(LS_ERROR) << "Encrypt: AEAD context is not initialized";
        return false;
    }

    auto rc = mbedtls_gcm_crypt_and_tag(&gcmCtx_,
                                        MBEDTLS_GCM_ENCRYPT,
                                        plaintextBuffer.size(),
                                        nonceBuffer.data(),
                                        nonceBuffer.size(),
                                        additionalData.data(),
                                        additionalData.size(),
                                        plaintextBuffer.data(),
                                        ciphertextBufferOut.data(),
                                        tagBufferOut.size(),
                                        tagBufferOut.data());
    if (rc != 0) {
        DISCORD_LOG(LS_ERROR) << "Failed to encrypt frame, mbedtls error: " << rc;
        return false;
    }

    return true;
}

bool MbedTLSCryptor::Decrypt(ArrayView<uint8_t> plaintextBufferOut,
                             ArrayView<const uint8_t> ciphertextBuffer,
                             ArrayView<const uint8_t> tagBuffer,
                             ArrayView<const uint8_t> nonceBuffer,
                             ArrayView<const uint8_t> additionalData)
{
    if (!isValid_) {
        DISCORD_LOG(LS_ERROR) << "Decrypt: AEAD context is not initialized";
        return false;
    }

    auto rc = mbedtls_gcm_auth_decrypt(&gcmCtx_,
                                       ciphertextBuffer.size(),
                                       nonceBuffer.data(),
                                       nonceBuffer.size(),
                                       additionalData.data(),
                                       additionalData.size(),
                                       tagBuffer.data(),
                                       tagBuffer.size(),
                                       ciphertextBuffer.data(),
                                       plaintextBufferOut.data());
    if (rc != 0) {
        DISCORD_LOG(LS_ERROR) << "Failed to decrypt frame, mbedtls error: " << rc;
        return false;
    }

    return true;
}

} // namespace dave
} // namespace discord
