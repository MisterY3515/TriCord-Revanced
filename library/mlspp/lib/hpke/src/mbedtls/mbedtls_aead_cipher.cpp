#include "aead_cipher.h"
#include "mbedtls_common.h"

#include <namespace.h>

#include <mbedtls/gcm.h>

// Only AES-128-GCM is implemented: DAVE ciphersuite 2 is the only one TriCord's
// VoiceClient negotiates. AEADCipher::get<AES_256_GCM/CHACHA20_POLY1305>() are
// intentionally left undefined so an unsupported ciphersuite fails to link.

namespace MLS_NAMESPACE::hpke {

///
/// ExportOnlyCipher
///
bytes
ExportOnlyCipher::seal(const bytes& /* key */,
                       const bytes& /* nonce */,
                       const bytes& /* aad */,
                       const bytes& /* pt */) const
{
  throw std::runtime_error("seal() on export-only context");
}

std::optional<bytes>
ExportOnlyCipher::open(const bytes& /* key */,
                       const bytes& /* nonce */,
                       const bytes& /* aad */,
                       const bytes& /* ct */) const
{
  throw std::runtime_error("open() on export-only context");
}

ExportOnlyCipher::ExportOnlyCipher()
  : AEAD(AEAD::ID::export_only, 0, 0)
{
}

///
/// AEADCipher (AES-128-GCM only)
///
namespace {
AEADCipher
makeAead(AEAD::ID cipher_in)
{
  return { cipher_in };
}

size_t
cipherKeySize(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
      return 16;
    default:
      throw std::runtime_error("Unsupported AEAD algorithm in mbedTLS backend");
  }
}

size_t
cipherNonceSize(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
      return 12;
    default:
      throw std::runtime_error("Unsupported AEAD algorithm in mbedTLS backend");
  }
}

constexpr size_t kTagSize = 16;
} // namespace

template<>
const AEADCipher&
AEADCipher::get<AEAD::ID::AES_128_GCM>()
{
  static const auto instance = makeAead(AEAD::ID::AES_128_GCM);
  return instance;
}

AEADCipher::AEADCipher(AEAD::ID id_in)
  : AEAD(id_in, cipherKeySize(id_in), cipherNonceSize(id_in))
  , tag_size(kTagSize)
{
}

bytes
AEADCipher::seal(const bytes& key, const bytes& nonce, const bytes& aad, const bytes& pt) const
{
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  auto cleanup = [&] { mbedtls_gcm_free(&gcm); };

  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
    cleanup();
    throw std::runtime_error("mbedtls_gcm_setkey failed");
  }

  auto ct = bytes(pt.size());
  auto tag = bytes(tag_size);
  const int rc = mbedtls_gcm_crypt_and_tag(&gcm,
                                           MBEDTLS_GCM_ENCRYPT,
                                           pt.size(),
                                           nonce.data(),
                                           nonce.size(),
                                           aad.data(),
                                           aad.size(),
                                           pt.data(),
                                           ct.data(),
                                           tag.size(),
                                           tag.data());
  cleanup();
  if (rc != 0) {
    throw mbedtls_error(rc);
  }

  return ct + tag;
}

std::optional<bytes>
AEADCipher::open(const bytes& key, const bytes& nonce, const bytes& aad, const bytes& ct) const
{
  if (ct.size() < tag_size) {
    throw std::runtime_error("AEAD ciphertext smaller than tag size");
  }

  const auto innerCtSize = ct.size() - tag_size;
  const auto tag = ct.slice(innerCtSize, ct.size());
  const auto innerCt = ct.slice(0, innerCtSize);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  auto cleanup = [&] { mbedtls_gcm_free(&gcm); };

  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
    cleanup();
    throw std::runtime_error("mbedtls_gcm_setkey failed");
  }

  auto pt = bytes(innerCtSize);
  const int rc = mbedtls_gcm_auth_decrypt(&gcm,
                                          innerCtSize,
                                          nonce.data(),
                                          nonce.size(),
                                          aad.data(),
                                          aad.size(),
                                          tag.data(),
                                          tag.size(),
                                          innerCt.data(),
                                          pt.data());
  cleanup();
  if (rc != 0) {
    // Authentication failure -- matches the OpenSSL backend's behavior of
    // throwing rather than returning std::nullopt (see aead_cipher.cpp upstream).
    throw std::runtime_error("AEAD authentication failure");
  }

  return pt;
}

} // namespace MLS_NAMESPACE::hpke
