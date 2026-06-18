#include <hpke/digest.h>
#include <namespace.h>

#include "mbedtls_common.h"

#include <mbedtls/md.h>

// Only SHA-256 is implemented: DAVE ciphersuite 2
// (DHKEMP256_AES128GCM_SHA256_P256) is the only suite TriCord's VoiceClient ever
// negotiates. Digest::get<SHA384/SHA512/SHA3_256>() are intentionally left
// undefined here so any accidental use of an unsupported ciphersuite fails to
// link rather than silently misbehaving at runtime.

namespace MLS_NAMESPACE::hpke {

template<>
const Digest&
Digest::get<Digest::ID::SHA256>()
{
  static const Digest instance(Digest::ID::SHA256);
  return instance;
}

namespace {
const mbedtls_md_info_t*
mdInfoFor(Digest::ID id)
{
  switch (id) {
    case Digest::ID::SHA256:
      return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    default:
      throw std::runtime_error("Unsupported digest algorithm in mbedTLS backend");
  }
}

size_t
hashSizeFor(Digest::ID id)
{
  const auto* info = mdInfoFor(id);
  return static_cast<size_t>(mbedtls_md_get_size(info));
}
} // namespace

Digest::Digest(Digest::ID id_in)
  : id(id_in)
  , hash_size(hashSizeFor(id_in))
{
}

bytes
Digest::hash(const bytes& data) const
{
  const auto* info = mdInfoFor(id);
  auto out = bytes(hash_size);
  if (mbedtls_md(info, data.data(), data.size(), out.data()) != 0) {
    throw std::runtime_error("mbedtls_md (hash) failed");
  }
  return out;
}

bytes
Digest::hmac(const bytes& key, const bytes& data) const
{
  const auto* info = mdInfoFor(id);
  auto out = bytes(hash_size);
  // mbedtls_md_hmac rejects a null key/data pointer even when length is 0.
  static const uint8_t zero = 0;
  const auto* keyPtr = key.empty() ? &zero : key.data();
  const auto* dataPtr = data.empty() ? &zero : data.data();
  if (mbedtls_md_hmac(info, keyPtr, key.size(), dataPtr, data.size(), out.data()) != 0) {
    throw std::runtime_error("mbedtls_md_hmac failed");
  }
  return out;
}

bytes
Digest::hmac_for_hkdf_extract(const bytes& key, const bytes& data) const
{
  // RFC 5869 Extract(salt, ikm) = HMAC-Hash(salt, ikm); mbedTLS's HMAC has no
  // FIPS-mode short-key restriction to work around here, unlike the OpenSSL
  // backend this replaces, so this is just a direct call to hmac().
  return hmac(key, data);
}

} // namespace MLS_NAMESPACE::hpke
