#include <hpke/digest.h>
#include <hpke/signature.h>
#include <namespace.h>

#include "group.h"

// TriCord-authored trimmed replacement for upstream mlspp's
// lib/hpke/src/signature.cpp. GroupSignature itself is reproduced from
// upstream (BSD-2-Clause, Cisco Systems) unchanged in substance -- it is fully
// generic, delegating every operation to the abstract Group interface. What's
// removed: the P384/P521/Ed25519/Ed448/RSA factory specializations (DAVE
// ciphersuite 2 only ever needs P256_SHA256) and the JWK import/export methods'
// real implementation (DAVE/MLS Basic credentials never use JWK; the
// pure-virtual interface still requires overrides, so they throw instead of
// pulling in a JSON + base64url dependency for unused functionality).

namespace MLS_NAMESPACE::hpke {

namespace {
struct GroupSignature : public Signature
{
  struct PrivateKey : public Signature::PrivateKey
  {
    explicit PrivateKey(Group::PrivateKey* group_priv_in)
      : group_priv(group_priv_in)
    {
    }

    std::unique_ptr<Signature::PublicKey> public_key() const override
    {
      return group_priv->public_key();
    }

    std::unique_ptr<Group::PrivateKey> group_priv;
  };

  static Signature::ID group_to_sig(Group::ID group_id)
  {
    switch (group_id) {
      case Group::ID::P256:
        return Signature::ID::P256_SHA256;
      default:
        throw std::runtime_error("Unsupported group in mbedTLS signature backend");
    }
  }

  explicit GroupSignature(const Group& group_in)
    : Signature(group_to_sig(group_in.id))
    , group(group_in)
  {
  }

  std::unique_ptr<Signature::PrivateKey> generate_key_pair() const override
  {
    return std::make_unique<PrivateKey>(group.generate_key_pair().release());
  }

  std::unique_ptr<Signature::PrivateKey> derive_key_pair(const bytes& ikm) const override
  {
    return std::make_unique<PrivateKey>(group.derive_key_pair({}, ikm).release());
  }

  bytes serialize(const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group.serialize(rpk);
  }

  std::unique_ptr<Signature::PublicKey> deserialize(const bytes& enc) const override
  {
    return group.deserialize(enc);
  }

  bytes serialize_private(const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group.serialize_private(*rsk.group_priv);
  }

  std::unique_ptr<Signature::PrivateKey> deserialize_private(const bytes& skm) const override
  {
    return std::make_unique<PrivateKey>(group.deserialize_private(skm).release());
  }

  std::unique_ptr<Signature::PrivateKey> deserialize_private_der(const bytes& der) const override
  {
    return std::make_unique<PrivateKey>(group.deserialize_private_der(der).release());
  }

  bytes sign(const bytes& data, const Signature::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const PrivateKey&>(sk);
    return group.sign(data, *rsk.group_priv);
  }

  bool verify(const bytes& data, const bytes& sig, const Signature::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const Group::PublicKey&>(pk);
    return group.verify(data, sig, rpk);
  }

  std::unique_ptr<Signature::PrivateKey> import_jwk_private(const std::string& /* jwk_json */) const override
  {
    throw std::runtime_error("JWK import not implemented (unused by DAVE)");
  }

  std::unique_ptr<Signature::PublicKey> import_jwk(const std::string& /* jwk_json */) const override
  {
    throw std::runtime_error("JWK import not implemented (unused by DAVE)");
  }

  std::string export_jwk(const Signature::PublicKey& /* pk */) const override
  {
    throw std::runtime_error("JWK export not implemented (unused by DAVE)");
  }

  std::string export_jwk_private(const Signature::PrivateKey& /* sk */) const override
  {
    throw std::runtime_error("JWK export not implemented (unused by DAVE)");
  }

private:
  const Group& group;
};
} // namespace

template<>
const Signature&
Signature::get<Signature::ID::P256_SHA256>()
{
  static const auto instance = GroupSignature(Group::get<Group::ID::P256>());
  return instance;
}

} // namespace MLS_NAMESPACE::hpke
