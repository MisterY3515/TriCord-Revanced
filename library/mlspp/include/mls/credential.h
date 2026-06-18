#pragma once

#include <mls/common.h>
#include <mls/crypto.h>
#include <namespace.h>

// TriCord-authored trimmed replacement for upstream mlspp's
// include/mls/credential.h. DAVE only ever uses Basic credentials (per the
// whitepaper: "Credential Type: Basic only"). X509Credential,
// UserInfoVCCredential and MultiCredential are removed -- keeping them would
// require vendoring hpke/certificate.h (X.509 parsing) and
// hpke/userinfo_vc.h (JWT-based verifiable credentials), neither of which
// DAVE/MLS as used by Discord's voice gateway ever exercises. If a peer
// somehow sends a non-Basic credential, TLS variant deserialization fails
// closed (throws) instead of silently mishandling it.

namespace MLS_NAMESPACE {

// struct {
//     opaque identity<0..2^16-1>;
//     SignaturePublicKey public_key;
// } BasicCredential;
struct BasicCredential
{
  BasicCredential() {}

  BasicCredential(bytes identity_in)
    : identity(std::move(identity_in))
  {
  }

  bytes identity;

  TLS_SERIALIZABLE(identity)
};

enum struct CredentialType : uint16_t
{
  reserved = 0,
  basic = 1,
  x509 = 2,

  userinfo_vc_draft_00 = 0xFE00,
  multi_draft_00 = 0xFF00,
};

// struct {
//     CredentialType credential_type;
//     select (credential_type) {
//         case basic:
//             BasicCredential;
//     };
// } Credential;
struct Credential
{
  Credential() = default;

  CredentialType type() const;

  template<typename T>
  const T& get() const
  {
    return var::get<T>(_cred);
  }

  static Credential basic(const bytes& identity);

  bool valid_for(const SignaturePublicKey& pub) const;

  TLS_SERIALIZABLE(_cred)
  TLS_TRAITS(tls::variant<CredentialType>)

private:
  using SpecificCredential = var::variant<BasicCredential>;

  Credential(SpecificCredential specific);
  SpecificCredential _cred;
};

} // namespace MLS_NAMESPACE

namespace MLS_NAMESPACE::tls {

TLS_VARIANT_MAP(MLS_NAMESPACE::CredentialType,
                MLS_NAMESPACE::BasicCredential,
                basic)

} // namespace MLS_NAMESPACE::tls
