#include <mls/credential.h>
#include <namespace.h>
#include <tls/tls_syntax.h>

// TriCord-authored trimmed replacement for upstream mlspp's src/credential.cpp.
// See credential.h for what was removed and why.

namespace MLS_NAMESPACE {

CredentialType
Credential::type() const
{
  return tls::variant<CredentialType>::type(_cred);
}

Credential
Credential::basic(const bytes& identity)
{
  return { BasicCredential{ identity } };
}

bool
Credential::valid_for(const SignaturePublicKey& /* pub */) const
{
  // Only BasicCredential is supported, and per upstream's own
  // pub_key_match::operator()(const BasicCredential&), a Basic credential is
  // always considered valid for any signature key.
  return true;
}

Credential::Credential(SpecificCredential specific)
  : _cred(std::move(specific))
{
}

} // namespace MLS_NAMESPACE
