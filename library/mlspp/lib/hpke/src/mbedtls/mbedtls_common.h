#pragma once

#include <namespace.h>
#include <stdexcept>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace MLS_NAMESPACE::hpke {

// Throws on mbedTLS error codes, consistent with the rest of this backend's
// "everything throws std::runtime_error" convention (matches openssl_error() in
// the upstream OpenSSL/BoringSSL backends this one replaces).
std::runtime_error
mbedtls_error(int errnum);

// Shared RNG used by every mbedTLS call in this backend that needs one (key
// generation, ECDSA signing -- GCM nonces are always caller-supplied, never
// generated here). Seeded once, lazily, via mbedtls_entropy_func the same way
// source/network/websocket_client.cpp seeds its own TLS context.
mbedtls_ctr_drbg_context&
sharedDrbg();

} // namespace MLS_NAMESPACE::hpke
