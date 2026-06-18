#include "../group.h"
#include "../hpke_common.h"
#include "mbedtls_common.h"

#include <hpke/digest.h>
#include <hpke/random.h>
#include <namespace.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>

#include <mutex>

// Only Group::ID::P256 is implemented: DAVE ciphersuite 2 is the only one
// TriCord's VoiceClient negotiates. Group::get<P384/P521/X25519/...>() are
// intentionally left undefined so an unsupported ciphersuite fails to link.
//
// JWK coordinate import/export (coordinates/public_key_from_coordinates) and
// DER private-key import (deserialize_private_der) are part of Group's
// interface but are never exercised by DAVE/MLS protocol operation (only by
// JWK tooling, which this backend does not support -- see signature.cpp) --
// they throw rather than carrying unused PEM/DER/JWK parsing code.

namespace MLS_NAMESPACE::hpke {

namespace {

constexpr size_t kP256ScalarSize = 32;
constexpr size_t kP256UncompressedPointSize = 65;

mbedtls_ecp_group&
p256Group()
{
  static mbedtls_ecp_group grp;
  static std::once_flag initialized;
  std::call_once(initialized, [] {
    mbedtls_ecp_group_init(&grp);
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
      throw std::runtime_error("Failed to load secp256r1 group");
    }
  });
  return grp;
}

bytes
mpiToFixed(const mbedtls_mpi& mpi, size_t size)
{
  auto out = bytes(size);
  if (mbedtls_mpi_write_binary(&mpi, out.data(), size) != 0) {
    throw std::runtime_error("mbedtls_mpi_write_binary failed");
  }
  return out;
}

struct ScopedMpi
{
  mbedtls_mpi v;
  ScopedMpi() { mbedtls_mpi_init(&v); }
  ~ScopedMpi() { mbedtls_mpi_free(&v); }
};

struct ScopedPoint
{
  mbedtls_ecp_point v;
  ScopedPoint() { mbedtls_ecp_point_init(&v); }
  ~ScopedPoint() { mbedtls_ecp_point_free(&v); }
};

// RFC 9180 7.1.3 DeriveKeyPair, NIST-curve case (matches upstream group.cpp's
// ECKeyGroup::derive_key_pair candidate-generation loop exactly, against the
// "KEM" suite_id dhkem.cpp passes in).
bytes
deriveP256Scalar(const KDF& kdf, const bytes& suite_id, const bytes& ikm)
{
  static const auto labelDkpPrk = from_ascii("dkp_prk");
  static const auto labelCandidate = from_ascii("candidate");
  static const int retryLimit = 255;

  auto dkpPrk = kdf.labeled_extract(suite_id, {}, labelDkpPrk, ikm);

  ScopedMpi sk;
  mbedtls_mpi_lset(&sk.v, 0);
  auto& grp = p256Group();

  int counter = 0;
  while (mbedtls_mpi_cmp_int(&sk.v, 0) == 0 || mbedtls_mpi_cmp_mpi(&sk.v, &grp.N) >= 0) {
    auto ctr = i2osp(static_cast<uint64_t>(counter), 1);
    auto candidate = kdf.labeled_expand(suite_id, dkpPrk, labelCandidate, ctr, kP256ScalarSize);
    candidate.at(0) &= 0xFF; // P-256 bitmask (group.cpp's bitmask()): no masking needed
    if (mbedtls_mpi_read_binary(&sk.v, candidate.data(), candidate.size()) != 0) {
      throw std::runtime_error("mbedtls_mpi_read_binary failed");
    }
    counter += 1;
    if (counter > retryLimit) {
      throw std::runtime_error("DeriveKeyPair iteration limit exceeded");
    }
  }

  return mpiToFixed(sk.v, kP256ScalarSize);
}

bytes
p256PublicFromScalar(const bytes& skRaw)
{
  auto& grp = p256Group();
  ScopedMpi d;
  ScopedPoint Q;
  if (mbedtls_mpi_read_binary(&d.v, skRaw.data(), skRaw.size()) != 0) {
    throw std::runtime_error("mbedtls_mpi_read_binary (private scalar) failed");
  }
  if (mbedtls_ecp_mul(&grp, &Q.v, &d.v, &grp.G, mbedtls_ctr_drbg_random, &sharedDrbg()) != 0) {
    throw std::runtime_error("mbedtls_ecp_mul (public key) failed");
  }

  auto out = bytes(kP256UncompressedPointSize);
  size_t outLen = 0;
  if (mbedtls_ecp_point_write_binary(&grp, &Q.v, MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen, out.data(), out.size()) != 0) {
    throw std::runtime_error("mbedtls_ecp_point_write_binary failed");
  }
  out.resize(outLen);
  return out;
}

struct P256PublicKey : public Group::PublicKey
{
  explicit P256PublicKey(bytes uncompressed_in)
    : uncompressed(std::move(uncompressed_in))
  {
  }
  bytes uncompressed; // 0x04 || X || Y, 65 bytes
};

struct P256PrivateKey : public Group::PrivateKey
{
  explicit P256PrivateKey(bytes scalar_in)
    : scalar(std::move(scalar_in))
  {
  }

  std::unique_ptr<Group::PublicKey> public_key() const override
  {
    return std::make_unique<P256PublicKey>(p256PublicFromScalar(scalar));
  }

  bytes scalar; // 32 bytes big-endian
};

struct P256Group : public Group
{
  explicit P256Group(const KDF& kdf_in)
    : Group(Group::ID::P256, kdf_in)
  {
  }

  std::unique_ptr<Group::PrivateKey> generate_key_pair() const override
  {
    return derive_key_pair({}, random_bytes(128)); // matches EVPGroup::generate_key_pair's pattern
  }

  std::unique_ptr<Group::PrivateKey> derive_key_pair(const bytes& suite_id, const bytes& ikm) const override
  {
    return std::make_unique<P256PrivateKey>(deriveP256Scalar(kdf, suite_id, ikm));
  }

  std::unique_ptr<Group::PrivateKey> random_scalar(const bytes& seed) const override
  {
    auto& grp = p256Group();
    ScopedMpi sk;
    mbedtls_mpi_lset(&sk.v, 0);

    size_t start = 0;
    size_t end = kP256ScalarSize;
    if (end > seed.size()) {
      throw std::runtime_error("Rejection sampling failed");
    }
    auto candidate = seed.slice(start, end);
    if (mbedtls_mpi_read_binary(&sk.v, candidate.data(), candidate.size()) != 0) {
      throw std::runtime_error("mbedtls_mpi_read_binary failed");
    }

    while (mbedtls_mpi_cmp_int(&sk.v, 0) == 0 || mbedtls_mpi_cmp_mpi(&sk.v, &grp.N) >= 0) {
      start = end;
      end = end + kP256ScalarSize;
      if (end > seed.size()) {
        throw std::runtime_error("Rejection sampling failed");
      }
      candidate = seed.slice(start, end);
      if (mbedtls_mpi_read_binary(&sk.v, candidate.data(), candidate.size()) != 0) {
        throw std::runtime_error("mbedtls_mpi_read_binary failed");
      }
    }

    return std::make_unique<P256PrivateKey>(mpiToFixed(sk.v, kP256ScalarSize));
  }

  bytes serialize(const Group::PublicKey& pk) const override
  {
    return dynamic_cast<const P256PublicKey&>(pk).uncompressed;
  }

  std::unique_ptr<Group::PublicKey> deserialize(const bytes& enc) const override
  {
    // Validate the encoding round-trips through mbedTLS's point parser before
    // accepting attacker-controlled key material (enc comes off the wire, e.g.
    // from a peer's MLS KeyPackage/LeafNode).
    auto& grp = p256Group();
    ScopedPoint Q;
    if (mbedtls_ecp_point_read_binary(&grp, &Q.v, enc.data(), enc.size()) != 0) {
      throw std::runtime_error("Invalid P-256 public key encoding");
    }
    if (mbedtls_ecp_check_pubkey(&grp, &Q.v) != 0) {
      throw std::runtime_error("P-256 public key not on curve");
    }
    return std::make_unique<P256PublicKey>(enc);
  }

  bytes serialize_private(const Group::PrivateKey& sk) const override
  {
    return dynamic_cast<const P256PrivateKey&>(sk).scalar;
  }

  std::unique_ptr<Group::PrivateKey> deserialize_private(const bytes& skm) const override
  {
    return std::make_unique<P256PrivateKey>(skm);
  }

  std::unique_ptr<Group::PrivateKey> deserialize_private_der(const bytes& /* der */) const override
  {
    throw std::runtime_error("DER private key import not implemented (unused by DAVE)");
  }

  bytes dh(const Group::PrivateKey& sk, const Group::PublicKey& pk) const override
  {
    const auto& rsk = dynamic_cast<const P256PrivateKey&>(sk);
    const auto& rpk = dynamic_cast<const P256PublicKey&>(pk);

    auto& grp = p256Group();
    ScopedMpi d;
    ScopedPoint Q;
    ScopedPoint shared;

    if (mbedtls_mpi_read_binary(&d.v, rsk.scalar.data(), rsk.scalar.size()) != 0) {
      throw std::runtime_error("mbedtls_mpi_read_binary (dh private) failed");
    }
    if (mbedtls_ecp_point_read_binary(&grp, &Q.v, rpk.uncompressed.data(), rpk.uncompressed.size()) != 0) {
      throw std::runtime_error("mbedtls_ecp_point_read_binary (dh public) failed");
    }
    if (mbedtls_ecp_mul(&grp, &shared.v, &d.v, &Q.v, mbedtls_ctr_drbg_random, &sharedDrbg()) != 0) {
      throw std::runtime_error("mbedtls_ecp_mul (dh) failed");
    }

    // Raw ECDH output per RFC 9180/SEC1: the X coordinate of the shared point only.
    return mpiToFixed(shared.v.X, dh_size);
  }

  bytes sign(const bytes& data, const Group::PrivateKey& sk) const override
  {
    const auto& rsk = dynamic_cast<const P256PrivateKey&>(sk);
    auto& grp = p256Group();

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    auto cleanup = [&] { mbedtls_ecdsa_free(&ctx); };

    if (mbedtls_ecp_group_copy(&ctx.grp, &grp) != 0) {
      cleanup();
      throw std::runtime_error("mbedtls_ecp_group_copy failed");
    }
    if (mbedtls_mpi_read_binary(&ctx.d, rsk.scalar.data(), rsk.scalar.size()) != 0) {
      cleanup();
      throw std::runtime_error("mbedtls_mpi_read_binary (sign) failed");
    }

    // P256_SHA256 (RFC 9180 5.1.1): hash with SHA-256, then ECDSA-sign the digest --
    // matches upstream's EVPGroup::sign, which uses EVP_DigestSignInit with
    // group_sig_digest(P256) == EVP_sha256().
    auto digest = Digest::get<Digest::ID::SHA256>().hash(data);
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sigLen = 0;
    const int rc = mbedtls_ecdsa_write_signature(&ctx,
                                                 MBEDTLS_MD_SHA256,
                                                 digest.data(),
                                                 digest.size(),
                                                 sig,
                                                 &sigLen,
                                                 mbedtls_ctr_drbg_random,
                                                 &sharedDrbg());
    cleanup();
    if (rc != 0) {
      throw mbedtls_error(rc);
    }
    return bytes(std::vector<uint8_t>(sig, sig + sigLen));
  }

  bool verify(const bytes& data, const bytes& sig, const Group::PublicKey& pk) const override
  {
    const auto& rpk = dynamic_cast<const P256PublicKey&>(pk);
    auto& grp = p256Group();

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    auto cleanup = [&] { mbedtls_ecdsa_free(&ctx); };

    if (mbedtls_ecp_group_copy(&ctx.grp, &grp) != 0 ||
        mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, rpk.uncompressed.data(), rpk.uncompressed.size()) != 0) {
      cleanup();
      return false;
    }

    // mbedtls_ecdsa_verify() takes pre-split (r, s) MPIs, not a DER buffer;
    // mbedtls_ecdsa_read_signature() is the DER-aware wrapper that matches the
    // signature encoding sign() (mbedtls_ecdsa_write_signature) produces, and
    // the same DER encoding mlspp's OpenSSL backend's EVP_DigestSign produces.
    auto digest = Digest::get<Digest::ID::SHA256>().hash(data);
    const int rc = mbedtls_ecdsa_read_signature(&ctx, digest.data(), digest.size(), sig.data(), sig.size());
    cleanup();
    return rc == 0;
  }

  std::tuple<bytes, bytes> coordinates(const Group::PublicKey& /* pk */) const override
  {
    throw std::runtime_error("JWK coordinates not implemented (unused by DAVE)");
  }

  std::unique_ptr<Group::PublicKey> public_key_from_coordinates(const bytes& /* x */,
                                                                 const bytes& /* y */) const override
  {
    throw std::runtime_error("JWK coordinates not implemented (unused by DAVE)");
  }
};

} // namespace

template<>
const Group&
Group::get<Group::ID::P256>()
{
  static const P256Group instance(KDF::get<KDF::ID::HKDF_SHA256>());
  return instance;
}

Group::Group(ID group_id_in, const KDF& kdf_in)
  : id(group_id_in)
  , seed_size(128)
  , dh_size(kP256ScalarSize)
  , pk_size(kP256UncompressedPointSize)
  , sk_size(kP256ScalarSize)
  , jwk_key_type("EC")
  , jwk_curve_name("P-256")
  , kdf(kdf_in)
{
}

} // namespace MLS_NAMESPACE::hpke
