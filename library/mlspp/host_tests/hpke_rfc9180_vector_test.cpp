// Phase 1 research harness (NOT the final vendored backend): validates that a
// minimal mbedTLS-backed HPKE Base-mode DHKEM(P-256,HKDF-SHA256)/AES-128-GCM
// implementation reproduces RFC 9180 test vector #64 (mlspp's bundled
// test-vectors.json) bit-for-bit. Once this passes, the same formulas get
// restructured into library/mlspp/lib/hpke/src/mbedtls/*.cpp against mlspp's
// actual hpke:: interfaces.
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

using Bytes = std::vector<uint8_t>;

// ---------- hex helpers ----------
static Bytes fromHex(const std::string &hex) {
	Bytes out(hex.size() / 2);
	for (size_t i = 0; i < out.size(); i++) {
		out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
	}
	return out;
}

static std::string toHex(const Bytes &data) {
	static const char *digits = "0123456789abcdef";
	std::string out;
	out.reserve(data.size() * 2);
	for (uint8_t b : data) {
		out.push_back(digits[b >> 4]);
		out.push_back(digits[b & 0xF]);
	}
	return out;
}

static Bytes operator+(const Bytes &a, const Bytes &b) {
	Bytes out(a);
	out.insert(out.end(), b.begin(), b.end());
	return out;
}

static Bytes fromAscii(const std::string &s) { return Bytes(s.begin(), s.end()); }

static Bytes i2osp(uint64_t val, size_t size) {
	Bytes out(size, 0);
	size_t max = size > 8 ? 8 : size;
	for (size_t i = 0; i < max; i++) {
		out[size - i - 1] = static_cast<uint8_t>(val >> (8 * i));
	}
	return out;
}

static Bytes xorBytes(const Bytes &a, const Bytes &b) {
	Bytes out(a.size());
	for (size_t i = 0; i < a.size(); i++) out[i] = a[i] ^ b[i];
	return out;
}

// ---------- mbedTLS-backed HMAC-SHA256 / HKDF ----------
static Bytes hmacSha256(const Bytes &key, const Bytes &data) {
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	Bytes out(32);
	const uint8_t zero = 0;
	const uint8_t *keyData = key.empty() ? &zero : key.data();
	size_t keyLen = key.empty() ? 0 : key.size();
	if (mbedtls_md_hmac(info, keyData, keyLen, data.empty() ? &zero : data.data(), data.size(), out.data()) != 0) {
		throw std::runtime_error("hmac failed");
	}
	return out;
}

static Bytes hkdfExtract(const Bytes &salt, const Bytes &ikm) { return hmacSha256(salt, ikm); }

static Bytes hkdfExpand(const Bytes &prk, const Bytes &info, size_t size) {
	Bytes okm;
	Bytes ti;
	uint8_t i = 0;
	while (okm.size() < size) {
		i += 1;
		Bytes block = ti + info + Bytes{i};
		ti = hmacSha256(prk, block);
		okm = okm + ti;
	}
	okm.resize(size);
	return okm;
}

// ---------- HPKE labeled KDF (RFC 9180 4.1) ----------
static const Bytes &hpkeV1() {
	static const Bytes v = fromAscii("HPKE-v1");
	return v;
}

static Bytes labeledExtract(const Bytes &suiteId, const Bytes &salt, const Bytes &label, const Bytes &ikm) {
	return hkdfExtract(salt, hpkeV1() + suiteId + label + ikm);
}

static Bytes labeledExpand(const Bytes &suiteId, const Bytes &prk, const Bytes &label, const Bytes &info, size_t size) {
	Bytes labeledInfo = i2osp(size, 2) + hpkeV1() + suiteId + label + info;
	return hkdfExpand(prk, labeledInfo, size);
}

// ---------- mbedTLS-backed P-256 group ops ----------
struct MbedRng {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	MbedRng() {
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&drbg);
		const char *pers = "dave-research";
		if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
		                          reinterpret_cast<const unsigned char *>(pers), strlen(pers)) != 0) {
			throw std::runtime_error("drbg seed failed");
		}
	}
	~MbedRng() {
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&entropy);
	}
};

static Bytes mpiToFixed(const mbedtls_mpi &mpi, size_t size) {
	Bytes out(size, 0);
	if (mbedtls_mpi_write_binary(&mpi, out.data(), size) != 0) {
		throw std::runtime_error("mpi_write_binary failed");
	}
	return out;
}

// RFC 9180 7.1.3 DeriveKeyPair for NIST curves (group.cpp's ECKeyGroup::derive_key_pair).
// suite_id here is the *KEM* suite_id ("KEM" || I2OSP(kem_id,2)), per dhkem.cpp.
static Bytes derivePrivateScalar(const mbedtls_ecp_group &grp, const Bytes &kemSuiteId, const Bytes &ikm) {
	static const Bytes labelDkpPrk = fromAscii("dkp_prk");
	static const Bytes labelCandidate = fromAscii("candidate");
	const size_t skSize = 32; // P-256

	Bytes dkpPrk = labeledExtract(kemSuiteId, {}, labelDkpPrk, ikm);

	mbedtls_mpi sk;
	mbedtls_mpi_init(&sk);
	mbedtls_mpi_lset(&sk, 0);

	int counter = 0;
	while (mbedtls_mpi_cmp_int(&sk, 0) == 0 || mbedtls_mpi_cmp_mpi(&sk, &const_cast<mbedtls_ecp_group &>(grp).N) >= 0) {
		Bytes ctr = i2osp(static_cast<uint64_t>(counter), 1);
		Bytes candidate = labeledExpand(kemSuiteId, dkpPrk, labelCandidate, ctr, skSize);
		candidate[0] &= 0xFF; // P-256 bitmask per group.cpp's bitmask()
		if (mbedtls_mpi_read_binary(&sk, candidate.data(), candidate.size()) != 0) {
			throw std::runtime_error("mpi_read_binary failed");
		}
		counter += 1;
		if (counter > 255) throw std::runtime_error("DeriveKeyPair iteration limit exceeded");
	}

	Bytes out = mpiToFixed(sk, skSize);
	mbedtls_mpi_free(&sk);
	return out;
}

struct P256KeyPair {
	Bytes skRaw; // 32 bytes big-endian scalar
	Bytes pkUncompressed; // 65 bytes: 0x04 || X || Y
};

static P256KeyPair p256KeyPairFromScalar(mbedtls_ecp_group &grp, const Bytes &skRaw) {
	mbedtls_mpi d;
	mbedtls_ecp_point Q;
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	if (mbedtls_mpi_read_binary(&d, skRaw.data(), skRaw.size()) != 0) throw std::runtime_error("read priv failed");

	MbedRng rng;
	if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &rng.drbg) != 0) {
		throw std::runtime_error("ecp_mul failed");
	}

	Bytes pub(65);
	size_t outLen = 0;
	if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen, pub.data(), pub.size()) != 0) {
		throw std::runtime_error("point_write_binary failed");
	}
	pub.resize(outLen);

	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Q);
	return {skRaw, pub};
}

static Bytes p256Dh(mbedtls_ecp_group &grp, const Bytes &skRaw, const Bytes &pkUncompressed) {
	mbedtls_mpi d;
	mbedtls_ecp_point Q, shared;
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_point_init(&shared);

	if (mbedtls_mpi_read_binary(&d, skRaw.data(), skRaw.size()) != 0) throw std::runtime_error("read priv failed");
	if (mbedtls_ecp_point_read_binary(&grp, &Q, pkUncompressed.data(), pkUncompressed.size()) != 0) {
		throw std::runtime_error("point_read_binary failed");
	}

	MbedRng rng;
	if (mbedtls_ecp_mul(&grp, &shared, &d, &Q, mbedtls_ctr_drbg_random, &rng.drbg) != 0) {
		throw std::runtime_error("ecp_mul (dh) failed");
	}

	Bytes x = mpiToFixed(shared.X, 32); // raw ECDH output = X coordinate only, per RFC9180/SEC1

	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_point_free(&shared);
	return x;
}

// ---------- DHKEM(P-256,HKDF-SHA256) Encap/Decap (dhkem.cpp, generic over Group) ----------
struct DhkemResult {
	Bytes sharedSecret;
	Bytes enc;
};

static const Bytes &kemSuiteIdP256() {
	static const Bytes v = fromAscii("KEM") + i2osp(0x0010, 2); // DHKEM_P256_SHA256
	return v;
}

static Bytes extractAndExpand(const Bytes &dh, const Bytes &kemContext) {
	static const Bytes labelEaePrk = fromAscii("eae_prk");
	static const Bytes labelSharedSecret = fromAscii("shared_secret");
	Bytes eaePrk = labeledExtract(kemSuiteIdP256(), {}, labelEaePrk, dh);
	return labeledExpand(kemSuiteIdP256(), eaePrk, labelSharedSecret, kemContext, 32); // Nsecret=32 for SHA256
}

static DhkemResult dhkemDecap(mbedtls_ecp_group &grp, const Bytes &enc, const Bytes &skR, const Bytes &pkR) {
	Bytes zz = p256Dh(grp, skR, enc);
	Bytes kemContext = enc + pkR;
	return {extractAndExpand(zz, kemContext), enc};
}

// ---------- HPKE Base mode KeySchedule + AES-128-GCM context (hpke.cpp + aead_cipher.cpp) ----------
static const Bytes &hpkeSuiteId() {
	static const Bytes v = fromAscii("HPKE") + i2osp(0x0010, 2) + i2osp(0x0001, 2) + i2osp(0x0001, 2);
	return v;
}

struct HpkeContext {
	Bytes key;
	Bytes baseNonce;
	Bytes exporterSecret;
};

static HpkeContext keySchedule(const Bytes &sharedSecret, const Bytes &info) {
	static const Bytes labelPskIdHash = fromAscii("psk_id_hash");
	static const Bytes labelInfoHash = fromAscii("info_hash");
	static const Bytes labelSecret = fromAscii("secret");
	static const Bytes labelKey = fromAscii("key");
	static const Bytes labelBaseNonce = fromAscii("base_nonce");
	static const Bytes labelExp = fromAscii("exp");

	Bytes pskIdHash = labeledExtract(hpkeSuiteId(), {}, labelPskIdHash, {});
	Bytes infoHash = labeledExtract(hpkeSuiteId(), {}, labelInfoHash, info);
	Bytes modeBase = {0x00};
	Bytes keyScheduleContext = modeBase + pskIdHash + infoHash;

	Bytes secret = labeledExtract(hpkeSuiteId(), sharedSecret, labelSecret, {});

	HpkeContext ctx;
	ctx.key = labeledExpand(hpkeSuiteId(), secret, labelKey, keyScheduleContext, 16); // AES-128-GCM Nk=16
	ctx.baseNonce = labeledExpand(hpkeSuiteId(), secret, labelBaseNonce, keyScheduleContext, 12); // Nn=12
	ctx.exporterSecret = labeledExpand(hpkeSuiteId(), secret, labelExp, keyScheduleContext, 32); // Nh=32
	return ctx;
}

static Bytes aesGcmSeal(const Bytes &key, const Bytes &nonce, const Bytes &aad, const Bytes &pt) {
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
		throw std::runtime_error("gcm_setkey failed");
	}
	Bytes ct(pt.size());
	Bytes tag(16);
	if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt.size(), nonce.data(), nonce.size(), aad.data(),
	                              aad.size(), pt.data(), ct.data(), tag.size(), tag.data()) != 0) {
		throw std::runtime_error("gcm seal failed");
	}
	mbedtls_gcm_free(&gcm);
	return ct + tag;
}

// matches AEADCipher::open in aead_cipher.cpp: ct is ciphertext||tag (tag last 16 bytes).
static Bytes aesGcmOpen(const Bytes &key, const Bytes &nonce, const Bytes &aad, const Bytes &ctAndTag) {
	if (ctAndTag.size() < 16) throw std::runtime_error("ciphertext smaller than tag");
	size_t ctLen = ctAndTag.size() - 16;
	Bytes ct(ctAndTag.begin(), ctAndTag.begin() + ctLen);
	Bytes tag(ctAndTag.begin() + ctLen, ctAndTag.end());

	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
		throw std::runtime_error("gcm_setkey failed");
	}
	Bytes pt(ctLen);
	int rc = mbedtls_gcm_auth_decrypt(&gcm, ctLen, nonce.data(), nonce.size(), aad.data(), aad.size(), tag.data(),
	                                  tag.size(), ct.data(), pt.data());
	mbedtls_gcm_free(&gcm);
	if (rc != 0) throw std::runtime_error("AEAD authentication failure");
	return pt;
}

// Round-trip-only check (ECDSA-P256 signatures are randomized, no fixed expected
// value to match) -- proves our sign()/verify() pair works with mbedTLS's DER
// signature encoding, the same wire format mlspp's EVPGroup sign/verify (used for
// Basic-credential signing) produces via OpenSSL's EVP_DigestSign/Verify.
static bool ecdsaP256RoundTrip() {
	MbedRng rng;
	mbedtls_ecdsa_context ctx;
	mbedtls_ecdsa_init(&ctx);
	if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &rng.drbg) != 0) {
		throw std::runtime_error("ecdsa_genkey failed");
	}

	Bytes message = fromAscii("dave research ecdsa-p256 roundtrip");
	Bytes digest = hmacSha256({}, message); // stand-in 32-byte digest; content is irrelevant for this check

	unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
	size_t sigLen = 0;
	int rc = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, digest.data(), digest.size(), sig, &sigLen,
	                                       mbedtls_ctr_drbg_random, &rng.drbg);
	bool ok = rc == 0;
	if (ok) {
		rc = mbedtls_ecdsa_read_signature(&ctx, digest.data(), digest.size(), sig, sigLen);
		ok = rc == 0;
	}

	mbedtls_ecdsa_free(&ctx);
	return ok;
}

int main() {
	// RFC 9180 test vector #64 (mlspp test-vectors.json): mode=base,
	// kem_id=DHKEM(P-256,HKDF-SHA256), kdf_id=HKDF-SHA256, aead_id=AES-128-GCM.
	Bytes info = fromHex("4f6465206f6e2061204772656369616e2055726e");
	Bytes ikmR = fromHex("6b1ec8ebf259e05ca9596fd0ec634035a649d81582b0e3007f8603c6eb3435ad");
	Bytes ikmE = fromHex("5377490d651f4cd3e97ddaaeb50f7337230618522c4e54c1d63587adf8c96cc7");
	std::string expectedEnc = "046c62e9ee75fe5b73c4aed592220c08b100a8dd0bc8ed09bfe3ccdcc2fcb12c84fc09748089abca1a2310ceebbbf3cc14e56bd325f74ba2dc8242b789f503f400";
	std::string expectedSharedSecret = "4c43dd81351c0d19bf5eff313012c080978aaa3b8d14aff42322f1b832cf2610";
	std::string expectedKey = "856ed4d1d5ebfdbb25fd2f3d4bca3f72";
	std::string expectedBaseNonce = "7f16c754a173fcd13d14f878";
	std::string expectedExporterSecret = "56f0f7619fa9a896d18da2f921597cd299c57985ca0c3c1cd473aa1c88d18377";
	std::string expectedCt0 = "b7481ce0b49e40d4a71a73b60beda9c5ea5656815608b96eb65ad9932511de4c2354e2444d310db8b9593ffb2c";

	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
		printf("FAIL: ecp_group_load\n");
		return 1;
	}

	int failures = 0;
	auto check = [&](const char *name, const std::string &got, const std::string &expected) {
		bool ok = got == expected;
		printf("%-20s %s\n", name, ok ? "OK" : "MISMATCH");
		if (!ok) {
			printf("  got:      %s\n  expected: %s\n", got.c_str(), expected.c_str());
			failures++;
		}
	};

	Bytes skR = derivePrivateScalar(grp, kemSuiteIdP256(), ikmR);
	Bytes skE = derivePrivateScalar(grp, kemSuiteIdP256(), ikmE);
	P256KeyPair kpR = p256KeyPairFromScalar(grp, skR);
	P256KeyPair kpE = p256KeyPairFromScalar(grp, skE);

	check("enc (pkE)", toHex(kpE.pkUncompressed), expectedEnc);

	// encap from sender's perspective: zz = DH(skE, pkR); enc = serialize(pkE)
	Bytes zz = p256Dh(grp, skE, kpR.pkUncompressed);
	Bytes kemContext = kpE.pkUncompressed + kpR.pkUncompressed;
	Bytes sharedSecret = extractAndExpand(zz, kemContext);
	check("shared_secret", toHex(sharedSecret), expectedSharedSecret);

	// decap from receiver's perspective should match
	DhkemResult decapped = dhkemDecap(grp, kpE.pkUncompressed, skR, kpR.pkUncompressed);
	check("shared_secret (decap)", toHex(decapped.sharedSecret), expectedSharedSecret);

	HpkeContext ctx = keySchedule(sharedSecret, info);
	check("key", toHex(ctx.key), expectedKey);
	check("base_nonce", toHex(ctx.baseNonce), expectedBaseNonce);
	check("exporter_secret", toHex(ctx.exporterSecret), expectedExporterSecret);

	Bytes pt0 = fromHex("4265617574792069732074727574682c20747275746820626561757479");
	Bytes aad0 = fromAscii("Count-0");
	Bytes ct0 = aesGcmSeal(ctx.key, ctx.baseNonce, aad0, pt0);
	check("ciphertext[0]", toHex(ct0), expectedCt0);

	Bytes decrypted0 = aesGcmOpen(ctx.key, ctx.baseNonce, aad0, fromHex(expectedCt0));
	check("decrypt(ciphertext[0])", toHex(decrypted0), toHex(pt0));

	bool ecdsaOk = ecdsaP256RoundTrip();
	printf("%-20s %s\n", "ecdsa-p256 roundtrip", ecdsaOk ? "OK" : "MISMATCH");
	if (!ecdsaOk) failures++;

	mbedtls_ecp_group_free(&grp);

	if (failures == 0) {
		printf("\nALL CHECKS PASSED\n");
		return 0;
	}
	printf("\n%d CHECK(S) FAILED\n", failures);
	return 1;
}
