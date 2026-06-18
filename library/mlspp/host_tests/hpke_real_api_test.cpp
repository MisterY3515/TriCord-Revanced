// Phase 1 validation through the REAL vendored hpke:: class hierarchy (not the
// standalone harness in dave_p256_hpke_test.cpp). Exercises HPKE::setup_base_s /
// setup_base_r end-to-end through DHKEM/Group/AEAD/Digest virtual dispatch, plus
// a Signature::P256_SHA256 sign/verify round trip through GroupSignature.
#include <hpke/hpke.h>
#include <hpke/signature.h>
#include <hpke/random.h>
#include <namespace.h>

#include <cstdio>
#include <string>

using namespace MLS_NAMESPACE::hpke;
using namespace MLS_NAMESPACE::bytes_ns;

static std::string toHex(const bytes &data) {
	static const char *digits = "0123456789abcdef";
	std::string out;
	for (uint8_t b : data) {
		out.push_back(digits[b >> 4]);
		out.push_back(digits[b & 0xF]);
	}
	return out;
}

int main() {
	int failures = 0;
	auto check = [&](const char *name, bool ok) {
		printf("%-30s %s\n", name, ok ? "OK" : "FAIL");
		if (!ok) failures++;
	};

	try {
		HPKE hpke(KEM::ID::DHKEM_P256_SHA256, KDF::ID::HKDF_SHA256, AEAD::ID::AES_128_GCM);

		auto &kem = KEM::get<KEM::ID::DHKEM_P256_SHA256>();
		auto skR = kem.generate_key_pair();
		auto pkR = skR->public_key();

		bytes info = from_ascii("dave research real-api test");
		auto [enc, senderCtx] = hpke.setup_base_s(*pkR, info);
		auto receiverCtx = hpke.setup_base_r(enc, *skR, info);

		bytes aad = from_ascii("aad");
		bytes pt = from_ascii("DAVE/MLS HPKE real-API round trip");

		bytes ct = senderCtx.seal(aad, pt);
		auto opened = receiverCtx.open(aad, ct);
		check("setup_base_s/r seal+open round trip", opened.has_value() && opened.value() == pt);

		// Export should match between sender and receiver (do_export uses the
		// shared exporter_secret derived identically on both sides).
		bytes exportCtx = from_ascii("export-context");
		bytes exp1 = senderCtx.do_export(exportCtx, 32);
		bytes exp2 = receiverCtx.do_export(exportCtx, 32);
		check("exporter_secret matches sender/receiver", exp1 == exp2);

		// Tampered AAD must fail to authenticate. Matches upstream's OpenSSL
		// backend: AEADCipher::open() throws on auth failure rather than
		// returning an empty optional (see aead_cipher.cpp upstream).
		bool tamperedRejected = false;
		try {
			receiverCtx.open(from_ascii("wrong-aad"), ct);
		} catch (const std::exception &) {
			tamperedRejected = true;
		}
		check("tampered AAD rejected", tamperedRejected);

		// Signature::P256_SHA256 sign/verify round trip through GroupSignature.
		auto &sig = Signature::get<Signature::ID::P256_SHA256>();
		auto sigSk = sig.generate_key_pair();
		auto sigPk = sigSk->public_key();
		bytes message = from_ascii("dave credential signing test");
		bytes signature = sig.sign(message, *sigSk);
		check("P256_SHA256 sign/verify round trip", sig.verify(message, signature, *sigPk));

		bytes tamperedMessage = from_ascii("dave credential signing TEST");
		check("P256_SHA256 verify rejects tampered message", !sig.verify(tamperedMessage, signature, *sigPk));

	} catch (const std::exception &e) {
		printf("EXCEPTION: %s\n", e.what());
		failures++;
	}

	if (failures == 0) {
		printf("\nALL REAL-API CHECKS PASSED\n");
		return 0;
	}
	printf("\n%d CHECK(S) FAILED\n", failures);
	return 1;
}
