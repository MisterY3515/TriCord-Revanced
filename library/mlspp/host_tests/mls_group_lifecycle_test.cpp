// Phase 2/3 validation: a real 2-party MLS group lifecycle (create -> add ->
// commit -> welcome -> join -> application message exchange) running
// entirely through the vendored mlspp core against the mbedTLS hpke backend.
// This is the same machinery libdave's mls::Session wraps for DAVE.
#include <mls/state.h>
#include <namespace.h>

#include <cstdio>

using namespace MLS_NAMESPACE;

static LeafNode makeLeafNode(CipherSuite suite,
                             const HPKEPrivateKey &encPriv,
                             const SignaturePrivateKey &sigPriv,
                             const std::string &name) {
	return LeafNode(suite, encPriv.public_key, sigPriv.public_key, Credential::basic(from_ascii(name)),
	                Capabilities::create_default(), Lifetime::create_default(), {}, sigPriv);
}

int main() {
	int failures = 0;
	auto check = [&](const char *name, bool ok) {
		printf("%-45s %s\n", name, ok ? "OK" : "FAIL");
		if (!ok) failures++;
	};

	try {
		auto suite = CipherSuite(CipherSuite::ID::P256_AES128GCM_SHA256_P256);

		// --- Alice creates a single-member group ---
		auto aliceSigPriv = SignaturePrivateKey::generate(suite);
		auto aliceEncPriv = HPKEPrivateKey::generate(suite);
		auto aliceLeaf = makeLeafNode(suite, aliceEncPriv, aliceSigPriv, "alice");
		auto groupId = random_bytes(16);
		auto aliceState = State(groupId, suite, aliceEncPriv, aliceSigPriv, aliceLeaf, {});

		check("Alice's solo group epoch is 0", aliceState.epoch() == 0);

		// --- Bob prepares a KeyPackage to join ---
		auto bobSigPriv = SignaturePrivateKey::generate(suite);
		auto bobEncPriv = HPKEPrivateKey::generate(suite);
		auto bobLeaf = makeLeafNode(suite, bobEncPriv, bobSigPriv, "bob");
		auto bobInitPriv = HPKEPrivateKey::generate(suite);
		auto bobKeyPackage = KeyPackage(suite, bobInitPriv.public_key, bobLeaf, {}, bobSigPriv);
		check("Bob's KeyPackage verifies", bobKeyPackage.verify());

		// --- Alice proposes+commits adding Bob in one step ---
		auto addProposal = aliceState.add_proposal(bobKeyPackage);
		auto commitOpts = CommitOpts{ {addProposal}, true, false, {} };
		auto [commitMsg, welcome, aliceState2] = aliceState.commit(random_bytes(32), commitOpts, MessageOpts{});
		(void)commitMsg;

		check("Alice's post-commit epoch is 1", aliceState2.epoch() == 1);
		check("Alice's post-commit roster has 2 members", aliceState2.roster().size() == 2);

		// --- Bob joins via the Welcome ---
		auto bobState = State(bobInitPriv, bobEncPriv, bobSigPriv, bobKeyPackage, welcome, std::nullopt, {});

		check("Bob's joined epoch matches Alice's", bobState.epoch() == aliceState2.epoch());
		check("Bob's epoch_authenticator matches Alice's",
		     bobState.epoch_authenticator() == aliceState2.epoch_authenticator());
		check("Bob's group_id matches Alice's", bobState.group_id() == aliceState2.group_id());

		// --- Alice sends an encrypted application message, Bob decrypts it ---
		auto msg1 = from_ascii("hello bob, this is alice over DAVE-style MLS");
		auto ct1 = aliceState2.protect({}, msg1, 0);
		// Application messages go straight to unprotect(); handle() is only for
		// handshake content (Proposal/Commit), not application data.
		auto [aad1, pt1] = bobState.unprotect(ct1);
		(void)aad1;
		check("Bob decrypted Alice's message correctly", pt1 == msg1);

		// --- Bob replies, Alice decrypts it ---
		auto msg2 = from_ascii("hi alice, bob here, loud and clear");
		auto ct2 = bobState.protect({}, msg2, 0);
		auto [aad2, pt2] = aliceState2.unprotect(ct2);
		(void)aad2;
		check("Alice decrypted Bob's reply correctly", pt2 == msg2);

		// --- Tamper check: flipping a byte in the ciphertext must fail to decrypt ---
		bool tamperRejected = false;
		try {
			auto tampered = ct1;
			// MLSMessage's actual ciphertext lives inside a private/variant payload;
			// the easiest robust tamper is re-marshalling + flipping a wire byte.
			auto wire = tls::marshal(tampered);
			wire.at(wire.size() / 2) ^= 0xFF;
			auto reparsed = tls::get<MLSMessage>(wire);
			bobState.unprotect(reparsed);
		} catch (const std::exception &) {
			tamperRejected = true;
		}
		check("Tampered application message rejected", tamperRejected);

	} catch (const std::exception &e) {
		printf("EXCEPTION: %s\n", e.what());
		failures++;
	}

	if (failures == 0) {
		printf("\nALL MLS GROUP LIFECYCLE CHECKS PASSED\n");
		return 0;
	}
	printf("\n%d CHECK(S) FAILED\n", failures);
	return 1;
}
