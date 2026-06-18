// Phase 3 validation: a full DAVE-level (libdave protocol-glue + mlspp core)
// 2-party voice-channel lifecycle, simulating the opcodes a real Discord voice
// gateway session drives: join -> commit/welcome -> encrypt/decrypt audio
// frames -> a third member joining triggers an epoch transition -> a frame
// still in flight when the transition happens is still decryptable inside the
// retained-old-key grace window (TOB-DISCE2EC-5 mitigation) -> a tampered
// frame is rejected. Exercises mls::Session (this layer), MlsKeyRatchet,
// Encryptor/Decryptor, Cryptor (mbedTLS AES-128-GCM), and frame_processors --
// i.e. everything Phase 3 vendored on top of the Phase 1/2 mlspp core.
//
// The external-proposal construction below mirrors libdave's own test fixture
// (cpp/test/external_sender.{h,cpp}, not vendored -- it's test-only scaffolding,
// not shipped runtime code), since clients never author these themselves; in
// production they arrive from Discord's voice gateway.
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include <bytes/bytes.h>
#include <dave/dave_interfaces.h>
#include <dave/version.h>
#include <mls/core_types.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <tls/tls_syntax.h>

#include "common.h"
#include "mls/util.h"

using namespace discord::dave;
using namespace discord::dave::mls;

namespace {

int gFailures = 0;

void check(const char* name, bool ok)
{
    printf("%-65s %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) {
        gFailures++;
    }
}

::mlspp::CipherSuite Suite()
{
    return ::mlspp::CipherSuite{::mlspp::CipherSuite::ID::P256_AES128GCM_SHA256_P256};
}

// Stands in for Discord's voice gateway: the one party allowed to author
// Add/Remove proposals (SenderType::external), which clients never do.
class FakeVoiceGateway {
public:
    explicit FakeVoiceGateway(const ::mlspp::bytes_ns::bytes& groupId)
      : groupId_(groupId)
      , signerKey_(::mlspp::SignaturePrivateKey::generate(Suite()))
    {
        externalSender_.signature_key = signerKey_.public_key;
        externalSender_.credential =
          ::mlspp::Credential::basic(::mlspp::bytes_ns::from_ascii("voice-gateway"));
    }

    std::vector<uint8_t> MarshalledExternalSender() const
    {
        return ::mlspp::tls::marshal(externalSender_);
    }

    std::vector<uint8_t> ProposeAdd(uint64_t epoch, const std::vector<uint8_t>& keyPackageBytes) const
    {
        auto keyPackage =
          ::mlspp::tls::get<::mlspp::KeyPackage>(::mlspp::bytes_ns::bytes(keyPackageBytes));
        auto proposal = ::mlspp::Proposal{::mlspp::Add{keyPackage}};
        auto message =
          ::mlspp::external_proposal(Suite(), groupId_, epoch, proposal, /*signer_index=*/0, signerKey_);

        ::mlspp::tls::ostream out;
        out << false; // isRevoke
        out << std::vector<::mlspp::MLSMessage>{message};
        return out.bytes();
    }

private:
    ::mlspp::bytes_ns::bytes groupId_;
    ::mlspp::SignaturePrivateKey signerKey_;
    ::mlspp::ExternalSender externalSender_;
};

// Splits the combined commit+welcome buffer ProcessProposals() returns into
// the separate commit/welcome buffers ProcessCommit()/ProcessWelcome() expect
// -- mirrors what the real voice-gateway opcode glue (Phase 5) will do.
struct CommitWelcomeSplit {
    std::vector<uint8_t> commit;
    std::vector<uint8_t> welcome; // empty if no Welcome was included
};

CommitWelcomeSplit SplitCommitWelcome(const std::vector<uint8_t>& combined)
{
    ::mlspp::tls::istream in(combined);
    ::mlspp::MLSMessage commitMsg;
    in >> commitMsg;

    CommitWelcomeSplit split;
    split.commit = ::mlspp::tls::marshal(commitMsg);
    if (!in.empty()) {
        ::mlspp::Welcome welcomeMsg;
        in >> welcomeMsg;
        split.welcome = ::mlspp::tls::marshal(welcomeMsg);
    }
    return split;
}

std::unique_ptr<ISession> MakeSession(const std::string& name)
{
    // authSessionId MUST be empty: persisted_key_pair_null.cpp makes
    // GetPersistedKeyPair() always return nullptr, and Session::InitLeafNode
    // only falls back to generating a fresh signing key when signingKeyId_
    // (== authSessionId) is empty. A non-empty authSessionId would silently
    // abort leaf-node init (logged, not thrown) -- see Gestione/DAVE_HANDOFF.md.
    return CreateSession(/*context=*/nullptr, /*authSessionId=*/"", [name](auto src, auto reason) {
        printf("[%s MLS failure] %s: %s\n", name.c_str(), src.c_str(), reason.c_str());
    });
}

} // namespace

int main()
{
    constexpr ProtocolVersion kVersion = 1;
    constexpr uint64_t kGroupId = 0xAABBCCDD;
    const auto groupIdBytes = BigEndianBytesFrom(kGroupId);

    FakeVoiceGateway gateway(groupIdBytes);
    auto extSenderBytes = gateway.MarshalledExternalSender();

    std::set<std::string> recognized = {"1001", "1002"};

    // -- Alice creates the group, Bob prepares to join --
    std::shared_ptr<::mlspp::SignaturePrivateKey> aliceKey;
    auto alice = MakeSession("Alice");
    alice->Init(kVersion, kGroupId, "1001", aliceKey);
    alice->SetExternalSender(extSenderBytes);

    std::shared_ptr<::mlspp::SignaturePrivateKey> bobKey;
    auto bob = MakeSession("Bob");
    bob->Init(kVersion, kGroupId, "1002", bobKey);
    bob->SetExternalSender(extSenderBytes);

    auto bobKeyPackageBytes = bob->GetMarshalledKeyPackage();
    check("Bob's key package is non-empty", !bobKeyPackageBytes.empty());

    // -- "Voice gateway" forwards an external Add proposal for Bob to Alice --
    auto addBobWire = gateway.ProposeAdd(/*epoch=*/0, bobKeyPackageBytes);
    auto commitWelcome1 = alice->ProcessProposals(addBobWire, recognized);
    check("Alice produced a commit/welcome for Bob's add", commitWelcome1.has_value());

    auto split1 = SplitCommitWelcome(*commitWelcome1);
    check("Commit/welcome split produced a non-empty welcome", !split1.welcome.empty());

    // -- Every client (including the committer) processes the commit --
    auto aliceRoster1 = GetOptional<RosterMap>(alice->ProcessCommit(split1.commit));
    check("Alice processed her own commit", aliceRoster1.has_value());

    auto bobJoinRoster = bob->ProcessWelcome(split1.welcome, recognized);
    check("Bob joined via welcome", bobJoinRoster.has_value());

    auto aliceAuth1 = alice->GetLastEpochAuthenticator();
    auto bobAuth1 = bob->GetLastEpochAuthenticator();
    check("Alice and Bob agree on the epoch authenticator",
          !aliceAuth1.empty() && aliceAuth1 == bobAuth1);

    // -- Cross-derived media key ratchets must match between both sides --
    auto aliceRatchetForSelf = alice->GetKeyRatchet("1001");
    auto bobRatchetForAlice = bob->GetKeyRatchet("1001");
    check("Alice and Bob's view of Alice's media ratchet matches",
          aliceRatchetForSelf && bobRatchetForAlice &&
            aliceRatchetForSelf->GetKey(0) == bobRatchetForAlice->GetKey(0));

    // -- Alice encrypts an Opus frame, Bob decrypts it --
    auto aliceEncryptor = CreateEncryptor();
    aliceEncryptor->SetKeyRatchet(alice->GetKeyRatchet("1001"));
    aliceEncryptor->AssignSsrcToCodec(/*ssrc=*/111, Codec::Opus);

    auto bobDecryptor = CreateDecryptor();
    bobDecryptor->TransitionToKeyRatchet(bob->GetKeyRatchet("1001"));

    const std::vector<uint8_t> opusFrame = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> encrypted(opusFrame.size() + 256);
    size_t encryptedSize = 0;
    auto encResult = aliceEncryptor->Encrypt(MediaType::Audio,
                                             111,
                                             MakeArrayView<const uint8_t>(opusFrame.data(), opusFrame.size()),
                                             MakeArrayView<uint8_t>(encrypted.data(), encrypted.size()),
                                             &encryptedSize);
    check("Alice encrypted the frame", encResult == IEncryptor::Success);

    std::vector<uint8_t> decrypted(encryptedSize);
    size_t decryptedSize = 0;
    auto decResult =
      bobDecryptor->Decrypt(MediaType::Audio,
                            MakeArrayView<const uint8_t>(encrypted.data(), encryptedSize),
                            MakeArrayView<uint8_t>(decrypted.data(), decrypted.size()),
                            &decryptedSize);
    decrypted.resize(decryptedSize);
    check("Bob decrypted Alice's frame", decResult == IDecryptor::Success && decrypted == opusFrame);

    // -- Tamper detection --
    auto tampered = encrypted;
    tampered[0] ^= 0xFF;
    std::vector<uint8_t> tamperOut(tampered.size());
    size_t tamperOutSize = 0;
    auto tamperResult =
      bobDecryptor->Decrypt(MediaType::Audio,
                            MakeArrayView<const uint8_t>(tampered.data(), encryptedSize),
                            MakeArrayView<uint8_t>(tamperOut.data(), tamperOut.size()),
                            &tamperOutSize);
    check("Tampered frame is rejected", tamperResult != IDecryptor::Success);

    // -- Encrypt one more frame under the OLD epoch but don't deliver it yet:
    //    simulates a frame still in flight on the network when the epoch
    //    transition below happens. --
    const std::vector<uint8_t> inFlightFrame = {0x20, 0x21, 0x22, 0x23};
    std::vector<uint8_t> inFlightEncrypted(inFlightFrame.size() + 256);
    size_t inFlightEncryptedSize = 0;
    aliceEncryptor->Encrypt(MediaType::Audio,
                            111,
                            MakeArrayView<const uint8_t>(inFlightFrame.data(), inFlightFrame.size()),
                            MakeArrayView<uint8_t>(inFlightEncrypted.data(), inFlightEncrypted.size()),
                            &inFlightEncryptedSize);

    // -- Carol joins, bumping the epoch --
    recognized.insert("1003");

    std::shared_ptr<::mlspp::SignaturePrivateKey> carolKey;
    auto carol = MakeSession("Carol");
    carol->Init(kVersion, kGroupId, "1003", carolKey);
    carol->SetExternalSender(extSenderBytes);

    auto carolKeyPackageBytes = carol->GetMarshalledKeyPackage();
    auto addCarolWire = gateway.ProposeAdd(/*epoch=*/1, carolKeyPackageBytes);

    // The voice gateway broadcasts the same proposal to every existing member,
    // not just whichever one ends up committing: each member must locally
    // build its own stateWithProposals_ via ProcessProposals() before it can
    // validate/apply the commit that's ultimately broadcast back (here,
    // Alice's -- Bob's own commitWelcome2-equivalent is simply discarded, as
    // if his commit lost the race against Alice's on the real gateway).
    auto commitWelcome2 = alice->ProcessProposals(addCarolWire, recognized);
    check("Alice produced a commit/welcome for Carol's add", commitWelcome2.has_value());
    bob->ProcessProposals(addCarolWire, recognized);
    auto split2 = SplitCommitWelcome(*commitWelcome2);

    auto aliceRoster2 = GetOptional<RosterMap>(alice->ProcessCommit(split2.commit));
    check("Alice processed the epoch-2 commit", aliceRoster2.has_value());
    auto bobRoster2 = GetOptional<RosterMap>(bob->ProcessCommit(split2.commit));
    check("Bob processed the epoch-2 commit", bobRoster2.has_value());
    auto carolJoinRoster = carol->ProcessWelcome(split2.welcome, recognized);
    check("Carol joined via welcome", carolJoinRoster.has_value());

    auto aliceAuth2 = alice->GetLastEpochAuthenticator();
    check("All three agree on the new epoch authenticator",
          aliceAuth2 != aliceAuth1 && aliceAuth2 == bob->GetLastEpochAuthenticator() &&
            aliceAuth2 == carol->GetLastEpochAuthenticator());

    // -- Epoch transition: Bob's decryptor moves to the new ratchet but keeps
    //    the old one alive for the grace window (default 10s); Alice's
    //    encryptor also rolls over. --
    bobDecryptor->TransitionToKeyRatchet(bob->GetKeyRatchet("1001"));
    aliceEncryptor->SetKeyRatchet(alice->GetKeyRatchet("1001"));

    const std::vector<uint8_t> newEpochFrame = {0x10, 0x11, 0x12, 0x13};
    std::vector<uint8_t> newEncrypted(newEpochFrame.size() + 256);
    size_t newEncryptedSize = 0;
    aliceEncryptor->Encrypt(MediaType::Audio,
                            111,
                            MakeArrayView<const uint8_t>(newEpochFrame.data(), newEpochFrame.size()),
                            MakeArrayView<uint8_t>(newEncrypted.data(), newEncrypted.size()),
                            &newEncryptedSize);

    std::vector<uint8_t> newDecrypted(newEncryptedSize);
    size_t newDecryptedSize = 0;
    auto newEpochResult =
      bobDecryptor->Decrypt(MediaType::Audio,
                            MakeArrayView<const uint8_t>(newEncrypted.data(), newEncryptedSize),
                            MakeArrayView<uint8_t>(newDecrypted.data(), newDecrypted.size()),
                            &newDecryptedSize);
    newDecrypted.resize(newDecryptedSize);
    check("Bob decrypts a new-epoch frame after transition",
          newEpochResult == IDecryptor::Success && newDecrypted == newEpochFrame);

    // -- The in-flight old-epoch frame held back above must still decrypt
    //    within the retained-old-key grace window. --
    std::vector<uint8_t> inFlightDecrypted(inFlightEncryptedSize);
    size_t inFlightDecryptedSize = 0;
    auto inFlightResult = bobDecryptor->Decrypt(
      MediaType::Audio,
      MakeArrayView<const uint8_t>(inFlightEncrypted.data(), inFlightEncryptedSize),
      MakeArrayView<uint8_t>(inFlightDecrypted.data(), inFlightDecrypted.size()),
      &inFlightDecryptedSize);
    inFlightDecrypted.resize(inFlightDecryptedSize);
    check("Bob still decrypts an in-flight old-epoch frame within the grace window",
          inFlightResult == IDecryptor::Success && inFlightDecrypted == inFlightFrame);

    printf("\n%s\n", gFailures == 0 ? "ALL DAVE SESSION LIFECYCLE CHECKS PASSED" : "SOME CHECKS FAILED");
    return gFailures == 0 ? 0 : 1;
}
