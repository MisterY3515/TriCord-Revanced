// Phase 6 hardening: a *real* wall-clock test of Decryptor's epoch-transition
// grace window (TOB-DISCE2EC-5 mitigation). dave_session_lifecycle_test.cpp
// already proves an in-flight old-epoch frame still decrypts milliseconds
// after a transition; it never proves the window actually closes. This test
// uses a short (1s) real expiry passed to TransitionToKeyRatchet() and a real
// std::this_thread::sleep_for() past it, exercising the actual
// std::chrono::steady_clock-backed Clock in decryptor.h/cryptor_manager.h --
// no fake/injected clock, no modification to the vendored Decryptor/
// CryptorManager code.
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <bytes/bytes.h>
#include <dave/array_view.h>
#include <dave/dave_interfaces.h>
#include <mls/crypto.h>

#include "mls_key_ratchet.h"

using namespace discord::dave;

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

// Encryptor-side/decryptor-side ratchet pair for one simulated "epoch":
// MlsKeyRatchet wraps an mlspp::HashRatchet seeded from the same base secret,
// the same relationship two real MLS members' ratchets have via the shared
// epoch exporter_secret.
std::pair<std::unique_ptr<IKeyRatchet>, std::unique_ptr<IKeyRatchet>> MakeRatchetPair(uint8_t seedByte)
{
    auto suite = Suite();
    ::mlspp::bytes_ns::bytes baseSecret(suite.secret_size(), seedByte);
    return {std::make_unique<MlsKeyRatchet>(suite, baseSecret),
            std::make_unique<MlsKeyRatchet>(suite, baseSecret)};
}

std::vector<uint8_t> Encrypt(IEncryptor& encryptor, uint32_t ssrc, const std::vector<uint8_t>& frame)
{
    std::vector<uint8_t> encrypted(frame.size() + 256);
    size_t encryptedSize = 0;
    auto result = encryptor.Encrypt(MediaType::Audio,
                                    ssrc,
                                    MakeArrayView<const uint8_t>(frame.data(), frame.size()),
                                    MakeArrayView<uint8_t>(encrypted.data(), encrypted.size()),
                                    &encryptedSize);
    if (result != IEncryptor::Success) {
        return {};
    }
    encrypted.resize(encryptedSize);
    return encrypted;
}

IDecryptor::ResultCode Decrypt(IDecryptor& decryptor,
                               const std::vector<uint8_t>& encrypted,
                               std::vector<uint8_t>& out)
{
    out.resize(encrypted.size());
    size_t decryptedSize = 0;
    auto result = decryptor.Decrypt(MediaType::Audio,
                                    MakeArrayView<const uint8_t>(encrypted.data(), encrypted.size()),
                                    MakeArrayView<uint8_t>(out.data(), out.size()),
                                    &decryptedSize);
    out.resize(decryptedSize);
    return result;
}

} // namespace

int main()
{
    constexpr uint32_t kSsrc = 555;
    constexpr auto kShortGrace = std::chrono::seconds(1);

    auto [epochAEncRatchet, epochADecRatchet] = MakeRatchetPair(0xA1);
    auto [epochBEncRatchet, epochBDecRatchet] = MakeRatchetPair(0xB2);

    auto encryptor = CreateEncryptor();
    encryptor->AssignSsrcToCodec(kSsrc, Codec::Opus);
    encryptor->SetKeyRatchet(std::move(epochAEncRatchet));

    auto decryptor = CreateDecryptor();
    decryptor->TransitionToKeyRatchet(std::move(epochADecRatchet));

    // Sanity check before any transition exists.
    const std::vector<uint8_t> frame1 = {0x01, 0x02, 0x03, 0x04};
    auto encrypted1 = Encrypt(*encryptor, kSsrc, frame1);
    check("Epoch A frame encrypted", !encrypted1.empty());
    std::vector<uint8_t> decrypted1;
    auto result1 = Decrypt(*decryptor, encrypted1, decrypted1);
    check("Epoch A frame decrypts before any transition",
          result1 == IDecryptor::Success && decrypted1 == frame1);

    // Two epoch-A frames "in flight" before the transition happens: one to
    // prove the grace window honors it right away, one held back to prove the
    // SAME window correctly stops honoring it once real wall-clock time moves
    // past the expiry.
    const std::vector<uint8_t> inFlightEarly = {0x05, 0x06, 0x07, 0x08};
    const std::vector<uint8_t> inFlightLate = {0x09, 0x0A, 0x0B, 0x0C};
    auto inFlightEarlyEncrypted = Encrypt(*encryptor, kSsrc, inFlightEarly);
    auto inFlightLateEncrypted = Encrypt(*encryptor, kSsrc, inFlightLate);
    check("Both in-flight epoch A frames encrypted",
          !inFlightEarlyEncrypted.empty() && !inFlightLateEncrypted.empty());

    // Transition to epoch B with a short (1s) real grace period -- short
    // enough to actually sleep past in a test, long enough not to race
    // against the few milliseconds the test itself takes to run.
    encryptor->SetKeyRatchet(std::move(epochBEncRatchet));
    decryptor->TransitionToKeyRatchet(std::move(epochBDecRatchet), kShortGrace);

    std::vector<uint8_t> inFlightEarlyDecrypted;
    auto earlyResult = Decrypt(*decryptor, inFlightEarlyEncrypted, inFlightEarlyDecrypted);
    check("In-flight epoch A frame decrypts immediately after transition",
          earlyResult == IDecryptor::Success && inFlightEarlyDecrypted == inFlightEarly);

    const std::vector<uint8_t> epochBFrame = {0x10, 0x11, 0x12, 0x13};
    auto epochBEncrypted = Encrypt(*encryptor, kSsrc, epochBFrame);
    std::vector<uint8_t> epochBDecrypted;
    auto epochBResult = Decrypt(*decryptor, epochBEncrypted, epochBDecrypted);
    check("Epoch B frame decrypts during the grace window",
          epochBResult == IDecryptor::Success && epochBDecrypted == epochBFrame);

    printf("Sleeping past the %lld-second grace window (real wall-clock wait)...\n",
           static_cast<long long>(kShortGrace.count()));
    std::this_thread::sleep_for(kShortGrace + std::chrono::milliseconds(300));

    std::vector<uint8_t> inFlightLateDecrypted;
    auto lateResult = Decrypt(*decryptor, inFlightLateEncrypted, inFlightLateDecrypted);
    check("Epoch A frame is rejected once the grace window has really elapsed",
          lateResult != IDecryptor::Success);

    const std::vector<uint8_t> epochBFrame2 = {0x14, 0x15, 0x16, 0x17};
    auto epochBEncrypted2 = Encrypt(*encryptor, kSsrc, epochBFrame2);
    std::vector<uint8_t> epochBDecrypted2;
    auto epochBResult2 = Decrypt(*decryptor, epochBEncrypted2, epochBDecrypted2);
    check("Epoch B frame still decrypts fine after epoch A's expiry",
          epochBResult2 == IDecryptor::Success && epochBDecrypted2 == epochBFrame2);

    printf("\n%s\n", gFailures == 0 ? "ALL EPOCH EXPIRY CHECKS PASSED" : "SOME CHECKS FAILED");
    return gFailures == 0 ? 0 : 1;
}
