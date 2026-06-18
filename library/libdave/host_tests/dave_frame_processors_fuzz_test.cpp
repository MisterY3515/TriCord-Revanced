// Phase 3 validation: fuzz/property test for frame_processors.cpp's
// unencrypted-range parsing and validation -- the TOB-DISCE2EC-7 mitigation
// (rejecting frames whose declared "unencrypted ranges" metadata could be used
// to smuggle ciphertext as if it were authenticated plaintext, or vice versa).
// This logic is unchanged from upstream (see frame_processors.cpp's top
// comment for what WAS trimmed -- only the Opus-only codec dispatch, not this).
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <random>
#include <vector>

#include <dave/array_view.h>

#include "frame_processors.h"

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

// Round-trips a valid Ranges list through Serialize/Deserialize and confirms
// it comes back unchanged.
bool RoundTripOk(const Ranges& ranges)
{
    auto size = UnencryptedRangesSize(ranges);
    std::vector<uint8_t> buffer(size);
    auto written = SerializeUnencryptedRanges(ranges, buffer.data(), buffer.size());
    if (written != size) {
        return false;
    }

    Ranges parsed;
    const uint8_t* readAt = buffer.data();
    DeserializeUnencryptedRanges(readAt, size, parsed);
    if (readAt == nullptr) {
        return false;
    }

    return parsed.size() == ranges.size() &&
      std::equal(parsed.begin(), parsed.end(), ranges.begin(), [](const Range& a, const Range& b) {
          return a.offset == b.offset && a.size == b.size;
      });
}

} // namespace

int main()
{
    constexpr auto kSizeMax = std::numeric_limits<size_t>::max();

    // -- Hand-picked malformed/edge-case range lists --
    check("Empty ranges accepted", ValidateUnencryptedRanges({}, 100));
    check("Single in-bounds range accepted", ValidateUnencryptedRanges({{0, 10}}, 100));
    check("Range exactly covering the frame accepted", ValidateUnencryptedRanges({{0, 100}}, 100));
    check("Range past end of frame rejected", !ValidateUnencryptedRanges({{90, 20}}, 100));
    check("Overflowing offset+size rejected", !ValidateUnencryptedRanges({{kSizeMax - 1, 10}}, 100));
    check("Overlapping ranges rejected", !ValidateUnencryptedRanges({{0, 10}, {5, 10}}, 100));
    check("Out-of-order ranges rejected", !ValidateUnencryptedRanges({{10, 5}, {0, 5}}, 100));
    check("Adjacent non-overlapping ranges accepted",
          ValidateUnencryptedRanges({{0, 10}, {10, 10}}, 100));

    // -- Round trip correctness for valid range lists --
    check("Round trip: single range", RoundTripOk({{3, 5}}));
    check("Round trip: many small ranges", RoundTripOk({{0, 1}, {1, 1}, {2, 1}, {3, 1}}));
    check("Round trip: large offsets/sizes (multi-byte leb128)",
          RoundTripOk({{1000000, 2000000}}));

    // -- ParseFrame must never crash on malformed/random input --
    std::mt19937 rng(0xD15C0D);
    for (int trial = 0; trial < 20000; ++trial) {
        auto size = rng() % 64;
        std::vector<uint8_t> garbage(size);
        for (auto& b : garbage) {
            b = static_cast<uint8_t>(rng());
        }

        InboundFrameProcessor processor;
        processor.ParseFrame(MakeArrayView<const uint8_t>(garbage.data(), garbage.size()));
        (void)processor.IsEncrypted();
    }
    check("ParseFrame survives 20000 random malformed frames (no crash/UB)", true);

    // -- Frames specifically crafted to probe the boundary-check arithmetic --
    {
        std::vector<uint8_t> tooShort = {0x01, 0x02, 0x03};
        InboundFrameProcessor processor;
        processor.ParseFrame(MakeArrayView<const uint8_t>(tooShort.data(), tooShort.size()));
        check("Frame shorter than minimum supplemental bytes rejected", !processor.IsEncrypted());
    }
    {
        std::vector<uint8_t> noMarker(11, 0x00);
        InboundFrameProcessor processor;
        processor.ParseFrame(MakeArrayView<const uint8_t>(noMarker.data(), noMarker.size()));
        check("Frame without magic marker rejected", !processor.IsEncrypted());
    }

    printf("\n%s\n", gFailures == 0 ? "ALL FRAME PROCESSOR FUZZ CHECKS PASSED" : "SOME CHECKS FAILED");
    return gFailures == 0 ? 0 : 1;
}
