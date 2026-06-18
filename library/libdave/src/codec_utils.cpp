#include "codec_utils.h"

#include "common.h"

// VP8/VP9/H264/H265/AV1 frame-splitting helpers removed: TriCord is audio-only
// (3DS has no video call support), see dave_interfaces.h's Codec enum trim and
// codec_utils.h. ValidateEncryptedFrame's H264/H265 start-code-collision check
// is now unreachable for the only codec left, so it's collapsed to a no-op
// rather than kept dead.

namespace discord {
namespace dave {
namespace codec_utils {

bool ProcessFrameOpus(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    processor.AddEncryptedBytes(frame.data(), frame.size());
    return true;
}

bool ValidateEncryptedFrame([[maybe_unused]] OutboundFrameProcessor& processor,
                            [[maybe_unused]] ArrayView<uint8_t> frame)
{
    return true;
}

} // namespace codec_utils
} // namespace dave
} // namespace discord
