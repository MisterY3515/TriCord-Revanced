#pragma once

#include <dave/array_view.h>

#include "common.h"
#include "frame_processors.h"

// VP8/VP9/H264/H265/AV1 frame-splitting helpers removed: TriCord is audio-only
// (3DS has no video call support), see dave_interfaces.h's Codec enum trim.
namespace discord {
namespace dave {
namespace codec_utils {

bool ProcessFrameOpus(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame);

bool ValidateEncryptedFrame(OutboundFrameProcessor& processor, ArrayView<uint8_t> frame);

} // namespace codec_utils
} // namespace dave
} // namespace discord
