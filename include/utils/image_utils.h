#pragma once
#include "core/config.h"
#include <citro3d.h>
#include <cstdio>

namespace Utils {
namespace Image {

struct TiledData {
	u32 *pixels = nullptr;
	int w = 0, h = 0;
	int p2w = 0, p2h = 0;
	size_t vramSize = 0;
};

// Message media is drawn at most ~330px wide on the 240p screens, so 256 is
// the largest power-of-two that stays sharp while capping the biggest texture
// at 256KB of linear heap (512 would be 1MB each). Old 3DS decodes 4x slower,
// so halve the cap there to cut resize work and linear-heap pressure.
inline int maxRemoteDim() { return isNew3DS() ? 256 : 128; }

TiledData decodeToTiled(const unsigned char *data, size_t size, int maxWidth = maxRemoteDim(),
                        int maxHeight = maxRemoteDim(), bool noResize = false, float cornerRatio = 0.0f);

C3D_Tex *loadTextureFromMemory(const unsigned char *data, size_t size, int &outW, int &outH, bool noResize = false);

C3D_Tex *loadTextureFromMemory(const unsigned char *data, size_t size);

bool saveJPG(const char *path, const u16 *rgb565, int width, int height);

} // namespace Image
} // namespace Utils
