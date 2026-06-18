#pragma once

// Renamed from upstream's common.h (content otherwise unchanged): devkitARM puts
// every SOURCES/INCLUDES directory on one flat search path, so "common.h" would
// otherwise collide with library/libdave/src/common.h depending on -I order.
#include <hpke/hpke.h>
#include <namespace.h>

namespace MLS_NAMESPACE::hpke {

bytes
i2osp(uint64_t val, size_t size);

} // namespace MLS_NAMESPACE::hpke
