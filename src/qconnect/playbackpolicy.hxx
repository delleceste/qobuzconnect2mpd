#pragma once

#include <cstdint>

namespace QConnect {

// Controller state can arrive a little after a replace-and-play command, so a
// logical start is often reported as a small non-zero interpolated position.
// Reopening at the beginning avoids a full-track download and a fragile HTTP
// decoder seek for an inaudible difference.
constexpr uint32_t SEEK_FROM_START_TOLERANCE_MS = 3000;

inline bool positionNeedsExactLength(bool has_position,
                                     uint32_t position_ms) {
    return has_position && position_ms > SEEK_FROM_START_TOLERANCE_MS;
}

} // namespace QConnect
