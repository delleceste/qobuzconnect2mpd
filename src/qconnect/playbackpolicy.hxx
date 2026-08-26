#pragma once

#include <cstdint>

namespace QConnect {

// Starting at byte/time zero does not need the final stream length.  MPD can
// select the queue item again and reopen it from its beginning; only non-zero
// positions need the complete segmented stream and exact Content-Length.
inline bool positionNeedsExactLength(bool has_position,
                                     uint32_t position_ms) {
    return has_position && position_ms != 0;
}

} // namespace QConnect
