#include "playbackpolicy.hxx"

#include <iostream>

int main() {
    using QConnect::positionNeedsExactLength;
    using QConnect::SEEK_FROM_START_TOLERANCE_MS;

    if (positionNeedsExactLength(true, 0)) {
        std::cerr << "seek-to-start unnecessarily needs the exact length\n";
        return 1;
    }
    if (positionNeedsExactLength(true, SEEK_FROM_START_TOLERANCE_MS)) {
        std::cerr << "near-start seek unnecessarily needs exact length\n";
        return 1;
    }
    if (!positionNeedsExactLength(true, SEEK_FROM_START_TOLERANCE_MS + 1)) {
        std::cerr << "real seek bypassed exact-length preparation\n";
        return 1;
    }
    if (positionNeedsExactLength(false, 1234)) {
        std::cerr << "absent position needs the exact length\n";
        return 1;
    }
    return 0;
}
