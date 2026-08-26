#include "playbackpolicy.hxx"

#include <iostream>

int main() {
    using QConnect::positionNeedsExactLength;

    if (positionNeedsExactLength(true, 0)) {
        std::cerr << "seek-to-start unnecessarily needs the exact length\n";
        return 1;
    }
    if (!positionNeedsExactLength(true, 1)) {
        std::cerr << "non-zero seek bypassed exact-length preparation\n";
        return 1;
    }
    if (positionNeedsExactLength(false, 1234)) {
        std::cerr << "absent position needs the exact length\n";
        return 1;
    }
    return 0;
}
