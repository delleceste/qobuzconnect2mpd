// The activity ring the omdrcctrl panel narrates the pre-playback gap from.
// What matters here is that progress rewrites its own entry instead of pushing
// one per segment: a 52-segment track must not flush the phases that came
// before it out of a three-line view.

#include "qcactivity.hxx"

#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

using namespace QConnect;

void testPhaseAndNote() {
    activityPhase(ActivityPhase::QueueReceived, "queue received: 14 tracks");
    auto snap = activitySnapshot();
    check(snap.state == "NEW PLAYLIST RECEIVED", "phase label");
    check(snap.events.size() == 1, "one entry after the first phase");
    check(endsWith(snap.events.back(), "queue received: 14 tracks"), "entry text");
    check(snap.events.back().size() > 9 && snap.events.back()[2] == ':',
          "entries are timestamped");

    activityNote("waiting for MusicPD");
    snap = activitySnapshot();
    check(snap.state == "NEW PLAYLIST RECEIVED", "a note leaves the phase alone");
    check(snap.events.size() == 2, "a note pushes an entry");
}

void testProgressRewritesOneEntry() {
    const std::size_t before = activitySnapshot().events.size();
    for (std::size_t segment = 1; segment <= 52; ++segment)
        activityProgress(ActivityPhase::Downloading, "track-1", "segment",
                         segment, 52);
    auto snap = activitySnapshot();
    check(snap.state == "LOADING SEGMENT", "progress sets the phase");
    check(snap.events.size() == before + 1,
          "52 segments must occupy a single ring entry");
    check(endsWith(snap.events.back(), "segment 52/52 (100%)"),
          "the entry shows the latest count");

    // A different track is a different run: that one does push an entry.
    activityProgress(ActivityPhase::Downloading, "track-2", "segment", 1, 40);
    check(activitySnapshot().events.size() == before + 2, "new run pushes");
}

void testRingDepth() {
    for (std::size_t i = 0; i < kActivityRingDepth + 4; ++i)
        activityNote("entry " + std::to_string(i));
    auto snap = activitySnapshot();
    check(snap.events.size() == kActivityRingDepth, "ring is bounded");
    check(endsWith(snap.events.back(),
                   "entry " + std::to_string(kActivityRingDepth + 3)),
          "newest entry is last");
}

void testIdleKeepsTheRecord() {
    activityIdle();
    auto snap = activitySnapshot();
    check(snap.state.empty(), "idle has no label");
    check(!snap.events.empty(),
          "the ring survives: it is the record of how long the wait was");
    // A progress call after idle starts a new entry rather than rewriting the
    // one the interrupted run left behind (the ring is saturated by now, so
    // count the entries that are not progress lines instead of the total).
    activityNote("something else happened");
    activityProgress(ActivityPhase::Downloading, "track-2", "segment", 2, 40);
    snap = activitySnapshot();
    check(endsWith(snap.events.back(), "segment 2/40 (5%)"), "newest is progress");
    check(endsWith(snap.events[snap.events.size() - 2], "something else happened"),
          "an interrupted run is not rewritten in place");
}

} // namespace

int main() {
    try {
        testPhaseAndNote();
        testProgressRewritesOneEntry();
        testRingDepth();
        testIdleKeepsTheRecord();
    } catch (const std::exception& e) {
        std::cerr << "qconnect activity test failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "qconnect activity test OK\n";
    return 0;
}
