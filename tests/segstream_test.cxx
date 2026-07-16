#include "segstream.hxx"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

bool check(bool condition, const char* expression, int line) {
    if (condition) return true;
    std::cerr << "segstream test failed at line " << line << ": "
              << expression << '\n';
    return false;
}

#define CHECK(expr) do { if (!check((expr), #expr, __LINE__)) return false; } while (0)

std::shared_ptr<QConnect::SegmentedTrackPlan>
makeImmediatePlan(uint32_t track_id, const std::string& bytes) {
    auto plan = std::make_shared<QConnect::SegmentedTrackPlan>();
    plan->track_id = track_id;
    plan->format_id = 6;
    plan->flac_header.assign(bytes.begin(), bytes.end());
    plan->total_bytes = bytes.size();
    return plan;
}

bool testGrowingCacheRead() {
    using namespace QConnect;
    auto plan = makeImmediatePlan(1, "fLaC-test-data");
    auto handle = acquireSegmentedTrackDownload(plan);
    CHECK(handle != nullptr);

    uint64_t exact_size = 0;
    std::string error;
    CHECK(waitForSegmentedTrack(handle, exact_size, 2000, &error));
    CHECK(exact_size == 14);
    CHECK(segmentedTrackExactSize(handle, exact_size));

    std::vector<uint8_t> bytes(exact_size);
    size_t first = 0;
    CHECK(readSegmentedTrack(handle, 0, bytes.data(), 4, first, 100, &error) == 1);
    CHECK(first == 4);
    size_t rest = 0;
    CHECK(readSegmentedTrack(handle, first, bytes.data() + first,
                             bytes.size() - first, rest, 100, &error) == 1);
    CHECK(first + rest == bytes.size());
    CHECK(std::string(bytes.begin(), bytes.end()) == "fLaC-test-data");
    size_t eof = 99;
    CHECK(readSegmentedTrack(handle, exact_size, bytes.data(), 1,
                             eof, 100, &error) == 0);
    CHECK(eof == 0);

    releaseSegmentedTrackDownload(handle);
    cancelSegmentedTrackDownload(plan);
    return true;
}

bool testRetryableFailure() {
    using namespace QConnect;
    auto plan = makeImmediatePlan(2, "fLaC");
    plan->url_template = "invalid-scheme://segment/$SEGMENT$";
    plan->segment_byte_lens = {1};

    auto first = acquireSegmentedTrackDownload(plan);
    CHECK(first != nullptr);
    uint64_t ignored = 0;
    std::string error;
    CHECK(!waitForSegmentedTrack(first, ignored, 4000, &error));
    CHECK(segmentedTrackFailed(first, &error));
    releaseSegmentedTrackDownload(first);

    auto second = acquireSegmentedTrackDownload(plan);
    CHECK(second != nullptr);
    CHECK(second != first);
    cancelSegmentedTrackDownload(plan);
    CHECK(!waitForSegmentedTrack(second, ignored, 100, &error));
    CHECK(segmentedTrackFailed(second, &error));
    releaseSegmentedTrackDownload(second);
    return true;
}

bool testCompletedCacheLru() {
    using namespace QConnect;
    std::vector<std::shared_ptr<SegmentedTrackPlan>> plans;
    std::vector<SegmentedDownloadHandle> handles;
    for (uint32_t i = 0; i < 9; ++i) {
        auto plan = makeImmediatePlan(100 + i, "fLaC-cache");
        auto handle = acquireSegmentedTrackDownload(plan);
        CHECK(handle != nullptr);
        uint64_t size = 0;
        CHECK(waitForSegmentedTrack(handle, size, 2000));
        CHECK(size == 10);
        releaseSegmentedTrackDownload(handle);
        plans.push_back(std::move(plan));
        handles.push_back(std::move(handle));
    }

    // Completing the ninth unpinned track evicts the least-recently-used
    // cache. Acquiring the first plan therefore creates a new state.
    auto restarted = acquireSegmentedTrackDownload(plans.front());
    CHECK(restarted != nullptr);
    CHECK(restarted != handles.front());
    uint64_t size = 0;
    CHECK(waitForSegmentedTrack(restarted, size, 2000));
    releaseSegmentedTrackDownload(restarted);

    for (const auto& plan : plans) cancelSegmentedTrackDownload(plan);
    return true;
}

bool testRegistryRetention() {
    using namespace QConnect;
    SegmentedTrackRegistry registry;
    auto first = makeImmediatePlan(201, "fLaC-one");
    auto second = makeImmediatePlan(202, "fLaC-two");
    const auto first_token = SegmentedTrackRegistry::tokenForTrack(201, 6);
    const auto second_token = SegmentedTrackRegistry::tokenForTrack(202, 6);
    registry.registerPlan(first_token, first);
    registry.registerPlan(second_token, second);
    CHECK(registry.size() == 2);

    registry.prioritize(second_token);
    registry.retainOnly(std::unordered_set<std::string>{second_token});
    CHECK(registry.size() == 1);
    CHECK(registry.get(first_token) == nullptr);
    CHECK(registry.get(second_token) == second);
    registry.clear();
    CHECK(registry.size() == 0);
    return true;
}

} // namespace

int main() {
    if (!testGrowingCacheRead() ||
        !testRetryableFailure() ||
        !testCompletedCacheLru() ||
        !testRegistryRetention())
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
