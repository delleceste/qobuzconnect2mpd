#include "segstream.hxx"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

std::ofstream g_qc_log_file;
std::mutex g_qc_log_mutex;
int g_qc_log_level = 0;

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

// The web panel's feedback line is only as good as this snapshot: it must name
// the track being reconstructed and how far along it is, while the work is
// still in flight.
bool testDownloadProgressSnapshot() {
    using namespace QConnect;
    auto plan = makeImmediatePlan(4242, "fLaC");
    plan->url_template = "invalid-scheme://segment/$SEGMENT$";
    plan->segment_byte_lens = {1, 1, 1};

    auto handle = acquireSegmentedTrackDownload(plan);
    CHECK(handle != nullptr);

    // The fetch fails and is retried with a backoff, so the job stays in the
    // scheduler long enough to be observed.
    bool seen = false;
    for (int i = 0; i < 200 && !seen; ++i) {
        for (const auto& p : segmentedDownloadProgress()) {
            if (p.track_id != 4242) continue;
            CHECK(p.segments_total == 3);
            CHECK(p.segments_done <= p.segments_total);
            CHECK(p.isPlayback());
            seen = true;
            break;
        }
        if (!seen)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(seen);

    clearSegmentedDownloadFailure();
    CHECK(!segmentedLastDownloadFailure().valid());

    uint64_t ignored = 0;
    std::string error;
    CHECK(!waitForSegmentedTrack(handle, ignored, 4000, &error));
    releaseSegmentedTrackDownload(handle);
    cancelSegmentedTrackDownload(plan);

    // A finished (here: failed) job is no longer owed work, so it drops out of
    // the snapshot and the panel stops claiming something is downloading.
    for (const auto& p : segmentedDownloadProgress())
        CHECK(p.track_id != 4242);

    // The failure itself must outlive the job, or a once-a-second status
    // reader would never see why the music stopped coming.
    const auto failure = segmentedLastDownloadFailure();
    CHECK(failure.valid());
    CHECK(failure.error.find("segment") != std::string::npos);
    CHECK(failure.ageSeconds() >= 0);
    clearSegmentedDownloadFailure();
    CHECK(!segmentedLastDownloadFailure().valid());
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

bool testVisibleCacheLifecycle() {
    using namespace QConnect;
    SegmentedTrackRegistry registry;
    auto plan = makeImmediatePlan(301, "fLaC-visible-cache");
    const auto token = SegmentedTrackRegistry::tokenForTrack(301, 6);
    registry.registerPlan(token, plan);

    auto handle = acquireSegmentedTrackDownload(plan);
    CHECK(handle != nullptr);
    uint64_t size = 0;
    CHECK(waitForSegmentedTrack(handle, size, 2000));
    CHECK(size == 18);

    const std::string path = registry.cachePath(token);
    CHECK(path.rfind(segmentedCacheDirectory() + "/track_301_6_", 0)
          == 0);
    CHECK(path.size() >= 5 && path.substr(path.size() - 5) == ".flac");
    CHECK(std::filesystem::is_regular_file(path));
    std::ifstream cache(path, std::ios::binary);
    const std::string cached_bytes{
        std::istreambuf_iterator<char>(cache),
        std::istreambuf_iterator<char>()};
    CHECK(cached_bytes == "fLaC-visible-cache");
    const auto permissions = std::filesystem::status(path).permissions();
    using perms = std::filesystem::perms;
    CHECK((permissions & (perms::group_all | perms::others_all)) == perms::none);
    const auto directory_permissions =
        std::filesystem::status(segmentedCacheDirectory()).permissions();
    CHECK((directory_permissions & (perms::group_all | perms::others_all)) ==
          perms::none);

    releaseSegmentedTrackDownload(handle);
    registry.clear();
    handle.reset();
    plan.reset();
    CHECK(!std::filesystem::exists(path));
    return true;
}

} // namespace

int main() {
    if (!testGrowingCacheRead() ||
        !testRetryableFailure() ||
        !testDownloadProgressSnapshot() ||
        !testCompletedCacheLru() ||
        !testRegistryRetention() ||
        !testVisibleCacheLifecycle())
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
