#include "segstream.hxx"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
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

// Build a minimal Qobuz CMAF segment: [styp][uuid(QBZ)][mdat].  Only the box
// headers and the uuid box's data-offset field matter for sizing.
std::vector<uint8_t> makeSyntheticSegment(size_t payload_bytes,
                                          size_t uuid_box_bytes = 64) {
    static const uint8_t QBZ_SEG_UUID[16] = {
        0x3b,0x42,0x12,0x92,0x56,0xf3,0x5f,0x75,
        0x92,0x36,0x63,0xb6,0x9a,0x1f,0x52,0xb2
    };
    auto put32 = [](std::vector<uint8_t>& v, size_t at, uint32_t x) {
        v[at]     = static_cast<uint8_t>(x >> 24);
        v[at + 1] = static_cast<uint8_t>(x >> 16);
        v[at + 2] = static_cast<uint8_t>(x >> 8);
        v[at + 3] = static_cast<uint8_t>(x);
    };
    const size_t styp_bytes = 16;
    const size_t uuid_pos = styp_bytes;
    const size_t mdat_pos = uuid_pos + uuid_box_bytes;
    const size_t mdat_bytes = 8 + payload_bytes;
    std::vector<uint8_t> seg(mdat_pos + mdat_bytes, 0);

    put32(seg, 0, static_cast<uint32_t>(styp_bytes));
    std::memcpy(&seg[4], "styp", 4);

    put32(seg, uuid_pos, static_cast<uint32_t>(uuid_box_bytes));
    std::memcpy(&seg[uuid_pos + 4], "uuid", 4);
    std::memcpy(&seg[uuid_pos + 8], QBZ_SEG_UUID, 16);
    // data_offset = uuid_pos + data_off_raw, and must land on the mdat payload
    const uint32_t data_off_raw =
        static_cast<uint32_t>((mdat_pos + 8) - uuid_pos);
    put32(seg, uuid_pos + 24 + 4, data_off_raw);

    put32(seg, mdat_pos, static_cast<uint32_t>(mdat_bytes));
    std::memcpy(&seg[mdat_pos + 4], "mdat", 4);
    return seg;
}

// The exact reconstructed length of a segment must be derivable from a short
// prefix, without the payload — this is what lets the proxy publish a real
// Content-Length before any audio is downloaded.
bool testGeometryFromPrefix() {
    using namespace QConnect;
    const size_t payload = 7359129;
    const auto seg = makeSyntheticSegment(payload);

    uint64_t len = 0;
    CHECK(segmentGeometryFromPrefix(seg.data(), seg.size(), seg.size(), len));
    CHECK(len == payload);

    // A prefix that stops just past the mdat header is enough.
    const size_t prefix = 16 + 64 + 8;
    len = 0;
    CHECK(segmentGeometryFromPrefix(seg.data(), prefix, seg.size(), len));
    CHECK(len == payload);

    // A prefix that stops before the mdat header is not, and must say so
    // rather than guess.
    CHECK(!segmentGeometryFromPrefix(seg.data(), 16 + 8, seg.size(), len));

    // A uuid box larger than the prefix must also fail closed.
    const auto wide = makeSyntheticSegment(payload, 4096);
    CHECK(!segmentGeometryFromPrefix(wide.data(), 512, wide.size(), len));
    CHECK(segmentGeometryFromPrefix(wide.data(), 16 + 4096 + 8, wide.size(), len));
    CHECK(len == payload);
    return true;
}

// Offset -> segment mapping is what turns a seek into a single segment fetch.
bool testSegmentForOffset() {
    using namespace QConnect;
    SegmentedTrackPlan plan;
    plan.flac_header.assign(496, 0);
    plan.exact_segment_lens = {100, 200, 300};
    plan.exact_segment_offsets = {496, 596, 796, 1096};
    plan.exact_total_bytes = 1096;
    CHECK(plan.hasExactGeometry());

    CHECK(plan.segmentForOffset(0) == 1);      // inside the FLAC header
    CHECK(plan.segmentForOffset(495) == 1);
    CHECK(plan.segmentForOffset(496) == 1);    // first byte of segment 1
    CHECK(plan.segmentForOffset(595) == 1);
    CHECK(plan.segmentForOffset(596) == 2);    // boundary
    CHECK(plan.segmentForOffset(795) == 2);
    CHECK(plan.segmentForOffset(796) == 3);
    CHECK(plan.segmentForOffset(1095) == 3);
    CHECK(plan.segmentForOffset(1096) == 0);   // EOF
    CHECK(plan.segmentForOffset(999999) == 0);

    SegmentedTrackPlan bare;
    CHECK(!bare.hasExactGeometry());
    CHECK(bare.segmentForOffset(0) == 0);
    return true;
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
    if (!testGeometryFromPrefix() ||
        !testSegmentForOffset() ||
        !testGrowingCacheRead() ||
        !testRetryableFailure() ||
        !testCompletedCacheLru() ||
        !testRegistryRetention() ||
        !testVisibleCacheLifecycle())
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
