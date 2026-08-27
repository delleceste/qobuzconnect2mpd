/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "segstream.hxx"
#include "qclog.hxx"
#include "qcactivity.hxx"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <limits>
#include <regex>
#include <thread>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace QConnect {

const std::string& segmentedCacheDirectory() {
    static const std::string path = "/tmp/qobuzconnect2mpd-" +
        std::to_string(static_cast<unsigned long>(::geteuid())) + "/cache";
    return path;
}

struct SegmentedDownloadState {
    ~SegmentedDownloadState() {
        if (fd >= 0) ::close(fd);
        if (!cache_path.empty()) ::unlink(cache_path.c_str());
    }

    std::mutex mutex;
    std::condition_variable changed;
    int fd{-1};
    // Bytes [0, available) are present.  With exact geometry the cache is
    // written out of order, so this is the contiguous watermark from the
    // start, not the number of bytes fetched; segment_present is the real
    // record of what is on disk.
    uint64_t available{0};
    uint64_t exact_size{0};
    // Per-segment presence, sized n_audio_segments when the plan has exact
    // geometry.  Empty for the legacy sequential path.
    std::vector<uint8_t> segment_present;
    size_t segments_done{0};
    // A reader blocked on a byte offset publishes the segment it needs here
    // so the downloader fetches that one next.  0 = no request.
    size_t wanted_segment{0};
    bool header_written{false};
    bool complete{false};
    bool failed{false};
    bool scheduling{true};
    bool scheduled{false};
    std::atomic<bool> cancelled{false};
    std::atomic<size_t> readers{0};
    std::atomic<int> requested_priority{
        static_cast<int>(SegmentedDownloadPriority::Background)};
    size_t next_segment{1};
    std::string error;
    std::string cache_path;
    // Retained so readers can map a byte offset onto the segment that holds
    // it without the caller having to pass the plan back in.  Weak because
    // the plan owns this state: a shared_ptr here would be a cycle.
    std::weak_ptr<SegmentedTrackPlan> plan;
};

namespace {

constexpr int kSegmentMaxAttempts = 3;
constexpr size_t kMaxConcurrentTrackDownloads = 2;
constexpr size_t kMaxAutomaticTrackDownloads = 4;
constexpr size_t kMaxPendingTrackDownloads = 16;
// Completed, unpinned caches are retained within these LRU limits.  The two
// active reconstructions and HTTP-pinned tracks are exempt: imposing a hard
// byte ceiling on them would truncate valid long tracks, and Qobuz's size
// table is not accurate enough to reject them in advance.
constexpr size_t kMaxRetainedCachedTracks = 8;
constexpr uint64_t kMaxRetainedCachedBytes = uint64_t{1024} * 1024 * 1024;
std::atomic<uint64_t> g_cache_sequence{0};

// True while this download is the one playback is blocked on.  Speculative
// prefetch of upcoming tracks runs at a lower priority and stays silent: its
// progress is not what the listener is waiting for.
static bool isForPlayback(const std::shared_ptr<SegmentedDownloadState>& state) {
    return state->requested_priority.load(std::memory_order_relaxed) ==
           static_cast<int>(SegmentedDownloadPriority::Playback);
}

static std::string makeCachePath(const SegmentedTrackPlan& plan) {
    return segmentedCacheDirectory() + "/track_" +
           std::to_string(plan.track_id) + "_" +
           std::to_string(plan.format_id) + "_" +
           std::to_string(static_cast<unsigned long>(::getpid())) + "_" +
           std::to_string(g_cache_sequence.fetch_add(
               1, std::memory_order_relaxed) + 1) + ".flac";
}

static std::string streamFormat(const SegmentedTrackPlan& plan) {
    std::string format = std::to_string(plan.sampling_rate) + "," +
        (plan.bit_depth > 0 ? std::to_string(plan.bit_depth) : "?");
    if (plan.channels > 0) format += "," + std::to_string(plan.channels);
    return format;
}

static int curlProgressCb(void* userdata, curl_off_t, curl_off_t,
                          curl_off_t, curl_off_t) {
    const auto* cancelled = static_cast<const std::atomic<bool>*>(userdata);
    return cancelled && cancelled->load(std::memory_order_relaxed) ? 1 : 0;
}

static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    if (size != 0 && nmemb > std::numeric_limits<size_t>::max() / size)
        return 0;
    const size_t bytes = size * nmemb;
    try {
        s->append(ptr, bytes);
    } catch (...) {
        return 0;
    }
    return bytes;
}

// Captures the Content-Range header value; everything else is ignored.
static size_t curlHeaderCb(char* ptr, size_t size, size_t nmemb,
                           void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    const size_t bytes = size * nmemb;
    static const char kName[] = "content-range:";
    const size_t name_len = sizeof(kName) - 1;
    if (bytes > name_len) {
        bool match = true;
        for (size_t i = 0; i < name_len; ++i) {
            if (std::tolower(static_cast<unsigned char>(ptr[i])) != kName[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            size_t begin = name_len;
            while (begin < bytes && (ptr[begin] == ' ' || ptr[begin] == '\t'))
                ++begin;
            size_t end = bytes;
            while (end > begin && (ptr[end - 1] == '\r' || ptr[end - 1] == '\n'))
                --end;
            try {
                out->assign(ptr + begin, end - begin);
            } catch (...) {
                return 0;
            }
        }
    }
    return bytes;
}

class CurlFetcher {
public:
    CurlFetcher() : m_curl(curl_easy_init()) {}
    ~CurlFetcher() {
        if (m_curl) curl_easy_cleanup(m_curl);
    }

    CurlFetcher(const CurlFetcher&) = delete;
    CurlFetcher& operator=(const CurlFetcher&) = delete;

    // range: nullptr for a whole-object GET, else a byte range such as
    // "0-65535". full_size_out receives the object's total size, parsed from
    // Content-Range on a 206 (or Content-Length on a 200).
    bool fetch(const std::string& url,
               const std::vector<std::string>& headers,
               std::vector<uint8_t>& out,
               std::string* err_out = nullptr,
               const std::atomic<bool>* cancelled = nullptr,
               const char* range = nullptr,
               uint64_t* full_size_out = nullptr) {
        if (!m_curl) {
            if (err_out) *err_out = "curl_easy_init failed";
            return false;
        }

        out.clear();
        std::string buf;
        curl_easy_reset(m_curl); // keeps the easy handle's connection cache
        curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
        curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(m_curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(m_curl, CURLOPT_LOW_SPEED_TIME, 30L);
        curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(m_curl, CURLOPT_TCP_KEEPALIVE, 1L);
        std::string content_range;
        if (range) {
            curl_easy_setopt(m_curl, CURLOPT_RANGE, range);
            curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, curlHeaderCb);
            curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &content_range);
        }
        if (cancelled) {
            curl_easy_setopt(m_curl, CURLOPT_NOPROGRESS, 0L);
            curl_easy_setopt(m_curl, CURLOPT_XFERINFOFUNCTION, curlProgressCb);
            curl_easy_setopt(m_curl, CURLOPT_XFERINFODATA, cancelled);
        }

        struct curl_slist* hdrs = nullptr;
        for (const auto& header : headers) {
            struct curl_slist* next = curl_slist_append(hdrs, header.c_str());
            if (!next) {
                if (hdrs) curl_slist_free_all(hdrs);
                if (err_out) *err_out = "cannot allocate HTTP headers";
                return false;
            }
            hdrs = next;
        }
        if (hdrs) curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, hdrs);

        const CURLcode rc = curl_easy_perform(m_curl);
        long code = 0;
        if (rc == CURLE_OK)
            curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &code);
        if (hdrs) curl_slist_free_all(hdrs);

        if (rc != CURLE_OK) {
            if (err_out) {
                *err_out = cancelled &&
                           cancelled->load(std::memory_order_relaxed)
                    ? "cancelled" : curl_easy_strerror(rc);
            }
            return false;
        }
        if (code != 200 && !(range && code == 206)) {
            if (err_out) {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "HTTP %ld", code);
                *err_out = tmp;
            }
            return false;
        }
        if (full_size_out) {
            *full_size_out = 0;
            // "bytes 0-65535/7366949" -> 7366949
            const size_t slash = content_range.rfind('/');
            if (slash != std::string::npos && slash + 1 < content_range.size()) {
                errno = 0;
                char* end = nullptr;
                const unsigned long long total = std::strtoull(
                    content_range.c_str() + slash + 1, &end, 10);
                if (errno == 0 && end && end != content_range.c_str() + slash + 1)
                    *full_size_out = static_cast<uint64_t>(total);
            }
            if (*full_size_out == 0) {
                curl_off_t len = 0;
                if (curl_easy_getinfo(m_curl,
                                      CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                                      &len) == CURLE_OK && len > 0)
                    *full_size_out = static_cast<uint64_t>(len);
            }
        }
        if (buf.empty()) {
            if (err_out) *err_out = "empty response";
            return false;
        }
        out.assign(buf.begin(), buf.end());
        return true;
    }

private:
    CURL* m_curl{nullptr};
};

static bool base64urlDecodeBytes(const std::string& in, std::vector<uint8_t>& out) {
    if (in.empty()) return false;
    std::string s = in;
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    size_t pad = (4 - s.size() % 4) % 4;
    s.append(pad, '=');
    size_t total_pad = 0;
    for (size_t i = s.size(); i > 0 && s[i - 1] == '='; --i) ++total_pad;
    out.resize(s.size());
    int n = EVP_DecodeBlock(out.data(),
                            reinterpret_cast<const unsigned char*>(s.data()),
                            static_cast<int>(s.size()));
    if (n < 0) return false;
    n -= static_cast<int>(total_pad);
    if (n < 0) return false;
    out.resize(static_cast<size_t>(n));
    return true;
}

static bool hexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned v = 0;
        if (sscanf(hex.c_str() + i, "%02x", &v) != 1) return false;
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

struct CmafFrameEntry {
    uint32_t size{0};
    uint16_t flags{0};
    uint8_t  iv[8]{0};
};

struct CmafSegmentCrypto {
    size_t data_offset{0};
    size_t mdat_end{0};
    std::vector<CmafFrameEntry> entries;
};

struct CmafInitInfo {
    std::vector<uint8_t>  flac_header;
    std::vector<uint32_t> segment_byte_lens;
    int sampling_rate{0};
    int bit_depth{0};
    int channels{0};
};

static size_t readBoxSize(const std::vector<uint8_t>& d, size_t p) {
    if (p + 8 > d.size()) return 0;
    uint32_t s = (uint32_t(d[p]) << 24) | (uint32_t(d[p + 1]) << 16) |
                 (uint32_t(d[p + 2]) << 8) | uint32_t(d[p + 3]);
    if (s == 0) return d.size() - p;
    if (s < 8) return 0;
    return static_cast<size_t>(s);
}

static bool parseInitSegment(const std::vector<uint8_t>& data, CmafInitInfo& out) {
    static const uint8_t QBZ_INIT_UUID[16] = {
        0xc7,0xc7,0x5d,0xf0,0xfd,0xd9,0x51,0xe9,0x8f,0xc2,0x29,0x71,0xe4,0xac,0xf8,0xd2
    };
    size_t pos = 0;
    while (pos + 8 <= data.size()) {
        size_t sz = readBoxSize(data, pos);
        if (sz < 8 || sz > data.size() - pos) return false;
        if (pos + 24 <= data.size() &&
            memcmp(&data[pos + 4], "uuid", 4) == 0 &&
            memcmp(&data[pos + 8], QBZ_INIT_UUID, 16) == 0) {
            const uint8_t* p = data.data() + pos + 24;
            size_t len = sz - 24;
            if (len < 28) return false;
            size_t a = 4 + 4 + 4 + 4 + 1 + 3 + 6;
            if (a + 2 > len) return false;
            uint16_t raw_len = (uint16_t(p[a]) << 8) | uint16_t(p[a + 1]); a += 2;
            if (raw_len > len - a) return false;
            std::vector<uint8_t> raw(p + a, p + a + raw_len); a += raw_len;
            size_t flac_pos = std::string::npos;
            for (size_t i = 0; i + 4 <= raw.size(); ++i) {
                if (memcmp(&raw[i], "fLaC", 4) == 0) { flac_pos = i; break; }
            }
            if (flac_pos == std::string::npos || flac_pos + 42 > raw.size()) return false;
            out.flac_header.assign(raw.begin() + flac_pos, raw.begin() + flac_pos + 42);
            // Set the "last metadata block" flag so MPD treats the STREAMINFO
            // as the final metadata block (no further headers follow).
            out.flac_header[4] |= 0x80;
            // FLAC STREAMINFO packs sample rate (20 bits), channels-1 (3),
            // and bits-per-sample-1 (5) into bytes 18..25 of this header.
            uint64_t format_bits = 0;
            for (size_t i = 18; i < 26; ++i)
                format_bits = (format_bits << 8) | out.flac_header[i];
            out.sampling_rate = static_cast<int>((format_bits >> 44) & 0xfffff);
            out.channels = static_cast<int>(((format_bits >> 41) & 0x7) + 1);
            out.bit_depth = static_cast<int>(((format_bits >> 36) & 0x1f) + 1);
            // Some valid init segments end after STREAMINFO and rely on the
            // /file/url n_segments field for the segment count.
            if (a + 1 > len) return true;
            uint8_t key_id_len = p[a++];
            if (key_id_len > len - a) return false;
            a += key_id_len;
            if (a + 2 > len) return true;
            uint16_t seg_count = (uint16_t(p[a]) << 8) | uint16_t(p[a + 1]); a += 2;
            if (seg_count == 0) return true;
            if (static_cast<size_t>(seg_count) > (len - a) / 8)
                return false;
            out.segment_byte_lens.clear();
            out.segment_byte_lens.reserve(seg_count);
            for (uint16_t i = 0; i < seg_count; ++i) {
                uint32_t blen = (uint32_t(p[a]) << 24) | (uint32_t(p[a + 1]) << 16) |
                                (uint32_t(p[a + 2]) << 8) | uint32_t(p[a + 3]);
                a += 8; // skip sample_count too
                if (blen == 0) return false;
                out.segment_byte_lens.push_back(blen);
            }
            return true;
        }
        pos += sz;
    }
    return false;
}

static bool parseSegmentCrypto(const std::vector<uint8_t>& data, CmafSegmentCrypto& out) {
    static const uint8_t QBZ_SEG_UUID[16] = {
        0x3b,0x42,0x12,0x92,0x56,0xf3,0x5f,0x75,0x92,0x36,0x63,0xb6,0x9a,0x1f,0x52,0xb2
    };
    size_t uuid_pos = std::string::npos;
    size_t mdat_end = 0;
    bool have_mdat = false;
    size_t pos = 0;
    while (pos + 8 <= data.size()) {
        size_t sz = readBoxSize(data, pos);
        if (sz < 8 || sz > data.size() - pos) return false;
        if (memcmp(&data[pos + 4], "uuid", 4) == 0 && pos + 24 <= data.size() &&
            memcmp(&data[pos + 8], QBZ_SEG_UUID, 16) == 0) {
            uuid_pos = pos;
        } else if (memcmp(&data[pos + 4], "mdat", 4) == 0) {
            mdat_end = pos + sz;
            have_mdat = true;
        }
        pos += sz;
    }
    if (uuid_pos == std::string::npos || !have_mdat) return false;
    size_t base = uuid_pos + 24;
    if (base + 12 > data.size()) return false;
    size_t a = base + 4;
    uint32_t data_off_raw = (uint32_t(data[a]) << 24) | (uint32_t(data[a + 1]) << 16) |
                            (uint32_t(data[a + 2]) << 8) | uint32_t(data[a + 3]);
    if (data_off_raw > data.size() - uuid_pos) return false;
    out.data_offset = uuid_pos + data_off_raw; a += 4;
    size_t iv_size = data[a++]; // usually 8
    if (iv_size == 0 || iv_size > 16) return false;
    size_t frame_count = (size_t(data[a]) << 16) | (size_t(data[a + 1]) << 8) | size_t(data[a + 2]); a += 3;
    size_t ent_sz = 4 + 2 + 2 + iv_size;
    if (frame_count == 0 || frame_count > (data.size() - a) / ent_sz)
        return false;
    out.entries.clear();
    out.entries.reserve(frame_count);
    for (size_t i = 0; i < frame_count; ++i) {
        CmafFrameEntry e;
        e.size = (uint32_t(data[a]) << 24) | (uint32_t(data[a + 1]) << 16) |
                 (uint32_t(data[a + 2]) << 8) | uint32_t(data[a + 3]); a += 4;
        a += 2; // skip
        e.flags = (uint16_t(data[a]) << 8) | uint16_t(data[a + 1]); a += 2;
        size_t copy = std::min<size_t>(8, iv_size);
        memcpy(e.iv, &data[a], copy);
        a += iv_size;
        out.entries.push_back(e);
    }
    out.mdat_end = std::min(mdat_end, data.size());
    if (out.data_offset > out.mdat_end) return false;
    return true;
}

// ---- Exact segment geometry (no audio download) -----------------------------
//
// decryptSegment() emits exactly the bytes in [data_offset, mdat_end): the
// encrypted FLAC frames, then any trailing mdat bytes.  AES-CTR is
// length-preserving, so that span's length IS the decrypted output length and
// needs neither the content key nor the payload.
//
// Both bounds come from box headers at the FRONT of the segment: data_offset
// from the Qobuz `uuid` box, mdat_end from the `mdat` box header.  A short
// prefix of each segment therefore yields its exact reconstructed length, and
// the whole track's exact length and cumulative offsets follow.  That is what
// lets the proxy answer with a real Content-Length before a single audio byte
// has been fetched, which is the only thing MusicPD's FLAC decoder needs in
// order to seek (FlacInput::Length -> InputStream::KnownSize).

struct CmafSegmentGeometry {
    uint64_t data_offset{0};
    uint64_t mdat_end{0};
    uint64_t decrypted_len() const { return mdat_end - data_offset; }
};

// Parse geometry from a prefix.  full_size is the segment's total size, used
// only to sanity-check box sizes that extend past the prefix.  Returns false
// if the prefix is too short to reach the mdat header, which the caller
// retries with a larger one.
static bool parseSegmentGeometry(const std::vector<uint8_t>& prefix,
                                 uint64_t full_size,
                                 CmafSegmentGeometry& out) {
    size_t uuid_pos = std::string::npos;
    size_t pos = 0;
    while (pos + 8 <= prefix.size()) {
        const size_t sz = readBoxSize(prefix, pos);
        if (sz < 8) return false;
        if (full_size != 0 && sz > full_size - pos) return false;
        if (memcmp(&prefix[pos + 4], "mdat", 4) == 0) {
            if (uuid_pos == std::string::npos) return false;
            const size_t base = uuid_pos + 24;
            if (base + 8 > prefix.size()) return false;
            const size_t a = base + 4;
            const uint32_t data_off_raw =
                (uint32_t(prefix[a]) << 24) | (uint32_t(prefix[a + 1]) << 16) |
                (uint32_t(prefix[a + 2]) << 8) | uint32_t(prefix[a + 3]);
            const uint64_t data_offset =
                static_cast<uint64_t>(uuid_pos) + data_off_raw;
            const uint64_t mdat_end = static_cast<uint64_t>(pos) + sz;
            if (data_offset > mdat_end) return false;
            if (full_size != 0 && mdat_end > full_size) return false;
            out.data_offset = data_offset;
            out.mdat_end = mdat_end;
            return true;
        }
        static const uint8_t QBZ_SEG_UUID[16] = {
            0x3b,0x42,0x12,0x92,0x56,0xf3,0x5f,0x75,
            0x92,0x36,0x63,0xb6,0x9a,0x1f,0x52,0xb2
        };
        if (memcmp(&prefix[pos + 4], "uuid", 4) == 0 &&
            pos + 24 <= prefix.size() &&
            memcmp(&prefix[pos + 8], QBZ_SEG_UUID, 16) == 0) {
            uuid_pos = pos;
        }
        pos += sz;
    }
    return false;
}

// Qobuz's own per-segment table in the init segment is an estimate and must
// never be used for byte offsets; these prefixes are measured instead.
constexpr size_t kGeometryProbeBytes = 64 * 1024;
constexpr size_t kGeometryProbeBytesMax = 1024 * 1024;
constexpr size_t kGeometryProbeThreads = 8;

static bool deriveSessionKey(const std::string& infos, uint8_t out_key[16]) {
    auto dot = infos.find('.');
    if (dot == std::string::npos) return false;
    std::vector<uint8_t> salt, info, ikm;
    if (!base64urlDecodeBytes(infos.substr(0, dot), salt)) return false;
    if (!base64urlDecodeBytes(infos.substr(dot + 1), info)) return false;
    if (!hexDecode("abb21364945c0583309667d13ca3d93a", ikm)) return false;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return false;
    bool ok = EVP_PKEY_derive_init(pctx) > 0 &&
              EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) > 0 &&
              EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) > 0;
    size_t outlen = 16;
    if (ok) ok = EVP_PKEY_derive(pctx, out_key, &outlen) > 0 && outlen == 16;
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

static bool unwrapContentKey(const uint8_t session_key[16], const std::string& keystr,
                             uint8_t out_key[16]) {
    auto p1 = keystr.find('.');
    if (p1 == std::string::npos) return false;
    auto p2 = keystr.find('.', p1 + 1);
    if (p2 == std::string::npos) return false;
    std::vector<uint8_t> wrapped, iv;
    if (!base64urlDecodeBytes(keystr.substr(p1 + 1, p2 - p1 - 1), wrapped)) return false;
    if (!base64urlDecodeBytes(keystr.substr(p2 + 1), iv)) return false;
    if (iv.size() != 16) return false;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    std::vector<uint8_t> out(wrapped.size() + 16);
    int n1 = 0, n2 = 0;
    bool ok = EVP_DecryptInit_ex(c, EVP_aes_128_cbc(), nullptr, session_key, iv.data()) > 0 &&
              EVP_DecryptUpdate(c, out.data(), &n1, wrapped.data(), wrapped.size()) > 0 &&
              EVP_DecryptFinal_ex(c, out.data() + n1, &n2) > 0;
    EVP_CIPHER_CTX_free(c);
    if (!ok || n1 + n2 != 16) return false;
    memcpy(out_key, out.data(), 16);
    return true;
}

static bool decryptCtrFrame(const uint8_t content_key[16], const uint8_t iv8[8],
                            uint8_t* data, size_t len) {
    if (len > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    uint8_t nonce[16] = {0};
    memcpy(nonce, iv8, 8);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    int outlen = 0;
    bool ok = EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), nullptr,
                                 content_key, nonce) > 0 &&
              EVP_EncryptUpdate(c, data, &outlen, data,
                                static_cast<int>(len)) > 0 &&
              static_cast<size_t>(outlen) == len;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// Decrypt a fetched audio segment into a flat byte buffer (concatenated
// FLAC frames + any trailing mdat bytes after the last frame entry).
static bool decryptSegment(const std::vector<uint8_t>& seg,
                            const uint8_t content_key[16],
                            std::vector<uint8_t>& out) {
    CmafSegmentCrypto c;
    if (!parseSegmentCrypto(seg, c)) return false;
    out.clear();
    out.reserve(seg.size());
    size_t p = c.data_offset;
    for (const auto& e : c.entries) {
        if (e.size > c.mdat_end - p) return false;
        size_t before = out.size();
        out.insert(out.end(), seg.begin() + p, seg.begin() + p + e.size);
        if (e.flags != 0 &&
            !decryptCtrFrame(content_key, e.iv, out.data() + before, e.size))
            return false;
        p += e.size;
    }
    if (p < c.mdat_end)
        out.insert(out.end(), seg.begin() + p, seg.begin() + c.mdat_end);
    return !out.empty();
}

static bool fetchAndDecryptSegmentOnce(
    const SegmentedTrackPlan& plan, size_t seg_1based,
    std::vector<uint8_t>& out_data, std::string& error,
    CurlFetcher& fetcher,
    const std::atomic<bool>* cancelled = nullptr) {
    std::string url = std::regex_replace(plan.url_template,
                                         std::regex("\\$SEGMENT\\$"),
                                         std::to_string(seg_1based));
    std::vector<uint8_t> raw;
    if (!fetcher.fetch(url, plan.http_headers, raw, &error, cancelled))
        return false;
    if (!decryptSegment(raw, plan.content_key, out_data)) {
        error = "truncated or invalid encrypted segment";
        return false;
    }
    return true;
}

static bool openDownloadCache(
    const SegmentedTrackPlan& plan,
    const std::shared_ptr<SegmentedDownloadState>& state,
    std::string& error) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path dir(segmentedCacheDirectory());
    fs::create_directories(dir, ec);
    if (ec) {
        error = "cannot create cache directory: " + ec.message();
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {
        error = "cannot restrict cache directory permissions: " +
                std::string(std::strerror(errno));
        return false;
    }

    state->fd = ::open(state->cache_path.c_str(),
                       O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (state->fd < 0) {
        error = "cannot create cache file: " +
                std::string(std::strerror(errno));
        return false;
    }
    if (::fchmod(state->fd, 0600) != 0) {
        error = "cannot restrict cache permissions: " +
                std::string(std::strerror(errno));
        ::close(state->fd);
        state->fd = -1;
        ::unlink(state->cache_path.c_str());
        return false;
    }

    if (plan.hasExactGeometry()) {
        // Preallocate sparse: every segment's offset is already known, so
        // segments can land in any order and the exact length can be
        // published before a single audio byte exists.
        if (::ftruncate(state->fd,
                        static_cast<off_t>(plan.exact_total_bytes)) != 0) {
            error = "cannot size cache file: " +
                    std::string(std::strerror(errno));
            ::close(state->fd);
            state->fd = -1;
            ::unlink(state->cache_path.c_str());
            return false;
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        state->segment_present.assign(plan.n_audio_segments(), 0);
        state->exact_size = plan.exact_total_bytes;
    }

    LOGINF("QobuzApi: track " << state->cache_path << " ["
           << streamFormat(plan) << "] reconstructing "
           << plan.n_audio_segments()
           << " encrypted Qobuz audio segments"
              " (initialization segment 0 already parsed)\n");
    if (isForPlayback(state))
        activityPhase(ActivityPhase::Downloading,
                      "reconstructing " +
                      std::to_string(plan.n_audio_segments()) +
                      " encrypted segments");
    return true;
}

static bool appendToCache(const std::shared_ptr<SegmentedDownloadState>& state,
                          const uint8_t* data, size_t size,
                          std::string& error) {
    size_t done = 0;
    while (done < size) {
        ssize_t written = ::write(state->fd, data + done, size - done);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            error = "cache write failed: " + std::string(std::strerror(errno));
            return false;
        }
        done += static_cast<size_t>(written);
    }
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (size > std::numeric_limits<uint64_t>::max() - state->available) {
            error = "reconstructed stream is too large";
            return false;
        }
        state->available += size;
    }
    state->changed.notify_all();
    return true;
}

// Write at an absolute offset in the preallocated cache.  Presence and the
// contiguous watermark are updated by the caller under the state lock.
static bool writeCacheAt(const std::shared_ptr<SegmentedDownloadState>& state,
                         uint64_t offset, const uint8_t* data, size_t size,
                         std::string& error) {
    size_t done = 0;
    while (done < size) {
        const ssize_t written = ::pwrite(
            state->fd, data + done, size - done,
            static_cast<off_t>(offset + done));
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            error = "cache write failed: " + std::string(std::strerror(errno));
            return false;
        }
        done += static_cast<size_t>(written);
    }
    return true;
}

// Recompute how far the stream is contiguously present from byte 0.  Must be
// called with state->mutex held.
static void refreshContiguousLocked(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    const std::shared_ptr<SegmentedDownloadState>& state) {
    if (!state->header_written) {
        state->available = 0;
        return;
    }
    uint64_t end = plan->flac_header.size();
    for (size_t i = 0; i < state->segment_present.size(); ++i) {
        if (!state->segment_present[i]) break;
        end = plan->exact_segment_offsets[i + 1];
    }
    state->available = end;
}

static void failDownload(const std::shared_ptr<SegmentedDownloadState>& state,
                         std::string error) {
    bool announce = false;
    std::string reported;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!state->complete && !state->failed) {
            state->failed = true;
            state->error = std::move(error);
            reported = state->error;
            // A cancelled download is the normal consequence of the queue
            // being replaced, not something to report as a failure.
            announce = !state->cancelled.load(std::memory_order_relaxed) &&
                       isForPlayback(state);
        }
    }
    if (announce)
        activityPhase(ActivityPhase::Error, "download failed: " + reported);
    state->changed.notify_all();
}

enum class ReconstructionStep { Finished, Continue };

static ReconstructionStep reconstructTrackStep(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    const std::shared_ptr<SegmentedDownloadState>& state,
    CurlFetcher& fetcher) {
    std::string error;
    if (state->cancelled.load(std::memory_order_relaxed))
        return ReconstructionStep::Finished;

    const bool exact = plan->hasExactGeometry();

    if (state->fd < 0) {
        if (!openDownloadCache(*plan, state, error)) {
            failDownload(state, std::move(error));
            return ReconstructionStep::Finished;
        }
        if (exact) {
            if (!writeCacheAt(state, 0, plan->flac_header.data(),
                              plan->flac_header.size(), error)) {
                failDownload(state, std::move(error));
                return ReconstructionStep::Finished;
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->header_written = true;
                refreshContiguousLocked(plan, state);
            }
            state->changed.notify_all();
        } else if (!appendToCache(state, plan->flac_header.data(),
                                  plan->flac_header.size(), error)) {
            failDownload(state, std::move(error));
            return ReconstructionStep::Finished;
        }
    }

    // Pick the next segment: honour a reader that is blocked on a seek
    // target, otherwise fill the lowest gap so sequential playback stays
    // ahead of the decoder.
    size_t segment = 0;
    if (exact) {
        std::lock_guard<std::mutex> lock(state->mutex);
        const size_t wanted = state->wanted_segment;
        if (wanted >= 1 && wanted <= state->segment_present.size() &&
            !state->segment_present[wanted - 1]) {
            segment = wanted;
        } else {
            for (size_t i = 0; i < state->segment_present.size(); ++i) {
                if (!state->segment_present[i]) { segment = i + 1; break; }
            }
        }
    } else if (state->next_segment <= plan->n_audio_segments()) {
        segment = state->next_segment;
    }

    if (segment != 0) {
        std::vector<uint8_t> data;
        bool fetched = false;
        for (int attempt = 1; attempt <= kSegmentMaxAttempts; ++attempt) {
            if (state->cancelled.load(std::memory_order_relaxed))
                return ReconstructionStep::Finished;
            if (fetchAndDecryptSegmentOnce(*plan, segment, data, error,
                                           fetcher,
                                           &state->cancelled)) {
                fetched = true;
                break;
            }
            if (state->cancelled.load(std::memory_order_relaxed))
                return ReconstructionStep::Finished;
            if (attempt < kSegmentMaxAttempts) {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->changed.wait_for(
                    lock, std::chrono::milliseconds(250 * attempt), [&state] {
                        return state->cancelled.load(std::memory_order_relaxed);
                    });
            }
        }
        if (!fetched) {
            failDownload(state, "segment " + std::to_string(segment) + "/" +
                         std::to_string(plan->n_audio_segments()) + ": " + error +
                         " after " + std::to_string(kSegmentMaxAttempts) +
                         " attempts");
            return ReconstructionStep::Finished;
        }
        if (state->cancelled.load(std::memory_order_relaxed))
            return ReconstructionStep::Finished;
        if (exact) {
            const uint64_t expected =
                plan->exact_segment_lens[segment - 1];
            if (data.size() != expected) {
                // The measured geometry is what the Content-Length promised.
                // A mismatch would corrupt every later offset, so stop rather
                // than serve a stream that does not match its own header.
                failDownload(state, "segment " + std::to_string(segment) +
                             " is " + std::to_string(data.size()) +
                             " bytes, geometry said " +
                             std::to_string(expected));
                return ReconstructionStep::Finished;
            }
            if (!writeCacheAt(state, plan->exact_segment_offsets[segment - 1],
                              data.data(), data.size(), error)) {
                failDownload(state, std::move(error));
                return ReconstructionStep::Finished;
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (!state->segment_present[segment - 1]) {
                    state->segment_present[segment - 1] = 1;
                    ++state->segments_done;
                }
                if (state->wanted_segment == segment) state->wanted_segment = 0;
                refreshContiguousLocked(plan, state);
            }
            state->changed.notify_all();
        } else {
            if (!appendToCache(state, data.data(), data.size(), error)) {
                failDownload(state, std::move(error));
                return ReconstructionStep::Finished;
            }
            ++state->next_segment;
        }
        const size_t segment_count = plan->n_audio_segments();
        const size_t done = exact ? state->segments_done : segment;
        const unsigned percent = segment_count == 0 ? 100 :
            static_cast<unsigned>((done * 100) / segment_count);
        LOGDEB("QobuzApi: track " << state->cache_path << " ["
               << streamFormat(*plan) << "] [segment " << segment << "/"
               << segment_count << "] in progress (" << percent << "%)\n");
        if (isForPlayback(state))
            activityProgress(ActivityPhase::Downloading, state->cache_path,
                             "segment", done, segment_count);
    }

    if (exact) {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->segments_done < state->segment_present.size())
            return ReconstructionStep::Continue;
    } else if (state->next_segment <= plan->n_audio_segments()) {
        return ReconstructionStep::Continue;
    }

    uint64_t completed_size = 0;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->cancelled.load(std::memory_order_relaxed))
            return ReconstructionStep::Finished;
        state->exact_size = state->available;
        state->complete = true;
        completed_size = state->exact_size;
    }
    state->changed.notify_all();
    LOGINF("QobuzApi: track " << state->cache_path << " ["
           << streamFormat(*plan) << "] complete: "
           << plan->n_audio_segments() << "/"
           << plan->n_audio_segments() << " segments, "
           << completed_size << " bytes\n");
    if (isForPlayback(state))
        activityNote("all " + std::to_string(plan->n_audio_segments()) +
                     " segments reconstructed, waiting for MusicPD");
    return ReconstructionStep::Finished;
}

static void promoteStatePriority(
    const std::shared_ptr<SegmentedDownloadState>& state,
    SegmentedDownloadPriority priority) {
    int requested = state->requested_priority.load(std::memory_order_relaxed);
    const int desired = static_cast<int>(priority);
    while (requested < desired &&
           !state->requested_priority.compare_exchange_weak(
               requested, desired, std::memory_order_relaxed)) {}
}

} // anonymous namespace

class SegmentedDownloadScheduler {
public:
    SegmentedDownloadScheduler() {
        try {
            for (size_t i = 0; i < kMaxConcurrentTrackDownloads; ++i)
                m_workers.emplace_back(&SegmentedDownloadScheduler::workerLoop,
                                       this);
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopping = true;
            }
            m_changed.notify_all();
            for (auto& worker : m_workers)
                if (worker.joinable()) worker.join();
            throw;
        }
    }

    ~SegmentedDownloadScheduler() {
        std::vector<std::shared_ptr<SegmentedDownloadState>> states;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopping = true;
            for (const auto& job : m_pending) states.push_back(job.state);
            for (const auto& state : m_running) states.push_back(state);
            m_pending.clear();
        }
        for (const auto& state : states) {
            state->cancelled.store(true, std::memory_order_relaxed);
            failDownload(state, "download scheduler stopped");
        }
        m_changed.notify_all();
        for (auto& worker : m_workers)
            if (worker.joinable()) worker.join();
    }

    bool enqueue(const std::shared_ptr<SegmentedTrackPlan>& plan,
                 const std::shared_ptr<SegmentedDownloadState>& state,
                 SegmentedDownloadPriority priority) {
        std::lock_guard<std::mutex> lock(m_mutex);
        cleanCacheLocked();
        if (m_stopping || state->cancelled.load(std::memory_order_relaxed))
            return false;

        promoteStatePriority(state, priority);
        if (state->readers.load(std::memory_order_relaxed) != 0)
            promoteStatePriority(state, SegmentedDownloadPriority::Playback);
        const auto effective_priority = static_cast<SegmentedDownloadPriority>(
            state->requested_priority.load(std::memory_order_relaxed));

        if (effective_priority != SegmentedDownloadPriority::Playback) {
            const size_t automatic_footprint =
                m_pending.size() + m_running.size();
            if (automatic_footprint >= kMaxAutomaticTrackDownloads)
                return false;
        }
        if (m_pending.size() + m_running.size() >= kMaxPendingTrackDownloads)
            return false;

        m_pending.push_back(Job{
            plan, state, effective_priority, ++m_sequence});
        m_changed.notify_one();
        return true;
    }

    void promote(const std::shared_ptr<SegmentedDownloadState>& state,
                 SegmentedDownloadPriority priority) {
        promoteStatePriority(state, priority);
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& job : m_pending) {
            if (job.state == state &&
                static_cast<int>(job.priority) < static_cast<int>(priority)) {
                job.priority = priority;
                job.sequence = ++m_sequence;
                m_changed.notify_one();
                break;
            }
        }
        touchLocked(state);
    }

    void cancel(const std::shared_ptr<SegmentedDownloadState>& state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pending.erase(
            std::remove_if(m_pending.begin(), m_pending.end(),
                           [&](const Job& job) { return job.state == state; }),
            m_pending.end());
        m_cache.erase(
            std::remove_if(m_cache.begin(), m_cache.end(),
                           [&](const CacheEntry& entry) {
                               return entry.state.lock() == state;
                           }),
            m_cache.end());
        m_changed.notify_all();
    }

    void touch(const std::shared_ptr<SegmentedDownloadState>& state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        touchLocked(state);
    }

    void trimCache() {
        std::lock_guard<std::mutex> lock(m_mutex);
        trimCacheLocked();
    }

private:
    struct Job {
        std::shared_ptr<SegmentedTrackPlan> plan;
        std::shared_ptr<SegmentedDownloadState> state;
        SegmentedDownloadPriority priority{SegmentedDownloadPriority::Background};
        uint64_t sequence{0};
    };

    struct CacheEntry {
        std::weak_ptr<SegmentedTrackPlan> plan;
        std::weak_ptr<SegmentedDownloadState> state;
        uint64_t size{0};
        uint64_t last_access{0};
    };

    void workerLoop() {
        CurlFetcher fetcher;
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_changed.wait(lock, [this] {
                    return m_stopping || !m_pending.empty();
                });
                if (m_stopping && m_pending.empty()) return;

                auto selected = std::max_element(
                    m_pending.begin(), m_pending.end(),
                    [](const Job& lhs, const Job& rhs) {
                        if (lhs.priority != rhs.priority)
                            return static_cast<int>(lhs.priority) <
                                   static_cast<int>(rhs.priority);
                        return lhs.sequence > rhs.sequence;
                    });
                job = std::move(*selected);
                m_pending.erase(selected);
                m_running.push_back(job.state);
            }

            ReconstructionStep step = ReconstructionStep::Finished;
            try {
                // One segment per scheduling turn bounds the time before a
                // newly promoted Playback job can overtake speculative work.
                step = reconstructTrackStep(job.plan, job.state, fetcher);
            } catch (const std::exception& e) {
                failDownload(job.state,
                             "download worker exception: " + std::string(e.what()));
            } catch (...) {
                failDownload(job.state, "download worker exception");
            }

            uint64_t exact_size = 0;
            bool complete = false;
            bool failed = false;
            {
                std::lock_guard<std::mutex> state_lock(job.state->mutex);
                complete = job.state->complete;
                failed = job.state->failed;
                exact_size = job.state->exact_size;
            }
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_running.erase(
                    std::remove(m_running.begin(), m_running.end(), job.state),
                    m_running.end());
                if (step == ReconstructionStep::Continue && !m_stopping &&
                    !failed &&
                    !job.state->cancelled.load(std::memory_order_relaxed)) {
                    job.priority = static_cast<SegmentedDownloadPriority>(
                        job.state->requested_priority.load(
                            std::memory_order_relaxed));
                    job.sequence = ++m_sequence;
                    m_pending.push_back(std::move(job));
                } else if (complete &&
                    !job.state->cancelled.load(std::memory_order_relaxed)) {
                    m_cache.push_back(CacheEntry{
                        job.plan, job.state, exact_size, ++m_sequence});
                }
                trimCacheLocked();
            }
            m_changed.notify_all();
        }
    }

    void cleanCacheLocked() {
        m_cache.erase(
            std::remove_if(m_cache.begin(), m_cache.end(),
                           [](const CacheEntry& entry) {
                               return entry.plan.expired() || entry.state.expired();
                           }),
            m_cache.end());
    }

    void touchLocked(const std::shared_ptr<SegmentedDownloadState>& state) {
        for (auto& entry : m_cache) {
            if (entry.state.lock() == state) {
                entry.last_access = ++m_sequence;
                break;
            }
        }
    }

    void trimCacheLocked() {
        cleanCacheLocked();
        for (;;) {
            uint64_t total = 0;
            for (const auto& entry : m_cache) {
                total = entry.size > std::numeric_limits<uint64_t>::max() - total
                    ? std::numeric_limits<uint64_t>::max()
                    : total + entry.size;
            }
            if (m_cache.size() <= kMaxRetainedCachedTracks &&
                total <= kMaxRetainedCachedBytes)
                return;

            auto victim = m_cache.end();
            for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
                auto state = it->state.lock();
                if (!state || state->readers.load(std::memory_order_relaxed) != 0)
                    continue;
                if (victim == m_cache.end() ||
                    it->last_access < victim->last_access)
                    victim = it;
            }
            if (victim == m_cache.end()) return;

            auto plan = victim->plan.lock();
            auto state = victim->state.lock();
            if (plan && state) {
                std::lock_guard<std::mutex> plan_lock(plan->m_download_mu);
                if (plan->m_download_state == state)
                    plan->m_download_state.reset();
            }
            m_cache.erase(victim);
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_changed;
    bool m_stopping{false};
    uint64_t m_sequence{0};
    std::deque<Job> m_pending;
    std::vector<std::shared_ptr<SegmentedDownloadState>> m_running;
    std::vector<CacheEntry> m_cache;
    std::vector<std::thread> m_workers;
};

static SegmentedDownloadScheduler& downloadScheduler() {
    static SegmentedDownloadScheduler scheduler;
    return scheduler;
}

SegmentedDownloadHandle scheduleSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    SegmentedDownloadPriority priority,
    bool pin_reader) {
    if (!plan) return {};

    std::shared_ptr<SegmentedDownloadState> state;
    bool needs_enqueue = false;
    {
        std::lock_guard<std::mutex> lock(plan->m_download_mu);
        if (plan->m_retired) return {};
        state = plan->m_download_state;
        if (state) {
            bool retryable_failure = false;
            {
                std::lock_guard<std::mutex> state_lock(state->mutex);
                retryable_failure = state->failed &&
                    !state->cancelled.load(std::memory_order_relaxed);
            }
            if (retryable_failure) state.reset();
        }
        if (!state) {
            state = std::make_shared<SegmentedDownloadState>();
            state->cache_path = makeCachePath(*plan);
            state->plan = plan;
            if (pin_reader)
                state->readers.store(1, std::memory_order_relaxed);
            plan->m_download_state = state;
            needs_enqueue = true;
        } else if (pin_reader) {
            state->readers.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (!needs_enqueue) {
        downloadScheduler().promote(state, priority);
        std::unique_lock<std::mutex> state_lock(state->mutex);
        state->changed.wait(state_lock, [&state] {
            return !state->scheduling;
        });
        return state;
    }

    bool enqueued = false;
    std::string schedule_error = "download scheduler is busy";
    try {
        enqueued = downloadScheduler().enqueue(plan, state, priority);
    } catch (const std::exception& e) {
        schedule_error = "cannot start download scheduler: " +
                         std::string(e.what());
    } catch (...) {
        schedule_error = "cannot start download scheduler";
    }
    {
        std::lock_guard<std::mutex> state_lock(state->mutex);
        state->scheduled = enqueued;
        state->scheduling = false;
        if (!enqueued && !state->complete && !state->failed) {
            state->failed = true;
            state->error = std::move(schedule_error);
        }
    }
    state->changed.notify_all();
    if (enqueued) return state;

    {
        std::lock_guard<std::mutex> lock(plan->m_download_mu);
        if (plan->m_download_state == state)
            plan->m_download_state.reset();
    }
    return pin_reader ? state : SegmentedDownloadHandle{};
}

void startSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    SegmentedDownloadPriority priority) {
    (void)scheduleSegmentedTrackDownload(plan, priority, false);
}

SegmentedDownloadHandle acquireSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    SegmentedDownloadPriority priority) {
    return scheduleSegmentedTrackDownload(plan, priority, true);
}

void releaseSegmentedTrackDownload(const SegmentedDownloadHandle& handle) {
    if (!handle) return;
    size_t previous = handle->readers.load(std::memory_order_relaxed);
    while (previous != 0 &&
           !handle->readers.compare_exchange_weak(
               previous, previous - 1, std::memory_order_relaxed)) {}
    if (previous == 1) downloadScheduler().trimCache();
}

void cancelSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan) {
    if (!plan) return;
    std::shared_ptr<SegmentedDownloadState> state;
    {
        std::lock_guard<std::mutex> lock(plan->m_download_mu);
        plan->m_retired = true;
        state = plan->m_download_state;
    }
    if (!state) return;
    state->cancelled.store(true, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!state->complete && !state->failed) {
            state->failed = true;
            state->error = "download cancelled";
        }
    }
    state->changed.notify_all();
    downloadScheduler().cancel(state);
}

bool segmentedTrackExactSize(const SegmentedDownloadHandle& state,
                             uint64_t& size_out) {
    if (!state) return false;
    std::lock_guard<std::mutex> lock(state->mutex);
    // With measured geometry the exact size is known before any audio has
    // been fetched, which is the whole point: the proxy can publish a real
    // Content-Length on the first response instead of after the download.
    if (!state->complete && state->exact_size == 0) return false;
    size_out = state->exact_size;
    return true;
}

bool segmentedTrackFailed(const SegmentedDownloadHandle& state,
                          std::string* err_out) {
    if (!state) {
        if (err_out) *err_out = "download not scheduled";
        return true;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    if (!state->failed) return false;
    if (err_out) *err_out = state->error;
    return true;
}

bool waitForSegmentedTrack(const SegmentedDownloadHandle& state,
                           uint64_t& size_out,
                           uint32_t timeout_ms,
                           std::string* err_out) {
    if (!state) {
        if (err_out) *err_out = "download not scheduled";
        return false;
    }

    std::unique_lock<std::mutex> lock(state->mutex);
    if (!state->changed.wait_for(
            lock, std::chrono::milliseconds(timeout_ms), [&state] {
                return state->complete || state->failed;
            })) {
        if (err_out) *err_out = "download not ready before timeout";
        return false;
    }
    if (state->failed) {
        if (err_out) *err_out = state->error;
        return false;
    }
    size_out = state->exact_size;
    return true;
}

int readSegmentedTrack(const SegmentedDownloadHandle& state,
                       uint64_t offset, uint8_t* buffer,
                       size_t capacity, size_t& size_out,
                       uint32_t timeout_ms,
                       std::string* err_out) {
    size_out = 0;
    if (!buffer || capacity == 0) {
        if (err_out) *err_out = "invalid read buffer";
        return -1;
    }

    if (!state) {
        if (err_out) *err_out = "download not scheduled";
        return -1;
    }

    uint64_t readable_end = 0;
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        const auto plan = state->plan.lock();
        const bool exact = plan && plan->hasExactGeometry() &&
                           !state->segment_present.empty();
        if (exact) {
            // Random access: only the segment holding `offset` has to be
            // present, and asking for it moves it to the front of the
            // download queue.  This is what makes a seek into an
            // undownloaded track cost one segment instead of the whole file.
            const size_t segment = plan->segmentForOffset(offset);
            if (segment == 0) {
                if (offset >= plan->exact_total_bytes) return 0;
                // Inside the FLAC header, which is written before anything
                // else.
                if (!state->changed.wait_for(
                        lock, std::chrono::milliseconds(timeout_ms),
                        [&state] {
                            return state->header_written || state->failed;
                        })) {
                    if (err_out) *err_out = "download stalled before header";
                    return -1;
                }
                readable_end = plan->flac_header.size();
            } else {
                if (!state->segment_present[segment - 1]) {
                    state->wanted_segment = segment;
                    state->changed.notify_all();
                    if (!state->changed.wait_for(
                            lock, std::chrono::milliseconds(timeout_ms),
                            [&state, segment] {
                                return state->segment_present[segment - 1] ||
                                       state->failed;
                            })) {
                        if (err_out)
                            *err_out = "download stalled before requested offset";
                        return -1;
                    }
                }
                if (state->failed) {
                    if (err_out) *err_out = state->error;
                    return -1;
                }
                // Read no further than this segment; the next one may be a
                // hole that reads back as zeroes.
                readable_end = plan->exact_segment_offsets[segment];
            }
        } else {
            if (!state->changed.wait_for(
                    lock, std::chrono::milliseconds(timeout_ms),
                    [&state, offset] {
                        return state->available > offset || state->complete ||
                               state->failed;
                    })) {
                if (err_out) *err_out = "download stalled before requested offset";
                return -1;
            }
            readable_end = state->available;
        }
        if (offset >= readable_end) {
            if (state->failed) {
                if (err_out) *err_out = state->error;
                return -1;
            }
            return 0;
        }
    }

    const uint64_t wanted64 = std::min<uint64_t>(capacity, readable_end - offset);
    if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        if (err_out) *err_out = "cache offset is too large";
        return -1;
    }
    ssize_t got;
    do {
        got = ::pread(state->fd, buffer, static_cast<size_t>(wanted64),
                      static_cast<off_t>(offset));
    } while (got < 0 && errno == EINTR);
    if (got <= 0) {
        if (err_out) {
            *err_out = got == 0 ? "unexpected cache EOF" :
                       "cache read failed: " + std::string(std::strerror(errno));
        }
        return -1;
    }
    size_out = static_cast<size_t>(got);
    return 1;
}

// ---- SegmentedTrackRegistry -------------------------------------------------

SegmentedTrackRegistry::~SegmentedTrackRegistry() {
    clear();
}

std::string SegmentedTrackRegistry::tokenForTrack(uint32_t track_id, int format_id) {
    // Keep repeated resolutions stable within this process without exposing
    // guessable track IDs on the LAN-facing HTTP endpoint.
    static const std::array<uint8_t, 32> secret = [] {
        std::array<uint8_t, 32> value{};
        if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
            const auto ticks = std::chrono::steady_clock::now()
                .time_since_epoch().count();
            const auto pid = static_cast<uint64_t>(::getpid());
            std::memcpy(value.data(), &ticks,
                        std::min(sizeof(ticks), value.size()));
            std::memcpy(value.data() + 16, &pid,
                        std::min(sizeof(pid), value.size() - 16));
        }
        return value;
    }();
    const std::string identity = std::to_string(track_id) + ":" +
                                 std::to_string(format_id);
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx &&
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, secret.data(), secret.size()) == 1 &&
        EVP_DigestUpdate(ctx, identity.data(), identity.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1;
    if (ctx) EVP_MD_CTX_free(ctx);
    if (!ok || digest_len < 20)
        return std::to_string(track_id) + "_" +
               std::to_string(format_id) + ".flac";

    static constexpr char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(45);
    for (size_t i = 0; i < 20; ++i) {
        token.push_back(hex[digest[i] >> 4]);
        token.push_back(hex[digest[i] & 0x0f]);
    }
    token += ".flac";
    return token;
}

void SegmentedTrackRegistry::registerPlan(const std::string& token,
                                           std::shared_ptr<SegmentedTrackPlan> plan) {
    if (!plan) return;
    std::shared_ptr<SegmentedTrackPlan> replaced;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_plans.find(token);
        if (it != m_plans.end()) {
            auto existing = it->second;
            std::shared_ptr<SegmentedDownloadState> state;
            {
                std::lock_guard<std::mutex> plan_lock(existing->m_download_mu);
                state = existing->m_download_state;
            }
            if (state) {
                std::lock_guard<std::mutex> state_lock(state->mutex);
                if (!state->failed &&
                    !state->cancelled.load(std::memory_order_relaxed))
                    return;
            }
            replaced = std::move(existing);
        }
        m_plans[token] = plan;
    }
    if (replaced != plan) cancelSegmentedTrackDownload(replaced);
}

std::shared_ptr<SegmentedTrackPlan>
SegmentedTrackRegistry::get(const std::string& token) const {
    std::lock_guard<std::mutex> lk(m_mu);
    auto it = m_plans.find(token);
    return (it == m_plans.end()) ? nullptr : it->second;
}

void SegmentedTrackRegistry::erase(const std::string& token) {
    std::shared_ptr<SegmentedTrackPlan> removed;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_plans.find(token);
        if (it == m_plans.end()) return;
        removed = it->second;
        m_plans.erase(it);
    }
    cancelSegmentedTrackDownload(removed);
}

void SegmentedTrackRegistry::retainOnly(
    const std::unordered_set<std::string>& tokens) {
    std::vector<std::shared_ptr<SegmentedTrackPlan>> removed;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        for (auto it = m_plans.begin(); it != m_plans.end();) {
            if (tokens.find(it->first) != tokens.end()) {
                ++it;
                continue;
            }
            removed.push_back(std::move(it->second));
            it = m_plans.erase(it);
        }
    }
    for (const auto& plan : removed) cancelSegmentedTrackDownload(plan);
}

void SegmentedTrackRegistry::prioritize(const std::string& token) {
    auto plan = get(token);
    if (plan)
        startSegmentedTrackDownload(plan, SegmentedDownloadPriority::Upcoming);
}

std::string SegmentedTrackRegistry::cachePath(const std::string& token) const {
    auto plan = get(token);
    if (!plan) return {};
    std::lock_guard<std::mutex> plan_lock(plan->m_download_mu);
    return plan->m_download_state
        ? plan->m_download_state->cache_path : std::string{};
}

void SegmentedTrackRegistry::clear() {
    std::vector<std::shared_ptr<SegmentedTrackPlan>> removed;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        removed.reserve(m_plans.size());
        for (const auto& entry : m_plans) removed.push_back(entry.second);
        m_plans.clear();
    }
    for (const auto& plan : removed) cancelSegmentedTrackDownload(plan);
}

size_t SegmentedTrackRegistry::size() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return m_plans.size();
}

// ---- buildSegmentedTrackPlan ------------------------------------------------

bool buildSegmentedTrackPlan(
    const std::string& url_template,
    const std::vector<std::string>& http_headers,
    const std::string& keystr,
    const std::string& session_infos,
    uint32_t track_id, int format_id,
    int json_n_segments_fallback,
    int sampling_rate, int bit_depth, uint32_t duration_ms,
    SegmentedTrackPlan& out,
    std::string* err_out) {

    if (url_template.empty() || keystr.empty() || session_infos.empty()) {
        if (err_out) *err_out = "missing url_template/key/session_infos";
        return false;
    }

    // Fetch the init segment (segment 0).
    CmafInitInfo init;
    std::string init_error;
    const std::string init_url = std::regex_replace(
        url_template, std::regex("\\$SEGMENT\\$"), "0");
    CurlFetcher init_fetcher;
    bool init_ok = false;
    for (int attempt = 1; attempt <= kSegmentMaxAttempts; ++attempt) {
        std::vector<uint8_t> seg0;
        std::string fetch_error;
        if (init_fetcher.fetch(init_url, http_headers, seg0, &fetch_error)) {
            if (parseInitSegment(seg0, init)) {
                init_ok = true;
                break;
            }
            init_error = "parse failed";
        } else {
            init_error = fetch_error;
        }
        if (attempt < kSegmentMaxAttempts)
            std::this_thread::sleep_for(std::chrono::milliseconds(250 * attempt));
    }
    if (!init_ok) {
        if (err_out) *err_out = "init segment failed after retries: " + init_error;
        return false;
    }
    if (init.flac_header.empty()) {
        if (err_out) *err_out = "init segment has no FLAC header";
        return false;
    }
    if (init.segment_byte_lens.empty() &&
        (json_n_segments_fallback <= 1 || json_n_segments_fallback > 65536)) {
        if (err_out) *err_out = "init segment has no usable segment count";
        return false;
    }

    uint8_t session_key[16];
    if (!deriveSessionKey(session_infos, session_key)) {
        if (err_out) *err_out = "HKDF session key derivation failed";
        return false;
    }
    uint8_t content_key[16];
    if (!unwrapContentKey(session_key, keystr, content_key)) {
        if (err_out) *err_out = "content key unwrap failed";
        return false;
    }

    out.track_id = track_id;
    out.format_id = format_id;
    out.url_template = url_template;
    out.http_headers = http_headers;
    std::memcpy(out.content_key, content_key, 16);
    out.flac_header = std::move(init.flac_header);
    out.segment_byte_lens = std::move(init.segment_byte_lens);
    const bool estimated_lengths_known = !out.segment_byte_lens.empty();
    if (!estimated_lengths_known) {
        out.segment_byte_lens.assign(
            static_cast<size_t>(json_n_segments_fallback - 1), 0);
    }

    out.segment_offsets.clear();
    out.segment_offsets.reserve(out.segment_byte_lens.size() + 1);
    uint64_t acc = 0;
    out.segment_offsets.push_back(0);
    for (uint32_t blen : out.segment_byte_lens) {
        if (blen > std::numeric_limits<uint64_t>::max() - acc) {
            if (err_out) *err_out = "segment length table overflows";
            return false;
        }
        acc += blen;
        out.segment_offsets.push_back(acc);
    }
    // The init fragment's per-fragment table is EXACT, not an estimate as
    // this code long assumed. Measured against a byte-accurate probe of every
    // fragment's own box headers on 2026-08-27: 6 tracks, formats 6/7/27,
    // 3 to 153 fragments, zero discrepancy in any fragment. It also
    // reconciles with the direct CDN file: for track 355836927 the table
    // totals 115,639,460 and the 604-byte FLAC header brings that to
    // 115,640,064, exactly the direct file's Content-Length.
    //
    // So take the geometry straight from the table, at no extra cost — it
    // arrives in the init fragment we already fetch. probeSegmentedTrackGeometry()
    // stays as the fallback for a response that omits the table, where the
    // fragment count comes from the JSON instead.
    //
    // This is trusted but verified: reconstructTrackStep() fails the download
    // if any fragment's decrypted size disagrees with the geometry, so a
    // future Qobuz change is caught on the first bad fragment rather than
    // silently serving a stream that contradicts its own Content-Length.
    if (estimated_lengths_known) {
        out.exact_segment_lens = out.segment_byte_lens;
        out.exact_segment_offsets.clear();
        out.exact_segment_offsets.reserve(out.exact_segment_lens.size() + 1);
        uint64_t exact_acc = out.flac_header.size();
        out.exact_segment_offsets.push_back(exact_acc);
        for (uint32_t blen : out.exact_segment_lens) {
            exact_acc += blen;
            out.exact_segment_offsets.push_back(exact_acc);
        }
        out.exact_total_bytes = exact_acc;
    }

    // Diagnostic estimate only.  The HTTP layer waits for the measured size
    // before advertising Content-Length or accepting a byte range.
    if (out.flac_header.size() > std::numeric_limits<uint64_t>::max() - acc) {
        if (err_out) *err_out = "estimated stream length overflows";
        return false;
    }
    out.total_bytes = estimated_lengths_known ? out.flac_header.size() + acc : 0;

    out.sampling_rate = init.sampling_rate > 0
        ? init.sampling_rate : sampling_rate;
    out.bit_depth = init.bit_depth > 0 ? init.bit_depth : bit_depth;
    out.channels = init.channels > 0 ? init.channels : -1;
    out.duration_ms = duration_ms;
    return true;
}

// ---- fetchAndDecryptSegment -------------------------------------------------

bool segmentGeometryFromPrefix(const uint8_t* prefix, size_t prefix_len,
                               uint64_t full_size, uint64_t& out_len) {
    if (!prefix || prefix_len == 0) return false;
    const std::vector<uint8_t> bytes(prefix, prefix + prefix_len);
    CmafSegmentGeometry geom;
    if (!parseSegmentGeometry(bytes, full_size, geom)) return false;
    out_len = geom.decrypted_len();
    return true;
}

size_t SegmentedTrackPlan::segmentForOffset(uint64_t offset) const {
    if (exact_segment_offsets.size() < 2) return 0;
    if (offset < exact_segment_offsets.front()) return 1;
    if (offset >= exact_segment_offsets.back()) return 0;
    // First index whose start is > offset; the segment is the one before it.
    const auto it = std::upper_bound(exact_segment_offsets.begin(),
                                     exact_segment_offsets.end(), offset);
    return static_cast<size_t>(it - exact_segment_offsets.begin());
}

bool probeSegmentedTrackGeometry(SegmentedTrackPlan& plan,
                                 std::string* err_out) {
    const size_t count = plan.n_audio_segments();
    if (count == 0) {
        if (err_out) *err_out = "no audio segments";
        return false;
    }

    std::vector<uint32_t> lens(count, 0);
    std::atomic<size_t> next_index{0};
    std::mutex err_mu;
    std::string first_error;

    auto worker = [&]() {
        CurlFetcher fetcher;
        std::vector<uint8_t> prefix;
        for (;;) {
            const size_t i = next_index.fetch_add(1, std::memory_order_relaxed);
            if (i >= count) return;
            {
                std::lock_guard<std::mutex> lk(err_mu);
                if (!first_error.empty()) return;
            }
            const std::string url = std::regex_replace(
                plan.url_template, std::regex("\\$SEGMENT\\$"),
                std::to_string(i + 1));
            std::string error;
            bool measured = false;
            for (size_t want = kGeometryProbeBytes;
                 want <= kGeometryProbeBytesMax && !measured; want *= 4) {
                const std::string range = "0-" + std::to_string(want - 1);
                uint64_t full_size = 0;
                if (!fetcher.fetch(url, plan.http_headers, prefix, &error,
                                   nullptr, range.c_str(), &full_size)) {
                    break;
                }
                CmafSegmentGeometry geom;
                if (parseSegmentGeometry(prefix, full_size, geom)) {
                    const uint64_t len = geom.decrypted_len();
                    if (len == 0 || len > std::numeric_limits<uint32_t>::max()) {
                        error = "implausible segment length";
                        break;
                    }
                    lens[i] = static_cast<uint32_t>(len);
                    measured = true;
                    break;
                }
                error = "segment headers not within " +
                        std::to_string(want) + " bytes";
                // The server may have returned the whole (small) segment; a
                // larger range would not add anything.
                if (prefix.size() < want) break;
            }
            if (!measured) {
                std::lock_guard<std::mutex> lk(err_mu);
                if (first_error.empty()) {
                    first_error = "segment " + std::to_string(i + 1) + ": " +
                                  (error.empty() ? "unmeasurable" : error);
                }
                return;
            }
        }
    };

    const size_t nthreads = std::min(kGeometryProbeThreads, count);
    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (size_t i = 0; i < nthreads; ++i) threads.emplace_back(worker);
    for (auto& t : threads) t.join();

    if (!first_error.empty()) {
        if (err_out) *err_out = first_error;
        return false;
    }

    plan.exact_segment_lens = std::move(lens);
    plan.exact_segment_offsets.clear();
    plan.exact_segment_offsets.reserve(count + 1);
    uint64_t acc = plan.flac_header.size();
    plan.exact_segment_offsets.push_back(acc);
    for (uint32_t len : plan.exact_segment_lens) {
        acc += len;
        plan.exact_segment_offsets.push_back(acc);
    }
    plan.exact_total_bytes = acc;
    LOGINF("QobuzApi: track " << plan.track_id << " geometry measured: "
           << count << " segments, exact size " << plan.exact_total_bytes
           << " bytes (probed " << (count * kGeometryProbeBytes / 1024)
           << "KB)\n");
    return true;
}

bool fetchAndDecryptSegment(const SegmentedTrackPlan& plan,
                            size_t seg_1based,
                            std::vector<uint8_t>& out_data,
                            std::string* err_out) {
    if (seg_1based == 0 || seg_1based > plan.n_audio_segments()) {
        if (err_out) *err_out = "segment index out of range";
        return false;
    }
    std::string last_error;
    CurlFetcher fetcher;
    for (int attempt = 1; attempt <= kSegmentMaxAttempts; ++attempt) {
        if (fetchAndDecryptSegmentOnce(plan, seg_1based, out_data, last_error,
                                       fetcher))
            return true;
        if (attempt < kSegmentMaxAttempts)
            std::this_thread::sleep_for(std::chrono::milliseconds(250 * attempt));
    }
    if (err_out) *err_out = last_error + " after " +
                            std::to_string(kSegmentMaxAttempts) + " attempts";
    return false;
}

} // namespace QConnect
