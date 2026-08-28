/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace QConnect {

// Per-effective-UID directory so tests, foreground runs, and the FreeBSD
// service account cannot interfere with each other's caches.
const std::string& segmentedCacheDirectory();

struct SegmentedDownloadState;
class SegmentedTrackRegistry;
class SegmentedDownloadScheduler;

enum class SegmentedDownloadPriority {
    Background = 0,
    Upcoming = 1,
    Playback = 2,
};

using SegmentedDownloadHandle = std::shared_ptr<SegmentedDownloadState>;

// Everything needed to fetch+decrypt the audio segments of one Qobuz CMAF
// track on demand.  Built by buildSegmentedTrackPlan() from the /file/url
// response; consumed by the HTTP proxy in httphandler.cxx, which streams
// segments to MPD as MPD reads from the proxy URL.
struct SegmentedTrackPlan {
    uint32_t track_id{0};
    int      format_id{6};
    std::string url_template;             // contains $SEGMENT$ placeholder
    std::vector<std::string> http_headers; // X-User-Auth-Token / X-Session-Id / etc.
    uint8_t  content_key[16]{};

    std::vector<uint8_t>  flac_header;
    // Qobuz's estimated decrypted length for each audio segment.  These values
    // are useful as seek hints, but are not safe for HTTP Content-Length or
    // byte-range boundaries.  The proxy measures the reconstructed stream.
    std::vector<uint32_t> segment_byte_lens;
    // Cumulative estimated offsets into the audio stream (excludes the FLAC
    // header).  Size == n_audio_segments + 1.
    std::vector<uint64_t> segment_offsets;
    // Estimated total retained for diagnostics only.  HTTP responses must use
    // exact_total_bytes when it is set, else segmentedTrackExactSize().
    uint64_t total_bytes{0};

    // Exact geometry, measured from each segment's own box headers by
    // probeSegmentedTrackGeometry() without downloading any audio.  When
    // exact_total_bytes is non-zero these are authoritative: the proxy can
    // publish a real Content-Length up front (so MusicPD can seek), and the
    // cache can be written out of order because every segment's byte offset
    // is known in advance.
    std::vector<uint32_t> exact_segment_lens;
    // Encrypted (on-the-wire) size of each audio segment, as reported by the
    // Content-Range of the geometry probe.  Only used to split a segment's
    // download across several connections; 0 means unknown, which falls back
    // to a single whole-object GET.  Never use these for stream offsets --
    // the decrypted lengths in exact_segment_lens are the authoritative ones.
    std::vector<uint64_t> encrypted_segment_sizes;
    // Cumulative offsets into the FULL stream, including flac_header.
    // Size == n_audio_segments + 1; front() == flac_header.size().
    std::vector<uint64_t> exact_segment_offsets;
    uint64_t exact_total_bytes{0};

    bool hasExactGeometry() const { return exact_total_bytes != 0; }

    // 1-based index of the segment holding a byte offset, or 0 if out of
    // range or geometry is unknown.
    size_t segmentForOffset(uint64_t offset) const;

    int      sampling_rate{44100};
    int      bit_depth{-1};
    int      channels{-1};
    uint32_t duration_ms{0};

    size_t n_audio_segments() const { return segment_byte_lens.size(); }

private:
    mutable std::mutex m_download_mu;
    std::shared_ptr<SegmentedDownloadState> m_download_state;
    bool m_retired{false};

    friend void startSegmentedTrackDownload(
        const std::shared_ptr<SegmentedTrackPlan>& plan,
        SegmentedDownloadPriority priority);
    friend SegmentedDownloadHandle acquireSegmentedTrackDownload(
        const std::shared_ptr<SegmentedTrackPlan>& plan,
        SegmentedDownloadPriority priority);
    friend SegmentedDownloadHandle scheduleSegmentedTrackDownload(
        const std::shared_ptr<SegmentedTrackPlan>& plan,
        SegmentedDownloadPriority priority,
        bool pin_reader);
    friend void cancelSegmentedTrackDownload(
        const std::shared_ptr<SegmentedTrackPlan>& plan);
    friend void hintSegmentedTrackTarget(
        const std::shared_ptr<SegmentedTrackPlan>& plan, uint64_t offset);
    friend bool segmentedTrackExactSize(const SegmentedDownloadHandle& handle,
                                         uint64_t& size_out);
    friend bool segmentedTrackFailed(const SegmentedDownloadHandle& handle,
                                      std::string* err_out);
    friend bool waitForSegmentedTrack(const SegmentedDownloadHandle& handle,
                                       uint64_t& size_out,
                                       uint32_t timeout_ms,
                                       std::string* err_out);
    friend int readSegmentedTrack(const SegmentedDownloadHandle& handle,
                                  uint64_t offset, uint8_t* buffer,
                                  size_t capacity, size_t& size_out,
                                  uint32_t timeout_ms,
                                  std::string* err_out);
    friend class SegmentedTrackRegistry;
    friend class SegmentedDownloadScheduler;
};

// Start the shared background reconstruction for a track.  Calls are
// idempotent.  The reconstructed FLAC is cached on disk and readers block only
// when they catch up with the downloader.
void startSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    SegmentedDownloadPriority priority = SegmentedDownloadPriority::Background);

// Schedule a track and pin its cache for an HTTP response.  Playback requests
// outrank speculative prefetch jobs.  Release the returned handle when the
// response is destroyed so completed caches become eligible for LRU eviction.
SegmentedDownloadHandle acquireSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan,
    SegmentedDownloadPriority priority = SegmentedDownloadPriority::Playback);
void releaseSegmentedTrackDownload(const SegmentedDownloadHandle& handle);

// Cancel a background reconstruction and wake any blocked readers. Calls are
// idempotent. Used when a plan is replaced or removed from the active queue.
void cancelSegmentedTrackDownload(
    const std::shared_ptr<SegmentedTrackPlan>& plan);

// Point an in-flight reconstruction at the byte offset playback is about to
// jump to, before MusicPD asks for it.  On a seek MusicPD only requests the
// target offset once its decoder has started, and the decoder cannot start
// until the head of the stream has downloaded — so without this hint a deep
// seek waits for the fill to walk there from wherever the reader is.
void hintSegmentedTrackTarget(const std::shared_ptr<SegmentedTrackPlan>& plan,
                              uint64_t offset);

// Return the measured stream size when reconstruction has completed.
bool segmentedTrackExactSize(const SegmentedDownloadHandle& handle,
                             uint64_t& size_out);

// Return true when reconstruction has failed and copy the stable error.
bool segmentedTrackFailed(const SegmentedDownloadHandle& handle,
                          std::string* err_out = nullptr);

// Wait until the complete reconstructed stream and its exact size are
// available.  Returns false if downloading or reconstruction failed.
bool waitForSegmentedTrack(const SegmentedDownloadHandle& handle,
                           uint64_t& size_out,
                           uint32_t timeout_ms,
                           std::string* err_out = nullptr);

// Read from the shared growing cache at an absolute FLAC byte offset.
// Returns 1 with size_out > 0 for data, 0 at EOF, and -1 on failure.
int readSegmentedTrack(const SegmentedDownloadHandle& handle,
                       uint64_t offset, uint8_t* buffer,
                       size_t capacity, size_t& size_out,
                       uint32_t timeout_ms,
                       std::string* err_out = nullptr);

// Opaque URL-safe token mapping a track to its plan. It is stable within one
// daemon process so MusicPD reconnects hit the same plan, but cannot be guessed
// from a Qobuz track ID by another LAN client.
class SegmentedTrackRegistry {
public:
    ~SegmentedTrackRegistry();

    static std::string tokenForTrack(uint32_t track_id, int format_id);

    void                              registerPlan(const std::string& token,
                                                    std::shared_ptr<SegmentedTrackPlan> plan);
    std::shared_ptr<SegmentedTrackPlan> get(const std::string& token) const;
    void                              erase(const std::string& token);
    void                              retainOnly(
        const std::unordered_set<std::string>& tokens);
    void                              prioritize(const std::string& token);
    std::string                       cachePath(const std::string& token) const;
    void                              clear();
    size_t                            size() const;
private:
    mutable std::mutex m_mu;
    std::map<std::string, std::shared_ptr<SegmentedTrackPlan>> m_plans;
};

// Construct a SegmentedTrackPlan: fetches segment 0 (the init segment) to
// extract the FLAC header and estimated per-segment lengths and derives the
// content key.  If the table is absent, n_segments from /file/url supplies the
// count; a present but truncated table is rejected.
bool buildSegmentedTrackPlan(
    const std::string& url_template,
    const std::vector<std::string>& http_headers,
    const std::string& keystr,
    const std::string& session_infos,
    uint32_t track_id, int format_id,
    int json_n_segments_fallback,
    int sampling_rate, int bit_depth, uint32_t duration_ms,
    SegmentedTrackPlan& out_plan,
    std::string* err_out = nullptr);

// Measure every segment's exact reconstructed length by fetching only a short
// prefix of each (box headers, no audio), in parallel.  Fills the plan's
// exact_* fields.  Costs roughly 64KB per segment — under 1% of a hi-res
// track — and is what makes a segmented track seekable, so it is worth doing
// before the first byte is served.  Returns false and leaves the plan's
// exact_* fields empty if any segment could not be measured; playback then
// falls back to the unseekable growing-cache behaviour.
bool probeSegmentedTrackGeometry(SegmentedTrackPlan& plan,
                                 std::string* err_out = nullptr);

// Measure one segment's exact reconstructed length from a prefix of its
// bytes, using only box headers.  full_size is the segment's total size (0 if
// unknown).  Returns false when the prefix stops short of the mdat header, in
// which case the caller should retry with more bytes.  Exposed for testing;
// probeSegmentedTrackGeometry() is the normal entry point.
bool segmentGeometryFromPrefix(const uint8_t* prefix, size_t prefix_len,
                               uint64_t full_size, uint64_t& out_len);

// Fetch and decrypt one audio segment (1-based index).  On success out_data
// contains the complete decrypted bytes.  Its measured size may differ from
// the corresponding Qobuz estimate.
bool fetchAndDecryptSegment(const SegmentedTrackPlan& plan,
                            size_t seg_1based,
                            std::vector<uint8_t>& out_data,
                            std::string* err_out = nullptr);

} // namespace QConnect
