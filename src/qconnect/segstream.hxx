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
#include <vector>

namespace QConnect {

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
    // Decrypted byte length of each audio segment.  Size == n_audio_segments.
    std::vector<uint32_t> segment_byte_lens;
    // Cumulative offsets into the audio stream (excludes flac_header).
    // Size == n_audio_segments + 1.  Last entry == sum(segment_byte_lens).
    std::vector<uint64_t> segment_offsets;
    // Total content length in bytes (flac_header.size() + segment_offsets.back()).
    uint64_t total_bytes{0};

    int      sampling_rate{44100};
    int      bit_depth{-1};
    uint32_t duration_ms{0};

    size_t n_audio_segments() const { return segment_byte_lens.size(); }

    // Map an audio-stream byte offset (i.e. file_offset - flac_header.size())
    // to (seg_1based, offset_within_seg).  Returns false if out of range.
    bool mapAudioOffset(uint64_t audio_off,
                        size_t& out_seg_1based,
                        size_t& out_in_seg) const;
};

// Stable URL-safe token mapping a track to its plan.  Same input → same token,
// so MPD re-requesting the same URL after a reconnect hits the same plan.
class SegmentedTrackRegistry {
public:
    static std::string tokenForTrack(uint32_t track_id, int format_id);

    void                              registerPlan(const std::string& token,
                                                    std::shared_ptr<SegmentedTrackPlan> plan);
    std::shared_ptr<SegmentedTrackPlan> get(const std::string& token) const;
    void                              erase(const std::string& token);
    void                              clear();
    size_t                            size() const;
private:
    mutable std::mutex m_mu;
    std::map<std::string, std::shared_ptr<SegmentedTrackPlan>> m_plans;
};

// Construct a SegmentedTrackPlan: fetches segment 0 (the init segment) to
// extract the FLAC header and per-segment decrypted byte lengths, derives
// the content key, and fills total_bytes.
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

// Fetch and decrypt one audio segment (1-based index).  On success out_data
// contains the fully decrypted bytes for that segment (size matches the
// corresponding segment_byte_lens entry).
bool fetchAndDecryptSegment(const SegmentedTrackPlan& plan,
                            size_t seg_1based,
                            std::vector<uint8_t>& out_data,
                            std::string* err_out = nullptr);

} // namespace QConnect
