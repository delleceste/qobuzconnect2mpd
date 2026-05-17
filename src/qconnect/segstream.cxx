/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "segstream.hxx"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cstring>
#include <regex>

namespace QConnect {

namespace {

static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

static bool fetchBinaryUrl(const std::string& url,
                           const std::vector<std::string>& headers,
                           std::vector<uint8_t>& out,
                           std::string* err_out = nullptr) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        if (err_out) *err_out = "curl_easy_init failed";
        return false;
    }
    std::string buf;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    struct curl_slist* hdrs = nullptr;
    for (const auto& h : headers) hdrs = curl_slist_append(hdrs, h.c_str());
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    if (rc == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        if (err_out) *err_out = curl_easy_strerror(rc);
        return false;
    }
    if (code != 200) {
        if (err_out) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "HTTP %ld", code);
            *err_out = tmp;
        }
        return false;
    }
    out.assign(buf.begin(), buf.end());
    return true;
}

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
        if (sz < 8 || pos + sz > data.size()) break;
        if (pos + 24 <= data.size() &&
            memcmp(&data[pos + 4], "uuid", 4) == 0 &&
            memcmp(&data[pos + 8], QBZ_INIT_UUID, 16) == 0) {
            const uint8_t* p = data.data() + pos + 24;
            size_t len = sz - 24;
            if (len < 28) return false;
            size_t a = 4 + 4 + 4 + 4 + 1 + 3 + 6;
            if (a + 2 > len) return false;
            uint16_t raw_len = (uint16_t(p[a]) << 8) | uint16_t(p[a + 1]); a += 2;
            if (a + raw_len > len) raw_len = static_cast<uint16_t>(len - a);
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
            if (a + 1 > len) return true;
            uint8_t key_id_len = p[a]; a += 1 + key_id_len;
            if (a + 2 > len) return true;
            uint16_t seg_count = (uint16_t(p[a]) << 8) | uint16_t(p[a + 1]); a += 2;
            out.segment_byte_lens.clear();
            for (uint16_t i = 0; i < seg_count; ++i) {
                if (a + 8 > len) break;
                uint32_t blen = (uint32_t(p[a]) << 24) | (uint32_t(p[a + 1]) << 16) |
                                (uint32_t(p[a + 2]) << 8) | uint32_t(p[a + 3]);
                a += 8; // skip sample_count too
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
    size_t mdat_end = data.size();
    size_t pos = 0;
    while (pos + 8 <= data.size()) {
        size_t sz = readBoxSize(data, pos);
        if (sz < 8 || pos + sz > data.size()) break;
        if (memcmp(&data[pos + 4], "uuid", 4) == 0 && pos + 24 <= data.size() &&
            memcmp(&data[pos + 8], QBZ_SEG_UUID, 16) == 0) {
            uuid_pos = pos;
        } else if (memcmp(&data[pos + 4], "mdat", 4) == 0) {
            mdat_end = pos + sz;
        }
        pos += sz;
    }
    if (uuid_pos == std::string::npos) return false;
    size_t base = uuid_pos + 24;
    if (base + 12 > data.size()) return false;
    size_t a = base + 4;
    uint32_t data_off_raw = (uint32_t(data[a]) << 24) | (uint32_t(data[a + 1]) << 16) |
                            (uint32_t(data[a + 2]) << 8) | uint32_t(data[a + 3]);
    out.data_offset = uuid_pos + data_off_raw; a += 4;
    size_t iv_size = data[a++]; // usually 8
    size_t frame_count = (size_t(data[a]) << 16) | (size_t(data[a + 1]) << 8) | size_t(data[a + 2]); a += 3;
    size_t ent_sz = 4 + 2 + 2 + iv_size;
    if (a + frame_count * ent_sz > data.size()) return false;
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
    return true;
}

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

static void decryptCtrFrame(const uint8_t content_key[16], const uint8_t iv8[8],
                            uint8_t* data, size_t len) {
    uint8_t nonce[16] = {0};
    memcpy(nonce, iv8, 8);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return;
    int outlen = 0;
    EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), nullptr, content_key, nonce);
    EVP_EncryptUpdate(c, data, &outlen, data, len);
    EVP_CIPHER_CTX_free(c);
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
        if (p + e.size > seg.size()) break;
        size_t before = out.size();
        out.insert(out.end(), seg.begin() + p, seg.begin() + p + e.size);
        if (e.flags != 0)
            decryptCtrFrame(content_key, e.iv, out.data() + before, e.size);
        p += e.size;
    }
    if (p < c.mdat_end && c.mdat_end <= seg.size())
        out.insert(out.end(), seg.begin() + p, seg.begin() + c.mdat_end);
    return true;
}

} // anonymous namespace

// ---- SegmentedTrackPlan -----------------------------------------------------

bool SegmentedTrackPlan::mapAudioOffset(uint64_t audio_off,
                                         size_t& out_seg_1based,
                                         size_t& out_in_seg) const {
    if (segment_offsets.size() < 2) return false;
    if (audio_off >= segment_offsets.back()) return false;
    // Binary search for the segment that contains audio_off.
    size_t lo = 0, hi = segment_offsets.size() - 1;
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (segment_offsets[mid] <= audio_off) lo = mid;
        else hi = mid;
    }
    out_seg_1based = lo + 1;
    out_in_seg = static_cast<size_t>(audio_off - segment_offsets[lo]);
    return true;
}

// ---- SegmentedTrackRegistry -------------------------------------------------

std::string SegmentedTrackRegistry::tokenForTrack(uint32_t track_id, int format_id) {
    return std::to_string(track_id) + "_" + std::to_string(format_id) + ".flac";
}

void SegmentedTrackRegistry::registerPlan(const std::string& token,
                                           std::shared_ptr<SegmentedTrackPlan> plan) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_plans[token] = std::move(plan);
}

std::shared_ptr<SegmentedTrackPlan>
SegmentedTrackRegistry::get(const std::string& token) const {
    std::lock_guard<std::mutex> lk(m_mu);
    auto it = m_plans.find(token);
    return (it == m_plans.end()) ? nullptr : it->second;
}

void SegmentedTrackRegistry::erase(const std::string& token) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_plans.erase(token);
}

void SegmentedTrackRegistry::clear() {
    std::lock_guard<std::mutex> lk(m_mu);
    m_plans.clear();
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
    std::vector<uint8_t> seg0;
    {
        std::string err;
        if (!fetchBinaryUrl(std::regex_replace(url_template,
                                                std::regex("\\$SEGMENT\\$"), "0"),
                            http_headers, seg0, &err)) {
            if (err_out) *err_out = "init segment fetch failed: " + err;
            return false;
        }
    }

    CmafInitInfo init;
    if (!parseInitSegment(seg0, init)) {
        if (err_out) *err_out = "init segment parse failed";
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

    // Fallback: if the init segment didn't carry the per-segment table, use
    // n_segments from the JSON response — but without sizes we can't support
    // Content-Length or Range, so leave total_bytes==0 in that case.
    if (out.segment_byte_lens.empty() && json_n_segments_fallback > 1) {
        // Synthesize a count-only entry list with unknown sizes (0).  Range
        // requests won't be satisfiable but linear playback still works.
        out.segment_byte_lens.assign(json_n_segments_fallback - 1, 0);
    }

    out.segment_offsets.clear();
    out.segment_offsets.reserve(out.segment_byte_lens.size() + 1);
    uint64_t acc = 0;
    out.segment_offsets.push_back(0);
    for (uint32_t blen : out.segment_byte_lens) {
        acc += blen;
        out.segment_offsets.push_back(acc);
    }
    // total_bytes = 0 if any segment length is unknown (i.e. fallback path).
    bool any_unknown = false;
    for (uint32_t b : out.segment_byte_lens)
        if (b == 0) { any_unknown = true; break; }
    out.total_bytes = any_unknown ? 0 : out.flac_header.size() + acc;

    out.sampling_rate = sampling_rate;
    out.bit_depth = bit_depth;
    out.duration_ms = duration_ms;
    return true;
}

// ---- fetchAndDecryptSegment -------------------------------------------------

bool fetchAndDecryptSegment(const SegmentedTrackPlan& plan,
                            size_t seg_1based,
                            std::vector<uint8_t>& out_data,
                            std::string* err_out) {
    if (seg_1based == 0 || seg_1based > plan.n_audio_segments()) {
        if (err_out) *err_out = "segment index out of range";
        return false;
    }
    std::string url = std::regex_replace(plan.url_template,
                                          std::regex("\\$SEGMENT\\$"),
                                          std::to_string(seg_1based));
    std::vector<uint8_t> raw;
    if (!fetchBinaryUrl(url, plan.http_headers, raw, err_out))
        return false;
    if (!decryptSegment(raw, plan.content_key, out_data)) {
        if (err_out) *err_out = "decrypt failed";
        return false;
    }
    return true;
}

} // namespace QConnect
