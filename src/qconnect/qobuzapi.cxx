/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the
 *  Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

// Qobuz REST API client for qconnect2mpd.
//
// Request signing: MD5 of the concatenated parameter string with the
// app_secret appended.
//
// app_id and app_secret are extracted automatically from the Qobuz web
// player bundle.js when not configured explicitly (fetchAppCredentials).

#include "qobuzapi.hxx"
#include "qclog.hxx"

#include <curl/curl.h>
#include <json/json.h>

#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <thread>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <regex>
#include <sstream>

namespace QConnect {

// ---- Helpers ----------------------------------------------------------------

static uint64_t unixTimestamp() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

static std::string hexString(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    return ss.str();
}

// libcurl write callback
static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

static bool fetchBinaryUrl(const std::string& url,
                           const std::vector<std::string>& headers,
                           std::vector<uint8_t>& out) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
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
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || code != 200) return false;
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
    std::vector<uint8_t> flac_header;
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

static bool appendMaterializedSegment(std::ofstream& ofs,
                                      const std::vector<uint8_t>& seg,
                                      const uint8_t content_key[16]) {
    CmafSegmentCrypto c;
    if (!parseSegmentCrypto(seg, c)) return false;
    size_t p = c.data_offset;
    for (const auto& e : c.entries) {
        if (p + e.size > seg.size()) break;
        std::vector<uint8_t> frame(seg.begin() + p, seg.begin() + p + e.size);
        if (e.flags != 0) decryptCtrFrame(content_key, e.iv, frame.data(), frame.size());
        ofs.write(reinterpret_cast<const char*>(frame.data()), frame.size());
        p += e.size;
    }
    if (p < c.mdat_end && c.mdat_end <= seg.size()) {
        ofs.write(reinterpret_cast<const char*>(seg.data() + p), c.mdat_end - p);
    }
    ofs.flush();
    return ofs.good();
}

// ---- QobuzApi implementation ------------------------------------------------

QobuzApi::QobuzApi(const std::string& api_base_url,
                    const std::string& app_id,
                    const std::string& app_secret)
    : m_base_url(api_base_url), m_app_id(app_id), m_app_secret(app_secret)
{
    // Ensure no trailing slash
    while (!m_base_url.empty() && m_base_url.back() == '/')
        m_base_url.pop_back();
}

bool QobuzApi::login(const std::string& user, const std::string& pass) {
    if (user.empty() || pass.empty()) return false;

    std::string path = "/user/login?username=" + user + "&password=" + pass
                       + "&app_id=" + m_app_id;
    std::string resp = httpGet(path);
    if (resp.empty()) return false;

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::login: JSON parse error: " << errs << "\n");
        return false;
    }

    m_user_token = root.get("user_auth_token", "").asString();
    if (m_user_token.empty()) {
        LOGERR("QobuzApi::login: no user_auth_token in response\n");
        return false;
    }
    LOGDEB("QobuzApi::login: ok\n");
    return true;
}

std::string QobuzApi::buildRequestSignature(const std::string& method_prefix,
                                            const std::map<std::string, std::string>& args,
                                            uint64_t ts) const {
    std::string plain = method_prefix;
    for (const auto& kv : args) {
        plain += kv.first;
        plain += kv.second;
    }
    plain += std::to_string(ts);
    plain += m_app_secret;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, plain.data(), plain.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    return hexString(digest, digest_len);
}

bool QobuzApi::getStreamUrl(uint32_t track_id, int format_id,
                              TrackStreamInfo& out) {
    bool refreshed_credentials = false;
retry_after_refresh:
    if (!ensureStreamSession()) {
        if (!refreshed_credentials && fetchAppCredentials()) {
            m_app_secret.clear();
            m_stream_session_id.clear();
            m_stream_session_expires_at = 0;
            refreshed_credentials = true;
            goto retry_after_refresh;
        }
        LOGERR("QobuzApi: unable to establish stream session for /file/url\n");
        return false;
    }

    // Try requested format, then fall back to lower qualities via /file/url only.
    static const int fallback_fmts[] = {27, 7, 6, 5};
    for (int fmt : fallback_fmts) {
        if (fmt > format_id) continue;

        long file_code = 0;
        if (tryFileUrl(track_id, fmt, out, &file_code))
            return true;
        if (file_code == 400 && !refreshed_credentials) {
            LOGINF("QobuzApi: /file/url signature rejected; refreshing app credentials and retrying\n");
            if (fetchAppCredentials()) {
                m_app_secret.clear();
                m_stream_session_id.clear();
                m_stream_session_expires_at = 0;
                refreshed_credentials = true;
                goto retry_after_refresh;
            }
        }
    }
    return false;
}

bool QobuzApi::ensureStreamSession() {
    uint64_t now = unixTimestamp();
    if (!m_stream_session_id.empty() &&
        m_stream_session_expires_at > now + 30) {
        return true;
    }

    if (!m_app_secret.empty() && startStreamSession())
        return true;

    if (!m_secret_candidates.empty()) {
        // qobuz-player currently uses this secret for session/file signing.
        static const std::string kPreferred = "abb21364945c0583309667d13ca3d93a";
        auto it = std::find(m_secret_candidates.begin(), m_secret_candidates.end(), kPreferred);
        if (it != m_secret_candidates.end() && it != m_secret_candidates.begin())
            std::iter_swap(m_secret_candidates.begin(), it);

        for (const auto& cand : m_secret_candidates) {
            m_app_secret = cand;
            if (startStreamSession()) {
                LOGINF("QobuzApi: active secret confirmed via session/start\n");
                m_secret_candidates.clear();
                return true;
            }
        }
    }
    return false;
}

bool QobuzApi::startStreamSession() {
    if (m_app_secret.empty()) return false;

    uint64_t ts = unixTimestamp();
    std::map<std::string, std::string> sigargs;
    sigargs["profile"] = "qbz-1";
    std::string sig = buildRequestSignature("sessionstart", sigargs, ts);

    std::map<std::string, std::string> form;
    form["profile"] = "qbz-1";
    form["request_ts"] = std::to_string(ts);
    form["request_sig"] = sig;

    long http_code = 0;
    std::string resp = httpPostForm("/session/start", form, &http_code);
    if (resp.empty()) return false;

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::startStreamSession: JSON parse error: " << errs << "\n");
        return false;
    }
    std::string sid = root.get("session_id", "").asString();
    if (sid.empty()) return false;

    m_stream_session_id = sid;
    m_stream_session_expires_at = root.get("expires_at", 0).asUInt64();
    m_stream_session_infos = root.get("infos", "").asString();
    LOGDEB("QobuzApi: session/start ok sid=" << sid << " exp=" << m_stream_session_expires_at << "\n");
    return true;
}

bool QobuzApi::tryFileUrl(uint32_t track_id, int format_id,
                          TrackStreamInfo& out, long* http_code) {
    if (m_stream_session_id.empty()) return false;
    uint64_t ts = unixTimestamp();
    std::map<std::string, std::string> sigargs;
    sigargs["format_id"] = std::to_string(format_id);
    sigargs["intent"] = "stream";
    sigargs["track_id"] = std::to_string(track_id);
    std::string sig = buildRequestSignature("fileurl", sigargs, ts);

    std::string path = "/file/url"
                       "?track_id="  + std::to_string(track_id)
                     + "&format_id=" + std::to_string(format_id)
                     + "&intent=stream"
                     + "&request_ts="  + std::to_string(ts)
                     + "&request_sig=" + sig;

    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: GET " << url << " [new-api]\n");
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    struct curl_slist* hdrs = nullptr;
    if (!m_user_token.empty()) {
        std::string authHdr = "X-User-Auth-Token: " + m_user_token;
        hdrs = curl_slist_append(hdrs, authHdr.c_str());
    }
    std::string appHdr = "X-App-Id: " + m_app_id;
    std::string sidHdr = "X-Session-Id: " + m_stream_session_id;
    hdrs = curl_slist_append(hdrs, appHdr.c_str());
    hdrs = curl_slist_append(hdrs, sidHdr.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code) *http_code = code;
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || code != 200 || result.empty()) return false;

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(result);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) return false;

    // If Qobuz still returns legacy direct URL, we can feed MPD directly.
    out.stream_url = root.get("url", "").asString();
    out.mime_type = root.get("mime_type", "audio/flac").asString();
    out.format_id = root.get("format_id", format_id).asInt();
    out.duration_ms = root.get("duration", 0).asUInt() * 1000;
    double sr = root.get("sampling_rate", 44.1).asDouble();
    out.sampling_rate = (sr < 1000) ? static_cast<int>(sr * 1000) : static_cast<int>(sr);
    out.bit_depth = root.isMember("bit_depth") ? root["bit_depth"].asInt() : -1;
    if (!out.stream_url.empty()) {
        LOGDEB("QobuzApi: /file/url returned direct URL\n");
        return true;
    }

    // Segmented stream path (url_template + key) needs decryption/reassembly
    // proxy before MPD can consume it. Materialize now.
    if (root.isMember("url_template")) {
        return materializeSegmentedTrack(root, track_id, format_id, out);
    }
    return false;
}

bool QobuzApi::materializeSegmentedTrack(const Json::Value& root, uint32_t track_id,
                                         int format_id, TrackStreamInfo& out) {
    namespace fs = std::filesystem;
    if (m_local_proxy_base_url.empty()) return false;
    std::string urltpl = root.get("url_template", "").asString();
    std::string keystr = root.get("key", "").asString();
    if (urltpl.empty() || keystr.empty() || m_stream_session_infos.empty())
        return false;

    std::vector<std::string> hdrs;
    if (!m_user_token.empty()) hdrs.push_back("X-User-Auth-Token: " + m_user_token);
    hdrs.push_back("X-App-Id: " + m_app_id);
    hdrs.push_back("X-Session-Id: " + m_stream_session_id);

    std::vector<uint8_t> seg0;
    if (!fetchBinaryUrl(std::regex_replace(urltpl, std::regex("\\$SEGMENT\\$"), "0"), hdrs, seg0))
        return false;

    CmafInitInfo init;
    if (!parseInitSegment(seg0, init)) return false;

    uint8_t session_key[16], content_key[16];
    if (!deriveSessionKey(m_stream_session_infos, session_key)) return false;
    if (!unwrapContentKey(session_key, keystr, content_key)) return false;

    fs::create_directories("/tmp/qconnect2mpd-segmented");
    std::string file_name = std::to_string(track_id) + "_" +
                            std::to_string(format_id) + "_" +
                            std::to_string(unixTimestamp()) + ".flac";
    std::string final_path = "/tmp/qconnect2mpd-segmented/" + file_name;
    std::string marker_path = final_path + ".inprogress";

    std::ofstream marker(marker_path, std::ios::binary);
    marker.close();

    std::ofstream ofs(final_path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(init.flac_header.data()), init.flac_header.size());
    ofs.flush();

    size_t n_audio = init.segment_byte_lens.empty()
                     ? static_cast<size_t>(root.get("n_segments", 1).asUInt()) - 1
                     : init.segment_byte_lens.size();
    if (n_audio == 0) {
        ofs.close();
        fs::remove(marker_path);
    } else {
        std::vector<uint8_t> seg1;
        if (!fetchBinaryUrl(std::regex_replace(urltpl, std::regex("\\$SEGMENT\\$"), "1"), hdrs, seg1) ||
            !appendMaterializedSegment(ofs, seg1, content_key)) {
            ofs.close();
            fs::remove(final_path);
            fs::remove(marker_path);
            return false;
        }
        ofs.close();

        if (n_audio > 1) {
            std::thread([urltpl, hdrs, final_path, marker_path, n_audio, content_key]() {
                namespace fs = std::filesystem;
                std::ofstream append(final_path, std::ios::binary | std::ios::app);
                if (!append) {
                    fs::remove(marker_path);
                    return;
                }
                for (size_t i = 2; i <= n_audio; ++i) {
                    std::vector<uint8_t> seg;
                    if (!fetchBinaryUrl(std::regex_replace(urltpl, std::regex("\\$SEGMENT\\$"),
                                                           std::to_string(i)), hdrs, seg) ||
                        !appendMaterializedSegment(append, seg, content_key)) {
                        LOGERR("QobuzApi: background materialization failed at segment "
                               << i << " for " << final_path << "\n");
                        break;
                    }
                }
                append.close();
                fs::remove(marker_path);
            }).detach();
        } else {
            fs::remove(marker_path);
        }
    }

    out.stream_url = m_local_proxy_base_url + "/" + file_name;
    out.local_path = final_path;
    out.mime_type = "audio/flac";
    out.format_id = root.get("format_id", format_id).asInt();
    out.duration_ms = static_cast<uint32_t>(root.get("duration", 0).asDouble() * 1000.0);
    double sr = root.get("sampling_rate", 44.1).asDouble();
    out.sampling_rate = (sr < 1000) ? static_cast<int>(sr * 1000) : static_cast<int>(sr);
    out.bit_depth = root.isMember("bit_depth") ? root["bit_depth"].asInt() : -1;
    LOGINF("QobuzApi: started segmented materialization at " << final_path << "\n");
    return true;
}

bool QobuzApi::getTrackMeta(uint32_t track_id, TrackMeta& out) {
    std::string path = "/track/get?track_id=" + std::to_string(track_id)
                     + "&app_id=" + m_app_id;
    std::string resp = httpGet(path);
    if (resp.empty()) return false;

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::getTrackMeta: JSON parse error: " << errs << "\n");
        return false;
    }

    out.track_id   = track_id;
    out.title      = root.get("title", "").asString();
    out.duration_s = root.get("duration", 0).asUInt();

    if (root.isMember("performer"))
        out.artist = root["performer"].get("name", "").asString();

    if (root.isMember("album"))
        out.album = root["album"].get("title", "").asString();

    return true;
}

// ---- fetchRawUrl: plain HTTPS GET to any URL, no auth headers ---------------

static std::string fetchRawUrl(const std::string& url) {
    LOGDEB("QobuzApi: fetchRawUrl " << url.substr(0, 80) << "\n");
    CURL* curl = curl_easy_init();
    if (!curl) return {};

    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    // Accept gzip so bundle.js arrives compressed and is decompressed by curl
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs,
        "User-Agent: Mozilla/5.0 (X11; FreeBSD x86_64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOGERR("QobuzApi: fetchRawUrl failed: " << curl_easy_strerror(rc) << "\n");
        result.clear();
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            LOGERR("QobuzApi: fetchRawUrl HTTP " << http_code << "\n");
            result.clear();
        }
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

// ---- base64url decode -------------------------------------------------------

static std::string base64urlDecode(const std::string& in) {
    if (in.empty()) return {};
    std::string s = in;
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Pad to a multiple of 4
    size_t pad = (4 - s.size() % 4) % 4;
    s.append(pad, '=');

    // Count total '=' padding (original + added) to compute actual data length
    size_t total_pad = 0;
    for (size_t i = s.size(); i > 0 && s[i - 1] == '='; --i)
        ++total_pad;

    std::vector<unsigned char> buf(s.size());
    int outlen = EVP_DecodeBlock(
        buf.data(),
        reinterpret_cast<const unsigned char*>(s.data()),
        static_cast<int>(s.size()));
    if (outlen < 0) return {};
    outlen -= static_cast<int>(total_pad);
    if (outlen < 0) return {};
    return std::string(reinterpret_cast<char*>(buf.data()), outlen);
}

// ---- fetchAppCredentials ----------------------------------------------------

bool QobuzApi::fetchAppCredentials() {
    const std::string play_url = "https://play.qobuz.com";

    // Step 1: fetch the login page to find the versioned bundle.js path
    std::string login_html = fetchRawUrl(play_url + "/login");
    if (login_html.empty()) {
        LOGERR("QobuzApi: fetchAppCredentials: could not fetch play.qobuz.com/login\n");
        return false;
    }

    // <script src="/resources/8.1.0-b019/bundle.js"></script>
    std::regex bundle_re(
        R"rx(<script src="(/resources/[\d.]+-[a-z0-9]+/bundle\.js)"></script>)rx");
    std::smatch bm;
    if (!std::regex_search(login_html, bm, bundle_re)) {
        LOGERR("QobuzApi: fetchAppCredentials: bundle.js path not found\n");
        return false;
    }
    std::string bundle_path = bm[1].str();
    LOGDEB("QobuzApi: fetchAppCredentials: bundle=" << bundle_path << "\n");

    // Step 2: fetch bundle.js (curl auto-decompresses gzip)
    std::string bundle = fetchRawUrl(play_url + bundle_path);
    if (bundle.empty()) {
        LOGERR("QobuzApi: fetchAppCredentials: could not fetch bundle.js\n");
        return false;
    }
    LOGDEB("QobuzApi: fetchAppCredentials: bundle.js size=" << bundle.size() << "\n");

    // Step 3: extract app_id
    // pattern: production:{api:{appId:"123456789",appSecret:"<32 hex chars>"
    std::regex appid_re(
        R"rx(production:\{api:\{appId:"(\d{9})",appSecret:"(\w{32})")rx");
    std::smatch am;
    if (!std::regex_search(bundle, am, appid_re)) {
        LOGERR("QobuzApi: fetchAppCredentials: app_id not found in bundle.js\n");
        return false;
    }
    m_app_id = am[1].str();
    LOGINF("QobuzApi: fetchAppCredentials: app_id=" << m_app_id << "\n");

    // Step 4: extract and decode secret candidates.
    // Pattern: x.initialSeed("SEED",window.utimezone.timezone)
    // Then for each seed, find:
    //   name:"<ns>/TimezoneXx",info:"INFO",extras:"EXTRAS"
    // The raw secret = base64url_decode( (seed+info+extras)[:-44] )
    m_secret_candidates.clear();
    std::regex seed_re(
        R"rx([a-z]\.initialSeed\("([\w=]+)",window\.utimezone\.([a-z]+)\))rx");

    for (auto it = std::sregex_iterator(bundle.begin(), bundle.end(), seed_re);
         it != std::sregex_iterator(); ++it) {
        std::string seed   = (*it)[1].str();
        std::string tz_raw = (*it)[2].str();
        // Capitalize first letter to match the name field
        std::string tz_cap = tz_raw;
        if (!tz_cap.empty()) tz_cap[0] = static_cast<char>(std::toupper(tz_cap[0]));

        std::string info_pat =
            "name:\"\\w+/(" + tz_cap + "[a-z]?)\",info:\"([\\w=]+)\",extras:\"([\\w=]+)\"";
        std::regex info_re(info_pat);
        for (auto jt = std::sregex_iterator(bundle.begin(), bundle.end(), info_re);
             jt != std::sregex_iterator(); ++jt) {
            std::string tz_full = (*jt)[1].str();
            std::string info    = (*jt)[2].str();
            std::string extras  = (*jt)[3].str();
            std::string chars   = seed + info + extras;
            if (chars.size() <= 44) continue;
            std::string encoded = chars.substr(0, chars.size() - 44);
            std::string secret  = base64urlDecode(encoded);
            if (!secret.empty()) {
                LOGDEB("QobuzApi: fetchAppCredentials: candidate ["
                       << tz_full << "] " << secret << "\n");
                m_secret_candidates.push_back(secret);
            }
        }
    }

    if (m_secret_candidates.empty()) {
        LOGERR("QobuzApi: fetchAppCredentials: no secrets decoded from bundle.js\n");
        return false;
    }
    LOGINF("QobuzApi: fetchAppCredentials: "
           << m_secret_candidates.size() << " secret candidate(s) ready\n");
    return true;
}

bool QobuzApi::fetchQwsToken(std::string& out_endpoint, std::string& out_jwt) {
    if (m_user_token.empty()) {
        LOGERR("QobuzApi::fetchQwsToken: no user token — call login() first\n");
        return false;
    }

    const std::string url = "https://www.qobuz.com/api.json/0.2/qws/createToken";
    const std::string post_body =
        "jwt=jwt_qws&user_auth_token_needed=true&strong_auth_needed=true";

    LOGINF("QobuzApi::fetchQwsToken: POST " << url << "\n");

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    post_body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,1L);

    struct curl_slist* hdrs = nullptr;
    std::string auth_hdr = "X-User-Auth-Token: " + m_user_token;
    std::string app_hdr  = "X-App-Id: "          + m_app_id;
    hdrs = curl_slist_append(hdrs, auth_hdr.c_str());
    hdrs = curl_slist_append(hdrs, app_hdr.c_str());
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        LOGERR("QobuzApi::fetchQwsToken: curl error: " << curl_easy_strerror(rc) << "\n");
        return false;
    }
    if (http_code != 200) {
        LOGERR("QobuzApi::fetchQwsToken: HTTP " << http_code
               << " body: " << result.substr(0, 300) << "\n");
        return false;
    }

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(result);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::fetchQwsToken: JSON parse error: " << errs << "\n");
        return false;
    }

    const Json::Value& jwt_payload = root["jwt_qws"];
    if (jwt_payload.isNull()) {
        LOGERR("QobuzApi::fetchQwsToken: response missing jwt_qws\n");
        return false;
    }

    out_endpoint = jwt_payload.get("endpoint", "wss://play.qobuz.com/ws").asString();
    out_jwt      = jwt_payload.get("jwt", "").asString();

    if (out_endpoint.empty()) {
        LOGERR("QobuzApi::fetchQwsToken: empty endpoint in response\n");
        return false;
    }

    LOGINF("QobuzApi::fetchQwsToken: ok, endpoint=" << out_endpoint << "\n");
    return true;
}

std::string QobuzApi::httpPostForm(const std::string& path,
                                   const std::map<std::string, std::string>& form,
                                   long* http_code_out) {
    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: POST " << url << "\n");
    CURL* curl = curl_easy_init();
    if (!curl) return {};

    std::string body;
    bool first = true;
    for (const auto& kv : form) {
        char* k = curl_easy_escape(curl, kv.first.c_str(), 0);
        char* v = curl_easy_escape(curl, kv.second.c_str(), 0);
        if (!first) body += "&";
        first = false;
        if (k) body += k;
        body += "=";
        if (v) body += v;
        if (k) curl_free(k);
        if (v) curl_free(v);
    }

    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    struct curl_slist* hdrs = nullptr;
    std::string appHdr = "X-App-Id: " + m_app_id;
    hdrs = curl_slist_append(hdrs, appHdr.c_str());
    if (!m_user_token.empty()) {
        std::string authHdr = "X-User-Auth-Token: " + m_user_token;
        hdrs = curl_slist_append(hdrs, authHdr.c_str());
    }
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code_out) *http_code_out = http_code;

    if (rc != CURLE_OK) {
        LOGERR("QobuzApi: POST curl failed: " << curl_easy_strerror(rc) << "\n");
        result.clear();
    } else if (http_code != 200) {
        LOGERR("QobuzApi: POST HTTP " << http_code << " for " << path << "\n");
        if (!result.empty())
            LOGERR("QobuzApi: response body: " << result.substr(0, 500) << "\n");
        result.clear();
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

std::string QobuzApi::httpGet(const std::string& path, long* http_code_out) {
    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: GET " << url << "\n");

    CURL* curl = curl_easy_init();
    if (!curl) return {};

    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Build auth header: use user_auth_token from login()
    // (JWT from the Qobuz app is for the WebSocket, not the REST API)
    struct curl_slist* hdrs = nullptr;
    std::string authHdr;
    if (!m_user_token.empty()) {
        authHdr = "X-User-Auth-Token: " + m_user_token;
    }
    if (!authHdr.empty()) {
        hdrs = curl_slist_append(hdrs, authHdr.c_str());
        std::string appHdr = "X-App-Id: " + m_app_id;
        hdrs = curl_slist_append(hdrs, appHdr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOGERR("QobuzApi: curl failed: " << curl_easy_strerror(rc) << "\n");
        result.clear();
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code_out) *http_code_out = http_code;
        if (http_code != 200) {
            LOGERR("QobuzApi: HTTP " << http_code << " for " << path << "\n");
            if (!result.empty())
                LOGERR("QobuzApi: response body: " << result.substr(0, 500) << "\n");
            result.clear();
        }
    }

    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace QConnect
