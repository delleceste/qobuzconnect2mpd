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
#include "segstream.hxx"

#include <curl/curl.h>
#include <json/json.h>

#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <openssl/evp.h>
#include <regex>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

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
    if (size != 0 && nmemb > std::numeric_limits<size_t>::max() / size)
        return 0;
    const size_t bytes = size * nmemb;
    constexpr size_t kMaxResponseBytes = 64 * 1024 * 1024;
    if (s->size() > kMaxResponseBytes ||
        bytes > kMaxResponseBytes - s->size())
        return 0;
    try {
        s->append(ptr, bytes);
    } catch (...) {
        return 0;
    }
    return bytes;
}

static std::string urlEncode(const std::string& value) {
    CURL* curl = curl_easy_init();
    if (!curl) return {};
    char* escaped = curl_easy_escape(curl, value.c_str(),
                                     static_cast<int>(value.size()));
    std::string result = escaped ? escaped : "";
    if (escaped) curl_free(escaped);
    curl_easy_cleanup(curl);
    return result;
}

static std::string endpointOnly(const std::string& path) {
    const auto query = path.find('?');
    return path.substr(0, query);
}

// (Segment fetch/decrypt and per-track plan building live in segstream.cxx.
//  This file no longer materializes anything to disk — it just constructs
//  the plan and registers it with the SegmentedTrackRegistry.)

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

std::string QobuzApi::buildRequestSignature(const std::string& method_prefix,
                                            const std::map<std::string, std::string>& args,
                                            uint64_t ts,
                                            const std::string& secret) const {
    std::string plain = method_prefix;
    for (const auto& kv : args) {
        plain += kv.first;
        plain += kv.second;
    }
    plain += std::to_string(ts);
    plain += secret;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, plain.data(), plain.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    return hexString(digest, digest_len);
}

StreamMode streamModeFromString(const std::string& v) {
    if (v == "segmented") return StreamMode::Segmented;
    if (v == "auto")      return StreamMode::Auto;
    return StreamMode::Direct;
}

const char* streamModeName(StreamMode m) {
    switch (m) {
    case StreamMode::Segmented: return "segmented";
    case StreamMode::Auto:      return "auto";
    case StreamMode::Direct:    break;
    }
    return "direct";
}

bool QobuzApi::getStreamUrl(uint32_t track_id, int format_id,
                              TrackStreamInfo& out) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_user_token.empty()) {
        LOGERR("QobuzApi::getStreamUrl: no OAuth user token\n");
        return false;
    }
    const bool want_direct    = m_stream_mode != StreamMode::Segmented;
    const bool want_segmented = m_stream_mode != StreamMode::Direct;

    bool refreshed_credentials = false;
retry_after_refresh:
    // The CMAF flow needs a stream session; the direct endpoint does not, so
    // do not pay for one (or log about it) unless segmented is reachable.
    bool have_stream_session = false;
    if (want_segmented) {
        have_stream_session = ensureStreamSession();
        if (!have_stream_session && want_direct) {
            LOGINF("QobuzApi: no stream session for /file/url; direct endpoint only\n");
        } else if (!have_stream_session) {
            LOGERR("QobuzApi: unable to establish stream session for /file/url\n");
        }
    }

    // Try the requested format, then fall back to lower qualities.
    //
    // Direct /track/getFileUrl is preferred: it hands MPD a signed CDN URL
    // with a Content-Length and byte-range support, which is the only shape
    // libFLAC can seek. The CMAF /file/url flow produces a reconstructed
    // stream of unknown length that MPD cannot seek until it is complete, so
    // it is a fallback for the day Qobuz retires the direct endpoint rather
    // than the normal path. See 'qconnectstreammode'.
    static const int fallback_fmts[] = {27, 7, 6, 5};
    for (int fmt : fallback_fmts) {
        if (fmt > format_id) continue;

        if (want_direct) {
            long legacy_code = 0;
            if (tryGetStreamUrl(track_id, fmt, out, &legacy_code))
                return true;
            if (legacy_code == 400 && !refreshed_credentials) {
                LOGINF("QobuzApi: getFileUrl signature rejected; refreshing app credentials and retrying\n");
                if (fetchAppCredentials()) {
                    m_app_secret.clear();
                    m_stream_session_id.clear();
                    m_stream_session_expires_at = 0;
                    refreshed_credentials = true;
                    goto retry_after_refresh;
                }
            }
        }

        if (have_stream_session) {
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
    std::string sig = buildRequestSignature("sessionstart", sigargs, ts,
                                            m_app_secret);

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
    LOGDEB("QobuzApi: session/start ok, expires="
           << m_stream_session_expires_at << "\n");
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
    std::string sig = buildRequestSignature("fileurl", sigargs, ts,
                                            m_app_secret);

    std::string path = "/file/url"
                       "?track_id="  + std::to_string(track_id)
                     + "&format_id=" + std::to_string(format_id)
                     + "&intent=stream"
                     + "&request_ts="  + std::to_string(ts)
                     + "&request_sig=" + sig;

    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: GET /file/url [new-api]\n");
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

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
        out.local_path.clear();
        out.segment_token.clear();
        LOGDEB("QobuzApi: /file/url returned direct URL\n");
        return true;
    }

    // Segmented stream path (url_template + key) — build a plan and register
    // it with the proxy.  No disk I/O, no segment downloads here; the HTTP
    // proxy will fetch+decrypt segments on demand as MPD reads from the URL.
    if (root.isMember("url_template")) {
        return planSegmentedTrack(root, track_id, format_id, out);
    }
    return false;
}

bool QobuzApi::planSegmentedTrack(const Json::Value& root, uint32_t track_id,
                                   int format_id, TrackStreamInfo& out) {
    if (m_local_proxy_base_url.empty()) {
        LOGERR("QobuzApi: plan track " << track_id
               << ": local proxy base URL not set\n");
        return false;
    }
    if (!m_seg_registry) {
        LOGERR("QobuzApi: plan track " << track_id
               << ": SegmentedTrackRegistry not wired in\n");
        return false;
    }
    std::string urltpl = root.get("url_template", "").asString();
    std::string keystr = root.get("key", "").asString();
    if (urltpl.empty() || keystr.empty() || m_stream_session_infos.empty()) {
        LOGERR("QobuzApi: plan track " << track_id
               << ": missing url_template/key/session_infos\n");
        return false;
    }

    // The template is already signed. Qobuz's own client sends no API/session
    // headers to the CDN, which also prevents bearer-token leakage on redirects.
    const std::vector<std::string> segment_headers;

    double sr_raw = root.get("sampling_rate", 44.1).asDouble();
    int sampling_rate = (sr_raw < 1000) ? static_cast<int>(sr_raw * 1000)
                                         : static_cast<int>(sr_raw);
    int bit_depth = root.isMember("bit_depth") ? root["bit_depth"].asInt() : -1;
    uint32_t duration_ms =
        static_cast<uint32_t>(root.get("duration", 0).asDouble() * 1000.0);
    int n_seg_fallback = root.get("n_segments", 0).asInt();
    int effective_format_id = root.get("format_id", format_id).asInt();

    auto plan = std::make_shared<SegmentedTrackPlan>();
    std::string err;
    if (!buildSegmentedTrackPlan(urltpl, segment_headers, keystr,
                                  m_stream_session_infos,
                                  track_id, effective_format_id, n_seg_fallback,
                                  sampling_rate, bit_depth, duration_ms,
                                  *plan, &err)) {
        LOGERR("QobuzApi: plan track " << track_id << " failed: " << err << "\n");
        return false;
    }

    // Measure the exact reconstructed length before serving anything: this
    // costs ~64KB per segment and is what lets the proxy publish a real
    // Content-Length, without which MusicPD's FLAC decoder cannot seek.
    // Failure is not fatal — playback still works, just unseekable.
    std::string geom_err;
    if (!probeSegmentedTrackGeometry(*plan, &geom_err)) {
        LOGERR("QobuzApi: track " << track_id
               << ": exact geometry unavailable (" << geom_err
               << "); this track will not be seekable\n");
    }

    std::string token = SegmentedTrackRegistry::tokenForTrack(
        track_id, effective_format_id);
    m_seg_registry->registerPlan(token, plan);

    out.stream_url   = m_local_proxy_base_url + "/" + token;
    out.local_path.clear(); // nothing on disk
    out.segment_token = token;
    out.mime_type    = "audio/flac";
    out.format_id    = effective_format_id;
    out.duration_ms  = duration_ms;
    out.sampling_rate = plan->sampling_rate;
    out.bit_depth    = plan->bit_depth;
    LOGDEB("QobuzApi: track " << track_id << " ["
           << plan->sampling_rate << ","
           << (plan->bit_depth > 0 ? std::to_string(plan->bit_depth) : "?")
           << (plan->channels > 0
               ? "," + std::to_string(plan->channels) : std::string{})
           << "]: planned " << plan->n_audio_segments()
           << " encrypted audio segments for FLAC reconstruction"
              " (estimated " << plan->total_bytes << " bytes)\n");
    return true;
}

bool QobuzApi::tryGetStreamUrl(uint32_t track_id, int format_id,
                                TrackStreamInfo& out, long* http_code) {
    auto do_call = [&](const std::string& secret, long* code_out) {
        const uint64_t ts = unixTimestamp();
        static const std::string method_prefix = "trackgetFileUrl";
        LOGDEB("QobuzApi: getFileUrl signing method=" << method_prefix
               << " track_id=" << track_id
               << " fmt=" << format_id
               << " ts=" << ts << "\n");

        std::map<std::string, std::string> sigargs;
        sigargs["format_id"] = std::to_string(format_id);
        sigargs["intent"] = "stream";
        sigargs["track_id"] = std::to_string(track_id);
        std::string sig = buildRequestSignature(method_prefix, sigargs, ts,
                                                secret);

        std::string path = "/track/getFileUrl"
                           "?track_id="  + std::to_string(track_id)
                         + "&format_id=" + std::to_string(format_id)
                         + "&intent=stream"
                         + "&request_ts="  + std::to_string(ts)
                         + "&request_sig=" + sig
                         + "&app_id="    + m_app_id;
        return httpGet(path, code_out, true);
    };

    // The current session secret and the classic API secret are not
    // necessarily the same bundle.js candidate. Probe a cached classic secret
    // first, then all retained bundle candidates, then the active session
    // secret. Keep candidates unique so a failed signature is not retried.
    std::vector<std::string> secrets;
    auto append_secret = [&secrets](const std::string& secret) {
        if (!secret.empty() &&
            std::find(secrets.begin(), secrets.end(), secret) == secrets.end())
            secrets.push_back(secret);
    };
    append_secret(m_classic_secret);
    for (const auto& candidate : m_bundle_secrets)
        append_secret(candidate);
    append_secret(m_app_secret);

    long code = 0;
    std::string resp;
    std::string accepted_secret;
    for (const auto& secret : secrets) {
        long attempt_code = 0;
        resp = do_call(secret, &attempt_code);
        code = attempt_code;
        if (!resp.empty()) {
            accepted_secret = secret;
            break;
        }
        // A 404 means the signature was accepted but this track is not
        // available in the requested format. Remember the secret so the next
        // lower-quality attempt does not repeat the full probe sequence.
        if (attempt_code == 404) {
            if (m_classic_secret != secret) {
                m_classic_secret = secret;
                LOGINF("QobuzApi: classic getFileUrl secret confirmed\n");
            }
            break;
        }
        // Qobuz reports invalid request signatures as HTTP 400. Other errors
        // are independent of the candidate, so do not multiply requests.
        if (attempt_code != 400)
            break;
    }
    if (http_code) *http_code = code;
    if (resp.empty()) return false;

    LOGDEB("QobuzApi: getFileUrl succeeded with method=trackgetFileUrl"
           << " (HTTP " << code << ")\n");

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::getStreamUrl: JSON parse error: " << errs << "\n");
        return false;
    }

    out.stream_url    = root.get("url", "").asString();
    out.mime_type     = root.get("mime_type", "audio/flac").asString();
    out.format_id     = root.get("format_id", format_id).asInt();
    out.duration_ms   = root.get("duration", 0).asUInt() * 1000;
    double sr = root.get("sampling_rate", 44.1).asDouble();
    out.sampling_rate = (sr < 1000) ? static_cast<int>(sr * 1000) : static_cast<int>(sr);
    out.bit_depth     = root.isMember("bit_depth") ? root["bit_depth"].asInt() : -1;

    if (out.stream_url.empty()) {
        LOGERR("QobuzApi::getStreamUrl: no url in response for track "
               << track_id << "\n");
        return false;
    }
    out.local_path.clear();
    out.segment_token.clear();
    if (m_classic_secret != accepted_secret) {
        m_classic_secret = accepted_secret;
        LOGINF("QobuzApi: classic getFileUrl secret confirmed\n");
    }
    return true;
}

bool QobuzApi::getTrackMeta(uint32_t track_id, TrackMeta& out) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
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

    std::string label;
    if (!out.artist.empty()) label = out.artist;
    if (!out.title.empty()) {
        if (!label.empty()) label += " - ";
        label += out.title;
    }
    if (!out.album.empty()) label += " [" + out.album + "]";
    if (!label.empty())
        LOGINF("QobuzApi: track " << track_id << ": " << label << "\n");

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
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,       1L);
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

// ---- OAuth login ------------------------------------------------------------

bool QobuzApi::oauthExchangeCode(const std::string& code) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    // Private key is hardcoded in the Qobuz player (extracted from qobuz-player v0.9.0).
    static const std::string kPrivateKey = "6lz8C03UDIC7";
    std::string path = "/oauth/callback?code=" + urlEncode(code)
                       + "&private_key=" + urlEncode(kPrivateKey);
    std::string resp = httpGet(path);
    if (resp.empty()) {
        LOGERR("QobuzApi::oauthExchangeCode: empty response\n");
        return false;
    }
    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::oauthExchangeCode: JSON parse error: " << errs << "\n");
        return false;
    }
    // Response has either "token" or "user_auth_token"
    std::string tok = root.get("token", "").asString();
    if (tok.empty()) tok = root.get("user_auth_token", "").asString();
    if (tok.empty()) {
        LOGERR("QobuzApi::oauthExchangeCode: response contained no token\n");
        return false;
    }
    m_user_token = tok;
    LOGINF("QobuzApi::oauthExchangeCode: user_auth_token obtained\n");
    return true;
}

std::string QobuzApi::buildOAuthUrl(const std::string& redirect_url) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return "https://www.qobuz.com/signin/oauth?ext_app_id=" + urlEncode(m_app_id)
           + "&redirect_url=" + urlEncode(redirect_url);
}

bool QobuzApi::saveToken(const std::string& path) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_user_token.empty() || path.empty()) return false;
    namespace fs = std::filesystem;
    fs::path p(path);
    if (p.filename().empty()) return false;
    fs::path parent = p.has_parent_path() ? p.parent_path() : fs::path(".");
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(parent, ec);
        if (ec) {
            LOGERR("QobuzApi::saveToken: cannot create token directory\n");
            return false;
        }
    }

    int dir_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat dir_stat{};
    if (dir_fd < 0 || ::fstat(dir_fd, &dir_stat) != 0 ||
        !S_ISDIR(dir_stat.st_mode) || dir_stat.st_uid != ::geteuid()) {
        LOGERR("QobuzApi::saveToken: token directory is not securely owned\n");
        if (dir_fd >= 0) ::close(dir_fd);
        return false;
    }

    std::string pattern = (parent / (p.filename().string() + ".tmp.XXXXXX")).string();
    std::vector<char> tmp_path(pattern.begin(), pattern.end());
    tmp_path.push_back('\0');
    int fd = ::mkstemp(tmp_path.data());
    if (fd < 0) {
        LOGERR("QobuzApi::saveToken: cannot write " << path << "\n");
        ::close(dir_fd);
        return false;
    }
    auto discard_temp = [&]() {
        ::close(fd);
        ::unlink(tmp_path.data());
        ::close(dir_fd);
    };
    if (::fchmod(fd, 0600) != 0) {
        LOGERR("QobuzApi::saveToken: cannot restrict permissions on "
               << path << "\n");
        discard_temp();
        return false;
    }
    size_t written = 0;
    while (written < m_user_token.size()) {
        ssize_t n = ::write(fd, m_user_token.data() + written,
                            m_user_token.size() - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            LOGERR("QobuzApi::saveToken: write failed for " << path << "\n");
            discard_temp();
            return false;
        }
        written += static_cast<size_t>(n);
    }
    const bool sync_ok = ::fsync(fd) == 0;
    const int close_result = ::close(fd);
    if (!sync_ok || close_result != 0) {
        fd = -1;
        LOGERR("QobuzApi::saveToken: could not flush " << path << "\n");
        ::unlink(tmp_path.data());
        ::close(dir_fd);
        return false;
    }
    fd = -1;
    if (::rename(tmp_path.data(), path.c_str()) != 0) {
        LOGERR("QobuzApi::saveToken: cannot install " << path << "\n");
        ::unlink(tmp_path.data());
        ::close(dir_fd);
        return false;
    }
    (void)::fsync(dir_fd);
    ::close(dir_fd);
    LOGINF("QobuzApi: token saved to " << path << "\n");
    return true;
}

bool QobuzApi::loadToken(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (path.empty()) return false;
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno != ENOENT)
            LOGERR("QobuzApi::loadToken: cannot open " << path << "\n");
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != ::geteuid() || ::fchmod(fd, 0600) != 0) {
        LOGERR("QobuzApi::loadToken: token is not a secure regular file\n");
        ::close(fd);
        return false;
    }
    std::string tok;
    char buffer[4096];
    constexpr size_t kMaxTokenBytes = 64 * 1024;
    for (;;) {
        ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || tok.size() + static_cast<size_t>(n) > kMaxTokenBytes) {
            LOGERR("QobuzApi::loadToken: invalid token file\n");
            ::close(fd);
            return false;
        }
        if (n == 0) break;
        tok.append(buffer, static_cast<size_t>(n));
    }
    ::close(fd);
    const auto newline = tok.find_first_of("\r\n");
    if (newline != std::string::npos) tok.resize(newline);
    if (tok.empty()) return false;
    m_user_token = tok;
    LOGINF("QobuzApi: token loaded from " << path << "\n");
    return true;
}

// ---- fetchAppCredentials ----------------------------------------------------

bool QobuzApi::fetchAppCredentials() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
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
                LOGDEB("QobuzApi: fetchAppCredentials: decoded candidate ["
                       << tz_full << "]\n");
                m_secret_candidates.push_back(secret);
            }
        }
    }

    if (m_secret_candidates.empty()) {
        LOGERR("QobuzApi: fetchAppCredentials: no secrets decoded from bundle.js\n");
        return false;
    }
    // ensureStreamSession() clears its working candidate list after finding
    // the session secret. Retain the complete bundle set for the classic API,
    // whose accepted secret may be a different candidate.
    m_bundle_secrets = m_secret_candidates;
    m_classic_secret.clear();
    LOGINF("QobuzApi: fetchAppCredentials: "
           << m_secret_candidates.size() << " secret candidate(s) ready\n");
    return true;
}

bool QobuzApi::fetchQwsToken(std::string& out_endpoint, std::string& out_jwt) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_user_token.empty()) {
        LOGERR("QobuzApi::fetchQwsToken: no OAuth user token\n");
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
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,      1L);

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
        LOGERR("QobuzApi::fetchQwsToken: HTTP " << http_code << "\n");
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

    // The qws JWT is short-lived and the cloud closes the socket when it
    // lapses. Log the remaining life so an otherwise unexplained session drop
    // can be matched against token expiry.
    const int64_t exp = jwt_payload.get("exp", 0).asInt64();
    if (exp > 0) {
        const int64_t now = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        LOGINF("QobuzApi::fetchQwsToken: ok, endpoint=" << out_endpoint
               << ", JWT valid for " << (exp - now) << "s\n");
    } else {
        LOGINF("QobuzApi::fetchQwsToken: ok, endpoint=" << out_endpoint
               << " (no expiry reported)\n");
    }
    return true;
}

std::string QobuzApi::httpPostForm(const std::string& path,
                                   const std::map<std::string, std::string>& form,
                                   long* http_code_out) {
    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: POST " << endpointOnly(path) << "\n");
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
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Origin: https://play.qobuz.com");
    hdrs = curl_slist_append(hdrs, "Referer: https://play.qobuz.com/");
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
        LOGERR("QobuzApi: POST HTTP " << http_code << " for "
               << endpointOnly(path) << "\n");
        result.clear();
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

std::string QobuzApi::httpGet(const std::string& path, long* http_code_out,
                              bool quiet) {
    std::string url = m_base_url + path;
    LOGDEB("QobuzApi: GET " << endpointOnly(path) << "\n");

    CURL* curl = curl_easy_init();
    if (!curl) return {};

    std::string result;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

    // Build auth headers. X-App-Id is sent on every request;
    // Origin/Referer mimic a web-player request so the server accepts the web-player app_id.
    // X-User-Auth-Token is added after OAuth or loading its cached token.
    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Origin: https://play.qobuz.com");
    hdrs = curl_slist_append(hdrs, "Referer: https://play.qobuz.com/");
    if (!m_app_id.empty()) {
        std::string appHdr = "X-App-Id: " + m_app_id;
        hdrs = curl_slist_append(hdrs, appHdr.c_str());
    }
    if (!m_user_token.empty()) {
        std::string authHdr = "X-User-Auth-Token: " + m_user_token;
        hdrs = curl_slist_append(hdrs, authHdr.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOGERR("QobuzApi: curl failed: " << curl_easy_strerror(rc) << "\n");
        result.clear();
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code_out) *http_code_out = http_code;
        if (http_code != 200) {
            if (quiet) {
                LOGDEB("QobuzApi: HTTP " << http_code << " for "
                       << endpointOnly(path) << "\n");
            } else {
                LOGERR("QobuzApi: HTTP " << http_code << " for "
                       << endpointOnly(path) << "\n");
            }
            result.clear();
        }
    }

    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace QConnect
