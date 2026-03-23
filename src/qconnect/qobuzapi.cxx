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
// Track URL signing: MD5 of the concatenated parameter string with the
// app_secret appended (matches the qobuz-player / qonductor approach):
//   sig = md5( "trackgetFileUrl"
//            + "format_id" + str(fmt_id)
//            + "intent"    + "stream"
//            + "track_id"  + str(track_id)
//            + str(ts)
//            + app_secret )
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
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/md5.h>
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

// Build the MD5 signature for /track/getFileUrl as in raw.py:
//   md5( "trackgetFileUrl" + "format_id" + fmt_id + "intent" + intent
//        + "track_id" + track_id + timestamp )
// Then XOR with app_secret nibbles.
std::string QobuzApi::buildFileUrlSignature(uint32_t track_id,
                                              int fmt_id,
                                              uint64_t ts) const {
    // Append the secret to the plain string before hashing — this is the
    // modern Qobuz signing method used by qobuz-player / qonductor.
    std::string plain = "trackgetFileUrl"
                      + std::string("format_id") + std::to_string(fmt_id)
                      + std::string("intent")    + std::string("stream")
                      + std::string("track_id")  + std::to_string(track_id)
                      + std::to_string(ts)
                      + m_app_secret;

    uint8_t digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(plain.data()),
        plain.size(), digest);
    return hexString(digest, MD5_DIGEST_LENGTH);
}

bool QobuzApi::getStreamUrl(uint32_t track_id, int format_id,
                              TrackStreamInfo& out) {
    // If no confirmed secret yet but we have candidates from fetchAppCredentials,
    // try each one; lock in the first that returns a valid URL.
    if (m_app_secret.empty() && !m_secret_candidates.empty()) {
        for (const auto& cand : m_secret_candidates) {
            m_app_secret = cand;
            if (tryGetStreamUrl(track_id, format_id, out)) {
                LOGINF("QobuzApi: active secret confirmed\n");
                m_secret_candidates.clear();
                return true;
            }
        }
        m_app_secret.clear();
        LOGERR("QobuzApi: none of the " << m_secret_candidates.size()
               << " secret candidates produced a valid URL\n");
        return false;
    }
    return tryGetStreamUrl(track_id, format_id, out);
}

bool QobuzApi::tryGetStreamUrl(uint32_t track_id, int format_id,
                                TrackStreamInfo& out) {
    uint64_t ts  = unixTimestamp();
    std::string sig = buildFileUrlSignature(track_id, format_id, ts);

    std::string path = "/track/getFileUrl"
                       "?track_id="  + std::to_string(track_id)
                     + "&format_id=" + std::to_string(format_id)
                     + "&intent=stream"
                     + "&request_ts="  + std::to_string(ts)
                     + "&request_sig=" + sig
                     + "&app_id="    + m_app_id;

    std::string resp = httpGet(path);
    if (resp.empty()) return false;

    Json::Value root;
    Json::CharReaderBuilder rdr;
    std::string errs;
    std::istringstream ss(resp);
    if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
        LOGERR("QobuzApi::getStreamUrl: JSON parse error: " << errs << "\n");
        return false;
    }

    out.stream_url  = root.get("url", "").asString();
    out.mime_type   = root.get("mime_type", "audio/flac").asString();
    out.format_id   = format_id;
    out.duration_ms = root.get("duration", 0).asUInt() * 1000;

    if (out.stream_url.empty()) {
        LOGERR("QobuzApi::getStreamUrl: no url in response for track "
               << track_id << "\n");
        return false;
    }
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

    std::vector<unsigned char> buf(s.size());
    int outlen = EVP_DecodeBlock(
        buf.data(),
        reinterpret_cast<const unsigned char*>(s.data()),
        static_cast<int>(s.size()));
    if (outlen < 0) return {};
    outlen -= static_cast<int>(pad); // EVP_DecodeBlock counts padding as output
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

std::string QobuzApi::httpGet(const std::string& path,
                               const std::string& /*extra_headers*/) {
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

    // Build auth header: prefer JWT, fallback to user token
    struct curl_slist* hdrs = nullptr;
    std::string authHdr;
    if (!m_jwt.empty()) {
        authHdr = "X-User-Auth-Token: " + m_jwt;
    } else if (!m_user_token.empty()) {
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
        if (http_code != 200) {
            LOGERR("QobuzApi: HTTP " << http_code << " for " << path << "\n");
            result.clear();
        }
    }

    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace QConnect
