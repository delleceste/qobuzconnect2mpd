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
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
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

static std::string md5Hex(const std::string& s) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, s.data(), s.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    return hexString(digest, digest_len);
}

bool QobuzApi::login(const std::string& user, const std::string& pass) {
    if (user.empty() || pass.empty()) return false;

    // Try plain password first, then MD5-hashed password_auth as fallback.
    // Note: as of early April 2026 Qobuz's /user/login endpoint is returning
    // 401 for all third-party clients due to a cloud infrastructure migration.
    // This is a Qobuz-side issue (see streamrip#954); we try both forms so we
    // automatically recover when Qobuz resolves it.
    struct LoginVariant { const char* pass_param; std::string pass_value; };
    const LoginVariant kTries[] = {
        {"password",      pass},
        {"password_auth", md5Hex(pass)},
    };

    for (const auto& v : kTries) {
        std::string path = "/user/login?username=" + user
                           + "&" + v.pass_param + "=" + v.pass_value
                           + "&app_id=" + m_app_id;
        long http_code = 0;
        std::string resp = httpGet(path, &http_code);
        if (resp.empty()) {
            LOGDEB("QobuzApi::login: " << v.pass_param << " attempt HTTP " << http_code << "\n");
            continue;
        }
        Json::Value root;
        Json::CharReaderBuilder rdr;
        std::string errs;
        std::istringstream ss(resp);
        if (!Json::parseFromStream(rdr, ss, &root, &errs)) continue;
        m_user_token = root.get("user_auth_token", "").asString();
        if (m_user_token.empty()) continue;
        LOGINF("QobuzApi::login: ok via " << v.pass_param << "\n");
        return true;
    }
    LOGERR("QobuzApi::login: failed (Qobuz cloud migration in progress — mDNS path still works)\n");
    return false;
}

std::string QobuzApi::buildRequestSignature(const std::string& method_prefix,
                                            const std::map<std::string, std::string>& args,
                                            uint64_t ts,
                                            const std::string& secret_override) const {
    std::string plain = method_prefix;
    for (const auto& kv : args) {
        plain += kv.first;
        plain += kv.second;
    }
    plain += std::to_string(ts);
    plain += secret_override.empty() ? m_app_secret : secret_override;
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
    // Try requested format, then fall back to lower qualities. The legacy
    // /track/getFileUrl endpoint returns a direct, complete, byte-range-seekable
    // CDN file URL (the same one upmpdcli uses); we hand it straight to MPD, so
    // seeking works and there is no local download/decryption.
    static const int fallback_fmts[] = {27, 7, 6, 5};
    for (int fmt : fallback_fmts) {
        if (fmt > format_id) continue;

        long code = 0;
        if (tryGetStreamUrl(track_id, fmt, out, &code)) {
            LOGINF("QobuzApi: using direct getFileUrl stream (fmt=" << fmt
                   << ", seekable)\n");
            return true;
        }
        if (code == 400 && !refreshed_credentials) {
            LOGINF("QobuzApi: getFileUrl signature rejected; refreshing app credentials and retrying\n");
            if (fetchAppCredentials()) {
                m_app_secret.clear();
                refreshed_credentials = true;
                goto retry_after_refresh;
            }
        }
    }
    return false;
}

bool QobuzApi::tryGetStreamUrl(uint32_t track_id, int format_id,
                                TrackStreamInfo& out, long* http_code) {
    // The legacy /track/getFileUrl is the *classic* Qobuz API. It needs the
    // classic app secret, which is a different bundle.js candidate than the
    // session/file secret in m_app_secret. Sign with a given secret.
    auto do_call = [&](const std::string& secret, long* code_out) {
        uint64_t ts = unixTimestamp();
        std::map<std::string, std::string> sigargs;
        sigargs["format_id"] = std::to_string(format_id);
        sigargs["intent"] = "stream";
        sigargs["track_id"] = std::to_string(track_id);
        std::string sig = buildRequestSignature("trackgetFileUrl", sigargs, ts,
                                                secret);

        std::string path = "/track/getFileUrl"
                           "?track_id="  + std::to_string(track_id)
                         + "&format_id=" + std::to_string(format_id)
                         + "&intent=stream"
                         + "&request_ts="  + std::to_string(ts)
                         + "&request_sig=" + sig
                         + "&app_id="    + m_app_id;
        return httpGet(path, code_out, /*quiet=*/true);
    };

    // Build the list of secrets to try: the cached classic secret first (if
    // known), then every bundle.js candidate, then the active secret as a last
    // resort. The first that yields a non-error response is cached.
    std::vector<std::string> to_try;
    if (!m_classic_secret.empty()) to_try.push_back(m_classic_secret);
    for (const auto& s : m_bundle_secrets)
        if (s != m_classic_secret) to_try.push_back(s);
    if (to_try.empty() && !m_app_secret.empty()) to_try.push_back(m_app_secret);

    long code = 0;
    std::string resp;
    std::string used_secret;
    for (const auto& secret : to_try) {
        long c = 0;
        std::string r = do_call(secret, &c);
        code = c;
        if (!r.empty()) {           // HTTP 200 (httpGet clears body on non-200)
            resp = std::move(r);
            used_secret = secret;
            break;
        }
        if (c != 400) break;        // a non-signature error: stop probing secrets
    }
    if (http_code) *http_code = code;
    if (resp.empty()) return false;

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
    // Cache the classic secret that worked so later tracks sign in one shot.
    if (m_classic_secret != used_secret) {
        m_classic_secret = used_secret;
        LOGINF("QobuzApi: classic getFileUrl secret confirmed\n");
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
    // Private key is hardcoded in the Qobuz player (extracted from qobuz-player v0.9.0).
    static const std::string kPrivateKey = "6lz8C03UDIC7";
    std::string path = "/oauth/callback?code=" + code + "&private_key=" + kPrivateKey;
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
        LOGERR("QobuzApi::oauthExchangeCode: no token in response: "
               << resp.substr(0, 300) << "\n");
        return false;
    }
    m_user_token = tok;
    LOGINF("QobuzApi::oauthExchangeCode: user_auth_token obtained\n");
    return true;
}

std::string QobuzApi::buildOAuthUrl(const std::string& redirect_url) const {
    return "https://www.qobuz.com/signin/oauth?ext_app_id=" + m_app_id
           + "&redirect_url=" + redirect_url;
}

bool QobuzApi::saveToken(const std::string& path) const {
    if (m_user_token.empty() || path.empty()) return false;
    namespace fs = std::filesystem;
    fs::path p(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }
    std::ofstream f(path);
    if (!f) {
        LOGERR("QobuzApi::saveToken: cannot write " << path << "\n");
        return false;
    }
    f << m_user_token;
    LOGINF("QobuzApi: token saved to " << path << "\n");
    return true;
}

bool QobuzApi::loadToken(const std::string& path) {
    if (path.empty()) return false;
    std::ifstream f(path);
    if (!f) return false;
    std::string tok;
    std::getline(f, tok);
    if (tok.empty()) return false;
    m_user_token = tok;
    LOGINF("QobuzApi: token loaded from " << path << "\n");
    return true;
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

    // Keep a persistent copy: m_secret_candidates is cleared once the session
    // secret is confirmed, but the classic /track/getFileUrl secret (a possibly
    // different candidate) is found lazily and needs the full list.
    m_bundle_secrets = m_secret_candidates;
    m_classic_secret.clear();
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

std::string QobuzApi::httpGet(const std::string& path, long* http_code_out,
                              bool quiet) {
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
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

    // Build auth headers. X-App-Id is sent on every request;
    // Origin/Referer mimic a web-player request so the server accepts the web-player app_id.
    // X-User-Auth-Token is added only after login.
    // (JWT from the Qobuz app is for the WebSocket, not the REST API)
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
                LOGDEB("QobuzApi: HTTP " << http_code << " for " << path << "\n");
            } else {
                LOGERR("QobuzApi: HTTP " << http_code << " for " << path << "\n");
                if (!result.empty())
                    LOGERR("QobuzApi: response body: " << result.substr(0, 500) << "\n");
            }
            result.clear();
        }
    }

    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace QConnect
