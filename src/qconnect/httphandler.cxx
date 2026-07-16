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

#include "httphandler.hxx"
#include "qclog.hxx"
#include "segstream.hxx"

#include <microhttpd.h>
#include <json/json.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <exception>
#include <fstream>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <thread>
#include <filesystem>

namespace QConnect {

// Per-connection state for POST body accumulation
struct PostCtx {
    std::string body;
    bool too_large{false};
    bool allocation_failed{false};
};

constexpr size_t kMaxConnectPostBytes = 1024 * 1024;

HttpHandler::HttpHandler(const std::string& uuid,
                          const std::string& friendlyname,
                          int                port,
                          int                max_quality,
                          const std::string& app_id,
                          ConnectCallback    on_connect)
    : m_uuid(uuid), m_name(friendlyname), m_app_id(app_id), m_port(port),
      m_max_quality(max_quality), m_on_connect(std::move(on_connect))
{}

HttpHandler::~HttpHandler() { stop(); }

bool HttpHandler::start() {
    // MHD_USE_THREAD_PER_CONNECTION: each connection (including the blocking
    // growingFileReader for audio streaming) runs in its own thread, so a slow
    // or stalled audio response never blocks the accept loop or other requests.
    m_daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY | MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK,
        static_cast<uint16_t>(m_port),
        nullptr, nullptr,          // accept policy callback
        &HttpHandler::requestCallback, this,
        MHD_OPTION_CONNECTION_LIMIT, static_cast<unsigned int>(64),
        MHD_OPTION_PER_IP_CONNECTION_LIMIT, static_cast<unsigned int>(16),
        MHD_OPTION_CONNECTION_TIMEOUT, static_cast<unsigned int>(30),
        MHD_OPTION_NOTIFY_COMPLETED,
        &HttpHandler::requestCompletedCallback, this,
        MHD_OPTION_END
    );
    if (!m_daemon) {
        LOGERR("HttpHandler: failed to start on port " << m_port << "\n");
        return false;
    }
    LOGDEB("HttpHandler: listening on port " << m_port << "\n");
    return true;
}

void HttpHandler::stop() {
    if (m_daemon) {
        MHD_stop_daemon(m_daemon);
        m_daemon = nullptr;
    }
}

void HttpHandler::setSessionId(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_session_id = session_id;
}

void HttpHandler::setOAuthCallback(const std::string& callback_path,
                                   OAuthCallback cb) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_oauth_path = callback_path;
    m_oauth_cb = std::move(cb);
    m_oauth_expires_at = std::chrono::steady_clock::now() +
                         std::chrono::minutes(5);
    m_oauth_in_progress = false;
}

void HttpHandler::setSegmentedRegistry(SegmentedTrackRegistry* registry) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_seg_registry = registry;
}

std::string HttpHandler::qualityIdToString(int fmt_id) {
    switch (fmt_id) {
    case 5:  return "MP3";
    case 6:  return "LOSSLESS";
    case 7:  return "HIRES_L2";
    case 27: return "HIRES_L3";
    default: return "LOSSLESS";
    }
}

// Static trampoline
MHD_Result HttpHandler::requestCallback(void*                  cls,
                                         struct MHD_Connection* conn,
                                         const char*            url,
                                         const char*            method,
                                         const char*            /*version*/,
                                         const char*            upload_data,
                                         size_t*                upload_data_size,
                                         void**                 con_cls) {
    try {
        return static_cast<HttpHandler*>(cls)->handleRequest(
            conn, url, method, upload_data, upload_data_size, con_cls);
    } catch (const std::exception& e) {
        LOGERR("HttpHandler: request callback failed: " << e.what() << "\n");
    } catch (...) {
        LOGERR("HttpHandler: request callback failed\n");
    }
    return MHD_NO;
}

void HttpHandler::requestCompletedCallback(
    void*, struct MHD_Connection*, void** con_cls,
    enum MHD_RequestTerminationCode) {
    if (!con_cls || !*con_cls) return;
    delete static_cast<PostCtx*>(*con_cls);
    *con_cls = nullptr;
}

static MHD_Result sendResponse(struct MHD_Connection* conn,
                                unsigned int           status,
                                const std::string&     body,
                                const std::string&     content_type = "application/json") {
    struct MHD_Response* resp = MHD_create_response_from_buffer(
        body.size(),
        const_cast<char*>(body.data()),
        MHD_RESPMEM_MUST_COPY
    );
    if (!resp) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", content_type.c_str());
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

struct ByteRange {
    uint64_t start{0};
    uint64_t end{0};
};

enum class RangeResult { None, Valid, Invalid };

static bool parseUint64(const std::string& value, uint64_t& out) {
    if (value.empty()) return false;
    uint64_t result = 0;
    for (unsigned char c : value) {
        if (!std::isdigit(c)) return false;
        const unsigned digit = c - '0';
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    out = result;
    return true;
}

static bool validByteRangeSyntax(const char* header) {
    if (!header || !*header) return true;
    const std::string value(header);
    if (value.rfind("bytes=", 0) != 0 || value.find(',') != std::string::npos)
        return false;

    const std::string spec = value.substr(6);
    const size_t dash = spec.find('-');
    if (dash == std::string::npos ||
        spec.find('-', dash + 1) != std::string::npos)
        return false;

    const std::string first = spec.substr(0, dash);
    const std::string last = spec.substr(dash + 1);
    if (first.empty() && last.empty()) return false;

    uint64_t start = 0;
    uint64_t end = 0;
    if (!first.empty() && !parseUint64(first, start)) return false;
    if (!last.empty() && !parseUint64(last, end)) return false;
    if (first.empty()) return end != 0;
    return last.empty() || start <= end;
}

static RangeResult parseByteRange(const char* header, uint64_t total,
                                  ByteRange& out) {
    if (!header || !*header) return RangeResult::None;
    if (!validByteRangeSyntax(header)) return RangeResult::Invalid;
    const std::string value(header);
    const std::string spec = value.substr(6);
    const size_t dash = spec.find('-');
    if (total == 0) return RangeResult::Invalid;

    const std::string first = spec.substr(0, dash);
    const std::string last = spec.substr(dash + 1);
    if (first.empty()) {
        uint64_t suffix = 0;
        if (!parseUint64(last, suffix) || suffix == 0)
            return RangeResult::Invalid;
        out.start = suffix >= total ? 0 : total - suffix;
        out.end = total - 1;
        return RangeResult::Valid;
    }

    uint64_t start = 0;
    if (!parseUint64(first, start) || start >= total)
        return RangeResult::Invalid;
    uint64_t end = total - 1;
    if (!last.empty() && (!parseUint64(last, end) || start > end))
        return RangeResult::Invalid;
    out.start = start;
    out.end = std::min(end, total - 1);
    return RangeResult::Valid;
}

static MHD_Result sendRangeNotSatisfiable(struct MHD_Connection* conn,
                                          uint64_t total) {
    struct MHD_Response* resp = MHD_create_response_from_buffer(
        0, nullptr, MHD_RESPMEM_PERSISTENT);
    if (!resp) return MHD_NO;
    const std::string content_range = "bytes */" + std::to_string(total);
    MHD_add_response_header(resp, "Content-Range", content_range.c_str());
    MHD_add_response_header(resp, "Accept-Ranges", "bytes");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_Result result = MHD_queue_response(
        conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, resp);
    MHD_destroy_response(resp);
    return result;
}

static MHD_Result sendRetryableUnavailable(struct MHD_Connection* conn,
                                           const std::string& body) {
    struct MHD_Response* resp = MHD_create_response_from_buffer(
        body.size(), const_cast<char*>(body.data()), MHD_RESPMEM_MUST_COPY);
    if (!resp) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Retry-After", "1");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_Result result = MHD_queue_response(
        conn, MHD_HTTP_SERVICE_UNAVAILABLE, resp);
    MHD_destroy_response(resp);
    return result;
}

static MHD_Result sendFileResponse(struct MHD_Connection* conn,
                                   const std::string& path,
                                   const std::string& content_type,
                                   bool head_only,
                                   const std::string& marker_path = {}) {
    namespace fs = std::filesystem;
    if (!fs::exists(path) || !fs::is_regular_file(path))
        return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");

    const char* range_header = MHD_lookup_connection_value(
        conn, MHD_HEADER_KIND, "Range");
    if (!validByteRangeSyntax(range_header))
        return sendResponse(conn, MHD_HTTP_BAD_REQUEST,
                            R"({"error":"malformed range"})");

    long long total = 0;
    const auto wait_deadline = std::chrono::steady_clock::now() +
                               std::chrono::seconds(30);
    for (;;) {
        std::error_code ec;
        if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec))
            return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");
        total = static_cast<long long>(fs::file_size(path, ec));
        if (ec) total = 0;
        bool growing = !marker_path.empty() && fs::exists(marker_path);
        if (!range_header || !*range_header || total > 0 || !growing)
            break;
        if (std::chrono::steady_clock::now() >= wait_deadline)
            return sendRetryableUnavailable(
                conn, R"({"error":"file is still growing"})");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (total < 0) total = 0;
    ByteRange requested{0, total > 0 ? static_cast<uint64_t>(total - 1) : 0};
    const RangeResult range_result = parseByteRange(
        range_header,
        static_cast<uint64_t>(total), requested);
    if (range_result == RangeResult::Invalid)
        return sendRangeNotSatisfiable(conn, static_cast<uint64_t>(total));
    const bool partial = range_result == RangeResult::Valid;
    const long long start = static_cast<long long>(requested.start);
    const long long end = static_cast<long long>(requested.end);

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, R"({"error":"open failed"})");

    long long len = (end >= start) ? (end - start + 1) : 0;

    std::string data;
    if (!head_only) {
        data.resize(static_cast<size_t>(len));
        ifs.seekg(start, std::ios::beg);
        if (len > 0) ifs.read(data.data(), len);
    }

    struct MHD_Response* resp = MHD_create_response_from_buffer(
        data.size(),
        data.empty() ? nullptr : const_cast<char*>(data.data()),
        MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", content_type.c_str());
    MHD_add_response_header(resp, "Content-Length", std::to_string(len).c_str());
    MHD_add_response_header(resp, "Accept-Ranges", "bytes");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    if (partial) {
        std::string cr = "bytes " + std::to_string(start) + "-" +
                         std::to_string(end) + "/" + std::to_string(total);
        MHD_add_response_header(resp, "Content-Range", cr.c_str());
    }
    MHD_Result ret = MHD_queue_response(conn,
                                        partial ? MHD_HTTP_PARTIAL_CONTENT : MHD_HTTP_OK,
                                        resp);
    MHD_destroy_response(resp);
    return ret;
}

// ---- Shared growing segmented-stream response ------------------------------
//
// Registered plans enter a bounded prefetch scheduler.  All HTTP connections
// read the same growing cache, so retries, reconnects and probes never refetch
// a segment.  Qobuz's segment lengths are estimates; a fixed Content-Length
// and byte ranges are exposed only after the stream has been measured.

struct SegStreamCtx {
    std::shared_ptr<SegmentedTrackPlan> plan;
    SegmentedDownloadHandle download;
    uint64_t range_start{0};
    uint64_t response_length{std::numeric_limits<uint64_t>::max()};
    bool logged_error{false};
};

static ssize_t segStreamReader(void* cls, uint64_t pos, char* buf, size_t max) {
    auto* ctx = static_cast<SegStreamCtx*>(cls);
    if (pos >= ctx->response_length)
        return MHD_CONTENT_READER_END_OF_STREAM;
    if (pos > std::numeric_limits<uint64_t>::max() - ctx->range_start)
        return MHD_CONTENT_READER_END_WITH_ERROR;

    size_t capacity = max;
    if (ctx->response_length != std::numeric_limits<uint64_t>::max())
        capacity = static_cast<size_t>(std::min<uint64_t>(
            capacity, ctx->response_length - pos));

    size_t read_size = 0;
    std::string error;
    const int result = readSegmentedTrack(
        ctx->download, ctx->range_start + pos,
        reinterpret_cast<uint8_t*>(buf), capacity, read_size,
        120000, &error);
    if (result > 0) return static_cast<ssize_t>(read_size);
    if (result == 0) return MHD_CONTENT_READER_END_OF_STREAM;
    if (!ctx->logged_error) {
        LOGERR("HttpHandler: segmented track " << ctx->plan->track_id
               << " reconstruction failed: " << error << "\n");
        ctx->logged_error = true;
    }
    return MHD_CONTENT_READER_END_WITH_ERROR;
}

static void freeSegStreamCtx(void* cls) {
    auto* ctx = static_cast<SegStreamCtx*>(cls);
    releaseSegmentedTrackDownload(ctx->download);
    delete ctx;
}

static MHD_Result sendSegmentedStreamResponse(
    struct MHD_Connection* conn,
    std::shared_ptr<SegmentedTrackPlan> plan,
    const char* method) {
    (void)method;
    auto download = acquireSegmentedTrackDownload(
        plan, SegmentedDownloadPriority::Playback);
    if (!download)
        return sendRetryableUnavailable(
            conn, R"({"error":"download scheduler busy"})");
    std::string download_error;
    if (segmentedTrackFailed(download, &download_error)) {
        releaseSegmentedTrackDownload(download);
        return sendRetryableUnavailable(
            conn, R"({"error":"track download unavailable"})");
    }

    const char* range_header = MHD_lookup_connection_value(
        conn, MHD_HEADER_KIND, "Range");
    const bool has_range = range_header && *range_header;
    if (has_range && !validByteRangeSyntax(range_header)) {
        releaseSegmentedTrackDownload(download);
        return sendResponse(conn, MHD_HTTP_BAD_REQUEST,
                            R"({"error":"malformed range"})");
    }

    uint64_t total = 0;
    bool exact = segmentedTrackExactSize(download, total);
    if (has_range && !exact) {
        std::string error;
        if (!waitForSegmentedTrack(download, total, 30000, &error)) {
            LOGERR("HttpHandler: segmented track " << plan->track_id
                   << " cannot satisfy Range: " << error << "\n");
            const bool failed = segmentedTrackFailed(download, nullptr);
            releaseSegmentedTrackDownload(download);
            if (!failed)
                return sendRetryableUnavailable(
                    conn, R"({"error":"track is still downloading"})");
            return sendResponse(conn, MHD_HTTP_BAD_GATEWAY,
                                R"({"error":"track reconstruction failed"})");
        }
        exact = true;
    }

    ByteRange range{0, exact && total > 0 ? total - 1 : 0};
    RangeResult range_result = RangeResult::None;
    if (has_range) {
        range_result = parseByteRange(range_header, total, range);
        if (range_result != RangeResult::Valid) {
            releaseSegmentedTrackDownload(download);
            return sendRangeNotSatisfiable(conn, total);
        }
    }
    const bool partial = range_result == RangeResult::Valid;
    const uint64_t start = partial ? range.start : 0;
    const uint64_t body_len = partial ? range.end - range.start + 1 :
                              exact ? total : MHD_SIZE_UNKNOWN;

    auto* ctx = new SegStreamCtx();
    ctx->plan = std::move(plan);
    ctx->download = std::move(download);
    ctx->range_start = start;
    ctx->response_length = body_len == MHD_SIZE_UNKNOWN ?
                           std::numeric_limits<uint64_t>::max() : body_len;
    struct MHD_Response* resp = MHD_create_response_from_callback(
        body_len, 64 * 1024, &segStreamReader, ctx, &freeSegStreamCtx);
    if (!resp) {
        freeSegStreamCtx(ctx);
        return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            R"({"error":"stream setup failed"})");
    }

    MHD_add_response_header(resp, "Content-Type", "audio/flac");
    if (exact) {
        MHD_add_response_header(resp, "Content-Length",
                                std::to_string(body_len).c_str());
    }
    // MusicPD decides seekability from the first response and cannot learn it
    // later when the growing cache becomes complete.
    MHD_add_response_header(resp, "Accept-Ranges", "bytes");
    if (partial) {
        std::string cr = "bytes " + std::to_string(start) + "-" +
                         std::to_string(range.end) + "/" +
                         std::to_string(total);
        MHD_add_response_header(resp, "Content-Range", cr.c_str());
    }
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Cache-Control", "no-store");

    MHD_Result ret = MHD_queue_response(
        conn, partial ? MHD_HTTP_PARTIAL_CONTENT : MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

MHD_Result HttpHandler::handleRequest(struct MHD_Connection* conn,
                                 const char*            url,
                                 const char*            method,
                                 const char*            upload_data,
                                 size_t*                upload_data_size,
                                 void**                 con_cls) {
    const std::string prefix = "/devices/" + m_uuid;
    const std::string seg_prefix = "/qobuz-segmented/";

    if ((strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) &&
        std::string(url).rfind(seg_prefix, 0) == 0) {
        std::string token = std::string(url).substr(seg_prefix.size());
        if (token.empty() || token.find("..") != std::string::npos ||
            token.front() == '/' || token.back() == '/') {
            return sendResponse(conn, MHD_HTTP_BAD_REQUEST, R"({"error":"bad path"})");
        }
        // Plan-based streaming path: fetch+decrypt segments on demand.
        SegmentedTrackRegistry* registry = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            registry = m_seg_registry;
        }
        if (registry) {
            auto plan = registry->get(token);
            if (plan) {
                return sendSegmentedStreamResponse(conn, std::move(plan), method);
            }
        }
        // Backwards-compatible disk fallback (kept for any leftover materialised
        // files from older releases — new tracks always go through the registry).
        const std::string path = "/tmp/qconnect2mpd-segmented/" + token;
        return sendFileResponse(conn, path, "audio/flac",
                                strcmp(method, "HEAD") == 0);
    }

    // ---- OPTIONS (CORS pre-flight) ----------------------------------------
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response* resp = MHD_create_response_from_buffer(
            0, nullptr, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods",
                                 "GET, POST, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers",
                                 "Content-Type");
        MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    // ---- GET get-display-info --------------------------------------------
    if (strcmp(method, "GET") == 0 &&
        std::string(url) == prefix + "/get-display-info") {
        LOGDEB("HttpHandler: GET get-display-info\n");
        Json::Value j;
        j["type"]                = "SPEAKER";
        j["friendly_name"]       = m_name;
        j["model_display_name"]  = m_name;
        j["brand_display_name"]  = "UpMpd";
        j["serial_number"]       = m_uuid;
        j["max_audio_quality"]   = qualityIdToString(m_max_quality);
        Json::StreamWriterBuilder wr;
        wr["indentation"] = "";
        return sendResponse(conn, MHD_HTTP_OK, Json::writeString(wr, j));
    }

    // ---- GET get-connect-info --------------------------------------------
    if (strcmp(method, "GET") == 0 &&
        std::string(url) == prefix + "/get-connect-info") {
        LOGDEB("HttpHandler: GET get-connect-info\n");
        Json::Value j;
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            j["current_session_id"] = m_session_id;
        }
        j["app_id"]             = m_app_id;
        Json::StreamWriterBuilder wr;
        wr["indentation"] = "";
        return sendResponse(conn, MHD_HTTP_OK, Json::writeString(wr, j));
    }

    // ---- POST connect-to-qconnect ----------------------------------------
    if (strcmp(method, "POST") == 0 &&
        std::string(url) == prefix + "/connect-to-qconnect") {

        // First call: allocate accumulation buffer
        if (!*con_cls) {
            auto* ctx = new (std::nothrow) PostCtx();
            if (!ctx)
                return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                    R"({"error":"allocation failed"})");
            *con_cls = ctx;
            return MHD_YES;
        }

        auto* ctx = static_cast<PostCtx*>(*con_cls);

        // Body still arriving
        if (*upload_data_size > 0) {
            if (!ctx->too_large && !ctx->allocation_failed) {
                if (*upload_data_size > kMaxConnectPostBytes - ctx->body.size()) {
                    ctx->too_large = true;
                    ctx->body.clear();
                } else {
                    try {
                        ctx->body.append(upload_data, *upload_data_size);
                    } catch (...) {
                        ctx->allocation_failed = true;
                        ctx->body.clear();
                    }
                }
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (ctx->too_large) {
            delete ctx;
            *con_cls = nullptr;
            return sendResponse(conn, MHD_HTTP_CONTENT_TOO_LARGE,
                                R"({"error":"request body too large"})");
        }
        if (ctx->allocation_failed) {
            delete ctx;
            *con_cls = nullptr;
            return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                R"({"error":"allocation failed"})");
        }

        // Body complete — parse JSON. Never log it: it contains bearer JWTs.
        ConnectCredentials creds;
        Json::Value root;
        Json::CharReaderBuilder rdr;
        std::string errs;
        std::istringstream ss(ctx->body);
        if (!Json::parseFromStream(rdr, ss, &root, &errs)) {
            LOGERR("HttpHandler: JSON parse error: " << errs << "\n");
            delete ctx; *con_cls = nullptr;
            return sendResponse(conn, MHD_HTTP_BAD_REQUEST,
                                 R"({"error":"invalid json"})");
        }

        creds.session_id = root.get("session_id", "").asString();

        const Json::Value& qcJwt = root["jwt_qconnect"];
        if (!qcJwt.isNull()) {
            creds.ws_endpoint = qcJwt.get("endpoint",
                                            "wss://play.qobuz.com/ws").asString();
            creds.ws_jwt      = qcJwt.get("jwt", "").asString();
            creds.ws_exp      = static_cast<uint64_t>(
                                    qcJwt.get("exp", 0).asInt64());
        }

        const Json::Value& apiJwt = root["jwt_api"];
        if (!apiJwt.isNull()) {
            creds.api_jwt = apiJwt.get("jwt", "").asString();
            creds.api_exp = static_cast<uint64_t>(
                                apiJwt.get("exp", 0).asInt64());
        }

        delete ctx; *con_cls = nullptr;

        // Fire callback (may block briefly while session starts)
        try {
            if (m_on_connect) m_on_connect(std::move(creds));
        } catch (const std::exception& e) {
            LOGERR("HttpHandler: connect callback failed: " << e.what() << "\n");
            return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                R"({"error":"connect callback failed"})");
        } catch (...) {
            LOGERR("HttpHandler: connect callback failed\n");
            return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                R"({"error":"connect callback failed"})");
        }

        return sendResponse(conn, MHD_HTTP_OK, R"({"status":"ok"})");
    }

    // ---- Short-lived OAuth browser redirect -------------------------------
    bool oauth_route = false;
    bool oauth_expired = false;
    bool oauth_busy = false;
    OAuthCallback oauth_cb;
    const char* oauth_code = nullptr;
    if (strcmp(method, "GET") == 0) {
        oauth_code = MHD_lookup_connection_value(
            conn, MHD_GET_ARGUMENT_KIND, "code_autorisation");
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            oauth_route = !m_oauth_path.empty() && url == m_oauth_path;
            if (oauth_route &&
                std::chrono::steady_clock::now() > m_oauth_expires_at) {
                oauth_expired = true;
                m_oauth_cb = {};
                m_oauth_path.clear();
                m_oauth_in_progress = false;
            } else if (oauth_route && oauth_code && *oauth_code) {
                if (m_oauth_in_progress) {
                    oauth_busy = true;
                } else {
                    m_oauth_in_progress = true;
                    oauth_cb = m_oauth_cb;
                }
            }
        }
    }

    if (oauth_route) {
        if (oauth_expired) {
            static const std::string kExpiredHtml =
                "<html><body><h2>Login expired</h2>"
                "<p>Restart the daemon to begin a new login.</p>"
                "</body></html>";
            return sendResponse(conn, MHD_HTTP_GONE,
                                kExpiredHtml, "text/html");
        }
        if (oauth_busy) {
            return sendResponse(conn, MHD_HTTP_CONFLICT,
                                R"({"error":"OAuth exchange already in progress"})");
        }
        if (oauth_code && *oauth_code) {
            LOGINF("HttpHandler: OAuth code received\n");
            bool oauth_ok = false;
            try {
                oauth_ok = oauth_cb && oauth_cb(oauth_code);
            } catch (const std::exception& e) {
                LOGERR("HttpHandler: OAuth callback failed: " << e.what() << "\n");
            } catch (...) {
                LOGERR("HttpHandler: OAuth callback failed\n");
            }
            {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                m_oauth_in_progress = false;
                if (oauth_ok) {
                    m_oauth_cb = {};
                    m_oauth_path.clear();
                }
            }
            if (!oauth_ok) {
                LOGERR("HttpHandler: OAuth token exchange failed\n");
                static const std::string kExchangeFailHtml =
                    "<html><body><h2>Login failed</h2>"
                    "<p>The authorization code could not be exchanged. "
                    "Check the daemon log and try again.</p>"
                    "</body></html>";
                return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                    kExchangeFailHtml, "text/html");
            }
            static const std::string kOkHtml =
                "<html><body><h2>Login successful!</h2>"
                "<p>You can close this tab and return to qconnect2mpd.</p>"
                "</body></html>";
            return sendResponse(conn, MHD_HTTP_OK, kOkHtml, "text/html");
        }
        static const std::string kFailHtml =
            "<html><body><h2>Login failed</h2>"
            "<p>No authorization code (code_autorisation) in redirect URL.</p>"
            "</body></html>";
        return sendResponse(conn, MHD_HTTP_BAD_REQUEST,
                            kFailHtml, "text/html");
    }

    // Unknown endpoint
    LOGDEB("HttpHandler: 404 " << method << " " << url << "\n");
    return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");
}

} // namespace QConnect
