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

#include <microhttpd.h>
#include <json/json.h>

#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <filesystem>
#include <chrono>
#include <thread>

namespace QConnect {

// Per-connection state for POST body accumulation
struct PostCtx {
    std::string body;
};

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
    m_daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY | MHD_USE_DUAL_STACK,
        static_cast<uint16_t>(m_port),
        nullptr, nullptr,          // accept policy callback
        &HttpHandler::requestCallback, this,
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
    m_session_id = session_id;
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
    return static_cast<HttpHandler*>(cls)->handleRequest(
        conn, url, method, upload_data, upload_data_size, con_cls);
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
    MHD_add_response_header(resp, "Content-Type", content_type.c_str());
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static MHD_Result sendFileResponse(struct MHD_Connection* conn,
                                   const std::string& path,
                                   const std::string& content_type,
                                   bool head_only,
                                   const std::string& marker_path = {}) {
    namespace fs = std::filesystem;
    if (!fs::exists(path) || !fs::is_regular_file(path))
        return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");

    long long start = 0;
    long long end = -1;
    bool partial = false;

    const char* range = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Range");
    if (range && strncmp(range, "bytes=", 6) == 0) {
        long long s = -1, e = -1;
        if (sscanf(range + 6, "%lld-%lld", &s, &e) >= 1) {
            if (s >= 0) start = s;
            if (e >= 0) end = e;
            partial = true;
        }
    }

    long long total = 0;
    for (;;) {
        std::error_code ec;
        if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec))
            return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");
        total = static_cast<long long>(fs::file_size(path, ec));
        if (ec) total = 0;
        bool growing = !marker_path.empty() && fs::exists(marker_path);
        if (!partial || start < total || !growing)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (total < 0) total = 0;
    if (end < 0 || end >= total) end = total > 0 ? total - 1 : 0;
    if (partial && start >= total) {
        return sendResponse(conn, MHD_HTTP_RANGE_NOT_SATISFIABLE,
                            R"({"error":"range not satisfiable"})");
    }
    if (start < 0) start = 0;

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

struct GrowingFileCtx {
    std::string path;
    std::string marker_path;
};

static ssize_t growingFileReader(void* cls, uint64_t pos, char* buf, size_t max) {
    namespace fs = std::filesystem;
    auto* ctx = static_cast<GrowingFileCtx*>(cls);
    for (;;) {
        std::error_code ec;
        uint64_t size = fs::exists(ctx->path, ec) ? fs::file_size(ctx->path, ec) : 0;
        if (!ec && pos < size) {
            std::ifstream ifs(ctx->path, std::ios::binary);
            if (!ifs) return MHD_CONTENT_READER_END_WITH_ERROR;
            ifs.seekg(static_cast<std::streamoff>(pos), std::ios::beg);
            size_t want = static_cast<size_t>(std::min<uint64_t>(size - pos, max));
            ifs.read(buf, static_cast<std::streamsize>(want));
            auto got = static_cast<ssize_t>(ifs.gcount());
            if (got > 0) return got;
        }
        if (!fs::exists(ctx->marker_path))
            return MHD_CONTENT_READER_END_OF_STREAM;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

static void freeGrowingFileCtx(void* cls) {
    delete static_cast<GrowingFileCtx*>(cls);
}

static MHD_Result sendGrowingFileResponse(struct MHD_Connection* conn,
                                          const std::string& path,
                                          const std::string& marker_path,
                                          const std::string& content_type,
                                          bool /*head_only*/) {
    auto* ctx = new GrowingFileCtx{path, marker_path};
    struct MHD_Response* resp = MHD_create_response_from_callback(
        MHD_SIZE_UNKNOWN, 64 * 1024, &growingFileReader, ctx, &freeGrowingFileCtx);
    if (!resp) {
        delete ctx;
        return sendResponse(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, R"({"error":"stream setup failed"})");
    }
    MHD_add_response_header(resp, "Content-Type", content_type.c_str());
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
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
        std::string name = std::string(url).substr(seg_prefix.size());
        if (name.empty() || name.find("..") != std::string::npos ||
            name.find('/') != std::string::npos) {
            return sendResponse(conn, MHD_HTTP_BAD_REQUEST, R"({"error":"bad path"})");
        }
        const std::string path = "/tmp/qconnect2mpd-segmented/" + name;
        const std::string marker_path = path + ".inprogress";
        if (std::filesystem::exists(marker_path)) {
            const char* range = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Range");
            if ((range && *range) || strcmp(method, "HEAD") == 0)
                return sendFileResponse(conn, path, "audio/flac",
                                        strcmp(method, "HEAD") == 0,
                                        marker_path);
            return sendGrowingFileResponse(conn, path, marker_path, "audio/flac",
                                           strcmp(method, "HEAD") == 0);
        }
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
        j["current_session_id"] = m_session_id;
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
            *con_cls = new PostCtx();
            return MHD_YES;
        }

        auto* ctx = static_cast<PostCtx*>(*con_cls);

        // Body still arriving
        if (*upload_data_size > 0) {
            ctx->body.append(upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        // Body complete — parse JSON
        LOGDEB("HttpHandler: POST connect-to-qconnect body: "
               << ctx->body << "\n");

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
        if (m_on_connect) m_on_connect(std::move(creds));

        return sendResponse(conn, MHD_HTTP_OK, R"({"status":"ok"})");
    }

    // Unknown endpoint
    LOGDEB("HttpHandler: 404 " << method << " " << url << "\n");
    return sendResponse(conn, MHD_HTTP_NOT_FOUND, R"({"error":"not found"})");
}

} // namespace QConnect
