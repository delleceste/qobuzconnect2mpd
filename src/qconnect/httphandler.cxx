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
#include <mutex>
#include <string>

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

MHD_Result HttpHandler::handleRequest(struct MHD_Connection* conn,
                                 const char*            url,
                                 const char*            method,
                                 const char*            upload_data,
                                 size_t*                upload_data_size,
                                 void**                 con_cls) {
    const std::string prefix = "/devices/" + m_uuid;

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
