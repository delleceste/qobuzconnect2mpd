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
#pragma once

#include <functional>
#include <string>
#include <cstdint>
#include <microhttpd.h>

namespace QConnect {

// Credentials delivered by the Qobuz app via POST connect-to-qconnect.
struct ConnectCredentials {
    std::string session_id;
    // QConnect WebSocket
    std::string ws_endpoint;    // e.g. "wss://play.qobuz.com/ws"
    std::string ws_jwt;
    uint64_t    ws_exp{0};      // expiry Unix timestamp
    // Qobuz API
    std::string api_jwt;
    uint64_t    api_exp{0};
};

// Called when the Qobuz app selects this device (POST connect-to-qconnect).
// The callback is invoked from the MHD request thread.
using ConnectCallback = std::function<void(ConnectCredentials)>;

// Serves the three HTTP endpoints required by the Qobuz Connect protocol:
//
//   GET  /devices/<uuid>/get-display-info   -> device metadata JSON
//   GET  /devices/<uuid>/get-connect-info   -> current session JSON
//   POST /devices/<uuid>/connect-to-qconnect -> receive JWT credentials
//
// Uses libmicrohttpd internally.  Thread-safe: callbacks are invoked
// synchronously in MHD's internal thread pool.

class HttpHandler {
public:
    // uuid:        device UUID (lowercase, with hyphens)
    // friendlyname device name shown in Qobuz app
    // port:        TCP port to listen on
    // max_quality: max format id (5/6/7/27 -> "MP3"/"LOSSLESS"/"HIRES_L2"/"HIRES_L3")
    // app_id:      Qobuz API app_id returned by get-connect-info
    HttpHandler(const std::string& uuid,
                const std::string& friendlyname,
                int                port,
                int                max_quality,
                const std::string& app_id,
                ConnectCallback    on_connect);
    ~HttpHandler();

    // Start the HTTP server.  Returns false if binding to port failed.
    bool start();

    // Stop the server and release all resources.
    void stop();

    // Update the session ID returned by get-connect-info.
    void setSessionId(const std::string& session_id);

private:
    static MHD_Result requestCallback(void* cls,
                                       struct MHD_Connection* conn,
                                       const char* url,
                                       const char* method,
                                       const char* version,
                                       const char* upload_data,
                                       size_t*     upload_data_size,
                                       void**      con_cls);

    MHD_Result handleRequest(struct MHD_Connection* conn,
                              const char* url,
                              const char* method,
                              const char* upload_data,
                              size_t*     upload_data_size,
                              void**      con_cls);

    static std::string qualityIdToString(int fmt_id);

    std::string      m_uuid;
    std::string      m_name;
    std::string      m_app_id;
    int              m_port;
    int              m_max_quality;
    ConnectCallback  m_on_connect;
    std::string      m_session_id;
    struct MHD_Daemon* m_daemon{nullptr};
};

} // namespace QConnect
