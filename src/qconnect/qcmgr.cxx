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

#include "qcmgr.hxx"
#include "qclog.hxx"
#include "mdns.hxx"
#include "httphandler.hxx"
#include "wsession.hxx"
#include "mpdctl.hxx"
#include "qobuzapi.hxx"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <mutex>

namespace QConnect {

// ---- UUID helpers -----------------------------------------------------------

// Generate a random UUID v4 string (lowercase, with hyphens)
static std::string generateUuid() {
    // Simple implementation using /dev/urandom
    uint8_t bytes[16];
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f || fread(bytes, 1, 16, f) != 16) {
        if (f) fclose(f);
        // Fallback: use time-based seed
        uint64_t t = static_cast<uint64_t>(time(nullptr));
        for (int i = 0; i < 8; ++i) bytes[i] = (t >> (i * 8)) & 0xff;
        for (int i = 8; i < 16; ++i) bytes[i] = i;
    } else {
        fclose(f);
    }
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    char buf[37];
    snprintf(buf, sizeof(buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x%02x%02x%02x%02x",
             bytes[0],bytes[1],bytes[2],bytes[3],
             bytes[4],bytes[5], bytes[6],bytes[7],
             bytes[8],bytes[9],
             bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]);
    return buf;
}

// Convert UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to 16 raw bytes
static Bytes uuidStringToBytes(const std::string& uuid_str) {
    std::string hex;
    hex.reserve(32);
    for (char c : uuid_str)
        if (c != '-') hex += c;
    if (hex.size() != 32) return Bytes(16, 0);
    Bytes out(16);
    for (int i = 0; i < 16; ++i) {
        int v = 0;
        sscanf(hex.c_str() + i * 2, "%02x", &v);
        out[i] = static_cast<uint8_t>(v);
    }
    return out;
}

// ============================================================
//  QcManager
// ============================================================

QcManager::QcManager(const QcConfig& cfg) : m_cfg(cfg) {
    if (m_cfg.uuid.empty()) m_cfg.uuid = generateUuid();

    m_devinfo.uuid          = uuidStringToBytes(m_cfg.uuid);
    m_devinfo.friendly_name = m_cfg.friendly_name;
    m_devinfo.brand         = "UpMpd";
    m_devinfo.model         = m_cfg.friendly_name;
    m_devinfo.serial        = m_cfg.uuid;
    m_devinfo.type          = m_cfg.device_type;
    m_devinfo.max_quality   = m_cfg.format_id;
}

QcManager::~QcManager() { stop(); }

bool QcManager::start() {
    // ---- Qobuz API client --------------------------------------------------
    m_api = std::make_unique<QobuzApi>(m_cfg.api_base_url,
                                        m_cfg.app_id,
                                        m_cfg.app_secret);

    // Auto-fetch app_id + secret from Qobuz bundle.js when not in config
    if (m_cfg.app_id.empty()) {
        LOGINF("QcManager: qobuzappid not configured — fetching from bundle.js\n");
        if (!m_api->fetchAppCredentials())
            LOGERR("QcManager: bundle.js fetch failed; streaming will not work\n");
    }

    if (!m_cfg.qobuz_user.empty()) {
        if (m_api->login(m_cfg.qobuz_user, m_cfg.qobuz_pass))
            LOGINF("QcManager: Qobuz API login OK (user=" << m_cfg.qobuz_user << ")\n");
        else
            LOGERR("QcManager: Qobuz API login FAILED — check credentials\n");
    }

    // ---- MPD controller ----------------------------------------------------
    m_mpd = std::make_unique<MpdCtl>(m_cfg.mpd_host, m_cfg.mpd_port,
                                      m_cfg.mpd_password);
    if (!m_mpd->connect()) {
        LOGERR("QcManager: cannot connect to MPD at "
               << m_cfg.mpd_host << ":" << m_cfg.mpd_port << "\n");
        return false;
    }
    m_mpd->setStateCallback(
        [this](const MpdState& st) { onMpdState(st); });

    // ---- HTTP server -------------------------------------------------------
    m_http = std::make_unique<HttpHandler>(
        m_cfg.uuid, m_cfg.friendly_name,
        m_cfg.http_port, m_cfg.format_id,
        m_api->appId(),
        [this](ConnectCredentials c) { onConnect(std::move(c)); });
    if (!m_http->start()) return false;

    // ---- mDNS announcer ----------------------------------------------------
    m_mdns = std::make_unique<MdnsAnnouncer>(
        m_cfg.uuid, m_cfg.friendly_name,
        m_cfg.http_port, m_cfg.iface);
    if (!m_mdns->start()) {
        LOGERR("QcManager: mDNS announcer failed to start\n");
        // Non-fatal: HTTP still works for manual connections
    }

    // ---- IPC with upmpdcli (optional) --------------------------------------
    if (!m_cfg.upmpdcli_sock.empty()) startIpcServer();

    // The WebSocket endpoint wss://play.qobuz.com/ws requires a QConnect JWT,
    // which is issued by the Qobuz cloud and only delivered by the mobile app
    // (or web player) in the POST /connect-to-qconnect request.  The REST API
    // user_auth_token is a different credential and is not accepted here.
    //
    // Discovery flow:
    //   Mobile app  → mDNS → finds this device → POSTs jwt_qconnect → we connect WS
    //   Web player  → cloud → lists WS-connected renderers → we appear once mobile
    //                         app has established the first session
    LOGINF("QcManager: waiting for Qobuz app to POST connect credentials\n");

    m_running = true;
    LOGINF("QcManager: ready — device '" << m_cfg.friendly_name
           << "' advertised as " << m_cfg.uuid << "\n");
    return true;
}

void QcManager::stop() {
    if (!m_running) return;
    m_running = false;

    stopIpcServer();

    if (m_ws) { m_ws->disconnect(); m_ws.reset(); }
    if (m_mdns) { m_mdns->stop(); m_mdns.reset(); }
    if (m_http) { m_http->stop(); m_http.reset(); }
    if (m_mpd)  { m_mpd->disconnect(); m_mpd.reset(); }

    LOGINF("QcManager: stopped\n");
}

void QcManager::run() {
    // Simply wait until stop() is called
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ---- Qobuz app connection --------------------------------------------------

void QcManager::onConnect(ConnectCredentials creds) {
    std::lock_guard<std::mutex> lk(m_session_mutex);

    LOGINF("QcManager: Qobuz app connected, session_id="
           << creds.session_id << "\n");

    // Tear down any existing WSession
    if (m_ws) {
        m_ws->disconnect();
        m_ws.reset();
    }

    // Update the API JWT so stream-URL requests use the new token
    if (!creds.api_jwt.empty()) m_api->setJwt(creds.api_jwt);

    // Update session ID shown in get-connect-info
    m_http->setSessionId(creds.session_id);

    // Build WSession callbacks
    WSessionCallbacks cbs;
    cbs.on_set_state  = [this](PlayingState ps, uint32_t pos_ms) {
        onSetState(ps, pos_ms);
    };
    cbs.on_set_volume = [this](uint32_t v, int32_t d) {
        onSetVolume(v, d);
    };
    cbs.on_queue_load = [this](const std::vector<uint32_t>& ids, uint32_t idx) {
        onQueueLoad(ids, idx);
    };
    cbs.on_tracks_inserted = [this](const std::vector<uint32_t>& ids, uint32_t after) {
        onTracksInserted(ids, after);
    };
    cbs.on_tracks_added = [this](const std::vector<uint32_t>& ids) {
        onTracksAdded(ids);
    };
    cbs.on_tracks_removed = [this](const std::vector<uint32_t>& ids) {
        onTracksRemoved(ids);
    };
    cbs.on_connected    = [this]() { onWsConnected(); };
    cbs.on_disconnected = [this]() { onWsDisconnected(); };

    m_ws = std::make_unique<WSession>(m_devinfo, cbs);
    if (!m_ws->connect(creds)) {
        LOGERR("QcManager: WebSocket connect failed\n");
        m_ws.reset();
    }
}

// ---- WSession callbacks ----------------------------------------------------

void QcManager::onWsConnected() {
    m_ws_active = true;
    notifyUpmpdcli("PLAYING\n");
    LOGINF("QcManager: WebSocket session active\n");
}

void QcManager::onWsDisconnected() {
    m_ws_active = false;
    if (m_mpd) m_mpd->stop();
    notifyUpmpdcli("STOPPED\n");
    LOGINF("QcManager: WebSocket session ended\n");
}

void QcManager::onSetState(PlayingState ps, uint32_t position_ms) {
    if (!m_mpd) return;
    switch (ps) {
    case PlayingState::PLAYING:
        if (position_ms > 0)
            m_mpd->seek(position_ms);
        m_mpd->play();
        break;
    case PlayingState::PAUSED:
        m_mpd->pause(true);
        break;
    case PlayingState::STOPPED:
        m_mpd->stop();
        break;
    default:
        break;
    }
}

void QcManager::onSetVolume(uint32_t volume, int32_t delta) {
    if (!m_mpd) return;
    if (delta != 0) {
        MpdState st = m_mpd->getState();
        int new_vol = static_cast<int>(st.volume) + delta;
        if (new_vol < 0)   new_vol = 0;
        if (new_vol > 100) new_vol = 100;
        m_mpd->setVolume(static_cast<uint32_t>(new_vol));
    } else {
        m_mpd->setVolume(volume);
    }
}

void QcManager::onQueueLoad(const std::vector<uint32_t>& track_ids,
                              uint32_t start_idx) {
    LOGINF("QcManager: loading " << track_ids.size()
           << " tracks from Qobuz, starting at " << start_idx << "\n");

    auto urls = resolveStreamUrls(track_ids);
    if (urls.empty()) {
        LOGERR("QcManager: failed to resolve any stream URLs\n");
        return;
    }

    if (!m_mpd) return;
    m_mpd->loadQueue(urls, static_cast<int>(start_idx));
}

void QcManager::onTracksInserted(const std::vector<uint32_t>& track_ids,
                                   uint32_t insert_after_item_id) {
    auto urls = resolveStreamUrls(track_ids);
    if (urls.empty() || !m_mpd) return;
    int mpd_id = m_mpd->queueItemToMpdId(insert_after_item_id);
    m_mpd->insertTracks(urls, mpd_id);
}

void QcManager::onTracksAdded(const std::vector<uint32_t>& track_ids) {
    auto urls = resolveStreamUrls(track_ids);
    if (urls.empty() || !m_mpd) return;
    m_mpd->addTracks(urls);
}

void QcManager::onTracksRemoved(const std::vector<uint32_t>& queue_item_ids) {
    if (!m_mpd) return;
    std::vector<int> mpd_ids;
    for (uint32_t qid : queue_item_ids) {
        int mid = m_mpd->queueItemToMpdId(qid);
        if (mid >= 0) mpd_ids.push_back(mid);
    }
    if (!mpd_ids.empty()) m_mpd->removeTracks(mpd_ids);
}

// ---- MPD state callback ----------------------------------------------------

void QcManager::onMpdState(const MpdState& st) {
    if (!m_ws || !m_ws_active) return;

    QueueRendererState qrs;
    qrs.state.current_position_ms = st.position_ms;
    qrs.state.duration_ms         = st.duration_ms;
    if (st.queue_id >= 0)
        qrs.state.current_queue_item_id = static_cast<uint32_t>(st.queue_id);

    switch (st.status) {
    case MpdState::Status::PLAY:
        qrs.state.playing_state = PlayingState::PLAYING;
        qrs.state.buffer_state  = BufferState::OK;
        break;
    case MpdState::Status::PAUSE:
        qrs.state.playing_state = PlayingState::PAUSED;
        break;
    case MpdState::Status::STOP:
        qrs.state.playing_state = PlayingState::STOPPED;
        break;
    default:
        break;
    }

    m_ws->reportState(qrs);
    m_ws->reportVolume(st.volume);
}

// ---- Stream URL resolution --------------------------------------------------

std::vector<std::string> QcManager::resolveStreamUrls(
    const std::vector<uint32_t>& track_ids) {
    std::vector<std::string> urls;
    urls.reserve(track_ids.size());
    for (uint32_t tid : track_ids) {
        TrackStreamInfo info;
        if (m_api->getStreamUrl(tid, m_cfg.format_id, info)) {
            urls.push_back(info.stream_url);
        } else {
            LOGERR("QcManager: could not get stream URL for track "
                   << tid << "\n");
            urls.push_back(""); // keep index alignment; MpdCtl skips empty
        }
    }
    return urls;
}

// ---- IPC with upmpdcli (Unix socket) ----------------------------------------

bool QcManager::startIpcServer() {
    m_ipc_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_ipc_sock < 0) {
        LOGERR("QcManager: IPC socket() failed: " << strerror(errno) << "\n");
        return false;
    }

    ::unlink(m_cfg.upmpdcli_sock.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_cfg.upmpdcli_sock.c_str(),
            sizeof(addr.sun_path) - 1);

    if (bind(m_ipc_sock, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        LOGERR("QcManager: IPC bind failed: " << strerror(errno) << "\n");
        close(m_ipc_sock); m_ipc_sock = -1;
        return false;
    }
    listen(m_ipc_sock, 2);

    m_ipc_stop   = false;
    m_ipc_thread = std::thread(&QcManager::ipcLoop, this);
    return true;
}

void QcManager::stopIpcServer() {
    m_ipc_stop = true;
    if (m_ipc_client >= 0) { close(m_ipc_client); m_ipc_client = -1; }
    if (m_ipc_sock   >= 0) { close(m_ipc_sock);   m_ipc_sock   = -1; }
    if (m_ipc_thread.joinable()) m_ipc_thread.join();
    if (!m_cfg.upmpdcli_sock.empty())
        ::unlink(m_cfg.upmpdcli_sock.c_str());
}

void QcManager::ipcLoop() {
    while (!m_ipc_stop && m_ipc_sock >= 0) {
        // Accept connection from upmpdcli
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m_ipc_sock, &rfds);
        struct timeval tv{1, 0};
        if (select(m_ipc_sock + 1, &rfds, nullptr, nullptr, &tv) <= 0)
            continue;

        int client = accept(m_ipc_sock, nullptr, nullptr);
        if (client < 0) continue;
        if (m_ipc_client >= 0) close(m_ipc_client);
        m_ipc_client = client;

        // Read commands from upmpdcli
        char buf[64];
        while (!m_ipc_stop) {
            FD_ZERO(&rfds);
            FD_SET(m_ipc_client, &rfds);
            tv = {1, 0};
            int r = select(m_ipc_client + 1, &rfds, nullptr, nullptr, &tv);
            if (r <= 0) continue;
            ssize_t n = read(m_ipc_client, buf, sizeof(buf) - 1);
            if (n <= 0) break; // client disconnected
            buf[n] = '\0';
            std::string cmd(buf);
            if (cmd.find("STOP") != std::string::npos) {
                LOGINF("QcManager: upmpdcli requests stop\n");
                if (m_ws) { m_ws->disconnect(); m_ws.reset(); }
                if (m_mpd) m_mpd->stop();
                m_ws_active = false;
            }
        }
    }
}

void QcManager::notifyUpmpdcli(const std::string& msg) {
    if (m_ipc_client >= 0)
        write(m_ipc_client, msg.data(), msg.size());
}

} // namespace QConnect
