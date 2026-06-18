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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>

static uint64_t nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

namespace QConnect {

namespace {

constexpr size_t kInitialQueuePrefetchTracks = 2;

}

static std::string formatMs(uint32_t ms) {
    uint32_t s = ms / 1000;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u:%02u", s / 60, s % 60);
    return buf;
}

void QcManager::printNowPlaying(const std::string& title, const std::string& local_path) {
    std::cout << "\033[1;32m▶  " << title << "\033[0m\n";
    LOGINF("▶  " << title << "\n");
    std::string fmt_info;
    if (!local_path.empty()) {
        std::string cmd = "file -b -- '";
        for (char c : local_path) {
            if (c == '\'') cmd += "'\\''";
            else cmd += c;
        }
        cmd += "' 2>/dev/null";
        FILE* fp = popen(cmd.c_str(), "r");
        if (fp) {
            char buf[512];
            while (fgets(buf, sizeof(buf), fp)) fmt_info += buf;
            pclose(fp);
            while (!fmt_info.empty() && (fmt_info.back() == '\n' || fmt_info.back() == '\r'))
                fmt_info.pop_back();
            if (!fmt_info.empty())
                std::cout << "   \033[2m" << fmt_info << "\033[0m\n";
        }
        std::cout << "   \033[2m" << local_path << "\033[0m\n";
    }
    std::cout << std::flush;
    // Update status file state
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status_title = title;
        m_status_format_info = fmt_info;
    }
    m_status_pos_ms.store(0);
    writeStatusFile();
}

void QcManager::writeStatusFile() {
    if (m_cfg.status_file.empty()) return;
    std::string title, fmt_info;
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        title    = m_status_title;
        fmt_info = m_status_format_info;
    }
    int play_state = m_status_play_state.load();
    const char* state_tag = (play_state == 2) ? "[playing] "
                          : (play_state == 3) ? "[paused] "
                                              : "[stopped] ";
    std::string tmp = m_cfg.status_file + ".tmp";
    std::ofstream f(tmp);
    if (!f) return;
    if (title.empty()) {
        f << state_tag << "\n";
    } else {
        uint32_t pos_ms = m_status_pos_ms.load();
        uint32_t dur_ms = m_status_dur_ms.load();
        f << state_tag << title << "  [" << formatMs(pos_ms) << " / " << formatMs(dur_ms) << "]\n";
        if (!fmt_info.empty()) f << fmt_info << "\n";
    }
    f.close();
    std::rename(tmp.c_str(), m_cfg.status_file.c_str());
}

void QcManager::statusLoop() {
    while (!m_status_stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        writeStatusFile();
    }
}

static void removeMaterializedFile(const std::string& path) {
    if (path.empty()) return;
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::remove(path, ec);
    fs::remove(path + ".inprogress", ec);
}

static void removeAllMaterializedFiles() {
    namespace fs = std::filesystem;
    const fs::path dir("/tmp/qconnect2mpd-segmented");
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec))
        return;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        fs::remove_all(entry.path(), ec);
        ec.clear();
    }
}

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

// Returns the path used to persist the OAuth user_auth_token across restarts.
static std::string tokenFilePath() {
    const char* home = getenv("HOME");
    if (home && *home)
        return std::string(home) + "/.local/share/qconnect2mpd/user_token";
    return "/tmp/qconnect2mpd_token";
}

// Detect the local outbound IP (the address other LAN hosts reach us on).
// Uses a non-blocking UDP "connect" to 8.8.8.8 — no packets are sent.
static std::string localIpAddr() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return "127.0.0.1";
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)) < 0) {
        close(fd);
        return "127.0.0.1";
    }
    struct sockaddr_in local{};
    socklen_t len = sizeof(local);
    getsockname(fd, reinterpret_cast<struct sockaddr*>(&local), &len);
    close(fd);
    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
    return ip[0] ? ip : "127.0.0.1";
}

bool QcManager::start() {
    // ---- Qobuz API client --------------------------------------------------
    m_api = std::make_unique<QobuzApi>(m_cfg.api_base_url,
                                        m_cfg.app_id,
                                        m_cfg.app_secret);

    // Authentication is OAuth-only: as of April 2026 Qobuz's /user/login endpoint
    // is closed to third-party clients (cloud migration), so qobuzuser/qobuzpass
    // no longer authenticate. Service mode therefore requires a cached OAuth token
    // — checked before any network call. The one-time token is obtained by running
    // `qobuzconnect2mpd -L` interactively and completing the browser login (see
    // runLogin); it is cached and reused on every subsequent start.
    std::string tok_file = tokenFilePath();
    if (!m_api->loadToken(tok_file)) {
        LOGERR("QcManager: not authenticated — no cached OAuth token at " << tok_file
               << ". Run 'qobuzconnect2mpd -L' once and complete the browser "
                  "login; refusing to start\n");
        return false;
    }

    // Auto-fetch app_id + secret from Qobuz bundle.js when not in config
    // (needed to resolve stream URLs).
    if (m_cfg.app_id.empty()) {
        LOGINF("QcManager: qobuzappid not configured — fetching from bundle.js\n");
        if (!m_api->fetchAppCredentials())
            LOGERR("QcManager: bundle.js fetch failed; streaming will not work\n");
    }

    // ---- MPD controller ----------------------------------------------------
    m_mpd = std::make_unique<MpdCtl>(m_cfg.mpd_host, m_cfg.mpd_port,
                                      m_cfg.mpd_password);
    if (!m_mpd->connect()) {
        LOGSTD("qconnect2mpd: MPD connect FAILED ("
               << m_cfg.mpd_host << ":" << m_cfg.mpd_port << ")\n");
        return false;
    }
    LOGSTD("qconnect2mpd: MPD connected OK ("
           << m_cfg.mpd_host << ":" << m_cfg.mpd_port << ")\n");
    m_mpd->setStateCallback(
        [this](const MpdState& st) { onMpdState(st); });

    // ---- HTTP server -------------------------------------------------------
    m_http = std::make_unique<HttpHandler>(
        m_cfg.uuid, m_cfg.friendly_name,
        m_cfg.http_port, m_cfg.format_id,
        m_api->appId(),
        [this](ConnectCredentials c) { onConnect(std::move(c)); });
    if (!m_http->start()) return false;
    m_api->setLocalProxyBaseUrl("http://127.0.0.1:" +
                                std::to_string(m_cfg.http_port) +
                                "/qobuz-segmented");

    // Register the OAuth redirect handler.  The browser is sent to a Qobuz login
    // page; after login Qobuz redirects to http://<device>:<port>/oauth/callback
    // which is handled here.  Token is cached so this is a one-time step.
    m_http->setOAuthCallback([this, tok_file](const std::string& code) {
        if (!m_api->oauthExchangeCode(code)) {
            LOGERR("QcManager: OAuth code exchange failed\n");
            return;
        }
        m_api->saveToken(tok_file);
        // Reconnect to the Qobuz Connect cloud WebSocket with the new token
        std::string ws_endpoint, ws_jwt;
        if (m_api->fetchQwsToken(ws_endpoint, ws_jwt)) {
            LOGINF("QcManager: cloud JWT obtained after OAuth — connecting\n");
            ConnectCredentials cloud_creds;
            cloud_creds.ws_endpoint = ws_endpoint;
            cloud_creds.ws_jwt      = ws_jwt;
            onConnect(std::move(cloud_creds));
        }
    });

    m_queue_load_stop = false;
    m_queue_load_thread = std::thread(&QcManager::queueLoadLoop, this);

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

    // Proactively connect to the Qobuz Connect cloud WebSocket by fetching a
    // JWT via POST /qws/createToken.  This makes the device visible from any
    // network without requiring the phone to be on the same LAN first.
    // mDNS continues to work as a fallback for same-network direct discovery.
    if (!m_api->userToken().empty()) {
        std::string ws_endpoint, ws_jwt;
        if (m_api->fetchQwsToken(ws_endpoint, ws_jwt)) {
            LOGINF("QcManager: cloud JWT obtained — connecting to WebSocket\n");
            ConnectCredentials cloud_creds;
            cloud_creds.ws_endpoint = ws_endpoint;
            cloud_creds.ws_jwt      = ws_jwt;
            onConnect(std::move(cloud_creds));
        } else {
            LOGERR("QcManager: cloud JWT fetch failed — will connect when phone discovers via mDNS\n");
        }
    } else {
        LOGINF("QcManager: no auth token — waiting for mDNS discovery or OAuth login\n");
    }

    if (!m_cfg.status_file.empty()) {
        m_status_stop = false;
        m_status_thread = std::thread(&QcManager::statusLoop, this);
    }

    m_running = true;
    LOGINF("QcManager: ready — device '" << m_cfg.friendly_name
           << "' advertised as " << m_cfg.uuid << "\n");
    return true;
}

bool QcManager::runLogin(const std::function<bool()>& aborted) {
    m_api = std::make_unique<QobuzApi>(m_cfg.api_base_url,
                                        m_cfg.app_id,
                                        m_cfg.app_secret);

    std::string tok_file = tokenFilePath();
    if (m_api->loadToken(tok_file)) {
        LOGSTD("qconnect2mpd: already authenticated — cached OAuth token at "
               << tok_file << "; nothing to do\n");
        return true;
    }

    // app_id/secret are needed both to build the OAuth URL and to exchange the
    // returned code for a token.
    if (m_cfg.app_id.empty()) {
        LOGINF("QcManager: fetching app credentials from bundle.js\n");
        if (!m_api->fetchAppCredentials()) {
            LOGERR("QcManager: bundle.js fetch failed; cannot start OAuth login\n");
            return false;
        }
    }

    // HTTP server brought up solely to receive the OAuth redirect callback.
    m_http = std::make_unique<HttpHandler>(
        m_cfg.uuid, m_cfg.friendly_name,
        m_cfg.http_port, m_cfg.format_id,
        m_api->appId(),
        [](ConnectCredentials) {});
    if (!m_http->start()) {
        LOGERR("QcManager: HTTP server failed to start on port "
               << m_cfg.http_port << "\n");
        return false;
    }

    std::promise<bool> done;
    std::future<bool>  fut = done.get_future();
    std::atomic<bool>  fired{false};
    m_http->setOAuthCallback(
        [this, tok_file, &done, &fired](const std::string& code) {
            if (fired.exchange(true)) return;   // first redirect wins
            bool ok = m_api->oauthExchangeCode(code) && m_api->saveToken(tok_file);
            done.set_value(ok);
        });

    std::string ip    = localIpAddr();
    std::string redir = "http://" + ip + ":" + std::to_string(m_cfg.http_port)
                        + "/oauth/callback";
    std::string url   = m_api->buildOAuthUrl(redir);
    std::cout << "\n"
              << "  Open this URL in a browser to log in to Qobuz:\n\n"
              << "  \033[1;33m" << url << "\033[0m\n\n"
              << "  Waiting for login to complete (Ctrl-C to abort)…\n\n"
              << std::flush;

    // Block until the redirect fires (token cached) or the caller asks to abort.
    bool ok = false;
    while (!aborted()) {
        if (fut.wait_for(std::chrono::milliseconds(200)) ==
            std::future_status::ready) {
            ok = fut.get();
            break;
        }
    }
    m_http->stop();

    if (ok)
        LOGSTD("qconnect2mpd: login OK — token cached at " << tok_file << "\n");
    else if (aborted())
        LOGSTD("qconnect2mpd: login aborted\n");
    else
        LOGERR("qconnect2mpd: login failed — OAuth code exchange did not succeed\n");
    return ok;
}

void QcManager::stop() {
    if (!m_running) return;
    m_running = false;

    m_status_stop = true;
    if (m_status_thread.joinable()) m_status_thread.join();
    if (!m_cfg.status_file.empty()) {
        std::error_code ec;
        std::filesystem::remove(m_cfg.status_file, ec);
        std::filesystem::remove(m_cfg.status_file + ".tmp", ec);
    }

    stopIpcServer();
    stopQueueLoadWorker();

    if (m_ws) { m_ws->disconnect(); m_ws.reset(); }
    if (m_mdns) { m_mdns->stop(); m_mdns.reset(); }
    if (m_http) { m_http->stop(); m_http.reset(); }
    if (m_mpd)  { m_mpd->disconnect(); m_mpd.reset(); }
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        cleanupMaterializedFiles(m_track_local_paths);
        m_queue_item_ids.clear();
        m_track_local_paths.clear();
        m_track_sample_rates.clear();
        m_track_titles.clear();
    }
    removeAllMaterializedFiles();

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
    cbs.on_set_state  = [this](PlayingState ps, uint32_t pos_ms,
                                bool has_pos,
                                const QueueTrackRef& cur) {
        onSetState(ps, pos_ms, has_pos, cur);
    };
    cbs.on_set_volume = [this](uint32_t v, int32_t d) {
        onSetVolume(v, d);
    };
    cbs.on_queue_load = [this](const std::vector<QueueTrack>& tracks, uint32_t idx) {
        onQueueLoad(tracks, idx);
    };
    cbs.on_tracks_inserted = [this](const std::vector<QueueTrack>& tracks, uint32_t after) {
        onTracksInserted(tracks, after);
    };
    cbs.on_tracks_added = [this](const std::vector<QueueTrack>& tracks) {
        onTracksAdded(tracks);
    };
    cbs.on_tracks_removed = [this](const std::vector<uint64_t>& ids) {
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
    m_queue_load_generation.fetch_add(1, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_pending_queue_load.pending = false;
        m_pending_queue_load.tracks.clear();
    }
    m_queue_load_cv.notify_all();
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        cleanupMaterializedFiles(m_track_local_paths);
        m_queue_item_ids.clear();
        m_track_local_paths.clear();
        m_track_sample_rates.clear();
        m_track_titles.clear();
    }
    if (m_mpd) m_mpd->stop();
    notifyUpmpdcli("STOPPED\n");
    LOGINF("QcManager: WebSocket session ended\n");
}

void QcManager::onSetState(PlayingState ps, uint32_t position_ms,
                           bool has_position,
                           const QueueTrackRef& current_item) {
    if (!m_mpd) return;

    // Clamp bogus positions (server can send unsigned-wrapped negatives)
    if (position_ms > 0x7FFFFFFF) position_ms = 0;

    // Handle track change independently of play state
    // (server sends state=UNKNOWN + qitem=N to mean "switch track, keep state")
    if (current_item.has_queue_item_id) {
        int target_pos = mpdPosForQueueItem(current_item.queue_item_id);
        if (target_pos >= 0)
            m_mpd->play(target_pos);
    }

    // Handle play state change
    switch (ps) {
    case PlayingState::PLAYING:
        // If no track change above, just unpause (don't use play() —
        // it can restart from wrong position after reconnection)
        if (!current_item.has_queue_item_id)
            m_mpd->pause(false);
        break;
    case PlayingState::PAUSED:
        m_mpd->pause(true);
        break;
    case PlayingState::STOPPED:
        m_mpd->stop();
        break;
    default:
        // UNKNOWN = no state change requested
        break;
    }

    // Handle seek independently of play state (has_position distinguishes
    // "seek to 0" from "no seek requested"). Seek can block for seconds
    // repositioning the remote stream, so run it (and the back-button "previous
    // track" heuristic it carries) on the worker thread, off the WS eventLoop.
    if (has_position) {
        bool has_q = current_item.has_queue_item_id;
        postBgTask([this, position_ms, has_q] { doSeek(position_ms, has_q); });
    }
}

void QcManager::doSeek(uint32_t position_ms, bool has_queue_item) {
    if (!m_mpd) return;
    // "Previous track" logic: the Qobuz app sends seek-to-0 for the back button
    // and expects a skip to the previous track when already near the start.
    if (position_ms == 0 && !has_queue_item) {
        MpdState st = m_mpd->getState();
        if (st.position_ms < 3000 && st.queue_pos > 0) {
            m_mpd->previous();
            return;
        }
    }
    bool ok = m_mpd->seek(position_ms);
    LOGINF("QcManager: seek to " << position_ms << " ms -> "
           << (ok ? "OK" : "FAILED (MPD refused — stream may be non-seekable)")
           << "\n");
}

void QcManager::postBgTask(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_bg_tasks.emplace_back(std::move(fn));
    }
    m_queue_load_cv.notify_one();
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

void QcManager::onQueueLoad(const std::vector<QueueTrack>& tracks,
                              uint32_t start_idx) {
    // Empty queue = queue cleared: stop playback and clear MPD
    if (tracks.empty()) {
        LOGINF("QcManager: queue cleared — stopping playback\n");
        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            cleanupMaterializedFiles(m_track_local_paths);
            m_queue_item_ids.clear();
            m_track_local_paths.clear();
            m_track_sample_rates.clear();
            m_track_titles.clear();
        }
        if (m_mpd) m_mpd->stopAndClear();
        return;
    }

    LOGINF("QcManager: loading " << tracks.size()
           << " tracks from Qobuz, starting at " << start_idx << "\n");
    for (size_t i = 0; i < tracks.size(); ++i) {
        LOGINF("QcManager:   track[" << i << "] qitem=" << tracks[i].queue_item_id
               << " trackid=" << tracks[i].track_id << "\n");
    }

    // Clear the current QConnect queue immediately so a user pressing play
    // during background URL resolution cannot resume stale tracks from the
    // previous playlist. Don't use stop() here: it restores the pre-QConnect
    // queue saved from MPD.
    if (m_mpd) {
        m_mpd->loadQueue({}, 0);
    }
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        cleanupMaterializedFiles(m_track_local_paths);
        m_queue_item_ids.clear();
        m_track_local_paths.clear();
        m_track_sample_rates.clear();
        m_track_titles.clear();
    }
    uint64_t generation = m_queue_load_generation.fetch_add(1, std::memory_order_relaxed) + 1;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        // A full queue (re)load replaces everything; drop any add/insert tasks
        // queued against the old queue so they don't append stale tracks.
        m_bg_tasks.clear();
        m_pending_queue_load.tracks = tracks;
        m_pending_queue_load.start_idx = start_idx;
        m_pending_queue_load.generation = generation;
        m_pending_queue_load.pending = true;
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksInserted(const std::vector<QueueTrack>& tracks,
                                   uint32_t insert_after_item_id) {
    // Offload to the queue-load worker: resolveStreamUrls + getTrackMeta do
    // blocking network per track, which must not run on the WS eventLoop thread.
    postBgTask([this, tracks, insert_after_item_id] {
        doTracksInserted(tracks, insert_after_item_id);
    });
}

void QcManager::doTracksInserted(const std::vector<QueueTrack>& tracks,
                                   uint32_t insert_after_item_id) {
    std::vector<uint64_t> item_ids;
    std::vector<int> sample_rates;
    std::vector<std::string> local_paths, titles;
    auto urls = resolveStreamUrls(tracks, item_ids, sample_rates, local_paths, titles);
    if (urls.empty() || !m_mpd) return;

    // Find insert position in our mapping
    int insert_pos = -1;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        for (size_t i = 0; i < m_queue_item_ids.size(); ++i) {
            if (m_queue_item_ids[i] == insert_after_item_id) {
                insert_pos = static_cast<int>(i);
                break;
            }
        }
        auto ins = [&](auto& vec, const auto& src) {
            int pos = insert_pos;
            if (pos >= 0 && pos + 1 <= static_cast<int>(vec.size()))
                vec.insert(vec.begin() + pos + 1, src.begin(), src.end());
            else
                vec.insert(vec.end(), src.begin(), src.end());
        };
        ins(m_queue_item_ids,     item_ids);
        ins(m_track_sample_rates, sample_rates);
        ins(m_track_local_paths,  local_paths);
        ins(m_track_titles,       titles);
    }

    int mpd_id = m_mpd->queueItemToMpdId(insert_after_item_id);
    m_mpd->insertTracks(urls, mpd_id);

    // Backfill display titles for direct-URL tracks (empty from resolve).
    fetchMissingTitles(tracks);
}

void QcManager::onTracksAdded(const std::vector<QueueTrack>& tracks) {
    // Offload to the queue-load worker (see onTracksInserted).
    postBgTask([this, tracks] { doTracksAdded(tracks); });
}

void QcManager::doTracksAdded(const std::vector<QueueTrack>& tracks) {
    std::vector<uint64_t> item_ids;
    std::vector<int> sample_rates;
    std::vector<std::string> local_paths, titles;
    auto urls = resolveStreamUrls(tracks, item_ids, sample_rates, local_paths, titles);
    if (urls.empty() || !m_mpd) return;

    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        m_queue_item_ids.insert(m_queue_item_ids.end(), item_ids.begin(), item_ids.end());
        m_track_sample_rates.insert(m_track_sample_rates.end(), sample_rates.begin(), sample_rates.end());
        m_track_local_paths.insert(m_track_local_paths.end(), local_paths.begin(), local_paths.end());
        m_track_titles.insert(m_track_titles.end(), titles.begin(), titles.end());
    }
    m_mpd->addTracks(urls);

    // Backfill display titles for direct-URL tracks (empty from resolve).
    fetchMissingTitles(tracks);
}

void QcManager::onTracksRemoved(const std::vector<uint64_t>& queue_item_ids) {
    if (!m_mpd) return;
    std::vector<std::string> stale_paths;
    std::vector<int>         positions;   // MPD queue positions to delete
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        // Our parallel vectors mirror the MPD queue 1:1 by position, so a
        // queue_item_id's index IS its MPD queue position. (The qid->mpd-id
        // map is unused/empty, which is why removal silently did nothing.)
        for (uint64_t qid : queue_item_ids) {
            auto it = std::find(m_queue_item_ids.begin(),
                                m_queue_item_ids.end(), qid);
            if (it == m_queue_item_ids.end()) continue;
            size_t idx = static_cast<size_t>(it - m_queue_item_ids.begin());
            positions.push_back(static_cast<int>(idx));
            if (idx < m_track_local_paths.size() && !m_track_local_paths[idx].empty())
                stale_paths.push_back(m_track_local_paths[idx]);
        }
        // Erase from the local vectors in descending index order so earlier
        // erases don't shift the indices still to be removed.
        std::sort(positions.begin(), positions.end(), std::greater<int>());
        for (int pos : positions) {
            size_t idx = static_cast<size_t>(pos);
            if (idx < m_queue_item_ids.size())
                m_queue_item_ids.erase(m_queue_item_ids.begin() + idx);
            if (idx < m_track_sample_rates.size())
                m_track_sample_rates.erase(m_track_sample_rates.begin() + idx);
            if (idx < m_track_local_paths.size())
                m_track_local_paths.erase(m_track_local_paths.begin() + idx);
            if (idx < m_track_titles.size())
                m_track_titles.erase(m_track_titles.begin() + idx);
        }
    }
    cleanupMaterializedFiles(stale_paths);
    if (!positions.empty()) {
        m_mpd->removeByQueuePositions(positions);
        LOGINF("QcManager: removed " << positions.size()
               << " track(s) from queue\n");
    }
}

// ---- MPD state callback ----------------------------------------------------

void QcManager::onMpdState(const MpdState& st) {
    if (!m_ws || !m_ws_active) return;

    QueueRendererState qrs;
    qrs.state.current_position_ms  = st.position_ms;
    qrs.state.position_timestamp_ms = nowMs(); // record when we sampled this
    qrs.state.duration_ms          = st.duration_ms;

    // Map MPD queue position to Qobuz queue_item_id; collect display info on track change.
    std::string track_title, track_local_path;
    if (st.queue_pos >= 0) {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (static_cast<size_t>(st.queue_pos) < m_queue_item_ids.size()) {
            qrs.state.current_queue_item_id = m_queue_item_ids[st.queue_pos];
            qrs.state.has_current_queue_item_id = true;
        }
        if (st.queue_pos != m_last_mpd_queue_pos.load() &&
            st.status == MpdState::Status::PLAY) {
            if (static_cast<size_t>(st.queue_pos) < m_track_titles.size())
                track_title = m_track_titles[st.queue_pos];
            if (static_cast<size_t>(st.queue_pos) < m_track_local_paths.size())
                track_local_path = m_track_local_paths[st.queue_pos];
        }
    }
    // Print now-playing outside the lock (popen/cout can be slow)
    if (!track_title.empty())
        printNowPlaying(track_title, track_local_path);

    switch (st.status) {
    case MpdState::Status::PLAY:
        qrs.state.playing_state = PlayingState::PLAYING;
        // Keep BUFFERING until MPD reports sustained position progression on
        // this track. This is state-based (not fixed-delay) and avoids phone
        // timer lead during startup/network warmup.
        {
            bool new_play_context =
                (m_last_mpd_status != MpdState::Status::PLAY) ||
                (st.queue_pos != m_last_mpd_queue_pos.load());
            if (new_play_context) {
                m_play_progress_samples = 0;
                m_playback_ready = false;
            }
            bool has_timing = (st.duration_ms > 0);
            bool progressed = (st.position_ms > m_last_mpd_pos_ms + 200);
            if (!m_playback_ready && has_timing && progressed) {
                ++m_play_progress_samples;
                if (m_play_progress_samples >= 2) {
                    m_playback_ready = true;
                }
            } else if (!progressed && !new_play_context) {
                // avoid stale count if progress stalls
                m_play_progress_samples = 0;
            }
            qrs.state.buffer_state = m_playback_ready
                                     ? BufferState::OK
                                     : BufferState::BUFFERING;
        }
        break;
    case MpdState::Status::PAUSE:
        qrs.state.playing_state = PlayingState::PAUSED;
        m_playback_ready = false;
        m_play_progress_samples = 0;
        break;
    case MpdState::Status::STOP:
        qrs.state.playing_state = PlayingState::STOPPED;
        m_playback_ready = false;
        m_play_progress_samples = 0;
        break;
    default:
        break;
    }

    LOGDEB("QcManager: reportState state=" << static_cast<int>(qrs.state.playing_state)
           << " pos_ms=" << qrs.state.current_position_ms
           << " dur_ms=" << qrs.state.duration_ms
           << " qitem=" << qrs.state.current_queue_item_id << "\n");

    m_ws->reportState(qrs);
    m_ws->reportVolume(st.volume);

    // Report file quality when track changes
    if (st.queue_pos >= 0) {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (static_cast<size_t>(st.queue_pos) < m_track_sample_rates.size())
            m_ws->reportFileQuality(m_track_sample_rates[st.queue_pos]);
    }
    cleanupPlayedMaterializedFiles(st.queue_pos);

    m_last_mpd_status = st.status;
    m_last_mpd_queue_pos.store(st.queue_pos);
    m_last_mpd_pos_ms = st.position_ms;
    m_status_pos_ms.store(st.position_ms);
    m_status_dur_ms.store(st.duration_ms);
    switch (st.status) {
    case MpdState::Status::PLAY:  m_status_play_state.store(2); break;
    case MpdState::Status::PAUSE: m_status_play_state.store(3); break;
    case MpdState::Status::STOP:  m_status_play_state.store(1); break;
    default:                      m_status_play_state.store(0); break;
    }

    // Audio-format line for the status file, taken from MPD's real decoded
    // format (works for direct-streamed tracks too, which have no local file).
    std::string fmt_info;
    if (st.status != MpdState::Status::STOP && st.sample_rate > 0) {
        std::ostringstream os;
        if (st.bits > 0 && st.bits < 32)      os << static_cast<int>(st.bits) << " bit / ";
        else if (st.bits == 32)               os << "float / ";
        if (st.sample_rate % 1000 == 0)       os << (st.sample_rate / 1000) << " kHz";
        else { char b[16]; snprintf(b, sizeof(b), "%.1f", st.sample_rate / 1000.0);
               os << b << " kHz"; }
        if (st.channels == 1)      os << " / mono";
        else if (st.channels == 2) os << " / stereo";
        else if (st.channels > 2)  os << " / " << static_cast<int>(st.channels) << "ch";
        fmt_info = os.str();
    }
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status_format_info = fmt_info;
    }
}

// ---- Stream URL resolution --------------------------------------------------

std::vector<std::string> QcManager::resolveStreamUrls(
    const std::vector<QueueTrack>& tracks,
    std::vector<uint64_t>& out_item_ids,
    std::vector<int>& out_sample_rates,
    std::vector<std::string>& out_local_paths,
    std::vector<std::string>& out_titles,
    uint64_t generation) {
    std::vector<std::string> urls;
    urls.reserve(tracks.size());
    out_item_ids.clear();
    out_item_ids.reserve(tracks.size());
    out_sample_rates.clear();
    out_sample_rates.reserve(tracks.size());
    out_local_paths.clear();
    out_local_paths.reserve(tracks.size());
    out_titles.clear();
    out_titles.reserve(tracks.size());
    for (const auto& t : tracks) {
        if (queueLoadAborted(generation))
            break;
        TrackStreamInfo info;
        if (m_api->getStreamUrl(t.track_id, m_cfg.format_id, info) &&
            !info.stream_url.empty()) {
            if (queueLoadAborted(generation)) {
                removeMaterializedFile(info.local_path);
                break;
            }
            urls.push_back(info.stream_url);
            out_item_ids.push_back(t.queue_item_id);
            out_sample_rates.push_back(info.sampling_rate);
            out_local_paths.push_back(info.local_path);
            // Title is set by materializeSegmentedTrack for segmented tracks;
            // empty for direct-URL tracks (filled later in queueLoadLoop).
            std::string label;
            if (!info.artist.empty() || !info.title.empty()) {
                label = info.artist.empty() ? info.title
                                            : info.artist + " - " + info.title;
            }
            out_titles.push_back(std::move(label));
        } else {
            LOGERR("QcManager: could not get stream URL for track "
                   << t.track_id << " (qitem=" << t.queue_item_id << ")\n");
        }
    }
    return urls;
}

void QcManager::fetchMissingTitles(const std::vector<QueueTrack>& tracks) {
    for (const auto& t : tracks) {
        // Skip if this queue item already has a title.
        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            auto it = std::find(m_queue_item_ids.begin(),
                                m_queue_item_ids.end(), t.queue_item_id);
            if (it == m_queue_item_ids.end()) continue;
            size_t idx = static_cast<size_t>(it - m_queue_item_ids.begin());
            if (idx >= m_track_titles.size() || !m_track_titles[idx].empty())
                continue;
        }
        TrackMeta meta;
        if (!m_api->getTrackMeta(t.track_id, meta)) continue;
        std::string label = meta.artist.empty()
                            ? meta.title
                            : meta.artist + " - " + meta.title;
        if (label.empty()) continue;
        // Re-resolve the position (it may have shifted) and store the title.
        std::string local_path;
        bool print_now = false;
        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            auto it = std::find(m_queue_item_ids.begin(),
                                m_queue_item_ids.end(), t.queue_item_id);
            if (it == m_queue_item_ids.end()) continue;
            size_t idx = static_cast<size_t>(it - m_queue_item_ids.begin());
            if (idx >= m_track_titles.size() || !m_track_titles[idx].empty())
                continue;
            m_track_titles[idx] = label;
            print_now = (m_last_mpd_queue_pos.load() == static_cast<int>(idx));
            if (print_now && idx < m_track_local_paths.size())
                local_path = m_track_local_paths[idx];
        }
        if (print_now)
            printNowPlaying(label, local_path);
    }
}

bool QcManager::queueLoadAborted(uint64_t generation) const {
    if (m_queue_load_stop.load(std::memory_order_relaxed))
        return true;
    if (generation == 0)
        return false;
    return generation != m_queue_load_generation.load(std::memory_order_relaxed);
}

void QcManager::queueLoadLoop() {
    while (!m_queue_load_stop.load(std::memory_order_relaxed)) {
        PendingQueueLoad req;
        bool have_req = false;
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(m_queue_load_mutex);
            m_queue_load_cv.wait(lk, [this] {
                return m_queue_load_stop.load(std::memory_order_relaxed) ||
                       m_pending_queue_load.pending ||
                       !m_bg_tasks.empty();
            });
            if (m_queue_load_stop.load(std::memory_order_relaxed))
                break;
            if (m_pending_queue_load.pending) {
                req = m_pending_queue_load;
                m_pending_queue_load.pending = false;
                have_req = true;
            } else if (!m_bg_tasks.empty()) {
                task = std::move(m_bg_tasks.front());
                m_bg_tasks.pop_front();
            }
        }
        // Background task (track add/insert): runs off the WebSocket eventLoop
        // thread so its per-track network calls can't stall ping handling.
        if (!have_req) {
            if (task) task();
            continue;
        }

        const size_t initial_track_count =
            std::min(req.tracks.size(),
                     std::max<size_t>(kInitialQueuePrefetchTracks,
                                      static_cast<size_t>(req.start_idx) + 1));

        std::vector<uint64_t> item_ids;
        std::vector<int> sample_rates;
        std::vector<std::string> local_paths, titles;
        auto urls = resolveStreamUrls(
            std::vector<QueueTrack>(req.tracks.begin(),
                                    req.tracks.begin() + initial_track_count),
            item_ids, sample_rates, local_paths, titles, req.generation);
        if (req.generation != m_queue_load_generation.load(std::memory_order_relaxed)) {
            cleanupMaterializedFiles(local_paths);
            LOGINF("QcManager: queue load superseded while resolving streams\n");
            continue;
        }
        if (urls.empty()) {
            LOGERR("QcManager: failed to resolve any stream URLs\n");
            continue;
        }
        if (!m_mpd) continue;

        int mpd_start = 0;
        if (req.start_idx > 0 && req.start_idx < req.tracks.size()) {
            uint64_t target_item = req.tracks[req.start_idx].queue_item_id;
            for (size_t i = 0; i < item_ids.size(); ++i) {
                if (item_ids[i] == target_item) {
                    mpd_start = static_cast<int>(i);
                    break;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            cleanupMaterializedFiles(m_track_local_paths);
            m_queue_item_ids    = item_ids;
            m_track_sample_rates = sample_rates;
            m_track_local_paths  = local_paths;
            m_track_titles       = titles;
        }

        if (!m_mpd->loadQueue(urls, mpd_start)) {
            LOGERR("QcManager: MPD loadQueue failed\n");
            continue;
        }

        if (m_ws) {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            if (static_cast<size_t>(mpd_start) < m_track_sample_rates.size())
                m_ws->reportFileQuality(m_track_sample_rates[mpd_start]);
        }

        // Fetch titles for initial tracks that don't have one yet (direct-URL tracks;
        // segmented tracks already got their title from materializeSegmentedTrack).
        // Runs after loadQueue so MPD is already playing.
        for (size_t i = 0; i < initial_track_count; ++i) {
            if (queueLoadAborted(req.generation)) break;
            bool need_title;
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                need_title = i < m_track_titles.size() && m_track_titles[i].empty();
            }
            if (!need_title) continue;
            TrackMeta meta;
            if (!m_api->getTrackMeta(req.tracks[i].track_id, meta)) continue;
            std::string label = meta.artist.empty() ? meta.title
                                                    : meta.artist + " - " + meta.title;
            std::string local_path;
            bool print_now = false;
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                if (i < m_track_titles.size() && m_track_titles[i].empty()) {
                    m_track_titles[i] = label;
                    print_now = (m_last_mpd_queue_pos.load() == static_cast<int>(i))
                                && !label.empty();
                    if (print_now && i < m_track_local_paths.size())
                        local_path = m_track_local_paths[i];
                }
            }
            if (print_now)
                printNowPlaying(label, local_path);
        }

        if (initial_track_count >= req.tracks.size())
            continue;

        std::vector<uint64_t> add_item_ids;
        std::vector<int> add_sample_rates;
        std::vector<std::string> add_local_paths, add_titles;
        auto add_urls = resolveStreamUrls(
            std::vector<QueueTrack>(req.tracks.begin() + initial_track_count,
                                    req.tracks.end()),
            add_item_ids, add_sample_rates, add_local_paths, add_titles, req.generation);
        if (req.generation != m_queue_load_generation.load(std::memory_order_relaxed)) {
            cleanupMaterializedFiles(add_local_paths);
            LOGINF("QcManager: queue load superseded while resolving remaining streams\n");
            continue;
        }
        if (add_urls.empty())
            continue;

        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            m_queue_item_ids.insert(m_queue_item_ids.end(), add_item_ids.begin(), add_item_ids.end());
            m_track_sample_rates.insert(m_track_sample_rates.end(), add_sample_rates.begin(), add_sample_rates.end());
            m_track_local_paths.insert(m_track_local_paths.end(), add_local_paths.begin(), add_local_paths.end());
            m_track_titles.insert(m_track_titles.end(), add_titles.begin(), add_titles.end());
        }
        if (!m_mpd->addTracks(add_urls)) {
            LOGERR("QcManager: MPD addTracks failed for deferred queue tail\n");
            cleanupMaterializedFiles(add_local_paths);
            continue;
        }

        // Fetch titles for tail tracks that don't have one yet.
        size_t tail_count = add_urls.size();
        for (size_t i = 0; i < tail_count; ++i) {
            if (queueLoadAborted(req.generation)) break;
            size_t map_idx = initial_track_count + i;
            size_t track_idx = initial_track_count + i;
            bool need_title;
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                need_title = map_idx < m_track_titles.size() && m_track_titles[map_idx].empty();
            }
            if (!need_title) continue;
            TrackMeta meta;
            if (!m_api->getTrackMeta(req.tracks[track_idx].track_id, meta)) continue;
            std::string label = meta.artist.empty() ? meta.title
                                                    : meta.artist + " - " + meta.title;
            std::string local_path;
            bool print_now = false;
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                if (map_idx < m_track_titles.size() && m_track_titles[map_idx].empty()) {
                    m_track_titles[map_idx] = label;
                    print_now = (m_last_mpd_queue_pos.load() == static_cast<int>(map_idx))
                                && !label.empty();
                    if (print_now && map_idx < m_track_local_paths.size())
                        local_path = m_track_local_paths[map_idx];
                }
            }
            if (print_now)
                printNowPlaying(label, local_path);
        }
    }
}

void QcManager::stopQueueLoadWorker() {
    m_queue_load_stop = true;
    m_queue_load_generation.fetch_add(1, std::memory_order_relaxed);
    m_queue_load_cv.notify_all();
    if (m_queue_load_thread.joinable())
        m_queue_load_thread.join();
}

void QcManager::cleanupMaterializedFiles(const std::vector<std::string>& paths) {
    for (const auto& path : paths)
        removeMaterializedFile(path);
}

void QcManager::cleanupPlayedMaterializedFiles(int queue_pos) {
    if (queue_pos < 2) return;
    std::vector<std::string> stale_paths;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        size_t keep_from = static_cast<size_t>(queue_pos - 1);
        size_t limit = std::min(keep_from, m_track_local_paths.size());
        for (size_t i = 0; i < limit; ++i) {
            if (!m_track_local_paths[i].empty()) {
                stale_paths.push_back(m_track_local_paths[i]);
                m_track_local_paths[i].clear();
            }
        }
    }
    cleanupMaterializedFiles(stale_paths);
}

uint64_t QcManager::queueItemIdAt(int mpd_pos) const {
    std::lock_guard<std::mutex> lk(m_qmap_mutex);
    if (mpd_pos >= 0 && static_cast<size_t>(mpd_pos) < m_queue_item_ids.size())
        return m_queue_item_ids[mpd_pos];
    return 0;
}

int QcManager::mpdPosForQueueItem(uint64_t queue_item_id) const {
    std::lock_guard<std::mutex> lk(m_qmap_mutex);
    for (size_t i = 0; i < m_queue_item_ids.size(); ++i) {
        if (m_queue_item_ids[i] == queue_item_id)
            return static_cast<int>(i);
    }
    return -1;
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
