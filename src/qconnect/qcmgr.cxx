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
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <openssl/rand.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

static uint64_t nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

namespace QConnect {

static std::string formatMs(uint32_t ms) {
    uint32_t s = ms / 1000;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u:%02u", s / 60, s % 60);
    return buf;
}

static std::string compactAudioFormat(const MpdState& state) {
    if (state.sample_rate == 0) return {};
    std::string value = std::to_string(state.sample_rate);
    if (state.bits > 0) value += "," + std::to_string(state.bits);
    if (state.channels > 0) value += "," + std::to_string(state.channels);
    return value;
}

void QcManager::printNowPlaying(const std::string& title,
                                const std::string& local_path,
                                const std::string& audio_format) {
    if (!title.empty())
        std::cout << "\033[1;32m▶  " << title << "\033[0m\n";
    if (!local_path.empty()) {
        std::cout << "   \033[2mtrack " << local_path;
        if (!audio_format.empty()) std::cout << " [" << audio_format << "]";
        std::cout << " playing...\033[0m\n";
        LOGINF("track " << local_path
               << (audio_format.empty() ? std::string{} :
                   " [" + audio_format + "]")
               << " playing"
               << (title.empty() ? std::string{} : ": " + title) << "\n");
    } else if (!title.empty()) {
        LOGINF("playing: " << title << "\n");
    }
    std::cout << std::flush;
    // Decoded format is populated from MusicPD's status response.
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status_title = title;
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
    for (const fs::path& dir : {
             fs::path(segmentedCacheDirectory()),
             fs::path("/tmp/qconnect2mpd-segmented")}) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec))
            continue;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            fs::remove_all(entry.path(), ec);
            ec.clear();
        }
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
    const char* data_home = getenv("XDG_DATA_HOME");
    if (data_home && *data_home)
        return std::string(data_home) + "/qconnect2mpd/user_token";
    const char* home = getenv("HOME");
    if (home && *home)
        return std::string(home) + "/.local/share/qconnect2mpd/user_token";
    const struct passwd* account = ::getpwuid(::geteuid());
    if (account && account->pw_dir && account->pw_dir[0] == '/' &&
        std::strcmp(account->pw_dir, "/nonexistent") != 0) {
        return std::string(account->pw_dir) +
               "/.local/share/qconnect2mpd/user_token";
    }
    return {};
}

static std::string oauthCallbackPath() {
    std::array<unsigned char, 16> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string path = "/oauth/callback/";
    path.reserve(path.size() + nonce.size() * 2);
    for (unsigned char byte : nonce) {
        path.push_back(hex[byte >> 4]);
        path.push_back(hex[byte & 0x0f]);
    }
    return path;
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
    if (m_running.exchange(true)) {
        LOGERR("QcManager: start requested while already running\n");
        return false;
    }
    m_stopping.store(false, std::memory_order_release);
    removeAllMaterializedFiles();
    // ---- Qobuz API client --------------------------------------------------
    m_api = std::make_unique<QobuzApi>(m_cfg.api_base_url,
                                        m_cfg.app_id,
                                        m_cfg.app_secret);
    m_api->setSegmentedRegistry(&m_seg_registry);

    // Both values are required to sign stream URL requests. Fetch a complete
    // pair when either half of the configured pair is missing.
    if (m_cfg.app_id.empty() || m_cfg.app_secret.empty()) {
        LOGINF("QcManager: Qobuz app credentials incomplete; fetching them\n");
        if (!m_api->fetchAppCredentials())
            LOGERR("QcManager: bundle.js fetch failed; streaming will not work\n");
    }

    // OAuth is the only user authentication path. The token is cached so login
    // is a one-time interactive step.
    std::string tok_file = m_cfg.token_file.empty()
        ? tokenFilePath() : m_cfg.token_file;
    if (tok_file.empty()) {
        LOGERR("QcManager: no token cache path; set qconnecttokenfile\n");
    } else {
        m_api->loadToken(tok_file);
    }

    // ---- MPD controller ----------------------------------------------------
    m_mpd = std::make_unique<MpdCtl>(m_cfg.mpd_host, m_cfg.mpd_port,
                                      m_cfg.mpd_password);
    if (!m_mpd->connect()) {
        LOGSTD("qconnect2mpd: MPD connect FAILED ("
               << m_cfg.mpd_host << ":" << m_cfg.mpd_port << ")\n");
        stop();
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
    m_http->setSegmentedRegistry(&m_seg_registry);

    const bool needs_oauth = m_api->userToken().empty();
    std::string oauth_path;
    if (needs_oauth && tok_file.empty()) {
        LOGERR("QcManager: OAuth login disabled without a secure token path\n");
    } else if (needs_oauth) {
        oauth_path = oauthCallbackPath();
        if (oauth_path.empty()) {
            LOGERR("QcManager: could not create a secure OAuth callback path\n");
        } else {
            // The browser redirect is accepted once, for five minutes, on an
            // unguessable path. The token is persisted before login succeeds.
            m_http->setOAuthCallback(
                oauth_path,
                [this, tok_file](const std::string& code) {
                    if (!m_api->oauthExchangeCode(code)) {
                        LOGERR("QcManager: OAuth code exchange failed\n");
                        return false;
                    }
                    if (!m_api->saveToken(tok_file)) {
                        LOGERR("QcManager: OAuth token could not be persisted\n");
                        return false;
                    }
                    std::string ws_endpoint, ws_jwt;
                    if (m_api->fetchQwsToken(ws_endpoint, ws_jwt)) {
                        LOGINF("QcManager: cloud JWT obtained after OAuth — connecting\n");
                        ConnectCredentials cloud_creds;
                        cloud_creds.ws_endpoint = ws_endpoint;
                        cloud_creds.ws_jwt      = ws_jwt;
                        onConnect(std::move(cloud_creds));
                    }
                    return true;
                });
        }
    }
    if (!m_http->start()) {
        stop();
        return false;
    }
    m_api->setLocalProxyBaseUrl("http://127.0.0.1:" +
                                std::to_string(m_cfg.http_port) +
                                "/qobuz-segmented");

    // If not yet authenticated, print the OAuth URL so the user can log in.
    if (needs_oauth && !oauth_path.empty() && !m_api->appId().empty()) {
        std::string ip    = localIpAddr();
        std::string redir = "http://" + ip + ":" + std::to_string(m_cfg.http_port)
                            + oauth_path;
        std::string oauth_url = m_api->buildOAuthUrl(redir);
        std::cout << "\n"
                  << "  Not authenticated — open this URL in a browser to log in:\n\n"
                  << "  \033[1;33m" << oauth_url << "\033[0m\n\n"
                  << "  (after login this device will connect automatically)\n\n"
                  << std::flush;
    }
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

    LOGINF("QcManager: ready — device '" << m_cfg.friendly_name
           << "' advertised as " << m_cfg.uuid << "\n");
    return true;
}

void QcManager::stop() {
    if (!m_running.exchange(false)) return;
    m_stopping.store(true, std::memory_order_release);

    m_status_stop = true;
    if (m_status_thread.joinable()) m_status_thread.join();
    if (!m_cfg.status_file.empty()) {
        std::error_code ec;
        std::filesystem::remove(m_cfg.status_file, ec);
        std::filesystem::remove(m_cfg.status_file + ".tmp", ec);
    }

    stopIpcServer();

    // Wait for a connect request which entered before m_stopping was set. New
    // requests observe m_stopping while holding this same mutex and are ignored.
    {
        std::lock_guard<std::mutex> connect_lk(m_connect_mutex);
    }

    std::shared_ptr<WSession> ws;
    {
        std::lock_guard<std::mutex> lk(m_session_mutex);
        ws = std::move(m_ws);
    }
    if (ws) ws->disconnect();
    deactivateRenderer();
    stopQueueLoadWorker();
    // The loader can publish a plan after deactivateRenderer() clears the
    // registry but before it observes its cancelled generation. Join it first,
    // then cancel every remaining reader before MHD waits for request threads.
    m_seg_registry.clear();
    if (m_http) { m_http->stop(); m_http.reset(); }
    if (m_mdns) { m_mdns->stop(); m_mdns.reset(); }
    if (m_mpd)  {
        m_mpd->restoreSavedQueue();
        m_mpd->disconnect();
        m_mpd.reset();
    }
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        cleanupMaterializedFiles(m_track_local_paths);
        m_queue_item_ids.clear();
        m_track_local_paths.clear();
        m_track_sample_rates.clear();
        m_track_titles.clear();
        m_track_segment_tokens.clear();
        m_all_queue_item_ids.clear();
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
    std::lock_guard<std::mutex> connect_lk(m_connect_mutex);
    if (m_stopping.load(std::memory_order_acquire)) {
        LOGINF("QcManager: ignoring Qobuz connection during shutdown\n");
        return;
    }

    LOGINF("QcManager: Qobuz app connected\n");

    // Fully retire an existing renderer session before installing its
    // replacement. Otherwise its loader and MPD events can leak into the new
    // WSession before SetActive arrives.
    std::shared_ptr<WSession> old;
    {
        std::lock_guard<std::mutex> lk(m_session_mutex);
        old = m_ws;
    }
    if (old) {
        deactivateRenderer();
        {
            std::lock_guard<std::mutex> lk(m_session_mutex);
            if (m_ws == old) m_ws.reset();
        }
        old->disconnect();
    }

    // Update session ID shown in get-connect-info
    m_http->setSessionId(creds.session_id);

    // Build WSession callbacks
    WSessionCallbacks cbs;
    cbs.on_set_state  = [this](uint64_t command_id, PlayingState ps,
                                uint32_t pos_ms,
                                bool has_pos,
                                const QueueTrackRef& cur) {
        onSetState(command_id, ps, pos_ms, has_pos, cur);
    };
    cbs.on_set_volume = [this](uint32_t v, int32_t d) {
        onSetVolume(v, d);
    };
    cbs.on_set_active = [this](bool active) { onSetActive(active); };
    cbs.on_session_state = [this](const MsgSessionState& state) {
        onSessionState(state);
    };
    cbs.on_queue_state = [this](const MsgQueueState& queue) {
        onQueueState(queue);
    };
    cbs.on_queue_load = [this](const MsgQueueLoadTracks& queue) {
        onQueueLoad(queue);
    };
    cbs.on_queue_cleared = [this](const MsgQueueCleared& queue) {
        onQueueCleared(queue);
    };
    cbs.on_tracks_inserted = [this](const MsgQueueTracksInserted& update) {
        onTracksInserted(update);
    };
    cbs.on_tracks_added = [this](const MsgQueueTracksAdded& update) {
        onTracksAdded(update);
    };
    cbs.on_tracks_removed = [this](const MsgQueueTracksRemoved& update) {
        onTracksRemoved(update);
    };
    cbs.on_tracks_reordered = [this](const MsgQueueTracksReordered& update) {
        onTracksReordered(update);
    };
    cbs.on_shuffle_mode = [this](const MsgShuffleMode& update) {
        onShuffleMode(update);
    };
    cbs.on_loop_mode = [this](const MsgLoopMode& update) {
        onLoopMode(update);
    };
    cbs.on_connected    = [this]() { onWsConnected(); };
    cbs.on_disconnected = [this](bool error) { onWsDisconnected(error); };

    auto ws = std::make_shared<WSession>(m_devinfo, cbs);
    {
        // Install ownership before connect() starts its receive/callback
        // threads. A fast SessionState/SetActive callback must be able to find
        // the session it belongs to.
        std::lock_guard<std::mutex> lk(m_session_mutex);
        m_ws = ws;
    }
    if (!ws->connect(creds)) {
        LOGERR("QcManager: WebSocket connect failed\n");
        {
            std::lock_guard<std::mutex> lk(m_session_mutex);
            if (m_ws == ws) m_ws.reset();
        }
        deactivateRenderer();
    }
}

// ---- WSession callbacks ----------------------------------------------------

void QcManager::onWsConnected() {
    LOGINF("QcManager: WebSocket session connected\n");
}

void QcManager::cancelQueueOperations() {
    m_queue_load_generation.fetch_add(1, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.clear();
    }
    m_queue_load_cv.notify_all();
    uint64_t pending_command = 0;
    {
        std::lock_guard<std::mutex> lk(m_pending_mutex);
        if (m_pending_playback.active)
            pending_command = m_pending_playback.command_id;
        m_pending_playback = PendingPlayback{};
    }
    completeSetState(pending_command);
    m_queue_loading.store(false, std::memory_order_relaxed);
}

void QcManager::deactivateRenderer() {
    m_ws_active = false;
    cancelQueueOperations();
    bool restored = true;
    std::vector<std::string> stale_paths;
    {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        if (m_mpd) restored = m_mpd->restoreSavedQueue();
        if (restored) {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            stale_paths.swap(m_track_local_paths);
            m_queue_item_ids.clear();
            m_all_queue_item_ids.clear();
            m_track_sample_rates.clear();
            m_track_titles.clear();
            m_track_segment_tokens.clear();
        }
    }
    if (restored) {
        cleanupMaterializedFiles(stale_paths);
        m_seg_registry.clear();
    } else {
        LOGERR("QcManager: could not restore the pre-QConnect MPD state\n");
    }
    notifyUpmpdcli("STOPPED\n");
}

void QcManager::onSetActive(bool active) {
    if (!active) {
        LOGINF("QcManager: renderer deactivated\n");
        deactivateRenderer();
        return;
    }

    if (m_mpd && !m_mpd->beginSession()) {
        LOGERR("QcManager: could not snapshot the pre-QConnect MPD state\n");
        return;
    }
    m_ws_active = true;
    notifyUpmpdcli("PLAYING\n");
    LOGINF("QcManager: renderer active\n");
}

void QcManager::onWsDisconnected(bool error) {
    deactivateRenderer();
    if (error) {
        LOGERR("QcManager: WebSocket connection lost — exiting so systemd can restart the service\n");
        m_fatal_error.store(true, std::memory_order_relaxed);
    } else {
        LOGINF("QcManager: WebSocket session ended (replaced or stopped)\n");
    }
}

void QcManager::onSetState(uint64_t command_id, PlayingState ps,
                           uint32_t position_ms,
                           bool has_position,
                           const QueueTrackRef& current_item) {
    if (!m_mpd || !m_ws_active.load(std::memory_order_relaxed)) {
        completeSetState(command_id);
        return;
    }

    // Clamp bogus positions (server can send unsigned-wrapped negatives)
    if (position_ms > 0x7FFFFFFF) position_ms = 0;

    LOGINF("QcManager: onSetState ps=" << static_cast<int>(ps)
           << " has_pos=" << has_position << " pos_ms=" << position_ms
           << " has_qitem=" << current_item.has_queue_item_id
           << " qid=" << current_item.queue_item_id << "\n");

    const bool unavailable_target = current_item.has_queue_item_id &&
        mpdPosForQueueItem(current_item.queue_item_id) < 0;
    if (m_queue_loading.load(std::memory_order_relaxed) || unavailable_target) {
        uint64_t superseded = 0;
        {
            std::lock_guard<std::mutex> lk(m_pending_mutex);
            if (m_pending_playback.active)
                superseded = m_pending_playback.command_id;
            m_pending_playback.active = true;
            m_pending_playback.command_id = command_id;
            m_pending_playback.state = ps;
            m_pending_playback.has_target = current_item.has_queue_item_id;
            m_pending_playback.target_qid = current_item.queue_item_id;
            m_pending_playback.has_position = has_position;
            m_pending_playback.position_ms = position_ms;
        }
        completeSetState(superseded);
        LOGINF("QcManager: playback command deferred until its target is queued\n");
        return;
    }

    applyPlaybackCommand(ps, current_item.has_queue_item_id,
                         current_item.queue_item_id, has_position, position_ms,
                         command_id);
}

void QcManager::onSetVolume(uint32_t volume, int32_t delta) {
    if (!m_mpd || !m_ws_active.load(std::memory_order_relaxed)) return;
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

void QcManager::onSessionState(const MsgSessionState& state) {
    m_session_has_track_index.store(state.has_track_index,
                                    std::memory_order_relaxed);
    if (state.has_track_index)
        m_session_track_index.store(state.track_index,
                                    std::memory_order_relaxed);
}

void QcManager::onQueueState(const MsgQueueState& queue) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    if (queue.has_shuffle_on) {
        MsgShuffleMode mode;
        mode.shuffle_on = queue.shuffle_on;
        mode.has_shuffle_on = true;
        onShuffleMode(mode);
    }

    std::vector<QueueTrack> effective_tracks = queue.tracks;
    if (queue.shuffle_on && !queue.shuffled_track_indexes.empty()) {
        bool valid = queue.shuffled_track_indexes.size() == queue.tracks.size();
        std::vector<bool> seen(queue.tracks.size(), false);
        for (uint32_t index : queue.shuffled_track_indexes) {
            if (index >= queue.tracks.size() || seen[index]) {
                valid = false;
                break;
            }
            seen[index] = true;
        }
        if (valid) {
            effective_tracks.clear();
            effective_tracks.reserve(queue.tracks.size());
            for (uint32_t index : queue.shuffled_track_indexes)
                effective_tracks.push_back(queue.tracks[index]);
        } else {
            LOGERR("QcManager: ignored invalid shuffled queue permutation\n");
        }
    }
    if (effective_tracks.empty()) {
        MsgQueueCleared cleared;
        cleared.queue_version = queue.queue_version;
        onQueueCleared(cleared);
        return;
    }

    bool same = false;
    uint64_t current_qid = 0;
    bool has_current = false;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        same = effective_tracks.size() == m_all_queue_item_ids.size();
        if (same) {
            for (size_t i = 0; i < effective_tracks.size(); ++i) {
                if (effective_tracks[i].queue_item_id != m_all_queue_item_ids[i]) {
                    same = false;
                    break;
                }
            }
        }
        int current_pos = m_last_mpd_queue_pos.load(std::memory_order_relaxed);
        if (current_pos >= 0 &&
            static_cast<size_t>(current_pos) < m_queue_item_ids.size()) {
            current_qid = m_queue_item_ids[current_pos];
            has_current = true;
        }
    }
    if (same) {
        commitQueueVersion(queue.queue_version);
        return;
    }

    uint32_t start_idx = 0;
    if (has_current) {
        for (size_t i = 0; i < effective_tracks.size(); ++i) {
            if (effective_tracks[i].queue_item_id == current_qid) {
                start_idx = static_cast<uint32_t>(i);
                MpdState st = m_mpd ? m_mpd->getState() : MpdState{};
                PlayingState desired = PlayingState::UNKNOWN;
                if (st.status == MpdState::Status::PLAY)
                    desired = PlayingState::PLAYING;
                else if (st.status == MpdState::Status::PAUSE)
                    desired = PlayingState::PAUSED;
                else if (st.status == MpdState::Status::STOP)
                    desired = PlayingState::STOPPED;
                std::lock_guard<std::mutex> plk(m_pending_mutex);
                m_pending_playback.active = true;
                m_pending_playback.state = desired;
                m_pending_playback.has_target = true;
                m_pending_playback.target_qid = current_qid;
                m_pending_playback.has_position = true;
                m_pending_playback.position_ms = st.position_ms;
                break;
            }
        }
    } else if (m_session_has_track_index.exchange(false,
                                                   std::memory_order_relaxed)) {
        start_idx = m_session_track_index.load(std::memory_order_relaxed);
    }
    enqueueQueueLoad(effective_tracks, start_idx, queue.queue_version);
}

void QcManager::onQueueLoad(const MsgQueueLoadTracks& queue) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    if (queue.has_shuffle_on)
        m_shuffle_on.store(queue.shuffle_on, std::memory_order_relaxed);
    enqueueQueueLoad(queue.tracks,
                     queue.has_queue_position ? queue.queue_position : 0,
                     queue.queue_version);
}

void QcManager::onQueueCleared(const MsgQueueCleared& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    LOGINF("QcManager: queue cleared\n");
    cancelQueueOperations();

    std::vector<std::string> stale_paths;
    {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        if (!m_mpd || !m_mpd->stopAndClear()) {
            LOGERR("QcManager: MusicPD rejected queue clear; local mapping retained\n");
            return;
        }
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        stale_paths.swap(m_track_local_paths);
        m_queue_item_ids.clear();
        m_all_queue_item_ids.clear();
        m_track_sample_rates.clear();
        m_track_titles.clear();
        m_track_segment_tokens.clear();
    }
    cleanupMaterializedFiles(stale_paths);
    m_seg_registry.clear();
    commitQueueVersion(update.queue_version);
    refreshMpdState();
}

void QcManager::enqueueQueueLoad(const std::vector<QueueTrack>& tracks,
                                 uint32_t start_idx,
                                 const QueueVersion& queue_version) {
    if (tracks.empty()) {
        MsgQueueCleared cleared;
        cleared.queue_version = queue_version;
        onQueueCleared(cleared);
        return;
    }
    if (start_idx >= tracks.size()) start_idx = 0;
    LOGINF("QcManager: queueing " << tracks.size()
           << " tracks, initial item " << start_idx << "\n");

    uint64_t generation =
        m_queue_load_generation.fetch_add(1, std::memory_order_relaxed) + 1;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.clear();
    }

    uint64_t abandoned_command = 0;
    {
        std::lock_guard<std::mutex> lk(m_pending_mutex);
        if (m_pending_playback.active && m_pending_playback.has_target) {
            bool target_present = std::any_of(
                tracks.begin(), tracks.end(), [this](const QueueTrack& track) {
                    return track.queue_item_id == m_pending_playback.target_qid;
                });
            if (!target_present) {
                abandoned_command = m_pending_playback.command_id;
                m_pending_playback = PendingPlayback{};
            }
        }
    }
    completeSetState(abandoned_command);

    // Stop the previous QConnect item while resolving the new current URL, but
    // keep it available for MpdCtl's transactional rollback.
    {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        if (generation !=
            m_queue_load_generation.load(std::memory_order_relaxed))
            return;
        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            m_all_queue_item_ids.clear();
            m_all_queue_item_ids.reserve(tracks.size());
            for (const auto& track : tracks)
                m_all_queue_item_ids.push_back(track.queue_item_id);
        }
        m_queue_loading.store(true, std::memory_order_relaxed);
        if (m_mpd && !m_mpd->stop())
            LOGERR("QcManager: could not stop old queue before replacement\n");
    }
    QueueOp op;
    op.type = QueueOp::Type::Load;
    op.generation = generation;
    op.queue_version = queue_version;
    op.tracks = tracks;
    op.start_idx = start_idx;

    // Resolve the requested item and its successor first. Nearby predecessors
    // and successors then alternate, so next/previous become usable quickly.
    std::vector<bool> queued(tracks.size(), false);
    auto push = [&](size_t index) {
        if (index < tracks.size() && !queued[index]) {
            queued[index] = true;
            op.remaining_indices.push_back(index);
        }
    };
    push(start_idx);
    push(static_cast<size_t>(start_idx) + 1);
    for (size_t distance = 1; distance < tracks.size(); ++distance) {
        if (distance <= start_idx) push(start_idx - distance);
        push(static_cast<size_t>(start_idx) + 1 + distance);
    }

    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.push_back(std::move(op));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksInserted(const MsgQueueTracksInserted& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    QueueOp op;
    op.type = QueueOp::Type::Insert;
    op.generation = m_queue_load_generation.load(std::memory_order_relaxed);
    op.queue_version = update.queue_version;
    op.tracks = update.tracks;
    op.insert_after_item_id = update.insert_after;
    op.has_insert_after = update.has_insert_after;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.push_back(std::move(op));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksAdded(const MsgQueueTracksAdded& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    QueueOp op;
    op.type = QueueOp::Type::Add;
    op.generation = m_queue_load_generation.load(std::memory_order_relaxed);
    op.queue_version = update.queue_version;
    op.tracks = update.tracks;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.push_back(std::move(op));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksRemoved(const MsgQueueTracksRemoved& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    QueueOp op;
    op.type = QueueOp::Type::Remove;
    op.generation = m_queue_load_generation.load(std::memory_order_relaxed);
    op.queue_version = update.queue_version;
    op.item_ids = update.queue_item_ids;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.push_back(std::move(op));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksReordered(const MsgQueueTracksReordered& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    QueueOp op;
    op.type = QueueOp::Type::Reorder;
    op.generation = m_queue_load_generation.load(std::memory_order_relaxed);
    op.queue_version = update.queue_version;
    op.item_ids = update.queue_item_ids;
    op.reorder_after_item_id = update.insert_after;
    op.has_reorder_after = update.has_insert_after;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_async_tasks.push_back(std::move(op));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onShuffleMode(const MsgShuffleMode& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    if (!update.has_shuffle_on) return;
    m_shuffle_on.store(update.shuffle_on, std::memory_order_relaxed);
    // ShuffleModeSet is an independent, authoritative notification in the
    // protocol. A later queue snapshot/reorder, when present, applies and
    // commits its own permutation; MusicPD random mode must stay disabled
    // because it would choose a different order from Qobuz.
    commitQueueVersion(update.queue_version);
}

void QcManager::onLoopMode(const MsgLoopMode& update) {
    if (!m_ws_active.load(std::memory_order_relaxed)) return;
    if (!update.has_mode || update.mode == LoopMode::UNKNOWN) return;
    m_loop_mode.store(static_cast<int>(update.mode), std::memory_order_relaxed);
    bool repeat = update.mode == LoopMode::REPEAT_ONE ||
                  update.mode == LoopMode::REPEAT_ALL;
    bool single = update.mode == LoopMode::REPEAT_ONE;
    bool applied = true;
    {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        bool have_qconnect_queue;
        {
            std::lock_guard<std::mutex> lk(m_qmap_mutex);
            have_qconnect_queue = !m_queue_item_ids.empty();
        }
        if (have_qconnect_queue && m_mpd)
            applied = m_mpd->setLoopMode(repeat, single);
    }
    if (!applied) {
        LOGERR("QcManager: failed to apply loop mode to MusicPD\n");
        return;
    }
}

// ---- MPD state callback ----------------------------------------------------

void QcManager::onMpdState(const MpdState& st) {
    std::lock_guard<std::mutex> report_lk(m_state_report_mutex);
    if (!m_ws_active.load(std::memory_order_relaxed) ||
        m_queue_loading.load(std::memory_order_relaxed))
        return;
    auto ws = currentWSession();
    if (!ws) return;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (st.queue_len != static_cast<int>(m_queue_item_ids.size()))
            return; // transient MPD event sampled across an atomic queue commit
    }
    prioritizeDownloads(st);

    QueueRendererState qrs;
    qrs.state.current_position_ms  = st.position_ms;
    qrs.state.has_position         = true;
    qrs.state.position_timestamp_ms = nowMs(); // record when we sampled this
    qrs.state.duration_ms          = st.duration_ms;

    // Map MPD queue position to Qobuz queue_item_id; collect display info when
    // MusicPD starts or resumes a track.
    const bool began_playing = st.status == MpdState::Status::PLAY &&
        (m_last_mpd_status != MpdState::Status::PLAY ||
         st.queue_pos != m_last_mpd_queue_pos.load(std::memory_order_relaxed));
    std::string track_title, track_local_path, track_segment_token;
    if (st.queue_pos >= 0) {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (static_cast<size_t>(st.queue_pos) < m_queue_item_ids.size()) {
            qrs.state.current_queue_item_id = m_queue_item_ids[st.queue_pos];
            qrs.state.has_current_queue_item_id = true;
            auto full = std::find(m_all_queue_item_ids.begin(),
                                  m_all_queue_item_ids.end(),
                                  qrs.state.current_queue_item_id);
            if (full != m_all_queue_item_ids.end()) {
                qrs.state.current_queue_index = static_cast<uint32_t>(
                    full - m_all_queue_item_ids.begin());
                qrs.state.has_current_queue_index = true;
            }
        }
        if (st.next_queue_pos >= 0 &&
            static_cast<size_t>(st.next_queue_pos) < m_queue_item_ids.size()) {
            qrs.state.next_queue_item_id = m_queue_item_ids[st.next_queue_pos];
            qrs.state.has_next_queue_item_id = true;
        }
        if (began_playing) {
            if (static_cast<size_t>(st.queue_pos) < m_track_titles.size())
                track_title = m_track_titles[st.queue_pos];
            if (static_cast<size_t>(st.queue_pos) < m_track_local_paths.size())
                track_local_path = m_track_local_paths[st.queue_pos];
            if (static_cast<size_t>(st.queue_pos) < m_track_segment_tokens.size())
                track_segment_token = m_track_segment_tokens[st.queue_pos];
        }
    }
    if (track_local_path.empty() && !track_segment_token.empty())
        track_local_path = m_seg_registry.cachePath(track_segment_token);

    std::string decoded_format;
    if (st.status != MpdState::Status::STOP && st.sample_rate > 0) {
        std::ostringstream stream;
        if (st.bits > 0 && st.bits < 32)
            stream << static_cast<unsigned>(st.bits) << " bit / ";
        else if (st.bits == 32)
            stream << "float / ";
        if (st.sample_rate % 1000 == 0) {
            stream << st.sample_rate / 1000 << " kHz";
        } else {
            char rate[16];
            snprintf(rate, sizeof(rate), "%.1f", st.sample_rate / 1000.0);
            stream << rate << " kHz";
        }
        if (st.channels == 1)
            stream << " / mono";
        else if (st.channels == 2)
            stream << " / stereo";
        else if (st.channels > 2)
            stream << " / " << static_cast<unsigned>(st.channels) << "ch";
        decoded_format = stream.str();
    }
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status_format_info = std::move(decoded_format);
    }
    // Print now-playing outside the queue-map and status locks. The compact
    // format comes from MusicPD's decoder, so channels are authoritative here.
    if (!track_title.empty() || !track_local_path.empty())
        printNowPlaying(track_title, track_local_path,
                        compactAudioFormat(st));

    switch (st.status) {
    case MpdState::Status::PLAY:
        qrs.state.playing_state = PlayingState::PLAYING;
        // Keep BUFFERING until MPD reports sustained position progression on
        // this track. This is state-based (not fixed-delay) and avoids phone
        // timer lead during startup/network warmup.
        {
            bool new_play_context =
                (m_last_mpd_status != MpdState::Status::PLAY) ||
                (st.queue_pos != m_last_mpd_queue_pos.load()) ||
                m_force_buffering.exchange(false, std::memory_order_relaxed);
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
        qrs.state.buffer_state = BufferState::OK;
        m_force_buffering.store(false, std::memory_order_relaxed);
        m_playback_ready = false;
        m_play_progress_samples = 0;
        break;
    case MpdState::Status::STOP:
        qrs.state.playing_state = PlayingState::STOPPED;
        qrs.state.buffer_state = BufferState::OK;
        m_force_buffering.store(false, std::memory_order_relaxed);
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

    ws->reportState(qrs);
    ws->reportVolume(st.volume);

    // Report file quality when track changes
    if (st.queue_pos >= 0) {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (static_cast<size_t>(st.queue_pos) < m_track_sample_rates.size())
            ws->reportFileQuality(m_track_sample_rates[st.queue_pos]);
    }

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
}

// ---- Stream URL resolution --------------------------------------------------

std::vector<std::string> QcManager::resolveStreamUrls(
    const std::vector<QueueTrack>& tracks,
    std::vector<uint64_t>& out_item_ids,
    std::vector<int>& out_sample_rates,
    std::vector<std::string>& out_local_paths,
    std::vector<std::string>& out_titles,
    std::vector<std::string>& out_segment_tokens,
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
    out_segment_tokens.clear();
    out_segment_tokens.reserve(tracks.size());
    for (const auto& t : tracks) {
        if (queueLoadAborted(generation))
            break;
        TrackStreamInfo info;
        if (m_api->getStreamUrl(t.track_id, m_cfg.format_id, info) &&
            !info.stream_url.empty()) {
            if (queueLoadAborted(generation)) {
                releaseSegmentTokenIfUnused(info.segment_token);
                removeMaterializedFile(info.local_path);
                break;
            }
            urls.push_back(info.stream_url);
            out_item_ids.push_back(t.queue_item_id);
            out_sample_rates.push_back(info.sampling_rate);
            out_local_paths.push_back(info.local_path);
            out_segment_tokens.push_back(info.segment_token);
            // Segmented responses include metadata; direct URLs may need the
            // separate metadata lookup below.
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

bool QcManager::queueLoadAborted(uint64_t generation) const {
    if (m_queue_load_stop.load(std::memory_order_relaxed))
        return true;
    return generation != m_queue_load_generation.load(std::memory_order_relaxed);
}

void QcManager::releaseSegmentTokenIfUnused(const std::string& token) {
    if (token.empty()) return;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (std::find(m_track_segment_tokens.begin(),
                      m_track_segment_tokens.end(), token) !=
            m_track_segment_tokens.end())
            return;
    }
    m_seg_registry.erase(token);
}

void QcManager::enqueueTitleBackfill(const QueueTrack& track,
                                     uint64_t generation) {
    if (queueLoadAborted(generation)) return;
    QueueOp metadata;
    metadata.type = QueueOp::Type::TitleBackfill;
    metadata.generation = generation;
    metadata.tracks.push_back(track);
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        if (queueLoadAborted(generation)) return;
        m_async_tasks.push_back(std::move(metadata));
    }
    m_queue_load_cv.notify_one();
}

void QcManager::queueLoadLoop() {
    while (!m_queue_load_stop.load(std::memory_order_relaxed)) {
        QueueOp op;
        {
            std::unique_lock<std::mutex> lk(m_queue_load_mutex);
            m_queue_load_cv.wait(lk, [this] {
                return m_queue_load_stop.load(std::memory_order_relaxed) ||
                       !m_async_tasks.empty();
            });
            if (m_queue_load_stop.load(std::memory_order_relaxed))
                break;
            op = std::move(m_async_tasks.front());
            m_async_tasks.pop_front();
        }

        if (queueLoadAborted(op.generation)) continue;

        if (op.type == QueueOp::Type::TitleBackfill) {
            if (op.tracks.empty() || !m_api) continue;
            const QueueTrack& track = op.tracks.front();
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                auto item = std::find(m_queue_item_ids.begin(),
                                      m_queue_item_ids.end(),
                                      track.queue_item_id);
                if (item == m_queue_item_ids.end()) continue;
                size_t position = static_cast<size_t>(
                    item - m_queue_item_ids.begin());
                if (position >= m_track_titles.size() ||
                    !m_track_titles[position].empty())
                    continue;
            }
            TrackMeta metadata;
            if (!m_api->getTrackMeta(track.track_id, metadata) ||
                queueLoadAborted(op.generation))
                continue;

            std::string title;
            if (!metadata.artist.empty() || !metadata.title.empty()) {
                title = metadata.artist.empty()
                    ? metadata.title
                    : metadata.artist + " - " + metadata.title;
            }
            if (title.empty()) continue;

            bool current_track = false;
            {
                std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
                if (queueLoadAborted(op.generation)) continue;
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                auto item = std::find(m_queue_item_ids.begin(),
                                      m_queue_item_ids.end(),
                                      track.queue_item_id);
                if (item == m_queue_item_ids.end()) continue;
                size_t position = static_cast<size_t>(
                    item - m_queue_item_ids.begin());
                if (position >= m_track_titles.size() ||
                    !m_track_titles[position].empty())
                    continue;
                m_track_titles[position] = title;
                current_track = static_cast<int>(position) ==
                    m_last_mpd_queue_pos.load(std::memory_order_relaxed);
            }
            if (current_track) {
                {
                    std::lock_guard<std::mutex> lk(m_status_mutex);
                    m_status_title = title;
                }
                writeStatusFile();
            }
            continue;
        }

        if (op.type == QueueOp::Type::Remove) {
            std::vector<int> positions;
            std::vector<std::string> stale_paths;
            std::vector<std::string> stale_tokens;
            {
                std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
                if (queueLoadAborted(op.generation)) continue;
                {
                    std::lock_guard<std::mutex> lk(m_qmap_mutex);
                    for (uint64_t qid : op.item_ids) {
                        auto it = std::find(m_queue_item_ids.begin(),
                                            m_queue_item_ids.end(), qid);
                        if (it != m_queue_item_ids.end())
                            positions.push_back(static_cast<int>(
                                it - m_queue_item_ids.begin()));
                    }
                }
                std::sort(positions.begin(), positions.end(), std::greater<int>());
                positions.erase(std::unique(positions.begin(), positions.end()),
                                positions.end());
                if (!positions.empty() &&
                    (!m_mpd || !m_mpd->removeTracksByPos(positions))) {
                    LOGERR("QcManager: MusicPD rejected track removal\n");
                    continue;
                }
                {
                    std::lock_guard<std::mutex> lk(m_qmap_mutex);
                    for (int position : positions) {
                        size_t index = static_cast<size_t>(position);
                        if (!m_track_local_paths[index].empty())
                            stale_paths.push_back(m_track_local_paths[index]);
                        if (!m_track_segment_tokens[index].empty())
                            stale_tokens.push_back(m_track_segment_tokens[index]);
                        m_queue_item_ids.erase(m_queue_item_ids.begin() + index);
                        m_track_sample_rates.erase(
                            m_track_sample_rates.begin() + index);
                        m_track_local_paths.erase(
                            m_track_local_paths.begin() + index);
                        m_track_titles.erase(m_track_titles.begin() + index);
                        m_track_segment_tokens.erase(
                            m_track_segment_tokens.begin() + index);
                    }
                    for (uint64_t qid : op.item_ids) {
                        m_all_queue_item_ids.erase(
                            std::remove(m_all_queue_item_ids.begin(),
                                        m_all_queue_item_ids.end(), qid),
                            m_all_queue_item_ids.end());
                    }
                }
            }
            cleanupMaterializedFiles(stale_paths);
            for (const auto& token : stale_tokens)
                releaseSegmentTokenIfUnused(token);
            {
                std::lock_guard<std::mutex> lk(m_queue_load_mutex);
                for (auto& pending : m_async_tasks) {
                    if (pending.type != QueueOp::Type::Load) continue;
                    pending.remaining_indices.erase(
                        std::remove_if(
                            pending.remaining_indices.begin(),
                            pending.remaining_indices.end(),
                            [&](size_t index) {
                                uint64_t qid = pending.tracks[index].queue_item_id;
                                return std::find(op.item_ids.begin(), op.item_ids.end(),
                                                 qid) != op.item_ids.end();
                            }),
                        pending.remaining_indices.end());
                }
            }
            uint64_t abandoned_command = 0;
            {
                std::lock_guard<std::mutex> lk(m_pending_mutex);
                if (m_pending_playback.active &&
                    m_pending_playback.has_target &&
                    std::find(op.item_ids.begin(), op.item_ids.end(),
                              m_pending_playback.target_qid) != op.item_ids.end()) {
                    abandoned_command = m_pending_playback.command_id;
                    m_pending_playback = PendingPlayback{};
                }
            }
            completeSetState(abandoned_command);
            commitQueueVersion(op.queue_version);
            prioritizeCurrentDownloads();
            refreshMpdState();
            continue;
        }

        if (op.type == QueueOp::Type::Reorder) {
            std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
            if (queueLoadAborted(op.generation)) continue;
            std::vector<uint64_t> old_full;
            std::vector<uint64_t> loaded;
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                old_full = m_all_queue_item_ids;
                loaded = m_queue_item_ids;
            }
            std::unordered_set<uint64_t> selected(op.item_ids.begin(),
                                                  op.item_ids.end());
            std::vector<uint64_t> reordered;
            reordered.reserve(old_full.size());
            for (uint64_t qid : old_full) {
                if (!selected.count(qid)) reordered.push_back(qid);
            }
            size_t insert_at = 0;
            if (op.has_reorder_after) {
                auto anchor = std::find(reordered.begin(), reordered.end(),
                                        op.reorder_after_item_id);
                insert_at = anchor == reordered.end()
                    ? reordered.size()
                    : static_cast<size_t>(anchor - reordered.begin()) + 1;
            }
            std::vector<uint64_t> moved;
            for (uint64_t qid : op.item_ids) {
                if (std::find(old_full.begin(), old_full.end(), qid) != old_full.end())
                    moved.push_back(qid);
            }
            reordered.insert(reordered.begin() + insert_at,
                             moved.begin(), moved.end());

            std::unordered_map<uint64_t, size_t> loaded_position;
            for (size_t i = 0; i < loaded.size(); ++i)
                loaded_position.emplace(loaded[i], i);
            std::vector<size_t> old_positions;
            old_positions.reserve(loaded.size());
            for (uint64_t qid : reordered) {
                auto it = loaded_position.find(qid);
                if (it != loaded_position.end()) old_positions.push_back(it->second);
            }
            for (size_t i = 0; i < loaded.size(); ++i) {
                if (std::find(old_positions.begin(), old_positions.end(), i) ==
                    old_positions.end())
                    old_positions.push_back(i);
            }
            if (!old_positions.empty() &&
                (!m_mpd || !m_mpd->reorderTracks(old_positions))) {
                LOGERR("QcManager: MusicPD rejected queue reorder\n");
                continue;
            }
            {
                std::lock_guard<std::mutex> lk(m_qmap_mutex);
                auto reorder_parallel = [&](auto& values) {
                    auto old = values;
                    values.clear();
                    values.reserve(old.size());
                    for (size_t position : old_positions)
                        values.push_back(std::move(old[position]));
                };
                reorder_parallel(m_queue_item_ids);
                reorder_parallel(m_track_sample_rates);
                reorder_parallel(m_track_local_paths);
                reorder_parallel(m_track_titles);
                reorder_parallel(m_track_segment_tokens);
                m_all_queue_item_ids = std::move(reordered);
            }
            commitQueueVersion(op.queue_version);
            prioritizeCurrentDownloads();
            refreshMpdState();
            continue;
        }

        if (op.type == QueueOp::Type::Insert || op.type == QueueOp::Type::Add) {
            std::vector<uint64_t> ids;
            std::vector<int> rates;
            std::vector<std::string> paths, titles, tokens;
            auto urls = resolveStreamUrls(op.tracks, ids, rates, paths, titles,
                                          tokens, op.generation);
            if (queueLoadAborted(op.generation) ||
                urls.size() != op.tracks.size() || !m_mpd) {
                cleanupMaterializedFiles(paths);
                for (const auto& token : tokens)
                    releaseSegmentTokenIfUnused(token);
                if (!queueLoadAborted(op.generation))
                    LOGERR("QcManager: incomplete queue insertion was not applied\n");
                continue;
            }

            bool inserted = false;
            {
                std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
                if (queueLoadAborted(op.generation)) {
                    cleanupMaterializedFiles(paths);
                } else {
                    size_t full_position;
                    size_t mpd_position = 0;
                    {
                        std::lock_guard<std::mutex> lk(m_qmap_mutex);
                        full_position = m_all_queue_item_ids.size();
                        if (op.type == QueueOp::Type::Insert) {
                            if (op.has_insert_after &&
                                op.insert_after_item_id == -1) {
                                full_position = 0;
                            } else if (op.has_insert_after) {
                                auto anchor = std::find(
                                    m_all_queue_item_ids.begin(),
                                    m_all_queue_item_ids.end(),
                                    static_cast<uint64_t>(
                                        op.insert_after_item_id));
                                if (anchor != m_all_queue_item_ids.end())
                                    full_position = static_cast<size_t>(
                                        anchor - m_all_queue_item_ids.begin()) + 1;
                            }
                        }
                        for (uint64_t loaded_qid : m_queue_item_ids) {
                            auto loaded = std::find(m_all_queue_item_ids.begin(),
                                                    m_all_queue_item_ids.end(),
                                                    loaded_qid);
                            if (loaded != m_all_queue_item_ids.end() &&
                                static_cast<size_t>(
                                    loaded - m_all_queue_item_ids.begin()) <
                                    full_position)
                                ++mpd_position;
                        }
                    }

                    if (!m_mpd->insertTracksAt(
                            urls, static_cast<int>(mpd_position))) {
                        LOGERR("QcManager: MusicPD rejected queue insertion\n");
                    } else {
                        std::lock_guard<std::mutex> lk(m_qmap_mutex);
                        m_all_queue_item_ids.insert(
                            m_all_queue_item_ids.begin() + full_position,
                            ids.begin(), ids.end());
                        m_queue_item_ids.insert(
                            m_queue_item_ids.begin() + mpd_position,
                            ids.begin(), ids.end());
                        m_track_sample_rates.insert(
                            m_track_sample_rates.begin() + mpd_position,
                            rates.begin(), rates.end());
                        m_track_local_paths.insert(
                            m_track_local_paths.begin() + mpd_position,
                            paths.begin(), paths.end());
                        m_track_titles.insert(
                            m_track_titles.begin() + mpd_position,
                            titles.begin(), titles.end());
                        m_track_segment_tokens.insert(
                            m_track_segment_tokens.begin() + mpd_position,
                            tokens.begin(), tokens.end());
                        inserted = true;
                    }
                }
            }
            if (!inserted) {
                cleanupMaterializedFiles(paths);
                for (const auto& token : tokens)
                    releaseSegmentTokenIfUnused(token);
                continue;
            }

            commitQueueVersion(op.queue_version);
            prioritizeCurrentDownloads();
            applyPendingPlayback();
            refreshMpdState();
            for (size_t i = 0; i < op.tracks.size(); ++i) {
                if (titles[i].empty())
                    enqueueTitleBackfill(op.tracks[i], op.generation);
            }
            continue;
        }

        // Load continuations resolve one item per worker turn. This gets the
        // current and next URL into MusicPD promptly and lets later queue
        // mutations run between slow network requests.
        if (op.remaining_indices.empty()) {
            if (!op.load_started)
                m_queue_loading.store(false, std::memory_order_relaxed);
            uint64_t abandoned_command = 0;
            {
                std::lock_guard<std::mutex> lk(m_pending_mutex);
                if (m_pending_playback.active) {
                    abandoned_command = m_pending_playback.command_id;
                    m_pending_playback = PendingPlayback{};
                }
            }
            completeSetState(abandoned_command);
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(m_pending_mutex);
            if (m_pending_playback.active && m_pending_playback.has_target) {
                auto requested = std::find_if(
                    op.remaining_indices.begin(), op.remaining_indices.end(),
                    [&](size_t index) {
                        return op.tracks[index].queue_item_id ==
                               m_pending_playback.target_qid;
                    });
                if (requested != op.remaining_indices.end())
                    std::iter_swap(op.remaining_indices.begin(), requested);
            }
        }
        size_t track_index = op.remaining_indices.front();
        op.remaining_indices.pop_front();
        const QueueTrack track = op.tracks[track_index];
        std::vector<uint64_t> ids;
        std::vector<int> rates;
        std::vector<std::string> paths, titles, tokens;
        auto urls = resolveStreamUrls({track}, ids, rates, paths, titles,
                                      tokens, op.generation);
        if (queueLoadAborted(op.generation)) {
            cleanupMaterializedFiles(paths);
            for (const auto& token : tokens)
                releaseSegmentTokenIfUnused(token);
            continue;
        }

        bool keep_loading = true;
        bool queue_changed = false;
        bool first_loaded = false;
        std::vector<std::string> stale_paths;
        std::unordered_set<std::string> retained_tokens;
        if (!urls.empty() && m_mpd) {
            std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
            if (queueLoadAborted(op.generation)) {
                keep_loading = false;
            } else if (!op.load_started) {
                LoopMode loop = static_cast<LoopMode>(
                    m_loop_mode.load(std::memory_order_relaxed));
                bool repeat = loop == LoopMode::REPEAT_ONE ||
                              loop == LoopMode::REPEAT_ALL;
                bool single = loop == LoopMode::REPEAT_ONE;
                // Qobuz supplies the authoritative shuffled order in its queue
                // snapshots. MusicPD random would create a different next item.
                if (!m_mpd->loadQueue(urls, 0, repeat, false, single)) {
                    LOGERR("QcManager: MusicPD rejected queue replacement\n");
                    m_queue_loading.store(false, std::memory_order_relaxed);
                    keep_loading = false;
                } else {
                    {
                        std::lock_guard<std::mutex> lk(m_qmap_mutex);
                        stale_paths.swap(m_track_local_paths);
                        m_queue_item_ids = ids;
                        m_track_sample_rates = rates;
                        m_track_local_paths = paths;
                        m_track_titles = titles;
                        m_track_segment_tokens = tokens;
                        for (const auto& token : m_track_segment_tokens) {
                            if (!token.empty()) retained_tokens.insert(token);
                        }
                    }
                    op.load_started = true;
                    first_loaded = true;
                    queue_changed = true;
                    m_queue_loading.store(false, std::memory_order_relaxed);
                    m_last_mpd_queue_pos.store(0, std::memory_order_relaxed);
                }
            } else {
                size_t insert_position = 0;
                bool still_planned = true;
                {
                    std::lock_guard<std::mutex> lk(m_qmap_mutex);
                    auto full_it = std::find(m_all_queue_item_ids.begin(),
                                             m_all_queue_item_ids.end(),
                                             track.queue_item_id);
                    if (full_it == m_all_queue_item_ids.end()) {
                        still_planned = false;
                    } else {
                        size_t full_position = static_cast<size_t>(
                            full_it - m_all_queue_item_ids.begin());
                        for (uint64_t loaded_qid : m_queue_item_ids) {
                            auto it = std::find(m_all_queue_item_ids.begin(),
                                                m_all_queue_item_ids.end(), loaded_qid);
                            if (it != m_all_queue_item_ids.end() &&
                                static_cast<size_t>(
                                    it - m_all_queue_item_ids.begin()) < full_position)
                                ++insert_position;
                        }
                    }
                }
                if (!still_planned) {
                    keep_loading = true;
                } else if (!m_mpd->insertTrackAt(
                               urls.front(), static_cast<int>(insert_position))) {
                    LOGERR("QcManager: MusicPD rejected deferred track\n");
                } else {
                    {
                        std::lock_guard<std::mutex> lk(m_qmap_mutex);
                        m_queue_item_ids.insert(
                            m_queue_item_ids.begin() + insert_position, ids.front());
                        m_track_sample_rates.insert(
                            m_track_sample_rates.begin() + insert_position,
                            rates.front());
                        m_track_local_paths.insert(
                            m_track_local_paths.begin() + insert_position,
                            paths.front());
                        m_track_titles.insert(
                            m_track_titles.begin() + insert_position,
                            titles.front());
                        m_track_segment_tokens.insert(
                            m_track_segment_tokens.begin() + insert_position,
                            tokens.front());
                        queue_changed = true;
                    }
                }
            }
        }

        cleanupMaterializedFiles(stale_paths);
        if (!queue_changed) {
            cleanupMaterializedFiles(paths);
            for (const auto& token : tokens)
                releaseSegmentTokenIfUnused(token);
        }
        if (first_loaded) {
            m_seg_registry.retainOnly(retained_tokens);
            commitQueueVersion(op.queue_version);
            if (auto ws = currentWSession())
                ws->reportFileQuality(rates.front());
        }
        if (queue_changed) {
            prioritizeCurrentDownloads();
            applyPendingPlayback();
            refreshMpdState();
        }

        const uint64_t load_generation = op.generation;
        bool requeued = false;
        if (keep_loading && !op.remaining_indices.empty() &&
            !queueLoadAborted(load_generation)) {
            std::lock_guard<std::mutex> lk(m_queue_load_mutex);
            m_async_tasks.push_back(std::move(op));
            m_queue_load_cv.notify_one();
            requeued = true;
        } else if (!op.load_started) {
            m_queue_loading.store(false, std::memory_order_relaxed);
        }
        // Queue the continuation first: the requested successor's stream URL
        // must be available before a separate metadata request for this item.
        if (queue_changed && !titles.empty() && titles.front().empty())
            enqueueTitleBackfill(track, load_generation);
        if (!requeued && !queueLoadAborted(load_generation)) {
            uint64_t abandoned_command = 0;
            {
                std::lock_guard<std::mutex> lk(m_pending_mutex);
                if (m_pending_playback.active) {
                    abandoned_command = m_pending_playback.command_id;
                    m_pending_playback = PendingPlayback{};
                }
            }
            completeSetState(abandoned_command);
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

bool QcManager::applyPlaybackCommand(PlayingState state, bool has_target,
                                     uint64_t target_qid, bool has_position,
                                     uint32_t position_ms,
                                     uint64_t command_id) {
    bool ok = false;
    if (m_mpd) {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        ok = applyPlaybackCommandLocked(state, has_target, target_qid,
                                        has_position, position_ms);
    }
    completeSetState(command_id);
    refreshMpdState();
    return ok;
}

bool QcManager::applyPlaybackCommandLocked(
    PlayingState state, bool has_target, uint64_t target_qid,
    bool has_position, uint32_t position_ms) {
    MpdState before = m_mpd->getState();
    int target_position = has_target ? mpdPosForQueueItem(target_qid)
                                     : before.queue_pos;
    if (has_target && target_position < 0) return false;

    // Selecting a different item at position zero already starts it at the
    // beginning. Do not wait for complete reconstruction just to seek to zero.
    const bool track_switch_at_start =
        has_position && position_ms == 0 && has_target &&
        target_position != before.queue_pos;

    // Qobuz encodes Previous as a zero-position seek without a queue target.
    // Near the start of a track, select the preceding item instead.
    const bool previous_track =
        has_position && position_ms == 0 && !has_target &&
        before.position_ms < 3000 && before.queue_pos > 0;
    if (previous_track) {
        target_position = before.queue_pos - 1;
        has_position = false;
    } else if (track_switch_at_start) {
        has_position = false;
    }

    PlayingState effective = state;
    if (effective == PlayingState::UNKNOWN) {
        if (before.status == MpdState::Status::PLAY)
            effective = PlayingState::PLAYING;
        else if (before.status == MpdState::Status::PAUSE)
            effective = PlayingState::PAUSED;
        else if (before.status == MpdState::Status::STOP)
            effective = PlayingState::STOPPED;
    }
    MpdState::Status final_state = MpdState::Status::UNKNOWN;
    if (effective == PlayingState::PLAYING)
        final_state = MpdState::Status::PLAY;
    else if (effective == PlayingState::PAUSED)
        final_state = MpdState::Status::PAUSE;
    else if (effective == PlayingState::STOPPED)
        final_state = MpdState::Status::STOP;

    if (has_position)
        m_force_buffering.store(true, std::memory_order_relaxed);
    bool restart_track = false;
    if (has_position && target_position >= 0 &&
        !prepareSegmentedSeek(target_position, restart_track)) {
        m_force_buffering.store(false, std::memory_order_relaxed);
        LOGERR("QcManager: segmented track was not ready for seeking\n");
        return false;
    }
    bool select_track =
        previous_track ||
        (has_target && target_position != before.queue_pos) ||
        (has_position && before.status == MpdState::Status::STOP &&
         target_position >= 0);
    bool ok = m_mpd->applyPlayback(target_position, select_track,
                                   has_position, position_ms, final_state,
                                   restart_track);
    if (!ok)
        m_force_buffering.store(false, std::memory_order_relaxed);
    if (!ok)
        LOGERR("QcManager: MusicPD could not fully apply playback command\n");
    return ok;
}

bool QcManager::prepareSegmentedSeek(int mpd_position,
                                     bool& restart_track) {
    restart_track = false;
    std::string token;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (mpd_position < 0 ||
            static_cast<size_t>(mpd_position) >= m_track_segment_tokens.size())
            return true;
        token = m_track_segment_tokens[mpd_position];
    }
    if (token.empty()) return true;

    auto plan = m_seg_registry.get(token);
    if (!plan) return false;
    auto download = acquireSegmentedTrackDownload(
        plan, SegmentedDownloadPriority::Playback);
    if (!download) return false;

    uint64_t exact_size = 0;
    std::string error;
    bool ready = false;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(120);
    while (std::chrono::steady_clock::now() < deadline) {
        auto ws = currentWSession();
        if (m_stopping.load(std::memory_order_acquire) ||
            !m_ws_active.load(std::memory_order_relaxed) ||
            !ws || !ws->isConnected()) {
            error = "renderer session ended";
            break;
        }
        if (waitForSegmentedTrack(download, exact_size, 250, &error)) {
            ready = true;
            break;
        }
        if (segmentedTrackFailed(download, &error)) break;
    }
    releaseSegmentedTrackDownload(download);
    if (!ready || exact_size == 0) {
        LOGERR("QcManager: segmented seek preparation failed: "
               << (error.empty() ? "empty reconstructed stream" : error)
               << "\n");
        return false;
    }

    restart_track = true;
    return true;
}

void QcManager::applyPendingPlayback() {
    PendingPlayback command;
    bool applied = false;
    {
        std::lock_guard<std::mutex> apply_lk(m_queue_apply_mutex);
        {
            std::lock_guard<std::mutex> lk(m_pending_mutex);
            if (!m_pending_playback.active) return;
            if (m_pending_playback.has_target &&
                mpdPosForQueueItem(m_pending_playback.target_qid) < 0)
                return;
            command = m_pending_playback;
            m_pending_playback = PendingPlayback{};
        }
        applied = applyPlaybackCommandLocked(
            command.state, command.has_target, command.target_qid,
            command.has_position, command.position_ms);
    }
    completeSetState(command.command_id);
    refreshMpdState();
    if (!applied)
        LOGERR("QcManager: deferred playback command was not applied\n");
}

std::shared_ptr<WSession> QcManager::currentWSession() const {
    std::shared_ptr<WSession> ws;
    {
        std::lock_guard<std::mutex> lk(m_session_mutex);
        ws = m_ws;
    }
    return ws;
}

void QcManager::completeSetState(uint64_t command_id) {
    if (command_id == 0) return;
    if (auto ws = currentWSession()) ws->completeSetState(command_id);
}

void QcManager::commitQueueVersion(const QueueVersion& version) {
    if (auto ws = currentWSession()) ws->commitQueueVersion(version);
}

void QcManager::refreshMpdState() {
    if (!m_mpd || !m_ws_active.load(std::memory_order_relaxed) ||
        m_queue_loading.load(std::memory_order_relaxed))
        return;
    onMpdState(m_mpd->getState());
}

void QcManager::prioritizeCurrentDownloads() {
    if (!m_mpd) return;
    prioritizeDownloads(m_mpd->getState());
}

void QcManager::prioritizeDownloads(const MpdState& state) {
    std::vector<std::string> tokens;
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        auto add = [&](int position) {
            if (position < 0 ||
                static_cast<size_t>(position) >= m_track_segment_tokens.size())
                return;
            const auto& token = m_track_segment_tokens[position];
            if (!token.empty() &&
                std::find(tokens.begin(), tokens.end(), token) == tokens.end())
                tokens.push_back(token);
        };
        add(state.queue_pos);
        add(state.next_queue_pos);
    }
    for (const auto& token : tokens) m_seg_registry.prioritize(token);
}

int QcManager::posInFullQueue(uint64_t queue_item_id) const {
    std::lock_guard<std::mutex> lk(m_qmap_mutex);
    for (size_t i = 0; i < m_all_queue_item_ids.size(); ++i) {
        if (m_all_queue_item_ids[i] == queue_item_id)
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
    if (m_ipc_thread.joinable()) m_ipc_thread.join();
    {
        std::lock_guard<std::mutex> lk(m_ipc_mutex);
        if (m_ipc_client >= 0) {
            close(m_ipc_client);
            m_ipc_client = -1;
        }
    }
    if (m_ipc_sock >= 0) {
        close(m_ipc_sock);
        m_ipc_sock = -1;
    }
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
        {
            std::lock_guard<std::mutex> lk(m_ipc_mutex);
            if (m_ipc_client >= 0) close(m_ipc_client);
            m_ipc_client = client;
        }

        // Read commands from upmpdcli
        char buf[64];
        while (!m_ipc_stop) {
            FD_ZERO(&rfds);
            FD_SET(client, &rfds);
            tv = {1, 0};
            int r = select(client + 1, &rfds, nullptr, nullptr, &tv);
            if (r <= 0) continue;
            ssize_t n = read(client, buf, sizeof(buf) - 1);
            if (n <= 0) break; // client disconnected
            buf[n] = '\0';
            std::string cmd(buf);
            if (cmd.find("STOP") != std::string::npos) {
                LOGINF("QcManager: upmpdcli requests stop\n");
                std::lock_guard<std::mutex> connect_lk(m_connect_mutex);
                std::shared_ptr<WSession> ws;
                {
                    std::lock_guard<std::mutex> lk(m_session_mutex);
                    ws = std::move(m_ws);
                }
                if (ws) ws->disconnect();
                deactivateRenderer();
            }
        }
        {
            std::lock_guard<std::mutex> lk(m_ipc_mutex);
            if (m_ipc_client == client) {
                close(m_ipc_client);
                m_ipc_client = -1;
            }
        }
    }
}

void QcManager::notifyUpmpdcli(const std::string& msg) {
    std::lock_guard<std::mutex> lk(m_ipc_mutex);
    if (m_ipc_client < 0) return;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
#ifdef MSG_DONTWAIT
    flags |= MSG_DONTWAIT;
#endif
    (void)send(m_ipc_client, msg.data(), msg.size(), flags);
}

} // namespace QConnect
