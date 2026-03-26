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

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <mutex>

static uint64_t nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

namespace QConnect {

static void removeMaterializedFile(const std::string& path) {
    if (path.empty()) return;
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::remove(path, ec);
    fs::remove(path + ".inprogress", ec);
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
    m_api->setLocalProxyBaseUrl("http://127.0.0.1:" +
                                std::to_string(m_cfg.http_port) +
                                "/qobuz-segmented");
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
    if (!m_cfg.qobuz_user.empty()) {
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
        LOGINF("QcManager: no Qobuz credentials configured — waiting for mDNS discovery\n");
    }

    m_running = true;
    LOGINF("QcManager: ready — device '" << m_cfg.friendly_name
           << "' advertised as " << m_cfg.uuid << "\n");
    return true;
}

void QcManager::stop() {
    if (!m_running) return;
    m_running = false;

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
    }

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
    // "seek to 0" from "no seek requested")
    if (has_position) {
        // "Previous track" logic: the Qobuz app sends seek-to-0 for the back
        // button and expects the renderer to skip to the previous track when
        // already near the start of the current one.
        if (position_ms == 0) {
            MpdState st = m_mpd->getState();
            if (st.position_ms < 3000 && st.queue_pos > 0) {
                m_mpd->previous();
                return;
            }
        }
        m_mpd->seek(position_ms);
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
        }
        if (m_mpd) m_mpd->stop();
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
    }
    uint64_t generation = m_queue_load_generation.fetch_add(1, std::memory_order_relaxed) + 1;
    {
        std::lock_guard<std::mutex> lk(m_queue_load_mutex);
        m_pending_queue_load.tracks = tracks;
        m_pending_queue_load.start_idx = start_idx;
        m_pending_queue_load.generation = generation;
        m_pending_queue_load.pending = true;
    }
    m_queue_load_cv.notify_one();
}

void QcManager::onTracksInserted(const std::vector<QueueTrack>& tracks,
                                   uint32_t insert_after_item_id) {
    std::vector<uint64_t> item_ids;
    std::vector<int> sample_rates;
    std::vector<std::string> local_paths;
    auto urls = resolveStreamUrls(tracks, item_ids, sample_rates, local_paths);
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
        // Insert new item_ids after insert_pos
        if (insert_pos >= 0 && insert_pos + 1 <= static_cast<int>(m_queue_item_ids.size()))
            m_queue_item_ids.insert(m_queue_item_ids.begin() + insert_pos + 1,
                                     item_ids.begin(), item_ids.end());
        else
            m_queue_item_ids.insert(m_queue_item_ids.end(),
                                     item_ids.begin(), item_ids.end());
        if (insert_pos >= 0 && insert_pos + 1 <= static_cast<int>(m_track_sample_rates.size()))
            m_track_sample_rates.insert(m_track_sample_rates.begin() + insert_pos + 1,
                                        sample_rates.begin(), sample_rates.end());
        else
            m_track_sample_rates.insert(m_track_sample_rates.end(),
                                        sample_rates.begin(), sample_rates.end());
        if (insert_pos >= 0 && insert_pos + 1 <= static_cast<int>(m_track_local_paths.size()))
            m_track_local_paths.insert(m_track_local_paths.begin() + insert_pos + 1,
                                       local_paths.begin(), local_paths.end());
        else
            m_track_local_paths.insert(m_track_local_paths.end(),
                                       local_paths.begin(), local_paths.end());
    }

    int mpd_id = m_mpd->queueItemToMpdId(insert_after_item_id);
    m_mpd->insertTracks(urls, mpd_id);
}

void QcManager::onTracksAdded(const std::vector<QueueTrack>& tracks) {
    std::vector<uint64_t> item_ids;
    std::vector<int> sample_rates;
    std::vector<std::string> local_paths;
    auto urls = resolveStreamUrls(tracks, item_ids, sample_rates, local_paths);
    if (urls.empty() || !m_mpd) return;

    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        m_queue_item_ids.insert(m_queue_item_ids.end(),
                                 item_ids.begin(), item_ids.end());
        m_track_sample_rates.insert(m_track_sample_rates.end(),
                                    sample_rates.begin(), sample_rates.end());
        m_track_local_paths.insert(m_track_local_paths.end(),
                                   local_paths.begin(), local_paths.end());
    }
    m_mpd->addTracks(urls);
}

void QcManager::onTracksRemoved(const std::vector<uint64_t>& queue_item_ids) {
    if (!m_mpd) return;
    std::vector<std::string> stale_paths;
    // Remove from our mapping
    {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        for (uint64_t qid : queue_item_ids) {
            auto it = std::find(m_queue_item_ids.begin(),
                                m_queue_item_ids.end(), qid);
            if (it != m_queue_item_ids.end()) {
                size_t idx = static_cast<size_t>(it - m_queue_item_ids.begin());
                if (idx < m_track_local_paths.size() && !m_track_local_paths[idx].empty())
                    stale_paths.push_back(m_track_local_paths[idx]);
                m_queue_item_ids.erase(it);
                if (idx < m_track_sample_rates.size())
                    m_track_sample_rates.erase(m_track_sample_rates.begin() + idx);
                if (idx < m_track_local_paths.size())
                    m_track_local_paths.erase(m_track_local_paths.begin() + idx);
            }
        }
    }
    cleanupMaterializedFiles(stale_paths);
    std::vector<int> mpd_ids;
    for (uint64_t qid : queue_item_ids) {
        int mid = m_mpd->queueItemToMpdId(qid);
        if (mid >= 0) mpd_ids.push_back(mid);
    }
    if (!mpd_ids.empty()) m_mpd->removeTracks(mpd_ids);
}

// ---- MPD state callback ----------------------------------------------------

void QcManager::onMpdState(const MpdState& st) {
    if (!m_ws || !m_ws_active) return;

    QueueRendererState qrs;
    qrs.state.current_position_ms  = st.position_ms;
    qrs.state.position_timestamp_ms = nowMs(); // record when we sampled this
    qrs.state.duration_ms          = st.duration_ms;

    // Map MPD queue position to Qobuz queue_item_id
    if (st.queue_pos >= 0) {
        std::lock_guard<std::mutex> lk(m_qmap_mutex);
        if (static_cast<size_t>(st.queue_pos) < m_queue_item_ids.size()) {
            qrs.state.current_queue_item_id = m_queue_item_ids[st.queue_pos];
            qrs.state.has_current_queue_item_id = true;
            LOGDEB("QcManager: mpdState queue_pos=" << st.queue_pos
                   << " -> qitem=" << qrs.state.current_queue_item_id
                   << " (map size=" << m_queue_item_ids.size() << ")\n");
        }
    }

    switch (st.status) {
    case MpdState::Status::PLAY:
        qrs.state.playing_state = PlayingState::PLAYING;
        // Keep BUFFERING until MPD reports sustained position progression on
        // this track. This is state-based (not fixed-delay) and avoids phone
        // timer lead during startup/network warmup.
        {
            bool new_play_context =
                (m_last_mpd_status != MpdState::Status::PLAY) ||
                (st.queue_pos != m_last_mpd_queue_pos);
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
    m_last_mpd_queue_pos = st.queue_pos;
    m_last_mpd_pos_ms = st.position_ms;
}

// ---- Stream URL resolution --------------------------------------------------

std::vector<std::string> QcManager::resolveStreamUrls(
    const std::vector<QueueTrack>& tracks,
    std::vector<uint64_t>& out_item_ids,
    std::vector<int>& out_sample_rates,
    std::vector<std::string>& out_local_paths) {
    std::vector<std::string> urls;
    urls.reserve(tracks.size());
    out_item_ids.clear();
    out_item_ids.reserve(tracks.size());
    out_sample_rates.clear();
    out_sample_rates.reserve(tracks.size());
    out_local_paths.clear();
    out_local_paths.reserve(tracks.size());
    for (const auto& t : tracks) {
        TrackStreamInfo info;
        if (m_api->getStreamUrl(t.track_id, m_cfg.format_id, info) &&
            !info.stream_url.empty()) {
            urls.push_back(info.stream_url);
            out_item_ids.push_back(t.queue_item_id);
            out_sample_rates.push_back(info.sampling_rate);
            out_local_paths.push_back(info.local_path);
            LOGDEB("QcManager:   resolved track " << t.track_id
                   << " " << info.sampling_rate << "Hz/"
                   << info.bit_depth << "bit\n");
        } else {
            LOGERR("QcManager: could not get stream URL for track "
                   << t.track_id << " (qitem=" << t.queue_item_id << ")\n");
        }
    }
    return urls;
}

void QcManager::queueLoadLoop() {
    while (!m_queue_load_stop.load(std::memory_order_relaxed)) {
        PendingQueueLoad req;
        {
            std::unique_lock<std::mutex> lk(m_queue_load_mutex);
            m_queue_load_cv.wait(lk, [this] {
                return m_queue_load_stop.load(std::memory_order_relaxed) ||
                       m_pending_queue_load.pending;
            });
            if (m_queue_load_stop.load(std::memory_order_relaxed))
                break;
            req = m_pending_queue_load;
            m_pending_queue_load.pending = false;
        }

        std::vector<uint64_t> item_ids;
        std::vector<int> sample_rates;
        std::vector<std::string> local_paths;
        auto urls = resolveStreamUrls(req.tracks, item_ids, sample_rates, local_paths);
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
            m_queue_item_ids = item_ids;
            m_track_sample_rates = sample_rates;
            m_track_local_paths = local_paths;
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
    }
}

void QcManager::stopQueueLoadWorker() {
    m_queue_load_stop = true;
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
