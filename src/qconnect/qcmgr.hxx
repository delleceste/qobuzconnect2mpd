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

#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>

#include "proto.hxx"
#include "mpdctl.hxx"

namespace QConnect {

class HttpHandler;
class MdnsAnnouncer;
class WSession;
class MpdCtl;
class QobuzApi;
struct ConnectCredentials;

// Configuration for qconnect2mpd.
struct QcConfig {
    // Device identity
    std::string uuid;           // generated at first run, persisted in state file
    std::string friendly_name;  // shown in Qobuz app
    int         device_type{1}; // 1=SPEAKER
    int         format_id{27};  // audio quality: 5/6/7/27

    // HTTP endpoint server
    int         http_port{9093};
    std::string iface;          // network interface (empty=auto)

    // MPD
    std::string mpd_host{"localhost"};
    int         mpd_port{6600};
    std::string mpd_password;

    // Qobuz API credentials
    std::string api_base_url{"https://www.qobuz.com/api.json/0.2"};
    std::string app_id;
    std::string app_secret;     // XOR-decoded secret
    std::string qobuz_user;
    std::string qobuz_pass;

    // IPC with upmpdcli (Unix socket path, empty = disable)
    std::string upmpdcli_sock;
};

// Top-level manager: wires together mDNS, HTTP, WebSocket, Qobuz API, and MPD.
//
// Lifecycle:
//   1. QcManager mgr(config);
//   2. mgr.start() — brings up mDNS + HTTP, waits for Qobuz app to connect
//   3. When app connects, mgr auto-starts WebSocket session + MPD control
//   4. mgr.stop() — shuts everything down
//
// IPC with upmpdcli (optional):
//   The manager listens on a Unix socket.  upmpdcli sends "STOP\n" when
//   another source starts playing; the manager sends "PLAYING\n" /
//   "STOPPED\n" to let upmpdcli switch the OHProduct source.

class QcManager {
public:
    explicit QcManager(const QcConfig& cfg);
    ~QcManager();

    // Start all subsystems.  Returns false on fatal error (e.g. port conflict).
    bool start();

    // Stop all subsystems gracefully.
    void stop();

    // Blocking wait until stop() is called or a fatal error occurs.
    void run();

    bool isRunning() const { return m_running.load(); }

    // Retrieve the UUID (may differ from config if it was generated at construction)
    const std::string& uuid() const { return m_cfg.uuid; }

private:
    // Called by HttpHandler when the Qobuz app sends credentials
    void onConnect(ConnectCredentials creds);

    // Called by WSession callbacks
    void onSetState(PlayingState ps, uint32_t position_ms,
                    bool has_position,
                    const QueueTrackRef& current_item);
    void onSetVolume(uint32_t volume, int32_t delta);
    void onQueueLoad(const std::vector<QueueTrack>& tracks, uint32_t start_idx);
    void onTracksInserted(const std::vector<QueueTrack>& tracks,
                           uint32_t insert_after_item_id);
    void onTracksAdded(const std::vector<QueueTrack>& tracks);
    void onTracksRemoved(const std::vector<uint64_t>& queue_item_ids);
    void onWsConnected();
    void onWsDisconnected();

    // Called by MpdCtl's event thread
    void onMpdState(const MpdState& st);

    // Qobuz API: resolve stream URLs and build queue_item_id mapping.
    // Returns URLs for successfully resolved tracks.
    // out_item_ids is filled with the queue_item_id for each returned URL.
    std::vector<std::string> resolveStreamUrls(
        const std::vector<QueueTrack>& tracks,
        std::vector<uint64_t>& out_item_ids);

    // Look up Qobuz queue_item_id from MPD queue position.
    uint64_t queueItemIdAt(int mpd_pos) const;
    // Look up MPD queue position from Qobuz queue_item_id. Returns -1 if not found.
    int mpdPosForQueueItem(uint64_t queue_item_id) const;

    // IPC with upmpdcli
    bool startIpcServer();
    void stopIpcServer();
    void ipcLoop();
    void notifyUpmpdcli(const std::string& msg);

    QcConfig    m_cfg;
    DeviceInfo  m_devinfo;

    std::unique_ptr<MdnsAnnouncer> m_mdns;
    std::unique_ptr<HttpHandler>   m_http;
    std::unique_ptr<WSession>      m_ws;
    std::unique_ptr<MpdCtl>        m_mpd;
    std::unique_ptr<QobuzApi>      m_api;

    std::mutex       m_session_mutex;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_ws_active{false};

    // Maps MPD queue position -> Qobuz queue_item_id (parallel to MPD queue)
    mutable std::mutex        m_qmap_mutex;
    std::vector<uint64_t>     m_queue_item_ids;
    std::vector<int>          m_track_sample_rates; // Hz, parallel to m_queue_item_ids

    // IPC
    int          m_ipc_sock{-1};
    int          m_ipc_client{-1};
    std::thread  m_ipc_thread;
    std::atomic<bool> m_ipc_stop{false};
};

} // namespace QConnect
