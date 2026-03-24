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
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>

#include "proto.hxx"
#include "httphandler.hxx"

// Forward declaration
typedef void CURL;

namespace QConnect {

// Callbacks fired from the WSession event loop (called from the ws thread).
struct WSessionCallbacks {
    // Play/pause/seek: playing_state is PLAYING/PAUSED/STOPPED,
    // position_ms is the target seek position (0 if no seek).
    // current_item identifies which track the app wants us to play.
    std::function<void(PlayingState, uint32_t /*position_ms*/,
                        const QueueTrackRef& /*current_item*/)> on_set_state;

    // Volume change: absolute volume (0-100), or delta if delta != 0.
    std::function<void(uint32_t /*volume*/, int32_t /*delta*/)> on_set_volume;

    // Qobuz app connected/disconnected
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;

    // Full queue received (e.g. user pressed Play Album).
    // tracks carry both queue_item_id and track_id for each entry.
    // start_index is the position within the queue to start playing.
    std::function<void(const std::vector<QueueTrack>& /*tracks*/,
                        uint32_t                       /*start_index*/)>
        on_queue_load;

    // Incremental queue updates (carry full QueueTrack for mapping)
    std::function<void(const std::vector<QueueTrack>& /*tracks*/,
                        uint32_t /*insert_after_item_id*/)>
        on_tracks_inserted;

    std::function<void(const std::vector<QueueTrack>& /*tracks*/)>
        on_tracks_added;

    std::function<void(const std::vector<uint32_t>& /*queue_item_ids*/)>
        on_tracks_removed;
};

// Manages one Qobuz Connect session.
//
// Lifecycle:
//   1. connect(credentials) — open WebSocket, authenticate, subscribe
//   2. Event loop runs in background thread, fires WSessionCallbacks
//   3. reportState() / reportVolume() — push state back to Qobuz server
//   4. disconnect() — close WebSocket (called when UPnP takes over or on stop)
//
// A new WSession must be created for each connect() call; instances are
// not reusable.

class WSession {
public:
    WSession(const DeviceInfo& devinfo, const WSessionCallbacks& cbs);
    ~WSession();

    // Open WebSocket and start event loop.
    // Returns false if the connection could not be established.
    bool connect(const ConnectCredentials& creds);

    // Close WebSocket and stop event loop.
    void disconnect();

    bool isConnected() const { return m_connected.load(); }

    // Report current playback state to the server (called after every MPD
    // state change while this session is active).
    void reportState(const QueueRendererState& state);

    // Report volume change.
    void reportVolume(uint32_t volume);

    // Report max audio quality supported.
    void reportMaxQuality(int32_t quality_fmt_id);

    // Declare renderer_id as the active renderer (sent after AddRenderer).
    void setActiveRenderer(uint64_t renderer_id);

private:
    void eventLoop();
    bool sendRaw(const Bytes& data);
    bool sendHeartbeat();
    void dispatchMessage(const Message& msg);

    DeviceInfo        m_devinfo;
    WSessionCallbacks m_cbs;

    std::string m_ws_jwt;
    std::string m_ws_endpoint;

    CURL*       m_curl{nullptr};
    std::thread m_thread;

    std::atomic<bool>  m_connected{false};
    std::atomic<bool>  m_stop{false};
    std::mutex         m_send_mutex;

    // Session context received from server
    Bytes    m_session_uuid;
    uint64_t m_session_id{0};
    uint64_t m_renderer_id{0};
    bool     m_is_active{false};

    // Rolling counters for message IDs
    std::atomic<int32_t> m_batch_id{0};
    uint64_t             m_msg_id{1};

    static constexpr int HEARTBEAT_INTERVAL_S = 10;
    static constexpr int RECV_TIMEOUT_MS      = 500;
};

} // namespace QConnect
