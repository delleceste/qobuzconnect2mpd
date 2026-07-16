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
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <optional>

#include "proto.hxx"
#include "httphandler.hxx"

// Forward declaration
typedef void CURL;

namespace QConnect {

// Callbacks are serialized on a worker thread so renderer operations cannot
// block WebSocket receive, heartbeat, or ping/pong handling.
struct WSessionCallbacks {
    // Play/pause/seek: playing_state is PLAYING/PAUSED/STOPPED,
    // position_ms is the target seek position, has_position distinguishes
    // "seek to 0" from "no seek". current_item identifies the track.
    std::function<void(uint64_t /*command_id*/, PlayingState,
                        uint32_t /*position_ms*/,
                        bool /*has_position*/,
                        const QueueTrackRef& /*current_item*/)> on_set_state;

    // Volume change: absolute volume (0-100), or delta if delta != 0.
    std::function<void(uint32_t /*volume*/, int32_t /*delta*/)> on_set_volume;

    // Renderer activation/deactivation. Runs on the serialized callback worker.
    std::function<void(bool /*active*/)> on_set_active;

    // Qobuz app connected/disconnected
    // on_disconnected is emitted for network/server failure only. Deliberate
    // disconnect during session replacement must not clear the new queue.
    std::function<void()> on_connected;
    std::function<void(bool /*error*/)> on_disconnected;
    // Pass decoded messages intact so queue version and scalar presence are
    // retained (queue item id 0 and insert_after=-1 are valid values).
    std::function<void(const MsgSessionState&)>         on_session_state;
    std::function<void(const MsgQueueState&)>           on_queue_state;
    std::function<void(const MsgQueueLoadTracks&)>      on_queue_load;
    std::function<void(const MsgQueueTracksInserted&)>  on_tracks_inserted;
    std::function<void(const MsgQueueTracksAdded&)>     on_tracks_added;
    std::function<void(const MsgQueueTracksRemoved&)>   on_tracks_removed;
    std::function<void(const MsgQueueTracksReordered&)> on_tracks_reordered;
    std::function<void(const MsgQueueCleared&)>         on_queue_cleared;
    std::function<void(const MsgShuffleMode&)>          on_shuffle_mode;
    std::function<void(const MsgLoopMode&)>             on_loop_mode;
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

    // Report actual file audio quality (sample rate in Hz) for current track.
    void reportFileQuality(int32_t sample_rate_hz);

    // Declare renderer_id as the active renderer (sent after AddRenderer).
    void setActiveRenderer(uint64_t renderer_id);

    // Publish a queue version only after the corresponding MusicPD and local
    // queue mutation has committed successfully.
    void commitQueueVersion(const QueueVersion& version);

    // Release state reporting after the matching SetState command has either
    // been applied or definitively abandoned. Later command IDs supersede
    // earlier deferred commands.
    void completeSetState(uint64_t command_id);

private:
    uint64_t nowAlignedMs() const;
    uint64_t alignTimestampMs(uint64_t ts_ms) const;
    void eventLoop();
    bool sendRaw(const Bytes& data);
    bool sendDirectFrame(const Bytes& data, unsigned int flags);
    bool flushOutbound();
    bool hasOutbound();
    bool enqueueFrame(Bytes data, unsigned int flags);
    void wakeEventLoop();
    void drainWakePipe();
    void callbackLoop();
    void postCallback(std::function<void()> callback);
    void stopCallbackWorker();
    void maybeRestoreState();
    bool sendHeartbeat();
    void dispatchMessage(const Message& msg);

    DeviceInfo        m_devinfo;
    WSessionCallbacks m_cbs;

    std::string m_ws_jwt;
    std::string m_ws_endpoint;

    CURL*       m_curl{nullptr};
    std::thread m_thread;
    std::thread m_callback_thread;
    // connect() publishes this object before starting its threads so early
    // callbacks can find it.  A concurrent stop must wait until startup has
    // either completed or rolled back before touching CURL or thread handles.
    std::mutex  m_lifecycle_mutex;

    std::atomic<bool>  m_connected{false};
    std::atomic<bool>  m_stop{false};
    std::atomic<bool>  m_event_started{false};
    // Set true only when the event loop exits due to a network error or
    // server-initiated CLOSE (not when disconnect() is called externally).
    std::atomic<bool>  m_error_exit{false};

    struct OutboundFrame {
        Bytes        data;
        size_t       offset{0};
        unsigned int flags{0};
    };
    std::mutex                   m_outbound_mutex;
    std::deque<OutboundFrame>    m_outbound;
    std::optional<OutboundFrame> m_current_outbound;
    int                          m_wake_pipe[2]{-1, -1};
    std::mutex                   m_wake_mutex;

    std::mutex                        m_callback_mutex;
    std::condition_variable           m_callback_cv;
    std::deque<std::function<void()>> m_callback_queue;
    bool                              m_callback_stop{false};

    // Session context received from server
    Bytes    m_session_uuid;
    uint64_t m_session_id{0};
    uint64_t m_renderer_id{0};
    bool     m_is_active{false};
    std::optional<MsgQueueState> m_last_queue_snapshot;
    std::optional<RendererState> m_pending_restore_state;

    // Last reported renderer state (used for heartbeats and immediate responses)
    QueueRendererState   m_last_state{};
    std::mutex           m_state_mutex;
    uint64_t             m_set_state_serial{0};
    uint64_t             m_set_state_completed{0};
    // Estimated cloud-time offset (cloud_epoch_ms - local_epoch_ms).
    std::atomic<int64_t> m_cloud_time_offset_ms{0};

    // Rolling counters for message IDs
    std::atomic<int32_t> m_batch_id{0};
    uint64_t             m_msg_id{1};

    static constexpr int HEARTBEAT_INTERVAL_S = 10;
    static constexpr int RECV_TIMEOUT_MS      = 500;
};

} // namespace QConnect
