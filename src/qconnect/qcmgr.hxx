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

#include <deque>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>

#include "proto.hxx"
#include "mpdctl.hxx"
#include "segstream.hxx"

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
    std::string token_file;     // OAuth token cache (empty = XDG/HOME default)

    // IPC with upmpdcli (Unix socket path, empty = disable)
    std::string upmpdcli_sock;

    // Status file path (empty = disabled); updated once per second while playing
    std::string status_file;
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

    // True when the WebSocket connection was lost unexpectedly.
    // main() uses this to exit with code 1 so systemd can restart the service.
    bool hasFatalError() const { return m_fatal_error.load(); }

    // Retrieve the UUID (may differ from config if it was generated at construction)
    const std::string& uuid() const { return m_cfg.uuid; }

private:
    // Called by HttpHandler when the Qobuz app sends credentials
    void onConnect(ConnectCredentials creds);

    // Called by WSession callbacks
    void onSetState(uint64_t command_id, PlayingState ps, uint32_t position_ms,
                    bool has_position,
                    const QueueTrackRef& current_item);
    void onSetVolume(uint32_t volume, int32_t delta);
    void onSetActive(bool active);
    void onSessionState(const MsgSessionState& state);
    void onQueueState(const MsgQueueState& queue);
    void onQueueLoad(const MsgQueueLoadTracks& queue);
    void onQueueCleared(const MsgQueueCleared& queue);
    void onTracksInserted(const MsgQueueTracksInserted& update);
    void onTracksAdded(const MsgQueueTracksAdded& update);
    void onTracksRemoved(const MsgQueueTracksRemoved& update);
    void onTracksReordered(const MsgQueueTracksReordered& update);
    void onShuffleMode(const MsgShuffleMode& update);
    void onLoopMode(const MsgLoopMode& update);
    void onWsConnected();
    void onWsDisconnected(bool error);
    void deactivateRenderer();
    void cancelQueueOperations();
    void queueLoadLoop();
    void stopQueueLoadWorker();
    void cleanupMaterializedFiles(const std::vector<std::string>& paths);

    // Called by MpdCtl's event thread
    void onMpdState(const MpdState& st);

    // Qobuz API: resolve stream URLs and build queue_item_id mapping.
    // Returns URLs for successfully resolved tracks.
    // out_item_ids is filled with the queue_item_id for each returned URL.
    std::vector<std::string> resolveStreamUrls(
        const std::vector<QueueTrack>& tracks,
        std::vector<uint64_t>& out_item_ids,
        std::vector<int>& out_sample_rates,
        std::vector<std::string>& out_local_paths,
        std::vector<std::string>& out_titles,
        std::vector<std::string>& out_segment_tokens,
        uint64_t generation = 0);
    bool queueLoadAborted(uint64_t generation) const;
    void releaseSegmentTokenIfUnused(const std::string& token);

    // Look up Qobuz queue_item_id from MPD queue position.
    uint64_t queueItemIdAt(int mpd_pos) const;
    // Look up MPD queue position from Qobuz queue_item_id. Returns -1 if not found.
    int mpdPosForQueueItem(uint64_t queue_item_id) const;
    // Look up position in the full Qobuz queue (includes not-yet-loaded tracks).
    int posInFullQueue(uint64_t queue_item_id) const;

    // Console + status file
    void printNowPlaying(const std::string& title, const std::string& local_path);
    void writeStatusFile();
    void statusLoop();

    void enqueueQueueLoad(const std::vector<QueueTrack>& tracks,
                          uint32_t start_idx,
                          const QueueVersion& queue_version);
    void applyPendingPlayback();
    bool applyPlaybackCommand(PlayingState state, bool has_target,
                              uint64_t target_qid, bool has_position,
                              uint32_t position_ms, uint64_t command_id);
    bool applyPlaybackCommandLocked(PlayingState state, bool has_target,
                                    uint64_t target_qid, bool has_position,
                                    uint32_t position_ms);
    bool prepareSegmentedSeek(int mpd_position, bool& restart_track);
    std::shared_ptr<WSession> currentWSession() const;
    void completeSetState(uint64_t command_id);
    void commitQueueVersion(const QueueVersion& version);
    void refreshMpdState();
    void prioritizeCurrentDownloads();
    void prioritizeDownloads(const MpdState& state);

    // IPC with upmpdcli
    bool startIpcServer();
    void stopIpcServer();
    void ipcLoop();
    void notifyUpmpdcli(const std::string& msg);

    QcConfig    m_cfg;
    DeviceInfo  m_devinfo;

    std::unique_ptr<MdnsAnnouncer> m_mdns;
    std::unique_ptr<HttpHandler>   m_http;
    std::shared_ptr<WSession>      m_ws;
    std::unique_ptr<MpdCtl>        m_mpd;
    std::unique_ptr<QobuzApi>      m_api;
    SegmentedTrackRegistry         m_seg_registry;

    mutable std::mutex m_session_mutex;
    std::mutex         m_connect_mutex;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};
    std::atomic<bool> m_ws_active{false};
    std::atomic<bool> m_fatal_error{false};
    // Startup synchronization gate: only switch to buffer_state=OK once MPD
    // shows sustained position progression on the current track.
    MpdState::Status   m_last_mpd_status{MpdState::Status::UNKNOWN};
    std::atomic<int>   m_last_mpd_queue_pos{-1};
    uint32_t           m_last_mpd_pos_ms{0};
    int                m_play_progress_samples{0};
    bool               m_playback_ready{false};
    std::mutex         m_state_report_mutex;
    std::atomic<bool>  m_force_buffering{false};

    // Maps MPD queue position -> Qobuz queue_item_id (parallel to MPD queue)
    mutable std::mutex        m_qmap_mutex;
    std::vector<uint64_t>     m_queue_item_ids;
    std::vector<int>          m_track_sample_rates; // Hz, parallel to m_queue_item_ids
    std::vector<std::string>  m_track_local_paths;  // local materialized FLAC paths
    std::vector<std::string>  m_track_titles;        // "Artist - Title", parallel to m_queue_item_ids
    std::vector<std::string>  m_track_segment_tokens; // empty for direct URLs
    // Full ordered Qobuz queue (all items, including tracks not yet loaded into MPD).
    // Set immediately when onQueueLoad fires so skip can find direction even
    // before URL resolution completes.
    std::vector<uint64_t>     m_all_queue_item_ids;

    // Async work queue shared by the worker thread and the WS event thread.
    // A Load op clears the deque first (cancelling stale Insert/Add ops for the
    // old queue). Insert and Add ops carry the generation at dispatch time so
    // the worker can detect when a new Load has superseded them.
    struct QueueOp {
        enum class Type { Load, Insert, Add, Remove, Reorder };
        Type                    type{Type::Load};
        uint64_t                generation{0};
        QueueVersion            queue_version;
        std::vector<QueueTrack> tracks;
        uint32_t                start_idx{0};             // Load only
        int32_t                 insert_after_item_id{0};  // Insert only
        bool                    has_insert_after{false};
        std::vector<uint64_t>   item_ids;                 // Remove/Reorder
        uint64_t                reorder_after_item_id{0};
        bool                    has_reorder_after{false};
        std::deque<size_t>      remaining_indices;        // Load continuation
        bool                    load_started{false};
    };
    std::mutex                m_queue_load_mutex;
    std::condition_variable   m_queue_load_cv;
    std::thread               m_queue_load_thread;
    std::atomic<bool>         m_queue_load_stop{false};
    std::atomic<uint64_t>     m_queue_load_generation{0};
    std::deque<QueueOp>       m_async_tasks;
    // Closes the gap between a generation check and the corresponding MPD +
    // map commit. Clear/load/session teardown take the same mutex.
    std::mutex                m_queue_apply_mutex;

    // Status file
    std::string           m_status_title;
    std::string           m_status_format_info;
    std::atomic<uint32_t> m_status_pos_ms{0};
    std::atomic<uint32_t> m_status_dur_ms{0};
    std::atomic<int>      m_status_play_state{0}; // 0=unknown 1=stopped 2=playing 3=paused
    mutable std::mutex    m_status_mutex;
    std::thread           m_status_thread;
    std::atomic<bool>     m_status_stop{false};

    struct PendingPlayback {
        bool         active{false};
        uint64_t     command_id{0};
        PlayingState state{PlayingState::UNKNOWN};
        bool         has_target{false};
        uint64_t     target_qid{0};
        bool         has_position{false};
        uint32_t     position_ms{0};
    };
    std::mutex      m_pending_mutex;
    PendingPlayback m_pending_playback;
    std::atomic<bool> m_queue_loading{false};
    std::atomic<bool> m_shuffle_on{false};
    std::atomic<int>  m_loop_mode{static_cast<int>(LoopMode::OFF)};
    std::atomic<bool> m_session_has_track_index{false};
    std::atomic<uint32_t> m_session_track_index{0};

    // IPC
    int          m_ipc_sock{-1};
    int          m_ipc_client{-1};
    std::mutex   m_ipc_mutex;
    std::thread  m_ipc_thread;
    std::atomic<bool> m_ipc_stop{false};
};

} // namespace QConnect
