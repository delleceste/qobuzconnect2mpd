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
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>

// Forward declaration to avoid pulling in libmpdclient headers
struct mpd_connection;

namespace QConnect {

// Current MPD playback state, reported to WSession on every change.
struct MpdState {
    enum class Status { UNKNOWN, STOP, PLAY, PAUSE };
    Status   status{Status::UNKNOWN};
    uint32_t position_ms{0};
    uint32_t duration_ms{0};
    uint32_t volume{0};         // 0-100
    int      queue_pos{-1};     // current song position in queue
    int      queue_id{-1};      // current song MPD id
    int      queue_len{0};
};

// Called from MpdCtl's event thread on every MPD state change.
using MpdStateCallback = std::function<void(const MpdState&)>;

// Controls MPD on behalf of the Qobuz Connect session.
//
// Responsibilities:
//  - Build and maintain the MPD queue from Qobuz track stream URLs
//  - Translate Qobuz Connect play/pause/seek commands to MPD calls
//  - Watch MPD for state changes and report them back (for WSession heartbeat)
//  - Restore the previous MPD queue when Qobuz Connect becomes inactive
//
// One MpdCtl instance is created when a Qobuz Connect session starts and
// destroyed when the session ends.

class MpdCtl {
public:
    MpdCtl(const std::string& host, int port, const std::string& password = "");
    ~MpdCtl();

    // Connect to MPD.  Returns false on failure.
    bool connect();

    // Disconnect and stop the event thread.
    void disconnect();

    // ---- Queue management --------------------------------------------------

    // Replace the entire MPD queue with the given stream URLs (in order),
    // then start playing from start_pos.
    // On first call, saves the existing queue so it can be restored later.
    bool loadQueue(const std::vector<std::string>& stream_urls,
                    int start_pos = 0);

    // Insert stream_urls after queue entry with MPD id insert_after_id.
    bool insertTracks(const std::vector<std::string>& stream_urls,
                       int insert_after_id);

    // Append stream_urls to the end of the queue.
    bool addTracks(const std::vector<std::string>& stream_urls);

    // Remove queue entries by MPD song id.
    bool removeTracks(const std::vector<int>& mpd_song_ids);

    // ---- Playback ----------------------------------------------------------

    bool play(int queue_pos = -1);
    bool pause(bool on);
    bool stop();
    bool seek(uint32_t position_ms);
    bool next();
    bool previous();

    // Set MPD volume (0-100).
    bool setVolume(uint32_t vol);

    // ---- State -------------------------------------------------------------

    MpdState getState();

    // Register a callback that fires on every MPD event (player/queue/mixer).
    void setStateCallback(MpdStateCallback cb);

    // Map a Qobuz queue_item_id to an MPD song id (maintained internally).
    // Returns -1 if not found.
    int queueItemToMpdId(uint32_t queue_item_id) const;

    // Register a mapping from Qobuz queue_item_id to mpd song id.
    void registerQueueItem(uint32_t queue_item_id, int mpd_id);

private:
    bool openConnection();
    void closeConnection();
    bool ensureConnected();
    void eventLoop();
    MpdState fetchState();
    void clearQueueItemMap();

    std::string m_host;
    int         m_port;
    std::string m_password;

    struct mpd_connection* m_conn{nullptr};
    struct mpd_connection* m_idle_conn{nullptr};
    std::mutex             m_conn_mutex;

    std::thread            m_event_thread;
    std::atomic<bool>      m_stop{false};
    MpdStateCallback       m_state_cb;
    std::mutex             m_cb_mutex;

    // Map Qobuz queue_item_id -> MPD song id
    std::vector<std::pair<uint32_t, int>> m_item_map;
    mutable std::mutex                    m_map_mutex;

    // Saved queue for restoration on disconnect
    struct SavedQueue {
        std::vector<std::string> uris;
        int                      current_pos{-1};
        uint32_t                 current_elapsed_ms{0};
    };
    SavedQueue m_saved_queue;
    bool       m_queue_saved{false};
};

} // namespace QConnect
