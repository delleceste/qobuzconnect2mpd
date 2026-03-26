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

#include "mpdctl.hxx"
#include "qclog.hxx"

#include <mpd/client.h>

#include <chrono>
#include <cstring>

namespace QConnect {

MpdCtl::MpdCtl(const std::string& host, int port, const std::string& password)
    : m_host(host), m_port(port), m_password(password)
{}

MpdCtl::~MpdCtl() { disconnect(); }

bool MpdCtl::openConnection() {
    m_conn = mpd_connection_new(m_host.c_str(),
                                 static_cast<unsigned>(m_port), 0);
    if (!m_conn || mpd_connection_get_error(m_conn) != MPD_ERROR_SUCCESS) {
        LOGERR("MpdCtl: connect to " << m_host << ":" << m_port
               << " failed: "
               << (m_conn ? mpd_connection_get_error_message(m_conn)
                           : "alloc failed") << "\n");
        if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
        return false;
    }
    if (!m_password.empty()) {
        if (!mpd_run_password(m_conn, m_password.c_str())) {
            LOGERR("MpdCtl: password auth failed\n");
            mpd_connection_free(m_conn); m_conn = nullptr;
            return false;
        }
    }
    LOGDEB("MpdCtl: connected to " << m_host << ":" << m_port << "\n");
    return true;
}

void MpdCtl::closeConnection() {
    if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    if (m_idle_conn) { mpd_connection_free(m_idle_conn); m_idle_conn = nullptr; }
}

bool MpdCtl::connect() {
    if (!openConnection()) return false;

    // Separate idle connection for event watching
    m_idle_conn = mpd_connection_new(m_host.c_str(),
                                      static_cast<unsigned>(m_port), 0);
    if (!m_idle_conn ||
        mpd_connection_get_error(m_idle_conn) != MPD_ERROR_SUCCESS) {
        LOGERR("MpdCtl: idle connection failed\n");
        closeConnection();
        return false;
    }
    if (!m_password.empty())
        mpd_run_password(m_idle_conn, m_password.c_str());

    m_stop = false;
    m_event_thread = std::thread(&MpdCtl::eventLoop, this);
    return true;
}

void MpdCtl::disconnect() {
    m_stop = true;
    // Unblock the idle connection so the event thread exits
    if (m_idle_conn) mpd_send_noidle(m_idle_conn);
    if (m_event_thread.joinable()) m_event_thread.join();
    closeConnection();
    clearQueueItemMap();
}

bool MpdCtl::ensureConnected() {
    if (m_conn && mpd_connection_get_error(m_conn) == MPD_ERROR_SUCCESS)
        return true;
    if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    return openConnection();
}

// ---- Queue management -------------------------------------------------------

bool MpdCtl::loadQueue(const std::vector<std::string>& stream_urls,
                         int start_pos) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;

    // Save current queue if not already saved
    if (!m_queue_saved) {
        struct mpd_song* song;
        mpd_send_list_queue_meta(m_conn);
        while ((song = mpd_recv_song(m_conn))) {
            const char* uri = mpd_song_get_uri(song);
            if (uri) m_saved_queue.uris.push_back(uri);
            mpd_song_free(song);
        }
        mpd_response_finish(m_conn);

        // Save current position and elapsed
        struct mpd_status* st = mpd_run_status(m_conn);
        if (st) {
            m_saved_queue.current_pos        = mpd_status_get_song_pos(st);
            m_saved_queue.current_elapsed_ms =
                mpd_status_get_elapsed_ms(st);
            mpd_status_free(st);
        }
        m_queue_saved = true;
    }

    // Stop, clear, and reset playback modes that could cause skipping
    mpd_run_stop(m_conn);
    mpd_run_clear(m_conn);
    mpd_run_consume(m_conn, false);
    mpd_run_single(m_conn, false);
    mpd_run_random(m_conn, false);
    mpd_run_repeat(m_conn, true);
    mpd_run_clearerror(m_conn);
    clearQueueItemMap();

    // Add tracks
    for (const auto& uri : stream_urls) {
        mpd_run_add(m_conn, uri.c_str());
    }

    if (start_pos < 0) start_pos = 0;
    if (!stream_urls.empty()) {
        mpd_run_clearerror(m_conn);
        if (!mpd_run_play_pos(m_conn, static_cast<unsigned>(start_pos))) {
            const char* emsg = mpd_connection_get_error_message(m_conn);
            LOGERR("MpdCtl::loadQueue: play_pos failed: "
                   << (emsg ? emsg : "?") << "\n");
            return false;
        }
    }
    LOGDEB("MpdCtl::loadQueue: " << stream_urls.size()
           << " tracks, starting at " << start_pos << "\n");
    return true;
}

bool MpdCtl::insertTracks(const std::vector<std::string>& stream_urls,
                            int insert_after_id) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;

    // Find position of insert_after_id in the queue
    int insert_pos = -1;
    if (insert_after_id >= 0) {
        struct mpd_song* s = mpd_run_get_queue_song_id(
            m_conn, static_cast<unsigned>(insert_after_id));
        if (s) {
            insert_pos = static_cast<int>(mpd_song_get_pos(s));
            mpd_song_free(s);
        }
    }

    for (size_t i = 0; i < stream_urls.size(); ++i) {
        int pos = (insert_pos >= 0)
                  ? insert_pos + 1 + static_cast<int>(i)
                  : -1; // -1 = append
        if (pos >= 0)
            mpd_run_add_id_to(m_conn, stream_urls[i].c_str(),
                               static_cast<unsigned>(pos));
        else
            mpd_run_add(m_conn, stream_urls[i].c_str());
    }
    return true;
}

bool MpdCtl::addTracks(const std::vector<std::string>& stream_urls) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    for (const auto& uri : stream_urls)
        mpd_run_add(m_conn, uri.c_str());
    return true;
}

bool MpdCtl::removeTracks(const std::vector<int>& mpd_song_ids) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    for (int id : mpd_song_ids)
        mpd_run_delete_id(m_conn, static_cast<unsigned>(id));
    return true;
}

// ---- Playback ---------------------------------------------------------------

bool MpdCtl::play(int queue_pos) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ensureConnected()) return false;
        bool ok;
        if (queue_pos >= 0)
            ok = mpd_run_play_pos(m_conn, static_cast<unsigned>(queue_pos));
        else
            ok = mpd_run_play(m_conn);
        if (ok) return true;
        const char* emsg = mpd_connection_get_error_message(m_conn);
        LOGDEB("MpdCtl::play: failed (attempt " << attempt << "): "
               << (emsg ? emsg : "?") << ", reconnecting\n");
        if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    }
    return false;
}

bool MpdCtl::pause(bool on) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ensureConnected()) return false;
        if (mpd_run_pause(m_conn, on)) return true;
        LOGDEB("MpdCtl::pause: failed (attempt " << attempt << "), reconnecting\n");
        if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    }
    return false;
}

bool MpdCtl::stop() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    bool ok = mpd_run_stop(m_conn);
    if (ok && m_queue_saved) {
        // Restore saved queue
        mpd_run_clear(m_conn);
        for (const auto& uri : m_saved_queue.uris)
            mpd_run_add(m_conn, uri.c_str());
        if (m_saved_queue.current_pos >= 0) {
            mpd_run_play_pos(m_conn,
                              static_cast<unsigned>(m_saved_queue.current_pos));
            // Seek back to where we were
            if (m_saved_queue.current_elapsed_ms > 0)
                mpd_run_seek_pos(m_conn,
                                  static_cast<unsigned>(m_saved_queue.current_pos),
                                  m_saved_queue.current_elapsed_ms / 1000);
            mpd_run_pause(m_conn, true);
        }
        m_saved_queue = SavedQueue{};
        m_queue_saved = false;
        LOGDEB("MpdCtl: restored saved queue\n");
    }
    clearQueueItemMap();
    return ok;
}

bool MpdCtl::seek(uint32_t position_ms) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ensureConnected()) return false;
        struct mpd_status* st = mpd_run_status(m_conn);
        if (!st) {
            if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
            continue;
        }
        int pos = mpd_status_get_song_pos(st);
        mpd_status_free(st);
        if (pos < 0) return false;
        // Record seek time BEFORE calling MPD so that any event-thread tick
        // that fires while mpd_run_seek_pos blocks is inside the cooldown
        // window and won't broadcast a stale pre-seek position to the phone.
        uint64_t now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        m_last_seek_ms.store(now_ms, std::memory_order_relaxed);
        if (mpd_run_seek_pos(m_conn, static_cast<unsigned>(pos),
                              position_ms / 1000)) {
            return true;
        }
        // Seek failed — clear the cooldown so normal reporting resumes
        m_last_seek_ms.store(0, std::memory_order_relaxed);
        LOGDEB("MpdCtl::seek: failed (attempt " << attempt << "), reconnecting\n");
        if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    }
    return false;
}

bool MpdCtl::next() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    return mpd_run_next(m_conn);
}

bool MpdCtl::previous() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    return mpd_run_previous(m_conn);
}

bool MpdCtl::setVolume(uint32_t vol) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    return mpd_run_set_volume(m_conn, vol);
}

// ---- State ------------------------------------------------------------------

MpdState MpdCtl::fetchState() {
    MpdState out;
    if (!m_conn) return out;
    struct mpd_status* st = mpd_run_status(m_conn);
    if (!st) return out;

    switch (mpd_status_get_state(st)) {
    case MPD_STATE_PLAY:  out.status = MpdState::Status::PLAY;  break;
    case MPD_STATE_PAUSE: out.status = MpdState::Status::PAUSE; break;
    case MPD_STATE_STOP:  out.status = MpdState::Status::STOP;  break;
    default: break;
    }

    out.position_ms = mpd_status_get_elapsed_ms(st);
    out.duration_ms = mpd_status_get_total_time(st) * 1000;
    out.volume      = mpd_status_get_volume(st);
    out.queue_pos   = mpd_status_get_song_pos(st);
    out.queue_id    = mpd_status_get_song_id(st);
    out.queue_len   = mpd_status_get_queue_length(st);
    mpd_status_free(st);
    return out;
}

MpdState MpdCtl::getState() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return {};
    return fetchState();
}

void MpdCtl::setStateCallback(MpdStateCallback cb) {
    std::lock_guard<std::mutex> lk(m_cb_mutex);
    m_state_cb = std::move(cb);
}

// ---- Queue item mapping -----------------------------------------------------

int MpdCtl::queueItemToMpdId(uint64_t queue_item_id) const {
    std::lock_guard<std::mutex> lk(m_map_mutex);
    for (const auto& p : m_item_map)
        if (p.first == queue_item_id) return p.second;
    return -1;
}

void MpdCtl::registerQueueItem(uint64_t queue_item_id, int mpd_id) {
    std::lock_guard<std::mutex> lk(m_map_mutex);
    m_item_map.emplace_back(queue_item_id, mpd_id);
}

void MpdCtl::clearQueueItemMap() {
    std::lock_guard<std::mutex> lk(m_map_mutex);
    m_item_map.clear();
}

// ---- Event loop -------------------------------------------------------------

void MpdCtl::eventLoop() {
    // Position-report interval during playback (milliseconds).
    // The Qobuz phone app doesn't interpolate position client-side, so we
    // must send regular updates for the seek bar to advance in real time.
    constexpr int POSITION_REPORT_MS = 1000;

    // Rate-limiting state: fire callback at most once per POSITION_REPORT_MS
    // during playback, and immediately on real state changes.
    auto last_cb = std::chrono::steady_clock::now();
    MpdState::Status last_status  = MpdState::Status::UNKNOWN;
    int              last_queue_pos = -1;

    while (!m_stop) {
        // Enter MPD idle mode for player/queue/mixer events
        if (!mpd_send_idle_mask(m_idle_conn,
                                 static_cast<enum mpd_idle>(
                                     MPD_IDLE_PLAYER |
                                     MPD_IDLE_QUEUE  |
                                     MPD_IDLE_MIXER))) {
            LOGERR("MpdCtl: send_idle failed; reconnecting\n");
            std::this_thread::sleep_for(std::chrono::seconds(2));
            mpd_connection_free(m_idle_conn);
            m_idle_conn = mpd_connection_new(m_host.c_str(),
                                              static_cast<unsigned>(m_port), 0);
            if (!m_idle_conn) break;
            if (!m_password.empty())
                mpd_run_password(m_idle_conn, m_password.c_str());
            continue;
        }

        // Wait up to POSITION_REPORT_MS for an MPD event using select().
        // On timeout we cancel idle, check position, and re-enter idle.
        int fd = mpd_connection_get_fd(m_idle_conn);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv{POSITION_REPORT_MS / 1000,
                         (POSITION_REPORT_MS % 1000) * 1000};
        int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);

        if (r > 0) {
            // Data available — receive the idle event normally
            mpd_recv_idle(m_idle_conn, true);
        } else {
            // Timeout (or EINTR): cancel idle and treat as position-poll tick
            mpd_send_noidle(m_idle_conn);
            mpd_recv_idle(m_idle_conn, true); // consume the cancelled-idle response
        }

        if (m_stop) break;

        // Fetch current MPD state
        MpdState st;
        {
            std::lock_guard<std::mutex> lk(m_conn_mutex);
            if (ensureConnected()) st = fetchState();
        }

        auto now = std::chrono::steady_clock::now();

        // Seek cooldown: for 300 ms after seek() starts, suppress all
        // position-tick callbacks.  This prevents a pre-seek position sampled
        // by the event thread DURING mpd_run_seek_pos from reaching the phone
        // before the WSession seek-ack (which carries the correct position).
        // Real state changes (PLAY/PAUSE/track switch) are still forwarded so
        // the phone stays responsive to those events.
        bool state_changed = (st.status != last_status ||
                               st.queue_pos != last_queue_pos);
        {
            uint64_t now_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count());
            uint64_t seek_ms = m_last_seek_ms.load(std::memory_order_relaxed);
            if (seek_ms > 0 && now_ms - seek_ms < 300 && !state_changed) {
                continue; // still in seek cooldown — skip position tick
            }
        }
        bool interval_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_cb).count() >= POSITION_REPORT_MS;

        if (state_changed ||
            (st.status == MpdState::Status::PLAY && interval_elapsed)) {
            {
                std::lock_guard<std::mutex> lk(m_cb_mutex);
                if (m_state_cb) m_state_cb(st);
            }
            last_cb        = now;
            last_status    = st.status;
            last_queue_pos = st.queue_pos;
        } else if (!m_stop) {
            // MPD fires events continuously during HTTP streaming (buffer /
            // bitrate events).  If we have nothing to report yet, sleep up
            // to 100 ms so we don't busy-spin, while still responding to
            // real state changes (play/pause/stop) within ~100 ms.
            auto remaining_ms =
                POSITION_REPORT_MS -
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_cb).count();
            long long sleep_ms = std::min(100LL, (long long)remaining_ms);
            if (sleep_ms > 0)
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(sleep_ms));
        }
    }
}

} // namespace QConnect
