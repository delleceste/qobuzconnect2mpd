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

#include <algorithm>
#include <chrono>
#include <cerrno>
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
    if (!m_password.empty() &&
        !mpd_run_password(m_idle_conn, m_password.c_str())) {
        LOGERR("MpdCtl: idle connection password auth failed\n");
        closeConnection();
        return false;
    }

    m_stop = false;
    m_event_thread = std::thread(&MpdCtl::eventLoop, this);
    return true;
}

void MpdCtl::disconnect() {
    m_stop = true;
    // The idle connection belongs exclusively to eventLoop(). Its select()
    // timeout is one second, so let that thread wake naturally instead of
    // using one libmpdclient connection concurrently from two threads.
    if (m_event_thread.joinable()) m_event_thread.join();
    closeConnection();
}

bool MpdCtl::ensureConnected() {
    if (m_conn && mpd_connection_get_error(m_conn) == MPD_ERROR_SUCCESS)
        return true;
    if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    return openConnection();
}

bool MpdCtl::beginSession() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (m_queue_saved) return true;
    if (!captureSnapshotLocked(m_saved_queue)) return false;
    m_queue_saved = true;
    return true;
}

// ---- Queue management -------------------------------------------------------

bool MpdCtl::captureSnapshotLocked(QueueSnapshot& snapshot) {
    if (!ensureConnected()) return false;

    QueueSnapshot captured;
    struct mpd_status* st = mpd_run_status(m_conn);
    if (!st) return false;
    captured.current_pos = mpd_status_get_song_pos(st);
    captured.current_elapsed_ms = mpd_status_get_elapsed_ms(st);
    captured.playback_state = static_cast<int>(mpd_status_get_state(st));
    captured.repeat = mpd_status_get_repeat(st);
    captured.random = mpd_status_get_random(st);
    captured.single_state =
        static_cast<int>(mpd_status_get_single_state(st));
    captured.consume_state =
        static_cast<int>(mpd_status_get_consume_state(st));
    mpd_status_free(st);

    if (!mpd_send_list_queue_meta(m_conn)) return false;
    struct mpd_song* song;
    while ((song = mpd_recv_song(m_conn))) {
        const char* uri = mpd_song_get_uri(song);
        if (uri) {
            SongSnapshot saved;
            saved.uri = uri;
            saved.id = mpd_song_get_id(song);
            saved.priority = mpd_song_get_prio(song);
            for (int type = 0; type < MPD_TAG_COUNT; ++type) {
                for (unsigned index = 0;; ++index) {
                    const char* value = mpd_song_get_tag(
                        song, static_cast<enum mpd_tag_type>(type), index);
                    if (!value) break;
                    saved.tags.push_back({type, value});
                }
            }
            captured.songs.push_back(std::move(saved));
        }
        mpd_song_free(song);
    }
    if (!mpd_response_finish(m_conn)) return false;

    snapshot = std::move(captured);
    return true;
}

bool MpdCtl::restoreSnapshotLocked(const QueueSnapshot& snapshot) {
    if (!ensureConnected()) return false;

    auto failed = [this](const char* command) {
        const char* message = mpd_connection_get_error_message(m_conn);
        LOGERR("MpdCtl: " << command << " failed while restoring queue: "
               << (message ? message : "unknown error") << "\n");
        return false;
    };

    if (!mpd_run_stop(m_conn)) return failed("stop");
    if (!mpd_run_clear(m_conn)) return failed("clear");
    if (!mpd_run_consume_state(
            m_conn, static_cast<enum mpd_consume_state>(snapshot.consume_state)))
        return failed("consume");
    if (!mpd_run_single_state(
            m_conn, static_cast<enum mpd_single_state>(snapshot.single_state)))
        return failed("single");
    if (!mpd_run_random(m_conn, snapshot.random)) return failed("random");
    if (!mpd_run_repeat(m_conn, snapshot.repeat)) return failed("repeat");

    for (const auto& song : snapshot.songs) {
        int id = mpd_run_add_id(m_conn, song.uri.c_str());
        if (id < 0) return failed("add");

        // MusicPD queue clients such as upmpdcli attach display metadata with
        // addtagid. Re-adding only the URI silently strips that metadata.
        int previous_type = -1;
        for (const auto& tag : song.tags) {
            if (tag.type != previous_type) {
                if (!mpd_run_clear_tag_id(
                        m_conn, static_cast<unsigned>(id),
                        static_cast<enum mpd_tag_type>(tag.type)))
                    return failed("clear tag");
                previous_type = tag.type;
            }
            if (!mpd_run_add_tag_id(
                    m_conn, static_cast<unsigned>(id),
                    static_cast<enum mpd_tag_type>(tag.type), tag.value.c_str()))
                return failed("add tag");
        }
        if (song.priority > 0 &&
            !mpd_run_prio_id(m_conn, song.priority,
                             static_cast<unsigned>(id)))
            return failed("priority");
    }

    if (snapshot.current_pos >= 0 &&
        static_cast<size_t>(snapshot.current_pos) < snapshot.songs.size()) {
        if (!mpd_run_play_pos(
                m_conn, static_cast<unsigned>(snapshot.current_pos)))
            return failed("play position");
        if (snapshot.current_elapsed_ms > 0 &&
            !mpd_run_seek_current(
                m_conn,
                static_cast<float>(snapshot.current_elapsed_ms) / 1000.0f,
                false))
            return failed("seek");

        switch (static_cast<enum mpd_state>(snapshot.playback_state)) {
        case MPD_STATE_PAUSE:
            if (!mpd_run_pause(m_conn, true)) return failed("pause");
            break;
        case MPD_STATE_STOP:
        case MPD_STATE_UNKNOWN:
            if (!mpd_run_stop(m_conn)) return failed("stop");
            break;
        case MPD_STATE_PLAY:
            break;
        }
    }
    return true;
}

bool MpdCtl::rollbackLocked(const char* operation,
                            const QueueSnapshot& snapshot) {
    LOGERR("MpdCtl: " << operation << " failed; restoring previous MPD state\n");
    if (m_conn && mpd_connection_get_error(m_conn) != MPD_ERROR_SUCCESS) {
        mpd_connection_free(m_conn);
        m_conn = nullptr;
    }
    if (restoreSnapshotLocked(snapshot)) return false;
    LOGERR("MpdCtl: rollback after " << operation << " also failed\n");
    return false;
}

bool MpdCtl::capturePlaybackLocked(PlaybackSnapshot& snapshot) {
    if (!ensureConnected()) return false;
    struct mpd_status* status = mpd_run_status(m_conn);
    if (!status) return false;
    snapshot.current_pos = mpd_status_get_song_pos(status);
    snapshot.elapsed_ms = mpd_status_get_elapsed_ms(status);
    snapshot.state = static_cast<int>(mpd_status_get_state(status));
    mpd_status_free(status);
    return true;
}

bool MpdCtl::restorePlaybackLocked(const PlaybackSnapshot& snapshot) {
    if (!ensureConnected()) return false;
    if (snapshot.current_pos < 0)
        return snapshot.state == static_cast<int>(MPD_STATE_STOP)
            ? mpd_run_stop(m_conn) : false;

    if (!mpd_run_play_pos(m_conn,
                          static_cast<unsigned>(snapshot.current_pos)))
        return false;
    if (snapshot.elapsed_ms > 0 &&
        !mpd_run_seek_current(m_conn,
                              static_cast<float>(snapshot.elapsed_ms) / 1000.0f,
                              false))
        return false;

    switch (static_cast<enum mpd_state>(snapshot.state)) {
    case MPD_STATE_PLAY:
        return true;
    case MPD_STATE_PAUSE:
        return mpd_run_pause(m_conn, true);
    case MPD_STATE_STOP:
    case MPD_STATE_UNKNOWN:
        return mpd_run_stop(m_conn);
    }
    return false;
}

bool MpdCtl::rollbackPlaybackLocked(const char* operation,
                                    const PlaybackSnapshot& snapshot) {
    LOGERR("MpdCtl: " << operation
           << " failed; restoring previous playback state\n");
    if (m_conn && mpd_connection_get_error(m_conn) != MPD_ERROR_SUCCESS) {
        mpd_connection_free(m_conn);
        m_conn = nullptr;
    }
    if (!restorePlaybackLocked(snapshot))
        LOGERR("MpdCtl: playback rollback after " << operation
               << " also failed\n");
    return false;
}

bool MpdCtl::loadQueue(const std::vector<std::string>& stream_urls,
                       int start_pos, bool repeat, bool random, bool single) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;

    // Save the pre-QConnect state once. Subsequent loads retain this snapshot.
    if (!m_queue_saved) {
        m_saved_queue = before;
        m_queue_saved = true;
    }

    auto require = [&](bool ok, const char* command) {
        if (ok) return true;
        const char* message = mpd_connection_get_error_message(m_conn);
        LOGERR("MpdCtl::loadQueue: " << command << " failed: "
               << (message ? message : "unknown error") << "\n");
        return false;
    };

    if (!require(mpd_run_stop(m_conn), "stop") ||
        !require(mpd_run_clear(m_conn), "clear") ||
        !require(mpd_run_consume(m_conn, false), "consume") ||
        !require(mpd_run_single(m_conn, single), "single") ||
        !require(mpd_run_random(m_conn, random), "random") ||
        !require(mpd_run_repeat(m_conn, repeat), "repeat"))
        return rollbackLocked("loadQueue", before);

    for (const auto& uri : stream_urls) {
        if (!require(mpd_run_add(m_conn, uri.c_str()), "add"))
            return rollbackLocked("loadQueue", before);
    }

    if (start_pos < 0) start_pos = 0;
    if (start_pos >= static_cast<int>(stream_urls.size())) start_pos = 0;
    if (!stream_urls.empty()) {
        if (!require(mpd_run_play_pos(m_conn, static_cast<unsigned>(start_pos)),
                     "play position") ||
            !require(mpd_run_pause(m_conn, true), "pause"))
            return rollbackLocked("loadQueue", before);
    }
    LOGDEB("MpdCtl::loadQueue: " << stream_urls.size()
           << " tracks, starting at " << start_pos << " (paused)\n");
    return true;
}

bool MpdCtl::insertTracks(const std::vector<std::string>& stream_urls,
                          int insert_after_pos) {
    return insertTracksAt(stream_urls,
                          insert_after_pos >= 0 ? insert_after_pos + 1 : -1);
}

bool MpdCtl::insertTracksAt(const std::vector<std::string>& stream_urls,
                            int position) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;

    for (size_t i = 0; i < stream_urls.size(); ++i) {
        int pos = position >= 0 ? position + static_cast<int>(i) : -1;
        bool ok = pos >= 0
            ? mpd_run_add_id_to(m_conn, stream_urls[i].c_str(),
                                static_cast<unsigned>(pos)) >= 0
            : mpd_run_add(m_conn, stream_urls[i].c_str());
        if (!ok) return rollbackLocked("insertTracksAt", before);
    }
    return true;
}

bool MpdCtl::insertTrackAt(const std::string& stream_url, int position) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;

    int id = position >= 0
        ? mpd_run_add_id_to(m_conn, stream_url.c_str(),
                            static_cast<unsigned>(position))
        : mpd_run_add_id(m_conn, stream_url.c_str());
    if (id >= 0) return true;

    const char* message = mpd_connection_get_error_message(m_conn);
    LOGERR("MpdCtl::insertTrackAt: add failed: "
           << (message ? message : "unknown error") << "\n");
    return false;
}

bool MpdCtl::addTracks(const std::vector<std::string>& stream_urls) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    for (const auto& uri : stream_urls) {
        if (!mpd_run_add(m_conn, uri.c_str()))
            return rollbackLocked("addTracks", before);
    }
    return true;
}

bool MpdCtl::removeTracks(const std::vector<int>& mpd_song_ids) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    for (int id : mpd_song_ids) {
        if (id >= 0 && !mpd_run_delete_id(m_conn, static_cast<unsigned>(id)))
            return rollbackLocked("removeTracks", before);
    }
    return true;
}

bool MpdCtl::removeTracksByPos(const std::vector<int>& mpd_positions) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    for (int pos : mpd_positions) {
        if (pos < 0) continue;
        if (!mpd_run_delete(m_conn, static_cast<unsigned>(pos)))
            return rollbackLocked("removeTracksByPos", before);
    }
    return true;
}

bool MpdCtl::reorderTracks(const std::vector<size_t>& old_positions) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    if (old_positions.size() != before.songs.size()) return false;

    std::vector<bool> seen(before.songs.size(), false);
    std::vector<unsigned> current_ids;
    std::vector<unsigned> desired_ids;
    current_ids.reserve(before.songs.size());
    desired_ids.reserve(before.songs.size());
    for (const auto& song : before.songs) current_ids.push_back(song.id);
    for (size_t old_pos : old_positions) {
        if (old_pos >= before.songs.size() || seen[old_pos]) return false;
        seen[old_pos] = true;
        desired_ids.push_back(before.songs[old_pos].id);
    }

    // Move existing queue entries by their stable MusicPD song IDs. This keeps
    // the active decoder, elapsed position, tags and priority intact.
    for (size_t new_pos = 0; new_pos < desired_ids.size(); ++new_pos) {
        if (current_ids[new_pos] == desired_ids[new_pos]) continue;
        auto from = std::find(current_ids.begin() + new_pos + 1,
                              current_ids.end(), desired_ids[new_pos]);
        if (from == current_ids.end() ||
            !mpd_run_move_id(m_conn, desired_ids[new_pos],
                             static_cast<unsigned>(new_pos)))
            return rollbackLocked("reorderTracks", before);
        unsigned moved = *from;
        current_ids.erase(from);
        current_ids.insert(current_ids.begin() + new_pos, moved);
    }
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
        LOGDEB("MpdCtl::play: failed (attempt " << attempt << "): "
               << (mpd_connection_get_error_message(m_conn)
                       ? mpd_connection_get_error_message(m_conn) : "?")
               << ", reconnecting\n");
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
    return mpd_run_stop(m_conn);
}

bool MpdCtl::stopAndClear() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    if (!mpd_run_stop(m_conn) || !mpd_run_clear(m_conn))
        return rollbackLocked("stopAndClear", before);
    return true;
}

bool MpdCtl::restoreSavedQueue() {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!m_queue_saved) return true;
    QueueSnapshot qconnect_state;
    if (!captureSnapshotLocked(qconnect_state)) return false;
    if (!restoreSnapshotLocked(m_saved_queue)) {
        rollbackLocked("restoreSavedQueue", qconnect_state);
        return false;
    }
    m_saved_queue = QueueSnapshot{};
    m_queue_saved = false;
    LOGDEB("MpdCtl: restored pre-QConnect queue and playback state\n");
    return true;
}

bool MpdCtl::seek(uint32_t position_ms) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ensureConnected()) return false;
        // Record seek time BEFORE calling MPD so that any event-thread tick
        // that fires while mpd_run_seek_current blocks is inside the
        // cooldown window and won't broadcast a stale pre-seek position.
        uint64_t now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        m_last_seek_ms.store(now_ms, std::memory_order_relaxed);
        // Use mpd_run_seek_current (the only seek variant that accepts a
        // float).  mpd_run_seek_pos takes `unsigned` seconds, so any sub-
        // second precision sent by the Qobuz app would silently round down.
        if (mpd_run_seek_current(m_conn,
                                  static_cast<float>(position_ms) / 1000.0f,
                                  false /*absolute*/)) {
            return true;
        }
        // Seek failed — clear the cooldown so normal reporting resumes
        m_last_seek_ms.store(0, std::memory_order_relaxed);
        LOGERR("MpdCtl::seek: failed (attempt " << attempt << "): "
               << mpd_connection_get_error_message(m_conn) << "\n");
        if (m_conn) { mpd_connection_free(m_conn); m_conn = nullptr; }
    }
    return false;
}

bool MpdCtl::applyPlayback(int queue_pos, bool select_track,
                           bool has_position, uint32_t position_ms,
                           MpdState::Status final_state,
                           bool restart_track) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    PlaybackSnapshot before;
    if (!capturePlaybackLocked(before)) return false;

    auto fail = [&]() {
        m_last_seek_ms.store(0, std::memory_order_relaxed);
        return rollbackPlaybackLocked("applyPlayback", before);
    };
    bool resume_from_stop =
        before.state == static_cast<int>(MPD_STATE_STOP) &&
        (final_state == MpdState::Status::PLAY ||
         final_state == MpdState::Status::PAUSE);
    int effective_pos = queue_pos >= 0 ? queue_pos : before.current_pos;
    // MusicPD/libFLAC cannot seek a growing HTTP input whose initial response
    // had no Content-Length. Once reconstruction is complete, force a decoder
    // reopen so the proxy's exact length is observed before seeking.
    if (restart_track &&
        before.state != static_cast<int>(MPD_STATE_STOP) &&
        !mpd_run_stop(m_conn))
        return fail();
    if ((select_track || resume_from_stop || restart_track) &&
        (effective_pos < 0 ||
         !mpd_run_play_pos(m_conn, static_cast<unsigned>(effective_pos))))
        return fail();

    if (has_position) {
        uint64_t now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        m_last_seek_ms.store(now_ms, std::memory_order_relaxed);
        if (!mpd_run_seek_current(
                m_conn, static_cast<float>(position_ms) / 1000.0f, false))
            return fail();
    }

    bool ok = true;
    switch (final_state) {
    case MpdState::Status::PLAY:
        ok = mpd_run_pause(m_conn, false);
        break;
    case MpdState::Status::PAUSE:
        ok = mpd_run_pause(m_conn, true);
        break;
    case MpdState::Status::STOP:
        ok = mpd_run_stop(m_conn);
        break;
    case MpdState::Status::UNKNOWN:
        break;
    }
    return ok ? true : fail();
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

bool MpdCtl::setRepeat(bool on) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    return mpd_run_repeat(m_conn, on);
}

bool MpdCtl::setRandom(bool on) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    if (!ensureConnected()) return false;
    return mpd_run_random(m_conn, on);
}

bool MpdCtl::setLoopMode(bool repeat, bool single) {
    std::lock_guard<std::mutex> lk(m_conn_mutex);
    QueueSnapshot before;
    if (!captureSnapshotLocked(before)) return false;
    if (!mpd_run_repeat(m_conn, repeat) || !mpd_run_single(m_conn, single))
        return rollbackLocked("setLoopMode", before);
    return true;
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
    out.next_queue_pos = mpd_status_get_next_song_pos(st);
    out.queue_len   = mpd_status_get_queue_length(st);
    if (const struct mpd_audio_format* format =
            mpd_status_get_audio_format(st)) {
        out.sample_rate = format->sample_rate;
        out.bits = format->bits;
        out.channels = format->channels;
    }
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

// ---- Event loop -------------------------------------------------------------

void MpdCtl::eventLoop() {
    // Position-report interval during playback (milliseconds).
    // The Qobuz phone app doesn't interpolate position client-side, so we
    // must send regular updates for the seek bar to advance in real time.
    constexpr int POSITION_REPORT_MS = 1000;

    // Rate-limiting state: fire callback at most once per POSITION_REPORT_MS
    // during playback, and immediately on real state changes.
    auto last_cb = std::chrono::steady_clock::now();
    MpdState last_state;
    bool     have_last_state = false;

    auto reconnect_idle = [this]() {
        if (m_idle_conn) mpd_connection_free(m_idle_conn);
        m_idle_conn = mpd_connection_new(m_host.c_str(),
                                          static_cast<unsigned>(m_port), 0);
        if (!m_idle_conn ||
            mpd_connection_get_error(m_idle_conn) != MPD_ERROR_SUCCESS) {
            if (m_idle_conn) {
                mpd_connection_free(m_idle_conn);
                m_idle_conn = nullptr;
            }
            return false;
        }
        if (!m_password.empty() &&
            !mpd_run_password(m_idle_conn, m_password.c_str())) {
            mpd_connection_free(m_idle_conn);
            m_idle_conn = nullptr;
            return false;
        }
        return true;
    };

    auto retry_delay = [this]() {
        for (int i = 0; i < 20 && !m_stop.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    while (!m_stop) {
        if (!m_idle_conn ||
            mpd_connection_get_error(m_idle_conn) != MPD_ERROR_SUCCESS) {
            LOGERR("MpdCtl: idle connection lost; reconnecting\n");
            if (!reconnect_idle()) retry_delay();
            continue;
        }
        // Enter MPD idle mode for player/queue/mixer events
        if (!mpd_send_idle_mask(m_idle_conn,
                                 static_cast<enum mpd_idle>(
                                     MPD_IDLE_PLAYER |
                                     MPD_IDLE_QUEUE  |
                                     MPD_IDLE_MIXER))) {
            LOGERR("MpdCtl: send_idle failed; reconnecting\n");
            if (!reconnect_idle()) retry_delay();
            continue;
        }

        // Wait up to POSITION_REPORT_MS for an MPD event using select().
        // On timeout we cancel idle, check position, and re-enter idle.
        int fd = mpd_connection_get_fd(m_idle_conn);
        if (fd < 0) {
            LOGERR("MpdCtl: idle connection has no socket; reconnecting\n");
            reconnect_idle();
            continue;
        }
        fd_set rfds;
        struct timeval tv;
        int r;
        do {
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            tv = {POSITION_REPORT_MS / 1000,
                  (POSITION_REPORT_MS % 1000) * 1000};
            r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        } while (r < 0 && errno == EINTR && !m_stop.load());

        if (r > 0) {
            // Data available — receive the idle event normally
            mpd_recv_idle(m_idle_conn, true);
        } else if (r == 0) {
            // Timeout: cancel idle and consume the cancelled-idle response.
            if (!mpd_send_noidle(m_idle_conn)) {
                reconnect_idle();
                continue;
            }
            mpd_recv_idle(m_idle_conn, true);
        } else {
            LOGERR("MpdCtl: select on idle connection failed; reconnecting\n");
            reconnect_idle();
            continue;
        }
        if (mpd_connection_get_error(m_idle_conn) != MPD_ERROR_SUCCESS) {
            LOGERR("MpdCtl: receive on idle connection failed; reconnecting\n");
            reconnect_idle();
            continue;
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
        bool state_changed = !have_last_state ||
            st.status != last_state.status ||
            st.volume != last_state.volume ||
            st.queue_pos != last_state.queue_pos ||
            st.queue_id != last_state.queue_id ||
            st.next_queue_pos != last_state.next_queue_pos ||
            st.queue_len != last_state.queue_len ||
            st.duration_ms != last_state.duration_ms ||
            st.sample_rate != last_state.sample_rate ||
            st.bits != last_state.bits ||
            st.channels != last_state.channels;
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
            last_state      = st;
            have_last_state = true;
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
