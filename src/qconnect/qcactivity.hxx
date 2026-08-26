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

// What the renderer is doing between the phone pressing play and the first
// sound.  That gap is routinely tens of seconds and occasionally minutes
// (stream URLs, segment reconstruction, MusicPD accepting the queue), and
// until now it was invisible: the status file still showed the *previous*
// track, paused, so the panel looked frozen while the daemon was busy.
//
// This is a process-wide sink rather than a QcManager member because the
// reporters are spread across translation units that know nothing about the
// manager — segstream.cxx reconstructs segments from its own worker threads,
// httphandler.cxx serves them.  Header-only so those units, and the test
// executables that link them, need no extra source file.
//
// QcManager::writeStatusFile() renders the snapshot into the status file the
// omdrcctrl panel polls; nothing else consumes it.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace QConnect {

// Coarse phase, shown on its own in the panel's big status line.  Ordered
// roughly as they occur, but nothing depends on the order.
enum class ActivityPhase {
    Idle,           // nothing to report — the panel shows the track again
    QueueReceived,  // the controller replaced the queue
    Resolving,      // asking Qobuz for stream URLs
    Downloading,    // reconstructing encrypted CMAF segments
    Buffering,      // handed to MusicPD, waiting for it to start
    Playing,        // audible
    Error,          // last operation failed; text says how
};

// How many entries the ring keeps.  The panel shows one or three; the extra
// depth costs nothing and leaves room for a longer view later.
inline constexpr std::size_t kActivityRingDepth = 6;

namespace detail {

struct ActivityState {
    std::mutex               mutex;
    ActivityPhase            phase{ActivityPhase::Idle};
    std::deque<std::string>  events;      // "HH:MM:SS text", oldest first
    // Progress throttling: the newest entry is rewritten in place rather than
    // pushed, so a 52-segment track cannot flush every other phase out of a
    // three-line ring.
    std::string              progress_key;
    unsigned                 progress_percent{0};
    std::chrono::steady_clock::time_point progress_at{};
    bool                     progress_open{false};  // newest entry is progress
};

inline ActivityState& activityState() {
    static ActivityState state;
    return state;
}

inline std::string activityStamp() {
    std::time_t now = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

// Caller holds the lock.
inline void activityPush(ActivityState& st, const std::string& text) {
    st.events.push_back(activityStamp() + " " + text);
    while (st.events.size() > kActivityRingDepth) st.events.pop_front();
    st.progress_open = false;
}

}  // namespace detail

// Label for the big status line.  Empty means "nothing to announce": the panel
// falls back to the now-playing line, which is what a settled system shows.
inline const char* activityPhaseLabel(ActivityPhase phase) {
    switch (phase) {
    case ActivityPhase::QueueReceived: return "NEW PLAYLIST RECEIVED";
    case ActivityPhase::Resolving:     return "RESOLVING STREAM";
    case ActivityPhase::Downloading:   return "LOADING SEGMENT";
    case ActivityPhase::Buffering:     return "BUFFERING";
    case ActivityPhase::Playing:       return "PLAYING";
    case ActivityPhase::Error:         return "ERROR";
    case ActivityPhase::Idle:          break;
    }
    return "";
}

// Enter `phase` and record `detail` in the ring (the phase label is used when
// `detail` is empty).
inline void activityPhase(ActivityPhase phase, const std::string& detail = {}) {
    auto& st = detail::activityState();
    std::lock_guard<std::mutex> lk(st.mutex);
    st.phase = phase;
    detail::activityPush(st, detail.empty() ? activityPhaseLabel(phase) : detail);
}

// Record something worth seeing without changing the phase — a scheduled next
// operation, a recoverable hiccup.
inline void activityNote(const std::string& text) {
    auto& st = detail::activityState();
    std::lock_guard<std::mutex> lk(st.mutex);
    detail::activityPush(st, text);
}

// Progress inside `phase`.  `key` identifies the run (the track, typically):
// while it is unchanged the newest ring entry is rewritten instead of pushed.
// Rate-limited to one update a second, plus the first and last step, so the
// ring keeps showing distinct phases rather than a column of segment counters.
inline void activityProgress(ActivityPhase phase, const std::string& key,
                             const std::string& label,
                             std::size_t done, std::size_t total) {
    auto& st = detail::activityState();
    std::lock_guard<std::mutex> lk(st.mutex);
    const unsigned percent = total == 0 ? 100u :
        static_cast<unsigned>((static_cast<uint64_t>(done) * 100) / total);
    const auto now = std::chrono::steady_clock::now();
    const bool new_run = (key != st.progress_key) || !st.progress_open;
    if (!new_run) {
        // Same run: rewriting the newest entry is cheap, but there is no point
        // doing it more than once a second per whole percent — the status file
        // itself is only rewritten at 1 Hz.
        const bool last = (total != 0 && done >= total);
        const bool due  = now - st.progress_at >= std::chrono::seconds(1);
        if (!last && !due && percent == st.progress_percent) return;
    }
    st.phase = phase;
    st.progress_key = key;
    st.progress_percent = percent;
    st.progress_at = now;

    std::string text = label + " " + std::to_string(done) + "/" +
                       std::to_string(total) + " (" + std::to_string(percent) + "%)";
    if (new_run) {
        detail::activityPush(st, text);
    } else {
        st.events.back() = detail::activityStamp() + " " + text;
    }
    st.progress_open = true;
}

// Nothing left to report.  The ring is kept: after the music starts, the last
// few lines are the record of how long getting there took.
inline void activityIdle() {
    auto& st = detail::activityState();
    std::lock_guard<std::mutex> lk(st.mutex);
    st.phase = ActivityPhase::Idle;
    st.progress_open = false;
}

struct ActivitySnapshot {
    std::string              state;   // phase label, empty when idle
    std::vector<std::string> events;  // "HH:MM:SS text", oldest first
};

inline ActivitySnapshot activitySnapshot() {
    auto& st = detail::activityState();
    std::lock_guard<std::mutex> lk(st.mutex);
    ActivitySnapshot snap;
    snap.state = activityPhaseLabel(st.phase);
    snap.events.assign(st.events.begin(), st.events.end());
    return snap;
}

}  // namespace QConnect
