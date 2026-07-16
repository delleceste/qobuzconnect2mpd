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

#include "wsession.hxx"
#include "qclog.hxx"

#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <exception>
#include <fcntl.h>
#include <sys/select.h>
#include <unistd.h>
#include <utility>

namespace QConnect {

// Milliseconds since Unix epoch
static uint64_t nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static int nextBatchId(std::atomic<int32_t>& counter) {
    return ++counter;
}

uint64_t WSession::nowAlignedMs() const {
    int64_t now = static_cast<int64_t>(nowMs());
    int64_t off = m_cloud_time_offset_ms.load(std::memory_order_relaxed);
    int64_t out = now + off;
    return out > 0 ? static_cast<uint64_t>(out) : 0;
}

uint64_t WSession::alignTimestampMs(uint64_t ts_ms) const {
    if (!ts_ms) return 0;
    int64_t ts = static_cast<int64_t>(ts_ms);
    int64_t off = m_cloud_time_offset_ms.load(std::memory_order_relaxed);
    int64_t out = ts + off;
    return out > 0 ? static_cast<uint64_t>(out) : 0;
}

WSession::WSession(const DeviceInfo& devinfo, const WSessionCallbacks& cbs)
    : m_devinfo(devinfo), m_cbs(cbs)
{}

WSession::~WSession() { disconnect(); }

bool WSession::connect(const ConnectCredentials& creds) {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycle_mutex);
    if (m_curl || m_thread.joinable() || m_callback_thread.joinable()) {
        LOGERR("WSession: connect called on an active session\n");
        return false;
    }
    m_ws_jwt      = creds.ws_jwt;
    m_ws_endpoint = creds.ws_endpoint.empty()
                    ? "wss://play.qobuz.com/ws"
                    : creds.ws_endpoint;

    m_curl = curl_easy_init();
    if (!m_curl) {
        LOGERR("WSession: curl_easy_init() failed\n");
        return false;
    }

    // WebSocket via libcurl: CURLOPT_CONNECT_ONLY=2 means "perform the
    // WebSocket upgrade handshake, then return leaving the socket open".
    curl_easy_setopt(m_curl, CURLOPT_URL,          m_ws_endpoint.c_str());
    curl_easy_setopt(m_curl, CURLOPT_CONNECT_ONLY, 2L);
    curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1L);
    // Required for WebSocket to be enabled in curl (experimental flag guard)
    curl_easy_setopt(m_curl, CURLOPT_PROTOCOLS_STR, "wss,ws");

    // The Qobuz WebSocket server checks Origin and User-Agent during the
    // HTTP upgrade handshake; without these it returns 403/400.
    struct curl_slist* ws_headers = nullptr;
    ws_headers = curl_slist_append(ws_headers, "Origin: https://play.qobuz.com");
    ws_headers = curl_slist_append(ws_headers,
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36");
    curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, ws_headers);

    CURLcode rc = curl_easy_perform(m_curl);
    curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, nullptr);
    curl_slist_free_all(ws_headers); // only needed for the HTTP upgrade
    if (rc != CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code);
        LOGERR("WSession: WebSocket connect to " << m_ws_endpoint
               << " failed: " << curl_easy_strerror(rc)
               << " (HTTP " << http_code << ")\n");
        curl_easy_cleanup(m_curl);
        m_curl = nullptr;
        return false;
    }

    LOGDEB("WSession: connected to " << m_ws_endpoint << "\n");

    // Send AUTHENTICATE envelope
    Bytes auth = buildAuthenticate(m_msg_id++, nowMs(), m_ws_jwt);
    if (!sendDirectFrame(auth, CURLWS_BINARY)) {
        LOGERR("WSession: failed to send Authenticate\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    // Subscribe to the QConnect channel
    Bytes sub = buildSubscribe(m_msg_id++, nowMs(), QCloudProto::QCONNECT);
    if (!sendDirectFrame(sub, CURLWS_BINARY)) {
        LOGERR("WSession: failed to send Subscribe\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    // Announce ourselves (CtrlSrvrJoinSession=61). Must be sent right after
    // Subscribe — the server will not send AddRenderer (83) until it knows
    // the device exists. session_uuid is omitted; server assigns one via
    // SessionState (81).
    Bytes join = buildCtrlJoinSession(nowMs(), m_msg_id++, m_devinfo);
    if (!sendDirectFrame(join, CURLWS_BINARY)) {
        LOGERR("WSession: failed to send CtrlJoinSession\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    if (pipe(m_wake_pipe) != 0) {
        LOGERR("WSession: could not create wake pipe: " << strerror(errno) << "\n");
        curl_easy_cleanup(m_curl);
        m_curl = nullptr;
        return false;
    }
    for (int fd : m_wake_pipe) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int fdflags = fcntl(fd, F_GETFD, 0);
        if (fdflags >= 0) fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC);
    }

    m_stop = false;
    m_error_exit = false;
    m_callback_stop = false;
    m_connected = true;
    m_event_started = true;
    try {
        m_callback_thread = std::thread(&WSession::callbackLoop, this);
        m_thread = std::thread(&WSession::eventLoop, this);
    } catch (const std::exception& e) {
        LOGERR("WSession: could not start session threads: " << e.what() << "\n");
        m_stop = true;
        {
            std::lock_guard<std::mutex> lk(m_callback_mutex);
            m_callback_queue.clear();
            m_callback_stop = true;
        }
        m_callback_cv.notify_all();
        wakeEventLoop();
        if (m_thread.joinable()) m_thread.join();
        if (m_callback_thread.joinable()) m_callback_thread.join();
        if (m_curl) {
            curl_easy_cleanup(m_curl);
            m_curl = nullptr;
        }
        {
            std::lock_guard<std::mutex> wake_lock(m_wake_mutex);
            for (int& fd : m_wake_pipe) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
        }
        m_connected = false;
        m_event_started = false;
        return false;
    }
    return true;
}

void WSession::disconnect() {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycle_mutex);
    // Don't gate on m_connected: eventLoop clears it before exiting on
    // recv error, after which m_thread is still joinable. Skipping the
    // join here leaves a joinable thread for the destructor, which then
    // calls std::terminate. Always join if there's a thread to join.
    m_stop = true;
    {
        std::lock_guard<std::mutex> lk(m_callback_mutex);
        m_callback_queue.clear();
        m_callback_stop = true;
    }
    m_callback_cv.notify_all();
    wakeEventLoop();
    if (m_thread.joinable()) m_thread.join();
    stopCallbackWorker();
    if (m_curl) {
        curl_easy_cleanup(m_curl);
        m_curl = nullptr;
    }
    {
        std::lock_guard<std::mutex> wake_lock(m_wake_mutex);
        for (int& fd : m_wake_pipe) {
            if (fd >= 0) close(fd);
            fd = -1;
        }
    }
    {
        std::lock_guard<std::mutex> lk(m_outbound_mutex);
        m_outbound.clear();
    }
    m_current_outbound.reset();
    m_connected = false;
    m_event_started = false;
    LOGDEB("WSession: disconnected\n");
}

bool WSession::sendRaw(const Bytes& data) {
    if (data.empty()) return false;
    return enqueueFrame(data, CURLWS_BINARY);
}

bool WSession::sendDirectFrame(const Bytes& data, unsigned int flags) {
    if (!m_curl) return false;
    size_t offset = 0;
    bool attempted = false;
    while (offset < data.size() || (!attempted && data.empty())) {
        size_t sent = 0;
        const void* ptr = data.empty() ? nullptr : data.data() + offset;
        CURLcode rc = curl_ws_send(m_curl, ptr, data.size() - offset,
                                   &sent, 0, flags);
        attempted = true;
        offset += sent;
        if (rc == CURLE_OK) {
            if (offset == data.size()) return true;
        } else if (rc != CURLE_AGAIN) {
            LOGERR("WSession: send failed: " << curl_easy_strerror(rc)
                   << " (sent " << offset << "/" << data.size() << ")\n");
            return false;
        }

        curl_socket_t sockfd = CURL_SOCKET_BAD;
        curl_easy_getinfo(m_curl, CURLINFO_ACTIVESOCKET, &sockfd);
        if (sockfd == CURL_SOCKET_BAD) return false;
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(sockfd, &rfds);
        FD_SET(sockfd, &wfds);
        timeval tv{5, 0};
        int ready;
        do {
            ready = select(static_cast<int>(sockfd) + 1,
                           &rfds, &wfds, nullptr, &tv);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0) {
            LOGERR("WSession: timed out waiting to send WebSocket frame\n");
            return false;
        }
    }
    return true;
}

bool WSession::enqueueFrame(Bytes data, unsigned int flags) {
    if (!m_connected.load(std::memory_order_acquire) ||
        !m_event_started.load(std::memory_order_acquire) ||
        m_stop.load(std::memory_order_relaxed)) return false;
    {
        std::lock_guard<std::mutex> lk(m_outbound_mutex);
        if (!m_connected.load(std::memory_order_relaxed) || m_stop.load())
            return false;
        OutboundFrame frame{std::move(data), 0, flags};
        if (flags & (CURLWS_PING | CURLWS_PONG | CURLWS_CLOSE))
            m_outbound.push_front(std::move(frame));
        else
            m_outbound.push_back(std::move(frame));
    }
    wakeEventLoop();
    return true;
}

bool WSession::hasOutbound() {
    if (m_current_outbound) return true;
    std::lock_guard<std::mutex> lk(m_outbound_mutex);
    return !m_outbound.empty();
}

bool WSession::flushOutbound() {
    constexpr int MAX_FRAMES_PER_PASS = 16;
    for (int frame_count = 0; frame_count < MAX_FRAMES_PER_PASS;) {
        if (!m_current_outbound) {
            std::lock_guard<std::mutex> lk(m_outbound_mutex);
            if (m_outbound.empty()) return true;
            m_current_outbound.emplace(std::move(m_outbound.front()));
            m_outbound.pop_front();
        }

        OutboundFrame& frame = *m_current_outbound;
        size_t sent = 0;
        const void* ptr = frame.data.empty()
            ? nullptr : frame.data.data() + frame.offset;
        CURLcode rc = curl_ws_send(m_curl, ptr,
                                   frame.data.size() - frame.offset,
                                   &sent, 0, frame.flags);
        frame.offset += sent;
        if (rc == CURLE_AGAIN) return true;
        if (rc != CURLE_OK) {
            LOGERR("WSession: send failed: " << curl_easy_strerror(rc)
                   << " (sent " << frame.offset << "/"
                   << frame.data.size() << ")\n");
            return false;
        }
        if (frame.offset < frame.data.size()) {
            if (sent == 0) return true;
            continue;
        }
        m_current_outbound.reset();
        ++frame_count;
    }
    return true;
}

void WSession::wakeEventLoop() {
    std::lock_guard<std::mutex> wake_lock(m_wake_mutex);
    if (m_wake_pipe[1] < 0) return;
    const uint8_t wake = 1;
    ssize_t result;
    do {
        result = write(m_wake_pipe[1], &wake, sizeof(wake));
    } while (result < 0 && errno == EINTR);
}

void WSession::drainWakePipe() {
    if (m_wake_pipe[0] < 0) return;
    uint8_t buf[64];
    while (read(m_wake_pipe[0], buf, sizeof(buf)) > 0) {}
}

void WSession::postCallback(std::function<void()> callback) {
    if (!callback) return;
    {
        std::lock_guard<std::mutex> lk(m_callback_mutex);
        if (m_callback_stop) return;
        m_callback_queue.push_back(std::move(callback));
    }
    m_callback_cv.notify_one();
}

void WSession::callbackLoop() {
    for (;;) {
        std::function<void()> callback;
        {
            std::unique_lock<std::mutex> lk(m_callback_mutex);
            m_callback_cv.wait(lk, [this] {
                return m_callback_stop || !m_callback_queue.empty();
            });
            if (m_callback_queue.empty()) {
                if (m_callback_stop) return;
                continue;
            }
            callback = std::move(m_callback_queue.front());
            m_callback_queue.pop_front();
        }
        try {
            callback();
        } catch (const std::exception& e) {
            LOGERR("WSession: callback failed: " << e.what() << "\n");
        } catch (...) {
            LOGERR("WSession: callback failed with an unknown exception\n");
        }
    }
}

void WSession::stopCallbackWorker() {
    {
        std::lock_guard<std::mutex> lk(m_callback_mutex);
        m_callback_stop = true;
    }
    m_callback_cv.notify_all();
    if (m_callback_thread.joinable()) m_callback_thread.join();
}

void WSession::commitQueueVersion(const QueueVersion& version) {
    if (!version.present) return;
    std::lock_guard<std::mutex> lk(m_state_mutex);
    const QueueVersion& current = m_last_state.queue_version;
    if (!current.present || version.major > current.major ||
        (version.major == current.major && version.minor >= current.minor))
        m_last_state.queue_version = version;
}

void WSession::completeSetState(uint64_t command_id) {
    std::lock_guard<std::mutex> lk(m_state_mutex);
    if (command_id > m_set_state_completed)
        m_set_state_completed = command_id;
}

void WSession::reportState(const QueueRendererState& state) {
    if (!m_connected) return;
    QueueRendererState s = state;
    std::lock_guard<std::mutex> lk(m_state_mutex);
    // The immediate SetState acknowledgement is authoritative until the
    // command is applied. In particular, do not let a pre-seek MPD tick
    // replace BUFFERING and the requested position while work is queued.
    if (m_set_state_completed < m_set_state_serial) return;
    // Preserve the server-assigned queue_version; QcManager doesn't track it.
    if (m_last_state.queue_version.present)
        s.queue_version = m_last_state.queue_version;
    m_last_state = s;
    LOGDEB("WSession: reportState pos_ms=" << s.state.current_position_ms
           << " buf=" << static_cast<int>(s.state.buffer_state)
           << " qver=" << s.queue_version.major << "." << s.queue_version.minor << "\n");
    int bid = nextBatchId(m_batch_id);
    s.state.position_timestamp_ms = alignTimestampMs(s.state.position_timestamp_ms);
    // Keep the state mutex through enqueue so a SetState acknowledgement can
    // never be queued before this older sample and then overwritten by it.
    sendRaw(buildStateUpdated(nowAlignedMs(), bid, s));
}

void WSession::reportVolume(uint32_t volume) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildVolumeChanged(nowAlignedMs(), bid, volume));
}

void WSession::reportMaxQuality(int32_t quality_fmt_id) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildMaxQualityChanged(nowAlignedMs(), bid, quality_fmt_id));
}

void WSession::reportFileQuality(int32_t sample_rate_hz) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildFileAudioQualityChanged(nowAlignedMs(), bid, sample_rate_hz));
}

void WSession::setActiveRenderer(uint64_t renderer_id) {
    if (!m_connected) return;
    m_renderer_id = renderer_id;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildSetActiveRenderer(nowAlignedMs(), bid,
                                    static_cast<int32_t>(renderer_id)));
}

bool WSession::sendHeartbeat() {
    if (!m_connected || !m_is_active) return true;
    std::lock_guard<std::mutex> lk(m_state_mutex);
    QueueRendererState state;
    state = m_last_state;
    // m_last_state.position_timestamp_ms was set when we last polled MPD.
    // If the event loop was blocked (e.g. during a long HTTP seek via
    // on_set_state), this timestamp can be 10-15 s stale.  Sending it as-is
    // causes the phone to project: position + (now - stale_ts), which is
    // many seconds ahead of reality.  Fix: always use nowMs() as timestamp.
    //   - BUFFERING: position unchanged (seek still in progress).
    //   - Playing:   advance position by elapsed time since last poll so the
    //                heartbeat gives a reasonable estimate until the next
    //                regular reportState arrives.
    uint64_t now = nowAlignedMs();
    uint64_t old_ts = alignTimestampMs(state.state.position_timestamp_ms);
    if (old_ts && now > old_ts) {
        uint64_t elapsed = now - old_ts;
        if (state.state.playing_state == PlayingState::PLAYING &&
            state.state.buffer_state != BufferState::BUFFERING &&
            elapsed < 30000) { // don't advance past a stale-by->30s snapshot
            uint64_t projected = state.state.current_position_ms + elapsed;
            if (state.state.duration_ms)
                projected = std::min<uint64_t>(projected,
                                               state.state.duration_ms);
            state.state.current_position_ms = static_cast<uint32_t>(projected);
        }
    }
    state.state.position_timestamp_ms = now;
    // Keep queue-version publication ordered with the state frame enqueue.
    return sendRaw(buildStateUpdated(now, nextBatchId(m_batch_id), state));
}


void WSession::eventLoop() {
    curl_socket_t sockfd = CURL_SOCKET_BAD;
    curl_easy_getinfo(m_curl, CURLINFO_ACTIVESOCKET, &sockfd);
    if (sockfd == CURL_SOCKET_BAD) {
        LOGERR("WSession: WebSocket has no active socket\n");
        m_error_exit = true;
        m_stop = true;
    }

    auto last_heartbeat = std::chrono::steady_clock::now();
    constexpr size_t BUFSIZE = 65536;
    std::vector<uint8_t> buf(BUFSIZE);
    Bytes incoming_frame;

    while (!m_stop) {
        if (!flushOutbound()) {
            m_error_exit = true;
            break;
        }

        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(sockfd, &rfds);
        int maxfd = static_cast<int>(sockfd);
        if (m_wake_pipe[0] >= 0) {
            FD_SET(m_wake_pipe[0], &rfds);
            if (m_wake_pipe[0] > maxfd) maxfd = m_wake_pipe[0];
        }
        bool outbound_pending = hasOutbound();
        if (outbound_pending) FD_SET(sockfd, &wfds);
        timeval tv{0, RECV_TIMEOUT_MS * 1000};
        int ready = select(maxfd + 1, &rfds,
                           outbound_pending ? &wfds : nullptr,
                           nullptr, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            LOGERR("WSession: connection lost (select: " << strerror(errno)
                   << ") — terminating session\n");
            m_error_exit = true;
            break;
        }

        if (m_wake_pipe[0] >= 0 && FD_ISSET(m_wake_pipe[0], &rfds))
            drainWakePipe();

        if (outbound_pending && FD_ISSET(sockfd, &wfds) && !flushOutbound()) {
            m_error_exit = true;
            break;
        }

        if (FD_ISSET(sockfd, &rfds)) {
            for (;;) {
                size_t recvd = 0;
                const struct curl_ws_frame* meta = nullptr;
                CURLcode rc = curl_ws_recv(m_curl,
                                            buf.data(), buf.size(),
                                            &recvd, &meta);
                if (rc == CURLE_AGAIN) break;
                if (rc != CURLE_OK) {
                    LOGERR("WSession: connection lost (recv: "
                           << curl_easy_strerror(rc) << ") — terminating session\n");
                    m_error_exit = true;
                    m_stop = true;
                    break;
                }
                if (!meta) break;

                // CLOSE frame — server-initiated close, treat as error exit
                if (meta->flags & CURLWS_CLOSE) {
                    LOGINF("WSession: server closed WebSocket connection — terminating session\n");
                    m_error_exit = true;
                    m_stop = true;
                    break;
                }
                // libcurl replies to PING automatically unless NOAUTOPONG is set.
                if (meta->flags & CURLWS_PING) {
                    continue;
                }
                if (meta->flags & CURLWS_PONG) continue;

                incoming_frame.insert(incoming_frame.end(),
                                      buf.begin(), buf.begin() + recvd);
                if (meta->bytesleft == 0 && !(meta->flags & CURLWS_CONT) &&
                    !incoming_frame.empty()) {
                    std::vector<Message> msgs;
                    uint64_t rx_msg_date_ms = 0;
                    if (parseFrame(incoming_frame, msgs, &rx_msg_date_ms)) {
                        if (rx_msg_date_ms) {
                            int64_t local_now = static_cast<int64_t>(nowMs());
                            int64_t sample_off =
                                static_cast<int64_t>(rx_msg_date_ms) - local_now;
                            if (std::llabs(sample_off) < 300000) {
                                int64_t old_off = m_cloud_time_offset_ms.load(
                                    std::memory_order_relaxed);
                                int64_t new_off = (old_off * 7 + sample_off) / 8;
                                m_cloud_time_offset_ms.store(
                                    new_off, std::memory_order_relaxed);
                            }
                        }
                        for (const auto& msg : msgs) dispatchMessage(msg);
                    } else {
                        LOGDEB("WSession: failed to parse frame of "
                               << incoming_frame.size() << " bytes\n");
                    }
                    incoming_frame.clear();
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - last_heartbeat).count() >= HEARTBEAT_INTERVAL_S) {
            sendHeartbeat();
            last_heartbeat = now;
        }
    }

    m_connected = false;
    m_event_started = false;
    if (!m_error_exit && m_curl)
        sendDirectFrame({}, CURLWS_CLOSE);
    if (m_error_exit && m_cbs.on_disconnected) {
        {
            std::lock_guard<std::mutex> lk(m_callback_mutex);
            m_callback_queue.clear();
        }
        auto callback = m_cbs.on_disconnected;
        postCallback([callback] { callback(true); });
    }
    LOGDEB("WSession: event loop exited\n");
}

void WSession::maybeRestoreState() {
    // RendererStateUpdated is captured while another renderer is active. Keep
    // it pending until this renderer is activated and the subsequent queue
    // snapshot arrives; applying it while inactive would discard the handoff.
    if (!m_is_active || !m_pending_restore_state) return;

    RendererState state = *m_pending_restore_state;
    uint64_t command_id = 0;
    QueueTrackRef current_item;
    if (state.has_current_queue_index) {
        if (!m_last_queue_snapshot) return;
        size_t index = state.current_queue_index;
        if (index >= m_last_queue_snapshot->tracks.size()) {
            LOGERR("WSession: restore-state queue index " << index
                   << " is outside queue size "
                   << m_last_queue_snapshot->tracks.size() << "\n");
            m_pending_restore_state.reset();
            return;
        }

        size_t track_index = index;
        const auto& shuffled = m_last_queue_snapshot->shuffled_track_indexes;
        if (m_last_queue_snapshot->shuffle_on &&
            shuffled.size() == m_last_queue_snapshot->tracks.size()) {
            std::vector<bool> seen(shuffled.size(), false);
            bool valid = true;
            for (uint32_t candidate : shuffled) {
                if (candidate >= shuffled.size() || seen[candidate]) {
                    valid = false;
                    break;
                }
                seen[candidate] = true;
            }
            if (valid) track_index = shuffled[index];
        }

        if (track_index < m_last_queue_snapshot->tracks.size()) {
            current_item.queue_item_id =
                m_last_queue_snapshot->tracks[track_index].queue_item_id;
            current_item.track_id =
                m_last_queue_snapshot->tracks[track_index].track_id;
            current_item.context_uuid =
                m_last_queue_snapshot->tracks[track_index].context_uuid;
            current_item.has_queue_item_id = true;
        }
    }

    {
        std::lock_guard<std::mutex> lk(m_state_mutex);
        command_id = ++m_set_state_serial;
        m_last_state.state.playing_state = state.playing_state;
        m_last_state.state.buffer_state =
            (state.has_position || current_item.has_queue_item_id)
                ? BufferState::BUFFERING : state.buffer_state;
        m_last_state.state.current_position_ms = state.current_position_ms;
        // RendererState timestamps are already in cloud time. Store local time
        // internally and freeze the requested restore point while buffering.
        m_last_state.state.position_timestamp_ms = nowMs();
        m_last_state.state.has_position = state.has_position;
        m_last_state.state.duration_ms = state.duration_ms;
        if (current_item.has_queue_item_id) {
            m_last_state.state.current_queue_item_id = current_item.queue_item_id;
            m_last_state.state.has_current_queue_item_id = true;
        }
        m_last_state.state.next_queue_item_id = state.next_queue_item_id;
        m_last_state.state.has_next_queue_item_id = state.has_next_queue_item_id;
    }

    m_pending_restore_state.reset();
    if (m_cbs.on_set_state) {
        auto callback = m_cbs.on_set_state;
        postCallback([callback, command_id, state, current_item] {
            callback(command_id, state.playing_state, state.current_position_ms,
                     state.has_position, current_item);
        });
    } else {
        completeSetState(command_id);
    }
}

// Dispatch a decoded inbound message to the appropriate callback.
// Called only from the WebSocket owner thread. Renderer callbacks are queued
// separately so this function never waits for MusicPD or HTTP stream work.
void WSession::dispatchMessage(const Message& msg) {
    switch (msg.type) {

    case MsgType::SRVRC_SESSION_STATE:
        LOGDEB("WSession: SessionState id=" << msg.session_state.session_id << "\n");
        m_session_uuid = msg.session_state.session_uuid;
        m_session_id   = msg.session_state.session_id;
        // Ask server to send current renderer state
        sendRaw(buildAskRendererState(nowAlignedMs(), nextBatchId(m_batch_id),
                                       m_session_id));
        if (m_cbs.on_session_state) {
            auto callback = m_cbs.on_session_state;
            MsgSessionState state = msg.session_state;
            postCallback([callback, state] { callback(state); });
        }
        if (m_cbs.on_connected) {
            auto callback = m_cbs.on_connected;
            postCallback([callback] { callback(); });
        }
        break;

    case MsgType::SRVRC_ADD_RENDERER:
        LOGDEB("WSession: AddRenderer id=" << msg.add_renderer.renderer_id
               << " uuid=" << msg.add_renderer.renderer.uuid.size() << "B\n");
        // Only act on AddRenderer for our own device (match by UUID)
        if (msg.add_renderer.renderer.uuid == m_devinfo.uuid) {
            setActiveRenderer(msg.add_renderer.renderer_id);
        }
        break;

    case MsgType::SRVRC_REMOVE_RENDERER:
        LOGDEB("WSession: RemoveRenderer id="
               << msg.remove_renderer.renderer_id << "\n");
        if (msg.remove_renderer.renderer_id == m_renderer_id)
            m_renderer_id = 0;
        break;

    case MsgType::SRVRC_ACTIVE_RNDR_CHANGED:
        LOGDEB("WSession: ActiveRendererChanged id="
               << msg.active_renderer_changed.renderer_id << "\n");
        break;

    case MsgType::CMD_SET_ACTIVE:
        LOGDEB("WSession: SetActive active=" << msg.set_active.active << "\n");
        m_is_active = msg.set_active.active;
        if (m_cbs.on_set_active) {
            auto callback = m_cbs.on_set_active;
            bool active = m_is_active;
            postCallback([callback, active] { callback(active); });
        }
        if (m_is_active) {
            // Activation handshake (matches qonductor order):
            // 1. VolumeMuted(false)  — field 29, must be sent even with empty body
            // 2. VolumeChanged       — field 25
            // 3. MaxAudioQualityChanged — field 28, value is quality level 1-4
            sendRaw(buildVolumeMuted(nowAlignedMs(), nextBatchId(m_batch_id), false));
            reportVolume(50);  // MPD volume will be reported accurately by MpdCtl later
            // Convert format_id to quality level: 27->4, 7->3, 6->2, 5->1
            int32_t ql = 4;
            if (m_devinfo.max_quality == 7) ql = 3;
            else if (m_devinfo.max_quality == 6) ql = 2;
            else if (m_devinfo.max_quality == 5) ql = 1;
            reportMaxQuality(ql);
            // Request current queue state from server
            if (!m_session_uuid.empty()) {
                sendRaw(buildAskQueueState(nowAlignedMs(), nextBatchId(m_batch_id),
                                            m_session_uuid));
            }
        }
        break;

    case MsgType::CMD_SET_LOOP_MODE:
    case MsgType::SRVRC_LOOP_MODE_SET:
        if (m_cbs.on_loop_mode) {
            auto callback = m_cbs.on_loop_mode;
            MsgLoopMode mode = msg.loop_mode;
            postCallback([callback, mode] { callback(mode); });
        }
        break;

    case MsgType::CMD_SET_SHUFFLE_MODE:
    case MsgType::SRVRC_SHUFFLE_MODE_SET:
        if (m_cbs.on_shuffle_mode) {
            auto callback = m_cbs.on_shuffle_mode;
            MsgShuffleMode mode = msg.shuffle_mode;
            postCallback([callback, mode] { callback(mode); });
        }
        break;

    case MsgType::CMD_SET_STATE:
        LOGDEB("WSession: SetState state="
               << static_cast<int>(msg.set_state.playing_state)
               << " pos=" << msg.set_state.current_position_ms
               << " has_pos=" << msg.set_state.has_position
               << " qitem=" << msg.set_state.current_queue_item.queue_item_id
               << " has_qitem=" << msg.set_state.current_queue_item.has_queue_item_id
               << " qver=" << msg.set_state.queue_version.major
               << "." << msg.set_state.queue_version.minor
               << "\n");
        // Only act on SetState when at least one field is actually present.
        // Responding to empty SetState creates a feedback loop with the server.
        // Use has-flags because 0 is a valid value for position and queue_item_id.
        if (msg.set_state.playing_state != PlayingState::UNKNOWN ||
            msg.set_state.has_position ||
            msg.set_state.current_queue_item.has_queue_item_id) {
            // Build and send the ack BEFORE calling on_set_state.
            // on_set_state → QcManager → MpdCtl::seek() → mpd_run_seek_pos()
            // can block this thread for many seconds while MPD repositions an
            // HTTP stream.  If we send the ack after that delay the phone has
            // already moved on (local interpolation) and rejects our position
            // as stale.  Sending first ensures the phone freezes its bar at
            // the seeked position (BUFFERING) within ~100 ms of the command,
            // then resumes when the MpdCtl event loop later sends OK.
            QueueRendererState ack;
            uint64_t command_id = 0;
            {
                std::lock_guard<std::mutex> lk(m_state_mutex);
                const QueueVersion& version = msg.set_state.queue_version;
                const QueueVersion& current = m_last_state.queue_version;
                if (version.present &&
                    (!current.present || version.major > current.major ||
                     (version.major == current.major &&
                      version.minor >= current.minor)))
                    m_last_state.queue_version = version;
                command_id = ++m_set_state_serial;
                ack = m_last_state;
            }
            bool repositioning = msg.set_state.has_position;
            if (msg.set_state.playing_state != PlayingState::UNKNOWN)
                ack.state.playing_state = msg.set_state.playing_state;
            if (msg.set_state.has_position) {
                ack.state.current_position_ms = msg.set_state.current_position_ms;
                ack.state.position_timestamp_ms = nowMs();
                ack.state.has_position = true;
            }
            if (msg.set_state.current_queue_item.has_queue_item_id) {
                bool item_changed =
                    (!ack.state.has_current_queue_item_id ||
                     ack.state.current_queue_item_id !=
                         msg.set_state.current_queue_item.queue_item_id);
                ack.state.current_queue_item_id = msg.set_state.current_queue_item.queue_item_id;
                ack.state.has_current_queue_item_id = true;
                repositioning = repositioning || item_changed;
                // Track switch without explicit position should reset to start.
                // Reusing a stale pre-switch timestamp/position makes the phone
                // jump ahead by several seconds on the new track.
                if (item_changed && !msg.set_state.has_position) {
                    ack.state.current_position_ms = 0;
                    ack.state.position_timestamp_ms = nowMs();
                    ack.state.has_position = true;
                }
                if (item_changed) {
                    ack.state.duration_ms = 0;
                    ack.state.next_queue_item_id = 0;
                    ack.state.has_next_queue_item_id = false;
                }
            }
            if (msg.set_state.next_queue_item.has_queue_item_id) {
                ack.state.next_queue_item_id =
                    msg.set_state.next_queue_item.queue_item_id;
                ack.state.has_next_queue_item_id = true;
            }
            if (repositioning)
                ack.state.buffer_state = BufferState::BUFFERING;
            // If no explicit seek was provided, refresh timestamp when entering
            // PLAYING so the app does not extrapolate from an old snapshot.
            if (!msg.set_state.has_position &&
                msg.set_state.playing_state == PlayingState::PLAYING &&
                ack.state.position_timestamp_ms == 0) {
                ack.state.position_timestamp_ms = nowMs();
                ack.state.has_position = true;
            }
            {
                std::lock_guard<std::mutex> lk(m_state_mutex);
                // A completed queue operation may have published a newer
                // version while this acknowledgement was being assembled.
                if (m_last_state.queue_version.present)
                    ack.queue_version = m_last_state.queue_version;
                m_last_state = ack;
            }
            QueueRendererState wire_ack = ack;
            wire_ack.state.position_timestamp_ms =
                alignTimestampMs(wire_ack.state.position_timestamp_ms);
            sendRaw(buildStateUpdated(nowAlignedMs(), nextBatchId(m_batch_id), wire_ack));

            if (m_cbs.on_set_state) {
                auto callback = m_cbs.on_set_state;
                MsgSetState state = msg.set_state;
                postCallback([callback, command_id, state] {
                    callback(command_id, state.playing_state,
                             state.current_position_ms,
                             state.has_position, state.current_queue_item);
                });
            } else {
                completeSetState(command_id);
            }
        } else {
            commitQueueVersion(msg.set_state.queue_version);
        }
        break;

    case MsgType::CMD_SET_VOLUME:
        LOGDEB("WSession: SetVolume vol=" << msg.set_volume.volume
               << " delta=" << msg.set_volume.volume_delta << "\n");
        if (m_cbs.on_set_volume) {
            auto callback = m_cbs.on_set_volume;
            MsgSetVolume volume = msg.set_volume;
            postCallback([callback, volume] {
                callback(volume.volume, volume.volume_delta);
            });
        }
        break;

    case MsgType::SRVRC_QUEUE_STATE:
        LOGDEB("WSession: QueueState tracks=" << msg.queue_state.tracks.size()
               << " qver=" << msg.queue_state.queue_version.major
               << "." << msg.queue_state.queue_version.minor << "\n");
        m_last_queue_snapshot = msg.queue_state;
        if (m_cbs.on_queue_state) {
            auto callback = m_cbs.on_queue_state;
            MsgQueueState state = msg.queue_state;
            postCallback([callback, state] { callback(state); });
        }
        maybeRestoreState();
        break;

    case MsgType::SRVRC_QUEUE_LOAD_TRACKS:
        LOGDEB("WSession: QueueLoadTracks tracks="
               << msg.queue_load_tracks.tracks.size()
               << " pos=" << msg.queue_load_tracks.queue_position
               << " qver=" << msg.queue_load_tracks.queue_version.major
               << "." << msg.queue_load_tracks.queue_version.minor << "\n");
        m_last_queue_snapshot = MsgQueueState{};
        m_last_queue_snapshot->queue_version =
            msg.queue_load_tracks.queue_version;
        m_last_queue_snapshot->tracks = msg.queue_load_tracks.tracks;
        m_last_queue_snapshot->shuffle_on =
            msg.queue_load_tracks.shuffle_on;
        m_last_queue_snapshot->has_shuffle_on =
            msg.queue_load_tracks.has_shuffle_on;
        if (m_cbs.on_queue_load) {
            auto callback = m_cbs.on_queue_load;
            MsgQueueLoadTracks load = msg.queue_load_tracks;
            postCallback([callback, load] { callback(load); });
        }
        maybeRestoreState();
        break;

    case MsgType::SRVRC_TRACKS_INSERTED:
        LOGDEB("WSession: TracksInserted tracks=" << msg.tracks_inserted.tracks.size()
               << " insert_after=" << msg.tracks_inserted.insert_after
               << " qver=" << msg.tracks_inserted.queue_version.major
               << "." << msg.tracks_inserted.queue_version.minor << "\n");
        if (m_cbs.on_tracks_inserted) {
            auto callback = m_cbs.on_tracks_inserted;
            MsgQueueTracksInserted inserted = msg.tracks_inserted;
            postCallback([callback, inserted] { callback(inserted); });
        }
        break;

    case MsgType::SRVRC_TRACKS_ADDED:
        if (m_cbs.on_tracks_added) {
            auto callback = m_cbs.on_tracks_added;
            MsgQueueTracksAdded added = msg.tracks_added;
            postCallback([callback, added] { callback(added); });
        }
        break;

    case MsgType::SRVRC_TRACKS_REMOVED:
        if (m_cbs.on_tracks_removed) {
            auto callback = m_cbs.on_tracks_removed;
            MsgQueueTracksRemoved removed = msg.tracks_removed;
            postCallback([callback, removed] { callback(removed); });
        }
        break;

    case MsgType::SRVRC_TRACKS_REORDERED:
        if (m_cbs.on_tracks_reordered) {
            auto callback = m_cbs.on_tracks_reordered;
            MsgQueueTracksReordered reordered = msg.tracks_reordered;
            postCallback([callback, reordered] { callback(reordered); });
        }
        break;

    case MsgType::SRVRC_QUEUE_CLEARED:
        LOGINF("WSession: QueueCleared\n");
        m_last_queue_snapshot = MsgQueueState{};
        m_last_queue_snapshot->queue_version = msg.queue_cleared.queue_version;
        if (m_cbs.on_queue_cleared) {
            auto callback = m_cbs.on_queue_cleared;
            MsgQueueCleared cleared = msg.queue_cleared;
            postCallback([callback, cleared] { callback(cleared); });
        }
        break;

    case MsgType::SRVRC_QUEUE_VERSION_CHANGED:
        LOGDEB("WSession: QueueVersionChanged qver="
               << msg.queue_version_changed.queue_version.major
               << "." << msg.queue_version_changed.queue_version.minor << "\n");
        // This notification contains no queue mutation for QcManager to apply,
        // so it is already authoritative when received. Keep the monotonic
        // guard used by completed asynchronous queue operations.
        commitQueueVersion(msg.queue_version_changed.queue_version);
        break;

    case MsgType::SRVRC_RENDERER_STATE_UPD:
        LOGDEB("WSession: RendererStateUpdated id="
               << msg.renderer_state_upd.renderer_id << "\n");
        if (msg.renderer_state_upd.renderer_id != m_renderer_id && !m_is_active) {
            m_pending_restore_state = msg.renderer_state_upd.state;
        }
        break;

    default:
        LOGDEB("WSession: unhandled msg type "
               << static_cast<int>(msg.type) << "\n");
        break;
    }
}

} // namespace QConnect
