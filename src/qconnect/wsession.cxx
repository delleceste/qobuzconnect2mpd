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

#include <chrono>
#include <cstring>
#include <sys/select.h>

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

WSession::WSession(const DeviceInfo& devinfo, const WSessionCallbacks& cbs)
    : m_devinfo(devinfo), m_cbs(cbs)
{}

WSession::~WSession() { disconnect(); }

bool WSession::connect(const ConnectCredentials& creds) {
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
    if (!sendRaw(auth)) {
        LOGERR("WSession: failed to send Authenticate\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    // Subscribe to the QConnect channel
    Bytes sub = buildSubscribe(m_msg_id++, nowMs(), QCloudProto::QCONNECT);
    if (!sendRaw(sub)) {
        LOGERR("WSession: failed to send Subscribe\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    // Announce ourselves (CtrlSrvrJoinSession=61). Must be sent right after
    // Subscribe — the server will not send AddRenderer (83) until it knows
    // the device exists. session_uuid is omitted; server assigns one via
    // SessionState (81).
    Bytes join = buildCtrlJoinSession(nowMs(), m_msg_id++, m_devinfo);
    if (!sendRaw(join)) {
        LOGERR("WSession: failed to send CtrlJoinSession\n");
        curl_easy_cleanup(m_curl); m_curl = nullptr;
        return false;
    }

    m_connected = true;
    m_stop      = false;
    m_thread    = std::thread(&WSession::eventLoop, this);
    return true;
}

void WSession::disconnect() {
    if (!m_connected) return;
    m_stop = true;
    if (m_thread.joinable()) m_thread.join();
    if (m_curl) {
        // Send a WebSocket CLOSE frame
        size_t sent = 0;
        curl_ws_send(m_curl, nullptr, 0, &sent, 0, CURLWS_CLOSE);
        curl_easy_cleanup(m_curl);
        m_curl = nullptr;
    }
    m_connected = false;
    LOGDEB("WSession: disconnected\n");
}

bool WSession::sendRaw(const Bytes& data) {
    if (!m_curl || data.empty()) return false;
    std::lock_guard<std::mutex> lk(m_send_mutex);
    size_t sent = 0;
    // Send as a single binary WebSocket frame
    CURLcode rc = curl_ws_send(m_curl,
                                data.data(), data.size(),
                                &sent,
                                0,       // fragmentation offset
                                CURLWS_BINARY);
    if (rc != CURLE_OK || sent != data.size()) {
        LOGERR("WSession: send failed: " << curl_easy_strerror(rc)
               << " (sent " << sent << "/" << data.size() << ")\n");
        return false;
    }
    return true;
}

void WSession::reportState(const QueueRendererState& state) {
    if (!m_connected) return;
    {
        std::lock_guard<std::mutex> lk(m_state_mutex);
        m_last_state = state;
    }
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildStateUpdated(nowMs(), bid, state));
}

void WSession::reportVolume(uint32_t volume) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildVolumeChanged(nowMs(), bid, volume));
}

void WSession::reportMaxQuality(int32_t quality_fmt_id) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildMaxQualityChanged(nowMs(), bid, quality_fmt_id));
}

void WSession::reportFileQuality(int32_t sample_rate_hz) {
    if (!m_connected) return;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildFileAudioQualityChanged(nowMs(), bid, sample_rate_hz));
}

void WSession::setActiveRenderer(uint64_t renderer_id) {
    if (!m_connected) return;
    m_renderer_id = renderer_id;
    int bid = nextBatchId(m_batch_id);
    sendRaw(buildSetActiveRenderer(nowMs(), bid,
                                    static_cast<int32_t>(renderer_id)));
}

bool WSession::sendHeartbeat() {
    if (!m_connected || !m_is_active) return true;
    QueueRendererState state;
    {
        std::lock_guard<std::mutex> lk(m_state_mutex);
        state = m_last_state;
    }
    return sendRaw(buildStateUpdated(nowMs(), nextBatchId(m_batch_id), state));
}


void WSession::eventLoop() {
    // Get raw socket fd for select()-based waiting
    curl_socket_t sockfd = CURL_SOCKET_BAD;
    curl_easy_getinfo(m_curl, CURLINFO_ACTIVESOCKET, &sockfd);

    auto last_heartbeat = std::chrono::steady_clock::now();
    constexpr size_t BUFSIZE = 65536;
    std::vector<uint8_t> buf(BUFSIZE);

    while (!m_stop) {
        // Wait up to RECV_TIMEOUT_MS for data to arrive
        int r = 0;
        if (sockfd != CURL_SOCKET_BAD) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv{0, RECV_TIMEOUT_MS * 1000};
            r = select(static_cast<int>(sockfd) + 1,
                       &rfds, nullptr, nullptr, &tv);
            if (r < 0 && errno != EINTR) {
                LOGERR("WSession: select error: " << strerror(errno) << "\n");
                break;
            }
        }

        // Receive one frame if data is ready (may be fragmented — reassemble)
        if (r > 0) {
            Bytes frame;
            bool  complete = false;
            while (!complete) {
                size_t recvd = 0;
                const struct curl_ws_frame* meta = nullptr;
                CURLcode rc = curl_ws_recv(m_curl,
                                            buf.data(), buf.size(),
                                            &recvd, &meta);
                if (rc == CURLE_AGAIN) break;
                if (rc != CURLE_OK) {
                    LOGERR("WSession: recv error: "
                           << curl_easy_strerror(rc) << "\n");
                    m_stop = true;
                    break;
                }
                if (!meta) break;

                // CLOSE frame
                if (meta->flags & CURLWS_CLOSE) {
                    LOGDEB("WSession: server sent CLOSE\n");
                    m_stop = true;
                    break;
                }
                // PING → respond with PONG
                if (meta->flags & CURLWS_PING) {
                    std::lock_guard<std::mutex> lk(m_send_mutex);
                    size_t sent = 0;
                    curl_ws_send(m_curl, buf.data(), recvd, &sent, 0, CURLWS_PONG);
                    break;
                }

                frame.insert(frame.end(), buf.begin(), buf.begin() + recvd);
                complete = (meta->bytesleft == 0);
            }

            if (!frame.empty()) {
                std::vector<Message> msgs;
                if (parseFrame(frame, msgs)) {
                    for (auto& msg : msgs) dispatchMessage(msg);
                } else {
                    LOGDEB("WSession: failed to parse frame of "
                           << frame.size() << " bytes\n");
                }
            }
        } // if (r > 0)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - last_heartbeat).count() >= HEARTBEAT_INTERVAL_S) {
            sendHeartbeat();
            last_heartbeat = now;
        }
    }

    m_connected = false;
    if (m_cbs.on_disconnected) m_cbs.on_disconnected();
    LOGDEB("WSession: event loop exited\n");
}

// Dispatch a decoded inbound message to the appropriate callback.
// (Called from eventLoop() — executes in the WS thread.)
void WSession::dispatchMessage(const Message& msg) {
    switch (msg.type) {

    case MsgType::SRVRC_SESSION_STATE:
        LOGDEB("WSession: SessionState id=" << msg.session_state.session_id << "\n");
        m_session_uuid = msg.session_state.session_uuid;
        m_session_id   = msg.session_state.session_id;
        // Ask server to send current renderer state
        sendRaw(buildAskRendererState(nowMs(), nextBatchId(m_batch_id),
                                       m_session_id));
        if (m_cbs.on_connected) m_cbs.on_connected();
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

    case MsgType::CMD_SET_ACTIVE:
        LOGDEB("WSession: SetActive active=" << msg.set_active.active << "\n");
        m_is_active = msg.set_active.active;
        if (m_is_active) {
            // Activation handshake (matches qonductor order):
            // 1. VolumeMuted(false)  — field 29, must be sent even with empty body
            // 2. VolumeChanged       — field 25
            // 3. MaxAudioQualityChanged — field 28, value is quality level 1-4
            sendRaw(buildVolumeMuted(nowMs(), nextBatchId(m_batch_id), false));
            reportVolume(50);  // MPD volume will be reported accurately by MpdCtl later
            // Convert format_id to quality level: 27->4, 7->3, 6->2, 5->1
            int32_t ql = 4;
            if (m_devinfo.max_quality == 7) ql = 3;
            else if (m_devinfo.max_quality == 6) ql = 2;
            else if (m_devinfo.max_quality == 5) ql = 1;
            reportMaxQuality(ql);
            // Request current queue state from server
            if (!m_session_uuid.empty()) {
                sendRaw(buildAskQueueState(nowMs(), nextBatchId(m_batch_id),
                                            m_session_uuid));
            }
        }
        break;

    case MsgType::CMD_SET_STATE:
        LOGDEB("WSession: SetState state="
               << static_cast<int>(msg.set_state.playing_state)
               << " pos=" << msg.set_state.current_position_ms
               << " qitem=" << msg.set_state.current_queue_item.queue_item_id
               << "\n");
        // Only act on SetState when at least one field is actually present.
        // Responding to empty SetState creates a feedback loop with the server.
        // Use has_queue_item_id flag because 0 is a valid queue_item_id.
        if (msg.set_state.playing_state != PlayingState::UNKNOWN ||
            msg.set_state.current_position_ms != 0 ||
            msg.set_state.current_queue_item.has_queue_item_id) {
            if (m_cbs.on_set_state) {
                m_cbs.on_set_state(msg.set_state.playing_state,
                                    msg.set_state.current_position_ms,
                                    msg.set_state.has_position,
                                    msg.set_state.current_queue_item);
            }
            // Immediately acknowledge with a StateUpdated response
            QueueRendererState ack;
            {
                std::lock_guard<std::mutex> lk(m_state_mutex);
                ack = m_last_state;
            }
            if (msg.set_state.playing_state != PlayingState::UNKNOWN)
                ack.state.playing_state = msg.set_state.playing_state;
            if (msg.set_state.has_position) {
                ack.state.current_position_ms = msg.set_state.current_position_ms;
                ack.state.position_timestamp_ms = nowMs();
            }
            if (msg.set_state.current_queue_item.has_queue_item_id) {
                ack.state.current_queue_item_id = msg.set_state.current_queue_item.queue_item_id;
                ack.state.has_current_queue_item_id = true;
            }
            {
                std::lock_guard<std::mutex> lk(m_state_mutex);
                m_last_state = ack;
            }
            sendRaw(buildStateUpdated(nowMs(), nextBatchId(m_batch_id), ack));
        }
        break;

    case MsgType::CMD_SET_VOLUME:
        LOGDEB("WSession: SetVolume vol=" << msg.set_volume.volume
               << " delta=" << msg.set_volume.volume_delta << "\n");
        if (m_cbs.on_set_volume) {
            m_cbs.on_set_volume(msg.set_volume.volume,
                                 msg.set_volume.volume_delta);
        }
        break;

    case MsgType::SRVRC_QUEUE_STATE:
        LOGDEB("WSession: QueueState tracks="
               << msg.queue_state.tracks.size() << "\n");
        // Full queue snapshot: treat as load at position 0
        if (m_cbs.on_queue_load && !msg.queue_state.tracks.empty()) {
            m_cbs.on_queue_load(msg.queue_state.tracks, 0);
        }
        break;

    case MsgType::SRVRC_QUEUE_LOAD_TRACKS:
        LOGDEB("WSession: QueueLoadTracks tracks="
               << msg.queue_load_tracks.tracks.size()
               << " pos=" << msg.queue_load_tracks.queue_position << "\n");
        if (m_cbs.on_queue_load) {
            m_cbs.on_queue_load(
                msg.queue_load_tracks.tracks,
                msg.queue_load_tracks.queue_position);
        }
        break;

    case MsgType::SRVRC_TRACKS_INSERTED:
        if (m_cbs.on_tracks_inserted) {
            m_cbs.on_tracks_inserted(
                msg.tracks_inserted.tracks,
                msg.tracks_inserted.insert_after);
        }
        break;

    case MsgType::SRVRC_TRACKS_ADDED:
        if (m_cbs.on_tracks_added) {
            m_cbs.on_tracks_added(msg.tracks_added.tracks);
        }
        break;

    case MsgType::SRVRC_TRACKS_REMOVED:
        if (m_cbs.on_tracks_removed) {
            m_cbs.on_tracks_removed(msg.tracks_removed.queue_item_ids);
        }
        break;

    case MsgType::SRVRC_QUEUE_CLEARED:
        LOGDEB("WSession: QueueCleared\n");
        if (m_cbs.on_queue_load)
            m_cbs.on_queue_load({}, 0); // empty queue
        break;

    case MsgType::SRVRC_RENDERER_STATE_UPD:
        // Another renderer's state — ignore unless it's ours
        LOGDEB("WSession: RendererStateUpdated id="
               << msg.renderer_state_upd.renderer_id << "\n");
        break;

    default:
        LOGDEB("WSession: unhandled msg type "
               << static_cast<int>(msg.type) << "\n");
        break;
    }
}

} // namespace QConnect
