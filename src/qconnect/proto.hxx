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

// Hand-coded protobuf encoder/decoder for the Qobuz Connect protocol.
//
// Wire format (outer envelope):
//   [QCloudMessageType: 1 byte][payload_len: varint][proto_bytes]
//
// For EnvType::PAYLOAD, proto_bytes is a serialised Payload message whose
// payload_data field contains a serialised QConnectBatch. A QConnectBatch
// holds one or more QConnectMessage items. Each QConnectMessage is a oneof
// where the chosen field tag (21-105) identifies the inner message type.
//
// Protocol source: reverse-engineered from github.com/nickblt/qonductor
// Proto definitions: proto/qconnect_envelope.proto, qconnect_payload.proto,
//                    qconnect_common.proto, qconnect_queue.proto

#include <cstdint>
#include <string>
#include <vector>

namespace QConnect {

using Bytes = std::vector<uint8_t>;

// ---- Outer envelope type (QCloudMessageType) --------------------------------

enum class EnvType : uint8_t {
    AUTHENTICATE = 1,
    SUBSCRIBE    = 2,
    UNSUBSCRIBE  = 3,
    PAYLOAD      = 6,
    ERROR_MSG    = 9,
    DISCONNECT   = 10,
};

// QConnect protocol version carried in Subscribe.proto field
enum class QCloudProto : int32_t {
    QCONNECT  = 1,
    QCONNECT2 = 2,
    QCONNECT3 = 3,
};

// ---- Inner QConnect message type IDs ----------------------------------------
// These are ALSO the protobuf field tag numbers in QConnectMessage oneof.

enum class MsgType : int32_t {
    UNKNOWN = 0,
    ERROR = 1,
    PLAYBACK_ERROR = 2,
    // Renderer -> Server  (21-29) — verified against qonductor proto
    RNDR_JOIN_SESSION          = 21,
    RNDR_DEVICE_INFO_UPDATED   = 22,
    RNDR_STATE_UPDATED         = 23,
    RNDR_ACTION                = 24,
    RNDR_VOLUME_CHANGED        = 25,
    RNDR_FILE_QUALITY          = 26,   // RndrSrvrFileAudioQualityChanged
    RNDR_DEVICE_QUALITY        = 27,   // RndrSrvrDeviceAudioQualityChanged
    RNDR_MAX_QUALITY           = 28,   // RndrSrvrMaxAudioQualityChanged (was 29)
    RNDR_VOLUME_MUTED          = 29,   // RndrSrvrVolumeMuted            (was 26)
    // Server -> Renderer  (41-47)
    CMD_SET_STATE              = 41,
    CMD_SET_VOLUME             = 42,
    CMD_SET_ACTIVE             = 43,
    CMD_SET_MAX_QUALITY        = 44,
    CMD_SET_LOOP_MODE          = 45,
    CMD_SET_SHUFFLE_MODE       = 46,
    CMD_MUTE_VOLUME            = 47,
    // Controller -> Server  (61-80) — verified against qonductor proto
    CTRL_JOIN_SESSION          = 61,
    CTRL_SET_PLAYER_STATE      = 62,
    CTRL_SET_ACTIVE_RENDERER   = 63,
    CTRL_SET_VOLUME            = 64,
    CTRL_CLEAR_QUEUE           = 65,   // CtrlSrvrClearQueue (was CTRL_MUTE_VOLUME)
    CTRL_LOAD_TRACKS           = 66,
    CTRL_INSERT_TRACKS         = 67,
    CTRL_ADD_TRACKS            = 68,
    CTRL_REMOVE_TRACKS         = 69,
    CTRL_REORDER_TRACKS        = 70,
    CTRL_SET_SHUFFLE_MODE      = 71,
    CTRL_SET_LOOP_MODE         = 72,
    CTRL_MUTE_VOLUME           = 73,   // CtrlSrvrMuteVolume (was CTRL_SET_MAX_QUALITY)
    CTRL_SET_MAX_QUALITY       = 74,   // (was CTRL_ASK_QUEUE_STATE)
    CTRL_SET_QUEUE_STATE       = 75,
    CTRL_ASK_QUEUE_STATE       = 76,   // (was 74)
    CTRL_ASK_RENDERER_STATE    = 77,   // (was 75)
    CTRL_SET_AUTOPLAY_MODE     = 78,   // (was 76)
    // Server -> Controller  (81-105) — verified against qonductor proto
    SRVRC_SESSION_STATE        = 81,
    SRVRC_RENDERER_STATE_UPD   = 82,
    SRVRC_ADD_RENDERER         = 83,
    SRVRC_UPDATE_RENDERER      = 84,
    SRVRC_REMOVE_RENDERER      = 85,
    SRVRC_ACTIVE_RNDR_CHANGED  = 86,
    SRVRC_VOLUME_CHANGED       = 87,
    SRVRC_QUEUE_ERROR          = 88,   // SrvrCtrlQueueErrorMessage (was SRVRC_VOLUME_MUTED)
    SRVRC_QUEUE_CLEARED        = 89,   // SrvrCtrlQueueCleared      (was 95)
    SRVRC_QUEUE_STATE          = 90,
    SRVRC_QUEUE_LOAD_TRACKS    = 91,   // SrvrCtrlQueueTracksLoaded (was 96)
    SRVRC_TRACKS_INSERTED      = 92,   // SrvrCtrlQueueTracksInserted (was 91)
    SRVRC_TRACKS_ADDED         = 93,   // SrvrCtrlQueueTracksAdded    (was 92)
    SRVRC_TRACKS_REMOVED       = 94,   // SrvrCtrlQueueTracksRemoved  (was 93)
    SRVRC_TRACKS_REORDERED     = 95,   // SrvrCtrlQueueTracksReordered (was 94)
    SRVRC_SHUFFLE_MODE_SET     = 96,   // (was SRVRC_QUEUE_LOAD_TRACKS=96)
    SRVRC_LOOP_MODE_SET        = 97,
    SRVRC_SRVRC_VOLUME_MUTED   = 98,   // Server→Controller volume muted notification
    SRVRC_MAX_QUALITY_CHANGED  = 99,
    SRVRC_FILE_QUALITY_CHANGED = 100,
    SRVRC_DEVICE_QUALITY_CHANGED = 101,
    SRVRC_AUTOPLAY_MODE_SET    = 102,
    SRVRC_AUTOPLAY_TRACKS_LOADED = 103,
    SRVRC_AUTOPLAY_TRACKS_REMOVED = 104,
    SRVRC_TRACKS_ADDED_FROM_AUTOPLAY = 105,
};

// ---- Common enums and structs ------------------------------------------------

enum class PlayingState : int32_t {
    UNKNOWN = 0,
    STOPPED = 1,
    PLAYING = 2,
    PAUSED  = 3,
};

enum class BufferState : int32_t {
    UNKNOWN   = 0,
    BUFFERING = 1,
    OK        = 2,
    ERROR_ST  = 3,
    UNDERRUN  = 4,
};

enum class LoopMode : int32_t {
    UNKNOWN    = 0,
    OFF        = 1,
    REPEAT_ONE = 2,
    REPEAT_ALL = 3,
};

// Format IDs: same as qobuzformatid config key
// MP3=5, FLAC=6, HiRes-96k=7, HiRes-192k=27
// Mapped to QConnect quality levels:
//   5  -> MP3      (Authenticate/max_quality value 1 or similar - TBD)
//   6  -> LOSSLESS (quality level 2)
//   7  -> HIRES_L2 (quality level 3)
//   27 -> HIRES_L3 (quality level 4)

struct QueueVersion {
    uint64_t major{0};
    int32_t  minor{0};
    bool     present{false};
};

struct QueueTrackRef {
    uint64_t queue_item_id{0};
    uint32_t track_id{0};
    Bytes    context_uuid; // 16-byte UUID
    bool     has_queue_item_id{false}; // presence flag (0 is a valid ID)
};

struct RendererState {
    PlayingState playing_state{PlayingState::UNKNOWN};
    BufferState  buffer_state{BufferState::UNKNOWN};
    uint32_t     current_position_ms{0};
    uint64_t     position_timestamp_ms{0}; // epoch ms when position was sampled
    uint32_t     duration_ms{0};
    uint32_t     current_queue_index{0};
    uint64_t     current_queue_item_id{0};
    uint64_t     next_queue_item_id{0};
    bool         has_current_queue_index{false};
    bool         has_position{false};              // position message present (0 is valid)
    bool         has_current_queue_item_id{false}; // presence flag (0 is valid)
    bool         has_next_queue_item_id{false};    // presence flag (0 is valid)
};

struct QueueRendererState {
    QueueVersion  queue_version;
    RendererState state;
};

struct DeviceInfo {
    Bytes       uuid;            // 16 bytes raw
    std::string friendly_name;
    std::string brand{"UpMpd"};
    std::string model;
    std::string serial;
    int32_t     type{1};         // DeviceType: 1=SPEAKER
    int32_t     max_quality{27}; // format id
    std::string software_version{"1.0"};
};

// ---- Decoded inbound messages ------------------------------------------------

struct MsgSetState {
    PlayingState  playing_state{PlayingState::UNKNOWN};
    uint32_t      current_position_ms{0};
    bool          has_position{false}; // presence flag (0 = seek to start)
    QueueVersion  queue_version;
    QueueTrackRef current_queue_item;
    QueueTrackRef next_queue_item;
};

struct MsgSetActive {
    bool active{false};
};

struct MsgSetVolume {
    uint32_t volume{0};
    int32_t  volume_delta{0};   // relative adjustment; 0 if absolute
};

struct MsgMuteVolume {
    bool muted{false};
    bool has_muted{false};
};

struct MsgSessionState {
    Bytes        session_uuid;  // 16 bytes
    // Field 2. qonductor calls this session_id, qbz calls it
    // active_renderer_id; a capture shows the server sending 0xFFFF...FF (the
    // -1 sentinel) when no renderer is active. We only ever echo it back in
    // CtrlSrvrAskForRendererState, which the server accepts, so the naming
    // does not matter to us.
    uint64_t     session_id{0};
    QueueVersion queue_version;
    // Field 4. Previously decoded as a queue start index. It is not one:
    // qonductor's ws-session-debug-while-playing capture carries field4=3 in
    // the same exchange where the renderer reports current_queue_index=1 and
    // playing_state=Paused (PLAYING_STATE_PAUSED == 3). qbz reads it as
    // playing_state; LOOP_MODE_REPEAT_ALL is also 3, so one capture cannot
    // separate those two readings. Decoded for logging only — never use it to
    // position playback until its meaning is settled.
    uint32_t     field4{0};
    bool         has_field4{false};
};

struct MsgRendererStateUpdated {
    uint64_t     renderer_id{0};
    uint64_t     message_id{0};
    RendererState state;
};

struct MsgAddRenderer {
    uint64_t  renderer_id{0};
    DeviceInfo renderer;
};

struct MsgRemoveRenderer {
    uint64_t renderer_id{0};
};

struct MsgActiveRendererChanged {
    uint64_t renderer_id{0};
};

struct QueueTrack {
    uint64_t queue_item_id{0};
    uint32_t track_id{0};
    Bytes    context_uuid;
};

struct MsgQueueState {
    QueueVersion           queue_version;
    std::vector<QueueTrack> tracks;
    std::vector<QueueTrack> autoplay_tracks;
    std::vector<uint32_t>  shuffled_track_indexes;
    bool                   shuffle_on{false};
    bool                   has_shuffle_on{false};
    bool                   autoplay_on{false};
    bool                   has_autoplay_on{false};
    bool                   autoplay_loading{false};
    bool                   has_autoplay_loading{false};
};

struct MsgQueueLoadTracks {
    QueueVersion            queue_version;
    std::vector<QueueTrack> tracks;
    uint32_t                queue_position{0};
    bool                    has_queue_position{false};
    int32_t                 shuffle_pivot_queue_item_id{0};
    bool                    has_shuffle_pivot_queue_item_id{false};
    bool                    shuffle_on{false};
    bool                    has_shuffle_on{false};
};

struct MsgQueueTracksInserted {
    QueueVersion            queue_version;
    std::vector<QueueTrack> tracks;
    int32_t                 insert_after{0};
    bool                    has_insert_after{false};
};

struct MsgQueueTracksAdded {
    QueueVersion            queue_version;
    std::vector<QueueTrack> tracks;
};

struct MsgQueueTracksRemoved {
    QueueVersion           queue_version;
    std::vector<uint64_t>  queue_item_ids;
};

struct MsgQueueTracksReordered {
    QueueVersion          queue_version;
    std::vector<uint64_t> queue_item_ids;
    uint64_t              insert_after{0};
    bool                  has_insert_after{false};
};

struct MsgQueueCleared {
    QueueVersion queue_version;
};

struct MsgShuffleMode {
    QueueVersion queue_version;
    bool         shuffle_on{false};
    bool         has_shuffle_on{false};
    uint32_t     current_queue_item_id{0};
    bool         has_current_queue_item_id{false};
    uint32_t     shuffle_pivot{0};
    bool         has_shuffle_pivot{false};
};

struct MsgLoopMode {
    LoopMode mode{LoopMode::UNKNOWN};
    bool     has_mode{false};
};

struct MsgError {
    std::string code;
    std::string message;
};

struct MsgPlaybackError {
    QueueVersion queue_version;
    int32_t      queue_item_id{0};
    int32_t      error_type{0};
    bool         has_queue_item_id{false};
    bool         has_error_type{false};
};

struct MsgQueueError {
    QueueVersion queue_version;
    Bytes        action_uuid;
    MsgError     error;
};

struct MsgAutoplayMode {
    QueueVersion queue_version;
    bool autoplay_on{false};
    bool has_autoplay_on{false};
    bool autoplay_reset{false};
    bool has_autoplay_reset{false};
    bool autoplay_loading{false};
    bool has_autoplay_loading{false};
};

struct MsgAutoplayTracksLoaded {
    QueueVersion            queue_version;
    std::vector<QueueTrack> tracks;
};

struct MsgTracksAddedFromAutoplay {
    QueueVersion          queue_version;
    std::vector<uint64_t> queue_item_ids;
};

// All parsed inbound data in one union-like struct.
// Only the field matching .type is populated.
struct Message {
    MsgType                type{MsgType::UNKNOWN};
    MsgError               error;
    MsgPlaybackError       playback_error;
    MsgSetState            set_state;
    MsgSetActive           set_active;
    MsgSetVolume           set_volume;
    MsgMuteVolume          mute_volume;
    MsgShuffleMode         shuffle_mode;
    MsgLoopMode            loop_mode;
    MsgSessionState        session_state;
    MsgRendererStateUpdated renderer_state_upd;
    MsgAddRenderer         add_renderer;
    MsgRemoveRenderer      remove_renderer;
    MsgActiveRendererChanged active_renderer_changed;
    MsgQueueState          queue_state;
    MsgQueueCleared        queue_cleared;
    MsgQueueLoadTracks     queue_load_tracks;
    MsgQueueTracksInserted tracks_inserted;
    MsgQueueTracksAdded    tracks_added;
    MsgQueueTracksRemoved  tracks_removed;
    MsgQueueTracksReordered tracks_reordered;
    MsgTracksAddedFromAutoplay tracks_added_from_autoplay;
    MsgQueueError          queue_error;
    MsgAutoplayMode        autoplay_mode;
    MsgAutoplayTracksLoaded autoplay_tracks_loaded;
};

struct QwsError {
    uint32_t    msg_id{0};
    uint32_t    code{0};
    std::string description;
    bool        present{false};
};

struct QwsDisconnect {
    uint32_t msg_id{0};
    bool     reconnect{false};
    bool     has_reconnect{false};
    bool     present{false};
};

// ---- Encoder API ------------------------------------------------------------

// Build envelope frame: [type_byte][varint_len][proto_bytes]
Bytes buildEnvelope(EnvType type, const Bytes& payload);

// Authentication (sent once after WebSocket connect):
//   buildAuthenticate(unique_id, now_ms(), jwt_qconnect_token)
Bytes buildAuthenticate(uint64_t msg_id, uint64_t msg_date_ms,
                        const std::string& jwt);

// Subscribe to QConnect channel (sent after authentication):
Bytes buildSubscribe(uint64_t msg_id, uint64_t msg_date_ms,
                     QCloudProto proto = QCloudProto::QCONNECT);

// QConnect batch messages (all wrapped in PAYLOAD envelope):
// Send immediately after SUBSCRIBE to register the device with the cloud.
// The server responds with SessionState (81) and AddRenderer (83).
Bytes buildCtrlJoinSession(uint64_t time_ms, int32_t batch_id,
                             const DeviceInfo& dev);

Bytes buildJoinSession(uint64_t time_ms, int32_t batch_id,
                       const Bytes& session_uuid,
                       const DeviceInfo& dev, int32_t reason, bool is_active,
                       const QueueRendererState& state);

Bytes buildStateUpdated(uint64_t time_ms, int32_t batch_id,
                        const QueueRendererState& state);

Bytes buildVolumeChanged(uint64_t time_ms, int32_t batch_id,
                         uint32_t volume);

Bytes buildMaxQualityChanged(uint64_t time_ms, int32_t batch_id,
                              int32_t quality);

// Tell server we want renderer_id to be the active renderer:
Bytes buildSetActiveRenderer(uint64_t time_ms, int32_t batch_id,
                              int32_t renderer_id);

// Ask server to send current renderer state:
Bytes buildAskRendererState(uint64_t time_ms, int32_t batch_id,
                             uint64_t session_id);

// Report that this renderer is muted (or not):
Bytes buildVolumeMuted(uint64_t time_ms, int32_t batch_id, bool muted);

// Report actual file audio quality (sample rate in Hz):
Bytes buildFileAudioQualityChanged(uint64_t time_ms, int32_t batch_id,
                                    int32_t sample_rate_hz);

// Ask server to send current queue state (sent after activation):
Bytes buildAskQueueState(uint64_t time_ms, int32_t batch_id,
                          const Bytes& queue_uuid);

// ---- Decoder API ------------------------------------------------------------

// Parse one WebSocket binary message (envelope + payload).
// Returns false if data is malformed or type is unrecognised.
// msgs is appended to (not cleared) so callers may process incrementally.
bool parseFrame(const uint8_t* data, size_t len, std::vector<Message>& msgs,
                uint64_t* payload_msg_date_ms = nullptr,
                QwsError* qws_error = nullptr,
                QwsDisconnect* qws_disconnect = nullptr);

// Convenience overload for Bytes
inline bool parseFrame(const Bytes& data, std::vector<Message>& msgs,
                       uint64_t* payload_msg_date_ms = nullptr,
                       QwsError* qws_error = nullptr,
                       QwsDisconnect* qws_disconnect = nullptr) {
    return parseFrame(data.data(), data.size(), msgs, payload_msg_date_ms,
                      qws_error, qws_disconnect);
}

} // namespace QConnect
