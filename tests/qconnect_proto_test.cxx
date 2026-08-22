#include "proto.hxx"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace QConnect;

namespace {

struct Span {
    const uint8_t* data{nullptr};
    size_t size{0};
};

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Bytes fromHex(const char* text) {
    Bytes out;
    std::string hex(text);
    check(hex.size() % 2 == 0, "odd fixture hex length");
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

void appendVarint(Bytes& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void appendVarintField(Bytes& out, int field, uint64_t value) {
    appendVarint(out, static_cast<uint64_t>(field) << 3);
    appendVarint(out, value);
}

void appendLengthField(Bytes& out, int field, const Bytes& value) {
    appendVarint(out, (static_cast<uint64_t>(field) << 3) | 2);
    appendVarint(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

Bytes payloadFrame(const Bytes& qconnect_message) {
    Bytes batch;
    appendLengthField(batch, 3, qconnect_message);
    Bytes payload;
    appendVarintField(payload, 3, 1);
    appendLengthField(payload, 7, batch);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

bool readVarint(Span input, size_t& position, uint64_t& value) {
    value = 0;
    unsigned shift = 0;
    while (position < input.size && shift < 64) {
        uint8_t byte = input.data[position++];
        value |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if (!(byte & 0x80)) return true;
        shift += 7;
    }
    return false;
}

struct WireField {
    int number{0};
    uint8_t type{0};
    uint64_t value{0};
    Span bytes;
};

bool nextField(Span input, size_t& position, WireField& field) {
    uint64_t tag = 0;
    if (!readVarint(input, position, tag)) return false;
    field = WireField{};
    field.number = static_cast<int>(tag >> 3);
    field.type = static_cast<uint8_t>(tag & 7);
    if (field.type == 0) return readVarint(input, position, field.value);
    if (field.type == 1) {
        if (position + 8 > input.size) return false;
        field.bytes = {input.data + position, 8};
        position += 8;
        return true;
    }
    if (field.type == 2) {
        uint64_t length = 0;
        if (!readVarint(input, position, length) ||
            length > input.size - position) return false;
        field.bytes = {input.data + position, static_cast<size_t>(length)};
        position += static_cast<size_t>(length);
        return true;
    }
    if (field.type == 5) {
        if (position + 4 > input.size) return false;
        field.bytes = {input.data + position, 4};
        position += 4;
        return true;
    }
    return false;
}

bool findLengthField(Span input, int number, Span& result) {
    size_t position = 0;
    WireField field;
    while (position < input.size && nextField(input, position, field)) {
        if (field.number == number && field.type == 2) {
            result = field.bytes;
            return true;
        }
    }
    return false;
}

bool findVarintField(Span input, int number, uint64_t& result) {
    size_t position = 0;
    WireField field;
    while (position < input.size && nextField(input, position, field)) {
        if (field.number == number && field.type == 0) {
            result = field.value;
            return true;
        }
    }
    return false;
}

Span envelopePayload(const Bytes& frame) {
    check(frame.size() >= 2 && frame[0] == 6, "not a payload envelope");
    Span all{frame.data(), frame.size()};
    size_t position = 1;
    uint64_t length = 0;
    check(readVarint(all, position, length), "invalid envelope length");
    check(length == frame.size() - position, "envelope length mismatch");
    return {frame.data() + position, static_cast<size_t>(length)};
}

const Message& parseOne(const char* fixture, std::vector<Message>& messages) {
    Bytes frame = fromHex(fixture);
    check(parseFrame(frame, messages), "fixture did not parse");
    check(messages.size() == 1, "fixture did not yield one message");
    return messages.front();
}

// These frames were serialized from qonductor's current proto2 definitions.
constexpr const char* SET_STATE_ZERO =
    "0632080110d20918013a2909d20400000000000010071a1c0829ca021708031000"
    "1a040800100022070800157b0000002a020800";
constexpr const char* QUEUE_LOAD_SIGNED =
    "0642080110d20918013a3909d20400000000000010071a2c085bda05270a0d0807"
    "10feffffffffffffffff011a07080015c8010000200030ffffffffffffffffff013800";
constexpr const char* QUEUE_STATE_SHUFFLE_ZERO =
    "0627080110d20918013a1e09d20400000000000010071a11085ad2050c0a020808"
    "1a02080020002800";
constexpr const char* QUEUE_REORDERED_ZERO =
    "0629080110d20918013a2009d20400000000000010071a13085ffa050e0a020809"
    "180018ffffffff0f2000";
constexpr const char* RESTORE_ZERO =
    "0632080110d20918013a2909d20400000000000010071a1c085292051708631a13"
    "08021a0b09e803000000000000100028003800";
constexpr const char* QUEUE_INSERT_BEFORE_ZERO =
    "062e080110d20918013a2509d20400000000000010071a18085ce205130a02080a"
    "1a02080020ffffffffffffffffff01";
constexpr const char* QUEUE_CLEARED =
    "061f080110d20918013a1609d20400000000000010071a090859ca05040a02080b";
constexpr const char* TRACKS_ADDED_FROM_AUTOPLAY =
    "0621080110d20918013a1809d20400000000000010071a0b0869ca06060a04080c1002";
constexpr const char* SHUFFLE_ZERO =
    "0628080110d20918013a1f09d20400000000000010071a12086082060d0a02080d"
    "180025000000002800";

void testGeneratedFixtures() {
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(SET_STATE_ZERO, messages);
        check(msg.type == MsgType::CMD_SET_STATE, "wrong SetState type");
        check(msg.set_state.has_position &&
              msg.set_state.current_position_ms == 0, "seek zero lost");
        check(msg.set_state.queue_version.present, "zero queue version lost");
        check(msg.set_state.current_queue_item.has_queue_item_id &&
              msg.set_state.current_queue_item.queue_item_id == 0,
              "current qid zero lost");
        check(msg.set_state.next_queue_item.has_queue_item_id &&
              msg.set_state.next_queue_item.queue_item_id == 0,
              "next qid zero lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(QUEUE_LOAD_SIGNED, messages);
        const auto& load = msg.queue_load_tracks;
        check(msg.type == MsgType::SRVRC_QUEUE_LOAD_TRACKS,
              "wrong queue-load type");
        check(load.queue_version.present && load.queue_version.major == 7 &&
              load.queue_version.minor == -2, "signed queue version lost");
        check(load.has_queue_position && load.queue_position == 0,
              "queue position zero lost");
        check(load.has_shuffle_pivot_queue_item_id &&
              load.shuffle_pivot_queue_item_id == -1, "shuffle pivot lost");
        check(load.has_shuffle_on && !load.shuffle_on, "shuffle false lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(QUEUE_STATE_SHUFFLE_ZERO, messages);
        check(msg.type == MsgType::SRVRC_QUEUE_STATE,
              "wrong queue-state type");
        check(msg.queue_state.has_shuffle_on && !msg.queue_state.shuffle_on,
              "queue-state shuffle false lost");
        check(msg.queue_state.shuffled_track_indexes == std::vector<uint32_t>{0},
              "packed shuffled index zero lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(QUEUE_REORDERED_ZERO, messages);
        check(msg.type == MsgType::SRVRC_TRACKS_REORDERED,
              "wrong reorder type");
        check(msg.tracks_reordered.queue_item_ids ==
                  std::vector<uint64_t>({0, UINT32_MAX}),
              "reordered qids lost");
        check(msg.tracks_reordered.has_insert_after &&
              msg.tracks_reordered.insert_after == 0,
              "reorder anchor zero lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(RESTORE_ZERO, messages);
        const auto& state = msg.renderer_state_upd.state;
        check(msg.type == MsgType::SRVRC_RENDERER_STATE_UPD,
              "wrong renderer-state type");
        check(state.has_current_queue_index && state.current_queue_index == 0,
              "restore index zero lost");
        check(state.has_next_queue_item_id && state.next_queue_item_id == 0,
              "restore next qid zero lost");
        check(state.has_position && state.current_position_ms == 0,
              "restore position zero lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(QUEUE_INSERT_BEFORE_ZERO, messages);
        check(msg.type == MsgType::SRVRC_TRACKS_INSERTED,
              "wrong insert type");
        check(msg.tracks_inserted.has_insert_after &&
              msg.tracks_inserted.insert_after == -1,
              "signed insert-before sentinel lost");
    }
    {
        std::vector<Message> messages;
        check(parseOne(QUEUE_CLEARED, messages).type ==
                  MsgType::SRVRC_QUEUE_CLEARED,
              "queue-cleared id is not 89");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(TRACKS_ADDED_FROM_AUTOPLAY, messages);
        check(msg.type == MsgType::SRVRC_TRACKS_ADDED_FROM_AUTOPLAY,
              "tracks-added-from-autoplay id is not 105");
        check(msg.tracks_added_from_autoplay.queue_version.major == 12,
              "tracks-added-from-autoplay version lost");
    }
    {
        std::vector<Message> messages;
        const auto& msg = parseOne(SHUFFLE_ZERO, messages);
        check(msg.type == MsgType::SRVRC_SHUFFLE_MODE_SET,
              "wrong shuffle-event type");
        check(msg.shuffle_mode.has_shuffle_on && !msg.shuffle_mode.shuffle_on,
              "shuffle event false lost");
        check(msg.shuffle_mode.has_current_queue_item_id &&
              msg.shuffle_mode.current_queue_item_id == 0,
              "shuffle current qid zero lost");
        check(msg.shuffle_mode.has_shuffle_pivot &&
              msg.shuffle_mode.shuffle_pivot == 0,
              "shuffle pivot zero lost");
    }
}

void testOutboundPresence() {
    QueueRendererState state;
    state.queue_version.present = true;
    state.state.playing_state = PlayingState::PAUSED;
    state.state.buffer_state = BufferState::BUFFERING;
    state.state.has_position = true;
    state.state.position_timestamp_ms = 1000;
    state.state.has_current_queue_item_id = true;
    state.state.has_next_queue_item_id = true;

    Bytes frame = buildStateUpdated(1000, 1, state);
    Span payload = envelopePayload(frame);
    Span batch, qconnect_message, state_updated, renderer_state, position;
    check(findLengthField(payload, 7, batch), "missing batch");
    check(findLengthField(batch, 3, qconnect_message), "missing message");
    uint64_t type = 0;
    check(findVarintField(qconnect_message, 1, type) && type == 23,
          "wrong outbound state message type");
    check(findLengthField(qconnect_message, 23, state_updated),
          "missing outbound state body");
    check(findLengthField(state_updated, 1, renderer_state),
          "missing queue renderer state");
    Span queue_version;
    check(findLengthField(renderer_state, 5, queue_version),
          "zero queue version presence lost");
    uint64_t value = 1;
    check(findVarintField(renderer_state, 6, value) && value == 0,
          "outbound current qid zero lost");
    check(findVarintField(renderer_state, 7, value) && value == 0,
          "outbound next qid zero lost");
    check(findLengthField(renderer_state, 3, position),
          "outbound position missing");
    check(findVarintField(position, 2, value) && value == 0,
          "outbound position zero lost");
}

void testRendererReconnectJoin() {
    DeviceInfo device;
    device.uuid = Bytes(16, 1);
    QueueRendererState state;
    state.state.playing_state = PlayingState::PLAYING;
    Bytes frame = buildJoinSession(1000, 1, Bytes(16, 2), device,
                                   2, true, state);
    Span payload = envelopePayload(frame);
    Span batch, qconnect_message, join;
    check(findLengthField(payload, 7, batch), "missing reconnect batch");
    check(findLengthField(batch, 3, qconnect_message),
          "missing reconnect message");
    check(findLengthField(qconnect_message, 21, join),
          "missing renderer join body");
    uint64_t value = 0;
    check(findVarintField(join, 3, value) && value == 2,
          "renderer reconnect reason missing");
    check(findVarintField(join, 5, value) && value == 1,
          "renderer reconnect active flag missing");
}

void testQwsErrorFrame() {
    Bytes payload;
    appendVarintField(payload, 1, 7);
    appendVarintField(payload, 2, 9);
    appendVarintField(payload, 3, 42);
    appendLengthField(payload, 4, Bytes{'r', 'e', 'j', 'e', 'c', 't'});
    Bytes frame = buildEnvelope(EnvType::ERROR_MSG, payload);
    std::vector<Message> messages;
    QwsError error;
    check(parseFrame(frame, messages, nullptr, &error),
          "QWS error frame did not parse");
    check(error.present && error.msg_id == 7 && error.code == 42,
          "QWS error scalar fields lost");
    check(error.description == "reject", "QWS error description lost");
    Bytes disconnect_payload;
    appendVarintField(disconnect_payload, 1, 8);
    appendVarintField(disconnect_payload, 2, 10);
    appendVarintField(disconnect_payload, 3, 1);
    Bytes disconnect_frame =
        buildEnvelope(EnvType::DISCONNECT, disconnect_payload);
    QwsDisconnect disconnect;
    check(parseFrame(disconnect_frame, messages, nullptr, nullptr,
                     &disconnect),
          "QWS disconnect frame did not parse");
    check(disconnect.present && disconnect.msg_id == 8 &&
              disconnect.has_reconnect && disconnect.reconnect,
          "QWS disconnect fields lost");
}

void testPlaybackErrorAndAutoplayQueue() {
    Bytes queue_version;
    appendVarintField(queue_version, 1, 2);
    Bytes playback_error;
    appendLengthField(playback_error, 1, queue_version);
    appendVarintField(playback_error, 2, 55);
    appendVarintField(playback_error, 3, 2);
    Bytes playback_message;
    appendVarintField(playback_message, 1, 2);
    appendLengthField(playback_message, 3, playback_error);
    std::vector<Message> messages;
    check(parseFrame(payloadFrame(playback_message), messages),
          "playback error frame did not parse");
    check(messages.size() == 1 && messages[0].type == MsgType::PLAYBACK_ERROR,
          "playback error message missing");
    check(messages[0].playback_error.queue_item_id == 55 &&
          messages[0].playback_error.error_type == 2,
          "playback error payload lost");

    Bytes qconnect_error;
    appendLengthField(qconnect_error, 1, Bytes{'E', '1'});
    appendLengthField(qconnect_error, 2, Bytes{'b', 'a', 'd'});
    Bytes error_message;
    appendVarintField(error_message, 1, 1);
    appendLengthField(error_message, 2, qconnect_error);
    messages.clear();
    check(parseFrame(payloadFrame(error_message), messages),
          "QConnect error frame did not parse");
    check(messages.size() == 1 && messages[0].type == MsgType::ERROR,
          "QConnect error message missing");
    check(messages[0].error.code == "E1" &&
              messages[0].error.message == "bad",
          "QConnect error payload lost");

    Bytes mute;
    appendVarintField(mute, 1, 1);
    Bytes mute_message;
    appendVarintField(mute_message, 1, 47);
    appendLengthField(mute_message, 47, mute);
    messages.clear();
    check(parseFrame(payloadFrame(mute_message), messages),
          "mute-volume frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::CMD_MUTE_VOLUME &&
              messages[0].mute_volume.has_muted &&
              messages[0].mute_volume.muted,
          "fresh command-47 mute payload lost");

    // Unmute travels as an empty body (None = not muted), and must still be
    // reported as a present command so the renderer restores the volume.
    Bytes unmute_message;
    appendVarintField(unmute_message, 1, 47);
    appendLengthField(unmute_message, 47, Bytes{});
    messages.clear();
    check(parseFrame(payloadFrame(unmute_message), messages),
          "unmute-volume frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::CMD_MUTE_VOLUME &&
              messages[0].mute_volume.has_muted &&
              !messages[0].mute_volume.muted,
          "empty command-47 body did not decode as unmute");

    // SrvrRndrSetShuffleMode (46) carries one optional bool. Shuffle-on sets
    // it explicitly; shuffle-off arrives as an empty body and must still be
    // decoded as a present "off" so the renderer stops tracking shuffle.
    Bytes shuffle_on_body;
    appendVarintField(shuffle_on_body, 1, 1);
    Bytes shuffle_on_message;
    appendVarintField(shuffle_on_message, 1, 46);
    appendLengthField(shuffle_on_message, 46, shuffle_on_body);
    messages.clear();
    check(parseFrame(payloadFrame(shuffle_on_message), messages),
          "set-shuffle-mode frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::CMD_SET_SHUFFLE_MODE &&
              messages[0].shuffle_mode.has_shuffle_on &&
              messages[0].shuffle_mode.shuffle_on,
          "command-46 shuffle-on payload lost");

    Bytes shuffle_off_message;
    appendVarintField(shuffle_off_message, 1, 46);
    appendLengthField(shuffle_off_message, 46, Bytes{});
    messages.clear();
    check(parseFrame(payloadFrame(shuffle_off_message), messages),
          "set-shuffle-mode off frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::CMD_SET_SHUFFLE_MODE &&
              messages[0].shuffle_mode.has_shuffle_on &&
              !messages[0].shuffle_mode.shuffle_on,
          "empty command-46 body did not decode as shuffle off");

    // SrvrCtrlShuffleModeSet (96) is a multi-purpose broadcast: it also
    // carries queue and autoplay fields, so a body without a shuffle field
    // must stay "no opinion" rather than defaulting to off.
    Bytes shuffle_set_body;
    appendVarintField(shuffle_set_body, 6, 1); // autoplay_mode only
    Bytes shuffle_set_message;
    appendVarintField(shuffle_set_message, 1, 96);
    appendLengthField(shuffle_set_message, 96, shuffle_set_body);
    messages.clear();
    check(parseFrame(payloadFrame(shuffle_set_message), messages),
          "shuffle-mode-set frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::SRVRC_SHUFFLE_MODE_SET &&
              !messages[0].shuffle_mode.has_shuffle_on,
          "message-96 without a shuffle field must not imply shuffle off");

    Bytes main_track;
    appendVarintField(main_track, 1, 10);
    Bytes autoplay_track;
    appendVarintField(autoplay_track, 1, 20);
    Bytes queue_state;
    appendLengthField(queue_state, 3, main_track);
    appendVarintField(queue_state, 6, 1);
    appendLengthField(queue_state, 8, autoplay_track);
    Bytes queue_message;
    appendVarintField(queue_message, 1, 90);
    appendLengthField(queue_message, 90, queue_state);
    messages.clear();
    check(parseFrame(payloadFrame(queue_message), messages),
          "autoplay queue frame did not parse");
    check(messages.size() == 1 && messages[0].queue_state.tracks.size() == 1 &&
          messages[0].queue_state.autoplay_tracks.size() == 1,
          "autoplay queue tracks lost");
    check(messages[0].queue_state.has_autoplay_on &&
          messages[0].queue_state.autoplay_on,
          "autoplay mode lost from queue state");

    Bytes autoplay_mode;
    appendLengthField(autoplay_mode, 1, queue_version);
    appendVarintField(autoplay_mode, 3, 1);
    appendVarintField(autoplay_mode, 4, 1);
    appendVarintField(autoplay_mode, 5, 0);
    Bytes autoplay_mode_message;
    appendVarintField(autoplay_mode_message, 1, 102);
    appendLengthField(autoplay_mode_message, 102, autoplay_mode);
    messages.clear();
    check(parseFrame(payloadFrame(autoplay_mode_message), messages),
          "autoplay-mode-set frame did not parse");
    check(messages.size() == 1 && messages[0].autoplay_mode.has_autoplay_on &&
              messages[0].autoplay_mode.autoplay_on,
          "new autoplay-mode-set layout lost");
    check(messages[0].autoplay_mode.has_autoplay_reset &&
              messages[0].autoplay_mode.autoplay_reset,
          "autoplay reset flag lost");
    Bytes promoted;
    appendLengthField(promoted, 1, queue_version);
    appendVarintField(promoted, 2, 20);
    appendVarintField(promoted, 2, 21);
    Bytes promoted_message;
    appendVarintField(promoted_message, 1, 105);
    appendLengthField(promoted_message, 105, promoted);
    messages.clear();
    check(parseFrame(payloadFrame(promoted_message), messages),
          "tracks-added-from-autoplay frame did not parse");
    check(messages.size() == 1 &&
              messages[0].type == MsgType::SRVRC_TRACKS_ADDED_FROM_AUTOPLAY,
          "tracks-added-from-autoplay message missing");
    check(messages[0].tracks_added_from_autoplay.queue_item_ids ==
              std::vector<uint64_t>({20, 21}),
          "tracks-added-from-autoplay IDs lost");
}

uint64_t payloadMessageId(const Bytes& frame) {
    Span payload = envelopePayload(frame);
    uint64_t id = 0;
    check(findVarintField(payload, 1, id), "payload message id missing");
    return id;
}

void testConcurrentMessageIds() {
    constexpr int THREADS = 8;
    constexpr int PER_THREAD = 250;
    std::mutex ids_mutex;
    std::set<uint64_t> ids;
    std::vector<std::thread> workers;
    for (int thread = 0; thread < THREADS; ++thread) {
        workers.emplace_back([&] {
            QueueRendererState state;
            for (int i = 0; i < PER_THREAD; ++i) {
                uint64_t id = payloadMessageId(buildStateUpdated(1000, i, state));
                std::lock_guard<std::mutex> lock(ids_mutex);
                ids.insert(id);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    check(ids.size() == static_cast<size_t>(THREADS * PER_THREAD),
          "concurrent payload message IDs collided");
}

} // namespace

int main() {
    try {
        testGeneratedFixtures();
        testOutboundPresence();
        testRendererReconnectJoin();
        testQwsErrorFrame();
        testPlaybackErrorAndAutoplayQueue();
        testConcurrentMessageIds();
        std::cout << "qconnect protocol fixtures passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "qconnect protocol test failed: " << error.what() << "\n";
        return 1;
    }
}
