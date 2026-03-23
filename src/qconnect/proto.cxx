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

#include "proto.hxx"

#include <cstring>

namespace QConnect {

// ============================================================
//  Low-level protobuf primitives
// ============================================================

namespace {

// Wire types
constexpr uint8_t WT_VARINT = 0;
constexpr uint8_t WT_64BIT  = 1;
constexpr uint8_t WT_LEN    = 2;
constexpr uint8_t WT_32BIT  = 5;

void appendByte(Bytes& b, uint8_t v) { b.push_back(v); }

// Encode unsigned varint (uint32 or uint64 both fit here)
void writeVarint(Bytes& b, uint64_t v) {
    do {
        uint8_t byte = v & 0x7f;
        v >>= 7;
        if (v) byte |= 0x80;
        b.push_back(byte);
    } while (v);
}

// Encode signed 32-bit int as varint (two's complement, sign-extended to 64 bit)
void writeVarintSigned(Bytes& b, int32_t v) {
    writeVarint(b, static_cast<uint64_t>(static_cast<int64_t>(v)));
}

void writeTag(Bytes& b, int field_number, uint8_t wire_type) {
    writeVarint(b, (static_cast<uint64_t>(field_number) << 3) | wire_type);
}

void writeUint32Field(Bytes& b, int fn, uint32_t v) {
    if (!v) return;
    writeTag(b, fn, WT_VARINT);
    writeVarint(b, v);
}

void writeUint64Field(Bytes& b, int fn, uint64_t v) {
    if (!v) return;
    writeTag(b, fn, WT_VARINT);
    writeVarint(b, v);
}

void writeInt32Field(Bytes& b, int fn, int32_t v) {
    if (!v) return;
    writeTag(b, fn, WT_VARINT);
    writeVarintSigned(b, v);
}

void writeBoolField(Bytes& b, int fn, bool v) {
    if (!v) return;
    writeTag(b, fn, WT_VARINT);
    b.push_back(1);
}

void writeBytesField(Bytes& b, int fn, const Bytes& data) {
    if (data.empty()) return;
    writeTag(b, fn, WT_LEN);
    writeVarint(b, data.size());
    b.insert(b.end(), data.begin(), data.end());
}

void writeStringField(Bytes& b, int fn, const std::string& s) {
    if (s.empty()) return;
    writeTag(b, fn, WT_LEN);
    writeVarint(b, s.size());
    b.insert(b.end(), s.begin(), s.end());
}

void writeMessageField(Bytes& b, int fn, const Bytes& submsg) {
    if (submsg.empty()) return;
    writeTag(b, fn, WT_LEN);
    writeVarint(b, submsg.size());
    b.insert(b.end(), submsg.begin(), submsg.end());
}

// ---- Decoder helpers --------------------------------------------------------

// Read varint from data[pos..], advance pos.  Returns false on truncation.
bool readVarint(const uint8_t* data, size_t len, size_t& pos, uint64_t& out) {
    out = 0;
    int shift = 0;
    while (pos < len) {
        uint8_t byte = data[pos++];
        out |= static_cast<uint64_t>(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) return true;
        if (shift >= 64) return false;
    }
    return false;
}

// Read field tag, return field_number and wire_type.
bool readTag(const uint8_t* data, size_t len, size_t& pos,
             int& field_number, uint8_t& wire_type) {
    uint64_t v;
    if (!readVarint(data, len, pos, v)) return false;
    wire_type    = v & 0x07;
    field_number = static_cast<int>(v >> 3);
    return true;
}

// Skip one field value (caller has already read the tag).
bool skipField(const uint8_t* data, size_t len, size_t& pos, uint8_t wire_type) {
    uint64_t v;
    switch (wire_type) {
    case WT_VARINT:
        return readVarint(data, len, pos, v);
    case WT_64BIT:
        if (pos + 8 > len) return false;
        pos += 8;
        return true;
    case WT_LEN:
        if (!readVarint(data, len, pos, v)) return false;
        if (pos + v > len) return false;
        pos += static_cast<size_t>(v);
        return true;
    case WT_32BIT:
        if (pos + 4 > len) return false;
        pos += 4;
        return true;
    default:
        return false;
    }
}

// Read a length-delimited field and return its span.
bool readLenField(const uint8_t* data, size_t len, size_t& pos,
                  const uint8_t*& field_data, size_t& field_len) {
    uint64_t flen;
    if (!readVarint(data, len, pos, flen)) return false;
    if (pos + flen > len) return false;
    field_data = data + pos;
    field_len  = static_cast<size_t>(flen);
    pos += field_len;
    return true;
}

// ---- Nested struct decoders -------------------------------------------------

bool decodeQueueVersion(const uint8_t* d, size_t len, QueueVersion& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        switch (fn) {
        case 1: readVarint(d, len, pos, v); out.major = v; break;
        case 2: {
            readVarint(d, len, pos, v);
            out.minor = static_cast<int32_t>(v); break;
        }
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeQueueTrackRef(const uint8_t* d, size_t len, QueueTrackRef& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d, len, pos, v); out.queue_item_id = static_cast<uint32_t>(v); break;
        case 2: readVarint(d, len, pos, v); out.track_id = static_cast<uint32_t>(v); break;
        case 3:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            out.context_uuid.assign(fd, fd + fl); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeRendererState(const uint8_t* d, size_t len, RendererState& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d, len, pos, v); out.playing_state = static_cast<PlayingState>(v); break;
        case 2: readVarint(d, len, pos, v); out.buffer_state  = static_cast<BufferState>(v);  break;
        // field 3 = Position message { timestamp=1, value_ms=2 } — we only need value_ms
        case 3:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            {
                size_t p2 = 0;
                while (p2 < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd, fl, p2, fn2, wt2)) break;
                    uint64_t v2;
                    if (fn2 == 2) { readVarint(fd, fl, p2, v2); out.current_position_ms = static_cast<uint32_t>(v2); }
                    else skipField(fd, fl, p2, wt2);
                }
            }
            break;
        case 4: readVarint(d, len, pos, v); out.duration_ms              = static_cast<uint32_t>(v); break;
        case 5: readVarint(d, len, pos, v); out.current_queue_item_id    = static_cast<uint32_t>(v); break;
        case 6: readVarint(d, len, pos, v); out.next_queue_item_id       = static_cast<uint32_t>(v); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeQueueRendererState(const uint8_t* d, size_t len, QueueRendererState& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            decodeQueueVersion(fd, fl, out.queue_version); break;
        case 2:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            decodeRendererState(fd, fl, out.state); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeDeviceInfo(const uint8_t* d, size_t len, DeviceInfo& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.uuid.assign(fd, fd+fl); break;
        case 2: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.friendly_name.assign(reinterpret_cast<const char*>(fd), fl); break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.brand.assign(reinterpret_cast<const char*>(fd), fl); break;
        case 4: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.model.assign(reinterpret_cast<const char*>(fd), fl); break;
        case 5: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.serial.assign(reinterpret_cast<const char*>(fd), fl); break;
        case 6: readVarint(d,len,pos,v); out.type = static_cast<int32_t>(v); break;
        // field 7 = DeviceCapabilities (max_quality etc) - skip for now
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeQueueTrack(const uint8_t* d, size_t len, QueueTrack& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d,len,pos,v); out.queue_item_id = static_cast<uint32_t>(v); break;
        // field 2 = track_id (fixed32 in some protos, varint in others – assume varint)
        case 2: readVarint(d,len,pos,v); out.track_id = static_cast<uint32_t>(v); break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.context_uuid.assign(fd, fd+fl); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

// ---- Specific message decoders ----------------------------------------------

bool decodeMsgSetState(const uint8_t* d, size_t len, MsgSetState& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d,len,pos,v); out.playing_state = static_cast<PlayingState>(v); break;
        case 2: readVarint(d,len,pos,v); out.current_position_ms = static_cast<uint32_t>(v); break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueVersion(fd, fl, out.queue_version); break;
        case 4: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueTrackRef(fd, fl, out.current_queue_item); break;
        case 5: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueTrackRef(fd, fl, out.next_queue_item); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgSessionState(const uint8_t* d, size_t len, MsgSessionState& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                out.session_uuid.assign(fd, fd+fl); break;
        case 2: readVarint(d,len,pos,v); out.session_id = v; break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueVersion(fd, fl, out.queue_version); break;
        case 4: readVarint(d,len,pos,v); out.track_index = static_cast<uint32_t>(v); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgRendererStateUpd(const uint8_t* d, size_t len,
                                MsgRendererStateUpdated& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d,len,pos,v); out.renderer_id = v; break;
        case 2: readVarint(d,len,pos,v); out.message_id  = v; break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeRendererState(fd, fl, out.state); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgAddRenderer(const uint8_t* d, size_t len, MsgAddRenderer& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: readVarint(d,len,pos,v); out.renderer_id = v; break;
        case 2: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeDeviceInfo(fd, fl, out.renderer); break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueTracks(const uint8_t* d, size_t len,
                           std::vector<QueueTrack>& tracks,
                           QueueVersion& qver,
                           uint32_t* queue_position = nullptr,
                           uint32_t* insert_after   = nullptr) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueVersion(fd, fl, qver); break;
        case 3: // tracks
            if (!readLenField(d,len,pos,fd,fl)) return false;
            { QueueTrack t; decodeQueueTrack(fd, fl, t); tracks.push_back(t); }
            break;
        case 4: // queue_position (load) or insert_after (insert)
            readVarint(d,len,pos,v);
            if (queue_position) *queue_position = static_cast<uint32_t>(v);
            if (insert_after)   *insert_after   = static_cast<uint32_t>(v);
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueRemoved(const uint8_t* d, size_t len, MsgQueueTracksRemoved& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueVersion(fd, fl, out.queue_version); break;
        case 3: // queue_item_ids (packed or repeated)
            if (wt == WT_LEN) {
                // packed varint
                if (!readLenField(d,len,pos,fd,fl)) return false;
                size_t p2 = 0;
                while (p2 < fl) {
                    if (!readVarint(fd, fl, p2, v)) break;
                    out.queue_item_ids.push_back(static_cast<uint32_t>(v));
                }
            } else {
                readVarint(d,len,pos,v);
                out.queue_item_ids.push_back(static_cast<uint32_t>(v));
            }
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

// ---- QConnectMessage and QConnectBatch decoders -----------------------------

bool decodeQConnectMessage(const uint8_t* d, size_t len,
                            std::vector<Message>& msgs) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        if (wt != WT_LEN) { skipField(d, len, pos, wt); continue; }
        if (!readLenField(d, len, pos, fd, fl)) return false;

        Message msg;
        msg.type = static_cast<MsgType>(fn);
        bool handled = true;

        switch (msg.type) {
        case MsgType::CMD_SET_STATE:
            decodeMsgSetState(fd, fl, msg.set_state); break;
        case MsgType::CMD_SET_ACTIVE:
            {
                size_t p = 0; uint64_t v;
                while (p < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd,fl,p,fn2,wt2)) break;
                    if (fn2 == 1) { readVarint(fd,fl,p,v); msg.set_active.active = (v != 0); }
                    else skipField(fd,fl,p,wt2);
                }
            }
            break;
        case MsgType::CMD_SET_VOLUME:
            {
                size_t p = 0; uint64_t v;
                while (p < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd,fl,p,fn2,wt2)) break;
                    if (fn2 == 1) { readVarint(fd,fl,p,v); msg.set_volume.volume = static_cast<uint32_t>(v); }
                    else if (fn2 == 2) { readVarint(fd,fl,p,v); msg.set_volume.volume_delta = static_cast<int32_t>(v); }
                    else skipField(fd,fl,p,wt2);
                }
            }
            break;
        case MsgType::SRVRC_SESSION_STATE:
            decodeMsgSessionState(fd, fl, msg.session_state); break;
        case MsgType::SRVRC_RENDERER_STATE_UPD:
            decodeMsgRendererStateUpd(fd, fl, msg.renderer_state_upd); break;
        case MsgType::SRVRC_ADD_RENDERER:
            decodeMsgAddRenderer(fd, fl, msg.add_renderer); break;
        case MsgType::SRVRC_REMOVE_RENDERER:
            {
                size_t p = 0; uint64_t v;
                while (p < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd,fl,p,fn2,wt2)) break;
                    if (fn2 == 1) { readVarint(fd,fl,p,v); msg.remove_renderer.renderer_id = v; }
                    else skipField(fd,fl,p,wt2);
                }
            }
            break;
        case MsgType::SRVRC_QUEUE_STATE:
            decodeMsgQueueTracks(fd, fl, msg.queue_state.tracks,
                                  msg.queue_state.queue_version);
            break;
        case MsgType::SRVRC_QUEUE_LOAD_TRACKS:
            decodeMsgQueueTracks(fd, fl, msg.queue_load_tracks.tracks,
                                  msg.queue_load_tracks.queue_version,
                                  &msg.queue_load_tracks.queue_position);
            break;
        case MsgType::SRVRC_TRACKS_INSERTED:
            decodeMsgQueueTracks(fd, fl, msg.tracks_inserted.tracks,
                                  msg.tracks_inserted.queue_version,
                                  nullptr,
                                  &msg.tracks_inserted.insert_after);
            break;
        case MsgType::SRVRC_TRACKS_ADDED:
            decodeMsgQueueTracks(fd, fl, msg.tracks_added.tracks,
                                  msg.tracks_added.queue_version);
            break;
        case MsgType::SRVRC_TRACKS_REMOVED:
            decodeMsgQueueRemoved(fd, fl, msg.tracks_removed); break;
        default:
            handled = false; break;
        }

        if (handled)
            msgs.push_back(msg);
    }
    return true;
}

bool decodeQConnectBatch(const uint8_t* d, size_t len,
                          std::vector<Message>& msgs) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        if (fn == 3 && wt == WT_LEN) {
            // repeated QConnectMessage messages = 3
            const uint8_t* fd; size_t fl;
            if (!readLenField(d, len, pos, fd, fl)) return false;
            decodeQConnectMessage(fd, fl, msgs);
        } else {
            if (!skipField(d, len, pos, wt)) return false;
        }
    }
    return true;
}

bool decodePayload(const uint8_t* d, size_t len,
                    std::vector<Message>& msgs) {
    // Payload { source_channel=1, dest_channel=2, proto=3, payload_data=4 }
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        if (fn == 4 && wt == WT_LEN) {
            const uint8_t* fd; size_t fl;
            if (!readLenField(d, len, pos, fd, fl)) return false;
            decodeQConnectBatch(fd, fl, msgs);
        } else {
            if (!skipField(d, len, pos, wt)) return false;
        }
    }
    return true;
}

// ---- Message encoders -------------------------------------------------------

Bytes encodeQueueVersion(const QueueVersion& v) {
    Bytes b;
    writeUint64Field(b, 1, v.major);
    writeInt32Field(b, 2, v.minor);
    return b;
}

Bytes encodeRendererState(const RendererState& s) {
    Bytes b;
    writeInt32Field(b, 1, static_cast<int32_t>(s.playing_state));
    writeInt32Field(b, 2, static_cast<int32_t>(s.buffer_state));
    // Position field 3: { timestamp=1 (unused), value_ms=2 }
    if (s.current_position_ms) {
        Bytes pos;
        writeUint32Field(pos, 2, s.current_position_ms);
        writeMessageField(b, 3, pos);
    }
    writeUint32Field(b, 4, s.duration_ms);
    writeUint32Field(b, 5, s.current_queue_item_id);
    writeUint32Field(b, 6, s.next_queue_item_id);
    return b;
}

Bytes encodeQueueRendererState(const QueueRendererState& s) {
    Bytes b;
    Bytes qv = encodeQueueVersion(s.queue_version);
    writeMessageField(b, 1, qv);
    Bytes rs = encodeRendererState(s.state);
    writeMessageField(b, 2, rs);
    return b;
}

Bytes encodeDeviceInfo(const DeviceInfo& d) {
    Bytes b;
    writeBytesField(b, 1, d.uuid);
    writeStringField(b, 2, d.friendly_name);
    writeStringField(b, 3, d.brand);
    writeStringField(b, 4, d.model);
    writeStringField(b, 5, d.serial);
    writeInt32Field(b, 6, d.type);
    // DeviceCapabilities field 7: { max_quality=1, ... } - minimal version
    {
        Bytes caps;
        writeInt32Field(caps, 1, d.max_quality);
        writeMessageField(b, 7, caps);
    }
    return b;
}

// Wrap an inner QConnect message in QConnectBatch + Payload envelope
Bytes wrapInPayload(uint64_t time_ms, int32_t batch_id,
                     int inner_msg_field_number,
                     const Bytes& inner_msg) {
    // QConnectMessage: oneof, inner field tag = inner_msg_field_number
    Bytes qcm;
    writeMessageField(qcm, inner_msg_field_number, inner_msg);

    // QConnectBatch { messages_time=1, messages_id=2, messages=3 }
    Bytes batch;
    writeUint64Field(batch, 1, time_ms);
    writeInt32Field(batch, 2, batch_id);
    writeMessageField(batch, 3, qcm);

    // Payload { payload_data=4, proto=3 }
    Bytes payload;
    writeInt32Field(payload, 3, static_cast<int32_t>(QCloudProto::QCONNECT));
    writeBytesField(payload, 4, batch);

    return payload;
}

} // anonymous namespace

// ============================================================
//  Public API implementations
// ============================================================

Bytes buildEnvelope(EnvType type, const Bytes& payload) {
    Bytes frame;
    frame.push_back(static_cast<uint8_t>(type));
    writeVarint(frame, payload.size());
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

Bytes buildAuthenticate(uint64_t msg_id, uint64_t msg_date_ms,
                         const std::string& jwt) {
    Bytes auth;
    writeUint64Field(auth, 1, msg_id);
    writeUint64Field(auth, 2, msg_date_ms);
    writeStringField(auth, 3, jwt);
    return buildEnvelope(EnvType::AUTHENTICATE, auth);
}

Bytes buildSubscribe(QCloudProto proto) {
    Bytes sub;
    writeInt32Field(sub, 1, static_cast<int32_t>(proto));
    // channel_ids = 2: empty means subscribe to all
    return buildEnvelope(EnvType::SUBSCRIBE, sub);
}

Bytes buildJoinSession(uint64_t time_ms, int32_t batch_id,
                        const Bytes& session_uuid,
                        const DeviceInfo& dev, bool is_active,
                        const QueueRendererState& state) {
    // RndrSrvrJoinSession { session_uuid=1, device_info=2, reason=3,
    //                       initial_state=4, is_active=5 }
    Bytes msg;
    writeBytesField(msg, 1, session_uuid);
    writeMessageField(msg, 2, encodeDeviceInfo(dev));
    writeInt32Field(msg, 3, 0); // reason=0 (initial join)
    writeMessageField(msg, 4, encodeQueueRendererState(state));
    writeBoolField(msg, 5, is_active);

    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_JOIN_SESSION), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildStateUpdated(uint64_t time_ms, int32_t batch_id,
                         const QueueRendererState& state) {
    // RndrSrvrStateUpdated { state=1 }
    Bytes msg;
    writeMessageField(msg, 1, encodeQueueRendererState(state));
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_STATE_UPDATED), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildVolumeChanged(uint64_t time_ms, int32_t batch_id, uint32_t volume) {
    Bytes msg;
    writeUint32Field(msg, 1, volume);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_VOLUME_CHANGED), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildMaxQualityChanged(uint64_t time_ms, int32_t batch_id, int32_t quality) {
    Bytes msg;
    writeInt32Field(msg, 1, quality);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_MAX_QUALITY), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildSetActiveRenderer(uint64_t time_ms, int32_t batch_id,
                              int32_t renderer_id) {
    // CtrlSrvrSetActiveRenderer { renderer_id=1 }
    Bytes msg;
    writeInt32Field(msg, 1, renderer_id);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::CTRL_SET_ACTIVE_RENDERER), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildAskRendererState(uint64_t time_ms, int32_t batch_id,
                             uint64_t session_id) {
    // CtrlSrvrAskForRendererState { session_id=1 }
    Bytes msg;
    writeUint64Field(msg, 1, session_id);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::CTRL_ASK_RENDERER_STATE), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

bool parseFrame(const uint8_t* data, size_t len, std::vector<Message>& msgs) {
    if (len < 2) return false;

    size_t pos = 0;
    EnvType type = static_cast<EnvType>(data[pos++]);

    uint64_t payload_len;
    if (!readVarint(data, len, pos, payload_len)) return false;
    if (pos + payload_len > len) return false;

    const uint8_t* payload = data + pos;
    size_t plen = static_cast<size_t>(payload_len);

    switch (type) {
    case EnvType::PAYLOAD:
        return decodePayload(payload, plen, msgs);
    case EnvType::AUTHENTICATE:
    case EnvType::SUBSCRIBE:
    case EnvType::DISCONNECT:
        // Server may echo these; ignore silently
        return true;
    case EnvType::ERROR_MSG:
        // TODO: log error
        return true;
    default:
        return true; // unknown type, ignore
    }
}

} // namespace QConnect
