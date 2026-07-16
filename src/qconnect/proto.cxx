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

#include <atomic>
#include <chrono>
#include <cstring>

namespace QConnect {

// ============================================================
//  Low-level protobuf primitives
// ============================================================

namespace {

static uint64_t nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

// Convert Qobuz format_id (5/6/7/27) to QConnect quality level (1-4).
// Level 1=MP3, 2=CD/FLAC, 3=HiRes-96k, 4=HiRes-192k.
static int32_t formatIdToQualityLevel(int32_t fmt) {
    if (fmt == 27) return 4;
    if (fmt == 7)  return 3;
    if (fmt == 6)  return 2;
    return 1;
}

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

// Presence-sensitive variant: emit field even when value is 0.
void writeUint32FieldPresent(Bytes& b, int fn, uint32_t v) {
    writeTag(b, fn, WT_VARINT);
    writeVarint(b, v);
}

// Presence-sensitive variant: emit field even when value is 0.
void writeUint64FieldPresent(Bytes& b, int fn, uint64_t v) {
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

void writeMessageFieldPresent(Bytes& b, int fn, const Bytes& submsg) {
    writeTag(b, fn, WT_LEN);
    writeVarint(b, submsg.size());
    b.insert(b.end(), submsg.begin(), submsg.end());
}

// Write a fixed64 field (wire type 1, 8 bytes little-endian)
void writeFixed64Field(Bytes& b, int fn, uint64_t v) {
    writeTag(b, fn, WT_64BIT);
    for (int i = 0; i < 8; ++i) {
        b.push_back(static_cast<uint8_t>(v & 0xff));
        v >>= 8;
    }
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

// Read a fixed32 field (4 bytes little-endian, wire type 5).
bool readFixed32(const uint8_t* data, size_t len, size_t& pos, uint32_t& out) {
    if (pos + 4 > len) return false;
    out = static_cast<uint32_t>(data[pos])
        | (static_cast<uint32_t>(data[pos+1]) << 8)
        | (static_cast<uint32_t>(data[pos+2]) << 16)
        | (static_cast<uint32_t>(data[pos+3]) << 24);
    pos += 4;
    return true;
}

// Read a fixed64 field (8 bytes little-endian, wire type 1).
bool readFixed64(const uint8_t* data, size_t len, size_t& pos, uint64_t& out) {
    if (pos + 8 > len) return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out |= static_cast<uint64_t>(data[pos + i]) << (8 * i);
    pos += 8;
    return true;
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
    out.present = true;
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
        case 1: readVarint(d, len, pos, v); out.queue_item_id = v; out.has_queue_item_id = true; break;
        case 2: // track_id is fixed32 (wire type 5, 4 bytes LE)
            { uint32_t fv = 0; readFixed32(d, len, pos, fv); out.track_id = fv; } break;
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
        // field 3 = Position message { fixed64 timestamp=1, value_ms=2 }
        case 3:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            out.has_position = true;
            {
                size_t p2 = 0;
                while (p2 < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd, fl, p2, fn2, wt2)) return false;
                    uint64_t v2;
                    if (fn2 == 1 && wt2 == WT_64BIT) {
                        if (!readFixed64(fd, fl, p2, v2)) return false;
                        out.position_timestamp_ms = v2;
                    } else if (fn2 == 2 && wt2 == WT_VARINT) {
                        if (!readVarint(fd, fl, p2, v2)) return false;
                        out.current_position_ms = static_cast<uint32_t>(v2);
                    } else if (!skipField(fd, fl, p2, wt2)) {
                        return false;
                    }
                }
            }
            break;
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.duration_ms = static_cast<uint32_t>(v);
            break;
        case 5:
            if (!readVarint(d, len, pos, v)) return false;
            out.current_queue_index = static_cast<uint32_t>(v);
            out.has_current_queue_index = true;
            break;
        case 7:
            if (!readVarint(d, len, pos, v)) return false;
            out.next_queue_item_id = v;
            out.has_next_queue_item_id = true;
            break;
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
        uint64_t v;
        switch (fn) {
        case 1:
            if (!readVarint(d, len, pos, v)) return false;
            out.state.playing_state = static_cast<PlayingState>(v);
            break;
        case 2:
            if (!readVarint(d, len, pos, v)) return false;
            out.state.buffer_state = static_cast<BufferState>(v);
            break;
        case 3:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            out.state.has_position = true;
            {
                size_t p2 = 0;
                while (p2 < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd, fl, p2, fn2, wt2)) return false;
                    uint64_t v2;
                    if (fn2 == 1 && wt2 == WT_64BIT) {
                        if (!readFixed64(fd, fl, p2, v2)) return false;
                        out.state.position_timestamp_ms = v2;
                    } else if (fn2 == 2 && wt2 == WT_VARINT) {
                        if (!readVarint(fd, fl, p2, v2)) return false;
                        out.state.current_position_ms = static_cast<uint32_t>(v2);
                    } else if (!skipField(fd, fl, p2, wt2)) {
                        return false;
                    }
                }
            }
            break;
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.state.duration_ms = static_cast<uint32_t>(v);
            break;
        case 5:
            if (!readLenField(d, len, pos, fd, fl)) return false;
            if (!decodeQueueVersion(fd, fl, out.queue_version)) return false;
            break;
        case 6:
            if (!readVarint(d, len, pos, v)) return false;
            out.state.current_queue_item_id = v;
            out.state.has_current_queue_item_id = true;
            break;
        case 7:
            if (!readVarint(d, len, pos, v)) return false;
            out.state.next_queue_item_id = v;
            out.state.has_next_queue_item_id = true;
            break;
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
        case 1: readVarint(d,len,pos,v); out.queue_item_id = v; break;
        case 2: // track_id is fixed32 (wire type 5, 4 bytes LE)
            { uint32_t fv = 0; readFixed32(d, len, pos, fv); out.track_id = fv; } break;
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
        case 2: readVarint(d,len,pos,v); out.current_position_ms = static_cast<uint32_t>(v); out.has_position = true; break;
        case 3: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueVersion(fd, fl, out.queue_version); break;
        case 4: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueTrackRef(fd, fl, out.current_queue_item);
                // The presence of the parent field 4 carries information even
                // when the inner queue_item_id (field 1) is omitted: Qobuz
                // omits inner scalar fields whose value is the proto3 default
                // (0).  So "field 4 present, field 1 absent" means qid=0 —
                // i.e. the *first* track.  Force the has-flag on so the
                // SetState handler treats it as a real qid.
                out.current_queue_item.has_queue_item_id = true;
                break;
        case 5: if (!readLenField(d,len,pos,fd,fl)) return false;
                decodeQueueTrackRef(fd, fl, out.next_queue_item);
                out.next_queue_item.has_queue_item_id = true;
                break;
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
        case 4:
            if (!readVarint(d,len,pos,v)) return false;
            out.track_index = static_cast<uint32_t>(v);
            out.has_track_index = true;
            break;
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

bool decodeVersionAndTracks(const uint8_t* d, size_t len,
                            std::vector<QueueTrack>& tracks,
                            QueueVersion& qver) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                if (!decodeQueueVersion(fd, fl, qver)) return false; break;
        case 3: // tracks
            if (!readLenField(d,len,pos,fd,fl)) return false;
            { QueueTrack t;
              if (!decodeQueueTrack(fd, fl, t)) return false;
              tracks.push_back(std::move(t)); }
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueState(const uint8_t* d, size_t len, MsgQueueState& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1:
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out.queue_version)) return false;
            break;
        case 3: {
            if (!readLenField(d, len, pos, fd, fl)) return false;
            QueueTrack track;
            if (!decodeQueueTrack(fd, fl, track)) return false;
            out.tracks.push_back(std::move(track));
            break;
        }
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.shuffle_on = v != 0;
            out.has_shuffle_on = true;
            break;
        case 5:
            if (wt == WT_LEN) {
                if (!readLenField(d, len, pos, fd, fl)) return false;
                size_t packed_pos = 0;
                while (packed_pos < fl) {
                    if (!readVarint(fd, fl, packed_pos, v)) return false;
                    out.shuffled_track_indexes.push_back(
                        static_cast<uint32_t>(v));
                }
            } else {
                if (wt != WT_VARINT || !readVarint(d, len, pos, v)) return false;
                out.shuffled_track_indexes.push_back(static_cast<uint32_t>(v));
            }
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueLoad(const uint8_t* d, size_t len, MsgQueueLoadTracks& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1:
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out.queue_version)) return false;
            break;
        case 3: {
            if (!readLenField(d, len, pos, fd, fl)) return false;
            QueueTrack track;
            if (!decodeQueueTrack(fd, fl, track)) return false;
            out.tracks.push_back(std::move(track));
            break;
        }
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.queue_position = static_cast<uint32_t>(v);
            out.has_queue_position = true;
            break;
        case 6:
            if (!readVarint(d, len, pos, v)) return false;
            out.shuffle_pivot_queue_item_id = static_cast<int32_t>(v);
            out.has_shuffle_pivot_queue_item_id = true;
            break;
        case 7:
            if (!readVarint(d, len, pos, v)) return false;
            out.shuffle_on = v != 0;
            out.has_shuffle_on = true;
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueInserted(const uint8_t* d, size_t len,
                            MsgQueueTracksInserted& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1:
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out.queue_version)) return false;
            break;
        case 3: {
            if (!readLenField(d, len, pos, fd, fl)) return false;
            QueueTrack track;
            if (!decodeQueueTrack(fd, fl, track)) return false;
            out.tracks.push_back(std::move(track));
            break;
        }
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.insert_after = static_cast<int32_t>(v);
            out.has_insert_after = true;
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeQueueItemIds(const uint8_t* d, size_t len, size_t& pos,
                        uint8_t wt, std::vector<uint64_t>& ids) {
    uint64_t v;
    if (wt == WT_LEN) {
        const uint8_t* fd; size_t fl;
        if (!readLenField(d, len, pos, fd, fl)) return false;
        size_t packed_pos = 0;
        while (packed_pos < fl) {
            if (!readVarint(fd, fl, packed_pos, v)) return false;
            ids.push_back(v);
        }
        return true;
    }
    if (wt != WT_VARINT || !readVarint(d, len, pos, v)) return false;
    ids.push_back(v);
    return true;
}

bool decodeMsgQueueRemoved(const uint8_t* d, size_t len, MsgQueueTracksRemoved& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        switch (fn) {
        case 1: if (!readLenField(d,len,pos,fd,fl)) return false;
                if (!decodeQueueVersion(fd, fl, out.queue_version)) return false; break;
        case 3: // queue_item_ids (packed or repeated)
            if (!decodeQueueItemIds(d, len, pos, wt, out.queue_item_ids)) return false;
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeMsgQueueReordered(const uint8_t* d, size_t len,
                             MsgQueueTracksReordered& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        const uint8_t* fd; size_t fl;
        uint64_t v;
        switch (fn) {
        case 1:
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out.queue_version)) return false;
            break;
        case 3:
            if (!decodeQueueItemIds(d, len, pos, wt, out.queue_item_ids)) return false;
            break;
        case 4:
            if (!readVarint(d, len, pos, v)) return false;
            out.insert_after = v;
            out.has_insert_after = true;
            break;
        default: if (!skipField(d, len, pos, wt)) return false; break;
        }
    }
    return true;
}

bool decodeQueueVersionOnly(const uint8_t* d, size_t len, QueueVersion& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        if (fn == 1 && wt == WT_LEN) {
            const uint8_t* fd; size_t fl;
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out)) return false;
        } else if (!skipField(d, len, pos, wt)) {
            return false;
        }
    }
    return true;
}

bool decodeMsgShuffleMode(const uint8_t* d, size_t len, MsgShuffleMode& out,
                          int shuffle_field) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        if (fn == 1 && wt == WT_LEN) {
            const uint8_t* fd; size_t fl;
            if (!readLenField(d, len, pos, fd, fl) ||
                !decodeQueueVersion(fd, fl, out.queue_version)) return false;
        } else if (fn == shuffle_field && wt == WT_VARINT) {
            if (!readVarint(d, len, pos, v)) return false;
            out.shuffle_on = v != 0;
            out.has_shuffle_on = true;
        } else if (fn == 4 && wt == WT_32BIT) {
            if (!readFixed32(d, len, pos, out.current_queue_item_id)) return false;
            out.has_current_queue_item_id = true;
        } else if (fn == 5 && wt == WT_VARINT) {
            if (!readVarint(d, len, pos, v)) return false;
            out.shuffle_pivot = static_cast<uint32_t>(v);
            out.has_shuffle_pivot = true;
        } else if (!skipField(d, len, pos, wt)) {
            return false;
        }
    }
    return true;
}

bool decodeMsgLoopMode(const uint8_t* d, size_t len, MsgLoopMode& out) {
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        uint64_t v;
        if (fn == 1 && wt == WT_VARINT) {
            if (!readVarint(d, len, pos, v)) return false;
            out.mode = static_cast<LoopMode>(v);
            out.has_mode = true;
        } else if (!skipField(d, len, pos, wt)) {
            return false;
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
        case MsgType::CMD_SET_SHUFFLE_MODE:
            if (!decodeMsgShuffleMode(fd, fl, msg.shuffle_mode, 1)) return false;
            break;
        case MsgType::CMD_SET_LOOP_MODE:
            if (!decodeMsgLoopMode(fd, fl, msg.loop_mode)) return false;
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
        case MsgType::SRVRC_ACTIVE_RNDR_CHANGED:
            {
                size_t p = 0; uint64_t v;
                while (p < fl) {
                    int fn2; uint8_t wt2;
                    if (!readTag(fd,fl,p,fn2,wt2)) break;
                    if (fn2 == 1) {
                        readVarint(fd,fl,p,v);
                        msg.active_renderer_changed.renderer_id = v;
                    } else {
                        skipField(fd,fl,p,wt2);
                    }
                }
            }
            break;
        case MsgType::SRVRC_QUEUE_STATE:
            if (!decodeMsgQueueState(fd, fl, msg.queue_state)) return false;
            break;
        case MsgType::SRVRC_QUEUE_CLEARED:
            if (!decodeQueueVersionOnly(fd, fl,
                                        msg.queue_cleared.queue_version)) return false;
            break;
        case MsgType::SRVRC_QUEUE_LOAD_TRACKS:
            if (!decodeMsgQueueLoad(fd, fl, msg.queue_load_tracks)) return false;
            break;
        case MsgType::SRVRC_TRACKS_INSERTED:
            if (!decodeMsgQueueInserted(fd, fl, msg.tracks_inserted)) return false;
            break;
        case MsgType::SRVRC_TRACKS_ADDED:
            if (!decodeVersionAndTracks(fd, fl, msg.tracks_added.tracks,
                                        msg.tracks_added.queue_version)) return false;
            break;
        case MsgType::SRVRC_TRACKS_REMOVED:
            if (!decodeMsgQueueRemoved(fd, fl, msg.tracks_removed)) return false;
            break;
        case MsgType::SRVRC_TRACKS_REORDERED:
            if (!decodeMsgQueueReordered(fd, fl, msg.tracks_reordered)) return false;
            break;
        case MsgType::SRVRC_SHUFFLE_MODE_SET:
            if (!decodeMsgShuffleMode(fd, fl, msg.shuffle_mode, 3)) return false;
            break;
        case MsgType::SRVRC_LOOP_MODE_SET:
            if (!decodeMsgLoopMode(fd, fl, msg.loop_mode)) return false;
            break;
        case MsgType::SRVRC_QUEUE_VERSION_CHANGED:
            if (!decodeQueueVersionOnly(
                    fd, fl, msg.queue_version_changed.queue_version)) return false;
            break;
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
                    std::vector<Message>& msgs,
                    uint64_t* payload_msg_date_ms = nullptr) {
    // Payload { msg_id=1, msg_date=2, proto=3, src=4, dests=5, payload=7 }
    size_t pos = 0;
    while (pos < len) {
        int fn; uint8_t wt;
        if (!readTag(d, len, pos, fn, wt)) return false;
        if (fn == 2 && wt == WT_VARINT) {
            uint64_t v = 0;
            if (!readVarint(d, len, pos, v)) return false;
            if (payload_msg_date_ms) *payload_msg_date_ms = v;
        } else if (fn == 7 && wt == WT_LEN) {
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
    if (s.has_position || s.position_timestamp_ms || s.current_position_ms) {
        Bytes pos;
        uint64_t ts = s.position_timestamp_ms ? s.position_timestamp_ms : nowMs();
        writeFixed64Field(pos, 1, ts);
        // value_ms=0 is semantically meaningful (start of track / seek-to-zero),
        // so emit it explicitly when Position is present.
        writeUint32FieldPresent(pos, 2, s.current_position_ms);
        writeMessageField(b, 3, pos);
    }
    writeUint32Field(b, 4, s.duration_ms);
    if (s.has_current_queue_index || s.current_queue_index)
        writeUint32FieldPresent(b, 5, s.current_queue_index);
    if (s.has_next_queue_item_id || s.next_queue_item_id)
        writeUint64FieldPresent(b, 7, s.next_queue_item_id);
    return b;
}

Bytes encodeQueueRendererState(const QueueRendererState& s) {
    // Wire layout matches QueueRendererState proto (flat, not nested):
    //   1: playing_state (varint enum)
    //   2: buffer_state  (varint enum)
    //   3: current_position (Position message: fixed64 timestamp @1, uint32 value_ms @2)
    //   4: duration (uint32, ms)
    //   5: queue_version (QueueVersion message)
    //   6: current_queue_item_id (uint64)
    //   7: next_queue_item_id (uint64)
    Bytes b;
    writeInt32Field(b, 1, static_cast<int32_t>(s.state.playing_state));
    writeInt32Field(b, 2, static_cast<int32_t>(s.state.buffer_state));
    // Always send Position when we have a timestamp (even if position_ms == 0,
    // e.g. start of track). The server extrapolates: pos + (now - timestamp).
    if (s.state.has_position || s.state.position_timestamp_ms ||
        s.state.current_position_ms) {
        Bytes pos;
        uint64_t ts = s.state.position_timestamp_ms ? s.state.position_timestamp_ms : nowMs();
        writeFixed64Field(pos, 1, ts);
        // value_ms=0 is semantically meaningful (start of track / seek-to-zero),
        // so emit it explicitly when Position is present.
        writeUint32FieldPresent(pos, 2, s.state.current_position_ms);
        writeMessageField(b, 3, pos);
    }
    writeUint32Field(b, 4, s.state.duration_ms);
    Bytes qv = encodeQueueVersion(s.queue_version);
    if (s.queue_version.present || !qv.empty())
        writeMessageFieldPresent(b, 5, qv);
    if (s.state.has_current_queue_item_id || s.state.current_queue_item_id)
        writeUint64FieldPresent(b, 6, s.state.current_queue_item_id);
    if (s.state.has_next_queue_item_id || s.state.next_queue_item_id)
        writeUint64FieldPresent(b, 7, s.state.next_queue_item_id);
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
    // DeviceCapabilities field 7: { min_quality@1, max_quality@2, volume_control@3 }
    // Quality levels: 1=MP3, 2=CD/FLAC, 3=HiRes-96k, 4=HiRes-192k
    {
        Bytes caps;
        writeInt32Field(caps, 1, 1); // min_audio_quality = MP3 (1)
        writeInt32Field(caps, 2, formatIdToQualityLevel(d.max_quality));
        writeInt32Field(caps, 3, 2); // volume_remote_control = 2
        writeMessageField(b, 7, caps);
    }
    if (!d.software_version.empty())
        writeStringField(b, 8, d.software_version);
    return b;
}

// Wrap an inner QConnect message in QConnectBatch + Payload envelope.
// force_content: if true, always write the inner message field even if empty
// (needed for messages like VolumeMuted(false) that must be present but have no fields).
Bytes wrapInPayload(uint64_t time_ms, int32_t batch_id,
                     int inner_msg_field_number,
                     const Bytes& inner_msg,
                     bool force_content = false) {
    // QConnectMessage { message_type=1 (varint), content at field=message_type }
    // The message_type field 1 must be present; qonductor always sets it.
    Bytes qcm;
    writeInt32Field(qcm, 1, inner_msg_field_number); // QConnectMessage.message_type
    if (force_content || !inner_msg.empty()) {
        writeTag(qcm, inner_msg_field_number, WT_LEN);
        writeVarint(qcm, inner_msg.size());
        qcm.insert(qcm.end(), inner_msg.begin(), inner_msg.end());
    }

    // QConnectBatch { messages_time=1 (fixed64), messages_id=2, messages=3 }
    Bytes batch;
    writeFixed64Field(batch, 1, time_ms);
    writeInt32Field(batch, 2, batch_id);
    writeMessageField(batch, 3, qcm);

    // Payload { msg_id=1, msg_date=2, proto=3, payload=7 }
    static std::atomic<uint32_t> s_payload_msg_id{0};
    Bytes payload;
    writeUint32Field(
        payload, 1,
        s_payload_msg_id.fetch_add(1, std::memory_order_relaxed) + 1);
    writeUint64Field(payload, 2, time_ms);
    writeInt32Field(payload, 3, static_cast<int32_t>(QCloudProto::QCONNECT));
    writeBytesField(payload, 7, batch);

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

Bytes buildSubscribe(uint64_t msg_id, uint64_t msg_date_ms, QCloudProto proto) {
    Bytes sub;
    writeUint32Field(sub, 1, static_cast<uint32_t>(msg_id));
    writeUint64Field(sub, 2, msg_date_ms);
    writeInt32Field(sub, 3, static_cast<int32_t>(proto));
    // channels = 4: empty means subscribe to all
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

// CtrlSrvrJoinSession (61): sent immediately after SUBSCRIBE to register
// the device with the cloud session manager.  session_uuid is omitted on
// the first call (we don't have one yet); the server will assign one and
// deliver it via SessionState (81).
Bytes buildCtrlJoinSession(uint64_t time_ms, int32_t batch_id,
                             const DeviceInfo& dev) {
    // CtrlSrvrJoinSession { session_uuid=1 (omit), device_info=2 }
    Bytes msg;
    writeMessageField(msg, 2, encodeDeviceInfo(dev));
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::CTRL_JOIN_SESSION), msg);
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

Bytes buildVolumeMuted(uint64_t time_ms, int32_t batch_id, bool muted) {
    // RndrSrvrVolumeMuted { value=1 (bool, optional) }
    // Protocol convention: None (no field) = not muted, Some(true) = muted.
    // Must always send the message even when not muted (empty body).
    Bytes msg;
    if (muted) writeBoolField(msg, 1, true);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_VOLUME_MUTED), msg,
                                   /*force_content=*/true);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildFileAudioQualityChanged(uint64_t time_ms, int32_t batch_id,
                                    int32_t sample_rate_hz) {
    // RndrSrvrFileAudioQualityChanged { value=1 (int32) }
    Bytes msg;
    writeInt32Field(msg, 1, sample_rate_hz);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::RNDR_FILE_QUALITY), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

Bytes buildAskQueueState(uint64_t time_ms, int32_t batch_id,
                          const Bytes& queue_uuid) {
    // CtrlSrvrAskForQueueState { queue_version=1 (omit), queue_uuid=2 (bytes) }
    Bytes msg;
    writeBytesField(msg, 2, queue_uuid);
    Bytes payload = wrapInPayload(time_ms, batch_id,
                                   static_cast<int>(MsgType::CTRL_ASK_QUEUE_STATE), msg);
    return buildEnvelope(EnvType::PAYLOAD, payload);
}

bool parseFrame(const uint8_t* data, size_t len, std::vector<Message>& msgs,
                uint64_t* payload_msg_date_ms) {
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
        return decodePayload(payload, plen, msgs, payload_msg_date_ms);
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
