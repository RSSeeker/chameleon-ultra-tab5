// SPDX-License-Identifier: MIT

#include "chameleon_protocol.h"

#include <string.h>

namespace chameleon {

uint8_t Lrc(const uint8_t* data, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum = static_cast<uint8_t>(sum + data[i]);
    }
    return static_cast<uint8_t>((0x100 - sum) & 0xFF);
}

size_t BuildFrame(uint8_t* out_buffer, size_t out_capacity, uint16_t cmd, uint16_t status, const uint8_t* data,
                  size_t data_len)
{
    if (out_buffer == nullptr) {
        return 0;
    }
    if (data_len > kMaxDataLength) {
        return 0;
    }
    if (data_len > 0 && data == nullptr) {
        return 0;
    }
    const size_t total = kFrameOverhead + data_len;
    if (out_capacity < total) {
        return 0;
    }

    // Header: 9 bytes, with LRC2 as its last byte.
    out_buffer[kOffsetSof]        = kFrameSof;
    out_buffer[kOffsetLrc1]       = 0;  // filled below
    out_buffer[kOffsetCmd]        = static_cast<uint8_t>(cmd >> 8);
    out_buffer[kOffsetCmd + 1]    = static_cast<uint8_t>(cmd & 0xFF);
    out_buffer[kOffsetStatus]     = static_cast<uint8_t>(status >> 8);
    out_buffer[kOffsetStatus + 1] = static_cast<uint8_t>(status & 0xFF);
    out_buffer[kOffsetLength]     = static_cast<uint8_t>(data_len >> 8);
    out_buffer[kOffsetLength + 1] = static_cast<uint8_t>(data_len & 0xFF);
    out_buffer[kOffsetLrc2]       = 0;  // filled below

    if (data_len > 0) {
        memcpy(out_buffer + kFrameHeaderLength, data, data_len);
    }

    // LRC1 covers the SOF only; LRC2 covers the first 8 header bytes; LRC3
    // covers the whole header plus the payload.
    out_buffer[kOffsetLrc1]                   = Lrc(out_buffer, kOffsetLrc1);
    out_buffer[kOffsetLrc2]                   = Lrc(out_buffer, kOffsetLrc2);
    out_buffer[kFrameHeaderLength + data_len] = Lrc(out_buffer, kFrameHeaderLength + data_len);
    return total;
}

void FrameParser::Reset()
{
    _position    = 0;
    _data_length = 0;
    _head_valid  = false;
}

size_t FrameParser::Push(const uint8_t* data, size_t len, FrameCallback callback, void* user)
{
    size_t emitted = 0;
    if (data == nullptr || callback == nullptr) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        handleByte(data[i], callback, user, emitted);
    }
    return emitted;
}

void FrameParser::handleByte(uint8_t byte, FrameCallback callback, void* user, size_t& emitted)
{
    // Position 0: SOF. Anything else is discarded until a frame starts.
    if (_position == 0) {
        if (byte != kFrameSof) {
            ++_error_count;
            return;
        }
        _buffer[0] = byte;
        _position  = 1;
        return;
    }

    // Accumulate the header, validating each checksum as soon as its bytes are
    // available. This mirrors the reference receiver in chameleon_com.py, which
    // validates after appending the byte at index 1 and again at index 9.
    if (_position < kFrameHeaderLength) {
        _buffer[_position] = byte;
        ++_position;

        if (_position == kOffsetLrc1 + 1 && _buffer[kOffsetLrc1] != Lrc(_buffer, kOffsetLrc1)) {
            ++_error_count;
            Reset();
            if (byte == kFrameSof) {  // the bad byte may itself start a frame
                _buffer[0] = byte;
                _position  = 1;
            }
            return;
        }

        if (_position == kFrameHeaderLength) {
            if (_buffer[kOffsetLrc2] != Lrc(_buffer, kOffsetLrc2)) {
                ++_error_count;
                Reset();
                if (byte == kFrameSof) {
                    _buffer[0] = byte;
                    _position  = 1;
                }
                return;
            }
            _data_length = (static_cast<size_t>(_buffer[kOffsetLength]) << 8) |
                           static_cast<size_t>(_buffer[kOffsetLength + 1]);
            if (_data_length > kMaxDataLength) {
                ++_error_count;
                Reset();
                return;
            }
            _head_valid = true;
        }
        return;
    }

    // Payload bytes.
    if (_position < kFrameHeaderLength + _data_length) {
        _buffer[_position] = byte;
        ++_position;
        return;
    }

    // Trailing data LRC: its position is kFrameHeaderLength + data_length.
    _buffer[_position] = byte;
    if (_head_valid && byte == Lrc(_buffer, _position)) {
        Frame frame;
        frame.cmd         = (static_cast<uint16_t>(_buffer[kOffsetCmd]) << 8) |
                            static_cast<uint16_t>(_buffer[kOffsetCmd + 1]);
        frame.status      = (static_cast<uint16_t>(_buffer[kOffsetStatus]) << 8) |
                            static_cast<uint16_t>(_buffer[kOffsetStatus + 1]);
        frame.data        = _buffer + kFrameHeaderLength;
        frame.data_length = _data_length;
        callback(frame, user);
        ++emitted;
    } else {
        ++_error_count;
    }

    Reset();
}

}  // namespace chameleon
