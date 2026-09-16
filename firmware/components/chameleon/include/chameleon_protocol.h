// SPDX-License-Identifier: MIT
//
// Chameleon Ultra wire protocol: framing + checksums.
//
// Mirrors software/script/chameleon_com.py from the official ChameleonUltra
// repository. A frame looks like:
//
//   idx:  0     1       2 3     4 5        6 7      8      9..     last
//         SOF   LRC1    CMD     STATUS     LEN      LRC2   DATA    LRC3
//
// Layout notes (subtle and easy to get wrong; verified byte for byte against
// the reference implementation by tools/verify_frame.py):
//   - LRC1 covers [0,1):  the SOF byte only.
//   - LRC2 covers [0,8):  SOF, LRC1, CMD, STATUS and LEN.
//   - LRC3 covers [0,9+len): the whole header plus the payload.
//   - The header is therefore 9 bytes, and a frame with an empty payload is
//     10 bytes. Python's struct.calcsize('!BBHHHB0s') == 9 confirms this.
//
// LRC is a two's complement running byte sum: LRC(xs) = (0x100 - sum(xs)) & 0xFF.
// All multi-byte integers are big endian.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace chameleon {

constexpr uint8_t kFrameSof = 0x11;

/// Maximum payload accepted from / sent to the device (chameleon_com.py: data_max_length).
constexpr size_t kMaxDataLength = 4096;

/// Offset of each header field within a frame.
constexpr size_t kOffsetSof    = 0;
constexpr size_t kOffsetLrc1   = 1;
constexpr size_t kOffsetCmd    = 2;
constexpr size_t kOffsetStatus = 4;
constexpr size_t kOffsetLength = 6;
constexpr size_t kOffsetLrc2   = 8;

/// Header size, i.e. the offset at which payload bytes start.
constexpr size_t kFrameHeaderLength = 9;

/// Total overhead for a frame with an empty payload (header + trailing LRC3).
constexpr size_t kFrameOverhead = kFrameHeaderLength + 1;

/// Minimum size of a well formed frame (no payload).
constexpr size_t kFrameMinLength = kFrameOverhead;

/// Number of slot indices supported by the firmware.
constexpr int kSlotCount = 8;

/**
 * @brief Chameleon Ultra LRC checksum.
 *
 * @param data  bytes to sum
 * @param len   number of bytes
 * @return uint8_t  (0x100 - (sum of bytes)) & 0xFF
 */
uint8_t Lrc(const uint8_t* data, size_t len);

/**
 * @brief Build a complete frame into out_buffer.
 *
 * @param out_buffer  destination, must hold at least kFrameOverhead + data_len bytes
 * @param out_capacity capacity of out_buffer
 * @param cmd     command id (big endian on the wire)
 * @param status  status code, 0 for host -> device requests
 * @param data    payload, may be nullptr when data_len is 0
 * @param data_len payload length, must be <= kMaxDataLength
 * @return size_t  total frame length, or 0 on invalid arguments
 */
size_t BuildFrame(uint8_t* out_buffer, size_t out_capacity, uint16_t cmd, uint16_t status, const uint8_t* data,
                  size_t data_len);

/**
 * @brief Incremental frame parser.
 *
 * Feed arbitrary chunks of received bytes; the parser emits one parsed frame at
 * a time via a callback. It validates all three LRCs and resynchronises on a
 * bad SOF byte. Byte-at-a-time state machine with a fixed buffer: no dynamic
 * allocation, safe to drive from the transport RX task.
 */
class FrameParser {
public:
    /// Payload view handed to the consumer. Only valid for the duration of the call.
    struct Frame {
        uint16_t cmd        = 0;
        uint16_t status     = 0;
        const uint8_t* data = nullptr;
        size_t data_length  = 0;
    };

    using FrameCallback = void (*)(const Frame& frame, void* user);

    FrameParser() = default;

    /**
     * @brief Reset the parser state (call when the transport reconnects).
     */
    void Reset();

    /**
     * @brief Push received bytes into the parser.
     *
     * @param data      received bytes
     * @param len       byte count
     * @param callback  invoked once per complete, checksum-valid frame
     * @param user      opaque pointer forwarded to the callback
     * @return size_t   number of frames emitted
     */
    size_t Push(const uint8_t* data, size_t len, FrameCallback callback, void* user);

    /**
     * @brief Count of frames dropped because of bad SOF / LRC / oversize length.
     */
    uint32_t errorCount() const
    {
        return _error_count;
    }

private:
    void handleByte(uint8_t byte, FrameCallback callback, void* user, size_t& emitted);

    uint8_t _buffer[kFrameOverhead + kMaxDataLength] = {};
    size_t _position                                 = 0;
    size_t _data_length                              = 0;
    bool _head_valid                                 = false;
    uint32_t _error_count                            = 0;
};

}  // namespace chameleon
