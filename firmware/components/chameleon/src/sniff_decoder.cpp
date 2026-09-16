// SPDX-License-Identifier: MIT
//
// See sniff_decoder.h for the buffer layout and for why the authentication
// frames are what they are.

#include "sniff_decoder.h"

#include <string.h>

namespace chameleon {

namespace {

uint16_t read_be16(const uint8_t* p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t read_be32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

/// Bits that are set in a byte, used to skip trailing CRC bits when a frame is
/// shorter than a whole byte count.
size_t bits_to_bytes(size_t bits)
{
    return (bits + 7) / 8;
}

}  // namespace

size_t DecodeTraceFrames(const uint8_t* buffer, size_t length, TraceFrame* out, size_t max)
{
    if (buffer == nullptr || out == nullptr || max == 0) {
        return 0;
    }

    size_t offset = 0;
    size_t count  = 0;
    while (offset + 2 <= length && count < max) {
        const uint16_t header = read_be16(buffer + offset);
        const size_t bits     = header & 0x7FFF;
        const size_t bytes    = bits_to_bytes(bits);

        // A frame declaring more bits than the buffer holds means the trace was
        // cut short (the device stores partial traces on purpose), so stop
        // rather than inventing a truncated frame.
        if (offset + 2 + bytes > length) {
            break;
        }

        out[count].from_card   = (header & 0x8000) != 0;
        out[count].bit_length  = bits;
        out[count].data        = buffer + offset + 2;
        out[count].byte_length = bytes;
        ++count;
        offset += 2 + bytes;
    }
    return count;
}

size_t DecodeTraceAuths(const uint8_t* buffer, size_t length, TraceAuth* out, size_t max)
{
    if (buffer == nullptr || out == nullptr || max == 0) {
        return 0;
    }

    // 64 frames is plenty for a single auth trace; the walk is bounded anyway.
    constexpr size_t kMaxFrames = 64;
    TraceFrame frames[kMaxFrames];
    const size_t frame_count = DecodeTraceFrames(buffer, length, frames, kMaxFrames);

    size_t count = 0;
    for (size_t i = 0; i + 1 < frame_count && count < max; ++i) {
        // 1. AUTH command from the reader: exactly 4 bytes (2 + CRC), 0x60/0x61.
        const TraceFrame& cmd = frames[i];
        if (cmd.from_card || cmd.byte_length != 4) {
            continue;
        }
        if (cmd.data[0] != 0x60 && cmd.data[0] != 0x61) {
            continue;
        }

        // A reader sent an AUTH command, so from here on the caller gets an
        // entry no matter what follows. A partial authentication - the card
        // rejected the key, or the trace was cut short - is reported with
        // complete = false and whatever fields were present, because "the key
        // was wrong" and "nothing was captured" are different things to tell a
        // user, and only the first one means the attack material is unusable.
        TraceAuth& auth = out[count++];
        auth            = TraceAuth{};
        auth.block      = cmd.data[1];
        auth.key_type   = cmd.data[0];

        if (i + 3 < frame_count) {
            // 2. nt from the card: 4 bytes.
            const TraceFrame& nt_frame = frames[i + 1];
            // 3. nr_enc || ar_enc from the reader: the device stores 8 bytes.
            const TraceFrame& nr_ar = frames[i + 2];
            // 4. the card's encrypted answer: 4 bytes.
            const TraceFrame& at = frames[i + 3];

            const bool nt_ok = nt_frame.from_card && nt_frame.byte_length == 4;
            const bool nr_ok = !nr_ar.from_card && nr_ar.byte_length == 8;
            const bool ar_ok = at.from_card && at.byte_length == 4;

            if (nt_ok) {
                auth.nt = read_be32(nt_frame.data);
            }
            if (nr_ok) {
                auth.nr_enc = read_be32(nr_ar.data);
            }
            if (ar_ok) {
                auth.ar_enc = read_be32(at.data);
            }

            if (nt_ok && nr_ok && ar_ok) {
                auth.complete = true;
                // Continue after this authentication so a trace holding several
                // of them yields several entries.
                i += 3;
            }
        }
    }
    return count;
}

}  // namespace chameleon
