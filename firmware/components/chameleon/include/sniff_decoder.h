// SPDX-License-Identifier: MIT
//
// Decoder for the packed frame buffers the device returns from HF14A_SNIFF and
// HF14A_AUTH_TRACE.
//
// Both commands answer with the same layout (app_cmd.c auth_trace_store):
//
//   [bits_be16][frame bytes] [bits_be16][frame bytes] ...
//
// where bit 15 of the header means card -> reader and the byte count is
// ceil(bits / 8). Frames are NOT byte aligned to anything: the trace starts with
// a 7 bit REQA, so the reader has to follow the bit counts rather than scan for
// patterns.
//
// The authentication part of an HF14A_AUTH_TRACE is four frames (app_cmd.c
// cmd_processor_hf14a_auth_trace):
//
//   reader -> card  4 bytes   AUTH command: 0x60/0x61, block, CRC[2]
//   card   -> reader 4 bytes   nt (plaintext, straight from the real card)
//   reader -> card  8 bytes   nr_enc[4] || ar_enc[4] as the *device* computed them
//   card   -> reader 4 bytes   the real card's encrypted answer
//
// Only the second and fourth frames come from the card. The middle frame is the
// device's own Crypto1 output, which is why producing a trace at all requires
// the sector key: the card rejects the authentication otherwise (the handler
// returns MF_ERR_AUTH when the card does not answer with 4 bytes).

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace chameleon {

/// One frame of a sniff / auth-trace buffer.
struct TraceFrame {
    bool from_card    = false;  ///< header bit 15
    size_t bit_length = 0;
    const uint8_t* data = nullptr;  ///< points into the caller's buffer
    size_t byte_length  = 0;
};

/**
 * @brief Walk the packed frame list.
 *
 * @return number of frames written; stops early on a truncated frame
 */
size_t DecodeTraceFrames(const uint8_t* buffer, size_t length, TraceFrame* out, size_t max);

/// One Mifare Classic authentication found in a trace.
struct TraceAuth {
    uint8_t block       = 0;
    uint8_t key_type    = 0;  ///< 0x60 (key A) or 0x61 (key B)
    uint32_t nt         = 0;  ///< card nonce, plaintext
    uint32_t nr_enc     = 0;  ///< reader nonce, encrypted by the device
    uint32_t ar_enc     = 0;  ///< card answer, encrypted (this is what a crack would need)
    bool complete       = false;  ///< true when all four frames were present
};

/**
 * @brief Pull the Crypto1 authentications out of a trace.
 *
 * A pair is only reported when all four frames are present and in the expected
 * direction; a partial authentication (a card that rejected the key) yields
 * complete == false so a caller cannot mistake it for usable material.
 */
size_t DecodeTraceAuths(const uint8_t* buffer, size_t length, TraceAuth* out, size_t max);

}  // namespace chameleon
