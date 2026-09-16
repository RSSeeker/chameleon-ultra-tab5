// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mifare Classic key recovery (mfkey32) - Tab5 port.
//
// This is the embedded-facing wrapper around the upstream Crapto1 implementation
// (crapto1.c / crypto1.c / bucketsort.c, GPL-3.0-or-later). Those files are kept
// as close to upstream as possible; everything specific to running them on the
// Tab5 lives here.
//
// Algorithm reference: software/src/mfkey32.c from the ChameleonUltra
// repository, itself derived from the original Crapto1 work.
//
// mfkey32 recovers a Mifare Classic sector key from two eavesdropped
// authentications of the same card, given:
//   uid      - card serial number
//   nt       - tag challenge of the first authentication
//   nr0/ar0  - encrypted reader challenge / tag response of the first auth
//   nr1/ar1  - encrypted reader challenge / tag response of the second auth

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace chameleon {
namespace crypto {

/// Status returned by the recovery helpers.
enum class KeyRecoveryStatus : uint8_t {
    Found        = 0,  ///< key recovered, see out_key
    NotFound     = 1,  ///< the search completed without a match
    OutOfMemory  = 2,  ///< recovery needs more RAM than is currently available
    BadArgument  = 3,
};

/// One successful authentication exchange, as observed on the RF link.
struct AuthTrace {
    uint32_t nt = 0;
    uint32_t nr = 0;  ///< encrypted reader nonce
    uint32_t ar = 0;  ///< encrypted tag response
};

/**
 * @brief Free bytes available in PSRAM (large recovery buffers live there).
 */
size_t FreePsramBytes();

/**
 * @brief Peak RAM the mfkey32 search needs.
 *
 * lfsr_recovery32() allocates two 2^21-entry tables plus the result list and a
 * bucket workspace. On a PC that is fine; on the Tab5 it must fit in PSRAM,
 * which the UI also uses for its LVGL buffers, so callers can check first.
 */
size_t Mfkey32RequiredBytes();

/**
 * @brief Recover the key from two authentication traces (mfkey32).
 *
 * @param uid      card serial number
 * @param a        first authentication trace
 * @param b        second authentication trace of the same key/sector
 * @param out_key  receives the recovered key on KeyRecoveryStatus::Found
 * @return KeyRecoveryStatus
 */
KeyRecoveryStatus Mfkey32(uint32_t uid, const AuthTrace& a, const AuthTrace& b, uint64_t* out_key);

/**
 * @brief Verify a candidate key against one authentication trace.
 *
 * Port of Crypto1.mfkey32_is_reader_has_key() from software/script/crypto1.py;
 * used as the oracle in the host tests and as a cheap sanity check.
 */
bool VerifyAuthTrace(uint32_t uid, const AuthTrace& trace, uint64_t key);

/**
 * @brief 32-bit LFSR (PRNG) successor, the tag's nonce generator.
 *
 * This is the C side of Crypto1.prng_next() from the reference Python.
 */
uint32_t PrngSuccessor(uint32_t nonce, uint32_t steps);

/**
 * @brief Number of cipher words a Crypto1 run can produce in one sequence.
 */
constexpr size_t kCrypto1MaxWords = 16;

/**
 * @brief Run a sequence of Crypto1 word operations from one key.
 *
 * The Crypto1 cipher is stateful: a real authentication advances the same LFSR
 * across every exchange. This mirrors Crypto1.lfsr48_u32() being called
 * repeatedly on one Python instance, which is how the reference three pass
 * authentication vector is defined.
 *
 * @param key      48-bit key
 * @param inputs   input words, one per step
 * @param encrypted ciphertext feedback flag per step
 * @param count    number of steps, must be <= kCrypto1MaxWords
 * @param out      receives every keystream word, oldest first
 * @return uint32_t the last word produced, or 0 when count is 0
 */
uint32_t Crypto1WordSequence(uint64_t key, const uint32_t* inputs, const bool* encrypted, size_t count,
                             uint32_t* out);

/**
 * @brief Convenience wrapper for a single Crypto1 word (fresh state).
 */
uint32_t Crypto1Word(uint64_t key, uint32_t in, bool is_encrypted);

}  // namespace crypto
}  // namespace chameleon
