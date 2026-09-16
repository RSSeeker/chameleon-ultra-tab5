// SPDX-License-Identifier: GPL-3.0-or-later
//
// mfkey32 wrapper - see mfkey32.h.

#include "mfkey32.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <esp_heap_caps.h>
#include <esp_log.h>

extern "C" {
#include "crapto1.h"
}

static const char* TAG = "mfkey32";

namespace chameleon {
namespace crypto {

// ---------------------------------------------------------------------------
// Thin wrappers over the upstream Crapto1 primitives
// ---------------------------------------------------------------------------

uint32_t PrngSuccessor(uint32_t nonce, uint32_t steps)
{
    return prng_successor(nonce, steps);
}

uint32_t Crypto1WordSequence(uint64_t key, const uint32_t* inputs, const bool* encrypted, size_t count, uint32_t* out)
{
    if (inputs == nullptr || encrypted == nullptr || count == 0 || count > kCrypto1MaxWords) {
        return 0;
    }

    struct Crypto1State state;
    crypto1_init(&state, key);

    uint32_t last = 0;
    for (size_t i = 0; i < count; ++i) {
        last = crypto1_word(&state, inputs[i], encrypted[i] ? 1 : 0);
        if (out != nullptr) {
            out[i] = last;
        }
    }
    return last;
}

uint32_t Crypto1Word(uint64_t key, uint32_t in, bool is_encrypted)
{
    return Crypto1WordSequence(key, &in, &is_encrypted, 1, nullptr);
}

bool VerifyAuthTrace(uint32_t uid, const AuthTrace& trace, uint64_t key)
{
    // Port of crypto1.py:Crypto1.mfkey32_is_reader_has_key()
    struct Crypto1State state;
    crypto1_init(&state, key);

    crypto1_word(&state, uid ^ trace.nt, 0);  // ks0, discarded
    crypto1_word(&state, trace.nr, 1);        // ks1, discarded
    const uint32_t ks2 = crypto1_word(&state, 0, 0);

    const uint32_t ar = trace.ar ^ ks2;
    return ar == prng_successor(trace.nt, 64);
}

// ---------------------------------------------------------------------------
// Memory accounting
// ---------------------------------------------------------------------------

namespace {

/// Upstream constants (crapto1.c lfsr_recovery32): two candidate tables of
/// 2^21 uint32_t and a 2^18 entry state list.
///
/// Note what is *not* here: upstream additionally allocates 2 x 256 buckets of
/// 2^14 entries for bucket_sort_intersect(), another 32 MB. This port sorts the
/// candidate tables in place instead (see radix_sort_u32), so that scratch no
/// longer exists and must not be counted. Counting it made the guard below ask
/// for 50 MB on a board with ~24 MB free, so every recovery on the real Tab5
/// failed with OutOfMemory before it started.
constexpr size_t kOddTableBytes  = sizeof(uint32_t) * (1u << 21);
constexpr size_t kEvenTableBytes = sizeof(uint32_t) * (1u << 21);
constexpr size_t kStateListBytes = sizeof(uint32_t) * 2 * (1u << 18);

}  // namespace

size_t FreePsramBytes()
{
    return heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
}

size_t Mfkey32RequiredBytes()
{
    return kOddTableBytes + kEvenTableBytes + kStateListBytes;
}

// ---------------------------------------------------------------------------
// mfkey32
// ---------------------------------------------------------------------------

KeyRecoveryStatus Mfkey32(uint32_t uid, const AuthTrace& a, const AuthTrace& b, uint64_t* out_key)
{
    if (out_key == nullptr) {
        return KeyRecoveryStatus::BadArgument;
    }

    // lfsr_recovery32() allocates ~50 MB. The Tab5 has 32 MB of PSRAM which the
    // UI also draws from, so refuse cleanly instead of failing mid-allocation
    // and leaving the upstream code's error path to free half-built tables.
    const size_t required = Mfkey32RequiredBytes();
    const size_t free_psram = FreePsramBytes();
    if (free_psram < required) {
        ESP_LOGW(TAG, "not enough PSRAM for mfkey32: need %" PRIu32 ", have %" PRIu32, (uint32_t)required,
                 (uint32_t)free_psram);
        return KeyRecoveryStatus::OutOfMemory;
    }

    // nt' = nonce 64 steps after nt; the tag's response to an authentication is
    // nt' encrypted with the keystream word that follows the nonce exchange.
    const uint32_t p64 = prng_successor(a.nt, 64);
    const uint32_t ks2 = a.ar ^ p64;

    struct Crypto1State* states = lfsr_recovery32(ks2, 0);
    if (states == nullptr) {
        return KeyRecoveryStatus::OutOfMemory;
    }

    // Second authentication derives its own successor and its own keystream, so
    // it must be verified with uid ^ nt1 and p64b. This is the difference
    // between upstream mfkey32.c (which reuses the first nonce) and mfkey32v2.c
    // - the CLI uses v2, and only v2 is correct when the second authentication
    // carries a fresh nonce.
    const uint32_t p64b = prng_successor(b.nt, 64);

    KeyRecoveryStatus result = KeyRecoveryStatus::NotFound;

    for (struct Crypto1State* t = states; t->odd | t->even; ++t) {
        // Rewind the state to just before the first authentication and replay.
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, a.nr, 1);
        lfsr_rollback_word(t, uid ^ a.nt, 0);

        uint64_t key = 0;
        crypto1_get_lfsr(t, &key);

        // Replay the second authentication from the same state.
        crypto1_word(t, uid ^ b.nt, 0);
        crypto1_word(t, b.nr, 1);
        if (b.ar == (crypto1_word(t, 0, 0) ^ p64b)) {
            *out_key = key;
            result   = KeyRecoveryStatus::Found;
            break;
        }
    }

    free(states);

    if (result == KeyRecoveryStatus::Found) {
        ESP_LOGI(TAG, "mfkey32 recovered key %012" PRIX64, *out_key);
    } else {
        ESP_LOGI(TAG, "mfkey32 found no key for uid %08" PRIX32, uid);
    }
    return result;
}

}  // namespace crypto
}  // namespace chameleon
