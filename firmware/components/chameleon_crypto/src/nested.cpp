// SPDX-License-Identifier: GPL-3.0-or-later
//
// Nested key recovery - Tab5 port of software/src/nested_util.c.
//
// The device collects the material (MF1_NESTED_ACQUIRE returns {nt, nt_enc, par}
// triples); this is the cracking half that the official CLI runs on a PC as
// nested.exe.
//
// Differences from upstream, all deliberate:
//
//  1. SINGLE THREADED. Upstream splits the nonce list across four pthreads and
//     merges the results. The nonce list is a few dozen to a few hundred entries
//     and each entry is an independent lfsr_recovery32() call, so running them
//     in sequence produces the same key set; the only thing threading bought was
//     wall clock time on a PC. Doing it in one pass removes the need to rewrite
//     pthread_create/pthread_join as FreeRTOS tasks, and makes the result
//     deterministic (upstream's merge order depends on thread completion).
//
//  2. uniqsort()'s out of bounds read is bounded. Upstream does
//        for (i = 0; i < size; i++)
//            if (possibleKeys[i + 1] == possibleKeys[i])
//     which reads past the end of the array on the last iteration. The result is
//     then fed to a count-based ranking, so that read can change which key wins.
//     Here the last element is always flushed instead of being compared against
//     whatever the allocator left next door. tools/probe_nested.py reports any
//     resulting difference explicitly rather than hiding it.
//
//  3. Memory comes from PSRAM (CP_MALLOC equivalent) and every allocation is
//     checked; upstream calls exit(EXIT_FAILURE) on a failed calloc, which on a
//     microcontroller would reboot the board.

#include "nested.h"

#include <stdlib.h>
#include <string.h>

#include <esp_heap_caps.h>
#include <esp_log.h>

extern "C" {
#include "crapto1.h"
#include "parity.h"
}

static const char* TAG = "nested";

namespace chameleon {
namespace crypto {

namespace {

/// Upstream's MEM_CHUNK (nested_util.c:19): keys are appended in blocks of this
/// many. Read from the source - the first version of this port guessed 256 and
/// the only thing that caught it was tools/probe_nested.py comparing candidate
/// sets against nested.exe.
constexpr uint32_t kMemChunk = 10000;
/// Upstream's TRY_KEYS (nested_util.c:20): how many of the highest scoring
/// candidates are returned. Guessed as 256 at first; upstream says 50.
constexpr uint32_t kTryKeys = 50;

void* psramMalloc(size_t size)
{
    return heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
}

void psramFree(void* ptr)
{
    if (ptr != nullptr) {
        heap_caps_free(ptr);
    }
}

int compareU64Ascending(const void* a, const void* b)
{
    const uint64_t x = *static_cast<const uint64_t*>(a);
    const uint64_t y = *static_cast<const uint64_t*>(b);
    if (x == y) {
        return 0;
    }
    return (x < y) ? -1 : 1;
}

/// countKeys from nested_util.h: a key plus how many nonces produced it.
struct CountKeys {
    uint64_t key;
    uint32_t count;
};

int compareCountDescending(const void* a, const void* b)
{
    const auto* x = static_cast<const CountKeys*>(a);
    const auto* y = static_cast<const CountKeys*>(b);
    if (x->count == y->count) {
        return 0;
    }
    return (x->count < y->count) ? 1 : -1;
}

/**
 * @brief Sort and count duplicates, highest count first.
 *
 * @param keys   modified in place (sorted)
 * @param size   number of keys
 * @param out_n  receives the number of distinct keys
 * @return array of distinct keys with their counts, or null
 */
CountKeys* uniqSort(uint64_t* keys, uint32_t size, uint32_t* out_n)
{
    *out_n = 0;
    if (keys == nullptr || size == 0) {
        return nullptr;
    }

    qsort(keys, size, sizeof(uint64_t), compareU64Ascending);

    CountKeys* counts = static_cast<CountKeys*>(psramMalloc(sizeof(CountKeys) * size));
    if (counts == nullptr) {
        return nullptr;
    }

    uint32_t distinct = 0;
    uint32_t run      = 0;
    for (uint32_t i = 0; i < size; ++i) {
        ++run;
        // Upstream compares keys[i + 1] here, reading one past the end on the
        // final iteration; flush at the boundary instead.
        const bool last = (i + 1 == size) || (keys[i + 1] != keys[i]);
        if (last) {
            counts[distinct].key = keys[i];
            // Upstream stores the number of *duplicates beyond the first*, not
            // the total: its `count` is only incremented when two neighbours are
            // equal and is reset on every write, so a key seen once scores 0 and
            // nested() drops it. Storing the total here instead would return
            // single-occurrence keys that the official nested.exe never emits,
            // which is exactly the kind of "looks fine, different answer" bug
            // this probe exists to catch.
            counts[distinct].count = run - 1;
            ++distinct;
            run = 0;
        }
    }

    qsort(counts, distinct, sizeof(CountKeys), compareCountDescending);
    *out_n = distinct;
    return counts;
}

}  // namespace

uint8_t NestedValidNonce(uint32_t nt, uint32_t nt_enc, uint32_t ks1, const uint8_t* parity)
{
    if (parity == nullptr) {
        return 0;
    }
    // Verbatim from nested_util.c valid_nonce().
    return (oddparity8((nt >> 24) & 0xFF) == (parity[0] ^ oddparity8((nt_enc >> 24) & 0xFF) ^ BIT(ks1, 16))) &&
                   (oddparity8((nt >> 16) & 0xFF) == (parity[1] ^ oddparity8((nt_enc >> 16) & 0xFF) ^ BIT(ks1, 8))) &&
                   (oddparity8((nt >> 8) & 0xFF) == (parity[2] ^ oddparity8((nt_enc >> 8) & 0xFF) ^ BIT(ks1, 0)))
               ? 1
               : 0;
}

size_t NestedRecover(const NestedNonce* nonces, size_t count, uint32_t authuid, uint64_t* out_keys,
                     size_t out_capacity, size_t* out_count)
{
    if (out_count == nullptr) {
        return 0;
    }
    *out_count = 0;
    if (nonces == nullptr || count == 0) {
        return 0;
    }

    // ---- gather every candidate key, exactly as nested_revover() does ----
    uint64_t* keys     = nullptr;
    uint32_t key_cap   = 0;
    uint32_t kcount    = 0;
    bool ok            = true;

    for (size_t i = 0; i < count && ok; ++i) {
        const uint32_t nt_probe = nonces[i].ntp ^ authuid;
        const uint32_t ks1      = nonces[i].ks1;

        struct Crypto1State* revstate = lfsr_recovery32(ks1, nt_probe);
        if (revstate == nullptr) {
            // Upstream would dereference null here; a failed recovery just means
            // this nonce contributed nothing.
            continue;
        }
        struct Crypto1State* const revstate_start = revstate;

        uint64_t lfsr = 0;
        while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
            lfsr_rollback_word(revstate, nt_probe, 0);
            crypto1_get_lfsr(revstate, &lfsr);

            if (((kcount % kMemChunk) == 0) || (kcount >= key_cap)) {
                key_cap += kMemChunk;
                void* tmp = heap_caps_realloc(keys, key_cap * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
                if (tmp == nullptr) {
                    ESP_LOGE(TAG, "out of memory growing the candidate list");
                    ok = false;
                    break;
                }
                keys = static_cast<uint64_t*>(tmp);
            }
            keys[kcount] = lfsr;
            ++kcount;
            ++revstate;
        }
        psramFree(revstate_start);

        // Upstream's `--kcount` drops the last candidate of every nonce (it
        // counts one more state than it keeps). Kept as-is so the port stays
        // comparable to nested.exe; probe_nested.py measures the effect.
        if (kcount > 0) {
            --kcount;
        }
    }

    if (!ok || kcount == 0) {
        psramFree(keys);
        return 0;
    }

    // ---- rank by how many nonces agreed, keep the top TRY_KEYS ----
    uint32_t distinct = 0;
    CountKeys* counts = uniqSort(keys, kcount, &distinct);
    psramFree(keys);
    if (counts == nullptr) {
        ESP_LOGE(TAG, "out of memory ranking the candidates");
        return 0;
    }

    size_t written = 0;
    for (uint32_t i = 0; i < kTryKeys && i < distinct; ++i) {
        if (counts[i].count == 0) {
            continue;
        }
        if (written < out_capacity && out_keys != nullptr) {
            out_keys[written] = counts[i].key;
        }
        ++written;
    }
    psramFree(counts);

    *out_count = written;
    ESP_LOGI(TAG, "nested: %u candidates from %u nonces", (unsigned)distinct, (unsigned)count);
    return written;
}

size_t NestedDerive(uint32_t dist, const NestedAcquireEntry* entries, size_t count, NestedNonce* out, size_t max)
{
    if (entries == nullptr || out == nullptr || count == 0 || max == 0 || dist < 14) {
        return 0;
    }

    size_t written = 0;
    uint8_t par[3] = {0, 0, 0};

    for (size_t i = 0; i < count; ++i) {
        // nested.c: bit m of the packed parity belongs to par_arr[m]; a zero
        // parity byte means "no parity information", not "all zero bits".
        if (entries[i].par != 0) {
            for (size_t m = 0; m < 3; ++m) {
                par[m] = (entries[i].par >> m) & 0x01;
            }
        } else {
            memset(par, 0, sizeof(par));
        }

        uint32_t nttest = prng_successor(entries[i].nt, dist - 14);
        for (uint32_t m = dist - 14; m <= dist + 14; ++m) {
            const uint32_t ks1 = entries[i].nt_enc ^ nttest;
            if (NestedValidNonce(nttest, entries[i].nt_enc, ks1, par)) {
                if (written >= max) {
                    // Truncating would silently drop candidates upstream keeps;
                    // report it instead of pretending the list is complete.
                    ESP_LOGW(TAG, "nested: derived list truncated at %u entries", (unsigned)max);
                    return written;
                }
                out[written].ntp = nttest;
                out[written].ks1 = ks1;
                ++written;
            }
            nttest = prng_successor(nttest, 1);
        }
    }
    return written;
}

size_t NestedRecoverFromAcquire(uint32_t uid, uint32_t dist, const NestedAcquireEntry* entries, size_t count,
                               uint64_t* out_keys, size_t out_capacity, size_t* out_count)
{
    if (out_count == nullptr) {
        return 0;
    }
    *out_count = 0;
    if (entries == nullptr || count == 0) {
        return 0;
    }

    // Up to 29 derived pairs per acquired triple.
    const size_t capacity = count * 29;
    NestedNonce* derived  = static_cast<NestedNonce*>(psramMalloc(sizeof(NestedNonce) * capacity));
    if (derived == nullptr) {
        ESP_LOGE(TAG, "out of memory deriving the nested nonces");
        return 0;
    }

    const size_t derived_count = NestedDerive(dist, entries, count, derived, capacity);
    size_t written             = 0;
    if (derived_count > 0) {
        written = NestedRecover(derived, derived_count, uid, out_keys, out_capacity, out_count);
    }
    psramFree(derived);
    return written;
}

size_t StaticNestedDerive(uint8_t key_type, const StaticNestedPair* pairs, size_t pair_count, NestedNonce* out,
                          size_t max)
{
    if (pairs == nullptr || out == nullptr || pair_count == 0 || max == 0) {
        return 0;
    }

    // staticnested.c decides the PRNG distance once, from the FIRST pair, and
    // bails out entirely if the tag is not one of the two known static
    // generations.
    uint32_t dist = 0;
    switch (pairs[0].nt) {
        case 0x01200145:  // static gen1
            dist = 160;
            break;
        case 0x009080A2:  // static gen2; the offset depends on the attacked key
            if (key_type == 0x61) {
                dist = 161;
            } else if (key_type == 0x60) {
                dist = 160;
            } else {
                return 0;
            }
            break;
        default:
            return 0;
    }

    const size_t n = (pair_count < max) ? pair_count : max;
    for (size_t i = 0; i < n; ++i) {
        const uint32_t nttest = prng_successor(pairs[i].nt, dist);
        out[i].ntp            = nttest;
        out[i].ks1            = pairs[i].nt_enc ^ nttest;
        dist += 160;
    }
    return n;
}

size_t StaticNestedRecover(uint32_t uid, uint8_t key_type, const StaticNestedPair* pairs, size_t pair_count,
                           uint64_t* out_keys, size_t out_capacity, size_t* out_count)
{
    if (out_count == nullptr) {
        return 0;
    }
    *out_count = 0;
    if (pairs == nullptr || pair_count == 0) {
        return 0;
    }

    NestedNonce* derived = static_cast<NestedNonce*>(psramMalloc(sizeof(NestedNonce) * pair_count));
    if (derived == nullptr) {
        ESP_LOGE(TAG, "out of memory deriving the static nested nonces");
        return 0;
    }

    const size_t derived_count = StaticNestedDerive(key_type, pairs, pair_count, derived, pair_count);
    if (derived_count == 0) {
        psramFree(derived);
        // Plain %08X with a cast: PRIX32 needs <inttypes.h>, which the firmware
        // headers pull in transitively but the host log stub does not.
        ESP_LOGW(TAG, "static nested: first nt %08X is not a known static generation", (unsigned)pairs[0].nt);
        return 0;
    }

    const size_t written = NestedRecover(derived, derived_count, uid, out_keys, out_capacity, out_count);
    psramFree(derived);
    return written;
}

}  // namespace crypto
}  // namespace chameleon
