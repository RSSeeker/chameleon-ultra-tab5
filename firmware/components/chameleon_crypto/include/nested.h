// SPDX-License-Identifier: GPL-3.0-or-later
//
// Nested key recovery - Tab5 port of software/src/nested_util.c.
//
// The device does the collecting (MF1_NESTED_ACQUIRE / MF1_STATIC_NESTED_ACQUIRE
// hand back the {nt, nt_enc, par} triples); this is the half the official CLI
// runs on a PC as nested.exe.
//
// See src/nested.cpp for the three deliberate differences from upstream
// (single threaded, bounds-checked uniqsort, PSRAM allocations).

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace chameleon {
namespace crypto {

/// One {predicted nonce, keystream} pair, upstream's NtpKs1.
struct NestedNonce {
    uint32_t ntp = 0;
    uint32_t ks1 = 0;
};

/**
 * @brief Recover candidate keys from a nonce list.
 *
 * Every candidate is a guess: the caller has to confirm it against the card
 * (MF1_AUTH_ONE_KEY_BLOCK) before treating it as the key, which is what the
 * official CLI does as well.
 *
 * @param nonces       pairs collected by MF1_NESTED_ACQUIRE, with `ntp` set to
 *                     the predicted nonce (see the CLI: nt ^ uid)
 * @param count        number of pairs
 * @param authuid      the card uid
 * @param out_keys     receives up to out_capacity candidates, best first
 * @param out_capacity capacity of out_keys
 * @param out_count    receives the number of candidates found (may exceed
 *                     out_capacity, in which case only the first are written)
 * @return size_t      number of candidates written
 */
size_t NestedRecover(const NestedNonce* nonces, size_t count, uint32_t authuid, uint64_t* out_keys,
                     size_t out_capacity, size_t* out_count);

/// One (nt, nt_enc, par) triple as MF1_NESTED_ACQUIRE reports it.
struct NestedAcquireEntry {
    uint32_t nt     = 0;
    uint32_t nt_enc = 0;
    uint8_t par     = 0;
};

/**
 * @brief Derive the {ntp, ks1} pairs from a plain nested acquisition.
 *
 * Port of the argument handling in software/src/nested.c: for every acquired
 * triple it walks 29 PRNG positions (dist - 14 .. dist + 14) and keeps the ones
 * `valid_nonce` accepts.
 *
 * @param dist   PRNG distance from MF1_DETECT_NT_DIST
 * @param out    receives the derived pairs
 * @param max    capacity of out
 * @return size_t pairs written
 */
size_t NestedDerive(uint32_t dist, const NestedAcquireEntry* entries, size_t count, NestedNonce* out, size_t max);

/// Convenience: NestedDerive() followed by NestedRecover().
size_t NestedRecoverFromAcquire(uint32_t uid, uint32_t dist, const NestedAcquireEntry* entries, size_t count,
                                uint64_t* out_keys, size_t out_capacity, size_t* out_count);

/**
 * @brief Port of nested_util.c valid_nonce().
 *
 * Predicate used to drop nonces whose parity cannot belong to the key.
 */
uint8_t NestedValidNonce(uint32_t nt, uint32_t nt_enc, uint32_t ks1, const uint8_t* parity);

/// One (nt, nt_enc) pair as MF1_STATIC_NESTED_ACQUIRE reports it.
struct StaticNestedPair {
    uint32_t nt     = 0;
    uint32_t nt_enc = 0;
};

/**
 * @brief Derive the {ntp, ks1} pairs from a static-nested acquisition.
 *
 * Port of the argument handling in software/src/staticnested.c: the first `nt`
 * identifies the tag generation, which fixes the initial PRNG distance, and
 * every following pair advances that distance by 160.
 *
 *   nt == 0x01200145  static gen1, distance starts at 160
 *   nt == 0x009080A2  static gen2, 161 for key B (0x61), 160 for key A (0x60)
 *
 * Split out from StaticNestedRecover() so the derivation can be verified on its
 * own - it is the only part of this attack that is not shared with plain nested.
 *
 * @param key_type 0x60 (key A) or 0x61 (key B)
 * @param out      receives the derived pairs
 * @param max      capacity of out
 * @return size_t  pairs written, or 0 when the first nt identifies no known generation
 */
size_t StaticNestedDerive(uint8_t key_type, const StaticNestedPair* pairs, size_t pair_count, NestedNonce* out,
                          size_t max);

/**
 * @brief Static-nested key recovery: derive, then run the nested search.
 *
 * @return size_t number of candidates written to out_keys
 */
size_t StaticNestedRecover(uint32_t uid, uint8_t key_type, const StaticNestedPair* pairs, size_t pair_count,
                           uint64_t* out_keys, size_t out_capacity, size_t* out_count);

}  // namespace crypto
}  // namespace chameleon
