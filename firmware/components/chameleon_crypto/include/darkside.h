// SPDX-License-Identifier: GPL-3.0-or-later
//
// Darkside key search - Tab5 port of software/src/darkside.c.
//
// The Chameleon Ultra does the RF side of the darkside attack itself: each
// MF1_DARKSIDE_ACQUIRE returns the material it managed to collect for one
// candidate nonce (uid, nt, nr, ar plus the observed parity and keystream
// bits). Turning that into a key is what darkside.exe does on a PC, using
// nonce2key() from mfkey.c.
//
// This class does the same loop in-process, one acquisition at a time, so the
// Tab5 can recover a key without a PC. The official CLI's control flow is:
//
//   first = True
//   for retry in range(255):
//       resp = mf1_darkside_acquire(block, type, first, sync_max=30)
//       first = False
//       if resp.status != OK: break
//       if resp.par != 0: collected.clear()      # NXP tag workaround
//       collected.append(resp)
//       keys = darkside(collected)               # nonce2key + intersection
//       for key in keys:
//           if mf1_auth_one_key_block(block, type, key): return key
//
// Feed() implements the "keys = darkside(collected)" line incrementally, which
// is equivalent to re-running darkside.c over the whole collected list each
// time (the loop there carries `last_keylist` across items, so only the newest
// item changes the result).
//
// IMPORTANT: a candidate key is only a candidate. The caller must confirm it
// with MF1_AUTH_ONE_KEY_BLOCK before reporting it as recovered - that is what
// the CLI does, and it is the only thing standing between a wrong candidate and
// a wrong answer.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace chameleon {
namespace crypto {

/// One MF1_DARKSIDE_ACQUIRE result.
struct DarksideNonce {
    uint32_t uid = 0;
    uint32_t nt  = 0;  ///< the tag nonce the device used for this attempt
    uint32_t nr  = 0;
    uint32_t ar  = 0;
    uint64_t ks  = 0;  ///< 8 packed keystream nibbles
    uint64_t par = 0;  ///< 8 packed parity bytes
};

/**
 * @brief Incremental darkside key search.
 *
 * Holds the running intersection of candidate keys across acquisitions. Both the
 * running list and the per-acquisition list are full size (a "parity zero"
 * round can produce ~200k candidates, ~1.7 MB), so they live in PSRAM and are
 * owned by this object.
 */
class DarksideSearch {
public:
    DarksideSearch() = default;
    ~DarksideSearch();

    DarksideSearch(const DarksideSearch&)            = delete;
    DarksideSearch& operator=(const DarksideSearch&) = delete;

    /// Forget the running intersection. Always safe to call.
    void Reset();

    /// True once the first "parity zero" candidate list has been stored.
    bool started() const
    {
        return _has_last;
    }

    /// Number of keys in the running list (0 until a round produces a match).
    size_t lastCount() const
    {
        return _last_count;
    }

    /**
     * @brief Feed one acquisition and collect whatever survived.
     *
     * @param n             one MF1_DARKSIDE_ACQUIRE result
     * @param out           receives candidate keys (may be smaller than the
     *                      total; callers verify candidates with the card)
     * @param out_capacity  entries available in out
     * @param total         receives the total candidate count before the copy
     * @return size_t       number of keys written to out
     */
    size_t Feed(const DarksideNonce& n, uint64_t* out, size_t out_capacity, size_t* total);

private:
    uint64_t* _last      = nullptr;
    size_t _last_count   = 0;
    bool _has_last       = false;
};

}  // namespace crypto
}  // namespace chameleon
