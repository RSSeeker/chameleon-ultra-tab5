// SPDX-License-Identifier: GPL-3.0-or-later
//
// Darkside key search - see darkside.h for the control flow being mirrored.

#include "darkside.h"

#include <stdlib.h>
#include <string.h>

#include <esp_heap_caps.h>
#include <esp_log.h>

extern "C" {
#include "mfkey.h"
}

static const char* TAG = "darkside";

namespace chameleon {
namespace crypto {

namespace {

/// nonce2key() hands back a block that lfsr_common_prefix() allocated with
/// CP_MALLOC, i.e. heap_caps_malloc(..., MALLOC_CAP_SPIRAM). It has to be
/// released with the matching PSRAM free: plain free() on a PSRAM pointer
/// corrupts the heap.
void FreeNonceList(uint64_t* list)
{
    if (list != nullptr) {
        heap_caps_free(list);
    }
}

}  // namespace

DarksideSearch::~DarksideSearch()
{
    Reset();
}

void DarksideSearch::Reset()
{
    FreeNonceList(_last);
    _last       = nullptr;
    _last_count = 0;
    _has_last   = false;
}

size_t DarksideSearch::Feed(const DarksideNonce& n, uint64_t* out, size_t out_capacity, size_t* total)
{
    if (total != nullptr) {
        *total = 0;
    }
    if (out == nullptr || out_capacity == 0) {
        return 0;
    }

    // The CLI throws away everything collected so far when par != 0 (the "NXP
    // tag workaround"). In darkside.c terms that is a fresh run, i.e. no
    // previous key list to intersect with.
    if (n.par != 0) {
        Reset();
    }

    uint64_t* keys = nullptr;
    const uint32_t count = nonce2key(n.uid, n.nt, n.nr, n.ar, n.par, n.ks, &keys);

    if (keys == nullptr) {
        return 0;
    }
    if (count == 0) {
        // nonce2key() can return 0 with a *valid* pointer: it hands back the
        // buffer lfsr_common_prefix() allocated, which holds a single zero
        // terminator when no state passed the parity checks. That buffer is
        // ~1.7 MB, and the common case for a card that does not answer the
        // attack is exactly this - so skipping the free here leaks 1.7 MB per
        // attempt and exhausts PSRAM within ~14 of the 60 attempts.
        //
        // (Upstream software/src/darkside.c has the same leak; it is a
        // short-lived process, so nobody noticed.)
        FreeNonceList(keys);
        return 0;
    }

    const uint64_t* report = nullptr;
    size_t report_count = 0;

    if (n.par == 0) {
        // Parity zero attack: only keys common to two independent collections
        // are worth keeping. intersection() needs sorted, -1 terminated lists
        // and writes its result back into the first one.
        qsort(keys, count, sizeof(uint64_t), compare_uint64);

        if (!_has_last) {
            // darkside.c stores this list and moves on without reporting.
            _last       = keys;
            _last_count = count;
            _has_last   = true;
            ESP_LOGI(TAG, "first parity-zero list stored: %u candidates", (unsigned)count);
            return 0;
        }

        const uint32_t common = intersection(_last, keys);
        if (common == 0) {
            // darkside.c: free(last_keylist); last_keylist = keylist. Restart
            // the running intersection from this acquisition.
            FreeNonceList(_last);
            _last       = keys;
            _last_count = count;
            ESP_LOGI(TAG, "no intersection, restarting with %u candidates", (unsigned)count);
            return 0;
        }

        // _last now holds the intersection in place; the fresh list is no
        // longer needed. (darkside.c leaks it.)
        FreeNonceList(keys);
        _last_count = common;
        report      = _last;
        report_count = common;
        ESP_LOGI(TAG, "intersection: %u candidate(s)", (unsigned)common);
    } else {
        report       = keys;
        report_count = count;
        ESP_LOGI(TAG, "parity non-zero: %u candidate(s)", (unsigned)count);
    }

    if (total != nullptr) {
        *total = report_count;
    }

    const size_t copy = (report_count < out_capacity) ? report_count : out_capacity;
    memcpy(out, report, copy * sizeof(uint64_t));

    if (n.par != 0) {
        FreeNonceList(keys);
    }
    return copy;
}

}  // namespace crypto
}  // namespace chameleon
