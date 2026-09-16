// SPDX-License-Identifier: GPL-3.0-or-later
//
// Host-test stand-in for ESP-IDF's esp_heap_caps.h.
//
// tools/verify_crypto.py compiles the real mfkey32.cpp and crapto1.c on a PC.
// On the Tab5 those allocations request MALLOC_CAP_SPIRAM so the ~18 MB of
// recovery tables land in PSRAM instead of the 317 KB of internal SRAM; on the
// host that is just malloc.
//
// Deliberately a *thin* mapping: no header, no pointer offset. An earlier
// version added a 16 byte tracking header, which shifted every pointer and
// changed heap behaviour enough to produce a crash that did not exist in the
// real code. Memory accounting is done separately and non-invasively by
// host_alloc_tracker.h, which only renames the libc entry points.
//
// Included from C (crapto1.c) as well as C++, so plain C constructs only.
// Not part of the firmware build.

#ifndef HOST_ESP_HEAP_CAPS_STUB_H
#define HOST_ESP_HEAP_CAPS_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MALLOC_CAP_SPIRAM   0
#define MALLOC_CAP_INTERNAL 1

static inline void *heap_caps_malloc(size_t size, int caps)
{
    (void)caps;
    return malloc(size);
}

static inline void *heap_caps_calloc(size_t n, size_t size, int caps)
{
    (void)caps;
    return calloc(n, size);
}

static inline void *heap_caps_realloc(void *ptr, size_t size, int caps)
{
    (void)caps;
    return realloc(ptr, size);
}

static inline void heap_caps_free(void *ptr)
{
    free(ptr);
}

static inline size_t heap_caps_get_free_size(int caps)
{
    (void)caps;
    /* Report plenty so the device-side budget guard does not short-circuit the
       recovery path while testing on a PC. */
    return (size_t)1024 * 1024 * 1024;
}

#endif /* HOST_ESP_HEAP_CAPS_STUB_H */
