// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tracker implementation for tools/host_stubs/host_alloc_tracker.h.
//
// Compiled *without* the tracker macros, so it can reach the real libc
// allocator. Every allocation gets an 8 byte header recording its size; the
// header is invisible to the caller, so the returned pointer has the same
// alignment libc would have produced.

#include <stddef.h>
#include <stdlib.h>

void *(*host_real_malloc)(size_t)        = malloc;
void (*host_real_free)(void *)           = free;
void *(*host_real_calloc)(size_t, size_t) = calloc;
void *(*host_real_realloc)(void *, size_t) = realloc;

size_t host_alloc_current = 0;
size_t host_alloc_peak    = 0;
size_t host_alloc_total   = 0;
size_t host_alloc_mallocs = 0;

void host_alloc_reset_stats(void)
{
    host_alloc_current = 0;
    host_alloc_peak    = 0;
    host_alloc_total   = 0;
    host_alloc_mallocs = 0;
}

static void *track(size_t size, void *raw)
{
    if (raw == NULL) {
        return NULL;
    }
    ((size_t *)raw)[0] = size;
    host_alloc_current += size;
    host_alloc_total += size;
    ++host_alloc_mallocs;
    if (host_alloc_current > host_alloc_peak) {
        host_alloc_peak = host_alloc_current;
    }
    /* +8 keeps the payload aligned to 16 bytes, matching libc on x86-64. */
    return (char *)raw + 16;
}

void *host_track_malloc(size_t size)
{
    return track(size, host_real_malloc(size + 16));
}

void *host_track_calloc(size_t n, size_t size)
{
    const size_t total = n * size;
    void *raw          = host_real_calloc(1, total + 16);
    return track(total, raw);
}

void *host_track_realloc(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return host_track_malloc(size);
    }
    char *base = (char *)ptr - 16;
    const size_t old = ((size_t *)base)[0];

    char *raw = (char *)host_real_realloc(base, size + 16);
    if (raw == NULL) {
        return NULL;
    }
    host_alloc_current -= old;
    ((size_t *)raw)[0] = size;
    host_alloc_current += size;
    host_alloc_total += size;
    if (host_alloc_current > host_alloc_peak) {
        host_alloc_peak = host_alloc_current;
    }
    return raw + 16;
}

void host_track_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    char *base = (char *)ptr - 16;
    host_alloc_current -= ((size_t *)base)[0];
    host_real_free(base);
}
