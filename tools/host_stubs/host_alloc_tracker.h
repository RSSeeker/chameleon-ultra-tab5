// SPDX-License-Identifier: GPL-3.0-or-later
//
// Non-invasive host allocation tracker for the crypto tests.
//
// tools/verify_crypto.py force-includes this (-include) when compiling
// crapto1.c for the host. It only intercepts the libc allocation names, so the
// code under test is byte-identical to the firmware source and no wrapper
// allocator sits in the middle. That matters: an earlier attempt used a
// stub that offset every pointer by a 16 byte header, which changed heap
// behaviour enough to mask (and mis-attribute) a genuine problem.
//
// The peak is what decides whether the key recovery fits in the Tab5's PSRAM.

#ifndef HOST_ALLOC_TRACKER_H
#define HOST_ALLOC_TRACKER_H

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Real libc entry points, captured before the macros below are defined. */
extern void *(*host_real_malloc)(size_t);
extern void (*host_real_free)(void *);
extern void *(*host_real_calloc)(size_t, size_t);
extern void *(*host_real_realloc)(void *, size_t);

extern size_t host_alloc_current;
extern size_t host_alloc_peak;
extern size_t host_alloc_total;
extern size_t host_alloc_mallocs;

/* These are only meaningful for pointers this tracker handed out; the test
   harness allocates the arrays it checks. */
void *host_track_malloc(size_t size);
void *host_track_calloc(size_t n, size_t size);
void *host_track_realloc(void *ptr, size_t size);
void host_track_free(void *ptr);

/// Reset the peak/total counters (call before the code under measurement).
void host_alloc_reset_stats(void);

#ifdef __cplusplus
}
#endif

#define malloc(n)       host_track_malloc(n)
#define calloc(n, s)    host_track_calloc((n), (s))
#define realloc(p, n)   host_track_realloc((p), (n))
#define free(p)         host_track_free(p)

#endif /* HOST_ALLOC_TRACKER_H */
