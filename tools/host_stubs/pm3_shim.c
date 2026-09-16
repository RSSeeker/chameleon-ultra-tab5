// SPDX-License-Identifier: GPL-3.0-or-later
//
// Host-side stand-ins for the Proxmark3 plumbing the hardnested cores need.
//
// The three cores (hardnested_bf_core.c, hardnested_bitarray_core.c,
// hardnested_bruteforce.c) compile unmodified on this machine - MinGW has
// Windows.h, intrin.h, __popcnt64 and pthread - so the upstream objects are the
// oracle for diffing a port against. What they do NOT have is a linkable
// implementation of six symbols they expect from the Proxmark3 application:
//
//   nm --undefined-only on the three objects lists exactly these
//   (everything else is libc, or crypto1/crapto1, or core-to-core):
//
//   PrintAndLogEx, hardnested_print_progress, msclock, num_CPUs, fmemopen
//
// This file supplies them, so the oracle links into a runnable program. It is
// deliberately NOT the port: the port needs the same six symbols implemented
// against ESP-IDF (ESP_LOGI, esp_timer, a no-op fmemopen), and keeping the host
// versions separate means the port's own shims get diffed, not these.
//
// Not part of the firmware build.

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- pm3 log ------------------------------------------------------------ */
/* logLevel_t is an enum in pm3/ui.h; the cores only ever pass values through,
   so an int here keeps this file independent of that header. */
void PrintAndLogEx(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    /* Quiet by default: a diff run must not drown the actual output. Set
       HN_VERBOSE=1 to see the cores' own progress chatter. */
    if (getenv("HN_VERBOSE") != NULL) {
        fprintf(stderr, "[pm3 %d] ", level);
        vfprintf(stderr, fmt, args);
        fputc('\n', stderr);
    }
    va_end(args);
}

/* ---- progress ----------------------------------------------------------- */
void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time)
{
    (void)min_diff_print_time;
    if (getenv("HN_VERBOSE") != NULL) {
        fprintf(stderr, "[progress] %u nonces, %s, bf %.1f\n", nonces, activity ? activity : "", brute_force);
    }
}

/* ---- pm3 util ----------------------------------------------------------- */

uint64_t msclock(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int num_CPUs(void)
{
    /* One: the port is single threaded, so pretending there are more would let
       the oracle take a different code path than the thing being compared. */
    return 1;
}

/* ---- fmemopen ----------------------------------------------------------- */
/* Only the benchmark path uses it, and that path is not exercised here. A
   minimal, honest implementation beats a fake one that silently returns a file
   nobody can read. */
FILE *fmemopen(void *buf, size_t len, const char *type)
{
    (void)buf;
    (void)len;
    (void)type;
    fprintf(stderr, "fmemopen: not implemented in the host shim\n");
    return NULL;
}
