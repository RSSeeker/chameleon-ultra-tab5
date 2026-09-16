// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tab5 port: the six symbols the upstream hardnested cores expect from the
// Proxmark3 application, implemented against ESP-IDF instead of pm3/ + Windows.
// Replaces upstream's "../pm3/ui.h", "../pm3/util_posix.h", <Windows.h>,
// <share.h>, <io.h> and compat/libfmemopen for the ported files.
//
// Why a shim instead of vendoring pm3/: the whole pm3 dependency of the cores
// boils down to `nm --undefined-only` on their objects, which lists exactly
// PrintAndLogEx, hardnested_print_progress, msclock, num_CPUs and fmemopen.
// Vendoring the Proxmark3 application layer (ui.c, util*.c, emojis.h, ...) to
// satisfy five functions would be the larger risk, not the smaller one.
//
// The host-side equivalents live in tools/host_stubs/pm3_shim.c. Keeping them
// separate is deliberate: the diff harness must compare the port against
// upstream, not against another copy of the harness.

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// pm3's logLevel_t. Upstream ui.h defines
///   enum logLevel {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG, INPLACE, HINT}
/// so the names and their order have to match, not just the ones used below:
/// the cores pass WARNING and DEBUG through to PrintAndLogEx.
typedef enum logLevel {
    NORMAL = 0,
    SUCCESS,
    INFO,
    FAILED,
    WARNING,
    ERR,
    DEBUG,
    INPLACE,
    HINT,
} logLevel_t;

/// pm3/common.h, verbatim (the non-MSVC branch; __builtin_bswap32 exists on RISC-V).
#ifndef BSWAP_32
#define BSWAP_32(x) __builtin_bswap32(x)
#endif

/// pm3/common.h, verbatim.
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/// pm3/ansi.h, verbatim (colour escapes included on purpose). These are only
/// used to build the progress strings the cores hand to
/// hardnested_print_progress(), and this port keeps them byte for byte so the
/// ported sources differ from upstream in their includes and nothing else.
#ifndef AEND
#define AEND  "\x1b[0m"
#define _RED_(s)            "\x1b[31m" s AEND
#define _GREEN_(s)          "\x1b[32m" s AEND
#define _YELLOW_(s)         "\x1b[33m" s AEND
#define _BLUE_(s)           "\x1b[34m" s AEND
#define _CYAN_(s)           "\x1b[36m" s AEND
#endif

#ifdef ESP_PLATFORM

#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_timer.h>

/// Upstream gets memalign() from <malloc.h>, which the core only includes on
/// non-Apple hosts and which this port skips on ESP. The cores use it for the
/// bitslice buffers, which belong in PSRAM, so route it there explicitly.
#ifndef memalign
#define memalign(align, size) heap_caps_aligned_alloc((align), (size), MALLOC_CAP_SPIRAM)
#endif

/// pm3 ui.c PrintAndLogEx -> the IDF logger. The cores use it for progress
/// chatter only, so INFO is the right level.
static inline void PrintAndLogEx(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (level >= WARNING) {
        esp_log_writev(ESP_LOG_WARN, "hardnested", fmt, args);
    } else {
        esp_log_writev(ESP_LOG_INFO, "hardnested", fmt, args);
    }
    va_end(args);
}

/// pm3 ui.c: progress reporting. The port reports through its own job status
/// text, so this is intentionally a no-op hook rather than a printf.
static inline void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force,
                                            uint64_t min_diff_print_time)
{
    (void)nonces;
    (void)activity;
    (void)brute_force;
    (void)min_diff_print_time;
}

/// pm3 util_posix.c: a millisecond clock.
static inline uint64_t msclock(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

/// pm3 util.c: the attack is single threaded here, and claiming otherwise would
/// make the port take a different code path than the oracle it is diffed against.
static inline int num_CPUs(void)
{
    return 1;
}

#else /* host build of the same header, for compile checks outside the firmware */

static inline void PrintAndLogEx(int level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

static inline void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force,
                                            uint64_t min_diff_print_time)
{
    (void)nonces;
    (void)activity;
    (void)brute_force;
    (void)min_diff_print_time;
}

static inline uint64_t msclock(void)
{
    return 0;
}

static inline int num_CPUs(void)
{
    return 1;
}

#endif

// No fmemopen() stub here, deliberately. Upstream ships compat/libfmemopen
// because MSVC lacks it; ESP-IDF's newlib already declares and defines it
// (adding one produced "static declaration of 'fmemopen' follows non-static
// declaration"). The host-side stub lives in tools/host_stubs/pm3_shim.c.

