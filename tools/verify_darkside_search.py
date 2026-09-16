"""Exercise DarksideSearch::Feed itself, against the upstream oracle.

tools/probe_darkside.py proves the *algorithm* (nonce2key) matches upstream. This
one covers the piece that is NOT a port: firmware/components/chameleon_crypto/
src/darkside.cpp was written by hand to replace software/src/darkside.c's main
loop with an incremental version, and nothing has ever executed it - it is only
compiled. Its risks are all memory-shaped:

  * the running candidate list is owned across calls (stored, intersected in
    place, replaced, freed), and darkside.c leaks one list per round,
  * intersection() writes back into the first list and needs both lists sorted
    and -1 terminated,
  * a candidate list can be ~1.8 MB, so only a slice may be copied out.

Checks:
  1. first feed stores without reporting (darkside.c semantics)
  2. feeding the SAME acquisition again intersects it with itself, so the whole
     list comes back - and the keys equal what upstream nonce2key produces for
     that input
  3. the returned slice is capped by out_capacity while *total* reports the real
     count (the caller must know it is not seeing everything)
  4. par != 0 resets the running state (the CLI's NXP workaround)
  5. Reset()/destructor release everything - verified via the host allocator,
     which is why this test is worth having at all
  6. defensive: null / zero-capacity output is refused without touching memory

Usage:  python tools/verify_darkside_search.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Where the reference ChameleonUltra checkout lives. The probes compare the port
# against upstream sources, so point this at your own checkout of
# https://github.com/chameleonultra/ChameleonUltra if it is somewhere else:
#     $env:CU_UPSTREAM = "D:\src\ChameleonUltra"
CU_UPSTREAM = Path(os.environ.get("CU_UPSTREAM", r"C:\Users\Jiang\Downloads\ChameleonUltra-main"))


REPO = Path(__file__).resolve().parent.parent
MINE = REPO / "firmware" / "components" / "chameleon_crypto"
UPSTREAM = CU_UPSTREAM / "software" / "src"
HOST_STUBS = REPO / "tools" / "host_stubs"
GCC = Path(r"C:\mingw64\bin\g++.exe")

# Firmware side: the real DarksideSearch plus the real crypto sources.
SEARCH_HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "darkside.h"
#include "esp_heap_caps.h"
#include "host_alloc_tracker.h"

using namespace chameleon::crypto;

/* parse "AA,BB,..." into out, returns the count */
static size_t parse_keys(const char* text, uint64_t* out, size_t cap) {
    size_t n = 0;
    const char* p = text;
    while (*p != '\0' && n < cap) {
        char* end = nullptr;
        unsigned long long v = strtoull(p, &end, 16);
        if (end == p) break;
        out[n++] = (uint64_t)v;
        p = end;
        if (*p == ',') ++p;
    }
    return n;
}

/* feed <uid> <nt> <nr> <ar> <par> <ks> <times> <cap>
   Feeds the same acquisition <times> times and prints one line per call. */
static int cmd_feed(int argc, char** argv) {
    if (argc < 9) return 2;

    DarksideNonce n;
    n.uid = (uint32_t)strtoul(argv[1], NULL, 16);
    n.nt  = (uint32_t)strtoul(argv[2], NULL, 16);
    n.nr  = (uint32_t)strtoul(argv[3], NULL, 16);
    n.ar  = (uint32_t)strtoul(argv[4], NULL, 16);
    n.par = strtoull(argv[5], NULL, 16);
    n.ks  = strtoull(argv[6], NULL, 16);
    const int times = atoi(argv[7]);
    const size_t cap = (size_t)strtoul(argv[8], NULL, 0);

    uint64_t* out = (uint64_t*)malloc(cap * sizeof(uint64_t));
    if (out == NULL) return 3;

    printf("baseline %zu\n", host_alloc_current);
    {
        DarksideSearch search;
        for (int i = 0; i < times; ++i) {
            size_t total = 0;
            const size_t got = search.Feed(n, out, cap, &total);
            printf("call %d returned %zu total %zu started %d current %zu", i, got, total,
                   search.started() ? 1 : 0, host_alloc_current);
            for (size_t k = 0; k < got; ++k) {
                printf(" %012" PRIX64, out[k]);
            }
            printf("\n");
        }
        search.Reset();
        printf("after_reset current %zu\n", host_alloc_current);
    }
    printf("after_scope current %zu\n", host_alloc_current);
    free(out);
    return 0;
}

/* guard <uid> <nt> <nr> <ar> <par> <ks> : output buffer edge cases */
static int cmd_guard(int argc, char** argv) {
    (void)argc;
    DarksideNonce n;
    n.uid = (uint32_t)strtoul(argv[1], NULL, 16);
    n.nt  = (uint32_t)strtoul(argv[2], NULL, 16);
    n.nr  = (uint32_t)strtoul(argv[3], NULL, 16);
    n.ar  = (uint32_t)strtoul(argv[4], NULL, 16);
    n.par = strtoull(argv[5], NULL, 16);
    n.ks  = strtoull(argv[6], NULL, 16);

    uint64_t one = 0;
    printf("baseline %zu\n", host_alloc_current);
    {
        DarksideSearch s;
        size_t total = 12345;
        const size_t a = s.Feed(n, NULL, 8, &total);   /* null buffer */
        printf("null_buffer returned %zu total %zu\n", a, total);
        total = 12345;
        const size_t b = s.Feed(n, &one, 0, &total);   /* zero capacity */
        printf("zero_capacity returned %zu total %zu\n", b, total);
        total = 12345;
        const size_t c = s.Feed(n, &one, 1, NULL);     /* null total out */
        printf("null_total returned %zu\n", c);
        /* The third call is valid, so it stores the candidate list; that is
           held until the search is destroyed, which is the point of printing
           the count after the scope rather than inside it. */
        printf("in_scope current %zu\n", host_alloc_current);
    }
    printf("after_scope current %zu\n", host_alloc_current);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "feed") == 0) return cmd_feed(argc - 1, argv + 1);
    if (strcmp(argv[1], "guard") == 0) return cmd_guard(argc - 1, argv + 1);
    return 2;
}
"""

# Oracle side: upstream nonce2key, printing at most N keys.
ORACLE_HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "mfkey.h"
}

/* n2k <uid> <nt> <nr> <ar> <par> <ks> <cap>
   Prints the key count and the first <cap> keys *sorted*, because the par==0
   path in darkside.c sorts before intersecting, so that is the order the
   firmware's Feed() hands back. */
int main(int argc, char** argv) {
    if (argc < 8) return 2;
    uint32_t uid = (uint32_t)strtoul(argv[1], NULL, 16);
    uint32_t nt  = (uint32_t)strtoul(argv[2], NULL, 16);
    uint32_t nr  = (uint32_t)strtoul(argv[3], NULL, 16);
    uint32_t ar  = (uint32_t)strtoul(argv[4], NULL, 16);
    uint64_t par = strtoull(argv[5], NULL, 16);
    uint64_t ks  = strtoull(argv[6], NULL, 16);
    const size_t cap = (size_t)strtoul(argv[7], NULL, 0);

    uint64_t* keys = NULL;
    const uint32_t n = nonce2key(uid, nt, nr, ar, par, ks, &keys);
    if (n > 0) {
        qsort(keys, n, sizeof(*keys), compare_uint64);
    }
    printf("%u", n);
    for (uint32_t i = 0; i < n && i < cap; ++i) {
        printf(" %012" PRIX64, keys[i]);
    }
    printf("\n");
    if (keys != NULL) free(keys);
    return 0;
}
"""


def build(out_dir, name, harness, mine):
    src = out_dir / f"{name}.cpp"
    src.write_text(harness, encoding="utf-8")
    exe = out_dir / f"{name}.exe"

    if mine:
        base = MINE / "src"
        inc = [HOST_STUBS, MINE / "include", MINE / "src"]
        extra = ["-include", str(HOST_STUBS / "host_alloc_tracker.h")]
        sources = ["crapto1.c", "mfkey.c", "crypto1.c", "parity.c", "bucketsort.c"]
        objs = [str(MINE / "src" / "darkside.cpp")]
    else:
        base = UPSTREAM
        inc = [UPSTREAM]
        extra = []
        sources = ["crapto1.c", "mfkey.c", "crypto1.c", "parity.c", "bucketsort.c"]
        objs = []

    args = [str(GCC), "-std=gnu++17", "-O2", "-w"]
    for d in inc:
        args += ["-I", str(d)]
    args.append(str(src))
    args += objs
    for s in sources:
        args += ["-x", "c", *extra, str(base / s)]
    args += [str(HOST_STUBS / "host_alloc_tracker.c"), "-o", str(exe)]

    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"build {name} failed:\n{res.stdout}\n{res.stderr}")
        sys.exit(1)
    return exe


def run(exe, argv):
    res = subprocess.run([str(exe), *argv], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  ! {argv[0]} exited {res.returncode}: {res.stderr.strip()[:300]}")
    return res.stdout.strip()


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    # Same input generator as probe_darkside.py, so these are the very cases the
    # upstream comparison already covers: case 0 yields a large key list.
    def lcg(state):
        return (state * 1103515245 + 12345) & 0xFFFFFFFF

    s = 0x1234ABCD
    s = lcg(s); uid = s
    s = lcg(s); nt = s
    s = lcg(s); nr = s
    s = lcg(s); ar = s
    s = lcg(s); ks = ((s & 0x0F0F0F0F) | ((s & 0x0F0F0F0F) << 4)) & 0xFFFFFFFF
    s = lcg(s); par_nonzero = s
    par_zero = 0

    feed_args = [f"{uid:08X}", f"{nt:08X}", f"{nr:08X}", f"{ar:08X}", f"{par_zero:016X}", f"{ks:016X}"]
    print(f"input: uid={uid:08X} nt={nt:08X} nr={nr:08X} ar={ar:08X} ks={ks:016X} par=0")

    failures = []

    def check(label, ok, detail=""):
        if ok:
            print(f"  ok   {label}")
        else:
            print(f"  FAIL {label}  {detail}")
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        exe_search = build(tmp, "search", SEARCH_HARNESS, mine=True)
        exe_oracle = build(tmp, "oracle", ORACLE_HARNESS, mine=False)

        cap = 8
        print("\n[1] upstream oracle")
        oracle_out = run(exe_oracle, [*feed_args, str(cap)]).split()
        oracle_total = int(oracle_out[0])
        oracle_keys = [int(x, 16) for x in oracle_out[1:]]
        print(f"  nonce2key -> {oracle_total} keys, first {len(oracle_keys)}:")
        print(f"    {' '.join(f'{k:012X}' for k in oracle_keys)}")
        check("oracle produced a non-empty list (test is not vacuous)", oracle_total > 0, f"got {oracle_total}")

        print("\n[2] DarksideSearch::Feed, same acquisition three times")
        out = run(exe_search, ["feed", *feed_args, "3", str(cap)])
        print("  " + out.replace("\n", "\n  "))
        lines = [l for l in out.splitlines() if l.startswith("call ")]
        baseline = int(next(l for l in out.splitlines() if l.startswith("baseline")).split()[1])

        check("three calls ran", len(lines) == 3, f"got {len(lines)}")

        first = lines[0].split()
        # fields: call <i> returned <n> total <n> started <0|1> current <bytes>
        check("call 0 stores without reporting (darkside.c semantics)",
              int(first[3]) == 0 and int(first[5]) == 0 and first[7] == "1",
              f"{first}")

        second = lines[1].split()
        got_total = int(second[5])
        check("call 1 intersects the list with itself -> full count",
              got_total == oracle_total, f"feed total {got_total} vs oracle {oracle_total}")
        # keys start after: call <n> returned <n> total <n> started <n> current <n>
        got_keys = [int(x, 16) for x in second[10 : 10 + cap]]
        check(f"call 1 first {cap} keys equal the oracle's", got_keys == oracle_keys,
              f"feed {[f'{k:012X}' for k in got_keys]} vs oracle {[f'{k:012X}' for k in oracle_keys]}")

        third = lines[2].split()
        check("call 2 repeats the same intersection", int(third[5]) == oracle_total, f"{third}")

        after_reset = int(next(l for l in out.splitlines() if l.startswith("after_reset")).split()[2])
        after_scope = int(next(l for l in out.splitlines() if l.startswith("after_scope")).split()[2])
        check("Reset() releases the running list", after_reset == baseline, f"{after_reset} vs baseline {baseline}")
        check("destructor releases everything", after_scope == baseline, f"{after_scope} vs baseline {baseline}")

        print("\n[3] par != 0 resets the running state (CLI NXP workaround)")
        out = run(exe_search, ["feed", f"{uid:08X}", f"{nt:08X}", f"{nr:08X}", f"{ar:08X}", f"{par_nonzero:016X}",
                               f"{ks:016X}", "2", str(cap)])
        print("  " + out.replace("\n", "\n  "))
        lines = [l for l in out.splitlines() if l.startswith("call ")]
        check("par != 0 leaves started == 0", all(l.split()[7] == "0" for l in lines), f"{lines}")
        base2 = int(next(l for l in out.splitlines() if l.startswith("baseline")).split()[1])
        check("par != 0 does not leak",
              int(next(l for l in out.splitlines() if l.startswith("after_scope")).split()[2]) == base2)

        print("\n[4] output buffer edge cases")
        out = run(exe_search, ["guard", *feed_args])
        print("  " + out.replace("\n", "\n  "))
        check("null buffer refused", "null_buffer returned 0 total 0" in out, out)
        check("zero capacity refused", "zero_capacity returned 0 total 0" in out, out)
        check("null total accepted", "null_total returned 0" in out, out)
        guard_lines = dict(
            (l.split()[0], int(l.split()[-1])) for l in out.splitlines() if l.endswith(tuple("0123456789"))
        )
        check("guard: the stored list is released when the search goes out of scope",
              "baseline" in guard_lines and guard_lines["after_scope"] == guard_lines["baseline"],
              f"{guard_lines}")

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("ALL DARKSIDE SEARCH CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
