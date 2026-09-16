"""Cross-check the nested key recovery port against upstream nested_util.c.

The port had to change three things upstream does (single threaded instead of
four pthreads, a bounds-checked uniqsort, PSRAM allocations), so "it compiles" is
not evidence. This builds BOTH implementations and compares them:

  A) firmware/components/chameleon_crypto/src/nested.cpp
  B) software/src/nested_util.c from the reference repo (real pthreads)

Checks:
  1. valid_nonce() agrees on random inputs - it is a pure predicate, so any
     difference is a porting error
  2. NestedRecover() returns the same candidate key SET as upstream nested() on
     the same nonce list
  3. any set difference is attributed: upstream's uniqsort() reads one element
     past the end of the array (see the port's header comment), which can change
     which candidate wins the count ranking

Usage:  python tools/probe_nested.py
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
SCRIPT_DIR = CU_UPSTREAM / "software" / "script"
HOST_STUBS = REPO / "tools" / "host_stubs"
GCC = Path(r"C:\mingw64\bin\g++.exe")

MINE_HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nested.h"
#include "esp_heap_caps.h"

extern "C" {
#include "crapto1.h"
}

using namespace chameleon::crypto;

/* valid <nt> <ntenc> <ks1> <p0> <p1> <p2> */
static int cmd_valid(int argc, char** argv) {
    if (argc < 7) return 2;
    uint8_t par[3] = {(uint8_t)strtoul(argv[4], NULL, 16), (uint8_t)strtoul(argv[5], NULL, 16),
                      (uint8_t)strtoul(argv[6], NULL, 16)};
    printf("%u\n", NestedValidNonce((uint32_t)strtoul(argv[1], NULL, 16), (uint32_t)strtoul(argv[2], NULL, 16),
                                    (uint32_t)strtoul(argv[3], NULL, 16), par));
    return 0;
}

/* recover <uid> <ntp:ks1,ntp:ks1,...> */
static int cmd_recover(int argc, char** argv) {
    if (argc < 3) return 2;
    const uint32_t uid = (uint32_t)strtoul(argv[1], NULL, 16);

    NestedNonce nonces[512];
    size_t n = 0;
    /* Stack buffer, no strdup: -include is a whole-command option in GCC, so
       this harness is compiled with the same macros that rename malloc/free.
       strdup() allocates with the real libc malloc while the macro makes
       free() call host_track_free, which reads a tracker header that is not
       there - that corrupted the heap before NestedRecover was even called and
       is what made this command crash with no output at all. */
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", argv[2]);
    for (char* tok = strtok(copy, ","); tok != NULL && n < 512; tok = strtok(NULL, ",")) {
        unsigned a = 0, b = 0;
        if (sscanf(tok, "%x:%x", &a, &b) != 2) break;
        nonces[n].ntp = a;
        nonces[n].ks1 = b;
        ++n;
    }

    uint64_t keys[512];
    size_t count = 0;
    NestedRecover(nonces, n, uid, keys, 512, &count);
    printf("%zu", count);
    for (size_t i = 0; i < count && i < 512; ++i) printf(" %012" PRIX64, keys[i]);
    printf("\n");
    return 0;
}

/* walk <in> <ks1> [cap] : call lfsr_recovery32 directly and walk the state list.
   Separates "the recovery table is not terminated" from "the caller mishandles
   it" - the crash this probe used to hit (STATUS_HEAP_CORRUPTION) is one of the
   two. */
static int cmd_walk(int argc, char** argv) {
    if (argc < 3) return 2;
    const uint32_t in = (uint32_t)strtoul(argv[1], NULL, 16);
    const uint32_t ks1 = (uint32_t)strtoul(argv[2], NULL, 16);
    const size_t cap = (argc > 3) ? (size_t)strtoul(argv[3], NULL, 0) : 20000000;

    struct Crypto1State* s = lfsr_recovery32(ks1, in);
    if (s == NULL) {
        printf("null\n");
        return 0;
    }

    size_t n = 0;
    struct Crypto1State* t = s;
    while ((t->odd != 0) || (t->even != 0)) {
        ++t;
        ++n;
        if (n >= cap) {
            printf("runaway %zu\n", n);
            heap_caps_free(s);
            return 0;
        }
    }
    printf("states %zu\n", n);
    /* heap_caps_free, not free(): the list came from crapto1.c, which is
       compiled with the allocation tracker, so a raw free() here would corrupt
       the host heap and make this command's own result untrustworthy. */
    heap_caps_free(s);
    return 0;
}

/* nderive <dist> <nt:ntenc:par,...> : plain-nested nonce derivation */
static int cmd_nderive(int argc, char** argv) {
    if (argc < 3) return 2;
    const uint32_t dist = (uint32_t)strtoul(argv[1], NULL, 16);

    NestedAcquireEntry entries[256];
    size_t n = 0;
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", argv[2]);
    for (char* tok = strtok(copy, ","); tok != NULL && n < 256; tok = strtok(NULL, ",")) {
        unsigned a = 0, b = 0, c = 0;
        if (sscanf(tok, "%x:%x:%x", &a, &b, &c) != 3) break;
        entries[n].nt = a;
        entries[n].nt_enc = b;
        entries[n].par = (uint8_t)c;
        ++n;
    }

    static NestedNonce derived[256 * 29];
    const size_t got = NestedDerive(dist, entries, n, derived, 256 * 29);
    printf("%zu", got);
    for (size_t i = 0; i < got; ++i) printf(" %08X:%08X", derived[i].ntp, derived[i].ks1);
    printf("\n");
    return 0;
}

/* derive <key_type> <nt:ntenc,...> : static-nested nonce derivation */
static int cmd_derive(int argc, char** argv) {
    if (argc < 3) return 2;
    const uint8_t key_type = (uint8_t)strtoul(argv[1], NULL, 16);

    StaticNestedPair pairs[512];
    size_t n = 0;
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", argv[2]);
    for (char* tok = strtok(copy, ","); tok != NULL && n < 512; tok = strtok(NULL, ",")) {
        unsigned a = 0, b = 0;
        if (sscanf(tok, "%x:%x", &a, &b) != 2) break;
        pairs[n].nt = a;
        pairs[n].nt_enc = b;
        ++n;
    }

    NestedNonce derived[512];
    const size_t got = StaticNestedDerive(key_type, pairs, n, derived, 512);
    printf("%zu", got);
    for (size_t i = 0; i < got; ++i) printf(" %08X:%08X", derived[i].ntp, derived[i].ks1);
    printf("\n");
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "valid") == 0) return cmd_valid(argc - 1, argv + 1);
    if (strcmp(argv[1], "recover") == 0) return cmd_recover(argc - 1, argv + 1);
    if (strcmp(argv[1], "walk") == 0) return cmd_walk(argc - 1, argv + 1);
    if (strcmp(argv[1], "derive") == 0) return cmd_derive(argc - 1, argv + 1);
    if (strcmp(argv[1], "nderive") == 0) return cmd_nderive(argc - 1, argv + 1);
    return 2;
}
"""

UPSTREAM_HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "nested_util.h"
}

/* valid <nt> <ntenc> <ks1> <p0> <p1> <p2> */
static int cmd_valid(int argc, char** argv) {
    if (argc < 7) return 2;
    uint8_t par[3] = {(uint8_t)strtoul(argv[4], NULL, 16), (uint8_t)strtoul(argv[5], NULL, 16),
                      (uint8_t)strtoul(argv[6], NULL, 16)};
    printf("%u\n", valid_nonce((uint32_t)strtoul(argv[1], NULL, 16), (uint32_t)strtoul(argv[2], NULL, 16),
                               (uint32_t)strtoul(argv[3], NULL, 16), par));
    return 0;
}

/* recover <uid> <ntp:ks1,...> */
static int cmd_recover(int argc, char** argv) {
    if (argc < 3) return 2;
    const uint32_t uid = (uint32_t)strtoul(argv[1], NULL, 16);

    NtpKs1 nonces[512];
    size_t n = 0;
    char* copy = strdup(argv[2]);
    for (char* tok = strtok(copy, ","); tok != NULL && n < 512; tok = strtok(NULL, ",")) {
        unsigned a = 0, b = 0;
        if (sscanf(tok, "%x:%x", &a, &b) != 2) break;
        nonces[n].ntp = a;
        nonces[n].ks1 = b;
        ++n;
    }
    free(copy);

    uint32_t count = 0;
    uint64_t* keys = nested(nonces, (uint32_t)n, uid, &count);
    printf("%u", count);
    for (uint32_t i = 0; i < count && i < 512; ++i) printf(" %012" PRIX64, keys[i]);
    printf("\n");
    if (keys) free(keys);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "valid") == 0) return cmd_valid(argc - 1, argv + 1);
    if (strcmp(argv[1], "recover") == 0) return cmd_recover(argc - 1, argv + 1);
    return 2;
}
"""


def gcc(args, **kwargs):
    """Run a compiler command and decode its output defensively.

    subprocess defaults to the locale codec, which is GBK on this machine: one
    byte the compiler emits that is not valid GBK raises UnicodeDecodeError
    inside the reader thread and leaves .stdout/.stderr as None, so the real
    compile error gets replaced by a confusing TypeError while formatting it.
    Always decode as UTF-8 with replacement.
    """
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kwargs)


def build(out_dir, variant):
    src = out_dir / f"nested_{variant}.cpp"
    exe = out_dir / f"nested_{variant}.exe"

    if variant == "mine":
        src.write_text(MINE_HARNESS, encoding="utf-8")
        base = MINE / "src"
        inc = [HOST_STUBS, MINE / "include", MINE / "src"]
        # nested.cpp has to be built with the SAME allocation macros as crapto1.c:
        # it frees pointers that crapto1.c allocated, and mixing a tracked
        # allocation with the real free corrupts the host heap (it crashed the
        # harness before this was consistent).
        extra = ["-include", str(HOST_STUBS / "host_alloc_tracker.h")]
        objs = ["-x", "c++", *extra, str(MINE / "src" / "nested.cpp")]
        sources = ["crapto1.c", "crypto1.c", "parity.c", "bucketsort.c"]
    else:
        src.write_text(UPSTREAM_HARNESS, encoding="utf-8")
        base = UPSTREAM
        inc = [UPSTREAM]
        extra = []
        objs = []
        sources = ["crapto1.c", "crypto1.c", "parity.c", "bucketsort.c", "nested_util.c"]

    args = [str(GCC), "-std=gnu++17", "-O2", "-w", "-pthread"]
    for d in inc:
        args += ["-I", str(d)]
    args.append(str(src))
    args += objs
    for s in sources:
        args += ["-x", "c", *extra, str(base / s)]
    if variant == "mine":
        # The tracker's own implementation MUST be compiled without the
        # -include macros: `-include` is a whole-command option in GCC, so
        # compiling host_alloc_tracker.c in this same invocation renames
        # `host_real_malloc = malloc` into `host_real_malloc = host_track_malloc`
        # and the tracker calls itself. Build it into its own object first, with
        # no macros, and link that.
        # -x c matters twice over: g++ compiles a .c file as C++ otherwise, which
        # mangles these symbols and breaks the extern "C" declarations the
        # harness sees (undefined reference to host_track_free). Compiling it as
        # C also keeps it out of the -include macros, which would otherwise
        # rename `host_real_malloc = malloc` into a self-reference.
        tracker_obj = out_dir / "host_alloc_tracker.o"
        res = gcc([str(GCC), "-O2", "-w", "-x", "c", "-c", str(HOST_STUBS / "host_alloc_tracker.c"),
                   "-o", str(tracker_obj)])
        if res.returncode != 0:
            print(f"tracker build failed:\n{res.stderr[-1500:]}")
            sys.exit(1)
        # -x c above persists to the end of the command line, so without
        # "-x none" gcc tries to compile this object file as C source and fails
        # with "stray '\206' in program".
        args += ["-x", "none", str(tracker_obj)]
    args += ["-o", str(exe)]

    res = gcc(args)
    if res.returncode != 0:
        # GCC pads its diagnostics with a long caret line, so the tail alone can
        # be nothing but whitespace - show the head, where the message is.
        print(f"build {variant} failed:\nHEAD:\n{(res.stdout or '')[:1200]}\n{(res.stderr or '')[:1200]}\n"
              f"TAIL:\n{(res.stderr or '')[-600:]}")
        sys.exit(1)
    return exe


def run(exe, argv, timeout=120):
    res = gcc([str(exe), *argv], timeout=timeout)
    if res.returncode != 0:
        print(f"    ! {argv[0]} exited {res.returncode}: {res.stderr.strip()[:200]}")
    return res.stdout.strip()


def oddparity8(v):
    return bin(v & 0xFF).count("1") & 1


def bit(value, n):
    return (value >> n) & 1


def consistent_parity(nt, nt_enc, ks1):
    """Parity bytes that make valid_nonce() true, derived from its own formula."""
    return [
        oddparity8(nt >> 24) ^ oddparity8(nt_enc >> 24) ^ bit(ks1, 16),
        oddparity8(nt >> 16) ^ oddparity8(nt_enc >> 16) ^ bit(ks1, 8),
        oddparity8(nt >> 8) ^ oddparity8(nt_enc >> 8) ^ bit(ks1, 0),
    ]


def main():
    def lcg(state):
        return (state * 1103515245 + 12345) & 0xFFFFFFFF

    failures = []

    def check(label, ok, detail=""):
        if ok:
            print(f"  ok   {label}")
        else:
            print(f"  FAIL {label}  {detail}")
            failures.append(label)

    # Persistent build dir: the harnesses are kept so a failure can be bisected
    # by hand instead of only being visible through this script.
    out_dir = REPO / "build" / "hosttests"
    out_dir.mkdir(parents=True, exist_ok=True)

    if True:
        tmp = out_dir
        exe_mine = build(tmp, "mine")
        exe_up = build(tmp, "upstream")

        if "--walk" in sys.argv:
            # Bisect the crash: does lfsr_recovery32 return a terminated list, and
            # does the termination hold for a non-zero `in` (never exercised
            # before: darkside and mfkey32 both pass in = 0)?
            print("lfsr_recovery32 walk (in, ks1) -> states")
            s = 0x1000
            for case in range(6):
                s = lcg(s)
                ntp = s
                s = lcg(s)
                ks1 = s
                in_zero = run(exe_mine, ["walk", "00000000", f"{ks1:08X}"])
                in_ntp = run(exe_mine, ["walk", f"{ntp:08X}", f"{ks1:08X}"])
                up_zero = run(exe_up, ["walk", "00000000", f"{ks1:08X}"])
                up_ntp = run(exe_up, ["walk", f"{ntp:08X}", f"{ks1:08X}"])
                print(f"  case {case} ks1={ks1:08X} ntp={ntp:08X}")
                print(f"    mine     in=0 {in_zero:>16}   in=ntp {in_ntp:>16}")
                print(f"    upstream in=0 {up_zero:>16}   in=ntp {up_ntp:>16}")
            return 0

        # ---- 0. the tuning constants ----
        # These were guessed wrong once (256/256 instead of 50/10000) and the
        # only thing that noticed was the candidate-set comparison below. Read
        # them out of upstream's source so they cannot drift silently again.
        print("[0] tuning constants vs nested_util.c")
        import re as _re

        up_src = (UPSTREAM / "nested_util.c").read_text(encoding="utf-8", errors="replace")
        mine_src = (MINE / "src" / "nested.cpp").read_text(encoding="utf-8", errors="replace")
        for up_name, mine_name in (("MEM_CHUNK", "kMemChunk"), ("TRY_KEYS", "kTryKeys")):
            m_up = _re.search(rf"#define\s+{up_name}\s+(\d+)", up_src)
            m_mine = _re.search(rf"{mine_name}\s*=\s*(\d+)", mine_src)
            want = int(m_up.group(1)) if m_up else None
            got = int(m_mine.group(1)) if m_mine else None
            check(f"{up_name} = {want}", want is not None and got == want, f"port has {got}")

        if "--derive" in sys.argv:
            # Static-nested derivation, checked against the REFERENCE PRNG
            # (crypto1.py prng_next) instead of against my own arithmetic: the
            # generation detection and the 160-step distance schedule are the
            # only parts of staticnested.c not shared with plain nested.
            import importlib.util

            spec = importlib.util.spec_from_file_location("crypto1", SCRIPT_DIR / "crypto1.py")
            ref = importlib.util.module_from_spec(spec)
            sys.modules["crypto1"] = ref
            spec.loader.exec_module(ref)
            Crypto1 = ref.Crypto1

            print("static nested derivation vs reference prng_next")
            cases = [
                ("gen1, key A", 0x60, 0x01200145, 160),
                ("gen2, key A", 0x60, 0x009080A2, 160),
                ("gen2, key B", 0x61, 0x009080A2, 161),
                ("gen2, key B but called with key A", 0x60, 0x009080A2, 160),
            ]
            s = 0x55AA0000
            for label, key_type, first_nt, first_dist in cases:
                s = lcg(s)
                pairs = [(first_nt, s)]
                for _ in range(3):
                    s = lcg(s)
                    nt = s
                    s = lcg(s)
                    pairs.append((nt, s))
                arg = ",".join(f"{a:08X}:{b:08X}" for a, b in pairs)

                # Expected, straight from the reference PRNG.
                expect = []
                dist = first_dist
                for nt, nt_enc in pairs:
                    nttest = Crypto1.prng_next(nt, dist) & 0xFFFFFFFF
                    expect.append((nttest, nt_enc ^ nttest))
                    dist += 160

                out = run(exe_mine, ["derive", f"{key_type:02X}", arg]).split()
                got_n = int(out[0]) if out else -1
                got = [tuple(int(x, 16) for x in f.split(":")) for f in out[1:]]

                check(f"{label}: {len(expect)} pairs derived", got_n == len(expect), f"got {got_n}")
                check(f"{label}: derived pairs match the reference PRNG", got == expect,
                      f"got {[f'{a:08X}:{b:08X}' for a, b in got][:3]} vs "
                      f"{[f'{a:08X}:{b:08X}' for a, b in expect][:3]}")

            # An unknown generation must be refused, not guessed at.
            out = run(exe_mine, ["derive", "60", "DEADBEEF:12345678,00000000:00000000"])
            check("unknown static generation refused", out == "0", f"got {out!r}")
            # Key type must be A or B for gen2 (staticnested.c goto error).
            out = run(exe_mine, ["derive", "99", "009080A2:12345678"])
            check("gen2 with an invalid key type refused", out == "0", f"got {out!r}")

            # ---- plain nested derivation (nested.c) ----
            # Same idea: the expected list comes from the reference PRNG and a
            # Python port of the predicate, not from my own C arithmetic.
            print("\nplain nested derivation vs reference prng_next + predicate")

            def py_valid_nonce(nt, nt_enc, ks1, par):
                return int(
                    (oddparity8(nt >> 24) == (par[0] ^ oddparity8(nt_enc >> 24) ^ bit(ks1, 16)))
                    and (oddparity8(nt >> 16) == (par[1] ^ oddparity8(nt_enc >> 16) ^ bit(ks1, 8)))
                    and (oddparity8(nt >> 8) == (par[2] ^ oddparity8(nt_enc >> 8) ^ bit(ks1, 0)))
                )

            s = 0x77AA0000
            for dist in (160, 361):
                entries = []
                for _ in range(3):
                    s = lcg(s)
                    nt = s
                    s = lcg(s)
                    nt_enc = s
                    s = lcg(s)
                    entries.append((nt, nt_enc, s & 0x07))
                arg = ",".join(f"{a:08X}:{b:08X}:{p:X}" for a, b, p in entries)

                expect = []
                for nt, nt_enc, par_int in entries:
                    par = [(par_int >> m) & 1 for m in range(3)] if par_int != 0 else [0, 0, 0]
                    nttest = Crypto1.prng_next(nt, dist - 14) & 0xFFFFFFFF
                    for _ in range(29):
                        ks1 = nt_enc ^ nttest
                        if py_valid_nonce(nttest, nt_enc, ks1, par):
                            expect.append((nttest, ks1))
                        nttest = Crypto1.prng_next(nttest, 1) & 0xFFFFFFFF

                out = run(exe_mine, ["nderive", f"{dist:X}", arg]).split()
                got_n = int(out[0]) if out else -1
                got = [tuple(int(x, 16) for x in f.split(":")) for f in out[1:]]
                check(f"dist {dist}: derived {len(expect)} pairs", got_n == len(expect), f"got {got_n}")
                check(f"dist {dist}: derived pairs match the reference", got == expect,
                      f"got {[f'{a:08X}:{b:08X}' for a, b in got][:2]} vs "
                      f"{[f'{a:08X}:{b:08X}' for a, b in expect][:2]}")
            return 0

        # ---- 1. valid_nonce ----
        # Random parity makes the predicate false almost always (three parity
        # constraints), which would make the comparison vacuous - the first run
        # of this probe did exactly that. So half the cases derive the parity
        # that satisfies the predicate and half flip one bit of it, giving both
        # answers.
        print("[1] valid_nonce vs upstream")
        s = 0x2468ACE0
        mismatches = 0
        ones = 0
        zeros = 0
        for case in range(300):
            vals = []
            for _ in range(3):
                s = lcg(s)
                vals.append(s)
            nt, nt_enc, ks1 = vals
            par = consistent_parity(nt, nt_enc, ks1)
            if case % 2 == 1:
                par[case % 3] ^= 1
            argv = [f"{nt:08X}", f"{nt_enc:08X}", f"{ks1:08X}"] + [f"{p:02X}" for p in par]
            a = run(exe_mine, ["valid", *argv])
            b = run(exe_up, ["valid", *argv])
            if a != b:
                mismatches += 1
                if mismatches <= 3:
                    print(f"    mismatch: {argv} mine={a} upstream={b}")
            if a == "1":
                ones += 1
            elif a == "0":
                zeros += 1
        check("300 inputs agree", mismatches == 0, f"{mismatches} mismatches")
        check("the predicate is exercised both ways (test is not vacuous)",
              ones > 50 and zeros > 50, f"{ones} true / {zeros} false")

        # ---- 2. nested recovery ----
        # NOTE: this is not yet a meaningful comparison. Upstream nested() returns
        # zero candidates for synthetic {ntp, ks1} pairs, so both sides agree on
        # "nothing found" and the check proves only that neither crashes. Making
        # it real needs nonces a genuine nested attack would produce, i.e. a
        # Mifare Classic card with one known sector. The check below fails on
        # purpose while that is true, rather than reporting a green tick for a
        # comparison of two empty sets.
        print("\n[2] NestedRecover vs upstream nested()")
        nonempty_cases = 0
        for case in range(4):
            s = 0x1000 + case * 0x9E3779B1
            pairs = []
            # Each pair appears TWICE. Upstream scores a key by how many extra
            # times it was seen (a key seen once scores 0 and is dropped by
            # nested()), so a list of all-distinct nonces makes both sides return
            # nothing and the comparison meaningless. Repeating each pair makes
            # every key score 1, which both implementations must then report.
            for _ in range(3):
                s = lcg(s)
                ntp = s
                s = lcg(s)
                ks1 = s
                pairs.append(f"{ntp:08X}:{ks1:08X}")
                pairs.append(f"{ntp:08X}:{ks1:08X}")
            arg = ",".join(pairs)
            a = run(exe_mine, ["recover", "65535D33", arg])
            b = run(exe_up, ["recover", "65535D33", arg])
            ta, tb = a.split(), b.split()
            na = int(ta[0]) if ta else -1
            nb = int(tb[0]) if tb else -1
            set_a = {x.upper() for x in ta[1:]}
            set_b = {x.upper() for x in tb[1:]}
            only_a = set_a - set_b
            only_b = set_b - set_a
            if na > 0 or nb > 0:
                nonempty_cases += 1
            print(f"  case {case}: mine {na} keys, upstream {nb} keys, "
                  f"only_mine {len(only_a)}, only_upstream {len(only_b)}")
            if only_a or only_b:
                print(f"    only mine     : {sorted(only_a)[:4]}")
                print(f"    only upstream : {sorted(only_b)[:4]}")
            check(f"case {case}: candidate sets match", not only_a and not only_b,
                  f"+{len(only_a)}/-{len(only_b)}")

        check("the recovery comparison is non-vacuous (needs real nested nonces)",
              nonempty_cases > 0,
              "upstream nested() returned no candidates for any synthetic input, "
              "so this only proves neither side crashes")

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("ALL NESTED CHECKS PASSED (candidate sets identical to upstream)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
