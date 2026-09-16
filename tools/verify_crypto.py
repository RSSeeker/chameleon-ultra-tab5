"""Verify the C crypto port against the upstream Python reference.

Two independent oracles are used:

  1. the hard-coded vectors in tests/test_crypto1.py from the ChameleonUltra repo
  2. the live crypto1.py reference implementation, driven to produce the same
     values (so the test also catches a vector being stale)

The C side is the real code: crapto1.c / crypto1.c / bucketsort.c are compiled
verbatim, plus the host stand-in headers in tools/host_stubs/ that replace the
ESP-IDF headers mfkey32.cpp uses.

The mfkey32 recovery itself is exercised as a round trip: a synthetic three pass
authentication is generated with a known key using the reference Python, and the
C implementation must recover that key from the resulting traces.

Usage:  python tools/verify_crypto.py
"""

import importlib.util
import os
import struct
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
CRYPTO = REPO / "firmware" / "components" / "chameleon_crypto"
CHAM = REPO / "firmware" / "components" / "chameleon"
SCRIPT_DIR = CU_UPSTREAM / "software" / "script"
HOST_STUBS = REPO / "tools" / "host_stubs"
GCC = Path(r"C:\mingw64\bin\g++.exe")

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mfkey32.h"
#include "sniff_decoder.h"

/* Host stand-in: provides heap_caps_* plus the peak tracker. */
#include "esp_heap_caps.h"
#include "host_alloc_tracker.h"


using namespace chameleon::crypto;
using chameleon::TraceAuth;
using chameleon::DecodeTraceAuths;

/* seq <key> <in1>:<enc1> <in2>:<enc2> ...  -> one keystream word per step */
static int cmd_seq(int argc, char** argv) {
    uint64_t key = strtoull(argv[2], NULL, 16);
    uint32_t inputs[kCrypto1MaxWords];
    bool encrypted[kCrypto1MaxWords];
    uint32_t out[kCrypto1MaxWords];
    size_t n = 0;

    for (int i = 3; i < argc && n < kCrypto1MaxWords; ++i) {
        char buf[64];
        strncpy(buf, argv[i], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char* colon = strchr(buf, ':');
        if (colon == NULL) return 2;
        *colon = '\0';
        inputs[n]    = (uint32_t)strtoul(buf, NULL, 16);
        encrypted[n] = (atoi(colon + 1) != 0);
        ++n;
    }

    Crypto1WordSequence(key, inputs, encrypted, n, out);
    for (size_t i = 0; i < n; ++i) printf("%08X%s", out[i], (i + 1 < n) ? " " : "");
    printf("\n");
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;

    if (strcmp(argv[1], "seq") == 0 && argc >= 4) return cmd_seq(argc, argv);

    if (strcmp(argv[1], "prng") == 0) {
        uint32_t nt = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t n  = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("%08X\n", PrngSuccessor(nt, n));
        return 0;
    }

    if (strcmp(argv[1], "word") == 0) {
        /* word <key> <in> <encrypted> */
        uint64_t key = strtoull(argv[2], NULL, 16);
        uint32_t in  = (uint32_t)strtoul(argv[3], NULL, 16);
        int enc      = atoi(argv[4]);
        printf("%08X\n", Crypto1Word(key, in, enc != 0));
        return 0;
    }

    if (strcmp(argv[1], "verify") == 0) {
        /* verify <uid> <nt> <nr> <ar> <key> */
        uint32_t uid = (uint32_t)strtoul(argv[2], NULL, 16);
        AuthTrace t;
        t.nt = (uint32_t)strtoul(argv[3], NULL, 16);
        t.nr = (uint32_t)strtoul(argv[4], NULL, 16);
        t.ar = (uint32_t)strtoul(argv[5], NULL, 16);
        uint64_t key = strtoull(argv[6], NULL, 16);
        printf("%d\n", VerifyAuthTrace(uid, t, key) ? 1 : 0);
        return 0;
    }

    if (strcmp(argv[1], "mfkey32") == 0) {
        /* mfkey32 <uid> <nt0> <nr0> <ar0> <nt1> <nr1> <ar1> */
        uint32_t uid = (uint32_t)strtoul(argv[2], NULL, 16);
        AuthTrace a, b;
        a.nt = (uint32_t)strtoul(argv[3], NULL, 16);
        a.nr = (uint32_t)strtoul(argv[4], NULL, 16);
        a.ar = (uint32_t)strtoul(argv[5], NULL, 16);
        b.nt = (uint32_t)strtoul(argv[6], NULL, 16);
        b.nr = (uint32_t)strtoul(argv[7], NULL, 16);
        b.ar = (uint32_t)strtoul(argv[8], NULL, 16);
        uint64_t key = 0;
        KeyRecoveryStatus st = Mfkey32(uid, a, b, &key);
        printf("%d %012llX\n", (int)st, (unsigned long long)key);
        return 0;
    }

    if (strcmp(argv[1], "crack") == 0) {
        /* crack <tracehex>
           The path the Tools page's mfkey32 button takes: decode a sniff /
           auth-trace buffer into authentications, then crack the first two
           complete ones. This is the join between sniff_decoder.cpp and
           mfkey32.cpp, which neither probe covered on its own. */
        const char* hex = argv[2];
        static uint8_t buf[4096];
        size_t n = 0;
        for (const char* p = hex; p[0] != '\0' && p[1] != '\0' && n < sizeof(buf); p += 2) {
            char byte[3] = {p[0], p[1], 0};
            buf[n++] = (uint8_t)strtoul(byte, NULL, 16);
        }
        TraceAuth auths[8];
        const size_t count = DecodeTraceAuths(buf, n, auths, 8);
        size_t usable = 0;
        AuthTrace pair[2];
        for (size_t i = 0; i < count && usable < 2; ++i) {
            if (!auths[i].complete) continue;
            pair[usable].nt = auths[i].nt;
            pair[usable].nr = auths[i].nr_enc;
            pair[usable].ar = auths[i].ar_enc;
            usable++;
        }
        printf("auths %zu usable %zu\n", count, usable);
        if (usable < 2) return 0;
        uint64_t key = 0;
        KeyRecoveryStatus st = Mfkey32((uint32_t)strtoul(argv[3], NULL, 16), pair[0], pair[1], &key);        printf("%d %012llX\n", (int)st, (unsigned long long)key);
        return 0;
    }

    if (strcmp(argv[1], "reqmem") == 0) {
        printf("%zu\n", Mfkey32RequiredBytes());
        return 0;
    }

    if (strcmp(argv[1], "peak") == 0) {
        /* peak <uid> <nt0> <nr0> <ar0> <nt1> <nr1> <ar1>
           Runs the recovery and reports the peak heap the algorithm touched. */
        uint32_t uid = (uint32_t)strtoul(argv[2], NULL, 16);
        AuthTrace a, b;
        a.nt = (uint32_t)strtoul(argv[3], NULL, 16);
        a.nr = (uint32_t)strtoul(argv[4], NULL, 16);
        a.ar = (uint32_t)strtoul(argv[5], NULL, 16);
        b.nt = (uint32_t)strtoul(argv[6], NULL, 16);
        b.nr = (uint32_t)strtoul(argv[7], NULL, 16);
        b.ar = (uint32_t)strtoul(argv[8], NULL, 16);

        host_alloc_reset_stats();
        uint64_t key = 0;
        KeyRecoveryStatus st = Mfkey32(uid, a, b, &key);
        printf("%d %zu %zu %zu\n", (int)st, host_alloc_peak, host_alloc_total, host_alloc_current);
        return 0;
    }

    return 2;
}
"""


def load_reference():
    sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("crypto1", SCRIPT_DIR / "crypto1.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["crypto1"] = mod
    spec.loader.exec_module(mod)
    return mod.Crypto1


def build(exe_out):
    src = exe_out.parent / "crypto_harness.cpp"
    src.write_text(HARNESS, encoding="utf-8")

    # The upstream Crapto1 files are C, but g++ defaults .c to C++ and then
    # rejects malloc() returning void*. Force C per file with -x c (a single
    # leading -x c would be reset as soon as -x none is implied by the next
    # language switch).
    # The tracker renames the libc allocation entry points via -include, so the
    # code under test stays byte-identical to the firmware source while the test
    # can still report the true peak allocation.
    c_sources = []
    for name in ("crapto1.c", "crypto1.c", "parity.c", "bucketsort.c"):
        c_sources += ["-x", "c", "-include", str(HOST_STUBS / "host_alloc_tracker.h"),
                      str(CRYPTO / "src" / name)]
    # gcc warns about the C++ standard flag reaching the C front end; harmless.
    cmd = [
        str(GCC),
        "-std=gnu++17",
        "-O2",
        "-I",
        str(HOST_STUBS),
        "-I",
        str(CRYPTO / "include"),
        "-I",
        str(CRYPTO / "src"),
        "-I",
        str(CHAM / "include"),
        str(src),
        str(CRYPTO / "src" / "mfkey32.cpp"),
        str(CHAM / "src" / "sniff_decoder.cpp"),
        str(HOST_STUBS / "host_alloc_tracker.c"),
        *c_sources,
        "-o",
        str(exe_out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("harness build failed:\n", res.stdout, res.stderr)
        sys.exit(1)


def run(exe, *args):
    res = subprocess.run([str(exe), *args], capture_output=True, text=True)
    if res.returncode != 0:
        # Surface crashes: a silent empty stdout previously hid a segfault.
        print(f"  ! {args[0] if args else ''} exited {res.returncode}")
        if res.stderr.strip():
            print("    stderr:", res.stderr.strip()[:2000])
    return res.stdout.strip()


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    Crypto1 = load_reference()
    tmp = Path(tempfile.mkdtemp(prefix="crypto_check_"))
    exe = tmp / "crypto_harness.exe"
    build(exe)

    failures = []

    def check(name, ok, detail=""):
        print(f"  {'OK  ' if ok else 'FAIL'} {name}{('  ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    # ---- 1. prng_successor against the shipped vector -------------------
    print("== prng_successor (test_crypto1.py vector) ==")
    # test_prng_next: prng_next(0x2C198BE4, 64) == 0xCC14C013
    got = run(exe, "prng", "2C198BE4", "64")
    check("prng_next(0x2C198BE4, 64) == 0xCC14C013", got.upper() == "CC14C013", f"got {got}")
    # and against the live reference
    for nt, n in ((0x2C198BE4, 64), (0xBE2B7B5D, 64), (0xBE2B7B5D, 96), (0x12345678, 1)):
        ref = Crypto1.prng_next(nt, n)
        got = int(run(exe, "prng", f"{nt:08X}", str(n)), 16)
        check(f"prng_next({nt:08X}, {n})", got == ref, f"ref {ref:08X} got {got:08X}")

    # ---- 2. crypto1 keystream against the three pass auth vector --------
    # The cipher is stateful: the reference test reuses ONE Crypto1 instance and
    # calls lfsr48_u32() three times, so the C side must run a word sequence
    # from a single init (a fresh state per call would produce prng successors).
    print("\n== crypto1 keystream (test_crypto1.py reader_three_pass_auth) ==")
    uid, nt, nr, at_enc = 0x65535D33, 0xBE2B7B5D, 0x0B4271BA, 0x36081500
    key = 0x974C262B9278

    reader = Crypto1()
    reader.key = f"{key:012x}"
    ref0 = reader.lfsr48_u32(uid ^ nt, False)
    ref1 = reader.lfsr48_u32(nr, False)
    ref2 = reader.lfsr48_u32(0, False)

    got = run(exe, "seq", f"{key:012X}", f"{uid ^ nt:08X}:0", f"{nr:08X}:0", "00000000:0").split()
    got = [int(v, 16) for v in got]
    check("ks0 == 0xAC93C1A4", got[0] == 0xAC93C1A4, f"got {got[0]:08X}")
    check("ks1 == 0xBAA3C92B", got[1] == 0xBAA3C92B, f"got {got[1]:08X}")
    check("ks2 == 0xDC652720", got[2] == 0xDC652720, f"got {got[2]:08X}")
    check("matches live reference", got == [ref0, ref1, ref2],
          f"ref {ref0:08X} {ref1:08X} {ref2:08X}")

    # ar / at from the vector: ar = prng_next(nt, 64), at = prng_next(nt, 96)
    check("prng_next(nt, 64) == 0xF0928568", Crypto1.prng_next(nt, 64) == 0xF0928568)
    check("prng_next(nt, 96) == 0xF0FCB593", Crypto1.prng_next(nt, 96) == 0xF0FCB593)

    # ---- 3. VerifyAuthTrace agrees with the Python oracle ---------------
    print("\n== VerifyAuthTrace (mfkey32_is_reader_has_key) ==")
    ok_key = Crypto1.mfkey32_is_reader_has_key(uid, nt, nr ^ ref1, Crypto1.prng_next(nt, 64) ^ ref2,
                                               f"{key:012x}")
    check("reference accepts the vector key", ok_key)

    # encrypted ar for the vector: ar_enc = prng_next(nt,64) ^ ks2
    ar_enc = Crypto1.prng_next(nt, 64) ^ ref2
    nr_enc = nr ^ ref1

    got = run(exe, "verify", f"{uid:08X}", f"{nt:08X}", f"{nr_enc:08X}", f"{ar_enc:08X}", f"{key:012X}")
    check("C accepts the vector key", got == "1", f"got {got}")

    got = run(exe, "verify", f"{uid:08X}", f"{nt:08X}", f"{nr_enc:08X}", f"{ar_enc:08X}", "FFFFFFFFFFFF")
    check("C rejects a wrong key", got == "0", f"got {got}")

    # ---- 4. mfkey32 round trip -----------------------------------------
    print("\n== mfkey32 recovery (synthetic two auth round trip) ==")
    print(f"  mfkey32 workspace requested: {run(exe, 'reqmem')} bytes")

    def synth_auth(uid, key_hex, nt, nr_plain):
        """One Mifare Classic authentication as seen on the wire.

        Mirrors the sequence in tests/test_crypto1.py: three lfsr48_u32 calls on
        ONE state advance the same cipher (uid^nt for ks0, nr for ks1, 0 for ks2).
        """
        st = Crypto1()
        st.key = key_hex
        st.lfsr48_u32(uid ^ nt, False)      # ks0
        ks1 = st.lfsr48_u32(nr_plain, False)  # ks1 encrypts nr
        ks2 = st.lfsr48_u32(0, False)         # ks2 encrypts ar
        nr_enc = nr_plain ^ ks1
        ar_enc = Crypto1.prng_next(nt, 64) ^ ks2
        return nr_enc, ar_enc

    uid = 0x65535D33
    key64 = 0xFFFFFFFFFFFF
    key_hex = f"{key64:012x}"

    # The reader's nonce is itself a PRNG successor of the tag nonce: a real
    # reader derives nr from the same 16-bit LFSR it predicts the tag with, and
    # mfkey32 depends on that structure. Inventing nr freely yields a trace no
    # real reader could produce, and recovery then legitimately finds nothing.
    #
    # The second authentication must carry an *independent* tag nonce, i.e. one
    # the tag would produce for a later transaction (prng successor of the
    # first). Two traces sharing the nt chain are the "same transaction" case
    # and do not constrain the key the same way.
    nt0 = 0xBE2B7B5D
    nr0, ar0 = synth_auth(uid, key_hex, nt0, Crypto1.prng_next(nt0, 32))

    nt1 = Crypto1.prng_next(nt0, 32 * 0x1000)  # a much later nonce
    nr1, ar1 = synth_auth(uid, key_hex, nt1, Crypto1.prng_next(nt1, 32))

    # sanity: the synthesized trace must satisfy the oracle
    check("synthetic trace verifies with the oracle",
          Crypto1.mfkey32_is_reader_has_key(uid, nt0, nr0, ar0, key_hex))

    out = run(exe, "mfkey32", f"{uid:08X}", f"{nt0:08X}", f"{nr0:08X}", f"{ar0:08X}",
              f"{nt1:08X}", f"{nr1:08X}", f"{ar1:08X}")
    parts = out.split()
    status = int(parts[0]) if parts else -1
    recovered = parts[1] if len(parts) > 1 else "?"
    check("status == Found(0)", status == 0, f"got status {status}")
    check(f"recovered key == {key64:012X}", recovered.upper() == f"{key64:012X}", f"got {recovered}")

    # ---- 5. the Tools page's mfkey32 path: trace bytes -> key ------------
    # sniff_decoder.cpp and mfkey32.cpp were each verified separately; this is
    # the join the "mfkey32 crack last trace" button actually runs, and the only
    # place a field mix-up between nr_enc and ar_enc would show up.
    print("\n== mfkey32 from a raw trace (the Tools page button path) ==")

    def push_frame(out, data, bits, from_card):
        header = bits | (0x8000 if from_card else 0)
        out += header.to_bytes(2, "big")
        out += bytes(data)

    trace = bytearray()
    push_frame(trace, [0x26], 7, False)                      # REQA (7 bits: not byte aligned)
    push_frame(trace, [0x04, 0x40], 16, True)                # ATQA
    push_frame(trace, [0x93, 0x20], 16, False)               # anticoll
    push_frame(trace, [(uid >> 24) & 0xFF, (uid >> 16) & 0xFF, (uid >> 8) & 0xFF, uid & 0xFF], 32, True)
    for nt, nr, ar, block in ((nt0, nr0, ar0, 3), (nt1, nr1, ar1, 4)):
        push_frame(trace, [0x60, block, 0xAA, 0xBB], 32, False)                 # AUTH key A + CRC
        push_frame(trace, list(nt.to_bytes(4, "big")), 32, True)                # tag nonce
        push_frame(trace, list(nr.to_bytes(4, "big")) + list(ar.to_bytes(4, "big")), 64, False)
        push_frame(trace, list(ar.to_bytes(4, "big")), 32, True)                # tag answer

    out = run(exe, "crack", trace.hex(), f"{uid:08X}").split("\n")
    print("  " + " | ".join(line for line in out if line.strip()))
    check("the decoder found two complete authentications in the trace",
          any(line.startswith("auths 2 usable 2") for line in out), " | ".join(out))
    tail = out[-1].split() if out else []
    check("mfkey32 from the decoded trace reports Found(0)",
          tail and tail[0] == "0", " | ".join(out))
    check(f"and recovers {key64:012X}",
          len(tail) > 1 and tail[1].upper() == f"{key64:012X}", " | ".join(out))

    # A trace whose authentication is incomplete (the card rejected the key, so
    # the last frame is missing) must be reported as unusable rather than
    # searched: this is exactly what the button shows for the device's own
    # traces, which cannot contain a solvable pair.
    one = bytearray()
    push_frame(one, [0x26], 7, False)
    push_frame(one, [0x60, 0x03, 0xAA, 0xBB], 32, False)     # AUTH key A, block 3
    push_frame(one, list(nt0.to_bytes(4, "big")), 32, True)  # tag nonce
    push_frame(one, list(nr0.to_bytes(4, "big")) + list(ar0.to_bytes(4, "big")), 64, False)
    # ... and then the trace stops: no tag answer frame.
    out_one = run(exe, "crack", one.hex(), f"{uid:08X}")
    check("an incomplete authentication counts as unusable",
          "auths 1 usable 0" in out_one, out_one.replace("\n", " | "))
    check("and no search is started for it",
          len([line for line in out_one.splitlines() if line.strip()]) == 1,
          out_one.replace("\n", " | "))

    # ---- 6. how much memory does it actually use? -----------------------
    # This is the number that decides whether the recovery fits in the Tab5's
    # ~24 MB of free PSRAM.
    print("\n== actual peak memory (decides the Tab5 budget) ==")
    peaks = []
    for trial in range(6):
        nt_a = (0xBE2B7B5D + trial * 0x01010101) & 0xFFFFFFFF
        nr_a, ar_a = synth_auth(uid, key_hex, nt_a, Crypto1.prng_next(nt_a, 32))
        nt_b = Crypto1.prng_next(nt_a, 64)
        nr_b, ar_b = synth_auth(uid, key_hex, nt_b, Crypto1.prng_next(nt_b, 32))
        line = run(exe, "peak", f"{uid:08X}", f"{nt_a:08X}", f"{nr_a:08X}", f"{ar_a:08X}",
                   f"{nt_b:08X}", f"{nr_b:08X}", f"{ar_b:08X}").split()
        st, peak = int(line[0]), int(line[1])
        peaks.append(peak)
        print(f"  trial {trial}: status {st}  peak {peak/1048576:6.2f} MB")

    worst = max(peaks)
    print(f"\n  worst observed peak : {worst/1048576:.2f} MB")
    print(f"  Tab5 free PSRAM     : 24.20 MB")
    check("recovery fits in free PSRAM", worst < 24 * 1024 * 1024,
          f"peak {worst/1048576:.2f} MB vs 24.20 MB available")
    # leave room for LVGL and the rest of the system
    check("recovery leaves >= 4 MB headroom", worst < 20 * 1024 * 1024,
          f"peak {worst/1048576:.2f} MB")

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("ALL CRYPTO CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
