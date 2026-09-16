"""Locate the mfkey32 recovery failure by diffing my port against upstream crapto1.

verify_crypto.py only says "no key found". This probe narrows it down by running
the SAME trace through two builds of lfsr_recovery32:

  A) firmware/components/chameleon_crypto  (my port: radix sort, bounds checks)
  B) software/src from the reference repo  (upstream: bucket_sort_intersect)

If A recovers fewer states than B, the bug is in my replacement of the bucketing,
not in the mfkey32 wrapper.

Usage:  python tools/probe_mfkey32.py
"""

import importlib.util
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

HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* crapto1.h has no extern "C" guard: without this the C objects get C++
   linkage and the link fails with undefined references. */
extern "C" {
#include "crapto1.h"
}

/* check <uid> <nt0> <nr0_enc> <ar0_enc> <nt1> <nr1_enc> <ar1_enc> <wantkey> */
int main(int argc, char** argv) {
    if (argc < 9) return 2;

    uint32_t uid = (uint32_t)strtoul(argv[1], NULL, 16);
    uint32_t nt0 = (uint32_t)strtoul(argv[2], NULL, 16);
    uint32_t nr0 = (uint32_t)strtoul(argv[3], NULL, 16);
    uint32_t ar0 = (uint32_t)strtoul(argv[4], NULL, 16);
    uint32_t nt1 = (uint32_t)strtoul(argv[5], NULL, 16);
    uint32_t nr1 = (uint32_t)strtoul(argv[6], NULL, 16);
    uint32_t ar1 = (uint32_t)strtoul(argv[7], NULL, 16);
    uint64_t want = strtoull(argv[8], NULL, 16);

    uint32_t p64  = prng_successor(nt0, 64);
    uint32_t p64b = prng_successor(nt1, 64);
    uint32_t ks2  = ar0 ^ p64;

    struct Crypto1State* s = lfsr_recovery32(ks2, 0);
    if (s == NULL) {
        printf("ks2=%08X p64=%08X states=NULL found=0\n", ks2, p64);
        return 0;
    }

    long n = 0;
    int found = 0;
    int found_second = 0;
    for (struct Crypto1State* t = s; t->odd | t->even; ++t) {
        struct Crypto1State c = *t;
        ++n;
        lfsr_rollback_word(&c, 0, 0);
        lfsr_rollback_word(&c, nr0, 1);
        lfsr_rollback_word(&c, uid ^ nt0, 0);
        uint64_t key = 0;
        crypto1_get_lfsr(&c, &key);
        if (key == want) {
            found = 1;
            /* does the second authentication confirm it? */
            crypto1_word(&c, uid ^ nt1, 0);
            crypto1_word(&c, nr1, 1);
            if (ar1 == (crypto1_word(&c, 0, 0) ^ p64b)) found_second = 1;
        }
    }
    printf("ks2=%08X p64=%08X p64b=%08X states=%ld key_in_list=%d second_auth_ok=%d\n",
           ks2, p64, p64b, n, found, found_second);
    free(s);
    return 0;
}
"""


def load_reference():
    sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("crypto1", SCRIPT_DIR / "crypto1.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["crypto1"] = mod
    spec.loader.exec_module(mod)
    return mod.Crypto1


def build(out_dir, variant):
    src = out_dir / f"recovery_{variant}.cpp"
    src.write_text(HARNESS, encoding="utf-8")
    exe = out_dir / f"recovery_{variant}.exe"

    if variant == "mine":
        c_sources = ["crapto1.c", "crypto1.c", "parity.c", "bucketsort.c"]
        inc = [HOST_STUBS, MINE / "include", MINE / "src"]
        base = MINE / "src"
        extra = ["-include", str(HOST_STUBS / "esp_heap_caps.h")]
    else:
        c_sources = ["crapto1.c", "crypto1.c", "parity.c", "bucketsort.c"]
        inc = [UPSTREAM]
        base = UPSTREAM
        extra = []

    args = [str(GCC), "-std=gnu++17", "-O2", "-w"]
    for d in inc:
        args += ["-I", str(d)]
    args.append(str(src))
    for name in c_sources:
        args += ["-x", "c", *extra, str(base / name)]
    args += ["-o", str(exe)]

    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"build {variant} failed:\n{res.stdout}\n{res.stderr}")
        sys.exit(1)
    return exe


def synth_auth(Crypto1, uid, key_hex, nt, nr_plain):
    """One three pass authentication as it appears on the wire."""
    st = Crypto1()
    st.key = key_hex
    st.lfsr48_u32(uid ^ nt, False)  # ks0
    ks1 = st.lfsr48_u32(nr_plain, False)  # ks1 encrypts nr
    ks2 = st.lfsr48_u32(0, False)  # ks2 encrypts ar
    return nr_plain ^ ks1, Crypto1.prng_next(nt, 64) ^ ks2


def main():
    Crypto1 = load_reference()

    uid = 0x65535D33
    key64 = 0xFFFFFFFFFFFF
    key_hex = f"{key64:012x}"

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        exe_mine = build(tmp, "mine")
        exe_up = build(tmp, "upstream")

        print("== same synthetic trace through both implementations ==")
        for label, nt0, nt1 in (
            ("two distant nonces (verify_crypto's case)", 0xBE2B7B5D, Crypto1.prng_next(0xBE2B7B5D, 32 * 0x1000)),
            ("two adjacent nonces (successor, 64 steps)", 0xBE2B7B5D, Crypto1.prng_next(0xBE2B7B5D, 64)),
            ("nonce pair from the mfkey32v2 doc example", 0x1A2B3C4D, 0x5E6F7A8B),
        ):
            nr0, ar0 = synth_auth(Crypto1, uid, key_hex, nt0, Crypto1.prng_next(nt0, 32))
            nr1, ar1 = synth_auth(Crypto1, uid, key_hex, nt1, Crypto1.prng_next(nt1, 32))
            argv = [f"{uid:08X}", f"{nt0:08X}", f"{nr0:08X}", f"{ar0:08X}",
                    f"{nt1:08X}", f"{nr1:08X}", f"{ar1:08X}", key_hex]

            oracle = Crypto1.mfkey32_is_reader_has_key(uid, nt0, nr0, ar0, key_hex)
            print(f"\n  {label}")
            print(f"    python oracle accepts auth1: {oracle}")
            for name, exe in (("mine    ", exe_mine), ("upstream", exe_up)):
                out = subprocess.run([str(exe), *argv], capture_output=True, text=True)
                print(f"    {name}: {out.stdout.strip() or out.stderr.strip()[:200]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
