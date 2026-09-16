"""Cross-check the darkside key-recovery core against upstream mfkey.c.

nonce2key() is the piece that turns the material MF1_DARKSIDE_ACQUIRE collects
(uid, nt, nr, ar, par, ks) into candidate keys. It has never been exercised on
this project, and the port had to change one thing upstream does not:
lfsr_common_prefix() there allocates 8 * 2^24 = 128 MB, which cannot exist on the
Tab5, so the port sizes the list from the real candidate counts instead.

That change is only safe if the produced key lists are identical, so this probe
compiles BOTH implementations and compares them on the same inputs:

  A) firmware/components/chameleon_crypto  (derived list size, bounds checks)
  B) software/src from the reference repo  (fixed 128 MB, no bounds checks)

Both the par==0 ("parity zero", no_par=1) and par!=0 paths are covered, because
they exercise different branches of check_pfx_parity().

Usage:  python tools/probe_darkside.py
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

HARNESS = r"""
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "mfkey.h"
#include "crapto1.h"
}

/* prefixks <ks> <isodd> : how many partial-state candidates survive? */
static int cmd_prefixks(int argc, char** argv) {
    if (argc < 4) return 2;
    uint64_t ksv = strtoull(argv[2], NULL, 16);
    uint8_t ks[8];
    for (int i = 0; i < 8; ++i) ks[i] = (ksv >> (i * 8)) & 0x0F;
    uint32_t* c = lfsr_prefix_ks(ks, atoi(argv[3]));
    if (!c) { printf("-1\n"); return 0; }
    uint32_t n = 0;
    while (c[n] != (uint32_t)-1 && n < 5000) ++n;
    printf("%u\n", n);
    free(c);
    return 0;
}

/* n2k <uid> <nt> <nr> <ar> <par> <ks> : print the recovered key list */
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "prefixks") == 0) return cmd_prefixks(argc, argv);
    if (argc < 7) return 2;

    uint32_t uid = (uint32_t)strtoul(argv[1], NULL, 16);
    uint32_t nt  = (uint32_t)strtoul(argv[2], NULL, 16);
    uint32_t nr  = (uint32_t)strtoul(argv[3], NULL, 16);
    uint32_t ar  = (uint32_t)strtoul(argv[4], NULL, 16);
    uint64_t par = strtoull(argv[5], NULL, 16);
    uint64_t ks  = strtoull(argv[6], NULL, 16);

    uint64_t* keys = NULL;
    uint32_t n = nonce2key(uid, nt, nr, ar, par, ks, &keys);

    printf("%u", n);
    for (uint32_t i = 0; i < n; ++i) {
        printf(" %012" PRIX64, keys[i]);
    }
    printf("\n");
    free(keys);
    return 0;
}
"""


def build(out_dir, variant):
    src = out_dir / f"n2k_{variant}.cpp"
    src.write_text(HARNESS, encoding="utf-8")
    exe = out_dir / f"n2k_{variant}.exe"

    if variant == "mine":
        base = MINE / "src"
        inc = [HOST_STUBS, MINE / "include", MINE / "src"]
        extra = ["-include", str(HOST_STUBS / "esp_heap_caps.h")]
    else:
        base = UPSTREAM
        inc = [UPSTREAM]
        extra = []

    args = [str(GCC), "-std=gnu++17", "-O2", "-w"]
    for d in inc:
        args += ["-I", str(d)]
    args.append(str(src))
    for name in ("crapto1.c", "crypto1.c", "parity.c", "bucketsort.c", "mfkey.c"):
        args += ["-x", "c", *extra, str(base / name)]
    args += ["-o", str(exe)]

    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"build {variant} failed:\n{res.stdout}\n{res.stderr}")
        sys.exit(1)
    return exe


def run(exe, argv):
    res = subprocess.run([str(exe), *argv], capture_output=True, text=True)
    if res.returncode != 0:
        return f"<exit {res.returncode}>"
    return res.stdout.strip()


def main():
    # Deterministic input space: a 32 bit LCG so both runs see identical values
    # and the case list is reproducible from the seed printed below.
    def lcg(state):
        return (state * 1103515245 + 12345) & 0xFFFFFFFF

    seed = 0x1234ABCD
    cases = []
    s = seed
    for i in range(24):
        s = lcg(s); uid = s
        s = lcg(s); nt = s
        s = lcg(s); nr = s
        s = lcg(s); ar = s
        s = lcg(s); ks = ((s & 0x0F0F0F0F) | ((s & 0x0F0F0F0F) << 4)) & 0xFFFFFFFF
        s = lcg(s); par = s
        # Alternate the two branches: par == 0 selects the no_par code path.
        if i % 2 == 0:
            par = 0
        cases.append((uid, nt, nr, ar, par, ks))
    # A second keystream pattern: every nibble equal, the degenerate case the
    # 1024-entry upstream candidate list could not have held.
    cases.append((0xDEADBEEF, 0xCAFEBABE, 0xA0A0A0A0, 0x12345678, 0, 0x00000000))
    cases.append((0xDEADBEEF, 0xCAFEBABE, 0xA0A0A0A0, 0x12345678, 0, 0x11111111))

    print(f"seed=0x{seed:08X}, {len(cases)} cases (par==0 on even indexes)")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        exe_mine = build(tmp, "mine")
        exe_up = build(tmp, "upstream")

        mismatches = 0
        empty = 0
        nonzero_par_ok = 0
        largest = 0
        for i, (uid, nt, nr, ar, par, ks) in enumerate(cases):
            argv = [f"{uid:08X}", f"{nt:08X}", f"{nr:08X}", f"{ar:08X}", f"{par:016X}", f"{ks:016X}"]
            a = run(exe_mine, argv)
            b = run(exe_up, argv)
            n = int(a.split()[0]) if a and not a.startswith("<") else -1
            if n == 0:
                empty += 1
            else:
                largest = max(largest, n)
            if par != 0 and n > 0:
                nonzero_par_ok += 1
            if a != b:
                mismatches += 1
                ta, tb = a.split(), b.split()
                print(f"  MISMATCH case {i}: par={par:016X} ks={ks:016X}")
                print(f"    mine    : n={ta[0]} first={ta[1:4]}")
                print(f"    upstream: n={tb[0]} first={tb[1:4]}")
            else:
                first = a.split()[1:3]
                print(f"  ok  case {i:2d} par={par:016X} -> n={n:6d} {first}")

        # The port sizes the state list from odd_count * even_count * 64 instead
        # of upstream's fixed 8 * 2^24. That is only sound if the candidate
        # counts really are small, so read them instead of assuming.
        print("\n  partial-state candidates per side (the sizing input):")
        for ks in (0x0000000000000000, 0x1111111111111111, 0x0F0F0F0F0F0F0F0F,
                   0x0123456789ABCDEF, 0xAAAAAAAAAAAAAAAA):
            counts = []
            for isodd in (0, 1):
                a = run(exe_mine, ["prefixks", f"{ks:016X}", str(isodd)])
                b = run(exe_up, ["prefixks", f"{ks:016X}", str(isodd)])
                counts.append((a, b))
            agree = all(x == y for x, y in counts)
            odd, even = counts[0][0], counts[1][0]
            bound = ""
            try:
                bound = f"  -> list bound {int(odd) * int(even) * 64} states"
            except ValueError:
                bound = ""
            print(f"    ks={ks:016X} odd={odd:>6} even={even:>6} agree={agree}{bound}")

        print()
        print(f"  cases with a non-empty key list : {len(cases) - empty}/{len(cases)}")
        print(f"  largest key list                : {largest} keys ({largest * 8 / 1048576:.2f} MB)")
        print(f"  par!=0 cases that produced keys : {nonzero_par_ok}")
        if empty == len(cases):
            print("  NOTE: every case was empty - the comparison would be vacuous")
        if nonzero_par_ok == 0:
            print("  NOTE: par!=0 only exercised the empty-result path. A consistent")
            print("        par vector has to come from a real card (40 parity")
            print("        constraints; random bits essentially never satisfy them),")
            print("        so that branch is compared but not yet meaningful.")
        if mismatches:
            print(f"{mismatches} MISMATCH(ES)")
            return 1
        print("ALL DARKSIDE CHECKS PASSED (identical to upstream mfkey.c)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
