#!/usr/bin/env python3
"""Measure what upstream's hardnested bitflip tables actually cost.

The question this answers: hardnested's candidate-generation stage (the half
that lives in upstream's cmdhfmfhard.c, not in the two cores this project
already ported) builds its candidate state lists from precomputed bitflip
bitarrays. Upstream keeps them all resident:

    bitflip_bitarrays[2][0x400]        // cmdhfmfhard.c:231

which is 2048 pointers to buffers of `sizeof(uint32_t) * (1 << 19)` = 2 MiB
(cm dhfmfhard.c:266). How many of those are actually kept decides whether the
stage can run on a Tab5 at all, so it is measured instead of estimated: every
XZ blob in hardnested/tables.c is decompressed here and run through the very
same acceptance test upstream applies,

    if ((float)count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD)   // < 0.99

with `count` being the first four bytes of the decompressed stream (read as a
little-endian uint32 by lzma_init_inflate).

Usage:
    python measure_hardnested_tables.py [path/to/tables.c]

Defaults to the reference checkout's copy. Prints a summary table and exits
non-zero if the file or the expected symbol shapes are not found.
"""

import lzma
import os
import re
import struct
import sys
from pathlib import Path

# Where the reference ChameleonUltra checkout lives. The probes compare the port
# against upstream sources, so point this at your own checkout of
# https://github.com/chameleonultra/ChameleonUltra if it is somewhere else:
#     $env:CU_UPSTREAM = "D:\src\ChameleonUltra"
CU_UPSTREAM = Path(os.environ.get("CU_UPSTREAM", r"C:\Users\Jiang\Downloads\ChameleonUltra-main"))
# The probes compare against upstream sources; without them there is nothing to
# compare, so refuse to run rather than report a comparison of nothing.
_UPSTREAM_SENTINEL = CU_UPSTREAM / "software" / "script" / "chameleon_cmd.py"
if not _UPSTREAM_SENTINEL.is_file():
    raise SystemExit(
        f"upstream ChameleonUltra checkout not found at {CU_UPSTREAM}\n"
        f"  (looked for {_UPSTREAM_SENTINEL})\n"
        "set CU_UPSTREAM to your checkout of "
        "https://github.com/RfidResearchGroup/ChameleonUltra"
    )



DEFAULT_TABLES = CU_UPSTREAM / "software" / "src" / "HardnestedRecovery" / "hardnested" / "tables.c"

# cmdhfmfhard.c:243-244 and :265 - the numbers the acceptance test uses.
OUTPUT_BUFFER_LEN = 80
IGNORE_BITFLIP_THRESHOLD = 0.99
STATE_SPACE_BITS = 1 << 24
BITARRAY_BYTES = 4 * (1 << 19)  # sizeof(uint32_t) * (1 << 19)

ARRAY_RE = re.compile(
    rb"^uint8_t\s+(bitflip_(\d+)_([0-9a-f]+)_states_bin_xz)\[\]\s*=\s*\{",
    re.MULTILINE,
)


def parse_arrays(text):
    """Yield (name, odd_even, bitflip_id, bytes) for every XZ array in tables.c."""
    matches = list(ARRAY_RE.finditer(text))
    if not matches:
        raise SystemExit("no bitflip_*_states_bin_xz arrays found")
    for i, m in enumerate(matches):
        name = m.group(1).decode()
        odd_even = int(m.group(2))
        bitflip = int(m.group(3), 16)
        body_start = m.end()
        body_end = text.index(b"};", body_start)
        body = text[body_start:body_end]
        # The initialisers are plain decimal byte values, one per comma.
        values = re.findall(rb"0x([0-9a-fA-F]{2})|\b(\d{1,3})\b", body)
        data = bytearray()
        for hexv, decv in values:
            data.append(int(hexv, 16) if hexv else int(decv))
        yield name, odd_even, bitflip, bytes(data)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TABLES
    if not os.path.isfile(path):
        raise SystemExit("tables.c not found: %s" % path)
    with open(path, "rb") as fh:
        text = fh.read()

    print("tables.c: %s (%d bytes on disk)" % (path, len(text)))
    print()

    kept = {0: [], 1: []}      # bitflips surviving upstream's threshold
    skipped_fat = {0: [], 1: []}  # decompressed fine but rejected as "nearly all valid"
    all_ids = {0: set(), 1: set()}  # every blob id present in tables.c
    bad = []
    total_compressed = 0
    total_decompressed = 0

    for name, odd_even, bitflip, blob in parse_arrays(text):
        all_ids[odd_even].add(bitflip)
        total_compressed += len(blob)
        if blob[:6] != b"\xfd7zXZ\x00":
            bad.append((name, "not an XZ stream (first bytes %s)" % blob[:6].hex()))
            continue
        try:
            raw = lzma.decompress(blob)
        except lzma.LZMAError as exc:
            bad.append((name, "lzma: %s" % exc))
            continue
        total_decompressed += len(raw)
        if len(raw) < 4:
            bad.append((name, "decompressed to %d bytes, need 4 for count" % len(raw)))
            continue
        count = struct.unpack_from("<I", raw, 0)[0]
        if count / STATE_SPACE_BITS < IGNORE_BITFLIP_THRESHOLD:
            kept[odd_even].append((bitflip, count, len(blob), len(raw)))
        else:
            skipped_fat[odd_even].append((bitflip, count))

    for odd_even, label in ((0, "EVEN_STATE (bitflip_0_*)"), (1, "ODD_STATE (bitflip_1_*)")):
        k = kept[odd_even]
        s = skipped_fat[odd_even]
        print("%s" % label)
        print("  blobs in tables.c          : %d" % (len(k) + len(s)))
        print("  kept by upstream threshold : %d" % len(k))
        print("  rejected (count/2^24>=0.99): %d" % len(s))
        if k:
            counts = [c for _, c, _, _ in k]
            print("  count range of kept        : %d .. %d (of 2^24)" % (min(counts), max(counts)))
            print("  resident RAM if all kept   : %.2f MiB" % (len(k) * BITARRAY_BYTES / (1024.0 * 1024.0)))
            print("  sum of real decompressed   : %.2f MiB" % (sum(l for _, _, _, l in k) / (1024.0 * 1024.0)))
        print()

    num_all = len(kept[0]) + len(kept[1])
    print("all_effective_bitflip would hold %d entries" % num_all)
    print("resident bitflip_bitarrays[2][0x400] if all kept: %.2f MiB"
          % (num_all * BITARRAY_BYTES / (1024.0 * 1024.0)))
    print("tables.c total compressed   : %.2f MiB" % (total_compressed / (1024.0 * 1024.0)))
    print("tables.c total decompressed : %.2f MiB" % (total_decompressed / (1024.0 * 1024.0)))
    print()

    if bad:
        print("PROBLEMS (%d):" % len(bad))
        for name, why in bad[:20]:
            print("  %-40s %s" % (name, why))
        return 1

    # Cross-check the two lookup tables at the end of tables.c: get_bitflip()
    # only ever reaches a blob through them, so their key sets must be exactly
    # the set of blobs this file defines - no missing entry (a table the
    # candidate generation would skip) and no dangling one (a pointer to an array
    # that is not there).
    #
    # The entries use designated initializers:
    #   [0x001].len = bitflip_0_001_states_bin_xz_len, [0x001].input_buffer = ...
    # and the table holds *every* blob, including the ones the threshold later
    # rejects, so this compares against all of them rather than against the kept
    # subset.
    for table, odd_even in ((b"bf_zero", 0), (b"bf_one", 1)):
        start = text.index(b"static bitflip_info %s[0x400]" % table)
        end = text.index(b"};", start)
        body = text[start:end]
        ids = set()
        for m in re.finditer(rb"\[0x([0-9a-fA-F]+)\]\.len\s*=\s*(\w+)", body):
            blob_id = int(m.group(1), 16)
            blob_name = m.group(2)
            # The declared id must match the array it points at.
            want = b"bitflip_%d_%03x_states_bin_xz_len" % (odd_even, blob_id)
            if blob_name != want:
                print("  MISMATCH %s[0x%03X] points at %s, expected %s"
                      % (table.decode(), blob_id, blob_name.decode(), want.decode()))
                return 1
            ids.add(blob_id)

        print("%s: %d entries, %d blob(s) in tables.c (bitflip_%d_*)"
              % (table.decode(), len(ids), len(all_ids[odd_even]), odd_even))
        if ids != all_ids[odd_even]:
            print("  MISMATCH: the lookup table and the blobs in this file differ")
            print("    only in %s      : %s" % (table.decode(), [hex(i) for i in sorted(ids - all_ids[odd_even])][:10]))
            print("    only in tables.c: %s"
                  % [hex(i) for i in sorted(all_ids[odd_even] - ids)][:10])
            return 1
    print()
    print("OK - every blob in tables.c has exactly one bf_zero/bf_one entry pointing "
          "at it, and every entry points at the array matching its id.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
