#!/usr/bin/env python3
"""Verify the Tab5 hardnested acquisition port against upstream.

What is being ported here is the *client* half of ChameleonUltra's hardnested
attack: the device acquires nonces (MF1_HARDNESTED_ACQUIRE), the client tracks
the first-byte parity sum and writes the nine-bytes-per-pair nonce file, and a
separate PC program (HardnestedRecovery) cracks that file. The solver is not
part of this port - see docs/M5-KEY-RECOVERY.md section 6 for the measured
reason (474 MiB + 1 GiB resident versus 32 MB of PSRAM).

Checks, each against upstream code rather than against a number written here:

  [0] the 19 legal Sum(a8) values in firmware/main/hardnested_acquire.cpp match
      both hardnested_utils.py (imported unmodified) and cmdhfmfhard.c's sums[],
      and the values the *compiled* table returns match them too
  [1] FirstByteTracker agrees with hardnested_utils.check_nonce_unique_sum on
      random collections, including duplicate first bytes and a trailing partial
      record
  [2] Crc32 agrees with binascii.crc32
  [3] the nonce file is read back correctly by upstream's own reader:
      HardnestedRecovery/hardnested_main.c, compiled verbatim, with only its
      solver replaced by a stub that prints the nonce pairs it receives
  [4] export -> tools/nonce_file_from_console.py reproduces the file byte for
      byte, and so does the ported line parser
  [5] dropping one exported line makes the decoder refuse the capture (the CRC
      check is not decorative)

Usage:  python tools/verify_hardnested_acquire.py
"""

import os
import binascii
import importlib.util
import random
import re
import subprocess
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



REPO = Path(__file__).resolve().parent.parent
MINE = REPO / "firmware" / "main"
TOOLS = REPO / "tools"
HOST_STUBS = TOOLS / "host_stubs"
PROBE_DIR = REPO / ".probe" / "hardnested"

UPSTREAM = CU_UPSTREAM / "software" / "src"
HARDNESTED_RECOVERY = UPSTREAM / "HardnestedRecovery"
SCRIPT_DIR = CU_UPSTREAM / "software" / "script"
GCC = Path(r"C:\mingw64\bin\gcc.exe")
GXX = Path(r"C:\mingw64\bin\g++.exe")

RECORD_SIZE = 9
HEADER_SIZE = 6
BYTES_PER_LINE = 16

failures = []


def gcc(args, **kwargs):
    """Decode compiler output as UTF-8 with replacement.

    subprocess defaults to the locale codec (GBK here); one byte that is not
    valid GBK raises inside the reader thread and leaves stdout/stderr as None,
    which replaces the real diagnostic with a TypeError while formatting it.
    """
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kwargs)


def build_harness():
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    exe = PROBE_DIR / "hardnested_harness.exe"
    res = gcc([str(GXX), "-std=gnu++17", "-O2", "-w",
               "-I", str(MINE), "-I", str(HOST_STUBS),
               str(HOST_STUBS / "hardnested_harness.cpp"),
               str(MINE / "hardnested_acquire.cpp"),
               "-o", str(exe)])
    if res.returncode != 0:
        print("harness build failed:\nHEAD:\n%s\n%s\nTAIL:\n%s"
              % ((res.stdout or "")[:1200], (res.stderr or "")[:1200], (res.stderr or "")[-800:]))
        sys.exit(1)
    return exe


ORACLE_STUB = r"""
/* Replaces only mfnestedhard()/hardnested_print_progress() so that upstream's
   own hardnested_main.c can be compiled and run: its reader is what proves the
   nonce file this port writes has the layout upstream's tool expects. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "cmdhfmfhard.h"

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType,
                 uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, uint64_t *foundkey,
                 char *filename, uint32_t uid, char *path) {
    (void)key; (void)trgBlockNo; (void)trgKeyType; (void)trgkey; (void)nonce_file_read;
    (void)nonce_file_write; (void)slow; (void)foundkey; (void)filename;
    printf("STUB uid=%08" PRIX32 " sector=%u keytype=%u path=%s\n", uid, blockNo, keyType, path ? path : "(null)");
    FILE *f = fopen(path, "r");
    if (f == NULL) { printf("STUB no-temp-file\n"); return 0; }
    unsigned long nt; unsigned par; int idx = 0;
    while (fscanf(f, "%lu|%u", &nt, &par) == 2) {
        printf("STUB NONCE %d %08lX %u\n", idx++, nt, par);
    }
    fclose(f);
    return 0;
}

void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time) {
    (void)nonces; (void)activity; (void)brute_force; (void)min_diff_print_time;
}
"""


def build_upstream_reader():
    """Compile upstream's hardnested_main.c verbatim plus the solver stub."""
    stub = PROBE_DIR / "upstream_solver_stub.c"
    stub.write_text(ORACLE_STUB, encoding="utf-8")
    exe = PROBE_DIR / "upstream_reader.exe"
    res = gcc([str(GCC), "-w", "-O1",
               "-I", str(HARDNESTED_RECOVERY), "-I", str(HARDNESTED_RECOVERY / "pm3"),
               str(HARDNESTED_RECOVERY / "hardnested_main.c"), str(stub),
               "-o", str(exe)])
    if res.returncode != 0:
        print("upstream reader build failed:\n%s\n%s" % ((res.stdout or "")[:1500], (res.stderr or "")[:1500]))
        sys.exit(1)
    return exe


def run(exe, argv, timeout=180):
    res = subprocess.run([str(exe), *argv], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=timeout)
    if res.returncode != 0:
        print("    ! %s %s exited %d: %s" % (Path(exe).name, argv, res.returncode, (res.stderr or "").strip()[:300]))
    return res


def check(label, ok, detail=""):
    if ok:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s  %s" % (label, detail))
        failures.append(label)


def load_hardnested_utils():
    """Import upstream's hardnested_utils.py unmodified."""
    path = SCRIPT_DIR / "hardnested_utils.py"
    spec = importlib.util.spec_from_file_location("hardnested_utils", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_table(text, pattern, group=1):
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return None
    return [int(v.strip()) for v in m.group(group).split(",") if v.strip()]


def make_records(rng, runs):
    """Deterministic nonce-pair records: mostly 9 byte records, one run ends on
    a half record, because the device can report an odd nonce count."""
    raw = bytearray()
    for run_index, n in enumerate(runs):
        for i in range(n):
            nt1 = rng.getrandbits(32)
            nt2 = rng.getrandbits(32)
            # Realistic packing: bit 3 of the second nibble is the parity of the
            # second nonce's first byte, and every first byte must appear at some
            # point for the completion path to be exercised.
            msb = nt2 >> 24
            par_bit = bin(msb).count("1") & 1
            par = ((rng.getrandbits(4) << 4) | (rng.getrandbits(3) << 1) | par_bit) & 0xFF
            raw += nt1.to_bytes(4, "big") + nt2.to_bytes(4, "big") + bytes([par])
        if run_index == 0:
            # A trailing 4 byte fragment as mf1_toolbox.c produces for an odd
            # nonce count; it must be ignored by both implementations.
            raw += rng.getrandbits(32).to_bytes(4, "big")
    return bytes(raw)


def main():
    print("hardnested acquisition probe")
    print("  upstream: %s" % UPSTREAM)
    print()

    harness = build_harness()
    reader = build_upstream_reader()
    hnu = load_hardnested_utils()
    rng = random.Random(0x5A17C0DE)

    mine_src = (MINE / "hardnested_acquire.cpp").read_text(encoding="utf-8", errors="replace")
    upstream_cmd = (HARDNESTED_RECOVERY / "cmdhfmfhard.c").read_text(encoding="utf-8", errors="replace")

    # ------------------------------------------------------------------ [0]
    print("[0] the 19 Sum(a8) values")
    mine = parse_table(mine_src, r"kValidSums\[kValidSumCount\]\s*=\s*\{(.*?)\};")
    up_cmd = parse_table(upstream_cmd, r"static uint16_t sums\[NUM_SUMS\]\s*=\s*\{(.*?)\};")
    # NUM_SUMS lives in the bruteforce header, which is where cmdhfmfhard.c gets
    # it from (via cmdhfmfhard.h -> hardnested_bruteforce.h).
    up_bf_header = (HARDNESTED_RECOVERY / "hardnested" / "hardnested_bruteforce.h").read_text(
        encoding="utf-8", errors="replace")
    up_num_sums = re.search(r"#define NUM_SUMS\s+(\d+)", up_bf_header)
    compiled = [int(v) for v in run(harness, ["sums"]).stdout.strip().split(",")]

    print("    port      : %s" % mine)
    print("    pm3 sums[]: %s" % up_cmd)
    print("    python    : %s" % hnu.hardnested_sums)
    check("the ported table exists", mine is not None)
    check("matches cmdhfmfhard.c sums[]", mine == up_cmd, "%s vs %s" % (mine, up_cmd))
    check("matches hardnested_utils.hardnested_sums", mine == hnu.hardnested_sums)
    check("matches the compiled table", mine == compiled, "%s vs %s" % (mine, compiled))
    check("count matches NUM_SUMS in cmdhfmfhard.c",
          up_num_sums is not None and len(mine) == int(up_num_sums.group(1)),
          "NUM_SUMS=%s" % (up_num_sums.group(1) if up_num_sums else "?"))
    check("count matches kValidSumCount in the header",
          len(mine) == int(re.search(r"kValidSumCount\s*=\s*(\d+)",
                                     (MINE / "hardnested_acquire.h").read_text(encoding="utf-8")).group(1)))
    print()

    # ------------------------------------------------------------------ [1]
    print("[1] FirstByteTracker vs hardnested_utils.check_nonce_unique_sum")
    cases = [
        ("all 256 first bytes, one record each", [256]),
        ("a run that repeats first bytes", [40, 40, 40]),
        ("one record only", [1]),
        ("empty", []),
        ("256 + duplicates in a second run", [256, 12]),
    ]
    for name, runs in cases:
        raw = make_records(rng, runs) if runs else b""
        rec_path = PROBE_DIR / "records.bin"
        rec_path.write_bytes(raw)

        out = run(harness, ["track", str(rec_path)]).stdout
        m_first = re.search(r"RECORDS=(\d+) UNIQ=(\d+) SUM=(\d+) COMPLETE=(\d) VALID=(\d)", out)
        m_second = re.search(r"PERRECORD_NEW=(\d+) UNIQ=(\d+) SUM=(\d+) VALID=(\d)", out)
        if not m_first or not m_second:
            check(name, False, "harness output: %r" % out[:200])
            continue

        # Upstream's own Python, driven exactly as chameleon_cli_unit.py drives it.
        hnu.reset()
        for i in range(len(raw) // RECORD_SIZE):
            off = i * RECORD_SIZE
            nt_enc1 = int.from_bytes(raw[off:off + 4], "big")
            nt_enc2 = int.from_bytes(raw[off + 4:off + 8], "big")
            par = raw[off + 8]
            hnu.check_nonce_unique_sum(nt_enc2, par)
        py_unique = hnu.hardnested_first_byte_num
        py_sum = hnu.hardnested_first_byte_sum
        py_valid = py_sum in hnu.hardnested_sums

        ok = (int(m_first.group(2)) == py_unique and int(m_first.group(3)) == py_sum
              and bool(int(m_first.group(5))) == py_valid
              and int(m_first.group(4)) == (1 if py_unique == 256 else 0))
        check(name, ok, "port uniq=%s sum=%s valid=%s | python uniq=%d sum=%d valid=%s"
              % (m_first.group(2), m_first.group(3), m_first.group(5), py_unique, py_sum, py_valid))
        check("  %s: per-record path agrees with the run path" % name,
              (m_first.group(2), m_first.group(3)) == (m_second.group(2), m_second.group(3)),
              "%s vs %s" % (m_first.groups(), m_second.groups()))
        check("  %s: record count (partial record dropped)" % name,
              int(m_first.group(1)) == len(raw) // RECORD_SIZE,
              "%s vs %d" % (m_first.group(1), len(raw) // RECORD_SIZE))
    print()

    # ------------------------------------------------------------------ [2]
    print("[2] Crc32 vs binascii.crc32")
    for n in (0, 1, 5, 6, 100, 4096):
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        p = PROBE_DIR / "crc.bin"
        p.write_bytes(blob)
        got = run(harness, ["crc", str(p)]).stdout.strip()
        want = "%08X" % (binascii.crc32(blob) & 0xFFFFFFFF)
        check("%d bytes" % n, got == want, "%s vs %s" % (got, want))
    print()

    # ------------------------------------------------------------------ [3]
    print("[3] the nonce file read back by upstream's hardnested_main.c")
    # Enough records that several lines are needed, and a UID/sector/type that
    # are easy to tell apart from the defaults.
    raw = make_records(rng, [300])
    rec_path = PROBE_DIR / "records.bin"
    rec_path.write_bytes(raw)

    uid_bytes = bytes([0x04, 0x3D, 0xB7, 0x65])   # last four of a 7 byte UID
    sector = 0x0B
    key_type = 1                                   # B
    header_hex = (uid_bytes + bytes([sector, key_type])).hex()
    nonce_file = PROBE_DIR / "nonces.bin"

    out = run(harness, ["build", str(rec_path), header_hex, str(nonce_file)]).stdout
    m = re.search(r"SZ=([0-9A-F]+) CRC=([0-9A-F]{8}) REC=([0-9A-F]+)", out)
    check("build reports a size", m is not None, out[:200])
    if m:
        want_size = HEADER_SIZE + (len(raw) // RECORD_SIZE) * RECORD_SIZE
        blob = nonce_file.read_bytes()
        check("file size", len(blob) == want_size and int(m.group(1), 16) == want_size,
              "%d vs %d" % (len(blob), want_size))
        check("file CRC32 vs binascii", m.group(2) == "%08X" % (binascii.crc32(blob) & 0xFFFFFFFF))
        check("header bytes", blob[0:4] == uid_bytes and blob[4] == sector and blob[5] == key_type,
              blob[0:6].hex())

    # Upstream's reader writes a temp text file of "%u|%u" per nonce and hands
    # its path to the solver; the stub prints what it finds there.
    cwd = PROBE_DIR / "run"
    cwd.mkdir(exist_ok=True)
    res = subprocess.run([str(reader), str(nonce_file.resolve())], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", cwd=str(cwd), timeout=120)
    text = res.stdout
    print("    upstream reader said: %s" % text.splitlines()[0] if text else "    upstream reader said nothing")

    m = re.search(r"Read Header -> UID: ([0-9a-fA-F]{8}), Sector: (\d+), Key type: ([AB])", text)
    if not m:
        check("upstream reader accepted the file", False, text[:400])
    else:
        check("upstream reader read the UID", int(m.group(1), 16) == int.from_bytes(uid_bytes, "big"),
              m.group(1))
        check("upstream reader read the sector", int(m.group(2)) == sector, m.group(2))
        check("upstream reader read the key type", m.group(3) == "B", m.group(3))

    stub_line = re.search(r"STUB uid=([0-9A-F]+) sector=(\d+) keytype=(\d+)", text)
    check("solver stub received the parsed header", stub_line is not None)
    nonces = re.findall(r"STUB NONCE (\d+) ([0-9A-F]+) (\d+)", text)
    want_pairs = len(raw) // RECORD_SIZE
    check("upstream reader handed the solver %d nonces (%d pairs)" % (want_pairs * 2, want_pairs),
          len(nonces) == want_pairs * 2, "got %d" % len(nonces))
    if len(nonces) == want_pairs * 2:
        mismatches = 0
        for pair in range(want_pairs):
            for half in (0, 1):
                off = pair * RECORD_SIZE + half * 4
                want_nt = int.from_bytes(raw[off:off + 4], "big")
                if half == 0:
                    want_par = raw[pair * RECORD_SIZE + 8] >> 4
                else:
                    want_par = raw[pair * RECORD_SIZE + 8] & 0x0F
                got_nt = int(nonces[pair * 2 + half][1], 16)
                got_par = int(nonces[pair * 2 + half][2])
                if got_nt != want_nt or got_par != want_par:
                    mismatches += 1
        check("every nonce and parity survived the round trip", mismatches == 0,
              "%d mismatching nonces" % mismatches)
    print()

    # ------------------------------------------------------------------ [4]
    print("[4] console export -> tools/nonce_file_from_console.py")
    export_txt = PROBE_DIR / "export.txt"
    res = run(harness, ["export", str(nonce_file)])
    export_txt.write_text(res.stdout, encoding="utf-8")
    lines = [l for l in res.stdout.splitlines() if "[HN]" in l]
    print("    export produced %d lines, %d of them data lines"
          % (len(lines), len(re.findall(r"\[HN\] [0-9A-F]{4} ", res.stdout))))
    check("export has a BEGIN line", any("BEGIN" in l for l in lines))
    check("export has an END line", any("END" in l for l in lines))
    check("export lines fit the 96 byte log line",
          all(len(l.split("[log] ")[-1]) <= 96 for l in lines),
          str(max(len(l) for l in lines)))

    rebuilt = PROBE_DIR / "rebuilt.bin"
    res = subprocess.run([sys.executable, str(TOOLS / "nonce_file_from_console.py"), str(export_txt),
                          "-o", str(rebuilt)], capture_output=True, text=True, encoding="utf-8",
                         errors="replace")
    print("    decoder: %s" % (res.stdout.strip() or res.stderr.strip()[:200]))
    check("decoder exits 0", res.returncode == 0, res.stderr.strip()[:300])
    check("decoder rebuilt the file byte for byte",
          rebuilt.exists() and rebuilt.read_bytes() == nonce_file.read_bytes())

    reparsed = PROBE_DIR / "reparsed.bin"
    out = run(harness, ["reparse", str(export_txt), str(reparsed)]).stdout
    check("ported line parser rebuilt the file byte for byte",
          reparsed.exists() and reparsed.read_bytes() == nonce_file.read_bytes(), out.strip())

    # The data lines encode their offset in four hex digits, so the last file
    # that can be represented is 6 + 7281 * 9 = 65535 bytes. Both sides of that
    # boundary are checked, because an off-by-one here would silently make the
    # last lines unreachable.
    for count, should_fit in ((7281, True), (7282, False)):
        big_raw = make_records(rng, [count])
        big_rec = PROBE_DIR / "big_records.bin"
        big_rec.write_bytes(big_raw[:count * RECORD_SIZE])
        big_file = PROBE_DIR / "big_nonces.bin"
        res = run(harness, ["build", str(big_rec), header_hex, str(big_file)])
        size = HEADER_SIZE + count * RECORD_SIZE
        res = run(harness, ["export", str(big_file)])
        emitted = res.stdout.count("[HN]")
        if should_fit:
            check("%d records (%d bytes) export" % (count, size),
                  res.returncode == 0 and emitted == 2 + (size + BYTES_PER_LINE - 1) // BYTES_PER_LINE,
                  "exit %d, %d lines" % (res.returncode, emitted))
        else:
            check("%d records (%d bytes) is refused" % (count, size),
                  res.returncode != 0 and "ERROR" in res.stdout and "SZ=%X" % size in res.stdout,
                  "exit %d, output %r" % (res.returncode, res.stdout[:200]))
    print()

    # ------------------------------------------------------------------ [5]
    print("[5] a capture that lost a line must be refused")
    kept = [l for l in export_txt.read_text(encoding="utf-8").splitlines()]
    data_indexes = [i for i, l in enumerate(kept) if re.search(r"\[HN\] [0-9A-F]{4} ", l)]
    dropped = kept[:data_indexes[len(data_indexes) // 2]] + kept[data_indexes[len(data_indexes) // 2] + 1:]
    truncated = PROBE_DIR / "export_dropped.txt"
    truncated.write_text("\n".join(dropped), encoding="utf-8")
    res = subprocess.run([sys.executable, str(TOOLS / "nonce_file_from_console.py"), str(truncated),
                          "-o", str(PROBE_DIR / "should_not_exist.bin")],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    check("decoder refuses the damaged capture", res.returncode != 0, "it exited 0")
    check("and says why", "CRC32 mismatch" in res.stderr or "gap" in res.stderr or "only" in res.stderr,
          res.stderr.strip()[:200])

    # A capture with no markers at all must also be refused.
    res = subprocess.run([sys.executable, str(TOOLS / "nonce_file_from_console.py"), "-"],
                         input="nothing to see here\n", capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    check("decoder refuses a capture with no markers", res.returncode != 0 and "BEGIN" in res.stderr,
          res.stderr.strip()[:200])
    print()

    if failures:
        print("%d CHECK(S) FAILED:" % len(failures))
        for f in failures:
            print("  -", f)
        return 1
    print("ALL HARDNESTED ACQUISITION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
