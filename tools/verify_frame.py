"""Cross-check the firmware's framing against the official Python protocol.

Uses the real chameleon_com.py (reference repo) as the oracle, and compiles the
real C++ protocol sources for the host so the code under test is exactly what
runs on the Tab5.

Checks:
  1. host -> device : BuildFrame() bytes == ChameleonCom.make_data_frame_bytes()
  2. device -> host : FrameParser accepts every reference frame with the right
                      cmd/status/payload
  3. corruption     : bad LRC1/LRC2/LRC3 and truncation are rejected
  4. resync         : leading garbage before a valid frame is tolerated

Usage:  python tools/verify_frame.py
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
SCRIPT_DIR = CU_UPSTREAM / "software" / "script"
PROTO_DIR = REPO / "firmware" / "components" / "chameleon"

GCC = Path(r"C:\mingw64\bin\g++.exe")

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chameleon_protocol.h"

using namespace chameleon;

static void on_frame(const FrameParser::Frame& f, void* user) {
    (void)user;
    printf("ACCEPT %u %u %zu ", f.cmd, f.status, f.data_length);
    for (size_t i = 0; i < f.data_length; ++i) printf("%02X", f.data[i]);
    printf("\n");
}

static size_t unhex(const char* hex, uint8_t* out) {
    size_t n = 0;
    for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
        unsigned v = 0;
        if (sscanf(hex + i, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;

    if (strcmp(argv[1], "build") == 0 && argc >= 5) {
        uint16_t cmd = (uint16_t)strtoul(argv[2], NULL, 0);
        uint16_t st  = (uint16_t)strtoul(argv[3], NULL, 0);
        uint8_t payload[4096];
        size_t n = unhex(argv[4], payload);
        uint8_t frame[8192];
        size_t len = BuildFrame(frame, sizeof(frame), cmd, st, n ? payload : NULL, n);
        for (size_t i = 0; i < len; ++i) printf("%02X", frame[i]);
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "parse") == 0 && argc >= 3) {
        uint8_t buf[8192];
        size_t n = unhex(argv[2], buf);
        FrameParser p;
        size_t got = p.Push(buf, n, on_frame, NULL);
        printf("count %zu errors %u\n", got, p.errorCount());
        return 0;
    }
    return 2;
}
"""


def load_reference():
    """Return an object exposing make_data_frame_bytes()/lrc_calc().

    chameleon_com.py transitively imports chameleon_utils -> prompt_toolkit,
    which may not be installed here. In that case fall back to a verbatim copy
    of the two framing functions and say so: importing the real module is
    stronger evidence, so the fallback is announced rather than silent.
    """
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        spec = importlib.util.spec_from_file_location("chameleon_com", SCRIPT_DIR / "chameleon_com.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["chameleon_com"] = mod
        spec.loader.exec_module(mod)
        return mod.ChameleonCom(), "chameleon_com.py (imported)"
    except Exception as exc:
        print(f"note: cannot import chameleon_com.py: {exc}")
        print("      falling back to a verbatim copy of its framing functions")
        print("      (pip install prompt-toolkit colorama pyserial for the real module)")

    class Fallback:
        @staticmethod
        def lrc_calc(array):
            ret = 0x00
            for b in array:
                ret += b
                ret &= 0xFF
            return (0x100 - ret) & 0xFF

        def make_data_frame_bytes(self, cmd, data=None, status=0):
            if data is None:
                data = b""
            frame = bytearray(
                struct.pack(f"!BBHHHB{len(data)}sB", 0x11, 0x00, cmd, status, len(data), 0x00, data, 0x00)
            )
            frame[struct.calcsize("!B")] = self.lrc_calc(frame[: struct.calcsize("!B")])
            frame[struct.calcsize("!BBHHH")] = self.lrc_calc(frame[: struct.calcsize("!BBHHH")])
            frame[struct.calcsize(f"!BBHHHB{len(data)}s")] = self.lrc_calc(
                frame[: struct.calcsize(f"!BBHHHB{len(data)}s")]
            )
            return bytes(frame)

    return Fallback(), "verbatim copy (chameleon_com.py not importable)"


def build_harness():
    tmp = Path(tempfile.mkdtemp(prefix="proto_check_"))
    src = tmp / "harness.cpp"
    src.write_text(HARNESS, encoding="utf-8")
    exe = tmp / "harness.exe"
    res = subprocess.run(
        [
            str(GCC),
            "-std=gnu++17",
            "-I",
            str(PROTO_DIR / "include"),
            str(src),
            str(PROTO_DIR / "src" / "chameleon_protocol.cpp"),
            "-o",
            str(exe),
        ],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print("harness build failed:\n", res.stdout, res.stderr)
        sys.exit(1)
    return exe


def run(exe, *args):
    return subprocess.run([str(exe), *args], capture_output=True, text=True).stdout.strip()


def accepted_count(out):
    """FrameParser reports its total on the trailing 'count N errors M' line."""
    for line in out.splitlines():
        if line.startswith("count "):
            return int(line.split()[1])
    return -1


def main():
    com, ref_source = load_reference()
    header = struct.calcsize("!BBHHHB0s")
    print(f"reference: {ref_source}")
    print(f"header bytes (calcsize '!BBHHHB0s') = {header}")
    print(f"empty-payload frame length           = {len(com.make_data_frame_bytes(1000, b''))}\n")

    exe = build_harness()
    failures = []

    def check(name, ok, detail=""):
        print(f"  {'OK  ' if ok else 'FAIL'} {name}{('  ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    cases = [
        (1000, 0, b""),
        (1018, 0, b""),
        (1003, 0, b"\x02"),
        (1007, 0, b"\x01\x02hello"),
        (1004, 0, b"\x00\x03\xe8"),
        (4000, 0, bytes(range(64))),
        (4000, 0, bytes(range(256))),
        # ---- M3 card operation payloads ----
        # MF1_READ_ONE_BLOCK / MF1_AUTH_ONE_KEY_BLOCK: key_type + block + 6 byte key
        (2008, 0, b"\x60\x04\xff\xff\xff\xff\xff\xff"),
        (2007, 0, b"\x61\x08\xa0\xa1\xa2\xa3\xa4\xa5"),
        # MF1_WRITE_ONE_BLOCK: key_type + block + key[6] + data[16]
        (2009, 0, b"\x60\x04" + b"\xff" * 6 + bytes(range(16))),
        # HF14A_SET_ANTI_COLL_DATA: uidlen + uid + atqa[2] + sak + atslen + ats
        (4001, 0, b"\x04\xde\xad\xbe\xef\x04\x00\x08"),
        (4001, 0, b"\x07" + bytes(range(7)) + b"\x44\x00\x00\x00"),
        # EM410X_SET_EMU_ID: 5 bytes (EM410X) and 13 bytes (Electra)
        (5000, 0, b"\x01\x02\x03\x04\x05"),
        (5000, 0, bytes(range(13))),
        # MF1_READ_EMU_BLOCK_DATA: block_start + block_count
        (4008, 0, b"\x00\x10"),
        # MF1_WRITE_EMU_BLOCK_DATA: block_start + data
        (4000, 0, b"\x04" + bytes(range(48))),
        # MF1_DETECT_SUPPORT: no payload
        (2001, 0, b""),
    ]

    print("== host -> device: BuildFrame vs make_data_frame_bytes ==")
    for cmd, status, payload in cases:
        official = com.make_data_frame_bytes(cmd, payload, status)
        mine = bytes.fromhex(run(exe, "build", str(cmd), str(status), payload.hex()))
        check(f"cmd={cmd} len={len(payload)}", official == mine,
              "" if official == mine else f"\n         official={official.hex(' ')}\n         mine    ={mine.hex(' ')}")

    print("\n== device -> host: FrameParser decodes reference frames ==")
    for cmd, status, payload in cases:
        wire = com.make_data_frame_bytes(cmd, payload, status)
        out = run(exe, "parse", wire.hex())
        accepted = [l for l in out.splitlines() if l.startswith("ACCEPT")]
        expect = f"ACCEPT {cmd} {status} {len(payload)} {payload.hex().upper()}"
        check(f"cmd={cmd} len={len(payload)}", len(accepted) == 1 and accepted[0] == expect, accepted[0] if accepted else "no frame accepted")

    print("\n== corrupted frames must be rejected ==")
    base = bytearray(com.make_data_frame_bytes(1000, b""))

    def bad_lrc1(f):
        f[1] ^= 0xFF

    def bad_lrc2(f):
        f[8] ^= 0xFF

    def bad_lrc3(f):
        f[9] ^= 0xFF

    def truncated(f):
        f.pop()

    for name, mutate in (("bad LRC1", bad_lrc1), ("bad LRC2", bad_lrc2), ("bad LRC3", bad_lrc3), ("truncated", truncated)):
        bad = bytearray(base)
        mutate(bad)
        out = run(exe, "parse", bytes(bad).hex())
        check(name, accepted_count(out) == 0, out)

    print("\n== resynchronisation after leading garbage ==")
    stream = b"\x00\xff\x11\x22" + com.make_data_frame_bytes(1002, b"")
    out = run(exe, "parse", stream.hex())
    check("garbage + valid frame", accepted_count(out) == 1, out)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED: {failures}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
