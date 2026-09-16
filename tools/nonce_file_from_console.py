#!/usr/bin/env python3
"""Rebuild a hardnested nonce file from a captured Tab5 console log.

The Tab5 cannot crack a hardnested nonce file itself: upstream's candidate
generation keeps 474 MiB of bitflip tables plus 1 GiB of per-first-byte state
bitarrays resident (measured; see docs/M5-KEY-RECOVERY.md section 6), which is
47x this board's PSRAM. What the Tab5 *can* do is what ChameleonUltra's client
does - drive MF1_HARDNESTED_ACQUIRE, track the first-byte parity sum, and write
the nine-bytes-per-pair nonce file. It prints that file to its console as

    [HN] BEGIN SZ=<hex> REC=<hex>
    [HN] <offset:04X> <32 hex digits>
    ...
    [HN] END SZ=<hex> CRC=<hex>

so the file can be handed to upstream's hardnested tool on a PC:

    python capture_console.py --seconds 60 > capture.txt
    python nonce_file_from_console.py capture.txt -o nonces.bin
    HardnestedRecovery/hardnested_main nonces.bin

The SZ and CRC fields are checked, so a capture that dropped lines (the device's
on-screen log is a 200 entry ring) or picked up unrelated output fails loudly
instead of producing a file that silently cracks to nothing.

Usage:
    python nonce_file_from_console.py CAPTURE.txt [-o nonces.bin]
    ... | python nonce_file_from_console.py - -o nonces.bin
"""

import argparse
import binascii
import re
import sys

BEGIN_RE = re.compile(r"\[HN\] BEGIN SZ=([0-9A-Fa-f]+) REC=([0-9A-Fa-f]+)")
END_RE = re.compile(r"\[HN\] END SZ=([0-9A-Fa-f]+) CRC=([0-9A-Fa-f]{8})")
DATA_RE = re.compile(r"\[HN\] ([0-9A-Fa-f]{4}) ((?:[0-9A-Fa-f]{2})+)\s*$")

BYTES_PER_LINE = 16
HEADER_SIZE = 6
RECORD_SIZE = 9


def parse(text):
    """Return (blob, problems). blob is None when the capture is unusable."""
    problems = []
    begin = None
    end = None
    chunks = {}

    for lineno, line in enumerate(text.splitlines(), 1):
        m = BEGIN_RE.search(line)
        if m:
            if begin is not None:
                problems.append("line %d: second BEGIN without an END" % lineno)
            begin = (int(m.group(1), 16), int(m.group(2), 16), lineno)
            chunks = {}
            continue
        m = END_RE.search(line)
        if m:
            end = (int(m.group(1), 16), int(m.group(2), 16), lineno)
            continue
        m = DATA_RE.search(line)
        if m:
            offset = int(m.group(1), 16)
            payload = m.group(2)
            if offset in chunks:
                problems.append("line %d: duplicate offset %04X" % (lineno, offset))
            chunks[offset] = bytes.fromhex(payload)
            continue

    if begin is None:
        problems.append("no '[HN] BEGIN' marker found - is this the right capture?")
        return None, problems
    if end is None:
        problems.append("no '[HN] END' marker found - the capture is incomplete")
        return None, problems

    size, records, _ = begin
    if len(chunks) * BYTES_PER_LINE < size:
        problems.append("only %d data lines for %d bytes (expected %d)"
                        % (len(chunks), size, (size + BYTES_PER_LINE - 1) // BYTES_PER_LINE))

    # Offsets arrive in order on the wire, but reassemble by offset so an
    # interleaved or reordered capture still works.
    blob = bytearray()
    for offset in sorted(chunks):
        if offset != len(blob):
            problems.append("gap at offset %04X (have %d bytes)" % (offset, len(blob)))
            return None, problems
        blob.extend(chunks[offset])

    if len(blob) < size:
        problems.append("reassembled %d bytes, header says %d" % (len(blob), size))
        return None, problems
    if len(blob) > size:
        blob = blob[:size]

    end_size, end_crc, end_line = end
    if end_size != size:
        problems.append("END SZ %d does not match BEGIN SZ %d" % (end_size, size))
        return None, problems

    have = binascii.crc32(bytes(blob)) & 0xFFFFFFFF
    if have != end_crc:
        problems.append("CRC32 mismatch: computed %08X, END says %08X" % (have, end_crc))
        return None, problems

    if (size - HEADER_SIZE) % RECORD_SIZE != 0:
        problems.append("payload %d is not a whole number of %d byte records"
                        % (size - HEADER_SIZE, RECORD_SIZE))
    if records != (size - HEADER_SIZE) // RECORD_SIZE:
        problems.append("REC %d does not match SZ %d" % (records, size))

    return bytes(blob), problems


def describe(blob):
    uid = int.from_bytes(blob[0:4], "big")
    sector = blob[4]
    key_type = "B" if blob[5] else "A"
    pairs = (len(blob) - HEADER_SIZE) // RECORD_SIZE
    return ("UID %08X, sector %d, target key %s, %d nonce pairs (%d nonces)"
            % (uid, sector, key_type, pairs, pairs * 2))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="console capture file, or - for stdin")
    ap.add_argument("-o", "--output", default="nonces.bin", help="nonce file to write")
    args = ap.parse_args()

    if args.capture == "-":
        text = sys.stdin.read()
    else:
        with open(args.capture, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()

    blob, problems = parse(text)
    if blob is None:
        for p in problems:
            print("error: %s" % p, file=sys.stderr)
        return 1

    with open(args.output, "wb") as fh:
        fh.write(blob)

    print("wrote %s: %s" % (args.output, describe(blob)))
    for p in problems:
        print("warning: %s" % p, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
