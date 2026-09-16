"""Capture the Tab5 console into a file without touching DTR/RTS.

DTR/RTS on the Tab5 USB-Serial-JTAG port are wired to GPIO9/EN, so toggling
them forces download mode. This script never sets them; it just keeps the port
open and drains whatever the board prints, re-opening across re-enumeration so
a manual reset does not lose the boot banner.

The output file is written by this script itself (not by shell redirection) so
that a background invocation reliably produces a file.

Usage:
    python capture_console.py [PORT] [SECONDS] [OUTFILE]
"""

import sys
import time
from pathlib import Path

import serial
import serial.tools.list_ports as list_ports

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
OUTFILE = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("console_capture.log")

chunks = []
deadline = time.time() + SECONDS
handle = None
last_error = None


def flush():
    OUTFILE.write_text("".join(chunks), encoding="utf-8", errors="replace")


flush()
while time.time() < deadline:
    if handle is None:
        if PORT not in [p.device for p in list_ports.comports()]:
            time.sleep(0.2)
            continue
        try:
            handle = serial.Serial(PORT, 115200, timeout=0.2)
        except Exception as exc:  # port busy / re-enumerating
            last_error = exc
            time.sleep(0.2)
            continue
    try:
        data = handle.read(4096)
        if data:
            chunks.append(data.decode("utf-8", "replace"))
            flush()
    except Exception as exc:
        last_error = exc
        try:
            handle.close()
        except Exception:
            pass
        handle = None
        time.sleep(0.2)

if handle is not None:
    handle.close()

flush()
print("captured %d chunks, %d bytes -> %s" % (len(chunks), OUTFILE.stat().st_size, OUTFILE))
if not chunks and last_error is not None:
    print("last error:", last_error)
