"""Decode the Tab5 console capture: keep the boot section and resolve addresses.

Two modes:
  python decode_boot.py <capture.log>
      print everything up to the first watchdog/panic, with every 0x48...
      address annotated with addr2line output.

  python decode_boot.py --addr <capture.log> 0x4805cf94 [more addresses...]
      resolve specific addresses only.
"""

import re
import subprocess
import sys
from pathlib import Path

ELF = Path(r"D:\vscode\ChameleonUltra\firmware\build\chameleon_tab5.elf")
ADDR2LINE = Path(
    r"C:\Users\Jiang\.espressif\tools\riscv32-esp-elf\esp-14.2.0_20241119"
    r"\riscv32-esp-elf\bin\riscv32-esp-elf-addr2line.exe"
)

ADDR_RE = re.compile(r"0x(4[0-9a-fA-F]{7})")


def resolve(addrs):
    addrs = list(dict.fromkeys(addrs))
    if not addrs or not ELF.exists() or not ADDR2LINE.exists():
        return {}
    try:
        out = subprocess.run(
            [str(ADDR2LINE), "-pfiaC", "-e", str(ELF), *addrs],
            capture_output=True,
            text=True,
            timeout=120,
        ).stdout
    except Exception as exc:
        return {"__error__": str(exc)}
    lines = [ln for ln in out.splitlines() if ln.strip()]
    # addr2line prints 2-3 lines per address (function, file:line, maybe inlined)
    result = {}
    idx = 0
    for addr in addrs:
        chunk = []
        while idx < len(lines) and len(chunk) < 2:
            chunk.append(lines[idx])
            idx += 1
        result[addr] = " | ".join(chunk)
    return result


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = sys.argv[1:]
    only = False
    if args and args[0] == "--addr":
        only = True
        args = args[1:]
    if not args:
        print(__doc__)
        return 1

    path = Path(args[0])
    text = path.read_text(encoding="utf-8", errors="replace")
    text = text.replace("\r", "")

    if only:
        addrs = args[1:]
        for addr, sym in resolve(addrs).items():
            print(f"{addr}  {sym}")
        return 0

    # Keep everything before the first watchdog / panic block.
    stop = len(text)
    for marker in ("task_wdt: Task watchdog", "Guru Meditation", "abort() was called"):
        pos = text.find(marker)
        if pos != -1:
            stop = min(stop, pos)
    boot = text[:stop]

    for addr, sym in resolve(ADDR_RE.findall(boot)).items():
        boot = boot.replace(addr, f"{addr} <{sym}>")

    print(boot)
    print("=" * 70)
    print("--- tail of full capture (first 40 lines after the cut) ---")
    print("\n".join(text[stop:].splitlines()[:40]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
