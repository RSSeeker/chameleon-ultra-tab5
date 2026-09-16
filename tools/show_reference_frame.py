"""Print the authoritative frame layout straight from chameleon_com.py."""

import importlib.util
import os
import sys
from pathlib import Path

# Where the reference ChameleonUltra checkout lives. The probes compare the port
# against upstream sources, so point this at your own checkout of
# https://github.com/chameleonultra/ChameleonUltra if it is somewhere else:
#     $env:CU_UPSTREAM = "D:\src\ChameleonUltra"
CU_UPSTREAM = Path(os.environ.get("CU_UPSTREAM", r"C:\Users\Jiang\Downloads\ChameleonUltra-main"))


SCRIPT_DIR = CU_UPSTREAM / "software" / "script"
sys.path.insert(0, str(SCRIPT_DIR))

spec = importlib.util.spec_from_file_location("chameleon_com", SCRIPT_DIR / "chameleon_com.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["chameleon_com"] = mod
spec.loader.exec_module(mod)
com = mod.ChameleonCom()

LABELS = {
    0: "SOF",
    1: "LRC1 (over SOF)",
    2: "CMD hi",
    3: "CMD lo",
    4: "STATUS hi",
    5: "STATUS lo",
    6: "LEN hi",
    7: "LEN lo",
    8: "LRC2 (over head+pad)",
    9: "LRC3 (over head+data)",
}

for cmd, data in ((1000, b""), (1003, b"\x02"), (1007, b"\x01\x02hi")):
    frame = com.make_data_frame_bytes(cmd, data)
    print(f"cmd={cmd} payload={data.hex() or '(none)'} -> {len(frame)} bytes")
    print("   ", frame.hex(" ").upper())

print()
frame = com.make_data_frame_bytes(1000, b"")
print("GET_APP_VERSION (cmd=1000) field by field:")
for i, b in enumerate(frame):
    print(f"   [{i}] {b:02X}  {LABELS.get(i, 'payload')}")
print()
print("length of an empty-payload frame:", len(frame))
print("lrc_calc(SOF)          =", "%02X" % com.lrc_calc(frame[:1]))
print("lrc_calc(head, idx<8)  =", "%02X" % com.lrc_calc(frame[:8]))
print("lrc_calc(head+pad, <9) =", "%02X" % com.lrc_calc(frame[:9]))
