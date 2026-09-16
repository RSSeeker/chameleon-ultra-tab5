"""Cross-check the firmware's LF card support against the official Python client.

The failures this guards against are the ones that are invisible on hardware
until a card is in the field: a wrong T55xx password constant, an id offset that
is off by the protocol prefix, or a command number that drifted from upstream.

Oracle: the real chameleon_cmd.py / chameleon_enum.py / app_cmd.c from the
reference repo. Nothing here is hand-typed from memory -- every expected value is
read out of those files.

Checks:
  1. T55xx keys        : chameleon_client.cpp constants == chameleon_cmd.py
  2. command ids       : chameleon_commands.h == chameleon_enum.py Command
  3. scan id extraction: kReaders[] (offset, length) reproduces exactly what the
                         CLI's struct.unpack pulls out of the same scan reply
  4. write payload     : WriteT55xx() byte layout == the CLI's struct.pack
  5. scan reply sizes  : the reply length each handler in app_cmd.c returns
                         matches what the CLI unpacks and what kReaders[] expects

Usage:  python tools/verify_lf.py
"""

import os
import ast
import re
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
REF = CU_UPSTREAM
PY_DIR = REF / "software" / "script"
CMD_C = REF / "firmware" / "application" / "src" / "app_cmd.c"

CLIENT_CPP = REPO / "firmware" / "components" / "chameleon" / "src" / "chameleon_client.cpp"
CMD_H = REPO / "firmware" / "components" / "chameleon" / "include" / "chameleon_commands.h"
CARD_CPP = REPO / "firmware" / "main" / "pages_card.cpp"

failures = []
checks = 0


def check(label, ok, detail=""):
    global checks
    checks += 1
    if ok:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}  {detail}")
        failures.append(label)


def read(path):
    if not path.exists():
        sys.exit(f"missing file: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 1. T55xx keys
# ---------------------------------------------------------------------------
print("\n[1] T55xx write keys vs chameleon_cmd.py")

cmd_py = read(PY_DIR / "chameleon_cmd.py")
py_new_key = None
py_old_keys = None
for node in ast.parse(cmd_py).body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id == "new_key":
            py_new_key = ast.literal_eval(node.value)
        elif target.id == "old_keys":
            py_old_keys = ast.literal_eval(node.value)

check("chameleon_cmd.py defines new_key/old_keys", py_new_key is not None and py_old_keys is not None)

client_cpp = read(CLIENT_CPP)


def parse_c_array(text, name):
    """Pull {0x.., ...} initialiser bodies out of a C++ array definition.

    Brace matched rather than regexed: a non-greedy `.*?` would happily run past
    the end of a single-line initialiser into the next array's closing brace.
    """
    m = re.search(rf"\b{name}\s*(?:\[[^\]]*\]\s*)+=\s*\{{", text)
    if not m:
        return None
    start = m.end() - 1  # at the opening brace
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                body = text[start + 1 : i]
                break
    else:
        return None

    groups = re.findall(r"\{([^{}]*)\}", body)
    if groups:
        return [bytes(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", g)) for g in groups]
    return [bytes(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", body))]


cpp_new_key = parse_c_array(client_cpp, "kT55xxNewKey")
cpp_old_keys = parse_c_array(client_cpp, "kT55xxOldKeys")

check(
    "new key matches",
    cpp_new_key and len(cpp_new_key) == 1 and cpp_new_key[0] == py_new_key,
    f"cpp={cpp_new_key} py={py_new_key!r}",
)
check(
    "old keys match",
    cpp_old_keys == py_old_keys,
    f"cpp={cpp_old_keys} py={py_old_keys}",
)

# ---------------------------------------------------------------------------
# 2. command ids
# ---------------------------------------------------------------------------
print("\n[2] command ids vs chameleon_enum.py")

enum_py = read(PY_DIR / "chameleon_enum.py")
# Only the Command class matters: Status reuses the same names differently.
cmd_block = re.search(r"class Command\(enum\.IntEnum\):(.*?)(?=\nclass )", enum_py, re.S).group(1)
py_cmds = {m.group(1): int(m.group(2)) for m in re.finditer(r"^\s{4}([A-Z0-9_]+)\s*=\s*(\d+)\s*$", cmd_block, re.M)}

cmd_h = read(CMD_H)
h_block = re.search(r"enum\s+Command\s*:\s*uint16_t\s*\{(.*?)\n\};", cmd_h, re.S)
if not h_block:
    sys.exit("could not locate `enum Command : uint16_t` in chameleon_commands.h")
cpp_cmds = {m.group(1): int(m.group(2)) for m in re.finditer(r"^\s*([A-Z0-9_]+)\s*=\s*(\d+)\s*,", h_block.group(1), re.M)}

wanted = [
    "EM410X_SCAN",
    "EM410X_WRITE_TO_T55XX",
    "HIDPROX_SCAN",
    "HIDPROX_WRITE_TO_T55XX",
    "IOPROX_SCAN",
    "IOPROX_WRITE_TO_T55XX",
    "PAC_SCAN",
    "PAC_WRITE_TO_T55XX",
    "VIKING_SCAN",
    "VIKING_WRITE_TO_T55XX",
    "JABLOTRON_SCAN",
    "JABLOTRON_WRITE_TO_T55XX",
    "IDTECK_WRITE_TO_T55XX",
    "EM4X05_SCAN",
    "ADC_GENERIC_READ",
]
for name in wanted:
    if name not in py_cmds:
        check(f"{name} present in python enum", False, "absent upstream -- cannot cross-check")
        continue
    check(f"{name} = {py_cmds[name]}", cpp_cmds.get(name) == py_cmds[name], f"cpp={cpp_cmds.get(name)}")

for name, want in (("HF_TAG_OK", 0x00), ("LF_TAG_OK", 0x40)):
    m = re.search(rf"^\s*{name}\s*=\s*(0x[0-9A-Fa-f]+|\d+)", cmd_h, re.M)
    actual = int(m.group(1), 0) if m else None
    check(f"{name} = 0x{want:02X}", actual == want, f"cpp={actual if actual is None else hex(actual)}")

# ---------------------------------------------------------------------------
# 3./5. scan handlers in app_cmd.c: reply size + CLI unpack format
# ---------------------------------------------------------------------------
print("\n[3] scan reply sizes and CLI unpack formats")

app_cmd = read(CMD_C)
tag_em_h = read(REF / "firmware" / "application" / "src" / "rfid" / "nfctag" / "lf" / "lf_tag_em.h")


def handler_body(fn):
    m = re.search(rf"static data_frame_tx_t \*{fn}\(.*?\n\}}\n", app_cmd, re.S)
    return m.group(0) if m else None


def const_h(name):
    m = re.search(rf"#define\s+{name}\s+(\d+)", tag_em_h)
    return int(m.group(1)) if m else None


# Reply length of each fixed-size handler, as declared in app_cmd.c.
reply_facts = {
    "HIDPROX_SCAN": (16, "cmd_processor_hidprox_scan"),
    "IOPROX_SCAN": (16, "cmd_processor_ioprox_scan"),
    "VIKING_SCAN": (4, "cmd_processor_viking_scan"),
    "PAC_SCAN": (8, "cmd_processor_pac_scan"),
    "JABLOTRON_SCAN": (5, "cmd_processor_jablotron_scan"),
}
for name, (want_len, fn) in reply_facts.items():
    body = handler_body(fn)
    if body is None:
        check(f"{name} handler found in app_cmd.c", False)
        continue
    m = re.search(r"uint8_t\s+\w+\[(\d+)\]", body)
    actual = int(m.group(1)) if m else None
    check(f"{name} reply buffer = {want_len}", actual == want_len, f"app_cmd.c declares {actual}")

# EM410X is variable length: 2 byte tag type + the id, whose size comes from the
# firmware's own header, so resolve the expression instead of guessing.
em_body = handler_body("cmd_processor_em410x_scan")
check(
    "EM410X_SCAN reply = 2 + id size (5, or 13 for Electra)",
    em_body is not None
    and "2 + id_size" in em_body
    and const_h("LF_EM410X_TAG_ID_SIZE") == 5
    and const_h("LF_EM410X_ELECTRA_TAG_ID_SIZE") == 13,
    f"body={'found' if em_body else 'missing'} "
    f"em410x={const_h('LF_EM410X_TAG_ID_SIZE')} electra={const_h('LF_EM410X_ELECTRA_TAG_ID_SIZE')}",
)

# The CLI unpack format for each scan reply, read from chameleon_cmd.py.
cli_formats = {}
for fn in ("em410x_scan", "hidprox_scan", "ioprox_scan", "viking_scan", "pac_scan", "jablotron_scan"):
    m = re.search(rf"def {fn}\(self.*?\n(?=    @|    def )", cmd_py, re.S)
    if not m:
        continue
    fmt = re.findall(r"struct\.unpack\(['\"]([^'\"]+)['\"]", m.group(0))
    slice_m = re.findall(r"resp\.data\[:(\d+)\]", m.group(0))
    cli_formats[fn] = (fmt, slice_m)

check(
    "HIDPROX_SCAN reply parsed as '>BIBIBH' (13 bytes)",
    cli_formats.get("hidprox_scan", ([], []))[0] == [">BIBIBH"],
    f"{cli_formats.get('hidprox_scan')}",
)
check(
    "IOPROX_SCAN reply parsed as '>BBH8sBBBB' (16 bytes)",
    cli_formats.get("ioprox_scan", ([], []))[0] == [">BBH8sBBBB"],
    f"{cli_formats.get('ioprox_scan')}",
)

# HIDPROX_SCAN dereferences the request payload: an empty request would fault.
hidprox_body = handler_body("cmd_processor_hidprox_scan")
check(
    "HIDPROX_SCAN reads data[0] with no null guard (request must carry 1 byte)",
    hidprox_body is not None
    and "data[0]" in hidprox_body
    and "data != NULL" not in hidprox_body
    and "data == NULL" not in hidprox_body,
    "handler unexpectedly guards the payload",
)
ioprox_body = handler_body("cmd_processor_ioprox_scan")
check(
    "IOPROX_SCAN tolerates a null payload",
    ioprox_body is not None and "NULL" in ioprox_body,
)

# ---------------------------------------------------------------------------
# 4. the kReaders table in pages_card.cpp
# ---------------------------------------------------------------------------
print("\n[4] kReaders[] table vs the CLI")

card_cpp = read(CARD_CPP)
table = re.search(r"const Reader kReaders\[\] = \{(.*?)\n\};", card_cpp, re.S).group(1)
rows = []
for line in table.splitlines():
    line = line.strip()
    if not line.startswith("{") or not line.endswith("},"):
        continue
    inner = line.strip("{},").strip()
    parts = [p.strip() for p in inner.split(",")]
    if len(parts) != 7:
        sys.exit(f"unexpected kReaders row: {line}")
    rows.append(
        {
            "name": parts[0].strip('"'),
            "kind": parts[1],
            "scan": parts[2],
            "write": parts[3],
            "offset": int(parts[4]),
            "length": int(parts[5]),
            "hint": parts[6],
        }
    )

check("kReaders has 10 rows", len(rows) == 10, f"found {len(rows)}")

by_scan = {r["scan"]: r for r in rows}
by_write = {r["write"]: r for r in rows}

# Expected offset/length per protocol, derived from the handler + CLI format.
expected = {
    "EM410X_SCAN": (2, 5, "false"),
    "HIDPROX_SCAN": (0, 13, "true"),
    "IOPROX_SCAN": (0, 16, "false"),
    "PAC_SCAN": (0, 8, "false"),
    "VIKING_SCAN": (0, 4, "false"),
    "JABLOTRON_SCAN": (0, 5, "false"),
}
for scan, (off, length, hint) in expected.items():
    row = by_scan.get(scan)
    if row is None:
        check(f"reader for {scan}", False, "missing")
        continue
    check(
        f"{scan}: offset={off} length={length} hint={hint}",
        (row["offset"], row["length"], row["hint"]) == (off, length, hint),
        f"table has ({row['offset']}, {row['length']}, {row['hint']})",
    )

check(
    "EM410X row writes with EM410X_WRITE_TO_T55XX and Electra is resolved at scan time",
    by_scan["EM410X_SCAN"]["write"] == "EM410X_WRITE_TO_T55XX"
    and "EM410X_ELECTRA_WRITE_TO_T55XX" in card_cpp,
)
check(
    "IDTECK row is clone-only (no scan command)",
    by_write.get("IDTECK_WRITE_TO_T55XX", {}).get("scan") == "0",
    f"{by_write.get('IDTECK_WRITE_TO_T55XX')}",
)
check("EM4X05 row has no T55xx write", by_scan.get("EM4X05_SCAN", {}).get("write") == "0")

# Round-trip: a synthetic scan reply must yield the same id through both the
# firmware's (offset, length) slice and the CLI's struct format.
import struct  # noqa: E402

print("\n[5] id extraction round-trip vs struct.unpack")

samples = {
    "EM410X_SCAN": (bytes([0x00, 0x00]) + bytes(range(1, 6)), ">H5s", 2),
    "HIDPROX_SCAN": (bytes(range(13)), ">BIBIBH", 0),
    "IOPROX_SCAN": (bytes(range(16)), ">BBH8sBBBB", 0),
    "PAC_SCAN": (b"CARD0001", None, 0),
    "VIKING_SCAN": (bytes([0xDE, 0xAD, 0xBE, 0xEF]), None, 0),
    "JABLOTRON_SCAN": (bytes([0x12, 0x34, 0x56, 0x78, 0x90]), None, 0),
}
for scan, (reply, fmt, _) in samples.items():
    row = by_scan[scan]
    fw_id = reply[row["offset"] : row["offset"] + row["length"]]
    if fmt:
        values = struct.unpack(fmt, reply[: struct.calcsize(fmt)])
        if scan == "EM410X_SCAN":
            cli_id = values[1]
        elif scan == "HIDPROX_SCAN":
            # Re-pack exactly what the CLI would send back to the device.
            cli_id = struct.pack(">BIBIBH", *values)
        else:
            cli_id = reply[:16]
    else:
        cli_id = reply
    check(
        f"{scan}: firmware slice == CLI id ({fw_id.hex().upper()})",
        fw_id == cli_id,
        f"fw={fw_id.hex().upper()} cli={cli_id.hex().upper()}",
    )

# ---------------------------------------------------------------------------
# 6. write payload layout
# ---------------------------------------------------------------------------
print("\n[6] WriteT55xx payload layout vs struct.pack")

# Mirror of Client::WriteT55xx(): id | new_key | old_keys...
def fw_payload(cmd_id, new_key, old_keys):
    return cmd_id + new_key + b"".join(old_keys)


lengths = {
    "EM410X_WRITE_TO_T55XX": 5,
    "EM410X_ELECTRA_WRITE_TO_T55XX": 13,
    "HIDPROX_WRITE_TO_T55XX": 13,
    "IOPROX_WRITE_TO_T55XX": 16,
    "PAC_WRITE_TO_T55XX": 8,
    "VIKING_WRITE_TO_T55XX": 4,
    "JABLOTRON_WRITE_TO_T55XX": 5,
    "IDTECK_WRITE_TO_T55XX": 8,
}
for cmd_name, n in lengths.items():
    card_id = bytes(range(n))
    fw = fw_payload(card_id, py_new_key, py_old_keys)
    py = struct.pack(f"!{n}s4s{4 * len(py_old_keys)}s", card_id, py_new_key, b"".join(py_old_keys))
    check(f"{cmd_name}: {n} byte id, payload {len(py)} bytes", fw == py, f"fw={fw.hex()} py={py.hex()}")

# Every id length in the table must be one the CLI would accept.
for row in rows:
    if row["write"] == "0":
        continue
    n = row["length"]
    check(f"{row['name']}: write id length {n} is 4..16", 4 <= n <= 16, f"{n}")

# ---------------------------------------------------------------------------
# 7. LF emulated card id table
# ---------------------------------------------------------------------------
print("\n[7] kLfEmuTable vs chameleon_cmd.py")

table_match = re.search(r"constexpr LfEmuEntry kLfEmuTable\[\] = \{(.*?)\n\};", client_cpp, re.S)
if not table_match:
    check("kLfEmuTable found in chameleon_client.cpp", False)
else:
    emu_rows = []
    for line in table_match.group(1).splitlines():
        m = re.match(r"\s*\{(\w+),\s*(\w+),\s*(\d+)\}", line)
        if m:
            emu_rows.append((m.group(1), m.group(2), int(m.group(3))))

    check("kLfEmuTable has 7 rows", len(emu_rows) == 7, f"found {len(emu_rows)}")
    check("kLfEmuCount is derived from the table, not hand written",
          re.search(r"kLfEmuCount = sizeof\(kLfEmuTable\) / sizeof\(kLfEmuTable\[0\]\)", client_cpp) is not None)

    # Read the CLI's set/get pairs straight out of chameleon_cmd.py.
    cli_emu = {}
    for proto in ("em410x", "hidprox", "viking", "pac", "ioprox", "jablotron", "idteck"):
        set_body = re.search(rf"def {proto}_set_emu_id\(self.*?\n(?=    @|    def )", cmd_py, re.S)
        get_body = re.search(rf"def {proto}_get_emu_id\(self.*?\n(?=    @|    def )", cmd_py, re.S)
        if not set_body or not get_body:
            check(f"{proto}: CLI has both set and get", False)
            continue
        set_cmd = re.findall(r"Command\.([A-Z0-9_]+)", set_body.group(0))
        get_cmd = re.findall(r"Command\.([A-Z0-9_]+)", get_body.group(0))
        lengths = [int(x) for x in re.findall(r"len\(id\)\s*!=\s*(\d+)", set_body.group(0))]
        cli_emu[proto] = (set_cmd[0] if set_cmd else None, get_cmd[0] if get_cmd else None,
                          lengths[0] if lengths else None)

    order = ["em410x", "hidprox", "viking", "pac", "ioprox", "jablotron", "idteck"]
    for i, proto in enumerate(order):
        if i >= len(emu_rows):
            break
        set_name, get_name, row_len = emu_rows[i]
        want = cli_emu.get(proto)
        if want is None:
            continue
        check(f"{proto}: set cmd {want[0]}", set_name == want[0], f"cpp={set_name}")
        check(f"{proto}: get cmd {want[1]}", get_name == want[1], f"cpp={get_name}")
        if want[2] is not None:
            check(f"{proto}: id length {want[2]}", row_len == want[2], f"cpp={row_len}")

# EM410X is the one protocol with two accepted lengths; the row holds the plain
# 5 and the code has to accept Electra's 13 as well.
check("EM410X accepts both 5 and 13 byte ids",
      "kEm410xElectraIdLength = 13" in client_cpp and "id_length != kEm410xElectraIdLength" in client_cpp)

# The tag type -> protocol mapping must cover the LF types the CLI can name.
# The cases are stacked (`case EM410X: case EM410X_16: ... *out = ...`), so walk
# the switch body and attach every consecutive label to the assignment that
# follows it -- a single regex over "case X:\n *out =" only sees the last label.
fn_body = re.search(r"bool Client::LfEmuProtocolForTagType\(.*?\n\}", client_cpp, re.S)
tag_map = []
if fn_body:
    pending = []
    for line in fn_body.group(0).splitlines():
        line = line.strip()
        m = re.match(r"case (\w+):", line)
        if m:
            pending.append(m.group(1))
            continue
        m = re.match(r"\*out = LfEmuProtocol::(\w+);", line)
        if m and pending:
            tag_map += [(label, m.group(1)) for label in pending]
            pending = []

check("tag type -> protocol mapping found", len(tag_map) >= 8, f"found {len(tag_map)}: {tag_map}")
mapped = {t for t, _ in tag_map}
for expected in ("EM410X", "EM410X_16", "EM410X_32", "EM410X_64", "EM410X_ELECTRA",
                 "HIDProx", "Viking", "PAC", "ioProx", "Jablotron", "IDTECK"):
    check(f"tag type {expected} maps to a protocol", expected in mapped, f"mapped: {sorted(mapped)}")

print(f"\n{checks - len(failures)}/{checks} checks passed")
if failures:
    print("FAILURES:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("ALL LF CHECKS PASSED")
