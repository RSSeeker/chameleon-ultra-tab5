#!/usr/bin/env python3
"""Compare the ported client's request payloads with upstream's, byte for byte.

The port's rule is that every command's payload layout comes from upstream's
chameleon_cmd.py / app_cmd.c and never from memory. That is a claim about bytes
on the wire, so this checks bytes on the wire:

  * the *ported* client (firmware/components/chameleon/src/*.cpp) is compiled on
    the host with a fake transport (tools/host_stubs/client_harness.cpp) that
    records the frame each client method sends;
  * upstream's chameleon_cmd.py is imported unmodified and driven with a fake
    device that records the payload each of its methods builds;
  * for every case both sides are called with the same arguments and the
    (command id, payload) pairs must be identical.

Nothing here is hand written expected data: the expected bytes are produced by
running upstream's own code.

Commands upstream's Python client does not implement at all (LF_T55XX_WRITE is
the one in this list) cannot be checked this way; they are checked against the
device-side handler in app_cmd.c instead - see check_app_cmd_structs().

Usage:  python tools/verify_payloads.py [case-name-filter]
"""

import os
import enum
import importlib
import re
import struct
import subprocess
import sys
from pathlib import Path

# Where the reference ChameleonUltra checkout lives. The probes compare the port
# against upstream sources, so point this at your own checkout of
# https://github.com/chameleonultra/ChameleonUltra if it is somewhere else:
#     $env:CU_UPSTREAM = "D:\src\ChameleonUltra"
CU_UPSTREAM = Path(os.environ.get("CU_UPSTREAM", r"C:\Users\Jiang\Downloads\ChameleonUltra-main"))


REPO = Path(__file__).resolve().parent.parent
CHAMELEON = REPO / "firmware" / "components" / "chameleon"
HOST_STUBS = REPO / "tools" / "host_stubs"
PROBE_DIR = REPO / ".probe" / "payloads"

UPSTREAM_SRC = CU_UPSTREAM / "software" / "src"
UPSTREAM_SCRIPT = CU_UPSTREAM / "software" / "script"
GXX = Path(r"C:\mingw64\bin\g++.exe")

failures = []


def gcc(args, **kwargs):
    """Compiler output must be decoded defensively: the locale codec here is GBK
    and one bad byte otherwise turns the real diagnostic into a TypeError."""
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kwargs)


def build_harness():
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    exe = PROBE_DIR / "client_harness.exe"
    res = gcc([str(GXX), "-std=gnu++17", "-O1", "-w",
               "-I", str(CHAMELEON / "include"), "-I", str(HOST_STUBS),
               str(HOST_STUBS / "client_harness.cpp"),
               "-x", "c++",
               str(CHAMELEON / "src" / "chameleon_client.cpp"),
               str(CHAMELEON / "src" / "chameleon_protocol.cpp"),
               str(CHAMELEON / "src" / "chameleon_commands.cpp"),
               "-o", str(exe)])
    if res.returncode != 0:
        print("harness build failed:\nHEAD:\n%s\n%s\nTAIL:\n%s"
              % ((res.stdout or "")[:1500], (res.stderr or "")[:1500], (res.stderr or "")[-800:]))
        sys.exit(1)
    return exe


def run_port(exe, case_filter=None):
    """Run the ported client's harness and return {case: (cmd, payload_bytes)}."""
    res = subprocess.run([str(exe)] + ([case_filter] if case_filter else []),
                         capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    out = {}
    for line in res.stdout.splitlines():
        m = re.match(r"CASE (\S+) (?:CMD (\d+) LEN (\d+) PAYLOAD ([0-9A-F]*)|(NOFRAME))$", line)
        if not m:
            continue
        name = m.group(1)
        if m.group(5):
            out[name] = None
        else:
            out[name] = (int(m.group(2)), bytes.fromhex(m.group(4)))
    return out, res


# ---------------------------------------------------------------------------
# Upstream side
# ---------------------------------------------------------------------------

def load_upstream():
    sys.path.insert(0, str(UPSTREAM_SCRIPT))
    for mod in ("chameleon_enum", "chameleon_utils", "chameleon_com", "chameleon_cmd"):
        if mod in sys.modules:
            del sys.modules[mod]
    E = importlib.import_module("chameleon_enum")
    COM = importlib.import_module("chameleon_com")
    CMD = importlib.import_module("chameleon_cmd")
    return E, COM, CMD


class FakeDevice:
    """Stands in for chameleon_com.ChameleonCom: records every request and
    answers the few probing commands upstream's client needs before it can build
    a payload (em410x_set_emu_id reads the active LF tag type first)."""

    def __init__(self, response_cls, default_status, replies=None):
        self.calls = []
        self.replies = replies or {}
        self._Response = response_cls
        self._status = default_status

    def _answer(self, cmd, data):
        # Some methods pass None for "no payload" (adc_generic_read does).
        self.calls.append((int(cmd), b"" if data is None else bytes(data)))
        return self._Response(cmd=cmd, status=self._status, data=self.replies.get(int(cmd), b""), parsed=None)

    def send_cmd_sync(self, cmd, data=b"", timeout=None, **kwargs):
        return self._answer(cmd, data)

    def send_cmd_auto(self, cmd, data=b"", close=False, **kwargs):
        """Fire and forget path, used by enter_bootloader()."""
        self.calls.append((int(cmd), b"" if data is None else bytes(data)))


def slot(n):
    """The ported client takes the firmware's slot value (0 based); upstream's
    API takes a SlotNumber (1 based) and converts with SlotNumber.to_fw()."""
    return n + 1


def key(hexstr):
    return bytes.fromhex(hexstr)


KEY_A = key("A0A1A2A3A4A5")
BLOCK16 = bytes(range(0x00, 0x100, 0x11))  # 00 11 22 ... FF
RATS = key("05788000")
HIDPROX_ID13 = key("2001002CC10A00000000000000")
IOPROX_ID16 = key("021F2EA6000000000000000000000000")
IDTECK_ID8 = key("0A0B0C0D0E0F1011")
PAC_ID8 = b"12345678"
LF_ID5 = key("123456789A")
LF_ID4 = key("12345678")

HF14A_RAW_OPTIONS = {
    "activate_rf_field": True,
    "wait_response": True,
    "append_crc": True,
    "auto_select": False,
    "keep_rf_field": False,
    "check_response_crc": False,
}

# Commands the port implements from app_cmd.c because upstream's Python client
# has no method for them at all. They are covered by section [2] instead.
NO_UPSTREAM_COUNTERPART = {"t55xx_write_block"}


def cases(E, CMD):
    """name -> callable that drives upstream's client once."""
    n = CMD.new_key
    old = CMD.old_keys
    return {
        # ---- W4: system / settings ----
        "set_active_slot": lambda c: c.set_active_slot(E.SlotNumber(slot(3))),
        "set_slot_enabled": lambda c: c.set_slot_enable(E.SlotNumber(slot(2)), E.TagSenseType.HF, True),
        "set_slot_tag_type": lambda c: c.set_slot_tag_type(E.SlotNumber(slot(2)), E.TagSpecificType.MIFARE_Mini),
        "set_slot_nick": lambda c: c.set_slot_tag_nick(E.SlotNumber(slot(1)), E.TagSenseType.LF, "abc"),
        "get_slot_nick": lambda c: c.get_slot_tag_nick(E.SlotNumber(slot(1)), E.TagSenseType.LF),
        "set_sleep_timeout": lambda c: c.set_sleep_timeout(120),
        "set_animation_mode": lambda c: c.set_animation_mode(2),
        "change_device_mode": lambda c: c.change_device_mode(1),
        "set_button_press_config": lambda c: c.set_button_press_config(E.ButtonType.A, 3),
        "get_button_press_config": lambda c: c.get_button_press_config(E.ButtonType.B),
        "set_long_button_press_config": lambda c: c.set_long_button_press_config(E.ButtonType.B, 4),
        "set_slot_data_default": lambda c: c.set_slot_data_default(E.SlotNumber(slot(4)), 0x0011),
        "delete_slot_tag_nick": lambda c: c.delete_slot_tag_nick(E.SlotNumber(slot(5)), E.TagSenseType.HF),
        "delete_slot_sense_type": lambda c: c.delete_slot_sense_type(E.SlotNumber(slot(6)), E.TagSenseType.LF),
        "set_hf14a_config": lambda c: c.hf14a_set_config({"bcc": 1, "cl2": 0, "cl3": 1, "rats": 1}),

        # ---- W5: HF14A raw / sniff / auth trace ----
        "hf14a_raw": lambda c: c.hf14a_raw(HF14A_RAW_OPTIONS, 500, list(RATS), None),
        "hf14a_sniff": lambda c: c.hf14a_sniff(2000),
        "hf14a_auth_trace": lambda c: c.hf14a_auth_trace(0x04, E.MfcKeyType.A, KEY_A, 1000),
        "enter_bootloader": lambda c: c.enter_bootloader(),

        # ---- W1/W2: LF and MF1 emulation ----
        "set_lf_emu_id_hidprox": lambda c: c.hidprox_set_emu_id(HIDPROX_ID13),
        "set_lf_emu_id_viking": lambda c: c.viking_set_emu_id(LF_ID4),
        "set_lf_emu_id_pac": lambda c: c.pac_set_emu_id(PAC_ID8),
        "set_lf_emu_id_ioprox": lambda c: c.ioprox_set_emu_id(IOPROX_ID16),
        "set_lf_emu_id_jablotron": lambda c: c.jablotron_set_emu_id(LF_ID5),
        "set_lf_emu_id_idteck": lambda c: c.idteck_set_emu_id(IDTECK_ID8),
        "set_em410x_emu_id": lambda c: c.em410x_set_emu_id(LF_ID5),
        "get_lf_emu_id": lambda c: c.hidprox_get_emu_id(),
        "set_hf_anticoll": lambda c: c.hf14a_set_anti_coll_data(key("04112233"), key("0400"), bytes([0x08]),
                                                              key("0578807000")),
        "write_emu_blocks": lambda c: c.mf1_write_emu_block_data(4, BLOCK16),
        "read_emu_blocks": lambda c: c.mf1_read_emu_block_data(4, 4),
        "mf1_set_gen1a": lambda c: c.mf1_set_gen1a_mode(True),
        "mf1_set_gen2": lambda c: c.mf1_set_gen2_mode(False),
        "mf1_set_block_anticoll": lambda c: c.mf1_set_block_anti_coll_mode(True),
        "mf1_set_write_mode": lambda c: c.mf1_set_write_mode(2),
        "mf1_set_field_off_reset": lambda c: c.mf1_set_field_off_do_reset(True),
        "mf1_set_prng_type": lambda c: c.mf1_set_prng_type(1),
        "mf1_set_detection_enable": lambda c: c.mf1_set_detection_enable(True),
        "mf1_get_detection_log": lambda c: c.mf1_get_detection_log(0),

        # ---- W3: MF0 / NTAG emulation ----
        "mf0_set_uid_magic_mode": lambda c: c.mf0_ntag_set_uid_magic_mode(True),
        "mf0_read_emu_page": lambda c: c.mfu_read_emu_page_data(4, 8),
        "mf0_write_emu_page": lambda c: c.mfu_write_emu_page_data(4, BLOCK16),
        "mf0_set_version": lambda c: c.mf0_ntag_set_version_data(key("0004040201000F03")),
        "mf0_set_signature": lambda c: c.mf0_ntag_set_signature_data(bytes(range(32))),
        "mf0_set_counter": lambda c: c.mfu_write_emu_counter_data(2, 0x2A, True),
        "mf0_set_write_mode": lambda c: c.mf0_ntag_set_write_mode(1),
        "mf0_set_detection_enable": lambda c: c.mf0_ntag_set_detection_enable(False),
        "mf0_get_detection_log": lambda c: c.mf0_ntag_get_detection_log(0),

        # ---- W6: acquisition commands ----
        "mf1_check_keys_of_sectors": lambda c: c.mf1_check_keys_of_sectors(key("0F000000000000000000"), [b"\xff" * 6, KEY_A]),
        "mf1_check_keys_on_block": lambda c: c.mf1_check_keys_on_block(3, 0x60, [b"\xff" * 6, KEY_A]),
        "mf1_darkside_acquire": lambda c: c.mf1_darkside_acquire(3, E.MfcKeyType.A, 1, 5),
        "mf1_nested_acquire": lambda c: c.mf1_nested_acquire(3, E.MfcKeyType.A, KEY_A, 8, E.MfcKeyType.A),
        "mf1_static_nested_acquire": lambda c: c.mf1_static_nested_acquire(3, E.MfcKeyType.A, KEY_A, 8, E.MfcKeyType.B),
        "mf1_hardnested_acquire": lambda c: c.mf1_hard_nested_acquire(False, 3, E.MfcKeyType.A, KEY_A, 8, E.MfcKeyType.B),
        "mf1_enc_nested_acquire": lambda c: c.mf1_static_encrypted_nested_acquire(KEY_A, 4, 1),
        "mf1_detect_prng": lambda c: c.mf1_detect_prng(),
        "mf1_detect_nt_dist": lambda c: c.mf1_detect_nt_dist(3, E.MfcKeyType.A, KEY_A),
        "mf1_manipulate_value_block": lambda c: c.mf1_manipulate_value_block(
            4, E.MfcKeyType.A, KEY_A, 0, 1, 8, E.MfcKeyType.B, KEY_A),

        # ---- W1/W5: LF writes and readers ----
        "em410x_write_to_t55xx": lambda c: c.em410x_write_to_t55xx(LF_ID5),
        "hidprox_write_to_t55xx": lambda c: c.hidprox_write_to_t55xx(HIDPROX_ID13),
        "em4x05_scan": lambda c: c.em4x05_scan(0x20206666),
        "adc_generic_read": lambda c: c.adc_generic_read(),
        "lf_sniff": lambda c: c.lf_sniff(1500),
        "ioprox_decode_raw": lambda c: c.ioprox_decode_raw(key("007D001F2EA60000")),
        "ioprox_compose_id": lambda c: c.ioprox_compose_id(0x02, 0x1F, 0x2EA6),

        # ---- W7: ISO14443-4 / EMV / SEOS ----
        "hf14a4_apdu_send": lambda c: c.hf14a_4_apdu_send(key("00A40400")),
        "hf14a4_reader_apdu": lambda c: c.hf14a_4_reader_apdu(key("00A4040000")),
        "hf14a4_add_static": lambda c: c.hf14a_4_add_static_response(key("00A40400"), key("9000")),
        "hf14a4_clear_static": lambda c: c.hf14a_4_clear_static_responses(),
        "hf14a4_set_anticoll": lambda c: c.hf14a_4_set_anti_coll(key("04112233"), key("0400"), 0x20,
                                                                key("0578807000")),
        "seos_write_emu_data": lambda c: c.seos_write_emu_data(key("40414243"), key("505152"), b"", b"", 1, 2),
        "seos_write_emu_keys": lambda c: c.seos_write_emu_keys(key("112233"), key("4455"), key("66778899")),
    }


# ---------------------------------------------------------------------------
# app_cmd.c: the commands upstream's Python client does not implement
# ---------------------------------------------------------------------------

def parse_app_cmd_payloads():
    """Return {command_id: (handler_name, [(name, type, size), ...])}.

    Reads the device firmware's dispatch table and the PACKED payload struct of
    each handler, so a command that has no Python counterpart can still be
    checked against the code that consumes it.
    """
    src = (UPSTREAM_SRC / ".." / "..").resolve()
    app_cmd = CU_UPSTREAM / "firmware" / "application" / "src" / "app_cmd.c"
    data_cmd = CU_UPSTREAM / "firmware" / "application" / "src" / "data_cmd.h"
    if not app_cmd.is_file() or not data_cmd.is_file():
        return None
    text = app_cmd.read_text(encoding="utf-8", errors="replace")
    header = data_cmd.read_text(encoding="utf-8", errors="replace")

    ids = {name: int(value) for name, value in
           re.findall(r"#define\s+(DATA_CMD_[A-Z0-9_]+)\s+\((\d+)\)", header)}

    # handler function name -> body
    bodies = {}
    for m in re.finditer(r"^static data_frame_tx_t \*(cmd_processor_[a-z0-9_]+)\([^)]*\)\s*\{", text, re.M):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        bodies[m.group(1)] = text[start:i]

    # dispatch table rows: {DATA_CMD_X, before, handler, after}
    table = {}
    for m in re.finditer(r"\{\s*(DATA_CMD_[A-Z0-9_]+)\s*,\s*[^,]+,\s*(cmd_processor_[a-z0-9_]+)\s*,", text):
        if m.group(1) in ids:
            table[ids[m.group(1)]] = m.group(2)

    result = {}
    for cmd_id, handler in table.items():
        body = bodies.get(handler)
        if not body:
            continue
        # the first PACKED struct declared in the handler
        sm = re.search(r"typedef struct\s*\{(.*?)\}\s*PACKED\s+(\w+)\s*;", body, re.S)
        if not sm:
            result[cmd_id] = (handler, None, 0)
            continue
        struct_body = sm.group(1)
        # A nested struct (hf14a_raw's options bitfield) cannot be sized from a
        # flat field list, so this handler is left unchecked rather than checked
        # against a wrong number. hf14a_raw is covered byte-for-byte by [1]
        # anyway, where the expected bytes come from running the ctypes
        # BigEndianStructure upstream actually uses.
        if re.search(r"^\s*struct\s*\{", struct_body, re.M) or ":" in struct_body:
            result[cmd_id] = (handler, None, 0)
            continue

        fields = []
        for fm in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(\w+)\s*(?:\[(\d*)\])?\s*;", struct_body, re.M):
            ftype, fname, count = fm.groups()
            size = {"uint8_t": 1, "int8_t": 1, "char": 1, "uint16_t": 2, "int16_t": 2,
                    "uint32_t": 4, "int32_t": 4, "uint64_t": 8}.get(ftype)
            if count is None:
                pass                                  # plain scalar
            elif count in ("", "0"):                  # flexible array member
                size = 0
            else:
                size = (size if size is not None else 1) * int(count)
            if size is None:
                fields = None
                break
            fields.append((fname, ftype, size))
        if fields is None:
            result[cmd_id] = (handler, None, 0)
            continue

        # The writers use `old_keys[4]` / `new_keys[4]` as "the smallest legal
        # tail" and then accept any number of repeats:
        #     (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) == 0
        # Detect that idiom and check the length as prefix + n * tail instead of
        # an exact total.
        tail_index = None
        om = re.search(r"offsetof\(\s*payload_t\s*,\s*(\w+)\s*\)", body)
        if om:
            for i, (fname, _, _) in enumerate(fields):
                if fname == om.group(1):
                    tail_index = i
                    break
        result[cmd_id] = (handler, fields, tail_index if tail_index is not None else -1)
    return result


def check_app_cmd_structs(port, structs):
    """For every command both sides know about, the ported payload length must
    equal the size the device handler reads."""
    print("[3] payload length vs the device handler's PACKED struct (app_cmd.c)")
    if structs is None:
        print("  FAIL app_cmd.c / data_cmd.h not found")
        failures.append("app_cmd.c missing")
        return
    checked = 0
    tail_checked = 0
    for cmd_id, (handler, fields, tail_index) in sorted(structs.items()):
        if fields is None:
            continue
        for name, got in port.items():
            if got is None or got[0] != cmd_id:
                continue

            if tail_index >= 0:
                # Fixed prefix + a repeating tail. `tail_index` points at the
                # first tail element; everything from there on repeats.
                prefix = sum(f[2] for f in fields[:tail_index])
                tail = fields[tail_index][2]
                names = ", ".join(f[0] for f in fields)
                tail_checked += 1
                if len(got[1]) < prefix + tail or (len(got[1]) - prefix) % tail != 0:
                    print("  FAIL %-28s port sends %d bytes, %s wants %d + n*%d (%s)"
                          % (name, len(got[1]), handler, prefix, tail, names))
                    failures.append("%s payload length" % name)
                continue

            total = sum(f[2] for f in fields)
            names = ", ".join(f[0] for f in fields)
            checked += 1
            if len(got[1]) != total:
                print("  FAIL %-28s port sends %d bytes, %s reads %d (%s)"
                      % (name, len(got[1]), handler, total, names))
                failures.append("%s payload length" % name)
    print("  checked %d fixed size struct(s) exactly, %d with a repeating tail" % (checked, tail_checked))


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Command coverage
# ---------------------------------------------------------------------------

# Commands with no place in this port, each with the reason. Anything not listed
# here must be referenced by the client, so a capability cannot quietly go
# missing.
NOT_IMPLEMENTED = {
    # Bluetooth is out of scope for this port (see README section 7).
    "SET_BLE_PAIRING_KEY": "bluetooth",
    "GET_BLE_PAIRING_KEY": "bluetooth",
    "DELETE_ALL_BLE_BONDS": "bluetooth",
    "GET_BLE_PAIRING_ENABLE": "bluetooth",
    "SET_BLE_PAIRING_ENABLE": "bluetooth",
    # The command id exists upstream but app_cmd.c has no handler for it and
    # chameleon_cmd.py has no method: there is nothing to call. That claim is
    # itself checked below, against app_cmd.c's dispatch table.
    "EM4X05_READSNIFF": "device has no handler (app_cmd.c) and no Python method",
}


def check_coverage(port_names):
    """Compare the ported command table with upstream's enum."""
    print("[0] command coverage: ported enum vs upstream chameleon_enum.Command")
    E = importlib.import_module("chameleon_enum")

    header = (CHAMELEON / "include" / "chameleon_commands.h").read_text(encoding="utf-8", errors="replace")
    ported = {}
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]+)\s*=\s*(\d+)\s*,", header, re.M):
        ported.setdefault(m.group(1), int(m.group(2)))

    official = {c.name: int(c) for c in E.Command}
    missing = sorted(set(official) - set(ported))
    mismatched = sorted(n for n in set(official) & set(ported) if official[n] != ported[n])

    # Names from the other upstream enums (status codes, tag types, ...) share
    # the header, so only report a port-only name as "extra" when upstream has no
    # enum member by that name at all.
    other_names = set()
    for member in dir(E):
        obj = getattr(E, member)
        if isinstance(obj, type) and issubclass(obj, enum.Enum) and obj is not E.Command:
            other_names.update(x.name for x in obj)
    extra = sorted(n for n, v in ported.items()
                   if n not in official and n not in other_names and v >= 1000)

    print("  upstream declares %d commands, the port declares %d" % (len(official), len(ported)))
    if missing:
        print("  FAIL not declared in the port: %s" % ", ".join(missing))
        failures.extend(missing)
    if extra:
        print("  FAIL declared in the port but not upstream: %s" % ", ".join(extra))
        failures.extend(extra)
    if mismatched:
        for n in mismatched:
            print("  FAIL %s: port %d, upstream %d" % (n, ported[n], official[n]))
        failures.extend(mismatched)

    # Where a command is used, not where its name is printed: the text table in
    # chameleon_commands.cpp names every command by construction, and comments
    # name the ones that are deliberately absent. Both are stripped, or this
    # check would count a mention as an implementation.
    sources = []
    for folder in (CHAMELEON / "src", CHAMELEON / "include", REPO / "firmware" / "main"):
        for path in sorted(folder.rglob("*")):
            if path.suffix in (".cpp", ".h") and path.name not in ("chameleon_commands.cpp",
                                                                  "chameleon_commands.h"):
                text = path.read_text(encoding="utf-8", errors="replace")
                text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
                text = re.sub(r"//[^\n]*", " ", text)
                sources.append(text)
    blob = "\n".join(sources)

    unreferenced = [n for n in sorted(official) if not re.search(r"\b%s\b" % re.escape(n), blob)]
    unexpected = [n for n in unreferenced if n not in NOT_IMPLEMENTED]
    for n in unreferenced:
        reason = NOT_IMPLEMENTED.get(n, "NO REASON GIVEN")
        print("  %-4s %-28s %s" % ("skip" if n in NOT_IMPLEMENTED else "FAIL", n, reason))

    # EM4X05_READSNIFF's exclusion rests on the device having no handler for it,
    # which is a fact about app_cmd.c and can be checked rather than asserted.
    structs = parse_app_cmd_payloads()
    if structs is not None and "EM4X05_READSNIFF" in NOT_IMPLEMENTED:
        readsniff_id = official["EM4X05_READSNIFF"]
        if readsniff_id in structs:
            print("  FAIL EM4X05_READSNIFF does have a handler (%s) - port it" % structs[readsniff_id][0])
            failures.append("EM4X05_READSNIFF")
        else:
            print("  ok   EM4X05_READSNIFF (%d) has no row in app_cmd.c's dispatch table" % readsniff_id)

    if not missing and not extra and not mismatched and not unexpected:
        print("  ok   every upstream command is present with the same id, and all but the "
              "%d listed above are used by the port" % len(unreferenced))
    print()


# ---------------------------------------------------------------------------
# UI reachability
# ---------------------------------------------------------------------------

# Ported client methods the UI does not reach, with the reason. Everything else
# must be reachable from a page: every wave of the port ends at a control the
# user can press, and section [4] fails if that stops being true.
KNOWN_UI_GAPS = {
    "deliberately not wired": {
        "EnterBootloader": "drops the USB link; the header says it is not a UI action",
        "Mf1DetectSupport": "MF1_DETECT_SUPPORT is a probe the attacks use internally",
        "FetchAppVersion": "part of the client's own connect handshake, not a user action",
        "FetchDeviceIdentity": "part of the client's own connect handshake, not a user action",
        "ScanEm410x": "superseded by ScanLfCommand(EM410X_SCAN); kept for protocol completeness",
        "SetEm410xEmuId": "superseded by SetLfEmuId(LfEmuProtocol::Em410x)",
        "GetEm410xEmuId": "superseded by GetLfEmuId(LfEmuProtocol::Em410x)",
        "DecodeTraceFrame": "the sniff decoder (sniff_decoder.cpp) walks the buffer itself; "
                            "this per-frame helper is the client-side twin of that loop",
    },
}


def check_ui_coverage():
    """Every ported client method should be reachable from a page, or be listed
    in KNOWN_UI_GAPS with a reason."""
    print("[4] UI reachability: ported client methods vs the pages")
    header = (CHAMELEON / "include" / "chameleon_client.h").read_text(encoding="utf-8", errors="replace")
    # Method declarations are the lines at class-body indentation that end in ');'
    # and are not part of a nested struct/typedef.
    methods = set()
    for m in re.finditer(r"^\s{4}(?:[\w:<>*&]+\s+)+(\w+)\s*\([^;{]*\)\s*;", header, re.M):
        name = m.group(1)
        if name[0].isupper() and name not in ("Client",):
            methods.add(name)
    methods -= {"Request", "OnTransportData", "OnTransportState"}

    sources = []
    for path in sorted((REPO / "firmware" / "main").rglob("*.cpp")):
        sources.append(path.read_text(encoding="utf-8", errors="replace"))
    blob = "\n".join(sources)

    wired = {n for n in methods if re.search(r"\b%s\b" % re.escape(n), blob)}

    gaps = {}
    for group, names in KNOWN_UI_GAPS.items():
        if isinstance(names, dict):
            for n, reason in names.items():
                gaps[n] = "%s: %s" % (group, reason)
        else:
            for n in names:
                gaps[n] = group

    missing = sorted(n for n in methods if n not in wired and n not in gaps)
    stale = sorted(n for n in gaps if n in wired)

    print("  %d of %d public client methods are used by a page" % (len(wired), len(methods)))
    by_group = {}
    for n, group in gaps.items():
        if n not in wired:
            by_group.setdefault(group.split(":")[0], []).append(n)
    for group in sorted(by_group):
        print("  gap  %-38s %d method(s): %s"
              % (group, len(by_group[group]), ", ".join(sorted(by_group[group]))))
    if missing:
        print("  FAIL not reachable from the UI and not listed as a gap: %s" % ", ".join(missing))
        failures.extend(missing)
    if stale:
        print("  note now wired, remove from KNOWN_UI_GAPS: %s" % ", ".join(stale))
    if not missing:
        print("  ok   every client method is either wired to a page or an accounted for gap")


def main():
    case_filter = sys.argv[1] if len(sys.argv) > 1 else None
    print("payload parity: ported client vs upstream chameleon_cmd.py")
    print()

    E, COM, CMD = load_upstream()
    check_coverage(None)

    exe = build_harness()
    port, res = run_port(exe, case_filter)
    if res.returncode != 0:
        print("  FAIL harness exited %d\n%s" % (res.returncode, (res.stderr or "")[:600]))
        failures.append("harness exit")
    noframe = sorted(k for k, v in port.items() if v is None)
    if noframe:
        print("  FAIL %d case(s) produced no frame: %s" % (len(noframe), ", ".join(noframe)))
        failures.extend(noframe)
    print("  the ported client sent %d frames" % len(port))
    print()

    table = cases(E, CMD)

    print("[1] every case: same command id, same payload bytes")
    # GET_SLOT_INFO answers 8 slots of (hf, lf) as big endian u16 pairs;
    # GET_ACTIVE_SLOT answers the firmware slot index. Slot 0 is given an
    # EM410X LF type so em410x_set_emu_id() accepts the 5 byte id this test uses.
    slot_info = b"".join(struct.pack("!HH", 0, 100) for _ in range(8))
    replies = {
        int(E.Command.GET_SLOT_INFO): slot_info,
        int(E.Command.GET_ACTIVE_SLOT): struct.pack("!B", 0),
    }
    fake = FakeDevice(COM.Response, E.Status.SUCCESS, replies)
    client = CMD.ChameleonCMD(fake)

    matched_names = []
    for name in sorted(port):
        if name in NO_UPSTREAM_COUNTERPART:
            continue
        if name not in table:
            print("  FAIL %-28s harness case has no upstream counterpart" % name)
            failures.append(name)
            continue
        fake.calls.clear()
        try:
            table[name](client)
        except Exception as exc:  # the call is recorded before any parsing happens
            if not fake.calls:
                print("  FAIL %-28s upstream raised before sending: %s" % (name, exc))
                failures.append(name)
                continue
        if not fake.calls:
            print("  FAIL %-28s upstream sent nothing" % name)
            failures.append(name)
            continue

        our_cmd, our_payload = port[name]
        # Upstream sometimes probes the device first (em410x_set_emu_id reads the
        # active LF tag type before it builds its payload), so the call to
        # compare is the first one carrying the command under test.
        matching = [call for call in fake.calls if call[0] == our_cmd]
        if not matching:
            print("  FAIL %-28s upstream never sent cmd %d, only %s"
                  % (name, our_cmd, [c[0] for c in fake.calls]))
            failures.append(name)
            continue
        up_cmd, up_payload = matching[0]
        if up_cmd != our_cmd:
            print("  FAIL %-28s command id: port %d, upstream %d" % (name, our_cmd, up_cmd))
            failures.append(name)
            continue
        if up_payload != our_payload:
            print("  FAIL %-28s payload differs" % name)
            print("        port     (%d): %s" % (len(our_payload), our_payload.hex().upper()))
            print("        upstream (%d): %s" % (len(up_payload), up_payload.hex().upper()))
            failures.append(name)
            continue
        matched_names.append(name)

    for name in matched_names:
        print("  ok   %-28s cmd %-5d %d bytes" % (name, port[name][0], len(port[name][1])))
    print("  %d/%d cases identical" % (len(matched_names), len(port)))
    print()

    # LF_T55XX_WRITE: no upstream Python method exists, so it is checked against
    # the handler in app_cmd.c by hand below rather than skipped silently.
    print("[2] commands upstream's Python client does not implement")
    t55 = port.get("t55xx_write_block")
    if t55 is None:
        print("  ..   t55xx_write_block not in this run")
    else:
        cmd_id, payload = t55
        # app_cmd.c cmd_processor_t55xx_write: typedef struct { uint8_t block;
        # uint32_t word; uint8_t use_pwd; uint32_t pwd; uint8_t page1; } PACKED
        want = bytes([1]) + (0x00148040).to_bytes(4, "big") + bytes([1]) + \
            (0x20206666).to_bytes(4, "big") + bytes([0])
        if cmd_id != 3016:
            print("  FAIL t55xx_write_block command id %d, expected 3016" % cmd_id)
            failures.append("t55xx_write_block")
        elif payload != want:
            print("  FAIL t55xx_write_block payload %s, app_cmd.c layout wants %s"
                  % (payload.hex().upper(), want.hex().upper()))
            failures.append("t55xx_write_block")
        else:
            print("  ok   t55xx_write_block             cmd 3016 %d bytes, matches app_cmd.c struct"
                  % len(payload))
    print()

    check_app_cmd_structs(port, parse_app_cmd_payloads())
    print()

    check_ui_coverage()
    print()

    if failures:
        print("%d CHECK(S) FAILED:" % len(failures))
        for f in failures:
            print("  -", f)
        return 1
    print("ALL PAYLOAD CHECKS PASSED (ported payloads identical to upstream)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
