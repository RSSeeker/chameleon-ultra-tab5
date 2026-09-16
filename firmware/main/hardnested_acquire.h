// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tab5 port of the *client* half of ChameleonUltra's hardnested attack.
//
// Upstream splits the attack across three programs, which is worth spelling out
// because it decides what "porting hardnested" can mean here:
//
//   1. the Chameleon Ultra device acquires the nonces
//      (DATA_CMD_MF1_HARDNESTED_ACQUIRE -> mf1_toolbox.c
//       mf1_hardnested_nonces_acquire(), 9 bytes per nonce pair)
//   2. the client collects them, tracks the first-byte parity sum and writes a
//      nonce file (software/script/chameleon_cli_unit.py, HFMFHardNested)
//   3. a *separate* PC program cracks that file
//      (software/src/HardnestedRecovery, its own Makefile, -llzma -lpthread);
//      the client only parses its "Key found: ..." line and re-authenticates
//      with the card.
//
// Steps 1-2 belong on the Tab5; step 3 does not, and not because of porting
// effort. cmdhfmfhard.c's candidate generation keeps
// bitflip_bitarrays[2][0x400] and nonces[256].states_bitarray[2] resident at
// 2 MiB each (cmdhfmfhard.c:266, :522, :529), which is 474 MiB + 1 GiB - see
// docs/M5-KEY-RECOVERY.md section 6 for the measurement. That is 47x the
// Tab5's 32 MB of PSRAM, so the solver stays a PC program and the Tab5's job
// ends at producing the nonce file.
//
// This file therefore implements step 2 and nothing ESP specific, so that
// tools/verify_hardnested_acquire.py can compile the very same code on the host
// and compare it with upstream's Python (imported unmodified) and with
// upstream's own nonce file reader.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace hardnested {

/// One 9 byte record exactly as the device emits it. Wire layout from
/// mf1_toolbox.c:1162-1176:
///   [0..3] nt_enc of the first nonce of the pair  (big endian)
///   [4..7] nt_enc of the second nonce of the pair (big endian)
///   [8]    first nonce's parity nibble << 4 | second nonce's parity nibble
/// where a nonce's nibble is
///   parity[3] << 0 | parity[2] << 1 | parity[1] << 2 | parity[0] << 3
/// i.e. bit 3 of the nibble is the parity of the nonce's first (most
/// significant) byte. That bit is the one the Sum(a8) test needs.
struct PairRecord {
    uint32_t nt_enc1;
    uint32_t nt_enc2;
    uint8_t par_packed;
};

/// Per-attempt state: which of the 256 possible first bytes have been seen and
/// the running parity sum, mirroring hardnested_utils.py's
/// hardnested_nonces_sum_map / hardnested_first_byte_sum / check_nonce_unique_sum
/// (which chameleon_cli_unit.py drives, and which decides whether an acquisition
/// attempt is worth keeping).
class FirstByteTracker {
public:
    void Reset();

    /// Feed one record. Returns true when it revealed a first byte that had not
    /// been seen in this attempt.
    bool Add(const PairRecord& rec);

    /// Feed a whole run of raw device bytes. Returns the number of records that
    /// were complete; a trailing partial record (the device can report an odd
    /// nonce count, see mf1_toolbox.c:1169) is ignored, which is what the
    /// Python client's `len(raw) // 9` does.
    size_t AddRun(const uint8_t* raw, size_t len);

    uint16_t uniqueCount() const
    {
        return _unique;
    }

    /// Sum of evenparity32((nt_enc2 & 0xFF000000) | (par & 0x08)) over the first
    /// record seen for each distinct first byte.
    uint16_t paritySum() const
    {
        return _sum;
    }

    bool complete() const
    {
        return _unique == kFirstByteCount;
    }

    /// True when paritySum() is one of upstream's 19 valid Sum(a8) values.
    /// A complete sweep with an invalid sum means the acquisition has to be
    /// thrown away and retried - the nonce data itself is fine, the sum is a
    /// property of this particular collection.
    bool sumIsValid() const;

    static constexpr size_t kFirstByteCount = 256;

private:
    uint8_t _seen[kFirstByteCount] = {};
    uint16_t _unique                = 0;
    uint16_t _sum                   = 0;
};

/// upstream cmdhfmfhard.c:65 `static uint16_t sums[NUM_SUMS]`, the 19 legal
/// Sum(a8) values. Identical to hardnested_utils.hardnested_sums; the probe
/// reads both files and compares them with this table instead of trusting it.
extern const uint16_t kValidSums[19];
constexpr size_t kValidSumCount = 19;

/// Nonce file layout that upstream's hardnested tool reads, taken from
/// HardnestedRecovery/hardnested_main.c:92-188:
///   4 byte big endian UID | 1 byte sector | 1 byte key type (0 = A, 1 = B)
///   then `PairRecord`s back to back until EOF.
constexpr size_t kNonceFileHeaderSize  = 6;
constexpr size_t kNonceFileRecordSize  = 9;

/// The four UID bytes the file carries: chameleon_cli_unit.py:1699-1704 takes
/// the *last* four bytes of a 4, 7 or 10 byte UID.
bool UidForNonceFile(const uint8_t* uid, size_t uid_len, uint8_t out4[4]);

/// Serialise header + records. Returns the number of bytes written, or 0 when
/// the output buffer is too small.
size_t BuildNonceFile(const uint8_t uid4[4], uint8_t sector, uint8_t key_type, const PairRecord* recs,
                      size_t count, uint8_t* out, size_t out_size);

/// Reflected IEEE CRC32, used to make the console export self-checking. The
/// probe compares it against zlib.crc32 on random inputs.
uint32_t Crc32(const uint8_t* data, size_t len);

/// Bytes encoded per exported console line. 16 keeps a line at
/// 5 + 4 + 1 + 32 = 42 characters, well inside the 96 byte log line and readable
/// in a terminal.
constexpr size_t kExportBytesPerLine = 16;

/// Longest line FormatExport() can produce, excluding the terminating NUL:
/// "[HN] " + 4 offset digits + " " + 16 bytes as hex.
constexpr size_t kExportLineLength = 5 + 4 + 1 + kExportBytesPerLine * 2;

/// Records one nonce file may carry. The data lines encode their offset in four
/// hex digits, so the file has to stay below 64 KiB; 7281 records is
/// 6 + 7281 * 9 = 65535 bytes exactly.
constexpr size_t kMaxRecords    = 7281;
constexpr size_t kMaxExportSize = kNonceFileHeaderSize + kMaxRecords * kNonceFileRecordSize;

/// Callback receiving one line of the export, NUL terminated and at most
/// kExportLineLength characters.
using ExportSink = void (*)(void* user, const char* line);

/// Wrap `file` in the `[HN]` line format, one line at a time:
///   [HN] BEGIN SZ=<hex bytes> REC=<hex records>
///   [HN] <offset:04X> <32 hex digits>
///   [HN] END SZ=<hex bytes> CRC=<hex crc32>
/// The BEGIN/END lines carry the size and CRC32 so a capture that lost lines (or
/// picked up interleaved ones) is detected instead of silently producing a
/// corrupt nonce file.
///
/// Streaming rather than "build a buffer of lines" on purpose: the biggest file
/// this accepts is 64 KiB, i.e. 4097 lines, and holding them would cost 176 KB
/// of RAM for no reason.
///
/// Returns the number of lines emitted. Returns 0 - after emitting a BEGIN line
/// that names the size - when `len` is beyond kMaxExportSize or is not a whole
/// number of records.
size_t FormatExport(const uint8_t* file, size_t len, uint32_t crc, ExportSink emit, void* user);

/// Parse one data line of the export. The marker may appear anywhere in the
/// line, because on the device the line goes through ESP_LOGI, which prefixes a
/// timestamp and the log tag.
///   "I (123) tab5: [log] [HN] 0010 00112233..." -> offset 0x10, 16 bytes
/// Returns the number of bytes decoded, or 0 when the line is not a data line.
size_t ParseExportDataLine(const char* line, size_t* offset_out, uint8_t* out, size_t out_size);

}  // namespace hardnested
