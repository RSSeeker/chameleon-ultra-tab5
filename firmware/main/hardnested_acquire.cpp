// SPDX-License-Identifier: GPL-3.0-or-later
//
// See hardnested_acquire.h for why the solver is not part of this file and for
// the upstream line numbers every rule below comes from.

#include "hardnested_acquire.h"

#include <stdio.h>
#include <string.h>

namespace hardnested {

/// cmdhfmfhard.c:65 / hardnested_utils.py:1. Read as upstream text, not typed
/// from memory: tools/verify_hardnested_acquire.py parses both files and fails
/// if this table stops matching either of them.
const uint16_t kValidSums[kValidSumCount] = {0,   32,  56,  64,  80,  96,  104, 112, 120, 128,
                                             136, 144, 152, 160, 176, 192, 200, 224, 256};

void FirstByteTracker::Reset()
{
    memset(_seen, 0, sizeof(_seen));
    _unique = 0;
    _sum    = 0;
}

bool FirstByteTracker::Add(const PairRecord& rec)
{
    // hardnested_utils.check_nonce_unique_sum: the first byte is taken from the
    // *second* nonce of the pair, which is the one chameleon_cli_unit.py passes
    // after `struct.unpack_from("!IIB", ...)`.
    const uint8_t first_byte = static_cast<uint8_t>(rec.nt_enc2 >> 24);
    if (_seen[first_byte] != 0) {
        return false;
    }
    _seen[first_byte] = 1;
    ++_unique;

    // evenparity32((nt & 0xff000000) | (par & 0x08)): the parity of the first
    // byte, together with that byte's own transmitted parity bit (bit 3 of the
    // second nonce's nibble, per mf1_toolbox.c's bit packing).
    const uint32_t v = (rec.nt_enc2 & 0xFF000000u) | static_cast<uint32_t>(rec.par_packed & 0x08u);
    uint32_t bits    = 0;
    for (uint32_t i = 0; i < 32; ++i) {
        bits += (v >> i) & 1u;
    }
    _sum = static_cast<uint16_t>(_sum + (bits & 1u));
    return true;
}

size_t FirstByteTracker::AddRun(const uint8_t* raw, size_t len)
{
    if (raw == nullptr) {
        return 0;
    }
    const size_t records = len / kNonceFileRecordSize;
    for (size_t i = 0; i < records; ++i) {
        const uint8_t* p = raw + i * kNonceFileRecordSize;
        PairRecord rec;
        rec.nt_enc1 = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                      (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
        rec.nt_enc2 = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
                      (static_cast<uint32_t>(p[6]) << 8) | static_cast<uint32_t>(p[7]);
        rec.par_packed = p[8];
        Add(rec);
    }
    return records;
}

bool FirstByteTracker::sumIsValid() const
{
    for (size_t i = 0; i < kValidSumCount; ++i) {
        if (kValidSums[i] == _sum) {
            return true;
        }
    }
    return false;
}

bool UidForNonceFile(const uint8_t* uid, size_t uid_len, uint8_t out4[4])
{
    if (uid == nullptr || out4 == nullptr) {
        return false;
    }
    // chameleon_cli_unit.py:1699-1704: the last four bytes of a 4, 7 or 10 byte
    // UID. Any other length is refused rather than guessed at.
    switch (uid_len) {
    case 4:
        memcpy(out4, uid, 4);
        return true;
    case 7:
        memcpy(out4, uid + 3, 4);
        return true;
    case 10:
        memcpy(out4, uid + 6, 4);
        return true;
    default:
        return false;
    }
}

size_t BuildNonceFile(const uint8_t uid4[4], uint8_t sector, uint8_t key_type, const PairRecord* recs,
                      size_t count, uint8_t* out, size_t out_size)
{
    if (uid4 == nullptr || out == nullptr) {
        return 0;
    }
    if (count != 0 && recs == nullptr) {
        return 0;
    }
    const size_t need = kNonceFileHeaderSize + count * kNonceFileRecordSize;
    if (out_size < need) {
        return 0;
    }

    // hardnested_main.c:92 reads the UID with read_uint32_be(); the sector and
    // key type are single bytes.
    size_t at = 0;
    memcpy(out + at, uid4, 4);
    at += 4;
    out[at++] = sector;
    out[at++] = static_cast<uint8_t>(key_type & 0x01);

    for (size_t i = 0; i < count; ++i) {
        const PairRecord& r = recs[i];
        out[at++] = static_cast<uint8_t>(r.nt_enc1 >> 24);
        out[at++] = static_cast<uint8_t>(r.nt_enc1 >> 16);
        out[at++] = static_cast<uint8_t>(r.nt_enc1 >> 8);
        out[at++] = static_cast<uint8_t>(r.nt_enc1);
        out[at++] = static_cast<uint8_t>(r.nt_enc2 >> 24);
        out[at++] = static_cast<uint8_t>(r.nt_enc2 >> 16);
        out[at++] = static_cast<uint8_t>(r.nt_enc2 >> 8);
        out[at++] = static_cast<uint8_t>(r.nt_enc2);
        out[at++] = r.par_packed;
    }
    return at;
}

uint32_t Crc32(const uint8_t* data, size_t len)
{
    static uint32_t table[256];
    static bool table_ready = false;
    if (!table_ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        table_ready = true;
    }

    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

size_t FormatExport(const uint8_t* file, size_t len, uint32_t crc, ExportSink emit, void* user)
{
    if (file == nullptr || emit == nullptr) {
        return 0;
    }

    char line[kExportLineLength + 1];
    size_t lines = 0;

    // BEGIN first, whatever happens next: a capture that only has this line
    // still tells the reader how big the file should have been.
    snprintf(line, sizeof(line), "[HN] BEGIN SZ=%zX REC=%zX", len,
             len >= kNonceFileHeaderSize ? (len - kNonceFileHeaderSize) / kNonceFileRecordSize : 0);
    emit(user, line);
    ++lines;

    if (len > kMaxExportSize || len < kNonceFileHeaderSize ||
        (len - kNonceFileHeaderSize) % kNonceFileRecordSize != 0) {
        // The offset field of a data line is four hex digits, so a larger file
        // cannot be represented; a partial record means the caller built the
        // file wrong and the reader would reject it anyway.
        //
        // The message is short on purpose: it shares the 43 byte line buffer
        // with the data lines, and IDF builds with -Werror=format-truncation.
        snprintf(line, sizeof(line), "[HN] ERROR max SZ=FFFF");
        emit(user, line);
        return 0;
    }

    static const char kHex[] = "0123456789ABCDEF";
    for (size_t off = 0; off < len; off += kExportBytesPerLine) {
        size_t at  = 0;
        line[at++] = '[';
        line[at++] = 'H';
        line[at++] = 'N';
        line[at++] = ']';
        line[at++] = ' ';
        for (int nib = 3; nib >= 0; --nib) {
            line[at++] = kHex[(off >> (nib * 4)) & 0xF];
        }
        line[at++] = ' ';
        const size_t end = (off + kExportBytesPerLine < len) ? off + kExportBytesPerLine : len;
        for (size_t i = off; i < end; ++i) {
            line[at++] = kHex[file[i] >> 4];
            line[at++] = kHex[file[i] & 0xF];
        }
        // kExportLineLength is exactly the number of characters written above,
        // and the buffer is one byte larger than that.
        line[at] = '\0';
        emit(user, line);
        ++lines;
    }

    snprintf(line, sizeof(line), "[HN] END SZ=%zX CRC=%08X", len, (unsigned)crc);
    emit(user, line);
    ++lines;
    return lines;
}

size_t ParseExportDataLine(const char* line, size_t* offset_out, uint8_t* out, size_t out_size)
{
    if (line == nullptr || offset_out == nullptr || out == nullptr) {
        return 0;
    }
    // Find the marker rather than requiring it at index 0: on the device these
    // lines go through ESP_LOGI, which prefixes a timestamp and the log tag, and
    // the console capture a PC sees has that prefix. The Python decoder accepts
    // the same thing (it uses re.search, not re.match), and the probe feeds both
    // decoders the prefixed form precisely so they cannot drift apart.
    const char* s = strstr(line, "[HN] ");
    if (s == nullptr) {
        return 0;
    }
    s += 5;
    if (strncmp(s, "BEGIN", 5) == 0 || strncmp(s, "END", 3) == 0) {
        return 0;
    }
    if (strlen(s) < 5) {
        return 0;
    }

    size_t offset = 0;
    for (int i = 0; i < 4; ++i) {
        const char c = s[i];
        uint8_t v;
        if (c >= '0' && c <= '9') {
            v = static_cast<uint8_t>(c - '0');
        } else if (c >= 'A' && c <= 'F') {
            v = static_cast<uint8_t>(c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
            v = static_cast<uint8_t>(c - 'a' + 10);
        } else {
            return 0;
        }
        offset = (offset << 4) | v;
    }
    if (s[4] != ' ') {
        return 0;
    }

    size_t n = 0;
    for (size_t i = 5; s[i] != '\0' && s[i + 1] != '\0'; i += 2) {
        if (n >= out_size) {
            return 0;
        }
        uint8_t hi;
        uint8_t lo;
        const char a = s[i];
        const char b = s[i + 1];
        if (a >= '0' && a <= '9') {
            hi = static_cast<uint8_t>(a - '0');
        } else if (a >= 'A' && a <= 'F') {
            hi = static_cast<uint8_t>(a - 'A' + 10);
        } else if (a >= 'a' && a <= 'f') {
            hi = static_cast<uint8_t>(a - 'a' + 10);
        } else {
            return 0;
        }
        if (b >= '0' && b <= '9') {
            lo = static_cast<uint8_t>(b - '0');
        } else if (b >= 'A' && b <= 'F') {
            lo = static_cast<uint8_t>(b - 'A' + 10);
        } else if (b >= 'a' && b <= 'f') {
            lo = static_cast<uint8_t>(b - 'a' + 10);
        } else {
            return 0;
        }
        out[n++] = static_cast<uint8_t>((hi << 4) | lo);
    }

    *offset_out = offset;
    return n;
}

}  // namespace hardnested
