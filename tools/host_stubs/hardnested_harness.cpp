// Host harness for firmware/main/hardnested_acquire.cpp.
//
// Built and driven by tools/verify_hardnested_acquire.py. It only marshals
// arguments and bytes; every rule under test lives in the ported file, and the
// expected values come from upstream (hardnested_utils.py imported unmodified,
// cmdhfmfhard.c's sums[], and HardnestedRecovery/hardnested_main.c's own file
// reader), never from a number typed in here.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "hardnested_acquire.h"

namespace {

bool read_file(const char* path, std::vector<unsigned char>* out)
{
    FILE* f = fopen(path, "rb");
    if (f == nullptr) {
        fprintf(stderr, "cannot open %s\n", path);
        return false;
    }
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        out->insert(out->end(), buf, buf + n);
    }
    fclose(f);
    return true;
}

bool write_file(const char* path, const unsigned char* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (f == nullptr) {
        fprintf(stderr, "cannot write %s\n", path);
        return false;
    }
    const size_t written = (len == 0) ? 0 : fwrite(data, 1, len, f);
    fclose(f);
    return written == len;
}

/// "<hex>" -> bytes. Returns false on an odd length or a non-hex character.
bool parse_hex(const char* text, std::vector<unsigned char>* out)
{
    const size_t len = strlen(text);
    if (len % 2 != 0) {
        return false;
    }
    for (size_t i = 0; i < len; i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(text[i]);
        const int lo = nib(text[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out->push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

int cmd_sums()
{
    for (size_t i = 0; i < hardnested::kValidSumCount; ++i) {
        printf("%s%u", i ? "," : "", hardnested::kValidSums[i]);
    }
    printf("\n");
    return 0;
}

int cmd_track(const char* rec_path)
{
    std::vector<unsigned char> raw;
    if (!read_file(rec_path, &raw)) {
        return 2;
    }
    hardnested::FirstByteTracker tracker;
    tracker.Reset();
    const size_t records = tracker.AddRun(raw.data(), raw.size());
    printf("RECORDS=%zu UNIQ=%u SUM=%u COMPLETE=%d VALID=%d\n", records, tracker.uniqueCount(),
           tracker.paritySum(), tracker.complete() ? 1 : 0, tracker.sumIsValid() ? 1 : 0);

    // Also exercise the per-record path, so Add() and AddRun() are shown to agree.
    hardnested::FirstByteTracker one;
    one.Reset();
    size_t added = 0;
    for (size_t i = 0; i + hardnested::kNonceFileRecordSize <= raw.size(); i += hardnested::kNonceFileRecordSize) {
        const unsigned char* p = raw.data() + i;
        hardnested::PairRecord rec;
        rec.nt_enc1 = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                      (static_cast<uint32_t>(p[2]) << 8) | p[3];
        rec.nt_enc2 = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
                      (static_cast<uint32_t>(p[6]) << 8) | p[7];
        rec.par_packed = p[8];
        added += one.Add(rec) ? 1 : 0;
    }
    printf("PERRECORD_NEW=%zu UNIQ=%u SUM=%u VALID=%d\n", added, one.uniqueCount(), one.paritySum(),
           one.sumIsValid() ? 1 : 0);
    return 0;
}

int cmd_build(const char* rec_path, const char* header_hex, const char* out_path)
{
    std::vector<unsigned char> header;
    if (!parse_hex(header_hex, &header) || header.size() != hardnested::kNonceFileHeaderSize) {
        fprintf(stderr, "header must be %zu hex bytes\n", hardnested::kNonceFileHeaderSize);
        return 2;
    }
    std::vector<unsigned char> raw;
    if (!read_file(rec_path, &raw)) {
        return 2;
    }

    const size_t count = raw.size() / hardnested::kNonceFileRecordSize;
    std::vector<hardnested::PairRecord> recs(count);
    for (size_t i = 0; i < count; ++i) {
        const unsigned char* p = raw.data() + i * hardnested::kNonceFileRecordSize;
        recs[i].nt_enc1 = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                          (static_cast<uint32_t>(p[2]) << 8) | p[3];
        recs[i].nt_enc2 = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
                          (static_cast<uint32_t>(p[6]) << 8) | p[7];
        recs[i].par_packed = p[8];
    }

    const size_t need = hardnested::kNonceFileHeaderSize + count * hardnested::kNonceFileRecordSize;
    std::vector<unsigned char> file(need);
    const size_t len = hardnested::BuildNonceFile(header.data(), header[4], header[5], recs.data(), count,
                                                 file.data(), file.size());
    if (len != need) {
        fprintf(stderr, "BuildNonceFile wrote %zu of %zu bytes\n", len, need);
        return 3;
    }
    if (!write_file(out_path, file.data(), len)) {
        return 2;
    }
    printf("SZ=%zX CRC=%08X REC=%zX\n", len, hardnested::Crc32(file.data(), len), count);
    return 0;
}

int cmd_crc(const char* path)
{
    std::vector<unsigned char> data;
    if (!read_file(path, &data)) {
        return 2;
    }
    printf("%08X\n", hardnested::Crc32(data.data(), data.size()));
    return 0;
}

/// Prints a line the way the device's logger does, so the decoder is tested
/// against the same prefix it will see on the wire.
void print_as_device(void* user, const char* line)
{
    (void)user;
    printf("I (12345) tab5: [log] %s\n", line);
}

int cmd_export(const char* path)
{
    std::vector<unsigned char> file;
    if (!read_file(path, &file)) {
        return 2;
    }
    const uint32_t crc = hardnested::Crc32(file.data(), file.size());
    const size_t lines = hardnested::FormatExport(file.data(), file.size(), crc, print_as_device, nullptr);
    if (lines == 0) {
        fprintf(stderr, "FormatExport refused a %zu byte file\n", file.size());
        return 3;
    }
    return 0;
}

/// Reassemble a file from export lines using the ported parser, proving the
/// direction the device-side code owns. The user-facing decoder lives in
/// tools/nonce_file_from_console.py and is exercised separately.
int cmd_reparse(const char* lines_path, const char* out_path)
{
    FILE* f = fopen(lines_path, "r");
    if (f == nullptr) {
        fprintf(stderr, "cannot open %s\n", lines_path);
        return 2;
    }
    std::vector<unsigned char> blob;
    char line[512];
    while (fgets(line, sizeof(line), f) != nullptr) {
        size_t offset = 0;
        unsigned char buf[64];
        const size_t n = hardnested::ParseExportDataLine(line, &offset, buf, sizeof(buf));
        if (n == 0) {
            continue;
        }
        if (blob.size() < offset + n) {
            blob.resize(offset + n, 0);
        }
        memcpy(blob.data() + offset, buf, n);
    }
    fclose(f);
    if (!write_file(out_path, blob.data(), blob.size())) {
        return 2;
    }
    printf("SZ=%zX CRC=%08X\n", blob.size(), hardnested::Crc32(blob.data(), blob.size()));
    return 0;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s sums\n"
                "       %s track <records.bin>\n"
                "       %s build <records.bin> <6-byte-header-hex> <out.bin>\n"
                "       %s export <nonces.bin>\n"
                "       %s reparse <export-lines.txt> <out.bin>\n"
                "       %s crc <file>\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    const std::string cmd = argv[1];
    if (cmd == "sums" && argc == 2) {
        return cmd_sums();
    }
    if (cmd == "track" && argc == 3) {
        return cmd_track(argv[2]);
    }
    if (cmd == "build" && argc == 5) {
        return cmd_build(argv[2], argv[3], argv[4]);
    }
    if (cmd == "export" && argc == 3) {
        return cmd_export(argv[2]);
    }
    if (cmd == "reparse" && argc == 4) {
        return cmd_reparse(argv[2], argv[3]);
    }
    if (cmd == "crc" && argc == 3) {
        return cmd_crc(argv[2]);
    }
    fprintf(stderr, "bad arguments\n");
    return 2;
}
