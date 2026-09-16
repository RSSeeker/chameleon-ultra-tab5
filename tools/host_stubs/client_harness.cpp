// SPDX-License-Identifier: MIT
//
// Host harness for tools/verify_payloads.py.
//
// It links the *ported* client (firmware/components/chameleon/src/*) on the host
// with a fake transport, drives one client method per case, and prints the
// request frame that came out. The Python side does the same thing to the
// official chameleon_cmd.py (with a fake device) and compares the two payloads
// byte for byte.
//
// Why this exists: the goal for this port is that every command's payload layout
// comes from upstream's chameleon_cmd.py / app_cmd.c and never from memory. That
// is a claim about bytes on the wire, so it is checked as bytes on the wire -
// not by eyeballing field assignments against a struct format string.
//
// Not part of the firmware build.

#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "chameleon_client.h"
#include "chameleon_protocol.h"

namespace {

using chameleon::Client;

/// One recorded request frame.
struct Recorded {
    uint16_t cmd = 0;
    std::vector<uint8_t> payload;
};

/// Non-null while a case is running; the handshake frames are ignored.
const char* g_case = nullptr;
std::vector<Recorded> g_frames;

/// Reply the fake device sends back. Zero filled, so a client that parses the
/// response sees a well formed but empty answer; the request payload we care
/// about has already been recorded by then.
std::vector<uint8_t> g_reply;
uint16_t g_reply_status = chameleon::SUCCESS;

void record_frame(const uint8_t* frame, size_t len, Recorded* out)
{
    struct Sink {
        static void on_frame(const chameleon::FrameParser::Frame& f, void* u) {
            auto* rec = static_cast<Recorded*>(u);
            rec->cmd = f.cmd;
            rec->payload.assign(f.data, f.data + f.data_length);
        }
    };
    chameleon::FrameParser parser;
    parser.Push(frame, len, &Sink::on_frame, out);
}

bool send_hook(const uint8_t* frame, size_t len, void* user)
{
    Client* client = static_cast<Client*>(user);

    Recorded rec;
    record_frame(frame, len, &rec);

    if (g_case != nullptr) {
        g_frames.push_back(rec);
    }

    // Answer immediately: Request() sends first and only then waits, so a
    // synchronous response is exactly what a real device looks like from here.
    if (client != nullptr) {
        uint8_t reply[8192];
        const size_t reply_len = chameleon::BuildFrame(reply, sizeof(reply), rec.cmd, g_reply_status,
                                                       g_reply.empty() ? nullptr : g_reply.data(),
                                                       g_reply.size());
        if (reply_len != 0) {
            client->OnTransportData(reply, reply_len);
        }
    }
    return true;
}

/// Print the first frame a case produced, in a form the Python side can parse.
void report(const char* name)
{
    if (g_frames.empty()) {
        printf("CASE %s NOFRAME\n", name);
        return;
    }
    const Recorded& rec = g_frames.front();
    printf("CASE %s CMD %u LEN %u PAYLOAD ", name, rec.cmd, (unsigned)rec.payload.size());
    for (uint8_t b : rec.payload) {
        printf("%02X", b);
    }
    printf("\n");
}

/// Run one case: reset the recording, call the body, report.
template <typename Fn>
void run(const char* name, Fn body)
{
    g_case = name;
    g_frames.clear();
    body();
    g_case = nullptr;
    report(name);
}

// ---------------------------------------------------------------------------
// Shared fixtures. Fixed values, so a mismatch can never be blamed on the input.
// ---------------------------------------------------------------------------

const uint8_t kKeyA[6]   = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
const uint8_t kBlock[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
const uint8_t kRats[4]   = {0x05, 0x78, 0x80, 0x00};

/// LF ids used by the emulation waves. The lengths are the ones upstream's
/// chameleon_cmd.py enforces in each *_set_emu_id: HIDProx 13, ioProx 16,
/// IDTECK 8, Viking 4, PAC 8, Jablotron 5, EM410X 5 (Electra 13).
const uint8_t kHidProxId13[13] = {0x20, 0x01, 0x00, 0x2C, 0xC1, 0x0A, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t kIoProxId16[16]  = {0x02, 0x1F, 0x2E, 0xA6, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t kIdteckId8[8]    = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11};
const uint8_t kPacId8[8]       = {'1', '2', '3', '4', '5', '6', '7', '8'};
const uint8_t kLfId5[5]        = {0x12, 0x34, 0x56, 0x78, 0x9A};
const uint8_t kLfId4[4]        = {0x12, 0x34, 0x56, 0x78};

}  // namespace

int main(int argc, char** argv)
{
    /// Filter by case-name substring, so one case can be debugged without
    /// rebuilding. No argument runs everything.
    const std::string filter = (argc > 1) ? argv[1] : std::string();

    static Client client;
    client.SetTransport(&send_hook, &client);
    client.OnTransportState(true);  // handshake; not recorded
    g_frames.clear();

    auto want = [&filter](const char* name) { return filter.empty() || filter == name; };

    // ---- W4: system / settings ------------------------------------------
    if (want("set_active_slot")) {
        run("set_active_slot", [&] { client.SetActiveSlot(3); });
    }
    if (want("set_slot_enabled")) {
        run("set_slot_enabled", [&] { client.SetSlotEnabled(2, chameleon::TagSenseType::HF, true); });
    }
    if (want("set_slot_tag_type")) {
        // 1000 = TagSpecificType.MIFARE_Mini, the first HF type in the CU enum.
        run("set_slot_tag_type", [&] { client.SetSlotTagType(2, chameleon::TagSenseType::HF, 1000); });
    }
    if (want("set_slot_nick")) {
        run("set_slot_nick", [&] { client.SetSlotNick(1, chameleon::TagSenseType::LF, "abc"); });
    }
    if (want("get_slot_nick")) {
        run("get_slot_nick", [&] {
            char nick[32];
            client.GetSlotNick(1, chameleon::TagSenseType::LF, nick, sizeof(nick));
        });
    }
    if (want("set_sleep_timeout")) {
        run("set_sleep_timeout", [&] { client.SetSleepTimeout(120); });
    }
    if (want("set_animation_mode")) {
        run("set_animation_mode", [&] { client.SetAnimationMode(0x02); });
    }
    if (want("change_device_mode")) {
        run("change_device_mode", [&] { client.ChangeDeviceMode(1); });
    }
    if (want("set_button_press_config")) {
        // 'A' = 0x41, see docs/PORTING-NOTES.md item 16.
        run("set_button_press_config", [&] { client.SetButtonPressConfig('A', 0x03); });
    }
    if (want("get_button_press_config")) {
        run("get_button_press_config", [&] {
            uint8_t fn = 0;
            client.GetButtonPressConfig('B', &fn);
        });
    }
    if (want("set_long_button_press_config")) {
        run("set_long_button_press_config", [&] { client.SetLongButtonPressConfig('B', 0x04); });
    }
    if (want("set_slot_data_default")) {
        run("set_slot_data_default", [&] { client.SetSlotDataDefault(4, 0x0011); });
    }
    if (want("delete_slot_tag_nick")) {
        run("delete_slot_tag_nick", [&] { client.DeleteSlotTagNick(5, chameleon::TagSenseType::HF); });
    }
    if (want("delete_slot_sense_type")) {
        run("delete_slot_sense_type", [&] { client.DeleteSlotSenseType(6, chameleon::TagSenseType::LF); });
    }
    if (want("set_hf14a_config")) {
        run("set_hf14a_config", [&] {
            Client::Hf14aConfig cfg;
            cfg.bcc  = 1;
            cfg.cl2  = 0;
            cfg.cl3  = 1;
            cfg.rats = 1;
            client.SetHf14aConfig(cfg);
        });
    }

    // ---- W5: HF14A raw / sniff / auth trace ------------------------------
    if (want("hf14a_raw")) {
        run("hf14a_raw", [&] {
            Client::Hf14aRawOptions opt;
            opt.activate_rf_field  = true;
            opt.wait_response      = true;
            opt.append_crc         = true;
            opt.auto_select        = false;
            opt.keep_rf_field      = false;
            opt.check_response_crc = false;
            uint8_t out[64];
            size_t out_len = 0;
            client.Hf14aRaw(opt, 500, 0, kRats, sizeof(kRats), out, sizeof(out), &out_len);
        });
    }
    if (want("hf14a_sniff")) {
        run("hf14a_sniff", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.Hf14aSniff(2000, out, sizeof(out), &out_len);
        });
    }
    if (want("hf14a_auth_trace")) {
        run("hf14a_auth_trace", [&] {
            uint8_t out[128];
            size_t out_len = 0;
            client.Hf14aAuthTrace(0x04, chameleon::MfcKeyType::A, kKeyA, 1000, out, sizeof(out), &out_len);
        });
    }
    if (want("enter_bootloader")) {
        run("enter_bootloader", [&] { client.EnterBootloader(); });
    }

    // ---- W1/W2: LF and MF1 emulation -------------------------------------
    if (want("set_lf_emu_id_hidprox")) {
        run("set_lf_emu_id_hidprox", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::HidProx, kHidProxId13, sizeof(kHidProxId13));
        });
    }
    if (want("set_lf_emu_id_viking")) {
        run("set_lf_emu_id_viking", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::Viking, kLfId4, sizeof(kLfId4));
        });
    }
    if (want("set_lf_emu_id_pac")) {
        run("set_lf_emu_id_pac", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::Pac, kPacId8, sizeof(kPacId8));
        });
    }
    if (want("set_lf_emu_id_ioprox")) {
        run("set_lf_emu_id_ioprox", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::IoProx, kIoProxId16, sizeof(kIoProxId16));
        });
    }
    if (want("set_lf_emu_id_jablotron")) {
        run("set_lf_emu_id_jablotron", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::Jablotron, kLfId5, sizeof(kLfId5));
        });
    }
    if (want("set_lf_emu_id_idteck")) {
        run("set_lf_emu_id_idteck", [&] {
            client.SetLfEmuId(Client::LfEmuProtocol::Idteck, kIdteckId8, sizeof(kIdteckId8));
        });
    }
    if (want("set_em410x_emu_id")) {
        run("set_em410x_emu_id", [&] { client.SetEm410xEmuId(kLfId5, sizeof(kLfId5)); });
    }
    if (want("get_lf_emu_id")) {
        run("get_lf_emu_id", [&] {
            uint8_t out[16];
            size_t out_len = 0;
            client.GetLfEmuId(Client::LfEmuProtocol::HidProx, out, sizeof(out), &out_len);
        });
    }
    if (want("set_hf_anticoll")) {
        run("set_hf_anticoll", [&] {
            const uint8_t uid4[4] = {0x04, 0x11, 0x22, 0x33};
            const uint8_t atqa[2] = {0x04, 0x00};
            const uint8_t ats[5]  = {0x05, 0x78, 0x80, 0x70, 0x00};
            client.SetHfAntiColl(uid4, sizeof(uid4), atqa, 0x08, ats, sizeof(ats));
        });
    }
    if (want("write_emu_blocks")) {
        run("write_emu_blocks", [&] { client.WriteEmuBlocks(4, kBlock, sizeof(kBlock)); });
    }
    if (want("read_emu_blocks")) {
        run("read_emu_blocks", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.ReadEmuBlocks(4, 4, out, sizeof(out), &out_len);
        });
    }
    if (want("mf1_set_gen1a")) {
        run("mf1_set_gen1a", [&] { client.SetMf1Toggle(Client::Mf1Toggle::Gen1aMagic, 1); });
    }
    if (want("mf1_set_gen2")) {
        run("mf1_set_gen2", [&] { client.SetMf1Toggle(Client::Mf1Toggle::Gen2Magic, 0); });
    }
    if (want("mf1_set_block_anticoll")) {
        run("mf1_set_block_anticoll", [&] { client.SetMf1Toggle(Client::Mf1Toggle::BlockAntiColl, 1); });
    }
    if (want("mf1_set_write_mode")) {
        run("mf1_set_write_mode", [&] { client.SetMf1Toggle(Client::Mf1Toggle::WriteMode, 2); });
    }
    if (want("mf1_set_field_off_reset")) {
        run("mf1_set_field_off_reset", [&] { client.SetMf1Toggle(Client::Mf1Toggle::FieldOffReset, 1); });
    }
    if (want("mf1_set_prng_type")) {
        run("mf1_set_prng_type", [&] { client.SetMf1Toggle(Client::Mf1Toggle::PrngType, 1); });
    }
    if (want("mf1_set_detection_enable")) {
        run("mf1_set_detection_enable", [&] { client.SetMf1Toggle(Client::Mf1Toggle::Detection, 1); });
    }
    if (want("mf1_get_detection_log")) {
        run("mf1_get_detection_log", [&] {
            Client::Mf1DetectionEntry entries[8];
            size_t count = 0;
            client.Mf1GetDetectionLog(0, entries, 8, &count);
        });
    }

    // ---- W3: MF0 / NTAG emulation ----------------------------------------
    if (want("mf0_set_uid_magic_mode")) {
        run("mf0_set_uid_magic_mode", [&] { client.Mf0SetUidMagicMode(true); });
    }
    if (want("mf0_read_emu_page")) {
        run("mf0_read_emu_page", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.Mf0ReadEmuPageData(4, 8, out, sizeof(out), &out_len);
        });
    }
    if (want("mf0_write_emu_page")) {
        run("mf0_write_emu_page", [&] { client.Mf0WriteEmuPageData(4, kBlock, 16); });
    }
    if (want("mf0_set_version")) {
        run("mf0_set_version", [&] {
            const uint8_t ver[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
            client.Mf0SetVersionData(ver);
        });
    }
    if (want("mf0_set_signature")) {
        run("mf0_set_signature", [&] {
            uint8_t sig[32];
            for (size_t i = 0; i < sizeof(sig); ++i) {
                sig[i] = static_cast<uint8_t>(i);
            }
            client.Mf0SetSignatureData(sig);
        });
    }
    if (want("mf0_set_counter")) {
        run("mf0_set_counter", [&] { client.Mf0SetCounterData(2, true, 0x0000002A); });
    }
    if (want("mf0_set_write_mode")) {
        run("mf0_set_write_mode", [&] { client.Mf0SetWriteMode(0x01); });
    }
    if (want("mf0_set_detection_enable")) {
        run("mf0_set_detection_enable", [&] { client.Mf0SetDetectionEnable(false); });
    }
    if (want("mf0_get_detection_log")) {
        run("mf0_get_detection_log", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.Mf0GetDetectionLog(0, out, sizeof(out), &out_len);
        });
    }

    // ---- W6: acquisition commands the attacks use -------------------------
    if (want("mf1_check_keys_of_sectors")) {
        run("mf1_check_keys_of_sectors", [&] {
            uint8_t mask[10] = {0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            uint8_t keys[12] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
            uint8_t found[10];
            uint8_t sector_keys[40][6];
            size_t out_len = 0;
            client.CheckKeysOfSectors(mask, keys, 2, found, sector_keys, &out_len);
        });
    }
    if (want("mf1_check_keys_on_block")) {
        run("mf1_check_keys_on_block", [&] {
            uint8_t keys[12] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
            const uint8_t* out = nullptr;
            size_t out_len = 0;
            client.CheckKeysOnBlock(3, chameleon::MfcKeyType::A, keys, 2, &out, &out_len);
        });
    }
    if (want("mf1_darkside_acquire")) {
        run("mf1_darkside_acquire", [&] {
            Client::DarksideResult res;
            client.DarksideAcquire(3, chameleon::MfcKeyType::A, true, 5, &res);
        });
    }
    if (want("mf1_nested_acquire")) {
        run("mf1_nested_acquire", [&] {
            Client::NestedNonce nonces[4];
            size_t count = 0;
            client.Mf1NestedAcquire(3, chameleon::MfcKeyType::A, kKeyA, 8, chameleon::MfcKeyType::A, nonces, 4,
                                    &count);
        });
    }
    if (want("mf1_static_nested_acquire")) {
        run("mf1_static_nested_acquire", [&] {
            Client::StaticNestedNonce nonces[4];
            size_t count = 0;
            uint32_t uid = 0;
            client.Mf1StaticNestedAcquire(3, chameleon::MfcKeyType::A, kKeyA, 8, chameleon::MfcKeyType::B, &uid,
                                          nonces, 4, &count);
        });
    }
    if (want("mf1_hardnested_acquire")) {
        run("mf1_hardnested_acquire", [&] {
            uint8_t out[512];
            size_t out_len = 0;
            client.Mf1HardNestedAcquire(false, 3, chameleon::MfcKeyType::A, kKeyA, 8, chameleon::MfcKeyType::B, out,
                                        sizeof(out), &out_len);
        });
    }
    if (want("mf1_enc_nested_acquire")) {
        run("mf1_enc_nested_acquire", [&] {
            uint32_t nonces[16];
            size_t count = 0;
            client.Mf1EncNestedAcquire(kKeyA, 4, 1, nonces, 16, &count);
        });
    }
    if (want("mf1_detect_prng")) {
        run("mf1_detect_prng", [&] {
            uint8_t level = 0;
            client.Mf1DetectPrng(&level);
        });
    }
    if (want("mf1_detect_nt_dist")) {
        run("mf1_detect_nt_dist", [&] {
            uint32_t uid = 0;
            uint32_t dist = 0;
            client.Mf1DetectNtDist(3, chameleon::MfcKeyType::A, kKeyA, &uid, &dist);
        });
    }
    if (want("mf1_manipulate_value_block")) {
        run("mf1_manipulate_value_block", [&] {
            client.Mf1ManipulateValueBlock(4, chameleon::MfcKeyType::A, kKeyA, 0, 1, 8, chameleon::MfcKeyType::B,
                                           kKeyA);
        });
    }

    // ---- W1/W5: LF writes and readers ------------------------------------
    if (want("t55xx_write_block")) {
        run("t55xx_write_block", [&] {
            client.T55xxWriteBlock(1, 0x00148040, true, 0x20206666, false);
        });
    }
    if (want("em410x_write_to_t55xx")) {
        run("em410x_write_to_t55xx", [&] {
            client.WriteT55xx(chameleon::EM410X_WRITE_TO_T55XX, kLfId5, sizeof(kLfId5));
        });
    }
    if (want("hidprox_write_to_t55xx")) {
        run("hidprox_write_to_t55xx", [&] {
            // The HIDProx id is the 13 byte scan reply (see PORTING-NOTES 11.2).
            const uint8_t id13[13] = {0x20, 0x01, 0x00, 0x2C, 0xC1, 0x0A, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00};
            client.WriteT55xx(chameleon::HIDPROX_WRITE_TO_T55XX, id13, sizeof(id13));
        });
    }
    if (want("em4x05_scan")) {
        run("em4x05_scan", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.Em4x05Scan(0x20206666, out, sizeof(out), &out_len);
        });
    }
    if (want("adc_generic_read")) {
        run("adc_generic_read", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.AdcGenericRead(out, sizeof(out), &out_len);
        });
    }
    if (want("lf_sniff")) {
        run("lf_sniff", [&] {
            uint8_t out[64];
            size_t out_len = 0;
            client.LfSniff(1500, out, sizeof(out), &out_len);
        });
    }
    if (want("ioprox_decode_raw")) {
        run("ioprox_decode_raw", [&] {
            const uint8_t raw8[8] = {0x00, 0x7D, 0x00, 0x1F, 0x2E, 0xA6, 0x00, 0x00};
            uint8_t out[16];
            client.IoProxDecodeRaw(raw8, out);
        });
    }
    if (want("ioprox_compose_id")) {
        run("ioprox_compose_id", [&] {
            uint8_t out[16];
            client.IoProxComposeId(0x02, 0x1F, 0x2EA6, out);
        });
    }

    // ---- W7: ISO14443-4 / EMV / SEOS -------------------------------------
    if (want("hf14a4_apdu_send")) {
        run("hf14a4_apdu_send", [&] {
            const uint8_t apdu[4] = {0x00, 0xA4, 0x04, 0x00};
            client.Hf14a4ApduSend(apdu, sizeof(apdu));
        });
    }
    if (want("hf14a4_reader_apdu")) {
        run("hf14a4_reader_apdu", [&] {
            const uint8_t apdu[5] = {0x00, 0xA4, 0x04, 0x00, 0x00};
            uint8_t out[64];
            size_t out_len = 0;
            client.Hf14a4ReaderApdu(apdu, sizeof(apdu), out, sizeof(out), &out_len);
        });
    }
    if (want("hf14a4_add_static")) {
        run("hf14a4_add_static", [&] {
            const uint8_t command[4]  = {0x00, 0xA4, 0x04, 0x00};
            const uint8_t response[2] = {0x90, 0x00};
            client.Hf14a4AddStaticResponse(command, sizeof(command), response, sizeof(response));
        });
    }
    if (want("hf14a4_clear_static")) {
        run("hf14a4_clear_static", [&] { client.Hf14a4ClearStaticResponses(); });
    }
    if (want("hf14a4_set_anticoll")) {
        run("hf14a4_set_anticoll", [&] {
            const uint8_t uid4[4] = {0x04, 0x11, 0x22, 0x33};
            const uint8_t atqa[2] = {0x04, 0x00};
            const uint8_t ats[5]  = {0x05, 0x78, 0x80, 0x70, 0x00};
            client.Hf14a4SetAntiColl(uid4, sizeof(uid4), atqa, 0x20, ats, sizeof(ats));
        });
    }
    if (want("seos_write_emu_data")) {
        run("seos_write_emu_data", [&] {
            Client::SeosEmuData data{};
            data.data_length = 4;
            for (size_t i = 0; i < data.data_length; ++i) {
                data.data[i] = static_cast<uint8_t>(0x40 + i);
            }
            data.oid_length = 3;
            for (size_t i = 0; i < data.oid_length; ++i) {
                data.oid[i] = static_cast<uint8_t>(0x50 + i);
            }
            data.hash_alg = 0x01;
            data.encr_alg = 0x02;
            client.SeosWriteEmuData(data);
        });
    }
    if (want("seos_write_emu_keys")) {
        run("seos_write_emu_keys", [&] {
            const uint8_t auth[3]     = {0x11, 0x22, 0x33};
            const uint8_t privenc[2]  = {0x44, 0x55};
            const uint8_t privmac[4]  = {0x66, 0x77, 0x88, 0x99};
            client.SeosWriteEmuKeys(auth, sizeof(auth), privenc, sizeof(privenc), privmac, sizeof(privmac));
        });
    }

    return 0;
}
