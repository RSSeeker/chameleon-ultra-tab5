// SPDX-License-Identifier: MIT
//
// Tools page: the operations that do not belong to one card type.
//
// Two panels share the tab, switched by the row of buttons at the top:
//
//   t4t   ISO14443-4 (T=CL) and EMV / SEOS - wave W7. Three roles live here:
//         the emulated T=CL card (set the anti-collision identity, queue the
//         response to the next APDU, add static responses), the reader (send one
//         APDU with HF14A_4_READER_APDU, run the whole EMV sequence), and the
//         SEOS emulator data.
//   raw   HF14A_RAW / HF14A_SNIFF / HF14A_AUTH_TRACE, the LF raw word write,
//         ioProx decoding and the LF sniffer - wave W5.
//
// The sniff and auth-trace answers are decoded with the ported sniff decoder
// (chameleon/sniff_decoder.h) rather than dumped as hex, because the whole point
// of those two commands is the frame boundaries, which a hex dump hides.

#include "pages.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

#include "app_context.h"
#include "sniff_decoder.h"

namespace app {

using namespace chameleon;

namespace {

/// Live instance for the keyboard path.
ToolsPage* s_active = nullptr;

/// Longest hex string this page will accept for one field.
constexpr size_t kMaxHexBytes = 128;

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

void ToolsPage::Create(lv_obj_t* parent)
{
    s_active = this;

    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(_root, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(_root, LV_FLEX_FLOW_COLUMN);
    lv_obj_clear_flag(_root, LV_OBJ_FLAG_SCROLLABLE);

    // ---- mode row ----
    lv_obj_t* modes = lv_obj_create(_root);
    lv_obj_set_size(modes, lv_pct(100), 62);
    lv_obj_set_style_bg_opa(modes, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(modes, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(modes, 0, LV_PART_MAIN);
    lv_obj_clear_flag(modes, LV_OBJ_FLAG_SCROLLABLE);

    _mode_btn[0] = ui::MakeButton(modes, "iso14443-4 / emv / seos", 0, 8, 280, 44, ui::theme::kAccent, on_mode, this);
    lv_obj_set_user_data(_mode_btn[0], (void*)(intptr_t)0);
    _mode_btn[1] = ui::MakeButton(modes, "raw hf / lf", 292, 8, 190, 44, ui::theme::kSurfaceHi, on_mode, this);
    lv_obj_set_user_data(_mode_btn[1], (void*)(intptr_t)1);
    _mode_btn[2] = ui::MakeButton(modes, "system / mf1", 494, 8, 190, 44, ui::theme::kSurfaceHi, on_mode, this);
    lv_obj_set_user_data(_mode_btn[2], (void*)(intptr_t)2);

    _panel[0] = lv_obj_create(_root);
    _panel[1] = lv_obj_create(_root);
    _panel[2] = lv_obj_create(_root);
    for (int i = 0; i < 3; ++i) {
        lv_obj_set_size(_panel[i], lv_pct(100), lv_pct(100));
        lv_obj_set_flex_grow(_panel[i], 1);
        lv_obj_set_style_bg_color(_panel[i], lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
        lv_obj_set_style_border_color(_panel[i], lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
        lv_obj_set_style_radius(_panel[i], 10, LV_PART_MAIN);
        lv_obj_set_style_pad_all(_panel[i], 12, LV_PART_MAIN);
        lv_obj_clear_flag(_panel[i], LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_flag(_panel[i], LV_OBJ_FLAG_HIDDEN);
    }

    create_t4t_panel(_panel[0]);
    create_raw_panel(_panel[1]);
    create_system_panel(_panel[2]);

    _keyboard = lv_keyboard_create(_root);
    lv_obj_set_size(_keyboard, 900, 200);
    lv_obj_align(_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_READY, this);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_CANCEL, this);

    showMode(0);
}

void ToolsPage::Destroy()
{
    if (s_active == this) {
        s_active = nullptr;
    }
    ui::Page::Destroy();
}

void ToolsPage::showMode(int mode)
{
    _mode = mode;
    for (int i = 0; i < 3; ++i) {
        if (_panel[i] == nullptr) {
            continue;
        }
        if (i == mode) {
            lv_obj_clear_flag(_panel[i], LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(_panel[i], LV_OBJ_FLAG_HIDDEN);
        }
        if (_mode_btn[i] != nullptr) {
            lv_obj_set_style_bg_color(_mode_btn[i],
                                      lv_color_hex(i == mode ? ui::theme::kAccent : ui::theme::kSurfaceHi),
                                      LV_PART_MAIN);
        }
    }
}

void ToolsPage::on_mode(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    const int mode = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    self->showMode(mode);
}

// ---------------------------------------------------------------------------
// Panel: ISO14443-4 / EMV / SEOS  (wave W7)
// ---------------------------------------------------------------------------

void ToolsPage::create_t4t_panel(lv_obj_t* panel)
{
    // ---- left column: the emulated T=CL card ----
    lv_obj_t* left = lv_obj_create(panel);
    lv_obj_set_size(left, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(left, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(left, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 0, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "emulated iso14443-4 card (active slot)");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    _t4_uid = ui::MakeField(left, "UID (hex)", 0, 28, 230, 24, on_field_focus, this);
    _t4_atqa = ui::MakeField(left, "ATQA (2 bytes)", 240, 28, 110, 8, on_field_focus, this);
    _t4_sak = ui::MakeField(left, "SAK", 360, 28, 60, 4, on_field_focus, this);
    _t4_ats = ui::MakeField(left, "ATS (hex, may be empty)", 430, 28, 170, 48, on_field_focus, this);
    ui::MakeButton(left, "set anti-coll data", 0, 92, 230, 42, ui::theme::kAccentDim, on_t4_set_anticoll, this);
    ui::MakeButton(left, "scan & keep field", 240, 92, 180, 42, ui::theme::kInfo, on_t4_scan_keep, this);
    ui::MakeButton(left, "read anti-coll data", 430, 92, 170, 42, ui::theme::kSurfaceHi, on_t4_get_anticoll, this);

    _t4_apdu_out = ui::MakeField(left, "APDU to send back to the reader (hex)", 0, 146, 400, 64, on_field_focus, this);
    ui::MakeButton(left, "queue response", 410, 162, 190, 42, ui::theme::kAccentDim, on_t4_apdu_send, this);

    _t4_cmd = ui::MakeField(left, "static response: command prefix (hex)", 0, 218, 280, 32, on_field_focus, this);
    _t4_resp = ui::MakeField(left, "response (hex)", 290, 218, 160, 32, on_field_focus, this);
    ui::MakeButton(left, "add", 460, 234, 70, 42, ui::theme::kAccentDim, on_t4_add_static, this);
    ui::MakeButton(left, "clear table", 540, 234, 60, 42, ui::theme::kError, on_t4_clear_static, this);

    _t4_log = lv_label_create(left);
    lv_label_set_text(_t4_log, "no APDU received yet");
    lv_obj_set_style_text_font(_t4_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_t4_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_t4_log, 600);
    lv_label_set_long_mode(_t4_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_t4_log, LV_ALIGN_TOP_LEFT, 0, 292);

    // ---- right column: reader side + SEOS ----
    lv_obj_t* right = lv_obj_create(panel);
    lv_obj_set_size(right, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(right, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(right, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 0, LV_PART_MAIN);
    lv_obj_align(right, LV_ALIGN_TOP_LEFT, 632, 0);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "reader side / seos");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    _t4_reader_apdu = ui::MakeField(right, "APDU to send to a card (hex)", 0, 28, 380, 64, on_field_focus, this);
    ui::MakeButton(right, "send as reader", 0, 92, 190, 42, ui::theme::kInfo, on_t4_reader_apdu, this);
    ui::MakeButton(right, "read queued APDU", 200, 92, 180, 42, ui::theme::kSurfaceHi, on_t4_apdu_recv, this);
    ui::MakeButton(right, "EMV scan", 390, 92, 180, 42, ui::theme::kAccentDim, on_t4_emv, this);

    _t4_reader_log = lv_label_create(right);
    lv_label_set_text(_t4_reader_log, "no reader exchange yet");
    lv_obj_set_style_text_font(_t4_reader_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_t4_reader_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_t4_reader_log, 600);
    lv_label_set_long_mode(_t4_reader_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_t4_reader_log, LV_ALIGN_TOP_LEFT, 0, 146);

    lv_obj_t* seos_title = lv_label_create(right);
    lv_label_set_text(seos_title, "seos emulator data");
    lv_obj_set_style_text_font(seos_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(seos_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(seos_title, LV_ALIGN_TOP_LEFT, 0, 260);

    _seos_data = ui::MakeField(right, "data (hex)", 0, 288, 250, 64, on_field_focus, this);
    _seos_oid = ui::MakeField(right, "oid (hex)", 260, 288, 160, 32, on_field_focus, this);
    _seos_tag = ui::MakeField(right, "tag (hex)", 430, 288, 170, 32, on_field_focus, this);
    _seos_div = ui::MakeField(right, "diversifier (hex, may be empty)", 0, 348, 250, 64, on_field_focus, this);
    _seos_alg = ui::MakeField(right, "hash alg / encr alg", 260, 348, 160, 12, on_field_focus, this);

    ui::MakeButton(right, "read seos data", 0, 412, 150, 42, ui::theme::kInfo, on_seos_read, this);
    ui::MakeButton(right, "write seos data", 160, 412, 150, 42, ui::theme::kAccentDim, on_seos_write, this);

    // SEOS_WRITE_EMU_KEYS is three fixed 16 byte blobs (app_cmd.c rejects
    // anything else: `if (length != 16 * 3) return STATUS_PAR_ERR`), so the
    // three fields are sized to match instead of being one flexible blob.
    _seos_auth = ui::MakeField(right, "auth key (16 bytes)", 0, 466, 190, 40, on_field_focus, this);
    _seos_privenc = ui::MakeField(right, "priv enc (16 bytes)", 200, 466, 190, 40, on_field_focus, this);
    _seos_privmac = ui::MakeField(right, "priv mac (16 bytes)", 400, 466, 190, 40, on_field_focus, this);
    ui::MakeButton(right, "write seos keys", 0, 530, 150, 42, ui::theme::kAccentDim, on_seos_write_keys, this);

    _seos_log = lv_label_create(right);
    lv_label_set_text(_seos_log, "seos: not read");
    lv_obj_set_style_text_font(_seos_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_seos_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_seos_log, 600);
    lv_label_set_long_mode(_seos_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_seos_log, LV_ALIGN_TOP_LEFT, 0, 580);
}

// ---------------------------------------------------------------------------
// Panel: raw HF / LF  (wave W5)
// ---------------------------------------------------------------------------

void ToolsPage::create_raw_panel(lv_obj_t* panel)
{
    // ---- left: HF14A_RAW ----
    lv_obj_t* left = lv_obj_create(panel);
    lv_obj_set_size(left, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(left, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(left, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 0, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "hf14a_raw");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    // The six option bits of the CLI's ctypes structure. The flag byte is what
    // the device reads, so the buttons are the bitfield, shown as text.
    static const char* kFlagNames[6] = {"activate rf", "wait resp", "append crc", "auto select", "keep field",
                                        "check crc"};
    for (int i = 0; i < 6; ++i) {
        const lv_coord_t x = static_cast<lv_coord_t>((i % 3) * 200);
        const lv_coord_t y = static_cast<lv_coord_t>(28 + (i / 3) * 46);
        _raw_flag[i]      = ui::MakeButton(left, kFlagNames[i], x, y, 190, 38, ui::theme::kSurfaceHi, on_raw_flag,
                                           this);
        lv_obj_set_user_data(_raw_flag[i], (void*)(intptr_t)i);
    }
    _raw_flags = 0x07;  // activate rf + wait response + append crc, the CLI default

    _raw_data = ui::MakeField(left, "data (hex)", 0, 128, 400, 64, on_field_focus, this);
    _raw_timeout = ui::MakeField(left, "response timeout (ms)", 410, 128, 100, 8, on_field_focus, this);
    _raw_bitlen = ui::MakeField(left, "bit length (0 = all)", 520, 128, 90, 8, on_field_focus, this);
    ui::MakeButton(left, "send raw", 0, 192, 150, 42, ui::theme::kInfo, on_raw_send, this);

    _raw_log = lv_label_create(left);
    lv_label_set_text(_raw_log, "raw: nothing sent yet");
    lv_obj_set_style_text_font(_raw_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_raw_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_raw_log, 600);
    lv_label_set_long_mode(_raw_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_raw_log, LV_ALIGN_TOP_LEFT, 0, 244);

    lv_obj_t* trace_title = lv_label_create(left);
    lv_label_set_text(trace_title, "sniff / auth trace");
    lv_obj_set_style_text_font(trace_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(trace_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(trace_title, LV_ALIGN_TOP_LEFT, 0, 320);

    _trace_timeout = ui::MakeField(left, "window (ms)", 0, 348, 100, 8, on_field_focus, this);
    _trace_block = ui::MakeField(left, "block", 110, 348, 60, 4, on_field_focus, this);
    _trace_key = ui::MakeField(left, "key (hex, 6 bytes)", 180, 348, 200, 16, on_field_focus, this);
    ui::MakeButton(left, "sniff", 0, 412, 130, 42, ui::theme::kInfo, on_trace_sniff, this);
    ui::MakeButton(left, "auth trace", 140, 412, 130, 42, ui::theme::kAccentDim, on_trace_auth, this);

    _trace_log = lv_label_create(left);
    lv_label_set_text(_trace_log, "trace: nothing captured yet");
    lv_obj_set_style_text_font(_trace_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_trace_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_trace_log, 600);
    lv_label_set_long_mode(_trace_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_trace_log, LV_ALIGN_TOP_LEFT, 0, 464);

    // mfkey32: the one recovery that needs no card and no known key, but it does
    // need a trace from a reader using an *unknown* key, which this device cannot
    // produce (docs/M5-KEY-RECOVERY.md section 5). The wiring is here so a trace
    // from a PC sniffer can be cracked on the Tab5.
    _mfk_uid = ui::MakeField(left, "uid for mfkey32 (8 hex digits)", 0, 530, 180, 8, on_field_focus, this);
    ui::MakeButton(left, "mfkey32 crack last trace", 190, 546, 230, 42, ui::theme::kAccentDim, on_mfkey32, this);

    // ---- right: LF raw operations ----
    lv_obj_t* right = lv_obj_create(panel);
    lv_obj_set_size(right, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(right, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(right, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 0, LV_PART_MAIN);
    lv_obj_align(right, LV_ALIGN_TOP_LEFT, 632, 0);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "lf raw word / ioprox / lf sniff");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    _t55_block = ui::MakeField(right, "block", 0, 28, 70, 4, on_field_focus, this);
    _t55_word = ui::MakeField(right, "word (4 bytes hex)", 80, 28, 140, 12, on_field_focus, this);
    _t55_pwd = ui::MakeField(right, "password (4 bytes hex)", 230, 28, 140, 12, on_field_focus, this);
    _t55_usepwd = ui::MakeButton(right, "use password: off", 380, 44, 180, 38, ui::theme::kSurfaceHi, on_t55_toggle_pwd,
                                 this);
    _t55_page1 = ui::MakeButton(right, "page 1: off", 380, 86, 180, 38, ui::theme::kSurfaceHi, on_t55_toggle_page,
                                this);
    ui::MakeButton(right, "write word", 0, 92, 150, 42, ui::theme::kError, on_t55_write, this);

    lv_obj_t* ioprox_title = lv_label_create(right);
    lv_label_set_text(ioprox_title, "ioprox");
    lv_obj_set_style_text_font(ioprox_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(ioprox_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(ioprox_title, LV_ALIGN_TOP_LEFT, 0, 150);

    _ioprox_raw = ui::MakeField(right, "raw 8 bytes (hex)", 0, 178, 240, 20, on_field_focus, this);
    ui::MakeButton(right, "decode raw", 250, 194, 140, 42, ui::theme::kInfo, on_ioprox_decode, this);
    _ioprox_ver = ui::MakeField(right, "ver", 0, 238, 60, 4, on_field_focus, this);
    _ioprox_fc = ui::MakeField(right, "fc", 70, 238, 60, 4, on_field_focus, this);
    _ioprox_cn = ui::MakeField(right, "cn", 140, 238, 90, 6, on_field_focus, this);
    ui::MakeButton(right, "compose id", 250, 254, 140, 42, ui::theme::kAccentDim, on_ioprox_compose, this);

    _ioprox_log = lv_label_create(right);
    lv_label_set_text(_ioprox_log, "ioprox: no result yet");
    lv_obj_set_style_text_font(_ioprox_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_ioprox_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_ioprox_log, 600);
    lv_label_set_long_mode(_ioprox_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_ioprox_log, LV_ALIGN_TOP_LEFT, 0, 306);

    _lf_timeout = ui::MakeField(right, "lf sniff window (ms)", 0, 366, 120, 8, on_field_focus, this);
    ui::MakeButton(right, "lf sniff", 130, 382, 130, 42, ui::theme::kInfo, on_lf_sniff, this);

    _lf_log = lv_label_create(right);
    lv_label_set_text(_lf_log, "lf sniff: nothing captured yet");
    lv_obj_set_style_text_font(_lf_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_lf_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_lf_log, 600);
    lv_label_set_long_mode(_lf_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_lf_log, LV_ALIGN_TOP_LEFT, 0, 434);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void ToolsPage::on_field_focus(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_keyboard_set_textarea(self->_keyboard, lv_event_get_target_obj(e));
    lv_obj_clear_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
}

void ToolsPage::on_keyboard_event(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_obj_add_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
    if (lv_event_get_code(e) == LV_EVENT_READY) {
        lv_obj_t* area = lv_keyboard_get_textarea(self->_keyboard);
        if (area != nullptr) {
            lv_obj_clear_state(area, LV_STATE_FOCUSED);
        }
    }
}

size_t ToolsPage::field_bytes(lv_obj_t* field, uint8_t* out, size_t out_size) const
{
    return ui::ParseHex(lv_textarea_get_text(field), out, out_size);
}

unsigned ToolsPage::field_uint(lv_obj_t* field, unsigned fallback, unsigned max) const
{
    if (field == nullptr) {
        return fallback;
    }
    const char* text = lv_textarea_get_text(field);
    if (text == nullptr || *text == '\0') {
        return fallback;
    }
    char* end          = nullptr;
    const unsigned long value = strtoul(text, &end, 0);
    if (end == text || value > max) {
        return fallback;
    }
    return static_cast<unsigned>(value);
}

// ---------------------------------------------------------------------------
// ISO14443-4 / EMV handlers
// ---------------------------------------------------------------------------

void ToolsPage::on_t4_set_anticoll(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t uid[10];
    uint8_t atqa[2];
    uint8_t sak[4];
    uint8_t ats[48];
    const size_t uid_len = self->field_bytes(self->_t4_uid, uid, sizeof(uid));
    const size_t atqa_len = self->field_bytes(self->_t4_atqa, atqa, sizeof(atqa));
    const size_t sak_len = self->field_bytes(self->_t4_sak, sak, sizeof(sak));
    const size_t ats_len = self->field_bytes(self->_t4_ats, ats, sizeof(ats));

    if (uid_len != 4 && uid_len != 7 && uid_len != 10) {
        lv_label_set_text(self->_t4_log, "the UID must be 4, 7 or 10 bytes");
        return;
    }
    if (atqa_len != 2 || sak_len < 1) {
        lv_label_set_text(self->_t4_log, "ATQA must be 2 bytes and SAK at least 1 byte");
        return;
    }
    if (!self->_ctx.client().Hf14a4SetAntiColl(uid, static_cast<uint8_t>(uid_len), atqa, sak[0], ats,
                                               static_cast<uint8_t>(ats_len))) {
        lv_label_set_text(self->_t4_log, "HF14A_4_SET_ANTI_COLL rejected");
        self->_ctx.LogEvent("HF14A_4_SET_ANTI_COLL failed");
        return;
    }
    char text[192];
    size_t at = 0;
    for (size_t i = 0; i < uid_len && at + 4 < sizeof(text); ++i) {
        const int r = snprintf(text + at, sizeof(text) - at, "%02X", uid[i]);
        at += static_cast<size_t>(r);
    }
    lv_label_set_text_fmt(self->_t4_log, "T=CL identity set: UID %s, SAK %02X, ATS %u byte(s)", text,
                          (unsigned)sak[0], (unsigned)ats_len);
    self->_ctx.LogEvent("t4t anti-coll set: uid %s sak %02X ats %u", text, (unsigned)sak[0], (unsigned)ats_len);
}

void ToolsPage::on_t4_get_anticoll(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    HfTag tag{};
    const uint16_t status = self->_ctx.client().GetHfAntiColl(&tag);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_t4_log, "read anti-coll failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[32];
    ui::FormatHex(tag.uid, tag.uid_length, hex, sizeof(hex), "");
    lv_label_set_text_fmt(self->_t4_log, "device reports UID %s, ATQA %02X%02X, SAK %02X, ATS %u byte(s)", hex,
                          tag.atqa[0], tag.atqa[1], tag.sak, (unsigned)tag.ats_length);
}

void ToolsPage::on_t4_scan_keep(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    HfTag tag{};
    size_t count         = 0;
    const uint16_t status = self->_ctx.client().Hf14aScanKeep(&tag, 1, &count);
    if (status != HF_TAG_OK || count == 0) {
        lv_label_set_text_fmt(self->_t4_log, "scan & keep found nothing: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[32];
    ui::FormatHex(tag.uid, tag.uid_length, hex, sizeof(hex), "");
    lv_label_set_text_fmt(self->_t4_log, "field kept: UID %s, SAK %02X, %u byte ATS", hex, tag.sak,
                          (unsigned)tag.ats_length);
    self->_ctx.LogEvent("t4t scan keep: uid %s", hex);
}

void ToolsPage::on_t4_apdu_send(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t response[kMaxHexBytes];
    const size_t length = self->field_bytes(self->_t4_apdu_out, response, sizeof(response));
    if (length == 0) {
        lv_label_set_text(self->_t4_log, "enter the APDU response to queue");
        return;
    }
    if (!self->_ctx.client().Hf14a4ApduSend(response, length)) {
        lv_label_set_text(self->_t4_log, "HF14A_4_APDU_SEND failed");
        return;
    }
    lv_label_set_text_fmt(self->_t4_log, "queued %u byte response for the next APDU", (unsigned)length);
    self->_ctx.LogEvent("t4t queued %u byte APDU response", (unsigned)length);
}

void ToolsPage::on_t4_apdu_recv(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t apdu[128];
    size_t length         = 0;
    const uint16_t status = self->_ctx.client().Hf14a4ApduRecv(apdu, sizeof(apdu), &length);
    if (status != SUCCESS || length == 0) {
        lv_label_set_text_fmt(self->_t4_reader_log, "no APDU queued by the reader (%s)", StatusText(status));
        return;
    }
    char hex[272];
    ui::FormatHex(apdu, length, hex, sizeof(hex), " ");
    lv_label_set_text_fmt(self->_t4_reader_log, "reader sent %u byte(s):\n%s", (unsigned)length, hex);
    self->_ctx.LogEvent("t4t reader APDU: %s", hex);
}

void ToolsPage::on_t4_add_static(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t command[32];
    uint8_t response[64];
    const size_t command_length = self->field_bytes(self->_t4_cmd, command, sizeof(command));
    const size_t response_length = self->field_bytes(self->_t4_resp, response, sizeof(response));
    if (command_length == 0 || response_length == 0) {
        lv_label_set_text(self->_t4_log, "a static response needs both a command prefix and a response");
        return;
    }
    if (!self->_ctx.client().Hf14a4AddStaticResponse(command, command_length, response, response_length)) {
        lv_label_set_text(self->_t4_log, "HF14A_4_STATIC_RESP failed");
        return;
    }
    char cmd_hex[96];
    ui::FormatHex(command, command_length, cmd_hex, sizeof(cmd_hex), " ");
    lv_label_set_text_fmt(self->_t4_log, "static response added for %s", cmd_hex);
    self->_ctx.LogEvent("t4t static response for %s", cmd_hex);
}

void ToolsPage::on_t4_clear_static(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    if (self->_ctx.client().Hf14a4ClearStaticResponses()) {
        lv_label_set_text(self->_t4_log, "static response table cleared");
        self->_ctx.LogEvent("t4t static response table cleared");
    } else {
        lv_label_set_text(self->_t4_log, "clearing the static responses failed");
    }
}

void ToolsPage::on_t4_reader_apdu(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t apdu[64];
    const size_t length = self->field_bytes(self->_t4_reader_apdu, apdu, sizeof(apdu));
    if (length == 0) {
        lv_label_set_text(self->_t4_reader_log, "enter the APDU to send");
        return;
    }
    uint8_t response[256];
    size_t response_length = 0;
    const uint16_t status =
        self->_ctx.client().Hf14a4ReaderApdu(apdu, length, response, sizeof(response), &response_length);
    if (status != HF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_t4_reader_log, "reader APDU failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    if (response_length == 0) {
        lv_label_set_text(self->_t4_reader_log, "the card answered with nothing");
        return;
    }
    char hex[544];
    ui::FormatHex(response, response_length, hex, sizeof(hex), " ");
    lv_label_set_text_fmt(self->_t4_reader_log, "response %u byte(s):\n%s", (unsigned)response_length, hex);
    self->_ctx.LogEvent("t4t reader APDU response: %s", hex);
}

void ToolsPage::on_t4_emv(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    static Client::EmvScanResult result;  // ~5 KB: static, not on this task's stack
    const uint16_t status = self->_ctx.client().Hf14a4EmvScan(&result);
    if (status != HF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_t4_reader_log, "EMV scan failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("HF14A_4_EMV_SCAN failed: %s (0x%02X)", StatusText(status), status);
        return;
    }

    char uid_hex[32];
    ui::FormatHex(result.tag.uid, result.tag.uid_length, uid_hex, sizeof(uid_hex), "");
    char text[512];
    size_t at = snprintf(text, sizeof(text), "EMV: UID %s, SAK %02X, %u exchange(s)\n", uid_hex,
                         result.tag.sak, (unsigned)result.apdu_count);
    // Show the last few exchanges: the SELECT AID and GPO answers are the ones a
    // user is looking for, and the label cannot hold the whole dialog.
    const size_t first = (result.apdu_count > 4) ? result.apdu_count - 4 : 0;
    for (size_t i = first; i < result.apdu_count && at + 96 < sizeof(text); ++i) {
        char cmd[40];
        char resp[72];
        ui::FormatHex(result.apdus[i].command, result.apdus[i].command_length, cmd, sizeof(cmd), "");
        ui::FormatHex(result.apdus[i].response, result.apdus[i].response_length, resp, sizeof(resp), "");
        const int r = snprintf(text + at, sizeof(text) - at, "%s -> %s\n", cmd, resp);
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(r);
    }
    lv_label_set_text(self->_t4_reader_log, text);
    self->_ctx.LogEvent("EMV scan: uid %s, %u exchanges", uid_hex, (unsigned)result.apdu_count);
}

void ToolsPage::on_seos_read(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    Client::SeosEmuData data{};
    const uint16_t status = self->_ctx.client().SeosReadEmuData(&data);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_seos_log, "read seos data failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char data_hex[136];
    char oid_hex[72];
    ui::FormatHex(data.data, data.data_length, data_hex, sizeof(data_hex), "");
    ui::FormatHex(data.oid, data.oid_length, oid_hex, sizeof(oid_hex), "");
    lv_label_set_text_fmt(self->_seos_log, "data %u B: %s\noid %u B: %s\nhash %u encr %u", (unsigned)data.data_length,
                          data_hex, (unsigned)data.oid_length, oid_hex, (unsigned)data.hash_alg,
                          (unsigned)data.encr_alg);

    // Fill the writable fields with what came back, so a round trip is one press.
    ui::FormatHex(data.data, data.data_length, data_hex, sizeof(data_hex), "");
    lv_textarea_set_text(self->_seos_data, data_hex);
    ui::FormatHex(data.oid, data.oid_length, oid_hex, sizeof(oid_hex), "");
    lv_textarea_set_text(self->_seos_oid, oid_hex);
    // LVGL 9 has no lv_textarea_set_text_fmt(), so format into a buffer first.
    char alg_text[16];
    snprintf(alg_text, sizeof(alg_text), "%u/%u", (unsigned)data.hash_alg, (unsigned)data.encr_alg);
    lv_textarea_set_text(self->_seos_alg, alg_text);
    self->_ctx.LogEvent("seos read: data %u B, oid %u B, tag %u B, div %u B", (unsigned)data.data_length,
                        (unsigned)data.oid_length, (unsigned)data.tag_length,
                        (unsigned)data.diversifier_length);
}

void ToolsPage::on_seos_write(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    Client::SeosEmuData data{};
    data.data_length = static_cast<uint8_t>(self->field_bytes(self->_seos_data, data.data, sizeof(data.data)));
    data.oid_length  = static_cast<uint8_t>(self->field_bytes(self->_seos_oid, data.oid, sizeof(data.oid)));
    data.tag_length  = static_cast<uint8_t>(self->field_bytes(self->_seos_tag, data.tag, sizeof(data.tag)));
    data.diversifier_length =
        static_cast<uint8_t>(self->field_bytes(self->_seos_div, data.diversifier, sizeof(data.diversifier)));

    // "hash/encr" is one field with the two algorithm ids separated by a slash.
    const char* alg = lv_textarea_get_text(self->_seos_alg);
    unsigned hash_alg = 0;
    unsigned encr_alg = 0;
    if (alg != nullptr && *alg != '\0') {
        if (sscanf(alg, "%u/%u", &hash_alg, &encr_alg) != 2) {
            if (sscanf(alg, "%u", &hash_alg) != 1) {
                lv_label_set_text(self->_seos_log, "hash/encr must look like 1/2");
                return;
            }
        }
    }
    data.hash_alg = static_cast<uint8_t>(hash_alg);
    data.encr_alg = static_cast<uint8_t>(encr_alg);

    const uint16_t status = self->_ctx.client().SeosWriteEmuData(data);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_seos_log, "write seos data failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("SEOS_WRITE_EMU_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    lv_label_set_text_fmt(self->_seos_log, "seos data written (data %u B, oid %u B, tag %u B, div %u B)",
                          (unsigned)data.data_length, (unsigned)data.oid_length, (unsigned)data.tag_length,
                          (unsigned)data.diversifier_length);
    self->_ctx.LogEvent("seos data written: hash %u encr %u", (unsigned)data.hash_alg, (unsigned)data.encr_alg);
}

void ToolsPage::on_seos_write_keys(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    // Exactly 16 bytes each: app_cmd.c cmd_processor_seos_write_emu_keys rejects
    // any other length outright (`if (length != 16 * 3) PAR_ERR`).
    uint8_t auth[16];
    uint8_t privenc[16];
    uint8_t privmac[16];
    if (self->field_bytes(self->_seos_auth, auth, sizeof(auth)) != sizeof(auth) ||
        self->field_bytes(self->_seos_privenc, privenc, sizeof(privenc)) != sizeof(privenc) ||
        self->field_bytes(self->_seos_privmac, privmac, sizeof(privmac)) != sizeof(privmac)) {
        lv_label_set_text(self->_seos_log, "each SEOS key blob is exactly 16 bytes (32 hex digits)");
        return;
    }

    const uint16_t status = self->_ctx.client().SeosWriteEmuKeys(auth, sizeof(auth), privenc, sizeof(privenc),
                                                                 privmac, sizeof(privmac));
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_seos_log, "write seos keys failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("SEOS_WRITE_EMU_KEYS failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    lv_label_set_text(self->_seos_log, "seos keys written (auth / priv enc / priv mac, 16 bytes each)");
    self->_ctx.LogEvent("seos keys written (48 bytes)");
}

// ---------------------------------------------------------------------------
// Raw HF handlers
// ---------------------------------------------------------------------------

void ToolsPage::on_raw_flag(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    const int bit = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    self->_raw_flags ^= static_cast<uint8_t>(1u << bit);
    for (int i = 0; i < 6; ++i) {
        static const char* kNames[6] = {"activate rf", "wait resp", "append crc", "auto select", "keep field",
                                        "check crc"};
        char text[40];
        snprintf(text, sizeof(text), "%s: %s", kNames[i], (self->_raw_flags & (1u << i)) ? "on" : "off");
        ui::SetButtonText(self->_raw_flag[i], text);
        lv_obj_set_style_bg_color(self->_raw_flag[i],
                                  lv_color_hex((self->_raw_flags & (1u << i)) ? ui::theme::kAccentDim
                                                                             : ui::theme::kSurfaceHi),
                                  LV_PART_MAIN);
    }
}

void ToolsPage::on_raw_send(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t data[kMaxHexBytes];
    const size_t length = self->field_bytes(self->_raw_data, data, sizeof(data));
    if (length == 0) {
        lv_label_set_text(self->_raw_log, "enter the bytes to send");
        return;
    }

    Client::Hf14aRawOptions options;
    options.activate_rf_field  = (self->_raw_flags & 0x01) != 0;
    options.wait_response      = (self->_raw_flags & 0x02) != 0;
    options.append_crc         = (self->_raw_flags & 0x04) != 0;
    options.auto_select        = (self->_raw_flags & 0x08) != 0;
    options.keep_rf_field      = (self->_raw_flags & 0x10) != 0;
    options.check_response_crc = (self->_raw_flags & 0x20) != 0;

    const unsigned timeout = self->field_uint(self->_raw_timeout, 500, 65535);
    const unsigned bitlen  = self->field_uint(self->_raw_bitlen, 0, 65535);

    uint8_t response[256];
    size_t response_length = 0;
    const uint16_t status = self->_ctx.client().Hf14aRaw(options, static_cast<uint16_t>(timeout),
                                                         static_cast<uint16_t>(bitlen), data, length, response,
                                                         sizeof(response), &response_length);
    if (status != HF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_raw_log, "HF14A_RAW failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("HF14A_RAW failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    if (response_length == 0) {
        lv_label_set_text_fmt(self->_raw_log, "sent %u byte(s), the card did not answer", (unsigned)length);
        return;
    }
    char hex[544];
    ui::FormatHex(response, response_length, hex, sizeof(hex), " ");
    lv_label_set_text_fmt(self->_raw_log, "answer %u byte(s):\n%s", (unsigned)response_length, hex);
    self->_ctx.LogEvent("HF14A_RAW answer: %s", hex);
}

void ToolsPage::on_trace_sniff(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned window = self->field_uint(self->_trace_timeout, 3000, 60000);
    uint8_t buffer[1024];
    size_t length         = 0;
    const uint16_t status = self->_ctx.client().Hf14aSniff(static_cast<uint16_t>(window), buffer, sizeof(buffer),
                                                           &length);
    if (status != HF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_trace_log, "sniff failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    self->show_trace(buffer, length, "sniff");
}

void ToolsPage::on_trace_auth(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t key[6];
    if (self->field_bytes(self->_trace_key, key, sizeof(key)) != sizeof(key)) {
        lv_label_set_text(self->_trace_log, "the key must be 6 bytes (12 hex digits)");
        return;
    }
    const unsigned block = self->field_uint(self->_trace_block, 3, 255);
    const unsigned window = self->field_uint(self->_trace_timeout, 3000, 60000);

    uint8_t buffer[1024];
    size_t length = 0;
    const uint16_t status = self->_ctx.client().Hf14aAuthTrace(static_cast<uint8_t>(block), MfcKeyType::A, key,
                                                               static_cast<uint16_t>(window), buffer, sizeof(buffer),
                                                               &length);
    if (status != HF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_trace_log, "auth trace failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("HF14A_AUTH_TRACE failed: %s (0x%02X)", StatusText(status), status);
        return;
    }

    // An auth trace exists to hand out (nt, nr_enc, ar_enc); show those first,
    // and mark an incomplete authentication instead of reporting unusable data.
    TraceAuth auths[4];
    const size_t count = DecodeTraceAuths(buffer, length, auths, 4);
    char text[512];
    size_t at = snprintf(text, sizeof(text), "auth trace (%zu authentication(s)):\n", count);
    for (size_t i = 0; i < count && at + 96 < sizeof(text); ++i) {
        const int r = snprintf(text + at, sizeof(text) - at, "blk %u key %02X nt %08X nr_enc %08X ar_enc %08X%s\n",
                               (unsigned)auths[i].block, (unsigned)auths[i].key_type, (unsigned)auths[i].nt,
                               (unsigned)auths[i].nr_enc, (unsigned)auths[i].ar_enc,
                               auths[i].complete ? "" : " (incomplete)");
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(r);
    }
    lv_label_set_text(self->_trace_log, text);
    self->show_trace(buffer, length, "auth");
    self->_ctx.LogEvent("auth trace: %u frame(s), %u authentication(s)", (unsigned)length, (unsigned)count);
}

void ToolsPage::show_trace(const uint8_t* buffer, size_t length, const char* what)
{
    // Keep the buffer: the mfkey32 button cracks the most recent trace.
    const size_t keep = (length <= sizeof(_trace_buffer)) ? length : sizeof(_trace_buffer);
    memcpy(_trace_buffer, buffer, keep);
    _trace_length = keep;

    TraceFrame frames[32];
    const size_t count = DecodeTraceFrames(buffer, length, frames, 32);

    char text[512];
    size_t at = snprintf(text, sizeof(text), "%s: %zu frame(s)\n", what, count);
    for (size_t i = 0; i < count && at + 40 < sizeof(text); ++i) {
        char hex[80];
        // A frame is at most 16 bytes here; the decoder reports bit lengths that
        // need not be byte aligned, which is exactly why a hex dump is not enough.
        const size_t shown = (frames[i].byte_length <= 16) ? frames[i].byte_length : 16;
        ui::FormatHex(frames[i].data, shown, hex, sizeof(hex), "");
        const int r = snprintf(text + at, sizeof(text) - at, "%s %u bit: %s%s\n", frames[i].from_card ? "card>" : "rdr>",
                               (unsigned)frames[i].bit_length, hex,
                               frames[i].byte_length > shown ? " .." : "");
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(r);
    }
    // Keep the sniff/trace detail in the Log tab (which scrolls) and the summary
    // on the page.
    lv_label_set_text(_trace_log, text);
    for (size_t i = 0; i < count; ++i) {
        char hex[80];
        const size_t shown = (frames[i].byte_length <= 16) ? frames[i].byte_length : 16;
        ui::FormatHex(frames[i].data, shown, hex, sizeof(hex), "");
        _ctx.LogEvent("trace %s %u bit: %s", frames[i].from_card ? "card>" : "rdr>",
                      (unsigned)frames[i].bit_length, hex);
    }
}

// ---------------------------------------------------------------------------
// mfkey32
// ---------------------------------------------------------------------------

void ToolsPage::on_mfkey32(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    if (self->_trace_length == 0) {
        lv_label_set_text(self->_trace_log, "capture a sniff or an auth trace first");
        return;
    }
    uint8_t uid_bytes[4];
    if (self->field_bytes(self->_mfk_uid, uid_bytes, sizeof(uid_bytes)) != sizeof(uid_bytes)) {
        lv_label_set_text(self->_trace_log, "mfkey32 needs the card UID: exactly 4 bytes (8 hex digits)");
        return;
    }
    const uint32_t uid = (static_cast<uint32_t>(uid_bytes[0]) << 24) | (static_cast<uint32_t>(uid_bytes[1]) << 16) |
                         (static_cast<uint32_t>(uid_bytes[2]) << 8) | uid_bytes[3];

    // mfkey32 needs two *complete* authentications. The decoder marks a partial
    // one explicitly (a card that rejected the key), so an unusable trace says so
    // instead of looking like a search that found nothing.
    TraceAuth auths[8];
    const size_t count = DecodeTraceAuths(self->_trace_buffer, self->_trace_length, auths, 8);
    size_t usable      = 0;
    chameleon::crypto::AuthTrace pair[2];
    for (size_t i = 0; i < count && usable < 2; ++i) {
        if (!auths[i].complete) {
            continue;
        }
        pair[usable].nt = auths[i].nt;
        pair[usable].nr = auths[i].nr_enc;
        pair[usable].ar = auths[i].ar_enc;
        ++usable;
    }
    if (usable < 2) {
        lv_label_set_text_fmt(self->_trace_log,
                              "mfkey32 needs two complete authentications, this trace has %zu (%zu usable).\n"
                              "This device cannot record a solvable pair: it emulates the card, so the reader's\n"
                              "responses are its own - see docs/M5-KEY-RECOVERY.md section 5.",
                              count, usable);
        self->_ctx.LogEvent("mfkey32: trace has %zu authentication(s), %zu usable", count, usable);
        return;
    }

    if (!self->_ctx.StartMfkey32(uid, pair[0], pair[1])) {
        lv_label_set_text(self->_trace_log, "mfkey32 not started (another key job is running)");
        return;
    }
    lv_label_set_text(self->_trace_log, "mfkey32 running on the key task (needs ~18 MB of PSRAM)...");
    self->_ctx.LogEvent("mfkey32 started: uid %08X, two complete authentications", (unsigned)uid);
}

void ToolsPage::on_t55_toggle_pwd(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_t55_use_pwd = !self->_t55_use_pwd;
    ui::SetButtonText(self->_t55_usepwd, self->_t55_use_pwd ? "use password: on" : "use password: off");
    lv_obj_set_style_bg_color(self->_t55_usepwd,
                              lv_color_hex(self->_t55_use_pwd ? ui::theme::kAccentDim : ui::theme::kSurfaceHi),
                              LV_PART_MAIN);
}

void ToolsPage::on_t55_toggle_page(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_t55_page1_on = !self->_t55_page1_on;
    ui::SetButtonText(self->_t55_page1, self->_t55_page1_on ? "page 1: on" : "page 1: off");
    lv_obj_set_style_bg_color(self->_t55_page1,
                              lv_color_hex(self->_t55_page1_on ? ui::theme::kAccentDim : ui::theme::kSurfaceHi),
                              LV_PART_MAIN);
}

void ToolsPage::on_t55_write(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t word[4];
    uint8_t pwd[4] = {0, 0, 0, 0};
    if (self->field_bytes(self->_t55_word, word, sizeof(word)) != sizeof(word)) {
        lv_label_set_text(self->_ioprox_log, "the T55xx word is exactly 4 bytes (8 hex digits)");
        return;
    }
    if (self->_t55_use_pwd && self->field_bytes(self->_t55_pwd, pwd, sizeof(pwd)) != sizeof(pwd)) {
        lv_label_set_text(self->_ioprox_log, "with a password you need exactly 4 bytes (8 hex digits)");
        return;
    }
    const unsigned block = self->field_uint(self->_t55_block, 0, 7);
    const uint32_t value = (static_cast<uint32_t>(word[0]) << 24) | (static_cast<uint32_t>(word[1]) << 16) |
                           (static_cast<uint32_t>(word[2]) << 8) | word[3];
    const uint32_t password = (static_cast<uint32_t>(pwd[0]) << 24) | (static_cast<uint32_t>(pwd[1]) << 16) |
                              (static_cast<uint32_t>(pwd[2]) << 8) | pwd[3];

    const uint16_t status = self->_ctx.client().T55xxWriteBlock(static_cast<uint8_t>(block), value,
                                                                self->_t55_use_pwd, password, self->_t55_page1_on);
    lv_label_set_text_fmt(self->_ioprox_log, "T55xx block %u <- %08X: %s", (unsigned)block, (unsigned)value,
                          StatusText(status));
    self->_ctx.LogEvent("LF_T55XX_WRITE block %u = %08X (%s, pwd %s)", (unsigned)block, (unsigned)value,
                        StatusText(status), self->_t55_use_pwd ? "used" : "not used");
}

void ToolsPage::on_ioprox_decode(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t raw[8];
    if (self->field_bytes(self->_ioprox_raw, raw, sizeof(raw)) != sizeof(raw)) {
        lv_label_set_text(self->_ioprox_log, "ioProx raw is exactly 8 bytes (16 hex digits)");
        return;
    }
    uint8_t out[16] = {};
    const uint16_t status = self->_ctx.client().IoProxDecodeRaw(raw, out);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_ioprox_log, "IOPROX_DECODE_RAW failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[40];
    ui::FormatHex(out, sizeof(out), hex, sizeof(hex), "");
    lv_label_set_text_fmt(self->_ioprox_log, "decoded card_data (%u bytes):\n%s", (unsigned)sizeof(out), hex);
    self->_ctx.LogEvent("ioProx decode raw -> %s", hex);
}

void ToolsPage::on_ioprox_compose(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned version  = self->field_uint(self->_ioprox_ver, 0, 255);
    const unsigned facility = self->field_uint(self->_ioprox_fc, 0, 255);
    const unsigned number   = self->field_uint(self->_ioprox_cn, 0, 65535);

    uint8_t out[16] = {};
    const uint16_t status = self->_ctx.client().IoProxComposeId(static_cast<uint8_t>(version),
                                                                static_cast<uint8_t>(facility),
                                                                static_cast<uint16_t>(number), out);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_ioprox_log, "IOPROX_COMPOSE_ID failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[40];
    ui::FormatHex(out, sizeof(out), hex, sizeof(hex), "");
    lv_label_set_text_fmt(self->_ioprox_log, "composed card_data (%u bytes):\n%s", (unsigned)sizeof(out), hex);
    self->_ctx.LogEvent("ioProx compose v%u fc%u cn%u -> %s", version, facility, number, hex);
}

void ToolsPage::on_lf_sniff(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned window = self->field_uint(self->_lf_timeout, 2000, 60000);
    uint8_t buffer[512];
    size_t length         = 0;
    const uint16_t status = self->_ctx.client().LfSniff(static_cast<uint16_t>(window), buffer, sizeof(buffer),
                                                        &length);
    if (status != LF_TAG_OK && status != SUCCESS) {
        lv_label_set_text_fmt(self->_lf_log, "LF_SNIFF failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[320];
    ui::FormatHex(buffer, length, hex, sizeof(hex), " ");
    lv_label_set_text_fmt(self->_lf_log, "%u byte(s) of LF samples:\n%s", (unsigned)length, hex);
    self->_ctx.LogEvent("LF_SNIFF returned %u byte(s)", (unsigned)length);
}

// ---------------------------------------------------------------------------
// Panel: system / MF1  (waves W4 and W6)
// ---------------------------------------------------------------------------

void ToolsPage::create_system_panel(lv_obj_t* panel)
{
    // ---- left: device settings and slot data ----
    lv_obj_t* left = lv_obj_create(panel);
    lv_obj_set_size(left, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(left, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(left, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 0, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "hf14a config / slot data / buttons");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    // HF14A_GET/SET_CONFIG: four signed bytes, so the fields accept -1.
    _sys_bcc  = ui::MakeField(left, "bcc", 0, 28, 60, 4, on_field_focus, this);
    _sys_cl2  = ui::MakeField(left, "cl2", 70, 28, 60, 4, on_field_focus, this);
    _sys_cl3  = ui::MakeField(left, "cl3", 140, 28, 60, 4, on_field_focus, this);
    _sys_rats = ui::MakeField(left, "rats", 210, 28, 60, 4, on_field_focus, this);
    ui::MakeButton(left, "read hf14a config", 280, 44, 180, 40, ui::theme::kInfo, on_hf14a_config_read, this);
    ui::MakeButton(left, "write hf14a config", 470, 44, 140, 40, ui::theme::kError, on_hf14a_config_write, this);

    lv_obj_t* slot_title = lv_label_create(left);
    lv_label_set_text(slot_title, "slot data");
    lv_obj_set_style_text_font(slot_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(slot_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(slot_title, LV_ALIGN_TOP_LEFT, 0, 100);

    // Slot numbers are shown 1 based and converted: the client takes the
    // firmware value, exactly like SlotNumber.to_fw() does upstream.
    _sys_slot = ui::MakeField(left, "slot (1-8)", 0, 128, 90, 4, on_field_focus, this);
    _sys_sense_btn = ui::MakeButton(left, "sense: hf", 100, 144, 130, 40, ui::theme::kSurfaceHi, on_sys_sense, this);
    ui::MakeButton(left, "enable", 240, 144, 100, 40, ui::theme::kInfo, on_sys_set_enabled, this);
    ui::MakeButton(left, "read active nick", 350, 144, 180, 40, ui::theme::kInfo, on_sys_read_nick, this);
    ui::MakeButton(left, "set data default", 0, 194, 170, 40, ui::theme::kAccentDim, on_sys_set_data_default, this);
    ui::MakeButton(left, "save slot data", 180, 194, 160, 40, ui::theme::kAccentDim, on_sys_save_slot_data, this);
    ui::MakeButton(left, "delete nick", 350, 194, 140, 40, ui::theme::kError, on_sys_delete_nick, this);
    ui::MakeButton(left, "delete sense", 0, 244, 170, 40, ui::theme::kError, on_sys_delete_sense, this);

    lv_obj_t* btn_title = lv_label_create(left);
    lv_label_set_text(btn_title, "button functions");
    lv_obj_set_style_text_font(btn_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(btn_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(btn_title, LV_ALIGN_TOP_LEFT, 0, 300);

    _sys_button_btn = ui::MakeButton(left, "button: A", 0, 328, 140, 40, ui::theme::kSurfaceHi, on_sys_button, this);
    _sys_fn = ui::MakeField(left, "function (decimal)", 150, 328, 100, 4, on_field_focus, this);
    ui::MakeButton(left, "read short+long", 260, 344, 170, 40, ui::theme::kInfo, on_sys_button_fn, this);
    ui::MakeButton(left, "write short+long", 440, 344, 170, 40, ui::theme::kError, on_sys_write_button_fn, this);

    _sys_reset_btn = ui::MakeButton(left, "reset settings", 0, 400, 170, 40, ui::theme::kError, on_sys_destructive,
                                    this);
    lv_obj_set_user_data(_sys_reset_btn, (void*)(intptr_t)0);
    _sys_wipe_btn = ui::MakeButton(left, "wipe fds", 180, 400, 170, 40, ui::theme::kError, on_sys_destructive, this);
    lv_obj_set_user_data(_sys_wipe_btn, (void*)(intptr_t)1);

    _sys_log = lv_label_create(left);
    lv_label_set_text(_sys_log, "system: idle");
    lv_obj_set_style_text_font(_sys_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_sys_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_sys_log, 600);
    lv_label_set_long_mode(_sys_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_sys_log, LV_ALIGN_TOP_LEFT, 0, 452);

    // ---- right: MF1 diagnostics and advanced operations ----
    lv_obj_t* right = lv_obj_create(panel);
    lv_obj_set_size(right, 620, lv_pct(100));
    lv_obj_set_style_bg_opa(right, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(right, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 0, LV_PART_MAIN);
    lv_obj_align(right, LV_ALIGN_TOP_LEFT, 632, 0);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "mf1 diagnostics / advanced");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    ui::MakeButton(right, "detect mifare", 0, 28, 150, 40, ui::theme::kInfo, on_mf1_detect_support, this);
    ui::MakeButton(right, "detection count", 160, 28, 160, 40, ui::theme::kInfo, on_mf1_detect_count, this);
    ui::MakeButton(right, "detection log", 330, 28, 150, 40, ui::theme::kAccentDim, on_mf1_detect_log, this);

    _mf1_log = lv_label_create(right);
    lv_label_set_text(_mf1_log, "mf1: idle");
    lv_obj_set_style_text_font(_mf1_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_mf1_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_mf1_log, 600);
    lv_label_set_long_mode(_mf1_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_mf1_log, LV_ALIGN_TOP_LEFT, 0, 76);

    // check keys on one block
    lv_obj_t* keys_title = lv_label_create(right);
    lv_label_set_text(keys_title, "check keys on one block");
    lv_obj_set_style_text_font(keys_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(keys_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(keys_title, LV_ALIGN_TOP_LEFT, 0, 170);

    _keys_block = ui::MakeField(right, "block", 0, 198, 70, 4, on_field_focus, this);
    _keys_type_btn = ui::MakeButton(right, "key A", 80, 214, 90, 40, ui::theme::kSurfaceHi, on_keys_type, this);
    ui::MakeButton(right, "check on block", 460, 214, 140, 40, ui::theme::kInfo, on_mf1_check_keys, this);
    _keys_keys = ui::MakeField(right, "keys (12 hex digits each, concatenated)", 180, 198, 270, 100, on_field_focus,
                               this);

    // value block arithmetic
    lv_obj_t* vb_title = lv_label_create(right);
    lv_label_set_text(vb_title, "value block (increment / decrement / restore)");
    lv_obj_set_style_text_font(vb_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(vb_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(vb_title, LV_ALIGN_TOP_LEFT, 0, 268);

    _vb_src_block = ui::MakeField(right, "src blk", 0, 296, 70, 4, on_field_focus, this);
    _vb_src_key = ui::MakeField(right, "src key", 80, 296, 130, 12, on_field_focus, this);
    _vb_op_btn = ui::MakeButton(right, "op: increment", 220, 312, 160, 40, ui::theme::kSurfaceHi, on_mf1_value_op,
                                this);
    _vb_operand = ui::MakeField(right, "operand", 390, 296, 80, 10, on_field_focus, this);
    _vb_dst_block = ui::MakeField(right, "dst blk", 480, 296, 70, 4, on_field_focus, this);
    _vb_dst_key = ui::MakeField(right, "dst key", 0, 350, 130, 12, on_field_focus, this);
    ui::MakeButton(right, "apply", 140, 366, 100, 40, ui::theme::kError, on_mf1_value_apply, this);

    // encrypted nested acquisition
    lv_obj_t* enc_title = lv_label_create(right);
    lv_label_set_text(enc_title, "encrypted nested acquire (backdoor key)");
    lv_obj_set_style_text_font(enc_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(enc_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(enc_title, LV_ALIGN_TOP_LEFT, 0, 420);

    _enc_key = ui::MakeField(right, "backdoor key", 0, 448, 150, 12, on_field_focus, this);
    _enc_sectors = ui::MakeField(right, "sectors", 160, 448, 70, 3, on_field_focus, this);
    _enc_start = ui::MakeField(right, "start", 240, 448, 70, 3, on_field_focus, this);
    ui::MakeButton(right, "acquire", 320, 464, 130, 40, ui::theme::kAccentDim, on_mf1_enc_nested, this);

    _mf1_adv_log = lv_label_create(right);
    lv_label_set_text(_mf1_adv_log, "advanced: idle");
    lv_obj_set_style_text_font(_mf1_adv_log, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_mf1_adv_log, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_mf1_adv_log, 600);
    lv_label_set_long_mode(_mf1_adv_log, LV_LABEL_LONG_WRAP);
    lv_obj_align(_mf1_adv_log, LV_ALIGN_TOP_LEFT, 0, 516);
}

// ---------------------------------------------------------------------------
// System panel handlers (W4)
// ---------------------------------------------------------------------------

void ToolsPage::on_hf14a_config_read(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    Client::Hf14aConfig config{};
    const uint16_t status = self->_ctx.client().GetHf14aConfig(&config);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_sys_log, "HF14A_GET_CONFIG failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char text[16];
    snprintf(text, sizeof(text), "%d", (int)config.bcc);
    lv_textarea_set_text(self->_sys_bcc, text);
    snprintf(text, sizeof(text), "%d", (int)config.cl2);
    lv_textarea_set_text(self->_sys_cl2, text);
    snprintf(text, sizeof(text), "%d", (int)config.cl3);
    lv_textarea_set_text(self->_sys_cl3, text);
    snprintf(text, sizeof(text), "%d", (int)config.rats);
    lv_textarea_set_text(self->_sys_rats, text);
    lv_label_set_text_fmt(self->_sys_log, "hf14a config: bcc %d cl2 %d cl3 %d rats %d", (int)config.bcc, (int)config.cl2,
                          (int)config.cl3, (int)config.rats);
    self->_ctx.LogEvent("hf14a config: bcc %d cl2 %d cl3 %d rats %d", (int)config.bcc, (int)config.cl2,
                        (int)config.cl3, (int)config.rats);
}

void ToolsPage::on_hf14a_config_write(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    // The four fields are signed bytes: the device stores them as int8_t and the
    // CLI packs them with '!bbbb'.
    auto read_field = [self](lv_obj_t* field, int fallback) -> int {
        const char* text = lv_textarea_get_text(field);
        if (text == nullptr || *text == '\0') {
            return fallback;
        }
        return static_cast<int>(strtol(text, nullptr, 10));
    };

    Client::Hf14aConfig config;
    config.bcc  = static_cast<int8_t>(read_field(self->_sys_bcc, 0));
    config.cl2  = static_cast<int8_t>(read_field(self->_sys_cl2, 0));
    config.cl3  = static_cast<int8_t>(read_field(self->_sys_cl3, 0));
    config.rats = static_cast<int8_t>(read_field(self->_sys_rats, 0));

    const uint16_t status = self->_ctx.client().SetHf14aConfig(config);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_sys_log, "HF14A_SET_CONFIG failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("HF14A_SET_CONFIG failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    lv_label_set_text(self->_sys_log, "hf14a config written (press 'read hf14a config' to confirm)");
    self->_ctx.LogEvent("hf14a config written: bcc %d cl2 %d cl3 %d rats %d", (int)config.bcc, (int)config.cl2,
                        (int)config.cl3, (int)config.rats);
}

void ToolsPage::on_sys_sense(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_sys_sense = (self->_sys_sense == TagSenseType::HF) ? TagSenseType::LF : TagSenseType::HF;
    ui::SetButtonText(self->_sys_sense_btn,
                      self->_sys_sense == TagSenseType::HF ? "sense: hf" : "sense: lf");
}

void ToolsPage::on_sys_set_enabled(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned slot = self->field_uint(self->_sys_slot, 1, 8);
    if (slot < 1) {
        lv_label_set_text(self->_sys_log, "slot numbers are 1..8");
        return;
    }
    // Enable (never disable): disabling the band a slot currently uses would
    // make the slot unreachable from this page, which is not what a button
    // labelled "enable" should risk.
    const bool ok = self->_ctx.client().SetSlotEnabled(static_cast<uint8_t>(slot - 1), self->_sys_sense, true);
    lv_label_set_text_fmt(self->_sys_log, "slot %u %s enabled: %s", slot,
                          self->_sys_sense == TagSenseType::HF ? "hf" : "lf", ok ? "ok" : "failed");
    self->_ctx.LogEvent("SET_SLOT_ENABLE slot %u %s -> %s", slot,
                        self->_sys_sense == TagSenseType::HF ? "hf" : "lf", ok ? "ok" : "failed");
}

void ToolsPage::on_sys_read_nick(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    char nick[40] = {};
    if (!self->_ctx.client().GetActiveSlotNick(nick, sizeof(nick))) {
        lv_label_set_text(self->_sys_log, "the active slot has no nickname");
        return;
    }
    lv_label_set_text_fmt(self->_sys_log, "active slot nick: %s", nick);
    self->_ctx.LogEvent("active slot nick: %s", nick);
}

void ToolsPage::on_sys_delete_nick(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned slot = self->field_uint(self->_sys_slot, 1, 8);
    const bool ok = self->_ctx.client().DeleteSlotTagNick(static_cast<uint8_t>(slot - 1), self->_sys_sense);
    lv_label_set_text_fmt(self->_sys_log, "delete nick slot %u %s: %s", slot,
                          self->_sys_sense == TagSenseType::HF ? "hf" : "lf", ok ? "ok" : "failed");
}

void ToolsPage::on_sys_delete_sense(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned slot = self->field_uint(self->_sys_slot, 1, 8);
    const bool ok = self->_ctx.client().DeleteSlotSenseType(static_cast<uint8_t>(slot - 1), self->_sys_sense);
    lv_label_set_text_fmt(self->_sys_log, "delete sense slot %u %s: %s", slot,
                          self->_sys_sense == TagSenseType::HF ? "hf" : "lf", ok ? "ok" : "failed");
    self->_ctx.LogEvent("DELETE_SLOT_SENSE_TYPE slot %u -> %s", slot, ok ? "ok" : "failed");
}

void ToolsPage::on_sys_set_data_default(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned slot = self->field_uint(self->_sys_slot, 1, 8);
    // The tag type lives in the same enum the Slots page uses; 1000 is
    // MIFARE_Mini, the first HF type, and 100 the first LF one.
    const uint16_t tag_type = (self->_sys_sense == TagSenseType::HF) ? 1000 : 100;
    const bool ok = self->_ctx.client().SetSlotDataDefault(static_cast<uint8_t>(slot - 1), tag_type);
    lv_label_set_text_fmt(self->_sys_log, "set slot %u data default (tag type %u): %s", slot, (unsigned)tag_type,
                          ok ? "ok" : "failed");
    self->_ctx.LogEvent("SET_SLOT_DATA_DEFAULT slot %u type %u -> %s", slot, (unsigned)tag_type, ok ? "ok" : "failed");
}

void ToolsPage::on_sys_save_slot_data(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const bool ok = self->_ctx.client().SlotDataConfigSave();
    lv_label_set_text_fmt(self->_sys_log, "save slot data: %s", ok ? "ok" : "failed");
    self->_ctx.LogEvent("SLOT_DATA_CONFIG_SAVE -> %s", ok ? "ok" : "failed");
}

void ToolsPage::on_sys_button(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_sys_current_button = (self->_sys_current_button == 'A') ? 'B' : 'A';
    char text[24];
    snprintf(text, sizeof(text), "button: %c", self->_sys_current_button);
    ui::SetButtonText(self->_sys_button_btn, text);
}

void ToolsPage::on_sys_button_fn(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t short_fn = 0;
    uint8_t long_fn  = 0;
    const uint16_t s1 = self->_ctx.client().GetButtonPressConfig(
        static_cast<uint8_t>(self->_sys_current_button), &short_fn);
    const uint16_t s2 = self->_ctx.client().GetLongButtonPressConfig(
        static_cast<uint8_t>(self->_sys_current_button), &long_fn);
    if (s1 != SUCCESS || s2 != SUCCESS) {
        lv_label_set_text_fmt(self->_sys_log, "button %c read failed (%s / %s)", self->_sys_current_button,
                              StatusText(s1), StatusText(s2));
        return;
    }
    lv_label_set_text_fmt(self->_sys_log, "button %c: short press %u, long press %u", self->_sys_current_button,
                          (unsigned)short_fn, (unsigned)long_fn);
    self->_ctx.LogEvent("button %c: short %u long %u", self->_sys_current_button, (unsigned)short_fn,
                        (unsigned)long_fn);
}

void ToolsPage::on_sys_write_button_fn(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const unsigned fn = self->field_uint(self->_sys_fn, 0xFFFF, 255);
    if (fn == 0xFFFF) {
        lv_label_set_text(self->_sys_log, "enter the function number (0..255) to assign");
        return;
    }
    // Both writes carry the same function: the device takes one byte per
    // command and the CLI's `hf fw` sets them separately too.
    const uint16_t s1 = self->_ctx.client().SetButtonPressConfig(
        static_cast<uint8_t>(self->_sys_current_button), static_cast<uint8_t>(fn));
    const uint16_t s2 = self->_ctx.client().SetLongButtonPressConfig(
        static_cast<uint8_t>(self->_sys_current_button), static_cast<uint8_t>(fn));
    lv_label_set_text_fmt(self->_sys_log, "button %c set to %u: short %s, long %s", self->_sys_current_button, fn,
                          StatusText(s1), StatusText(s2));
    self->_ctx.LogEvent("button %c -> function %u (short %s, long %s)", self->_sys_current_button, fn,
                        StatusText(s1), StatusText(s2));
}

void ToolsPage::on_sys_destructive(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const int which = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    if (self->_sys_arm_pending != which) {
        // First press only arms: RESET_SETTINGS and WIPE_FDS throw away every
        // slot and setting, so one stray touch must not do it.
        self->_sys_arm_pending = which;
        ui::SetButtonText(which == 0 ? self->_sys_reset_btn : self->_sys_wipe_btn, "press again to confirm");
        lv_label_set_text(self->_sys_log,
                          which == 0 ? "arm RESET_SETTINGS: press 'reset settings' again"
                                     : "arm WIPE_FDS: press 'wipe fds' again");
        return;
    }

    self->_sys_arm_pending = -1;
    if (which == 0) {
        ui::SetButtonText(self->_sys_reset_btn, "reset settings");
        const bool ok = self->_ctx.client().ResetSettings();
        lv_label_set_text_fmt(self->_sys_log, "RESET_SETTINGS: %s", ok ? "done" : "failed");
        self->_ctx.LogEvent("RESET_SETTINGS -> %s", ok ? "done" : "failed");
    } else {
        ui::SetButtonText(self->_sys_wipe_btn, "wipe fds");
        const bool ok = self->_ctx.client().WipeFds();
        lv_label_set_text_fmt(self->_sys_log, "WIPE_FDS: %s", ok ? "done" : "failed");
        self->_ctx.LogEvent("WIPE_FDS -> %s", ok ? "done" : "failed");
    }
    self->_ctx.RefreshSlotState();
}

void ToolsPage::on_mf1_detect_count(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint32_t count = 0;
    const uint16_t status = self->_ctx.client().Mf1GetDetectionCount(&count);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_mf1_log, "MF1_GET_DETECTION_COUNT: %s (0x%02X)", StatusText(status), status);
        return;
    }
    lv_label_set_text_fmt(self->_mf1_log, "detection count: %u authentication(s) captured", (unsigned)count);
    self->_ctx.LogEvent("mf1 detection count: %u", (unsigned)count);
}

void ToolsPage::on_mf1_detect_log(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    Client::Mf1DetectionEntry entries[8];
    size_t count          = 0;
    const uint16_t status = self->_ctx.client().Mf1GetDetectionLog(0, entries, 8, &count);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_mf1_log, "MF1_GET_DETECTION_LOG: %s (0x%02X)", StatusText(status), status);
        return;
    }
    if (count == 0) {
        lv_label_set_text(self->_mf1_log, "detection log: empty");
        return;
    }

    char text[512];
    size_t at = snprintf(text, sizeof(text), "%zu record(s) (block, bitfield, uid, nt, nr, ar):\n", count);
    for (size_t i = 0; i < count && at + 96 < sizeof(text); ++i) {
        const Client::Mf1DetectionEntry& r = entries[i];
        const int written = snprintf(text + at, sizeof(text) - at, "%u/%02X %02X%02X%02X%02X nt %02X%02X%02X%02X\n",
                                     (unsigned)r.block, (unsigned)r.bitfield, r.uid[0], r.uid[1], r.uid[2], r.uid[3],
                                     r.nt[0], r.nt[1], r.nt[2], r.nt[3]);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(written);
    }
    lv_label_set_text(self->_mf1_log, text);
    self->_ctx.LogEvent("mf1 detection log: %zu record(s)", count);
    // The full records, including nr and ar, go to the log where they scroll.
    for (size_t i = 0; i < count; ++i) {
        const Client::Mf1DetectionEntry& r = entries[i];
        self->_ctx.LogEvent("mf1 det %zu: blk %u bf %02X uid %02X%02X%02X%02X nt %02X%02X%02X%02X "
                            "nr %02X%02X%02X%02X ar %02X%02X%02X%02X",
                            i, (unsigned)r.block, (unsigned)r.bitfield, r.uid[0], r.uid[1], r.uid[2], r.uid[3],
                            r.nt[0], r.nt[1], r.nt[2], r.nt[3], r.nr[0], r.nr[1], r.nr[2], r.nr[3], r.ar[0], r.ar[1],
                            r.ar[2], r.ar[3]);
    }
}

// ---------------------------------------------------------------------------
// MF1 advanced handlers (W6)
// ---------------------------------------------------------------------------

void ToolsPage::on_mf1_detect_support(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const bool present = self->_ctx.client().MifareSupported();
    lv_label_set_text_fmt(self->_mf1_log, "MF1_DETECT_SUPPORT: %s",
                          present ? "a Mifare Classic card is in the field" : "no Mifare Classic card");
    self->_ctx.LogEvent("MF1_DETECT_SUPPORT -> %s", present ? "present" : "absent");
}

void ToolsPage::on_keys_type(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_keys_type = (self->_keys_type == MfcKeyType::A) ? MfcKeyType::B : MfcKeyType::A;
    ui::SetButtonText(self->_keys_type_btn, self->_keys_type == MfcKeyType::A ? "key A" : "key B");
}

void ToolsPage::on_mf1_check_keys(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t keys[6 * 83];
    const size_t length = self->field_bytes(self->_keys_keys, keys, sizeof(keys));
    if (length == 0 || (length % 6) != 0) {
        lv_label_set_text(self->_mf1_adv_log, "give whole 6 byte keys (12 hex digits each)");
        return;
    }
    const size_t count  = length / 6;
    const unsigned block = self->field_uint(self->_keys_block, 3, 255);

    const uint8_t* out = nullptr;
    size_t out_length  = 0;
    const uint16_t status = self->_ctx.client().CheckKeysOnBlock(static_cast<uint8_t>(block), self->_keys_type, keys,
                                                                 count, &out, &out_length);
    if (status != HF_TAG_OK && status != HF_TAG_NO) {
        lv_label_set_text_fmt(self->_mf1_adv_log, "MF1_CHECK_KEYS_ON_BLOCK: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("MF1_CHECK_KEYS_ON_BLOCK failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    // The answer is the 6 byte key the card accepted, or an empty payload.
    if (out_length >= 6 && out != nullptr) {
        char hex[16];
        ui::FormatHex(out, 6, hex, sizeof(hex), "");
        lv_label_set_text_fmt(self->_mf1_adv_log, "block %u opens with %s (%zu key(s) tried)", block, hex, count);
        self->_ctx.LogEvent("MF1_CHECK_KEYS_ON_BLOCK block %u: key %s", block, hex);
    } else {
        lv_label_set_text_fmt(self->_mf1_adv_log, "block %u: none of the %zu key(s) matched", block, count);
        self->_ctx.LogEvent("MF1_CHECK_KEYS_ON_BLOCK block %u: no match among %zu keys", block, count);
    }
}

void ToolsPage::on_mf1_value_op(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_vb_op_index = (self->_vb_op_index + 1) % 3;
    static const char* kNames[3] = {"op: decrement", "op: increment", "op: restore"};
    ui::SetButtonText(self->_vb_op_btn, kNames[self->_vb_op_index]);
}

void ToolsPage::on_mf1_value_apply(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t src_key[6];
    uint8_t dst_key[6];
    if (self->field_bytes(self->_vb_src_key, src_key, sizeof(src_key)) != sizeof(src_key) ||
        self->field_bytes(self->_vb_dst_key, dst_key, sizeof(dst_key)) != sizeof(dst_key)) {
        lv_label_set_text(self->_mf1_adv_log, "both keys must be 6 bytes (12 hex digits)");
        return;
    }
    // MfcValueBlockOperator: DECREMENT 0xC0, INCREMENT 0xC1, RESTORE 0xC2.
    static const uint8_t kOps[3] = {0xC0, 0xC1, 0xC2};
    const unsigned src_block = self->field_uint(self->_vb_src_block, 4, 255);
    const unsigned dst_block = self->field_uint(self->_vb_dst_block, 8, 255);
    const uint8_t op         = kOps[self->_vb_op_index];
    // The operand field is decimal and may be negative (a restore ignores it,
    // a decrement subtracts it).
    const char* operand_text = lv_textarea_get_text(self->_vb_operand);
    const int32_t operand    = static_cast<int32_t>(strtol(operand_text != nullptr ? operand_text : "1", nullptr, 10));

    const uint16_t status = self->_ctx.client().Mf1ManipulateValueBlock(
        static_cast<uint8_t>(src_block), MfcKeyType::A, src_key, op, operand, static_cast<uint8_t>(dst_block),
        MfcKeyType::A, dst_key);
    lv_label_set_text_fmt(self->_mf1_adv_log, "value block %u -> %u (op %02X, operand %ld): %s",
                          src_block, dst_block, (unsigned)op, (long)operand, StatusText(status));
    self->_ctx.LogEvent("MF1_MANIPULATE_VALUE_BLOCK %u->%u op %02X operand %ld: %s", src_block, dst_block,
                        (unsigned)op, (long)operand, StatusText(status));
}

void ToolsPage::on_mf1_enc_nested(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<ToolsPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t key[6];
    if (self->field_bytes(self->_enc_key, key, sizeof(key)) != sizeof(key)) {
        lv_label_set_text(self->_mf1_adv_log, "the backdoor key is 6 bytes (12 hex digits)");
        return;
    }
    const unsigned sectors = self->field_uint(self->_enc_sectors, 1, 40);
    const unsigned start   = self->field_uint(self->_enc_start, 0, 39);

    uint32_t nonces[64];
    size_t count          = 0;
    const uint16_t status = self->_ctx.client().Mf1EncNestedAcquire(key, static_cast<uint8_t>(sectors),
                                                                    static_cast<uint8_t>(start), nonces, 64, &count);
    if ((status != HF_TAG_OK && status != HF_TAG_NO) || count == 0) {
        lv_label_set_text_fmt(self->_mf1_adv_log, "MF1_ENC_NESTED_ACQUIRE: %s (0x%02X), %zu nonce(s)",
                              StatusText(status), status, count);
        self->_ctx.LogEvent("MF1_ENC_NESTED_ACQUIRE failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char text[256];
    size_t at = snprintf(text, sizeof(text), "%zu encrypted nonce(s):\n", count);
    for (size_t i = 0; i < count && i < 6 && at + 16 < sizeof(text); ++i) {
        const int written = snprintf(text + at, sizeof(text) - at, "%s%08X", i == 0 ? "" : " ", (unsigned)nonces[i]);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(written);
    }
    lv_label_set_text(self->_mf1_adv_log, text);
    self->_ctx.LogEvent("MF1_ENC_NESTED_ACQUIRE: %zu nonce(s)", count);
}

// ---------------------------------------------------------------------------

void ToolsPage::Refresh()
{
    // Nothing to poll: every panel action is a one-shot command whose answer is
    // written straight into the panel's own label.
}

bool ToolsPage::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    if (hid_key_code == ui::key::kEscape) {
        if (_keyboard != nullptr) {
            lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
            return true;
        }
        return false;
    }
    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c == 'm' || c == 'M') {
        showMode((_mode + 1) % 3);
        return true;
    }
    return false;
}

}  // namespace app
