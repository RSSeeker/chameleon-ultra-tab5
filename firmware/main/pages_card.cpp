// SPDX-License-Identifier: MIT
//
// Card operations page: HF/LF scanning across protocols, T55xx cloning, and
// Mifare Classic block read/write.
//
// The device must be in reader mode for the scan/clone commands; the page
// switches it automatically and says so in the log, because CHANGE_DEVICE_MODE
// otherwise fails with DEVICE_MODE_ERROR and looks like a broken button.

#include "pages.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

#include "app_context.h"

namespace app {

using namespace chameleon;

namespace {

/// The live page instance, used by the static LVGL callbacks. They normally
/// recover `this` from the event's user data; OnKey() has no event object, so it
/// routes through this pointer instead of fabricating one.
CardPage* s_active = nullptr;

/// Default Mifare Classic key: the factory transport key.
constexpr const char* kDefaultKeyHex = "FFFFFFFFFFFF";

/// Parse a hex string ("FF00AB", spaces allowed) into bytes.
size_t parse_hex(const char* text, uint8_t* out, size_t out_size)
{
    size_t n = 0;
    int hi   = -1;

    for (const char* p = text; *p != '\0' && n < out_size; ++p) {
        int v;
        const char c = *p;
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        } else {
            continue;  // skip separators
        }

        if (hi < 0) {
            hi = v;
        } else {
            out[n++] = static_cast<uint8_t>((hi << 4) | v);
            hi       = -1;
        }
    }
    return n;
}

/// Format bytes as uppercase hex with a separator.
void format_hex(const uint8_t* data, size_t len, char* out, size_t out_size, const char* sep = " ")
{
    size_t written = 0;
    out[0]         = '\0';
    for (size_t i = 0; i < len; ++i) {
        const int r = snprintf(out + written, out_size - written, "%s%02X", i == 0 ? "" : sep, data[i]);
        if (r <= 0 || static_cast<size_t>(r) >= out_size - written) {
            return;
        }
        written += static_cast<size_t>(r);
    }
}

/// Guess the card family from SAK, so the UI can tell the user whether the
/// Mifare Classic block tools apply at all.
const char* card_family_from_sak(uint8_t sak)
{
    switch (sak) {
        case 0x00:
            return "Mifare Ultralight / NTAG (no sectors)";
        case 0x08:
            return "Mifare Classic 1K";
        case 0x09:
            return "Mifare Mini";
        case 0x18:
            return "Mifare Classic 4K";
        case 0x10:
        case 0x11:
            return "Mifare Plus (SL1)";
        case 0x20:
            return "ISO14443-4 (DESFire / Plus SL3)";
        case 0x28:
            return "SmartMX (JCOP)";
        case 0x38:
            return "Mifare Plus (SL2)";
        default:
            return "unknown / other";
    }
}

/// True when the block read/write tools are meaningful for this SAK.
bool sak_is_mifare_classic(uint8_t sak)
{
    return sak == 0x08 || sak == 0x09 || sak == 0x18;
}

// ---------------------------------------------------------------------------
// Reader table
//
// Each entry is one selectable reader: the HF ISO14443-A scan, one LF protocol,
// or a diagnostic read. They differ only in the command issued and how the reply
// is rendered, so a table keeps this file free of per-protocol branches.
// ---------------------------------------------------------------------------

enum ReaderKind : int {
    kReaderHf14a = 0,  ///< ISO14443-A: returns uid/atqa/sak/ats
    kReaderLf,         ///< a *_SCAN command returning a protocol specific payload
    kReaderEm4x05,     ///< reader-talk-first tag with a 32-bit password
    kReaderAdc,        ///< raw LF ADC level
};

struct Reader {
    const char* name;
    ReaderKind kind;
    uint16_t scan_cmd;   ///< for kReaderLf
    uint16_t write_cmd;  ///< for kReaderLf; 0 when cloning is unsupported
    uint8_t id_offset;   ///< bytes to skip in the scan reply to reach the id
    uint8_t id_length;   ///< id length the write command expects
    bool needs_hint;     ///< send a 1 byte format hint with the scan
};

const Reader kReaders[] = {
    //  name                kind            scan                 write                    off  len  hint
    {"HF14A (13.56M)",     kReaderHf14a,   0,                   0,                       0,   0,   false},
    {"EM410X (125k)",      kReaderLf,      EM410X_SCAN,         EM410X_WRITE_TO_T55XX,   2,   5,   false},
    {"HIDProx (125k)",     kReaderLf,      HIDPROX_SCAN,        HIDPROX_WRITE_TO_T55XX,  0,   13,  true},
    {"ioProx (125k)",      kReaderLf,      IOPROX_SCAN,         IOPROX_WRITE_TO_T55XX,   0,   16,  false},
    {"PAC/Stanley",        kReaderLf,      PAC_SCAN,            PAC_WRITE_TO_T55XX,      0,   8,   false},
    {"Viking",             kReaderLf,      VIKING_SCAN,         VIKING_WRITE_TO_T55XX,   0,   4,   false},
    {"Jablotron",          kReaderLf,      JABLOTRON_SCAN,      JABLOTRON_WRITE_TO_T55XX, 0,  5,   false},
    {"IDTECK (clone only)", kReaderLf,     0,                   IDTECK_WRITE_TO_T55XX,   0,   8,   false},
    {"EM4x05/EM4x69",      kReaderEm4x05,  EM4X05_SCAN,         0,                       0,   0,   false},
    {"ADC level",          kReaderAdc,     ADC_GENERIC_READ,    0,                       0,   0,   false},
};

constexpr size_t kReaderCount = sizeof(kReaders) / sizeof(kReaders[0]);

/// EM410X Electra shares the EM410X reader but carries a 13 byte id.
constexpr size_t kEm410xElectraIdLength = 13;

}  // namespace

// ===========================================================================
// CardPage
// ===========================================================================

void CardPage::Create(lv_obj_t* parent)
{
    s_active = this;

    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(_root, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_column(_root, 12, LV_PART_MAIN);
    lv_obj_set_style_pad_row(_root, 12, LV_PART_MAIN);
    lv_obj_set_flex_flow(_root, LV_FLEX_FLOW_ROW);
    lv_obj_clear_flag(_root, LV_OBJ_FLAG_SCROLLABLE);

    // ---------------- left: reader + result ----------------
    lv_obj_t* left = lv_obj_create(_root);
    lv_obj_set_size(left, 620, lv_pct(100));
    lv_obj_set_style_bg_color(left, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(left, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(left, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 14, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* scan_title = lv_label_create(left);
    lv_label_set_text(scan_title, "read card");
    lv_obj_set_style_text_font(scan_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(scan_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(scan_title, LV_ALIGN_TOP_LEFT, 0, 0);

    _scan_hf_btn = lv_button_create(left);
    lv_obj_set_size(_scan_hf_btn, 130, 44);
    lv_obj_set_style_radius(_scan_hf_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_scan_hf_btn, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_align(_scan_hf_btn, LV_ALIGN_TOP_LEFT, 0, 34);
    lv_obj_add_event_cb(_scan_hf_btn, on_scan, LV_EVENT_CLICKED, this);
    lv_obj_t* scan_label = lv_label_create(_scan_hf_btn);
    lv_label_set_text(scan_label, "scan");
    lv_obj_set_style_text_font(scan_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_center(scan_label);

    _reader_dropdown = lv_dropdown_create(left);
    {
        static char options[256];
        size_t written = 0;
        options[0]     = '\0';
        for (size_t i = 0; i < kReaderCount; ++i) {
            const int r = snprintf(options + written, sizeof(options) - written, "%s%s", i == 0 ? "" : "\n",
                                   kReaders[i].name);
            if (r <= 0 || static_cast<size_t>(r) >= sizeof(options) - written) {
                break;
            }
            written += static_cast<size_t>(r);
        }
        lv_dropdown_set_options_static(_reader_dropdown, options);
    }
    lv_obj_set_size(_reader_dropdown, 300, 44);
    lv_obj_set_style_text_font(_reader_dropdown, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_reader_dropdown, LV_ALIGN_TOP_LEFT, 140, 34);

    _clone_btn = lv_button_create(left);
    lv_obj_set_size(_clone_btn, 150, 44);
    lv_obj_set_style_radius(_clone_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_clone_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_clone_btn, LV_ALIGN_TOP_LEFT, 450, 34);
    lv_obj_add_event_cb(_clone_btn, on_clone, LV_EVENT_CLICKED, this);
    lv_obj_t* clone_label = lv_label_create(_clone_btn);
    lv_label_set_text(clone_label, "clone to T55xx");
    lv_obj_set_style_text_font(clone_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(clone_label);

    _scan_hint = lv_label_create(left);
    lv_label_set_text(_scan_hint, "pick a reader, place a card, then scan");
    lv_obj_set_style_text_font(_scan_hint, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_scan_hint, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(_scan_hint, LV_ALIGN_TOP_LEFT, 0, 86);

    // Selecting IDTECK changes what the scan button does, so the hint follows.
    lv_obj_add_event_cb(_reader_dropdown, on_reader_changed, LV_EVENT_VALUE_CHANGED, this);

    // Key recovery lives on the Keys tab; this pulls its result into the key
    // field so the block tools can be used without typing 12 hex digits.
    _use_key_btn = lv_button_create(left);
    lv_obj_set_size(_use_key_btn, 160, 40);
    lv_obj_set_style_radius(_use_key_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_use_key_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_use_key_btn, LV_ALIGN_TOP_LEFT, 450, 86);
    lv_obj_add_event_cb(_use_key_btn, on_use_found_key, LV_EVENT_CLICKED, this);
    lv_obj_t* use_label = lv_label_create(_use_key_btn);
    lv_label_set_text(use_label, "use found key");
    lv_obj_set_style_text_font(use_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(use_label);

    _detail_label = lv_label_create(left);
    lv_label_set_text(_detail_label, "(no card)");
    lv_obj_set_style_text_font(_detail_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_detail_label, lv_color_hex(ui::theme::kText), LV_PART_MAIN);
    lv_obj_set_width(_detail_label, 580);
    lv_label_set_long_mode(_detail_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_detail_label, LV_ALIGN_TOP_LEFT, 0, 112);

    // ---------------- right: Mifare block access ----------------
    lv_obj_t* right = lv_obj_create(_root);
    lv_obj_set_size(right, 590, lv_pct(100));
    lv_obj_set_style_bg_color(right, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(right, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(right, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 14, LV_PART_MAIN);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* block_title = lv_label_create(right);
    lv_label_set_text(block_title, "mifare classic block");
    lv_obj_set_style_text_font(block_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(block_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(block_title, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t* keytype_caption = lv_label_create(right);
    lv_label_set_text(keytype_caption, "key type");
    lv_obj_set_style_text_font(keytype_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(keytype_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(keytype_caption, LV_ALIGN_TOP_LEFT, 0, 34);

    _keytype_dropdown = lv_dropdown_create(right);
    lv_dropdown_set_options_static(_keytype_dropdown, "Key A\nKey B");
    lv_obj_set_size(_keytype_dropdown, 150, 42);
    lv_obj_set_style_text_font(_keytype_dropdown, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_keytype_dropdown, LV_ALIGN_TOP_LEFT, 0, 54);

    lv_obj_t* block_caption = lv_label_create(right);
    lv_label_set_text(block_caption, "block number");
    lv_obj_set_style_text_font(block_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(block_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(block_caption, LV_ALIGN_TOP_LEFT, 170, 34);

    _block_spinbox = lv_spinbox_create(right);
    lv_spinbox_set_range(_block_spinbox, 0, 255);
    lv_spinbox_set_digit_format(_block_spinbox, 3, 0);
    lv_obj_set_size(_block_spinbox, 130, 42);
    lv_obj_set_style_text_font(_block_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_block_spinbox, LV_ALIGN_TOP_LEFT, 170, 54);

    lv_obj_t* block_minus = lv_button_create(right);
    lv_obj_set_size(block_minus, 42, 42);
    lv_obj_align(block_minus, LV_ALIGN_TOP_LEFT, 306, 54);
    lv_obj_set_style_radius(block_minus, 8, LV_PART_MAIN);
    lv_obj_add_event_cb(block_minus, on_block_step, LV_EVENT_CLICKED, this);
    lv_obj_set_user_data(block_minus, (void*)(intptr_t)-1);
    lv_obj_t* minus_label = lv_label_create(block_minus);
    lv_label_set_text(minus_label, "-");
    lv_obj_set_style_text_font(minus_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_center(minus_label);

    lv_obj_t* block_plus = lv_button_create(right);
    lv_obj_set_size(block_plus, 42, 42);
    lv_obj_align(block_plus, LV_ALIGN_TOP_LEFT, 354, 54);
    lv_obj_set_style_radius(block_plus, 8, LV_PART_MAIN);
    lv_obj_add_event_cb(block_plus, on_block_step, LV_EVENT_CLICKED, this);
    lv_obj_set_user_data(block_plus, (void*)(intptr_t)1);
    lv_obj_t* plus_label = lv_label_create(block_plus);
    lv_label_set_text(plus_label, "+");
    lv_obj_set_style_text_font(plus_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_center(plus_label);

    lv_obj_t* key_caption = lv_label_create(right);
    lv_label_set_text(key_caption, "key (hex, 6 bytes)");
    lv_obj_set_style_text_font(key_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(key_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(key_caption, LV_ALIGN_TOP_LEFT, 0, 106);

    _key_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_key_input, true);
    lv_textarea_set_max_length(_key_input, 17);
    lv_textarea_set_text(_key_input, kDefaultKeyHex);
    lv_obj_set_size(_key_input, 250, 44);
    lv_obj_set_style_text_font(_key_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_key_input, LV_ALIGN_TOP_LEFT, 0, 126);
    lv_obj_add_event_cb(_key_input, on_key_focus, LV_EVENT_FOCUSED, this);

    _keyboard = lv_keyboard_create(right);
    lv_obj_set_size(_keyboard, 560, 220);
    lv_obj_align(_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_keyboard_set_textarea(_keyboard, _key_input);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_READY, this);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_CANCEL, this);

    _read_btn = lv_button_create(right);
    lv_obj_set_size(_read_btn, 140, 44);
    lv_obj_set_style_radius(_read_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_read_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_read_btn, LV_ALIGN_TOP_LEFT, 264, 126);
    lv_obj_add_event_cb(_read_btn, on_read_block, LV_EVENT_CLICKED, this);
    lv_obj_t* read_label = lv_label_create(_read_btn);
    lv_label_set_text(read_label, "read");
    lv_obj_set_style_text_font(read_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(read_label);

    _write_btn = lv_button_create(right);
    lv_obj_set_size(_write_btn, 140, 44);
    lv_obj_set_style_radius(_write_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_write_btn, lv_color_hex(ui::theme::kError), LV_PART_MAIN);
    lv_obj_align(_write_btn, LV_ALIGN_TOP_LEFT, 412, 126);
    lv_obj_add_event_cb(_write_btn, on_write_block, LV_EVENT_CLICKED, this);
    lv_obj_t* write_label = lv_label_create(_write_btn);
    lv_label_set_text(write_label, "write");
    lv_obj_set_style_text_font(write_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(write_label);

    lv_obj_t* data_caption = lv_label_create(right);
    lv_label_set_text(data_caption, "block data (hex, 16 bytes)");
    lv_obj_set_style_text_font(data_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(data_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(data_caption, LV_ALIGN_TOP_LEFT, 0, 180);

    _data_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_data_input, true);
    lv_textarea_set_max_length(_data_input, 48);
    lv_textarea_set_text(_data_input, "");
    lv_obj_set_size(_data_input, 560, 44);
    lv_obj_set_style_text_font(_data_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_data_input, LV_ALIGN_TOP_LEFT, 0, 200);
}

void CardPage::Destroy()
{
    if (s_active == this) {
        s_active = nullptr;
    }
    ui::Page::Destroy();
}

void CardPage::Refresh()
{
    const bool online = _ctx.connected();
    lv_obj_t* buttons[3] = {_scan_hf_btn, _clone_btn, _read_btn};
    for (lv_obj_t* b : buttons) {
        if (b == nullptr) {
            continue;
        }
        if (online) {
            lv_obj_remove_state(b, LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(b, LV_STATE_DISABLED);
        }
    }
    if (_use_key_btn != nullptr) {
        if (_ctx.hasFoundKey()) {
            lv_obj_remove_state(_use_key_btn, LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(_use_key_btn, LV_STATE_DISABLED);
        }
    }
    if (!online && _detail_label != nullptr) {
        lv_label_set_text(_detail_label, "(device offline)");
    }
}

void CardPage::on_use_found_key(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_key_input == nullptr) {
        return;
    }
    uint8_t key[6];
    if (!self->_ctx.foundKey(key)) {
        return;
    }
    char hex[16];
    snprintf(hex, sizeof(hex), "%02X%02X%02X%02X%02X%02X", key[0], key[1], key[2], key[3], key[4], key[5]);
    lv_textarea_set_text(self->_key_input, hex);
    lv_label_set_text_fmt(self->_detail_label, "using recovered key %s", hex);
    self->_ctx.LogEvent("cards page switched to the recovered key");
}

/// Ensure reader mode; scanning and block access require it.
bool CardPage::ensureReaderMode()
{
    uint8_t mode = 0;
    if (!_ctx.client().FetchDeviceMode(&mode)) {
        return false;
    }
    if (mode != 0) {
        return true;
    }
    if (_ctx.client().ChangeDeviceMode(1)) {
        _ctx.LogEvent("switched to reader mode for card access");
        return true;
    }
    _ctx.LogEvent("cannot switch to reader mode");
    return false;
}

void CardPage::on_scan(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    self->runScan();
}

void CardPage::on_reader_changed(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_scan_hint == nullptr) {
        return;
    }
    const int index = static_cast<int>(lv_dropdown_get_selected(self->_reader_dropdown));
    if (index < 0 || index >= static_cast<int>(kReaderCount)) {
        return;
    }
    lv_label_set_text(self->_scan_hint, kReaders[index].scan_cmd == 0
                                            ? "no reader command: type the frame, then scan to write"
                                            : "pick a reader, place a card, then scan");
}

void CardPage::runScan()
{
    if (!ensureReaderMode()) {
        return;
    }

    const int index = static_cast<int>(lv_dropdown_get_selected(_reader_dropdown));
    if (index < 0 || index >= static_cast<int>(kReaderCount)) {
        return;
    }
    const Reader& reader = kReaders[index];

    _last_id_length = 0;
    _last_reader    = -1;
    _last_write_cmd = 0;

    char text[640];
    text[0] = '\0';

    switch (reader.kind) {
        case kReaderHf14a: {
            HfTag tags[4];
            size_t count          = 0;
            const uint16_t status = _ctx.client().ScanHf(tags, 4, &count);
            if (status != HF_TAG_OK || count == 0) {
                lv_label_set_text_fmt(_detail_label, "no HF card found\nstatus: %s (0x%02X)", StatusText(status),
                                      status);
                _ctx.LogEvent("HF14A_SCAN: %s", StatusText(status));
                return;
            }

            const HfTag& t = tags[0];
            char uid_text[64];
            format_hex(t.uid, t.uid_length, uid_text, sizeof(uid_text), "");

            char hex[64];
            format_hex(t.uid, t.uid_length, hex, sizeof(hex), "");
            int r = snprintf(text, sizeof(text), "UID   %s\n", hex);
            format_hex(t.atqa, 2, hex, sizeof(hex));
            r += snprintf(text + r, sizeof(text) - r, "ATQA  %s\nSAK   %02X\n", hex, t.sak);
            if (t.ats_length > 0) {
                format_hex(t.ats, t.ats_length, hex, sizeof(hex));
                r += snprintf(text + r, sizeof(text) - r, "ATS   %s\n", hex);
            }
            r += snprintf(text + r, sizeof(text) - r, "type  %s\n%s\n", card_family_from_sak(t.sak),
                          sak_is_mifare_classic(t.sak) ? "block tools available (right panel)"
                                                       : "block tools do not apply to this card");

            lv_label_set_text(_detail_label, text);
            _ctx.LogEvent("HF14A_SCAN: %u tag(s), UID %s, SAK %02X (%s)", (unsigned)count, uid_text, t.sak,
                          card_family_from_sak(t.sak));
            return;
        }

        case kReaderLf: {
            if (reader.scan_cmd == 0) {
                // The firmware has no IDTECK reader command, only a writer, so
                // the id has to come from the user: 8 bytes of hex typed into the
                // block data field on the right.
                uint8_t frame[8];
                if (parse_hex(lv_textarea_get_text(_data_input), frame, sizeof(frame)) != sizeof(frame)) {
                    lv_label_set_text(_detail_label,
                                      "IDTECK has no reader command in the firmware.\n"
                                      "Type the 8 byte frame (16 hex digits) into the\n"
                                      "block data field, then press scan to write it.");
                    return;
                }
                char hex[32];
                format_hex(frame, sizeof(frame), hex, sizeof(hex), "");
                const uint16_t status = _ctx.client().WriteT55xx(reader.write_cmd, frame, sizeof(frame));
                if (status == LF_TAG_OK) {
                    lv_label_set_text_fmt(_detail_label, "IDTECK frame written to T55xx\n%s", hex);
                    _ctx.LogEvent("IDTECK clone to T55xx: %s", hex);
                } else {
                    lv_label_set_text_fmt(_detail_label, "IDTECK write failed\nstatus: %s (0x%02X)",
                                          StatusText(status), status);
                    _ctx.LogEvent("IDTECK clone failed: %s", StatusText(status));
                }
                return;
            }

            // HIDPROX_SCAN dereferences the request's first byte on the device,
            // so the hint must always be present. 0 means "try every format".
            const uint8_t hint = 0;
            chameleon::Client::LfResult res;
            const uint16_t status =
                reader.needs_hint ? _ctx.client().ScanLfCommand(reader.scan_cmd, &res, &hint, 1)
                                  : _ctx.client().ScanLfCommand(reader.scan_cmd, &res);
            if (status != LF_TAG_OK || res.length == 0) {
                lv_label_set_text_fmt(_detail_label, "%s: no card\nstatus: %s (0x%02X)", reader.name,
                                      StatusText(status), status);
                _ctx.LogEvent("%s scan: %s", reader.name, StatusText(status));
                return;
            }

            char raw[128];
            format_hex(res.data, res.length, raw, sizeof(raw), "");
            char hex[64];
            int r = 0;

            // The card id the T55xx writer expects is the scan reply minus the
            // protocol specific prefix the device prepends.
            size_t offset = reader.id_offset;
            size_t id_len = reader.id_length;
            uint16_t write_cmd = reader.write_cmd;

            if (reader.scan_cmd == EM410X_SCAN && res.length >= 2) {
                // tag_type[2] then the id: 5 bytes, or 13 for Electra.
                const uint16_t tag_type = static_cast<uint16_t>((res.data[0] << 8) | res.data[1]);
                const bool electra      = (tag_type == EM410X_ELECTRA);
                id_len                  = electra ? kEm410xElectraIdLength : 5;
                write_cmd               = electra ? EM410X_ELECTRA_WRITE_TO_T55XX : EM410X_WRITE_TO_T55XX;
                if (offset + id_len <= res.length) {
                    format_hex(res.data + offset, id_len, hex, sizeof(hex), "");
                    r = snprintf(text, sizeof(text), "%s\nID    %s\n", electra ? "EM410X Electra" : "EM410X", hex);
                }
            } else if (reader.scan_cmd == HIDPROX_SCAN && res.length >= 13) {
                // Layout unpacked by chameleon_cmd.py as '>BIBIBH':
                // format, facility code, card number, issue level, OEM.
                const uint8_t hid_format = res.data[0];
                const uint32_t fc        = ((uint32_t)res.data[1] << 24) | ((uint32_t)res.data[2] << 16) |
                                           ((uint32_t)res.data[3] << 8) | res.data[4];
                const uint64_t cn        = ((uint64_t)res.data[5] << 32) |
                                           ((uint32_t)res.data[6] << 24) | ((uint32_t)res.data[7] << 16) |
                                           ((uint32_t)res.data[8] << 8) | res.data[9];
                const uint8_t il  = res.data[10];
                const uint16_t oem = static_cast<uint16_t>((res.data[11] << 8) | res.data[12]);
                format_hex(res.data, 13, hex, sizeof(hex), "");
                r = snprintf(text, sizeof(text),
                             "HIDProx format %u\nFC    %u\nCN    %llu\nIL    %u\nOEM   %u\nid    %s\n",
                             hid_format, (unsigned)fc, (unsigned long long)cn, il, oem, hex);
            } else if (reader.scan_cmd == IOPROX_SCAN && res.length >= 16) {
                // '>BBH8s': version, facility code, card number, raw8.
                const uint8_t ver = res.data[0];
                const uint8_t fc  = res.data[1];
                const uint16_t cn = static_cast<uint16_t>((res.data[2] << 8) | res.data[3]);
                format_hex(res.data + 4, 8, hex, sizeof(hex), "");
                r = snprintf(text, sizeof(text), "ioProx XSF\nver   %u\nFC    %u\nCN    %u\nraw8  %s\n", ver, fc, cn,
                             hex);
            } else if (reader.scan_cmd == PAC_SCAN && res.length >= 8) {
                char ascii[9];
                for (int i = 0; i < 8; ++i) {
                    ascii[i] = (res.data[i] >= 0x20 && res.data[i] < 0x7F) ? (char)res.data[i] : '.';
                }
                ascii[8] = '\0';
                format_hex(res.data, 8, hex, sizeof(hex), "");
                r = snprintf(text, sizeof(text), "PAC/Stanley\nCN    %s\nraw   %s\n", ascii, hex);
            } else if (reader.scan_cmd == JABLOTRON_SCAN && res.length >= 5) {
                // Card number is BCD, as computed by jablotron_card_id() in the CLI.
                uint64_t card_id = 0;
                for (int i = 0; i < 5; ++i) {
                    card_id = card_id * 100 + ((res.data[i] >> 4) * 10) + (res.data[i] & 0x0F);
                }
                format_hex(res.data, 5, hex, sizeof(hex), "");
                r = snprintf(text, sizeof(text), "Jablotron\nID    %s\nCN    %llu\n", hex, (unsigned long long)card_id);
            } else if (reader.scan_cmd == VIKING_SCAN && res.length >= 4) {
                const uint32_t uid = ((uint32_t)res.data[0] << 24) | ((uint32_t)res.data[1] << 16) |
                                     ((uint32_t)res.data[2] << 8) | res.data[3];
                format_hex(res.data, 4, hex, sizeof(hex), "");
                r = snprintf(text, sizeof(text), "Viking\nID    %s\nCN    %u\n", hex, (unsigned)uid);
            } else {
                r = snprintf(text, sizeof(text), "%s\n%u bytes\n", reader.name, (unsigned)res.length);
            }

            // Retain the id so it can be cloned onto a T55xx tag.
            if (id_len > 0 && id_len <= sizeof(_last_id) && offset + id_len <= res.length) {
                memcpy(_last_id, res.data + offset, id_len);
                _last_id_length = id_len;
                _last_reader    = index;
                _last_write_cmd = write_cmd;
            } else {
                _last_id_length = 0;
                _last_reader    = -1;
            }

            if (r > 0) {
                snprintf(text + r, sizeof(text) - static_cast<size_t>(r), "raw   %s", raw);
                lv_label_set_text(_detail_label, text);
            } else {
                lv_label_set_text_fmt(_detail_label, "%s\n%u bytes\n%s", reader.name, (unsigned)res.length, raw);
            }
            _ctx.LogEvent("%s scan: %u bytes %s", reader.name, (unsigned)res.length, raw);
            return;
        }

        case kReaderEm4x05: {
            uint8_t buf[32];
            size_t len = 0;
            // Default password: these tags are normally left on the 0x00000000
            // transport password.
            const uint16_t status = _ctx.client().Em4x05Scan(0x00000000, buf, sizeof(buf), &len);
            if (status != LF_TAG_OK || len == 0) {
                lv_label_set_text_fmt(_detail_label, "no EM4x05/EM4x69 tag\nstatus: %s (0x%02X)",
                                      StatusText(status), status);
                _ctx.LogEvent("EM4X05_SCAN: %s", StatusText(status));
                return;
            }

            // config[4] uid[4] uid_hi[4] is_em4x69[1] (uid_block[1] on some builds)
            char raw[128];
            format_hex(buf, len, raw, sizeof(raw), "");
            if (len >= 9) {
                const uint32_t config = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                                        ((uint32_t)buf[2] << 8) | buf[3];
                const uint32_t uid = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                                     ((uint32_t)buf[6] << 8) | buf[7];
                const bool em4x69 = (len >= 13) && (buf[12] != 0);
                if (em4x69 && len >= 12) {
                    const uint32_t uid_hi = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                            ((uint32_t)buf[10] << 8) | buf[11];
                    snprintf(text, sizeof(text), "config %08X\nuid    %08X %08X\n64-bit uid (EM4x69)\nraw    %s",
                             (unsigned)config, (unsigned)uid_hi, (unsigned)uid, raw);
                } else {
                    snprintf(text, sizeof(text), "config %08X\nuid    %08X\n32-bit uid (EM4x05)\nraw    %s",
                             (unsigned)config, (unsigned)uid, raw);
                }
            } else {
                snprintf(text, sizeof(text), "%u bytes\n%s", (unsigned)len, raw);
            }
            lv_label_set_text(_detail_label, text);
            _ctx.LogEvent("EM4X05_SCAN: %u bytes %s", (unsigned)len, raw);
            return;
        }

        case kReaderAdc: {
            uint8_t buf[16];
            size_t len            = 0;
            const uint16_t status = _ctx.client().AdcGenericRead(buf, sizeof(buf), &len);
            if (status != LF_TAG_OK || len == 0) {
                lv_label_set_text_fmt(_detail_label, "ADC read failed\nstatus: %s (0x%02X)", StatusText(status),
                                      status);
                return;
            }
            char raw[64];
            format_hex(buf, len, raw, sizeof(raw));
            lv_label_set_text_fmt(_detail_label, "LF field ADC (0x80 = field on)\n%s", raw);
            _ctx.LogEvent("ADC: %s", raw);
            return;
        }

        default:
            return;
    }
}

void CardPage::on_clone(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    self->cloneLastTag();
}

void CardPage::cloneLastTag()
{
    if (_last_reader < 0 || _last_id_length == 0 || _last_write_cmd == 0) {
        lv_label_set_text(_detail_label, "scan a card first");
        return;
    }

    const Reader& reader = kReaders[_last_reader];

    // _last_id already holds exactly the bytes the writer wants: the scan reply
    // minus its protocol prefix, with the Electra variant resolved at scan time.
    const uint16_t status = _ctx.client().WriteT55xx(_last_write_cmd, _last_id, _last_id_length);
    if (status == LF_TAG_OK) {
        char hex[64];
        format_hex(_last_id, _last_id_length, hex, sizeof(hex), "");
        lv_label_set_text_fmt(_detail_label, "cloned %s to T55xx\n%s", reader.name, hex);
        _ctx.LogEvent("%s clone to T55xx: %u bytes %s", reader.name, (unsigned)_last_id_length, hex);
    } else {
        lv_label_set_text_fmt(_detail_label, "clone failed for %s\nstatus: %s (0x%02X)", reader.name,
                              StatusText(status), status);
        _ctx.LogEvent("%s clone failed: %s", reader.name, StatusText(status));
    }
}

void CardPage::on_block_step(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_block_spinbox == nullptr) {
        return;
    }
    const int delta = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    int32_t value   = lv_spinbox_get_value(self->_block_spinbox) + delta;
    if (value < 0) {
        value = 0;
    }
    if (value > 255) {
        value = 255;
    }
    lv_spinbox_set_value(self->_block_spinbox, value);
}

void CardPage::on_key_focus(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_obj_remove_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_keyboard_set_textarea(self->_keyboard, lv_event_get_target_obj(e));
}

void CardPage::on_keyboard_event(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_obj_add_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
}

void CardPage::on_read_block(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected() || !self->ensureReaderMode()) {
        return;
    }

    uint8_t key[6];
    if (parse_hex(lv_textarea_get_text(self->_key_input), key, sizeof(key)) != sizeof(key)) {
        lv_label_set_text(self->_detail_label, "key must be exactly 6 bytes of hex\n(e.g. FFFFFFFFFFFF)");
        return;
    }

    const uint8_t block = static_cast<uint8_t>(lv_spinbox_get_value(self->_block_spinbox));
    const auto key_type =
        lv_dropdown_get_selected(self->_keytype_dropdown) == 0 ? MfcKeyType::A : MfcKeyType::B;

    uint8_t data[16];
    const uint16_t status = self->_ctx.client().ReadMifareBlock(block, key_type, key, data);
    if (status != HF_TAG_OK) {
        lv_label_set_text_fmt(self->_detail_label, "read block %u failed\nstatus: %s (0x%02X)", block,
                              StatusText(status), status);
        self->_ctx.LogEvent("MF1_READ_ONE_BLOCK %u: %s", block, StatusText(status));
        return;
    }

    char hex[64];
    format_hex(data, sizeof(data), hex, sizeof(hex));
    lv_textarea_set_text(self->_data_input, hex);
    lv_label_set_text_fmt(self->_detail_label, "read block %u ok\ndata %s", block, hex);
    self->_ctx.LogEvent("MF1_READ_ONE_BLOCK %u ok: %s", block, hex);
}

bool CardPage::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    // The key and block-data fields accept physical typing: hex digits, plus
    // Backspace. Enter reads the block, which is the common loop when walking a
    // card (type a block number, press Enter, look at the data).
    lv_obj_t* target = nullptr;
    if (_key_input != nullptr && lv_obj_has_state(_key_input, LV_STATE_FOCUSED)) {
        target = _key_input;
    } else if (_data_input != nullptr && lv_obj_has_state(_data_input, LV_STATE_FOCUSED)) {
        target = _data_input;
    }

    if (target == nullptr) {
        return false;
    }

    if (hid_key_code == ui::key::kBackspace) {
        lv_textarea_delete_char(target);
        return true;
    }
    if (hid_key_code == ui::key::kDelete) {
        lv_textarea_delete_char_forward(target);
        return true;
    }
    if (hid_key_code == ui::key::kEnter) {
        if (target == _key_input) {
            on_read_block(nullptr);
        } else {
            on_write_block(nullptr);
        }
        return true;
    }
    if (hid_key_code == ui::key::kEscape) {
        lv_obj_clear_state(target, LV_STATE_FOCUSED);
        if (_keyboard != nullptr) {
            lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
        }
        return true;
    }

    // Hex fields only take [0-9a-f]; everything else is rejected rather than
    // silently producing a key the parser would later reject.
    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c == 0) {
        return false;
    }
    const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!is_hex) {
        return false;
    }
    lv_textarea_add_char(target, static_cast<uint32_t>(c));
    return true;
}

void CardPage::on_write_block(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<CardPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected() || !self->ensureReaderMode()) {
        return;
    }

    uint8_t key[6];
    if (parse_hex(lv_textarea_get_text(self->_key_input), key, sizeof(key)) != sizeof(key)) {
        lv_label_set_text(self->_detail_label, "key must be exactly 6 bytes of hex");
        return;
    }

    uint8_t data[16];
    if (parse_hex(lv_textarea_get_text(self->_data_input), data, sizeof(data)) != sizeof(data)) {
        lv_label_set_text(self->_detail_label, "block data must be exactly 16 bytes of hex\n(32 hex digits)");
        return;
    }

    const uint8_t block = static_cast<uint8_t>(lv_spinbox_get_value(self->_block_spinbox));
    const auto key_type =
        lv_dropdown_get_selected(self->_keytype_dropdown) == 0 ? MfcKeyType::A : MfcKeyType::B;

    const uint16_t status = self->_ctx.client().WriteMifareBlock(block, key_type, key, data);
    if (status == HF_TAG_OK) {
        lv_label_set_text_fmt(self->_detail_label, "wrote block %u ok", block);
        self->_ctx.LogEvent("MF1_WRITE_ONE_BLOCK %u ok", block);
    } else {
        lv_label_set_text_fmt(self->_detail_label, "write block %u failed\nstatus: %s (0x%02X)", block,
                              StatusText(status), status);
        self->_ctx.LogEvent("MF1_WRITE_ONE_BLOCK %u: %s", block, StatusText(status));
    }
}

}  // namespace app
