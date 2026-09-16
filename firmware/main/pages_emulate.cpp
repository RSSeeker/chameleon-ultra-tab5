// SPDX-License-Identifier: MIT
//
// Emulate page: configure the card the active slot presents.
//
// Everything on this page is device-side state (the slot's stored identity and
// block data), not something read off the RF field. That makes it the one part
// of the card feature set that can be verified end to end without a physical
// card: write a value, read it back, compare.
//
//   LF  - the emulated card number for whichever LF protocol the slot is set to
//         (EM410X / HIDProx / Viking / PAC / ioProx / Jablotron / IDTECK)
//   HF  - the emulated ISO14443-A anti-collision data: UID, ATQA, SAK, ATS
//   MF1 - the emulated Mifare Classic block contents
//
// The LF/HF tag *types* themselves are chosen on the Slots page; this page only
// fills in the data behind them.

#include "pages.h"

#include <stdio.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

#include "app_context.h"

namespace app {

namespace {

using namespace chameleon;

/// Copy of the live page instance for the keyboard path, which has no event.
EmulatePage* s_active = nullptr;

/// Parse a hex string ("FF00AB", separators allowed) into bytes.
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
            continue;
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

void format_hex(const uint8_t* data, size_t len, char* out, size_t out_size)
{
    size_t written = 0;
    out[0]         = '\0';
    for (size_t i = 0; i < len; ++i) {
        const int r = snprintf(out + written, out_size - written, "%02X", data[i]);
        if (r <= 0 || static_cast<size_t>(r) >= out_size - written) {
            return;
        }
        written += static_cast<size_t>(r);
    }
}

/// A caption plus a one line hex textarea, the shape every field here shares.
lv_obj_t* make_field(lv_obj_t* parent, const char* caption, lv_coord_t x, lv_coord_t y, lv_coord_t width,
                     uint32_t max_length, lv_event_cb_t on_focus, void* user)
{
    lv_obj_t* label = lv_label_create(parent);
    lv_label_set_text(label, caption);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, x, y);

    lv_obj_t* input = lv_textarea_create(parent);
    lv_textarea_set_one_line(input, true);
    lv_textarea_set_max_length(input, max_length);
    lv_textarea_set_text(input, "");
    lv_obj_set_size(input, width, 42);
    lv_obj_set_style_text_font(input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(input, LV_ALIGN_TOP_LEFT, x, y + 16);
    lv_obj_add_event_cb(input, on_focus, LV_EVENT_FOCUSED, user);
    return input;
}

lv_obj_t* make_button(lv_obj_t* parent, const char* text, lv_coord_t x, lv_coord_t y, lv_coord_t width,
                      lv_coord_t height, uint32_t colour, lv_event_cb_t cb, void* user)
{
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_set_size(button, width, height);
    lv_obj_set_style_radius(button, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(button, lv_color_hex(colour), LV_PART_MAIN);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, y);
    lv_obj_add_event_cb(button, cb, LV_EVENT_CLICKED, user);

    lv_obj_t* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(label);
    return button;
}

}  // namespace

void EmulatePage::Create(lv_obj_t* parent)
{
    s_active = this;

    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(_root, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_column(_root, 12, LV_PART_MAIN);
    lv_obj_set_flex_flow(_root, LV_FLEX_FLOW_ROW);
    lv_obj_clear_flag(_root, LV_OBJ_FLAG_SCROLLABLE);

    // ---------------- left: emulated identity ----------------
    lv_obj_t* left = lv_obj_create(_root);
    lv_obj_set_size(left, 700, lv_pct(100));
    lv_obj_set_style_bg_color(left, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(left, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(left, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 14, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "emulated identity (active slot)");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    _summary_label = lv_label_create(left);
    lv_label_set_text(_summary_label, "(loading slot info)");
    lv_obj_set_style_text_font(_summary_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_summary_label, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_set_width(_summary_label, 660);
    lv_label_set_long_mode(_summary_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_summary_label, LV_ALIGN_TOP_LEFT, 0, 28);

    _read_card_btn = make_button(left, "read everything from the device", 0, 66, 300, 40, ui::theme::kInfo,
                                 on_read_card, this);

    _lf_input = make_field(left, "LF card number (hex, length depends on the LF type above)", 0, 118, 330, 40,
                           on_field_focus, this);
    _write_lf_btn = make_button(left, "write LF", 344, 134, 120, 42, ui::theme::kAccentDim, on_write_lf, this);

    _uid_input = make_field(left, "HF UID (hex)", 0, 176, 330, 24, on_field_focus, this);
    _write_hf_btn = make_button(left, "write HF", 344, 192, 120, 42, ui::theme::kAccentDim, on_write_hf, this);

    _atqa_input = make_field(left, "ATQA", 0, 228, 100, 6, on_field_focus, this);
    _sak_input  = make_field(left, "SAK", 112, 228, 70, 4, on_field_focus, this);
    _ats_input  = make_field(left, "ATS (hex, may be empty)", 194, 228, 260, 40, on_field_focus, this);

    _status_label = lv_label_create(left);
    lv_label_set_text(_status_label, "ready");
    lv_obj_set_style_text_font(_status_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_status_label, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_set_width(_status_label, 660);
    lv_label_set_long_mode(_status_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_status_label, LV_ALIGN_TOP_LEFT, 0, 284);

    // ---- classic emulator options ----
    // These decide how the emulated Mifare Classic behaves towards a real
    // reader: the magic (gen1a/gen2) modes, whether the stored block 0 is fed
    // back as the anti-collision answer, write handling and the PRNG the card
    // should appear to have. All device-side state, so a read-back verifies it.
    lv_obj_t* opt_caption = lv_label_create(left);
    lv_label_set_text(opt_caption, "classic emulator options");
    lv_obj_set_style_text_font(opt_caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(opt_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(opt_caption, LV_ALIGN_TOP_LEFT, 0, 330);

    _options_label = lv_label_create(left);
    lv_label_set_text(_options_label, "(press read to load)");
    lv_obj_set_style_text_font(_options_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_options_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_set_width(_options_label, 660);
    lv_label_set_long_mode(_options_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_options_label, LV_ALIGN_TOP_LEFT, 0, 356);

    static const char* kOptionNames[5] = {"gen1a magic", "gen2 magic", "block anti-coll", "detect", "use mf1 coll"};
    for (int i = 0; i < 5; ++i) {
        const lv_coord_t x = static_cast<lv_coord_t>((i % 3) * 224);
        const lv_coord_t y = static_cast<lv_coord_t>(382 + (i / 3) * 50);
        _options_btn[i]    = make_button(left, kOptionNames[i], x, y, 210, 42, ui::theme::kSurfaceHi, on_toggle, this);
        lv_obj_set_user_data(_options_btn[i], (void*)(intptr_t)i);
    }
    _write_mode_btn = make_button(left, "write mode: -", 224, 432, 210, 42, ui::theme::kInfo, on_cycle_write_mode,
                                  this);
    _prng_btn = make_button(left, "prng: -", 448, 432, 210, 42, ui::theme::kInfo, on_cycle_prng, this);
    make_button(left, "read options", 0, 432, 210, 42, ui::theme::kAccentDim, on_read_options, this);

    _keyboard = lv_keyboard_create(left);
    lv_obj_set_size(_keyboard, 670, 200);
    lv_obj_align(_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_READY, this);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_CANCEL, this);

    // ---------------- right: emulated classic blocks ----------------
    lv_obj_t* right = lv_obj_create(_root);
    lv_obj_set_size(right, 520, lv_pct(100));
    lv_obj_set_style_bg_color(right, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(right, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(right, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 14, LV_PART_MAIN);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "emulated classic blocks");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t* hint = lv_label_create(right);
    lv_label_set_text(hint, "the data the slot answers with when a reader\nrequests these blocks");
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(hint, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(hint, LV_ALIGN_TOP_LEFT, 0, 28);

    lv_obj_t* block_caption = lv_label_create(right);
    lv_label_set_text(block_caption, "block");
    lv_obj_set_style_text_font(block_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(block_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(block_caption, LV_ALIGN_TOP_LEFT, 0, 76);

    _block_spinbox = lv_spinbox_create(right);
    lv_spinbox_set_range(_block_spinbox, 0, 255);
    lv_spinbox_set_digit_format(_block_spinbox, 3, 0);
    lv_obj_set_size(_block_spinbox, 120, 42);
    lv_obj_set_style_text_font(_block_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_block_spinbox, LV_ALIGN_TOP_LEFT, 0, 94);

    lv_obj_t* minus = make_button(right, "-", 128, 94, 42, 42, ui::theme::kSurfaceHi, on_block_step, this);
    lv_obj_set_user_data(minus, (void*)(intptr_t)-1);
    lv_obj_t* plus = make_button(right, "+", 176, 94, 42, 42, ui::theme::kSurfaceHi, on_block_step, this);
    lv_obj_set_user_data(plus, (void*)(intptr_t)1);

    _read_block_btn  = make_button(right, "read", 236, 94, 110, 42, ui::theme::kInfo, on_read_block, this);
    _write_block_btn = make_button(right, "write", 356, 94, 110, 42, ui::theme::kError, on_write_block, this);

    lv_obj_t* data_caption = lv_label_create(right);
    lv_label_set_text(data_caption, "block data (hex, 16 bytes)");
    lv_obj_set_style_text_font(data_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(data_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(data_caption, LV_ALIGN_TOP_LEFT, 0, 146);

    _data_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_data_input, true);
    lv_textarea_set_max_length(_data_input, 40);
    lv_obj_set_size(_data_input, 470, 44);
    lv_obj_set_style_text_font(_data_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_data_input, LV_ALIGN_TOP_LEFT, 0, 166);
    lv_obj_add_event_cb(_data_input, on_field_focus, LV_EVENT_FOCUSED, this);
}

void EmulatePage::Destroy()
{
    if (s_active == this) {
        s_active = nullptr;
    }
    ui::Page::Destroy();
}

bool EmulatePage::activeLfProtocol(chameleon::Client::LfEmuProtocol* out, size_t* id_length) const
{
    if (out == nullptr) {
        return false;
    }
    const uint8_t slot       = _ctx.client().activeSlot();
    const uint16_t lf_type   = _ctx.client().slotInfo(slot).lf_tag_type;
    chameleon::Client::LfEmuProtocol protocol;
    if (!chameleon::Client::LfEmuProtocolForTagType(lf_type, &protocol)) {
        return false;
    }
    *out = protocol;
    if (id_length != nullptr) {
        *id_length = (lf_type == EM410X_ELECTRA) ? 13 : chameleon::Client::LfEmuIdLength(protocol);
    }
    return true;
}

uint8_t EmulatePage::selectedBlock() const
{
    return _block_spinbox != nullptr ? static_cast<uint8_t>(lv_spinbox_get_value(_block_spinbox)) : 0;
}

lv_obj_t* EmulatePage::focusedField() const
{
    lv_obj_t* fields[] = {_lf_input, _uid_input, _atqa_input, _sak_input, _ats_input, _data_input};
    for (lv_obj_t* f : fields) {
        if (f != nullptr && lv_obj_has_state(f, LV_STATE_FOCUSED)) {
            return f;
        }
    }
    return nullptr;
}

void EmulatePage::updateSummary()
{
    if (_summary_label == nullptr) {
        return;
    }
    const uint8_t slot     = _ctx.client().activeSlot();
    const SlotInfo& info   = _ctx.client().slotInfo(slot);

    chameleon::Client::LfEmuProtocol protocol;
    size_t lf_len = 0;
    const bool has_lf = activeLfProtocol(&protocol, &lf_len);

    char lf_text[48];
    if (has_lf) {
        snprintf(lf_text, sizeof(lf_text), "LF type %u, id %u bytes", (unsigned)info.lf_tag_type, (unsigned)lf_len);
    } else {
        snprintf(lf_text, sizeof(lf_text), "LF type %u (no host configurable id)", (unsigned)info.lf_tag_type);
    }

    // Spell out that this is the *active* slot: the device's emulator commands
    // carry no slot parameter, so the only way to edit another slot is to make
    // it active on the Slots page first. Without this the page silently edits a
    // different slot than the one the user just changed.
    lv_label_set_text_fmt(_summary_label, "ACTIVE SLOT %u   %s   HF type %u   %s", (unsigned)(slot + 1), lf_text,
                          (unsigned)info.hf_tag_type, info.enabled_hf || info.enabled_lf ? "enabled" : "disabled");
}

void EmulatePage::updateOptions()
{
    if (_options_label == nullptr) {
        return;
    }
    if (!_options_valid) {
        lv_label_set_text(_options_label, "(press read options to load)");
        return;
    }

    const uint8_t flags[5] = {_config.gen1a_magic, _config.gen2_magic, _config.use_mf1_coll, _config.detection,
                              _config.use_mf1_coll};
    (void)flags;
    const uint8_t states[5] = {_config.gen1a_magic, _config.gen2_magic, _config.use_mf1_coll, _config.detection,
                               _config.use_mf1_coll};

    for (int i = 0; i < 5; ++i) {
        if (_options_btn[i] == nullptr) {
            continue;
        }
        lv_obj_set_style_bg_color(_options_btn[i],
                                  lv_color_hex(states[i] ? ui::theme::kAccentDim : ui::theme::kSurfaceHi),
                                  LV_PART_MAIN);
    }

    if (_write_mode_btn != nullptr) {
        static const char* kModes[] = {"normal", "denied", "deceive", "shadow", "shadow+req"};
        const char* name = (_config.write_mode < 5) ? kModes[_config.write_mode] : "?";
        lv_obj_t* label  = lv_obj_get_child(_write_mode_btn, 0);
        if (label != nullptr) {
            lv_label_set_text_fmt(label, "write mode: %s", name);
        }
    }
    if (_prng_btn != nullptr) {
        static const char* kPrng[] = {"weak", "static", "hard"};
        const char* name = (_prng_type < 3) ? kPrng[_prng_type] : "?";
        lv_obj_t* label  = lv_obj_get_child(_prng_btn, 0);
        if (label != nullptr) {
            lv_label_set_text_fmt(label, "prng: %s", name);
        }
    }

    lv_label_set_text_fmt(_options_label, "detection %u   gen1a %u   gen2 %u   coll %u   write mode %u   prng %u",
                          (unsigned)_config.detection, (unsigned)_config.gen1a_magic, (unsigned)_config.gen2_magic,
                          (unsigned)_config.use_mf1_coll, (unsigned)_config.write_mode, (unsigned)_prng_type);
}

void EmulatePage::Refresh()
{
    updateSummary();
}

void EmulatePage::on_read_options(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    const uint16_t cfg_status = self->_ctx.client().GetMf1EmulatorConfig(&self->_config);
    uint8_t prng              = 0;
    const uint16_t prng_status = self->_ctx.client().GetMf1Toggle(chameleon::Client::Mf1Toggle::PrngType, &prng);
    if (prng_status == chameleon::SUCCESS) {
        self->_prng_type = prng;
    }

    if (cfg_status == chameleon::SUCCESS) {
        self->_options_valid = true;
        self->updateOptions();
        lv_label_set_text(self->_status_label, "emulator options read");
        self->_ctx.LogEvent("emulate: MF1 options detection %u gen1a %u gen2 %u coll %u write_mode %u prng %u",
                            (unsigned)self->_config.detection, (unsigned)self->_config.gen1a_magic,
                            (unsigned)self->_config.gen2_magic, (unsigned)self->_config.use_mf1_coll,
                            (unsigned)self->_config.write_mode, (unsigned)self->_prng_type);
    } else {
        lv_label_set_text_fmt(self->_status_label, "options read failed: %s (0x%02X)",
                              chameleon::StatusText(cfg_status), cfg_status);
        self->_ctx.LogEvent("emulate: MF1 options read FAILED: %s (0x%02X)", chameleon::StatusText(cfg_status),
                            cfg_status);
    }
}

void EmulatePage::on_toggle(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const int index = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    if (index < 0 || index > 3) {
        return;
    }

    // Button 2 is "block anti-coll", which is the device's *use mf1 coll res*
    // flag; button 4 in the array is a duplicate display-only entry.
    static const chameleon::Client::Mf1Toggle kWhich[4] = {
        chameleon::Client::Mf1Toggle::Gen1aMagic,
        chameleon::Client::Mf1Toggle::Gen2Magic,
        chameleon::Client::Mf1Toggle::BlockAntiColl,
        chameleon::Client::Mf1Toggle::Detection,
    };
    static const char* kNames[4] = {"gen1a magic", "gen2 magic", "block anti-coll", "detection"};

    // Read first so a stale local cache cannot invert the setting.
    uint8_t current = 0;
    const uint16_t read_status = self->_ctx.client().GetMf1Toggle(kWhich[index], &current);
    if (read_status != chameleon::SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "read %s failed: %s (0x%02X)", kNames[index],
                              chameleon::StatusText(read_status), read_status);
        self->_ctx.LogEvent("emulate: read %s FAILED: %s (0x%02X)", kNames[index],
                            chameleon::StatusText(read_status), read_status);
        return;
    }

    const uint8_t next         = current ? 0 : 1;
    const uint16_t set_status  = self->_ctx.client().SetMf1Toggle(kWhich[index], next);
    if (set_status != chameleon::SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "set %s failed: %s (0x%02X)", kNames[index],
                              chameleon::StatusText(set_status), set_status);
        self->_ctx.LogEvent("emulate: set %s FAILED: %s (0x%02X)", kNames[index], chameleon::StatusText(set_status),
                            set_status);
        return;
    }

    lv_label_set_text_fmt(self->_status_label, "%s -> %s", kNames[index], next ? "on" : "off");
    self->_ctx.LogEvent("emulate: %s set to %u", kNames[index], (unsigned)next);
    // Re-read the whole config so the buttons always show device state.
    self->on_read_options(nullptr);
}

void EmulatePage::on_cycle_write_mode(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t current = 0;
    if (self->_ctx.client().GetMf1Toggle(chameleon::Client::Mf1Toggle::WriteMode, &current) != chameleon::SUCCESS) {
        lv_label_set_text(self->_status_label, "could not read the write mode");
        self->_ctx.LogEvent("emulate: write mode read FAILED");
        return;
    }
    // MF1_SET_WRITE_MODE rejects anything above 3 (app_cmd.c), so the cycle
    // covers 0..3 even though the getter has been seen to answer 31.
    const uint8_t next    = static_cast<uint8_t>((current + 1) % chameleon::Client::kMf1WriteModeCount);
    const uint16_t status = self->_ctx.client().SetMf1Toggle(chameleon::Client::Mf1Toggle::WriteMode, next);
    if (status == chameleon::SUCCESS) {
        self->_config.write_mode = next;
        self->_options_valid     = true;
        self->updateOptions();
        lv_label_set_text_fmt(self->_status_label, "write mode -> %u (read back %u)", (unsigned)next,
                              (unsigned)current);
        self->_ctx.LogEvent("emulate: write mode set to %u (was %u)", (unsigned)next, (unsigned)current);
    } else {
        lv_label_set_text_fmt(self->_status_label, "write mode failed: %s (0x%02X)", chameleon::StatusText(status),
                              status);
        self->_ctx.LogEvent("emulate: write mode set FAILED: %s (0x%02X)", chameleon::StatusText(status), status);
    }
}

void EmulatePage::on_cycle_prng(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t current = 0;
    if (self->_ctx.client().GetMf1Toggle(chameleon::Client::Mf1Toggle::PrngType, &current) != chameleon::SUCCESS) {
        lv_label_set_text(self->_status_label, "could not read the prng type");
        self->_ctx.LogEvent("emulate: prng read FAILED");
        return;
    }
    // MF1_SET_PRNG_TYPE accepts 0..2 (app_cmd.c rejects anything above 2).
    const uint8_t next    = static_cast<uint8_t>((current + 1) % 3);
    const uint16_t status = self->_ctx.client().SetMf1Toggle(chameleon::Client::Mf1Toggle::PrngType, next);
    if (status == chameleon::SUCCESS) {
        self->_prng_type     = next;
        self->_options_valid = true;
        self->updateOptions();
        lv_label_set_text_fmt(self->_status_label, "prng -> %u", (unsigned)next);
        self->_ctx.LogEvent("emulate: prng type set to %u", (unsigned)next);
    } else {
        lv_label_set_text_fmt(self->_status_label, "prng failed: %s (0x%02X)", chameleon::StatusText(status), status);
        self->_ctx.LogEvent("emulate: prng set FAILED: %s (0x%02X)", chameleon::StatusText(status), status);
    }
}

void EmulatePage::on_field_focus(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_obj_remove_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_keyboard_set_textarea(self->_keyboard, lv_event_get_target_obj(e));
}

void EmulatePage::on_keyboard_event(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_obj_add_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
}

void EmulatePage::on_read_card(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    // The device keeps slot data per slot, so re-read the slot table first: the
    // user may have changed type or slot on the Slots page since the last poll.
    self->_ctx.RefreshSlotState();
    self->updateSummary();

    char text[256];
    int written = 0;

    // Every outcome is logged, including the failures. An earlier version only
    // logged "read card data" unconditionally, which made a failed read look
    // like a successful one in the console record.
    const uint8_t slot = self->_ctx.client().activeSlot();

    // ---- LF id ----
    chameleon::Client::LfEmuProtocol protocol;
    size_t lf_len = 0;
    if (self->activeLfProtocol(&protocol, &lf_len)) {
        uint8_t id[32] = {};
        size_t got     = 0;
        const uint16_t status = self->_ctx.client().GetLfEmuId(protocol, id, sizeof(id), &got);
        if (status == chameleon::SUCCESS && got > 0) {
            char hex[80];
            format_hex(id, got, hex, sizeof(hex));
            lv_textarea_set_text(self->_lf_input, hex);
            written += snprintf(text + written, sizeof(text) - written, "LF id read (%u bytes)\n", (unsigned)got);
            self->_ctx.LogEvent("emulate: slot %u LF id read, %u bytes %s", (unsigned)(slot + 1), (unsigned)got, hex);
        } else {
            written += snprintf(text + written, sizeof(text) - written, "LF id read failed: %s (0x%02X)\n",
                                chameleon::StatusText(status), status);
            self->_ctx.LogEvent("emulate: slot %u LF id read FAILED: %s (0x%02X)", (unsigned)(slot + 1),
                                chameleon::StatusText(status), status);
        }
    } else {
        written += snprintf(text + written, sizeof(text) - written,
                            "active slot has no configurable LF id (set the LF type on Slots)\n");
        self->_ctx.LogEvent("emulate: slot %u LF type %u has no configurable id", (unsigned)(slot + 1),
                            (unsigned)self->_ctx.client().slotInfo(slot).lf_tag_type);
    }

    // ---- HF anti-collision data ----
    HfTag tag;
    const uint16_t status = self->_ctx.client().GetHfAntiColl(&tag);
    if (status == chameleon::SUCCESS) {
        // ATQA/SAK/ATS are filled in even when the slot has no UID yet: the
        // device returns them with a zero length UID, and prefilling them means
        // the user only has to type the UID before pressing write.
        char hex[80];
        snprintf(hex, sizeof(hex), "%02X%02X", tag.atqa[0], tag.atqa[1]);
        lv_textarea_set_text(self->_atqa_input, hex);
        snprintf(hex, sizeof(hex), "%02X", tag.sak);
        lv_textarea_set_text(self->_sak_input, hex);
        format_hex(tag.ats, tag.ats_length, hex, sizeof(hex));
        lv_textarea_set_text(self->_ats_input, hex);

        if (tag.uid_length > 0) {
            format_hex(tag.uid, tag.uid_length, hex, sizeof(hex));
            lv_textarea_set_text(self->_uid_input, hex);
            written += snprintf(text + written, sizeof(text) - written, "HF identity read (%u byte UID, SAK %02X)",
                                (unsigned)tag.uid_length, tag.sak);
            self->_ctx.LogEvent("emulate: slot %u HF identity read, uidlen %u uid %s sak %02X atslen %u",
                                (unsigned)(slot + 1), (unsigned)tag.uid_length, hex, tag.sak,
                                (unsigned)tag.ats_length);
        } else {
            // The device answers SUCCESS with a zero length UID when the slot has
            // no emulated identity yet: "nothing configured", not a failure.
            written += snprintf(text + written, sizeof(text) - written,
                                "no HF UID configured on this slot yet.\n"
                                "ATQA/SAK came from the device - type a UID and press write HF.");
            self->_ctx.LogEvent("emulate: slot %u has no HF UID yet (atqa %02X%02X sak %02X)",
                                (unsigned)(slot + 1), tag.atqa[0], tag.atqa[1], tag.sak);
        }
    } else {
        written += snprintf(text + written, sizeof(text) - written, "HF identity read failed: %s (0x%02X)",
                            chameleon::StatusText(status), status);
        self->_ctx.LogEvent("emulate: slot %u HF identity read FAILED: %s (0x%02X)", (unsigned)(slot + 1),
                            chameleon::StatusText(status), status);
    }

    lv_label_set_text(self->_status_label, text);
}

void EmulatePage::on_write_lf(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    chameleon::Client::LfEmuProtocol protocol;
    size_t expected = 0;
    if (!self->activeLfProtocol(&protocol, &expected)) {
        const uint8_t slot     = self->_ctx.client().activeSlot();
        const uint16_t lf_type = self->_ctx.client().slotInfo(slot).lf_tag_type;
        lv_label_set_text_fmt(self->_status_label,
                              "the active slot (%u) has LF type %u, which has no configurable id.\n"
                              "set its LF tag type on the Slots page, then press Use on that slot.",
                              (unsigned)(slot + 1), (unsigned)lf_type);
        self->_ctx.LogEvent("emulate: LF write refused, slot %u LF type %u has no configurable id",
                            (unsigned)(slot + 1), (unsigned)lf_type);
        return;
    }

    uint8_t id[32];
    const size_t got = parse_hex(lv_textarea_get_text(self->_lf_input), id, sizeof(id));
    if (got != expected) {
        lv_label_set_text_fmt(self->_status_label, "LF id must be exactly %u bytes (%u hex digits), got %u",
                              (unsigned)expected, (unsigned)(expected * 2), (unsigned)got);
        self->_ctx.LogEvent("emulate: LF write refused, %u bytes typed but %u expected", (unsigned)got,
                            (unsigned)expected);
        return;
    }

    const uint16_t status = self->_ctx.client().SetLfEmuId(protocol, id, got);
    char hex[80];
    format_hex(id, got, hex, sizeof(hex));
    if (status == chameleon::SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "LF id written (%u bytes)\n%s", (unsigned)got, hex);
        self->_ctx.LogEvent("emulate: slot %u LF id set, %u bytes %s", (unsigned)(self->_ctx.client().activeSlot() + 1),
                            (unsigned)got, hex);
    } else {
        lv_label_set_text_fmt(self->_status_label, "LF id write failed: %s (0x%02X)", chameleon::StatusText(status),
                              status);
        self->_ctx.LogEvent("emulate: LF id write FAILED: %s (0x%02X)", chameleon::StatusText(status), status);
    }
}

void EmulatePage::on_write_hf(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t uid[10];
    uint8_t atqa[2];
    uint8_t sak = 0;
    uint8_t ats[32];

    const size_t uid_len = parse_hex(lv_textarea_get_text(self->_uid_input), uid, sizeof(uid));
    if (uid_len != 4 && uid_len != 7 && uid_len != 10) {
        lv_label_set_text_fmt(self->_status_label,
                              "UID must be 4, 7 or 10 bytes, got %u.\n"
                              "press 'read everything' first if the fields are empty.",
                              (unsigned)uid_len);
        self->_ctx.LogEvent("emulate: HF write refused, UID is %u bytes", (unsigned)uid_len);
        return;
    }
    const size_t atqa_len = parse_hex(lv_textarea_get_text(self->_atqa_input), atqa, sizeof(atqa));
    if (atqa_len != 2) {
        lv_label_set_text_fmt(self->_status_label,
                              "ATQA must be 2 bytes (4 hex digits), got %u.\n"
                              "press 'read everything' first if the fields are empty.",
                              (unsigned)atqa_len);
        self->_ctx.LogEvent("emulate: HF write refused, ATQA is %u bytes", (unsigned)atqa_len);
        return;
    }
    parse_hex(lv_textarea_get_text(self->_sak_input), &sak, 1);
    const size_t ats_len = parse_hex(lv_textarea_get_text(self->_ats_input), ats, sizeof(ats));

    const bool ok = self->_ctx.client().SetHfAntiColl(uid, static_cast<uint8_t>(uid_len), atqa, sak, ats,
                                                      static_cast<uint8_t>(ats_len));
    char uid_hex[32];
    format_hex(uid, uid_len, uid_hex, sizeof(uid_hex));
    if (ok) {
        lv_label_set_text_fmt(self->_status_label, "HF identity written\nUID %s  SAK %02X  ATS %u bytes", uid_hex, sak,
                              (unsigned)ats_len);
        self->_ctx.LogEvent("emulate: slot %u HF identity set, uidlen %u uid %s sak %02X atslen %u",
                            (unsigned)(self->_ctx.client().activeSlot() + 1), (unsigned)uid_len, uid_hex, sak,
                            (unsigned)ats_len);
    } else {
        lv_label_set_text(self->_status_label,
                          "HF identity write failed (device refused the payload, or the link is busy)");
        self->_ctx.LogEvent("emulate: HF identity write FAILED (uidlen %u uid %s sak %02X atslen %u)",
                            (unsigned)uid_len, uid_hex, sak, (unsigned)ats_len);
    }
}

void EmulatePage::on_read_block(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t data[16] = {};
    size_t got       = 0;
    const uint16_t status = self->_ctx.client().ReadEmuBlocks(self->selectedBlock(), 1, data, sizeof(data), &got);
    if (status == chameleon::SUCCESS && got >= 16) {
        char hex[40];
        format_hex(data, 16, hex, sizeof(hex));
        lv_textarea_set_text(self->_data_input, hex);
        lv_label_set_text_fmt(self->_status_label, "block %u read", (unsigned)self->selectedBlock());
        self->_ctx.LogEvent("emulate: block %u read", (unsigned)self->selectedBlock());
    } else {
        lv_label_set_text_fmt(self->_status_label, "block read failed: %s (0x%02X)", chameleon::StatusText(status),
                              status);
        self->_ctx.LogEvent("emulate: block %u read FAILED: %s (0x%02X)", (unsigned)self->selectedBlock(),
                            chameleon::StatusText(status), status);
    }
}

void EmulatePage::on_write_block(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t data[16];
    if (parse_hex(lv_textarea_get_text(self->_data_input), data, sizeof(data)) != sizeof(data)) {
        lv_label_set_text(self->_status_label, "block data must be exactly 16 bytes (32 hex digits)");
        return;
    }

    if (self->_ctx.client().WriteEmuBlocks(self->selectedBlock(), data, sizeof(data))) {
        lv_label_set_text_fmt(self->_status_label, "block %u written", (unsigned)self->selectedBlock());
        self->_ctx.LogEvent("emulate: block %u set", (unsigned)self->selectedBlock());
    } else {
        lv_label_set_text(self->_status_label, "block write failed (device refused the payload or is busy)");
        self->_ctx.LogEvent("emulate: block %u write FAILED", (unsigned)self->selectedBlock());
    }
}

void EmulatePage::on_block_step(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<EmulatePage*>(lv_event_get_user_data(e)) : s_active;
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

bool EmulatePage::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    // Hex fields only, same rule as the Cards page: anything that is not a hex
    // digit is left for the shell so it does not silently corrupt a value.
    lv_obj_t* field = focusedField();
    if (field == nullptr) {
        return false;
    }

    if (hid_key_code == ui::key::kBackspace) {
        lv_textarea_delete_char(field);
        return true;
    }
    if (hid_key_code == ui::key::kDelete) {
        lv_textarea_delete_char_forward(field);
        return true;
    }
    if (hid_key_code == ui::key::kEscape) {
        lv_obj_clear_state(field, LV_STATE_FOCUSED);
        if (_keyboard != nullptr) {
            lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
        }
        return true;
    }
    if (hid_key_code == ui::key::kEnter) {
        // Enter reads the block for the data field, or re-reads the card for the
        // identity fields: the common "type a value then act" loop.
        if (field == _data_input) {
            on_read_block(nullptr);
        } else {
            on_read_card(nullptr);
        }
        return true;
    }

    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c == 0) {
        return false;
    }
    const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!is_hex) {
        return false;
    }
    lv_textarea_add_char(field, static_cast<uint32_t>(c));
    return true;
}

}  // namespace app
