// SPDX-License-Identifier: MIT
//
// Mifare Classic key recovery page.
//
// Two ways to get a key, both driven through the Chameleon:
//
//   1. "check factory keys" - the device tries a built-in list of factory and
//      transport keys against every sector (MF1_CHECK_KEYS_OF_SECTORS). This is
//      instant and covers the common case of a card nobody ever re-keyed.
//
//   2. "darkside attack" - the device collects the material for the classic
//      darkside attack one attempt at a time (MF1_DARKSIDE_ACQUIRE), the Tab5
//      turns it into candidate keys (see components/chameleon_crypto/darkside.h)
//      and every candidate is confirmed with an actual authentication before it
//      is reported.
//
// Both run on the Context key job task because they take tens of seconds. This
// page only starts the job and renders its progress.

#include "pages.h"

#include <stdio.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

#include "app_context.h"

namespace app {

namespace {

using namespace chameleon;

/// Copy of the live page instance for the keyboard path, which has no event.
KeysPage* s_active = nullptr;

}  // namespace

void KeysPage::Create(lv_obj_t* parent)
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

    // ---------------- left: what to attack ----------------
    lv_obj_t* left = lv_obj_create(_root);
    lv_obj_set_size(left, 470, lv_pct(100));
    lv_obj_set_style_bg_color(left, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(left, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(left, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 14, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "mifare classic key recovery");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t* block_caption = lv_label_create(left);
    lv_label_set_text(block_caption, "target block");
    lv_obj_set_style_text_font(block_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(block_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(block_caption, LV_ALIGN_TOP_LEFT, 0, 40);

    _block_spinbox = lv_spinbox_create(left);
    lv_spinbox_set_range(_block_spinbox, 0, 255);
    lv_spinbox_set_digit_format(_block_spinbox, 3, 0);
    lv_spinbox_set_value(_block_spinbox, 3);  // block 3 = sector 0 trailer, the usual target
    lv_obj_set_size(_block_spinbox, 130, 44);
    lv_obj_set_style_text_font(_block_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_block_spinbox, LV_ALIGN_TOP_LEFT, 0, 60);

    lv_obj_t* minus = lv_button_create(left);
    lv_obj_set_size(minus, 44, 44);
    lv_obj_set_style_radius(minus, 8, LV_PART_MAIN);
    lv_obj_align(minus, LV_ALIGN_TOP_LEFT, 138, 60);
    lv_obj_set_user_data(minus, (void*)(intptr_t)-1);
    lv_obj_add_event_cb(minus, on_block_step, LV_EVENT_CLICKED, this);
    lv_obj_t* minus_label = lv_label_create(minus);
    lv_label_set_text(minus_label, "-");
    lv_obj_set_style_text_font(minus_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_center(minus_label);

    lv_obj_t* plus = lv_button_create(left);
    lv_obj_set_size(plus, 44, 44);
    lv_obj_set_style_radius(plus, 8, LV_PART_MAIN);
    lv_obj_align(plus, LV_ALIGN_TOP_LEFT, 186, 60);
    lv_obj_set_user_data(plus, (void*)(intptr_t)1);
    lv_obj_add_event_cb(plus, on_block_step, LV_EVENT_CLICKED, this);
    lv_obj_t* plus_label = lv_label_create(plus);
    lv_label_set_text(plus_label, "+");
    lv_obj_set_style_text_font(plus_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_center(plus_label);

    lv_obj_t* type_caption = lv_label_create(left);
    lv_label_set_text(type_caption, "key type");
    lv_obj_set_style_text_font(type_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(type_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(type_caption, LV_ALIGN_TOP_LEFT, 248, 40);

    _keytype_dropdown = lv_dropdown_create(left);
    lv_dropdown_set_options_static(_keytype_dropdown, "Key A\nKey B");
    lv_obj_set_size(_keytype_dropdown, 150, 44);
    lv_obj_set_style_text_font(_keytype_dropdown, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_keytype_dropdown, LV_ALIGN_TOP_LEFT, 248, 60);

    _check_btn = lv_button_create(left);
    lv_obj_set_size(_check_btn, 420, 52);
    lv_obj_set_style_radius(_check_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_check_btn, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_align(_check_btn, LV_ALIGN_TOP_LEFT, 0, 122);
    lv_obj_add_event_cb(_check_btn, on_check_keys, LV_EVENT_CLICKED, this);
    lv_obj_t* check_label = lv_label_create(_check_btn);
    lv_label_set_text(check_label, "check factory keys (fast)");
    lv_obj_set_style_text_font(check_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(check_label);

    _darkside_btn = lv_button_create(left);
    lv_obj_set_size(_darkside_btn, 270, 52);
    lv_obj_set_style_radius(_darkside_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_darkside_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_darkside_btn, LV_ALIGN_TOP_LEFT, 0, 184);
    lv_obj_add_event_cb(_darkside_btn, on_darkside, LV_EVENT_CLICKED, this);
    lv_obj_t* ds_label = lv_label_create(_darkside_btn);
    lv_label_set_text(ds_label, "darkside attack (slow)");
    lv_obj_set_style_text_font(ds_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(ds_label);

    _stop_btn = lv_button_create(left);
    lv_obj_set_size(_stop_btn, 140, 52);
    lv_obj_set_style_radius(_stop_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_stop_btn, lv_color_hex(ui::theme::kError), LV_PART_MAIN);
    lv_obj_align(_stop_btn, LV_ALIGN_TOP_LEFT, 280, 184);
    lv_obj_add_event_cb(_stop_btn, on_stop, LV_EVENT_CLICKED, this);
    lv_obj_t* stop_label = lv_label_create(_stop_btn);
    lv_label_set_text(stop_label, "stop");
    lv_obj_set_style_text_font(stop_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(stop_label);

    _status_label = lv_label_create(left);
    lv_label_set_text(_status_label, "idle");
    lv_obj_set_style_text_font(_status_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_status_label, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_set_width(_status_label, 420);
    lv_label_set_long_mode(_status_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_status_label, LV_ALIGN_TOP_LEFT, 0, 250);

    _hint_label = lv_label_create(left);
    lv_label_set_text(_hint_label,
                      "the card must be on the antenna and the device in\n"
                      "reader mode. every candidate key is confirmed with a\n"
                      "real authentication before it is reported.");
    lv_obj_set_style_text_font(_hint_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_hint_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_set_width(_hint_label, 420);
    lv_label_set_long_mode(_hint_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_hint_label, LV_ALIGN_TOP_LEFT, 0, 300);

    // ---------------- right: result ----------------
    lv_obj_t* right = lv_obj_create(_root);
    lv_obj_set_size(right, 740, lv_pct(100));
    lv_obj_set_style_bg_color(right, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(right, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(right, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 14, LV_PART_MAIN);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "recovered key");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    _result_label = lv_label_create(right);
    lv_label_set_text(_result_label, "------------");
    lv_obj_set_style_text_font(_result_label, ui::FontLarge, LV_PART_MAIN);
    lv_obj_set_style_text_color(_result_label, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_align(_result_label, LV_ALIGN_TOP_LEFT, 0, 40);

    _copy_btn = lv_button_create(right);
    lv_obj_set_size(_copy_btn, 300, 48);
    lv_obj_set_style_radius(_copy_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_copy_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_copy_btn, LV_ALIGN_TOP_LEFT, 0, 100);
    lv_obj_add_event_cb(_copy_btn, on_copy_key, LV_EVENT_CLICKED, this);
    lv_obj_t* copy_label = lv_label_create(_copy_btn);
    lv_label_set_text(copy_label, "use this key on the Cards page");
    lv_obj_set_style_text_font(copy_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(copy_label);

    lv_obj_t* log_caption = lv_label_create(right);
    lv_label_set_text(log_caption, "the Log tab has the per-sector and per-attempt detail");
    lv_obj_set_style_text_font(log_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(log_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(log_caption, LV_ALIGN_TOP_LEFT, 0, 160);

    // ---- nested attack ----
    // Nested recovers the key of one sector using a key you already have on
    // another. The known side is whatever key this page last confirmed (the
    // factory key check or a darkside round); the target is the block and type
    // selected above. MF1_DETECT_PRNG decides which attack the card allows.
    lv_obj_t* nested_caption = lv_label_create(right);
    lv_label_set_text(nested_caption, "nested (needs a key you already have)");
    lv_obj_set_style_text_font(nested_caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(nested_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(nested_caption, LV_ALIGN_TOP_LEFT, 0, 210);

    _nested_btn = lv_button_create(right);
    lv_obj_set_size(_nested_btn, 300, 48);
    lv_obj_set_style_radius(_nested_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_nested_btn, lv_color_hex(ui::theme::kWarn), LV_PART_MAIN);
    lv_obj_align(_nested_btn, LV_ALIGN_TOP_LEFT, 0, 240);
    lv_obj_add_event_cb(_nested_btn, on_nested, LV_EVENT_CLICKED, this);
    lv_obj_t* nested_label = lv_label_create(_nested_btn);
    lv_label_set_text(nested_label, "nested attack");
    lv_obj_set_style_text_font(nested_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(nested_label);

    lv_obj_t* nested_hint = lv_label_create(right);
    lv_label_set_text(nested_hint,
                      "uses the key last confirmed on this page as the known side,\n"
                      "and targets the block and key type selected above.\n"
                      "the device reports which attack the card allows.");
    lv_obj_set_style_text_font(nested_hint, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(nested_hint, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(nested_hint, LV_ALIGN_TOP_LEFT, 0, 300);

    // ---- hardnested ----
    // A hardened card refuses the plain nested attack, and the ciphertext-only
    // attack that beats it needs gigabytes of bitflip tables, so the Tab5 does
    // the half that has to be next to the card: acquire the nonces and write the
    // file the PC solver reads. Pressing the button prints it to the console.
    lv_obj_t* hn_caption = lv_label_create(right);
    lv_label_set_text(hn_caption, "hardnested (nonce file for the PC solver)");
    lv_obj_set_style_text_font(hn_caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(hn_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(hn_caption, LV_ALIGN_TOP_LEFT, 0, 380);

    _hardnested_btn = lv_button_create(right);
    lv_obj_set_size(_hardnested_btn, 300, 48);
    lv_obj_set_style_radius(_hardnested_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_hardnested_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(_hardnested_btn, LV_ALIGN_TOP_LEFT, 0, 410);
    lv_obj_add_event_cb(_hardnested_btn, on_hardnested, LV_EVENT_CLICKED, this);
    lv_obj_t* hn_label = lv_label_create(_hardnested_btn);
    lv_label_set_text(hn_label, "acquire hardnested nonces");
    lv_obj_set_style_text_font(hn_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(hn_label);

    _hn_slow_btn = lv_button_create(right);
    lv_obj_set_size(_hn_slow_btn, 110, 48);
    lv_obj_set_style_radius(_hn_slow_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_hn_slow_btn, lv_color_hex(ui::theme::kSurfaceHi), LV_PART_MAIN);
    lv_obj_align(_hn_slow_btn, LV_ALIGN_TOP_LEFT, 310, 410);
    lv_obj_add_event_cb(_hn_slow_btn, on_hardnested_slow, LV_EVENT_CLICKED, this);
    _hn_slow_label = lv_label_create(_hn_slow_btn);
    lv_label_set_text(_hn_slow_label, "fast");
    lv_obj_set_style_text_font(_hn_slow_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(_hn_slow_label);

    _hn_export_btn = lv_button_create(right);
    lv_obj_set_size(_hn_export_btn, 200, 48);
    lv_obj_set_style_radius(_hn_export_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_hn_export_btn, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_align(_hn_export_btn, LV_ALIGN_TOP_LEFT, 430, 410);
    lv_obj_add_event_cb(_hn_export_btn, on_export_nonces, LV_EVENT_CLICKED, this);
    lv_obj_t* export_label = lv_label_create(_hn_export_btn);
    lv_label_set_text(export_label, "export nonces");
    lv_obj_set_style_text_font(export_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(export_label);

    _hn_info_label = lv_label_create(right);
    lv_label_set_text(_hn_info_label, "no nonce file yet");
    lv_obj_set_style_text_font(_hn_info_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_hn_info_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_set_width(_hn_info_label, 700);
    lv_label_set_long_mode(_hn_info_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_hn_info_label, LV_ALIGN_TOP_LEFT, 0, 466);

    updateLabels();
}

void KeysPage::Destroy()
{
    if (s_active == this) {
        s_active = nullptr;
    }
    ui::Page::Destroy();
}

uint8_t KeysPage::selectedBlock() const
{
    return _block_spinbox != nullptr ? static_cast<uint8_t>(lv_spinbox_get_value(_block_spinbox)) : 0;
}

chameleon::MfcKeyType KeysPage::selectedKeyType() const
{
    return (_keytype_dropdown != nullptr && lv_dropdown_get_selected(_keytype_dropdown) != 0) ? MfcKeyType::B
                                                                                             : MfcKeyType::A;
}

void KeysPage::updateLabels()
{
    if (_result_label != nullptr) {
        uint8_t key[6];
        if (_ctx.foundKey(key)) {
            lv_label_set_text_fmt(_result_label, "%02X%02X%02X%02X%02X%02X", key[0], key[1], key[2], key[3], key[4],
                                  key[5]);
        } else {
            lv_label_set_text(_result_label, "------------");
        }
    }

    const bool running = _ctx.keyJob() != Context::KeyJob::Idle;
    if (_status_label != nullptr) {
        lv_label_set_text(_status_label, running ? _ctx.keyJobStatus() : "idle");
    }

    const bool online = _ctx.connected();
    lv_obj_t* buttons[6] = {_check_btn, _darkside_btn, _nested_btn, _hardnested_btn, _hn_slow_btn, _stop_btn};
    for (lv_obj_t* b : buttons) {
        if (b == nullptr) {
            continue;
        }
        const bool disable = (b == _stop_btn) ? !running : (!online || running);
        if (disable) {
            lv_obj_add_state(b, LV_STATE_DISABLED);
        } else {
            lv_obj_remove_state(b, LV_STATE_DISABLED);
        }
    }
    if (_hn_export_btn != nullptr) {
        // Exporting is a local operation, so it does not need the device - only
        // a file that was already acquired.
        if (_ctx.hasHardNestedFile() && !running) {
            lv_obj_remove_state(_hn_export_btn, LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(_hn_export_btn, LV_STATE_DISABLED);
        }
    }
    if (_hn_info_label != nullptr) {
        if (_ctx.hasHardNestedFile()) {
            lv_label_set_text_fmt(_hn_info_label,
                                  "%u records (%u nonces) acquired, parity sum %u.\n"
                                  "'export nonces' prints them to the serial console; run\n"
                                  "tools/nonce_file_from_console.py on the capture to rebuild\n"
                                  "the file, then feed it to HardnestedRecovery on a PC.",
                                  (unsigned)_ctx.hardNestedRecords(), (unsigned)(_ctx.hardNestedRecords() * 2),
                                  (unsigned)_ctx.hardNestedParitySum());
        } else {
            lv_label_set_text(_hn_info_label,
                              "acquires a nonce file for the ciphertext-only attack on a\n"
                              "hardened card. the solver needs gigabytes of bitflip tables, so\n"
                              "it runs on a PC: this page produces the file it reads.");
        }
    }
    if (_hn_slow_label != nullptr) {
        lv_label_set_text(_hn_slow_label, _slow ? "slow" : "fast");
    }
    if (_copy_btn != nullptr) {
        if (_ctx.hasFoundKey()) {
            lv_obj_remove_state(_copy_btn, LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(_copy_btn, LV_STATE_DISABLED);
        }
    }
}

void KeysPage::Refresh()
{
    updateLabels();
}

void KeysPage::on_block_step(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
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

void KeysPage::on_check_keys(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    if (!self->_ctx.StartKeyCheck(self->selectedBlock(), self->selectedKeyType())) {
        self->_ctx.LogEvent("key check not started (busy or device offline)");
    }
    self->updateLabels();
}

void KeysPage::on_nested(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }

    // The known side has to be a key the card already accepted, otherwise the
    // acquisition returns nothing and the attack cannot start.
    uint8_t known_key[6];
    if (!self->_ctx.foundKey(known_key)) {
        lv_label_set_text(self->_status_label,
                          "nested needs a key you already have.\n"
                          "run 'check factory keys' first, or a darkside round.");
        self->_ctx.LogEvent("nested: no known key yet");
        return;
    }

    char hex[16];
    snprintf(hex, sizeof(hex), "%02X%02X%02X%02X%02X%02X", known_key[0], known_key[1], known_key[2], known_key[3],
             known_key[4], known_key[5]);
    self->_ctx.LogEvent("nested: known key %s on block %u, target block %u", hex,
                        (unsigned)self->_ctx.foundKeyBlock(), (unsigned)self->selectedBlock());

    if (!self->_ctx.StartNested(self->_ctx.foundKeyBlock(), self->_ctx.foundKeyType(), known_key,
                                self->selectedBlock(), self->selectedKeyType())) {
        self->_ctx.LogEvent("nested not started (busy or device offline)");
    }
    self->updateLabels();
}

void KeysPage::on_darkside(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    if (!self->_ctx.StartDarkside(self->selectedBlock(), self->selectedKeyType())) {
        self->_ctx.LogEvent("darkside not started (busy or device offline)");
    }
    self->updateLabels();
}

void KeysPage::on_hardnested(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }

    // Like nested, hardnested needs one key the card already accepts: it is the
    // key the device authenticates with before asking for the target sector's
    // nonces.
    uint8_t known_key[6];
    if (!self->_ctx.foundKey(known_key)) {
        lv_label_set_text(self->_status_label,
                          "hardnested needs a key you already have.\n"
                          "run 'check factory keys' first, or a darkside round.");
        self->_ctx.LogEvent("hardnested: no known key yet");
        return;
    }

    char hex[16];
    snprintf(hex, sizeof(hex), "%02X%02X%02X%02X%02X%02X", known_key[0], known_key[1], known_key[2], known_key[3],
             known_key[4], known_key[5]);
    self->_ctx.LogEvent("hardnested: known key %s on block %u, target block %u", hex,
                        (unsigned)self->_ctx.foundKeyBlock(), (unsigned)self->selectedBlock());

    if (!self->_ctx.StartHardNested(self->_ctx.foundKeyBlock(), self->_ctx.foundKeyType(), known_key,
                                    self->selectedBlock(), self->selectedKeyType(), self->_slow)) {
        self->_ctx.LogEvent("hardnested not started (busy, device offline or no PSRAM)");
    }
    self->updateLabels();
}

void KeysPage::on_hardnested_slow(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_slow = !self->_slow;
    // The CLI's --slow flag: some non-standard cards only answer reliably when
    // the device pauses between the two authentications of a run.
    self->_ctx.LogEvent("hardnested: %s acquisition mode", self->_slow ? "slow" : "fast");
    self->updateLabels();
}

void KeysPage::on_export_nonces(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    if (!self->_ctx.hasHardNestedFile()) {
        self->_ctx.LogEvent("hardnested: no nonce file to export");
        return;
    }
    // Clear first so the capture holds the file and nothing else: the console
    // sees every line, but the on-screen log is a 200 line ring and the export
    // can be thousands of lines.
    self->_ctx.ClearLog();
    self->_ctx.ExportHardNestedNonces();
    // The export is a series of log lines; the Log tab is where the user sees it
    // and the serial console is where the host captures it.
    self->_ctx.shell().ShowPage(6);
}

void KeysPage::on_stop(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_ctx.StopKeyJob();
    self->updateLabels();
}

void KeysPage::on_copy_key(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<KeysPage*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    if (!self->_ctx.hasFoundKey()) {
        return;
    }
    // The Cards page reads the found key from the context, so switching tabs is
    // all that is needed.
    self->_ctx.LogEvent("switching to Cards with the recovered key");
    self->_ctx.shell().ShowPage(2);
}

bool KeysPage::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    // Enter starts the fast check, D starts the darkside attack. Neither key
    // clashes with a text field on this page (there are none).
    if (hid_key_code == ui::key::kEnter) {
        on_check_keys(nullptr);
        return true;
    }
    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c == 'd' || c == 'D') {
        on_darkside(nullptr);
        return true;
    }
    if (c == 's' || c == 'S') {
        on_stop(nullptr);
        return true;
    }
    return false;
}

}  // namespace app
