// SPDX-License-Identifier: MIT
//
// UI pages: slot manager, device info/settings, protocol log.

#include "pages.h"

#include <stdio.h>
#include <string.h>

#include <esp_log.h>

#include <bsp/m5stack_tab5.h>
#include <esp_heap_caps.h>

#include "app_context.h"

namespace app {
namespace {

using namespace chameleon;

/// Tag types offered in the slot dropdowns.
///
/// Kept deliberately short: this is what the firmware can emulate and what a
/// user actually picks day to day. The full enum lives in chameleon_commands.h.
struct TagChoice {
    uint16_t type;
    const char* name;
};

/// HF (13.56 MHz) choices.
const TagChoice kHfChoices[] = {
    {TAG_UNDEFINED, "None"},
    {MIFARE_1024, "Mifare Classic 1K"},
    {MIFARE_2048, "Mifare Classic 2K"},
    {MIFARE_4096, "Mifare Classic 4K"},
    {MIFARE_Mini, "Mifare Mini"},
    {NTAG_213, "NTAG213"},
    {NTAG_215, "NTAG215"},
    {NTAG_216, "NTAG216"},
    {MF0UL11, "Ultralight EV1 640"},
    {MF0UL21, "Ultralight EV1 1312"},
    {MF0ICU1, "Mifare Ultralight"},
    {MF0ICU2, "Mifare Ultralight C"},
    {NTAG_210, "NTAG210"},
    {NTAG_212, "NTAG212"},
    {HF14A_4, "ISO14443-4 T=CL"},
    {SEOS, "SEOS"},
};

/// LF (125 kHz) choices.
const TagChoice kLfChoices[] = {
    {TAG_UNDEFINED, "None"},
    {EM410X, "EM410X"},
    {EM410X_16, "EM410X/16"},
    {EM410X_32, "EM410X/32"},
    {EM410X_64, "EM410X/64"},
    {EM410X_ELECTRA, "EM410X Electra"},
    {HIDProx, "HIDProx"},
    {ioProx, "ioProx"},
    {PAC, "PAC/Stanley"},
    {Viking, "Viking"},
    {Jablotron, "Jablotron"},
    {IDTECK, "IDTECK"},
};

constexpr size_t kHfChoiceCount = sizeof(kHfChoices) / sizeof(kHfChoices[0]);
constexpr size_t kLfChoiceCount = sizeof(kLfChoices) / sizeof(kLfChoices[0]);

/// Build the newline separated option string for an lv_dropdown.
void build_options(const TagChoice* choices, size_t count, char* out, size_t out_size)
{
    size_t written = 0;
    out[0]         = '\0';
    for (size_t i = 0; i < count; ++i) {
        const int n = snprintf(out + written, out_size - written, "%s%s", i == 0 ? "" : "\n", choices[i].name);
        if (n <= 0 || static_cast<size_t>(n) >= out_size - written) {
            return;
        }
        written += static_cast<size_t>(n);
    }
}

/// Index of a tag type inside a choice table, or 0 (None) when absent.
int choice_index(const TagChoice* choices, size_t count, uint16_t type)
{
    for (size_t i = 0; i < count; ++i) {
        if (choices[i].type == type) {
            return static_cast<int>(i);
        }
    }
    return 0;
}

lv_obj_t* make_card(lv_obj_t* parent)
{
    lv_obj_t* card = lv_obj_create(parent);
    lv_obj_set_style_bg_color(card, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(card, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(card, 10, LV_PART_MAIN);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    return card;
}

}  // namespace

// ===========================================================================
// SlotPage
// ===========================================================================

void SlotPage::Create(lv_obj_t* parent)
{
    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(_root, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_row(_root, 6, LV_PART_MAIN);
    lv_obj_set_flex_flow(_root, LV_FLEX_FLOW_COLUMN);
    lv_obj_clear_flag(_root, LV_OBJ_FLAG_SCROLLABLE);

    static char hf_options[512];
    static char lf_options[384];
    build_options(kHfChoices, kHfChoiceCount, hf_options, sizeof(hf_options));
    build_options(kLfChoices, kLfChoiceCount, lf_options, sizeof(lf_options));

    for (int i = 0; i < chameleon::kSlotCount; ++i) {
        Row& row = _rows[i];

        row.card = make_card(_root);
        lv_obj_set_size(row.card, lv_pct(100), 66);
        lv_obj_set_style_pad_all(row.card, 10, LV_PART_MAIN);

        // slot number
        row.slot_label = lv_label_create(row.card);
        lv_label_set_text_fmt(row.slot_label, "%d", i + 1);
        lv_obj_set_style_text_font(row.slot_label, ui::FontLarge, LV_PART_MAIN);
        lv_obj_set_style_text_color(row.slot_label, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
        lv_obj_align(row.slot_label, LV_ALIGN_LEFT_MID, 0, -12);

        // Nickname cell: the label shows the current nick, the button below it
        // opens the editor. Both sit in the narrow column left of the dropdowns.
        row.nick_label = lv_label_create(row.card);
        lv_label_set_text(row.nick_label, "-");
        lv_obj_set_style_text_font(row.nick_label, &lv_font_montserrat_12, LV_PART_MAIN);
        lv_obj_set_style_text_color(row.nick_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
        lv_obj_set_width(row.nick_label, 60);
        lv_label_set_long_mode(row.nick_label, LV_LABEL_LONG_DOT);
        lv_obj_align(row.nick_label, LV_ALIGN_LEFT_MID, 0, 8);

        row.rename_btn = lv_button_create(row.card);
        lv_obj_set_size(row.rename_btn, 56, 24);
        lv_obj_set_style_radius(row.rename_btn, 6, LV_PART_MAIN);
        lv_obj_set_style_bg_color(row.rename_btn, lv_color_hex(ui::theme::kSurfaceHi), LV_PART_MAIN);
        lv_obj_align(row.rename_btn, LV_ALIGN_LEFT_MID, 0, 19);
        lv_obj_add_event_cb(row.rename_btn, on_rename_clicked, LV_EVENT_CLICKED, this);
        lv_obj_set_user_data(row.rename_btn, (void*)(intptr_t)i);
        lv_obj_t* nick_btn_label = lv_label_create(row.rename_btn);
        lv_label_set_text(nick_btn_label, "nick");
        lv_obj_set_style_text_font(nick_btn_label, &lv_font_montserrat_12, LV_PART_MAIN);
        lv_obj_center(nick_btn_label);

        // HF tag type
        lv_obj_t* hf_caption = lv_label_create(row.card);
        lv_label_set_text(hf_caption, "HF");
        lv_obj_set_style_text_font(hf_caption, &lv_font_montserrat_12, LV_PART_MAIN);
        lv_obj_set_style_text_color(hf_caption, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
        lv_obj_align(hf_caption, LV_ALIGN_LEFT_MID, 42, -16);

        row.hf_dropdown = lv_dropdown_create(row.card);
        lv_dropdown_set_options_static(row.hf_dropdown, hf_options);
        lv_obj_set_size(row.hf_dropdown, 300, 36);
        lv_obj_set_style_text_font(row.hf_dropdown, ui::FontSmall, LV_PART_MAIN);
        lv_obj_align(row.hf_dropdown, LV_ALIGN_LEFT_MID, 42, 12);
        lv_obj_add_event_cb(row.hf_dropdown, on_hf_changed, LV_EVENT_VALUE_CHANGED, this);
        lv_obj_set_user_data(row.hf_dropdown, (void*)(intptr_t)i);

        // LF tag type
        lv_obj_t* lf_caption = lv_label_create(row.card);
        lv_label_set_text(lf_caption, "LF");
        lv_obj_set_style_text_font(lf_caption, &lv_font_montserrat_12, LV_PART_MAIN);
        lv_obj_set_style_text_color(lf_caption, lv_color_hex(ui::theme::kWarn), LV_PART_MAIN);
        lv_obj_align(lf_caption, LV_ALIGN_LEFT_MID, 352, -16);

        row.lf_dropdown = lv_dropdown_create(row.card);
        lv_dropdown_set_options_static(row.lf_dropdown, lf_options);
        lv_obj_set_size(row.lf_dropdown, 260, 36);
        lv_obj_set_style_text_font(row.lf_dropdown, ui::FontSmall, LV_PART_MAIN);
        lv_obj_align(row.lf_dropdown, LV_ALIGN_LEFT_MID, 352, 12);
        lv_obj_add_event_cb(row.lf_dropdown, on_lf_changed, LV_EVENT_VALUE_CHANGED, this);
        lv_obj_set_user_data(row.lf_dropdown, (void*)(intptr_t)i);

        // active slot button
        row.active_btn = lv_button_create(row.card);
        lv_obj_set_size(row.active_btn, 96, 40);
        lv_obj_align(row.active_btn, LV_ALIGN_RIGHT_MID, -8, 0);
        lv_obj_set_style_radius(row.active_btn, 8, LV_PART_MAIN);
        lv_obj_add_event_cb(row.active_btn, on_active_clicked, LV_EVENT_CLICKED, this);
        lv_obj_set_user_data(row.active_btn, (void*)(intptr_t)i);

        lv_obj_t* btn_label = lv_label_create(row.active_btn);
        lv_label_set_text(btn_label, "Use");
        lv_obj_set_style_text_font(btn_label, ui::FontSmall, LV_PART_MAIN);
        lv_obj_center(btn_label);

        // state text
        row.state_label = lv_label_create(row.card);
        lv_label_set_text(row.state_label, "");
        lv_obj_set_style_text_font(row.state_label, &lv_font_montserrat_12, LV_PART_MAIN);
        lv_obj_set_style_text_color(row.state_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
        lv_obj_align(row.state_label, LV_ALIGN_LEFT_MID, 630, 0);
    }
}

void SlotPage::Refresh()
{
    const bool connected = _ctx.connected();

    _updating = true;
    for (int i = 0; i < chameleon::kSlotCount; ++i) {
        Row& row = _rows[i];
        if (row.card == nullptr) {
            continue;
        }

        lv_obj_set_style_border_color(row.card,
                                      lv_color_hex(i == _ctx.client().activeSlot() ? ui::theme::kAccent
                                                                                  : ui::theme::kBorder),
                                      LV_PART_MAIN);

        if (!connected) {
            lv_obj_add_state(row.hf_dropdown, LV_STATE_DISABLED);
            lv_obj_add_state(row.lf_dropdown, LV_STATE_DISABLED);
            lv_obj_add_state(row.active_btn, LV_STATE_DISABLED);
            lv_label_set_text(row.state_label, "offline");
            continue;
        }

        lv_obj_remove_state(row.hf_dropdown, LV_STATE_DISABLED);
        lv_obj_remove_state(row.lf_dropdown, LV_STATE_DISABLED);
        lv_obj_remove_state(row.active_btn, LV_STATE_DISABLED);

        const SlotInfo& info = _ctx.client().slotInfo(i);
        lv_dropdown_set_selected(row.hf_dropdown, choice_index(kHfChoices, kHfChoiceCount, info.hf_tag_type));
        lv_dropdown_set_selected(row.lf_dropdown, choice_index(kLfChoices, kLfChoiceCount, info.lf_tag_type));

        if (i == _ctx.client().activeSlot()) {
            lv_obj_set_style_bg_color(row.active_btn, lv_color_hex(ui::theme::kAccent), LV_PART_MAIN);
            lv_label_set_text(row.state_label, "ACTIVE");
            lv_obj_set_style_text_color(row.state_label, lv_color_hex(ui::theme::kAccent), LV_PART_MAIN);
        } else {
            lv_obj_set_style_bg_color(row.active_btn, lv_color_hex(ui::theme::kSurfaceHi), LV_PART_MAIN);
            lv_label_set_text(row.state_label, info.enabled_hf || info.enabled_lf ? "set" : "empty");
            lv_obj_set_style_text_color(row.state_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
        }
    }
    _updating = false;
}

void SlotPage::apply_tag_type(int slot, bool hf, uint16_t tag_type)
{
    auto& client = _ctx.client();
    if (!_ctx.connected()) {
        return;
    }

    char msg[96];
    snprintf(msg, sizeof(msg), "set slot %d %s -> %s", slot + 1, hf ? "HF" : "LF", TagTypeText(tag_type));
    _ctx.LogEvent("%s", msg);

    if (client.SetSlotTagType(static_cast<uint8_t>(slot), hf ? TagSenseType::HF : TagSenseType::LF, tag_type)) {
        // Persist so the setting survives a device power cycle.
        client.SaveSettings();
        _ctx.RefreshSlotState();
    } else {
        _ctx.LogEvent("SET_SLOT_TAG_TYPE failed (slot %d %s)", slot + 1, hf ? "HF" : "LF");
    }
}

void SlotPage::on_hf_changed(lv_event_t* e)
{
    auto* self = static_cast<SlotPage*>(lv_event_get_user_data(e));
    if (self == nullptr || self->_updating) {
        return;
    }
    lv_obj_t* dd = lv_event_get_target_obj(e);
    const int slot = (int)(intptr_t)lv_obj_get_user_data(dd);
    const int sel  = lv_dropdown_get_selected(dd);
    if (sel < 0 || sel >= (int)kHfChoiceCount) {
        return;
    }
    self->apply_tag_type(slot, true, kHfChoices[sel].type);
}

void SlotPage::on_lf_changed(lv_event_t* e)
{
    auto* self = static_cast<SlotPage*>(lv_event_get_user_data(e));
    if (self == nullptr || self->_updating) {
        return;
    }
    lv_obj_t* dd = lv_event_get_target_obj(e);
    const int slot = (int)(intptr_t)lv_obj_get_user_data(dd);
    const int sel  = lv_dropdown_get_selected(dd);
    if (sel < 0 || sel >= (int)kLfChoiceCount) {
        return;
    }
    self->apply_tag_type(slot, false, kLfChoices[sel].type);
}

void SlotPage::on_active_clicked(lv_event_t* e)
{
    auto* self = static_cast<SlotPage*>(lv_event_get_user_data(e));
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const int slot = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));

    if (self->_ctx.client().SetActiveSlot(static_cast<uint8_t>(slot))) {
        self->_ctx.LogEvent("active slot -> %d", slot + 1);
        self->_ctx.RefreshSlotState();
    } else {
        self->_ctx.LogEvent("SET_ACTIVE_SLOT failed (slot %d)", slot + 1);
    }
}

// ---------------------------------------------------------------------------
// Nickname editor
//
// One modal dialog is reused for every slot. The nick is stored per sense type
// on the device, so a slot can carry separate HF and LF names; the editor edits
// whichever band the slot currently uses, defaulting to HF.
// ---------------------------------------------------------------------------

void SlotPage::on_rename_clicked(lv_event_t* e)
{
    auto* self = static_cast<SlotPage*>(lv_event_get_user_data(e));
    if (self == nullptr || !self->_ctx.connected()) {
        if (self != nullptr) {
            self->_ctx.LogEvent("nickname editing needs a connected device");
        }
        return;
    }
    self->open_nick_editor((int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e)));
}

void SlotPage::open_nick_editor(int slot)
{
    if (_nick.dialog != nullptr) {
        close_nick_editor();
    }
    _nick.slot = slot;

    lv_obj_t* screen = lv_screen_active();

    _nick.dialog = lv_obj_create(screen);
    lv_obj_set_size(_nick.dialog, 720, 460);
    lv_obj_center(_nick.dialog);
    lv_obj_set_style_bg_color(_nick.dialog, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(_nick.dialog, lv_color_hex(ui::theme::kAccent), LV_PART_MAIN);
    lv_obj_set_style_border_width(_nick.dialog, 2, LV_PART_MAIN);
    lv_obj_set_style_radius(_nick.dialog, 14, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_nick.dialog, 16, LV_PART_MAIN);
    lv_obj_clear_flag(_nick.dialog, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* caption = lv_label_create(_nick.dialog);
    lv_label_set_text_fmt(caption, "slot %d nickname", slot + 1);
    lv_obj_set_style_text_font(caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(caption, lv_color_hex(ui::theme::kText), LV_PART_MAIN);
    lv_obj_align(caption, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t* hint = lv_label_create(_nick.dialog);
    lv_label_set_text(hint, "max 32 characters; stored on the device (SAVE_SETTINGS)");
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(hint, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(hint, LV_ALIGN_TOP_LEFT, 0, 28);

    _nick.input = lv_textarea_create(_nick.dialog);
    lv_textarea_set_one_line(_nick.input, true);
    lv_textarea_set_max_length(_nick.input, 32);
    lv_obj_set_size(_nick.input, 660, 48);
    lv_obj_set_style_text_font(_nick.input, ui::FontBody, LV_PART_MAIN);
    lv_obj_align(_nick.input, LV_ALIGN_TOP_LEFT, 0, 52);

    // Seed with whatever the device currently reports for this slot's band.
    char current[40] = {};
    if (_ctx.client().GetSlotNick(static_cast<uint8_t>(slot), chameleon::TagSenseType::HF, current, sizeof(current)) &&
        current[0] != '\0') {
        lv_textarea_set_text(_nick.input, current);
    } else if (_ctx.client().GetSlotNick(static_cast<uint8_t>(slot), chameleon::TagSenseType::LF, current,
                                         sizeof(current)) &&
               current[0] != '\0') {
        lv_textarea_set_text(_nick.input, current);
    }

    _nick.keyboard = lv_keyboard_create(_nick.dialog);
    lv_obj_set_size(_nick.keyboard, 660, 230);
    lv_obj_align(_nick.keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_keyboard_set_textarea(_nick.keyboard, _nick.input);
    lv_obj_add_event_cb(_nick.keyboard, on_nick_dialog_event, LV_EVENT_READY, this);
    lv_obj_add_event_cb(_nick.keyboard, on_nick_dialog_event, LV_EVENT_CANCEL, this);

    lv_obj_t* save_btn = lv_button_create(_nick.dialog);
    lv_obj_set_size(save_btn, 160, 40);
    lv_obj_set_style_radius(save_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(save_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(save_btn, LV_ALIGN_TOP_RIGHT, -180, 52);
    lv_obj_add_event_cb(save_btn, on_nick_dialog_event, LV_EVENT_CLICKED, this);
    lv_obj_t* save_label = lv_label_create(save_btn);
    lv_label_set_text(save_label, "save");
    lv_obj_center(save_label);

    lv_obj_t* cancel_btn = lv_button_create(_nick.dialog);
    lv_obj_set_size(cancel_btn, 160, 40);
    lv_obj_set_style_radius(cancel_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_hex(ui::theme::kSurfaceHi), LV_PART_MAIN);
    lv_obj_align(cancel_btn, LV_ALIGN_TOP_RIGHT, 0, 52);
    lv_obj_add_event_cb(cancel_btn, on_nick_dialog_event, LV_EVENT_CANCEL, this);
    lv_obj_t* cancel_label = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_label, "cancel");
    lv_obj_center(cancel_label);
}

void SlotPage::close_nick_editor()
{
    if (_nick.dialog != nullptr) {
        lv_obj_delete(_nick.dialog);
    }
    _nick = NickEditor{};
}

void SlotPage::commit_nick()
{
    if (_nick.slot < 0 || _nick.input == nullptr || !_ctx.connected()) {
        return;
    }
    const int slot = _nick.slot;
    const char* text = lv_textarea_get_text(_nick.input);
    if (text == nullptr) {
        return;
    }

    // Store under the band this slot actually uses, so the nick shows up where
    // the user set it. HF takes precedence when both are configured.
    const chameleon::SlotInfo& info = _ctx.client().slotInfo(slot);
    const chameleon::TagSenseType sense =
        info.hf_tag_type != chameleon::TAG_UNDEFINED ? chameleon::TagSenseType::HF : chameleon::TagSenseType::LF;

    if (_ctx.client().SetSlotNick(static_cast<uint8_t>(slot), sense, text)) {
        _ctx.client().SaveSettings();
        _ctx.LogEvent("slot %d nick -> \"%s\"", slot + 1, text);
    } else {
        _ctx.LogEvent("SET_SLOT_TAG_NICK failed (slot %d)", slot + 1);
    }

    _ctx.RefreshSlotState();
}

void SlotPage::on_nick_dialog_event(lv_event_t* e)
{
    auto* self = static_cast<SlotPage*>(lv_event_get_user_data(e));
    if (self == nullptr) {
        return;
    }
    const lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_READY || code == LV_EVENT_CLICKED) {
        self->commit_nick();
    }
    self->close_nick_editor();
}

bool SlotPage::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    // Only the nickname dialog has a text field, and only while it is open.
    if (_nick.dialog == nullptr || _nick.input == nullptr) {
        return false;
    }

    if (hid_key_code == ui::key::kEscape) {
        close_nick_editor();
        return true;
    }
    if (hid_key_code == ui::key::kEnter) {
        commit_nick();
        close_nick_editor();
        return true;
    }
    if (hid_key_code == ui::key::kBackspace) {
        lv_textarea_delete_char(_nick.input);
        return true;
    }
    if (hid_key_code == ui::key::kDelete) {
        lv_textarea_delete_char_forward(_nick.input);
        return true;
    }

    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c != 0 && c != '\n' && c != '\b') {
        lv_textarea_add_char(_nick.input, static_cast<uint32_t>(c));
        return true;
    }
    return false;
}

// ===========================================================================
// DevicePage
// ===========================================================================

void DevicePage::Create(lv_obj_t* parent)
{
    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(_root, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_column(_root, 12, LV_PART_MAIN);
    lv_obj_set_style_pad_row(_root, 12, LV_PART_MAIN);
    lv_obj_set_flex_flow(_root, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_clear_flag(_root, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* ident = make_card(_root);
    lv_obj_set_size(ident, 600, 260);
    lv_obj_set_style_pad_all(ident, 16, LV_PART_MAIN);

    lv_obj_t* ident_title = lv_label_create(ident);
    lv_label_set_text(ident_title, "device");
    lv_obj_set_style_text_font(ident_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(ident_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(ident_title, LV_ALIGN_TOP_LEFT, 0, 0);

    _ident_label = lv_label_create(ident);
    lv_label_set_text(_ident_label, "not connected");
    lv_obj_set_style_text_font(_ident_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_set_style_text_color(_ident_label, lv_color_hex(ui::theme::kText), LV_PART_MAIN);
    lv_obj_set_width(_ident_label, 560);
    lv_label_set_long_mode(_ident_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_ident_label, LV_ALIGN_TOP_LEFT, 0, 40);

    _battery_label = lv_label_create(ident);
    lv_label_set_text(_battery_label, "");
    lv_obj_set_style_text_font(_battery_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_set_style_text_color(_battery_label, lv_color_hex(ui::theme::kText), LV_PART_MAIN);
    lv_obj_align(_battery_label, LV_ALIGN_TOP_LEFT, 0, 170);

    _mode_label = lv_label_create(ident);
    lv_label_set_text(_mode_label, "");
    lv_obj_set_style_text_font(_mode_label, ui::FontBody, LV_PART_MAIN);
    lv_obj_set_style_text_color(_mode_label, lv_color_hex(ui::theme::kText), LV_PART_MAIN);
    lv_obj_align(_mode_label, LV_ALIGN_TOP_LEFT, 0, 200);

    // Memory readout. The UI does not need this, but key recovery does: the
    // upstream lfsr_recovery32() workspace is far larger than this board's
    // PSRAM, so the real budget has to be visible to judge what fits.
    _mem_label = lv_label_create(ident);
    lv_label_set_text(_mem_label, "");
    lv_obj_set_style_text_font(_mem_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_mem_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(_mem_label, LV_ALIGN_TOP_LEFT, 0, 228);

    // ---- mode / settings card ----
    lv_obj_t* settings = make_card(_root);
    lv_obj_set_size(settings, 600, 260);
    lv_obj_set_style_pad_all(settings, 16, LV_PART_MAIN);

    lv_obj_t* set_title = lv_label_create(settings);
    lv_label_set_text(set_title, "mode & settings");
    lv_obj_set_style_text_font(set_title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(set_title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(set_title, LV_ALIGN_TOP_LEFT, 0, 0);

    _mode_btn = lv_button_create(settings);
    lv_obj_set_size(_mode_btn, 240, 44);
    lv_obj_set_style_radius(_mode_btn, 8, LV_PART_MAIN);
    lv_obj_align(_mode_btn, LV_ALIGN_TOP_LEFT, 0, 40);
    lv_obj_add_event_cb(_mode_btn, on_mode_clicked, LV_EVENT_CLICKED, this);
    lv_obj_t* mode_btn_label = lv_label_create(_mode_btn);
    lv_label_set_text(mode_btn_label, "switch to reader mode");
    lv_obj_set_style_text_font(mode_btn_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(mode_btn_label);

    lv_obj_t* anim_caption = lv_label_create(settings);
    lv_label_set_text(anim_caption, "LED animation");
    lv_obj_set_style_text_font(anim_caption, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(anim_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(anim_caption, LV_ALIGN_TOP_LEFT, 0, 100);

    _anim_dropdown = lv_dropdown_create(settings);
    lv_dropdown_set_options_static(_anim_dropdown, "Full\nMinimal\nNone\nSymmetric");
    lv_obj_set_size(_anim_dropdown, 240, 40);
    lv_obj_set_style_text_font(_anim_dropdown, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_anim_dropdown, LV_ALIGN_TOP_LEFT, 0, 124);
    lv_obj_add_event_cb(_anim_dropdown, on_animation_changed, LV_EVENT_VALUE_CHANGED, this);

    lv_obj_t* sleep_caption = lv_label_create(settings);
    lv_label_set_text(sleep_caption, "sleep timeout");
    lv_obj_set_style_text_font(sleep_caption, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(sleep_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(sleep_caption, LV_ALIGN_TOP_LEFT, 280, 100);

    _sleep_dropdown = lv_dropdown_create(settings);
    lv_dropdown_set_options_static(_sleep_dropdown, "15 s\n30 s\n60 s\n120 s\n300 s");
    lv_obj_set_size(_sleep_dropdown, 240, 40);
    lv_obj_set_style_text_font(_sleep_dropdown, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_sleep_dropdown, LV_ALIGN_TOP_LEFT, 280, 124);
    lv_obj_add_event_cb(_sleep_dropdown, on_sleep_changed, LV_EVENT_VALUE_CHANGED, this);

    lv_obj_t* save_btn = lv_button_create(settings);
    lv_obj_set_size(save_btn, 240, 44);
    lv_obj_set_style_radius(save_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(save_btn, lv_color_hex(ui::theme::kAccentDim), LV_PART_MAIN);
    lv_obj_align(save_btn, LV_ALIGN_TOP_LEFT, 0, 186);
    lv_obj_add_event_cb(save_btn, on_save_clicked, LV_EVENT_CLICKED, this);
    lv_obj_t* save_label = lv_label_create(save_btn);
    lv_label_set_text(save_label, "save settings to flash");
    lv_obj_set_style_text_font(save_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(save_label);

    // Reads every remaining system query in one go and writes the result to the
    // log. They are diagnostics rather than controls, so one button covering
    // capabilities / settings / enabled slots / button config / nicknames beats
    // five screens of read-only labels.
    lv_obj_t* report_btn = lv_button_create(settings);
    lv_obj_set_size(report_btn, 240, 44);
    lv_obj_set_style_radius(report_btn, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(report_btn, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_align(report_btn, LV_ALIGN_TOP_LEFT, 280, 186);
    lv_obj_add_event_cb(report_btn, on_report_clicked, LV_EVENT_CLICKED, this);
    lv_obj_t* report_label = lv_label_create(report_btn);
    lv_label_set_text(report_label, "report device state");
    lv_obj_set_style_text_font(report_label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(report_label);
}

void DevicePage::Refresh()
{
    _updating = true;

    // Memory budget: reported unconditionally so it is visible even offline.
    if (_mem_label != nullptr) {
        const size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        const size_t psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
        const size_t int_free    = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        lv_label_set_text_fmt(_mem_label, "PSRAM %u/%u KB free    SRAM %u KB free",
                              (unsigned)(psram_free / 1024), (unsigned)(psram_total / 1024),
                              (unsigned)(int_free / 1024));
    }

    if (!_ctx.connected()) {
        lv_label_set_text(_ident_label, "not connected\n\nattach the Chameleon Ultra to the USB-A port");
        lv_label_set_text(_battery_label, "");
        lv_label_set_text(_mode_label, "");
        lv_obj_add_state(_mode_btn, LV_STATE_DISABLED);
        lv_obj_add_state(_anim_dropdown, LV_STATE_DISABLED);
        lv_obj_add_state(_sleep_dropdown, LV_STATE_DISABLED);
        _updating = false;
        return;
    }

    lv_obj_remove_state(_mode_btn, LV_STATE_DISABLED);
    lv_obj_remove_state(_anim_dropdown, LV_STATE_DISABLED);
    lv_obj_remove_state(_sleep_dropdown, LV_STATE_DISABLED);

    const auto& info = _ctx.client().deviceInfo();
    char buf[256];
    snprintf(buf, sizeof(buf),
             "model      %s\n"
             "app        %u.%u\n"
             "git        %s\n"
             "BLE MAC    %02X:%02X:%02X:%02X:%02X:%02X",
             info.device_model == 0 ? "Chameleon Ultra" : "Chameleon Lite", info.app_version_major,
             info.app_version_minor, info.git_version[0] != '\0' ? reinterpret_cast<const char*>(info.git_version) : "-",
             info.device_address[0], info.device_address[1], info.device_address[2], info.device_address[3],
             info.device_address[4], info.device_address[5]);
    lv_label_set_text(_ident_label, buf);

    if (_ctx.client().batteryInfo().valid) {
        snprintf(buf, sizeof(buf), "battery    %u%%   %u mV%s", _ctx.client().batteryInfo().percentage,
                 _ctx.client().batteryInfo().voltage_mv, _ctx.client().batteryInfo().charging ? "   charging" : "");
        lv_label_set_text(_battery_label, buf);
    }

    uint8_t mode = 0;
    if (_ctx.client().FetchDeviceMode(&mode)) {
        snprintf(buf, sizeof(buf), "mode       %s", mode ? "reader" : "tag (emulator)");
        lv_label_set_text(_mode_label, buf);
        lv_obj_t* label = lv_obj_get_child(_mode_btn, 0);
        if (label != nullptr) {
            lv_label_set_text(label, mode ? "switch to tag mode" : "switch to reader mode");
        }
    }

    uint8_t anim = 0;
    if (_ctx.client().GetAnimationMode(&anim) && anim <= 3) {
        // The dropdown lists Full/Minimal/None/Symmetric.
        static const uint8_t kOrder[4] = {0, 1, 2, 3};
        for (int i = 0; i < 4; ++i) {
            if (kOrder[i] == anim) {
                lv_dropdown_set_selected(_anim_dropdown, i);
                break;
            }
        }
    }

    uint32_t sleep_s = 0;
    if (_ctx.client().GetSleepTimeout(&sleep_s)) {
        static const uint32_t kSleeps[5] = {15, 30, 60, 120, 300};
        int best = 0;
        for (int i = 0; i < 5; ++i) {
            if (sleep_s >= kSleeps[i]) {
                best = i;
            }
        }
        lv_dropdown_set_selected(_sleep_dropdown, best);
    }

    _updating = false;
}

void DevicePage::on_mode_clicked(lv_event_t* e)
{
    auto* self = static_cast<DevicePage*>(lv_event_get_user_data(e));
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }

    uint8_t mode = 0;
    if (!self->_ctx.client().FetchDeviceMode(&mode)) {
        return;
    }
    const uint8_t target = mode ? 0 : 1;
    if (self->_ctx.client().ChangeDeviceMode(target)) {
        self->_ctx.LogEvent("device mode -> %s", target ? "reader" : "tag");
        self->_ctx.client().SaveSettings();
    } else {
        self->_ctx.LogEvent("CHANGE_DEVICE_MODE failed");
    }
    self->Refresh();
}

void DevicePage::on_save_clicked(lv_event_t* e)
{
    auto* self = static_cast<DevicePage*>(lv_event_get_user_data(e));
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    if (self->_ctx.client().SaveSettings()) {
        self->_ctx.LogEvent("settings saved to flash");
    } else {
        self->_ctx.LogEvent("SAVE_SETTINGS failed");
    }
}

void DevicePage::on_report_clicked(lv_event_t* e)
{
    auto* self = static_cast<DevicePage*>(lv_event_get_user_data(e));
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    chameleon::Client& client = self->_ctx.client();

    // ---- capabilities ----
    // Broken into chunks: the log ring keeps ~90 characters per entry, so one
    // long line gets silently truncated (which is exactly what happened on the
    // first run of this report).
    uint16_t caps[32] = {};
    size_t cap_count  = 0;
    if (client.GetDeviceCapabilities(caps, 32, &cap_count) == chameleon::SUCCESS) {
        char line[80];
        for (size_t i = 0; i < cap_count; i += 10) {
            int written = snprintf(line, sizeof(line), "caps[%u]:", (unsigned)i);
            for (size_t k = i; k < i + 10 && k < cap_count && written < (int)sizeof(line) - 8; ++k) {
                written += snprintf(line + written, sizeof(line) - written, " %u", (unsigned)caps[k]);
            }
            self->_ctx.LogEvent("%s", line);
        }
    } else {
        self->_ctx.LogEvent("GET_DEVICE_CAPABILITIES failed");
    }

    // ---- persisted settings ----
    chameleon::Client::DeviceSettings settings;
    if (client.GetDeviceSettings(&settings) == chameleon::SUCCESS) {
        char key[16];
        for (int i = 0; i < 6; ++i) {
            snprintf(key + i * 2, 3, "%02X", settings.ble_pairing_key[i]);
        }
        self->_ctx.LogEvent("settings v%u: anim %u, btn A %u B %u, long A %u B %u, sleep %us, ble pair %u key %s",
                            (unsigned)settings.version, (unsigned)settings.animation_mode,
                            (unsigned)settings.button_press_a, (unsigned)settings.button_press_b,
                            (unsigned)settings.button_long_press_a, (unsigned)settings.button_long_press_b,
                            (unsigned)settings.sleep_timeout, (unsigned)settings.ble_pairing_enable, key);
    } else {
        self->_ctx.LogEvent("GET_DEVICE_SETTINGS failed");
    }

    // ---- button press functions ----
    // The device wants ASCII 'A'/'B' here, not an index (settings.c
    // is_settings_button_type_valid). Passing 0/1 is answered with PAR_ERR.
    const uint8_t buttons[2] = {chameleon::Client::kButtonA, chameleon::Client::kButtonB};
    for (uint8_t button : buttons) {
        uint8_t short_fn = 0;
        uint8_t long_fn  = 0;
        char short_text[16];
        char long_text[16];
        const uint16_t s1 = client.GetButtonPressConfig(button, &short_fn);
        const uint16_t s2 = client.GetLongButtonPressConfig(button, &long_fn);
        // Raw ids (chameleon_commands.h ButtonPressFunction): the firmware has no
        // text table for them, so printing the number keeps this honest.
        if (s1 == chameleon::SUCCESS) {
            snprintf(short_text, sizeof(short_text), "%u", (unsigned)short_fn);
        } else {
            snprintf(short_text, sizeof(short_text), "failed 0x%02X", s1);
        }
        if (s2 == chameleon::SUCCESS) {
            snprintf(long_text, sizeof(long_text), "%u", (unsigned)long_fn);
        } else {
            snprintf(long_text, sizeof(long_text), "failed 0x%02X", s2);
        }
        self->_ctx.LogEvent("button %c: press fn %s, long press fn %s", (char)button, short_text, long_text);
    }

    // ---- enabled slots ----
    chameleon::Client::EnabledSlot slots[8] = {};
    size_t slot_count                       = 0;
    if (client.GetEnabledSlots(slots, 8, &slot_count) == chameleon::SUCCESS) {
        char line[160];
        int written = snprintf(line, sizeof(line), "enabled slots:");
        for (size_t i = 0; i < slot_count && written < (int)sizeof(line) - 12; ++i) {
            written += snprintf(line + written, sizeof(line) - written, " %u:hf%u/lf%u", (unsigned)(i + 1),
                                (unsigned)slots[i].hf, (unsigned)slots[i].lf);
        }
        self->_ctx.LogEvent("%s", line);
    } else {
        self->_ctx.LogEvent("GET_ENABLED_SLOTS failed");
    }

    // ---- nicknames ----
    chameleon::Client::SlotNicks nicks[8] = {};
    size_t nick_count                     = 0;
    if (client.GetAllSlotNicks(nicks, 8, &nick_count) == chameleon::SUCCESS) {
        for (size_t i = 0; i < nick_count; ++i) {
            if (nicks[i].hf[0] != '\0' || nicks[i].lf[0] != '\0') {
                self->_ctx.LogEvent("slot %u nick: hf '%s' lf '%s'", (unsigned)(i + 1), nicks[i].hf, nicks[i].lf);
            }
        }
        self->_ctx.LogEvent("%u slot nicknames read", (unsigned)nick_count);
    } else {
        self->_ctx.LogEvent("GET_ALL_SLOT_NICKS failed");
    }

    self->_ctx.LogEvent("device state report complete");
}

void DevicePage::on_animation_changed(lv_event_t* e)
{
    auto* self = static_cast<DevicePage*>(lv_event_get_user_data(e));
    if (self == nullptr || self->_updating || !self->_ctx.connected()) {
        return;
    }
    const int sel = lv_dropdown_get_selected(lv_event_get_target_obj(e));
    // Dropdown order is Full/Minimal/None/Symmetric; AnimationMode values are
    // FULL=0, MINIMAL=1, NONE=2, SYMMETRIC=3, so the index maps directly.
    if (self->_ctx.client().SetAnimationMode(static_cast<uint8_t>(sel))) {
        self->_ctx.LogEvent("animation mode -> %d", sel);
    } else {
        self->_ctx.LogEvent("SET_ANIMATION_MODE failed");
    }
}

void DevicePage::on_sleep_changed(lv_event_t* e)
{
    auto* self = static_cast<DevicePage*>(lv_event_get_user_data(e));
    if (self == nullptr || self->_updating || !self->_ctx.connected()) {
        return;
    }
    static const uint32_t kSleeps[5] = {15, 30, 60, 120, 300};
    const int sel                    = lv_dropdown_get_selected(lv_event_get_target_obj(e));
    if (sel < 0 || sel > 4) {
        return;
    }
    if (self->_ctx.client().SetSleepTimeout(kSleeps[sel])) {
        self->_ctx.LogEvent("sleep timeout -> %u s", (unsigned)kSleeps[sel]);
    } else {
        self->_ctx.LogEvent("SET_SLEEP_TIMEOUT failed");
    }
}

// ===========================================================================
// LogPage
// ===========================================================================

void LogPage::Create(lv_obj_t* parent)
{
    _root = lv_obj_create(parent);
    lv_obj_set_size(_root, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(_root, lv_color_hex(0x0A0D11), LV_PART_MAIN);
    lv_obj_set_style_border_color(_root, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(_root, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_root, 12, LV_PART_MAIN);

    lv_obj_t* clear_btn = lv_button_create(_root);
    lv_obj_set_size(clear_btn, 110, 36);
    lv_obj_align(clear_btn, LV_ALIGN_TOP_RIGHT, 0, 0);
    lv_obj_set_style_radius(clear_btn, 8, LV_PART_MAIN);
    lv_obj_add_event_cb(clear_btn, on_clear_clicked, LV_EVENT_CLICKED, this);
    lv_obj_t* clear_label = lv_label_create(clear_btn);
    lv_label_set_text(clear_label, "clear");
    lv_obj_set_style_text_font(clear_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(clear_label);

    _label = lv_label_create(_root);
    lv_label_set_text(_label, "(no traffic yet)");
    lv_obj_set_style_text_font(_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_label, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_label, lv_pct(100));
    lv_label_set_long_mode(_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_label, LV_ALIGN_TOP_LEFT, 0, 44);
}

void LogPage::Refresh()
{
    if (_label == nullptr) {
        return;
    }

    // Render the newest entries that fit in the label buffer.
    constexpr size_t kMaxRows = 28;
    static LogEntry entries[kMaxRows];
    static char text[kMaxRows * (kLogLineLength + 8)];

    const size_t total = _ctx.logSequence();
    const size_t avail = total < app::kLogLines ? total : app::kLogLines;
    const size_t rows  = avail < kMaxRows ? avail : kMaxRows;
    const size_t skip  = avail - rows;

    const size_t n = _ctx.CopyLog(entries, rows, skip);

    size_t written = 0;
    text[0]        = '\0';
    for (size_t i = 0; i < n; ++i) {
        const int r = snprintf(text + written, sizeof(text) - written, "%s\n", entries[i].text);
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - written) {
            break;
        }
        written += static_cast<size_t>(r);
    }
    if (n == 0) {
        snprintf(text, sizeof(text), "(no traffic yet)");
    }

    lv_label_set_text(_label, text);
}

void LogPage::on_clear_clicked(lv_event_t* e)
{
    auto* self = static_cast<LogPage*>(lv_event_get_user_data(e));
    if (self == nullptr) {
        return;
    }
    self->_ctx.ClearLog();
    self->Refresh();
}

}  // namespace app
