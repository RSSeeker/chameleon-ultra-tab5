// SPDX-License-Identifier: MIT
//
// MF0 / NTAG emulator page (wave W3).
//
// The active slot can emulate an MF0UL/NTAG tag instead of a Mifare Classic, and
// the device exposes that emulated tag's whole identity to the host: pages, the
// GET_VERSION bytes, the ECC signature, the NTAG 21x counters, the "magic" UID
// mode, the write mode and the authentication detection log. None of it was
// reachable from the UI before this page existed, which is why the payload
// verifier's UI coverage check lists these methods by name.
//
// Every read here is followed by the value the device returned, and every write
// is written back with the same bytes plus a read-back, so a mismatch is visible
// instead of being assumed to have worked.

#include "pages.h"

#include <stdio.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

#include "app_context.h"

namespace app {

namespace {

using namespace chameleon;

/// Live instance for the keyboard path.
Mf0Page* s_active = nullptr;

/// Three states of the one byte settings this page toggles.
const char* on_off(uint8_t v)
{
    return v != 0 ? "on" : "off";
}

}  // namespace

void Mf0Page::Create(lv_obj_t* parent)
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

    // ---------------- left: emulated tag + pages ----------------
    lv_obj_t* left = lv_obj_create(_root);
    lv_obj_set_size(left, 690, lv_pct(100));
    lv_obj_set_style_bg_color(left, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(left, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(left, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(left, 14, LV_PART_MAIN);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(left);
    lv_label_set_text(title, "mf0 / ntag emulated tag (active slot)");
    lv_obj_set_style_text_font(title, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 0, 0);

    _config_label = lv_label_create(left);
    lv_label_set_text(_config_label, "(press 'read config')");
    lv_obj_set_style_text_font(_config_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_config_label, lv_color_hex(ui::theme::kInfo), LV_PART_MAIN);
    lv_obj_set_width(_config_label, 650);
    lv_label_set_long_mode(_config_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_config_label, LV_ALIGN_TOP_LEFT, 0, 28);

    _read_config_btn = make_button(left, "read config", 0, 66, 200, 42, ui::theme::kInfo, on_read_config, this);
    _magic_btn = make_button(left, "uid magic: -", 210, 66, 200, 42, ui::theme::kSurfaceHi, on_toggle_magic, this);
    _detect_btn = make_button(left, "detection: -", 420, 66, 200, 42, ui::theme::kSurfaceHi, on_toggle_detection,
                              this);
    _write_mode_btn = make_button(left, "write mode: -", 0, 118, 200, 42, ui::theme::kInfo, on_cycle_write_mode,
                                  this);
    _reset_auth_btn = make_button(left, "reset auth counter", 210, 118, 200, 42, ui::theme::kWarn, on_reset_auth, this);
    _detect_log_btn = make_button(left, "read detect log", 420, 118, 200, 42, ui::theme::kSurfaceHi, on_read_detect_log,
                                  this);

    lv_obj_t* pages_caption = lv_label_create(left);
    lv_label_set_text(pages_caption, "pages (4 bytes each)");
    lv_obj_set_style_text_font(pages_caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(pages_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(pages_caption, LV_ALIGN_TOP_LEFT, 0, 172);

    lv_obj_t* start_caption = lv_label_create(left);
    lv_label_set_text(start_caption, "first page");
    lv_obj_set_style_text_font(start_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(start_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(start_caption, LV_ALIGN_TOP_LEFT, 0, 200);

    _page_spinbox = lv_spinbox_create(left);
    lv_spinbox_set_range(_page_spinbox, 0, 255);
    lv_spinbox_set_digit_format(_page_spinbox, 3, 0);
    lv_obj_set_size(_page_spinbox, 110, 42);
    lv_obj_set_style_text_font(_page_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_page_spinbox, LV_ALIGN_TOP_LEFT, 0, 218);

    lv_obj_t* minus = make_button(left, "-", 118, 218, 42, 42, ui::theme::kSurfaceHi, on_page_step, this);
    lv_obj_set_user_data(minus, (void*)(intptr_t)-1);
    lv_obj_t* plus = make_button(left, "+", 166, 218, 42, 42, ui::theme::kSurfaceHi, on_page_step, this);
    lv_obj_set_user_data(plus, (void*)(intptr_t)1);

    lv_obj_t* count_caption = lv_label_create(left);
    lv_label_set_text(count_caption, "count");
    lv_obj_set_style_text_font(count_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(count_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(count_caption, LV_ALIGN_TOP_LEFT, 224, 200);

    _count_spinbox = lv_spinbox_create(left);
    lv_spinbox_set_range(_count_spinbox, 1, 64);
    lv_spinbox_set_digit_format(_count_spinbox, 2, 0);
    lv_spinbox_set_value(_count_spinbox, 4);
    lv_obj_set_size(_count_spinbox, 90, 42);
    lv_obj_set_style_text_font(_count_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_count_spinbox, LV_ALIGN_TOP_LEFT, 224, 218);

    _read_pages_btn = make_button(left, "read pages", 322, 218, 160, 42, ui::theme::kInfo, on_read_pages, this);
    _write_pages_btn = make_button(left, "write pages", 490, 218, 160, 42, ui::theme::kError, on_write_pages, this);

    _pages_label = lv_label_create(left);
    lv_label_set_text(_pages_label, "(not read yet)");
    lv_obj_set_style_text_font(_pages_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_pages_label, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_pages_label, 650);
    lv_label_set_long_mode(_pages_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_pages_label, LV_ALIGN_TOP_LEFT, 0, 272);

    lv_obj_t* data_caption = lv_label_create(left);
    lv_label_set_text(data_caption, "page bytes to write (hex, 4 per page, starts at 'first page')");
    lv_obj_set_style_text_font(data_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(data_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(data_caption, LV_ALIGN_TOP_LEFT, 0, 366);

    _pages_input = lv_textarea_create(left);
    lv_textarea_set_one_line(_pages_input, true);
    lv_textarea_set_max_length(_pages_input, 96);
    lv_obj_set_size(_pages_input, 650, 44);
    lv_obj_set_style_text_font(_pages_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_pages_input, LV_ALIGN_TOP_LEFT, 0, 386);
    lv_obj_add_event_cb(_pages_input, on_field_focus, LV_EVENT_FOCUSED, this);

    _status_label = lv_label_create(left);
    lv_label_set_text(_status_label, "ready");
    lv_obj_set_style_text_font(_status_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_status_label, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_set_width(_status_label, 650);
    lv_label_set_long_mode(_status_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_status_label, LV_ALIGN_TOP_LEFT, 0, 442);

    _keyboard = lv_keyboard_create(left);
    lv_obj_set_size(_keyboard, 660, 200);
    lv_obj_align(_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(_keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_READY, this);
    lv_obj_add_event_cb(_keyboard, on_keyboard_event, LV_EVENT_CANCEL, this);

    // ---------------- right: version / signature / counters ----------------
    lv_obj_t* right = lv_obj_create(_root);
    lv_obj_set_size(right, 540, lv_pct(100));
    lv_obj_set_style_bg_color(right, lv_color_hex(ui::theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(right, lv_color_hex(ui::theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(right, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(right, 14, LV_PART_MAIN);
    lv_obj_clear_flag(right, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* rtitle = lv_label_create(right);
    lv_label_set_text(rtitle, "version / signature / counters");
    lv_obj_set_style_text_font(rtitle, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(rtitle, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(rtitle, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t* ver_caption = lv_label_create(right);
    lv_label_set_text(ver_caption, "GET_VERSION (8 bytes, hex)");
    lv_obj_set_style_text_font(ver_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(ver_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(ver_caption, LV_ALIGN_TOP_LEFT, 0, 34);

    _version_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_version_input, true);
    lv_textarea_set_max_length(_version_input, 24);
    lv_obj_set_size(_version_input, 340, 42);
    lv_obj_set_style_text_font(_version_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_version_input, LV_ALIGN_TOP_LEFT, 0, 52);
    lv_obj_add_event_cb(_version_input, on_field_focus, LV_EVENT_FOCUSED, this);

    _read_version_btn = make_button(right, "read", 350, 52, 80, 42, ui::theme::kInfo, on_read_version, this);
    _write_version_btn = make_button(right, "write", 438, 52, 80, 42, ui::theme::kError, on_write_version, this);

    lv_obj_t* sig_caption = lv_label_create(right);
    lv_label_set_text(sig_caption, "ECC signature (32 bytes, hex)");
    lv_obj_set_style_text_font(sig_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(sig_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(sig_caption, LV_ALIGN_TOP_LEFT, 0, 104);

    _signature_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_signature_input, true);
    lv_textarea_set_max_length(_signature_input, 72);
    lv_obj_set_size(_signature_input, 340, 42);
    lv_obj_set_style_text_font(_signature_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_signature_input, LV_ALIGN_TOP_LEFT, 0, 122);
    lv_obj_add_event_cb(_signature_input, on_field_focus, LV_EVENT_FOCUSED, this);

    _read_signature_btn = make_button(right, "read", 350, 122, 80, 42, ui::theme::kInfo, on_read_signature, this);
    _write_signature_btn = make_button(right, "write", 438, 122, 80, 42, ui::theme::kError, on_write_signature, this);

    lv_obj_t* cnt_caption = lv_label_create(right);
    lv_label_set_text(cnt_caption, "ntag counter");
    lv_obj_set_style_text_font(cnt_caption, ui::FontMedium, LV_PART_MAIN);
    lv_obj_set_style_text_color(cnt_caption, lv_color_hex(ui::theme::kTextDim), LV_PART_MAIN);
    lv_obj_align(cnt_caption, LV_ALIGN_TOP_LEFT, 0, 180);

    lv_obj_t* idx_caption = lv_label_create(right);
    lv_label_set_text(idx_caption, "index");
    lv_obj_set_style_text_font(idx_caption, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(idx_caption, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(idx_caption, LV_ALIGN_TOP_LEFT, 0, 206);

    _counter_spinbox = lv_spinbox_create(right);
    lv_spinbox_set_range(_counter_spinbox, 0, 2);
    lv_spinbox_set_digit_format(_counter_spinbox, 1, 0);
    lv_obj_set_size(_counter_spinbox, 70, 42);
    lv_obj_set_style_text_font(_counter_spinbox, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_counter_spinbox, LV_ALIGN_TOP_LEFT, 0, 224);

    lv_obj_t* cminus = make_button(right, "-", 78, 224, 42, 42, ui::theme::kSurfaceHi, on_counter_step, this);
    lv_obj_set_user_data(cminus, (void*)(intptr_t)-1);
    lv_obj_t* cplus = make_button(right, "+", 126, 224, 42, 42, ui::theme::kSurfaceHi, on_counter_step, this);
    lv_obj_set_user_data(cplus, (void*)(intptr_t)1);

    _counter_value_input = lv_textarea_create(right);
    lv_textarea_set_one_line(_counter_value_input, true);
    lv_textarea_set_max_length(_counter_value_input, 10);
    lv_obj_set_size(_counter_value_input, 130, 42);
    lv_obj_set_style_text_font(_counter_value_input, ui::FontSmall, LV_PART_MAIN);
    lv_obj_align(_counter_value_input, LV_ALIGN_TOP_LEFT, 176, 224);
    lv_obj_add_event_cb(_counter_value_input, on_field_focus, LV_EVENT_FOCUSED, this);

    _read_counter_btn = make_button(right, "read", 314, 224, 100, 42, ui::theme::kInfo, on_read_counter, this);
    _write_counter_btn = make_button(right, "write", 422, 224, 100, 42, ui::theme::kError, on_write_counter, this);

    _tearing_btn = make_button(right, "reset tearing: off", 0, 276, 250, 42, ui::theme::kSurfaceHi, on_toggle_tearing,
                               this);

    _counter_label = lv_label_create(right);
    lv_label_set_text(_counter_label, "(not read yet)");
    lv_obj_set_style_text_font(_counter_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_counter_label, lv_color_hex(ui::theme::kMono), LV_PART_MAIN);
    lv_obj_set_width(_counter_label, 500);
    lv_label_set_long_mode(_counter_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_counter_label, LV_ALIGN_TOP_LEFT, 0, 328);

    _detect_label = lv_label_create(right);
    lv_label_set_text(_detect_label, "detection log: not read");
    lv_obj_set_style_text_font(_detect_label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_detect_label, lv_color_hex(ui::theme::kTextFaint), LV_PART_MAIN);
    lv_obj_set_width(_detect_label, 500);
    lv_label_set_long_mode(_detect_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(_detect_label, LV_ALIGN_TOP_LEFT, 0, 400);

    updateLabels();
}

void Mf0Page::Destroy()
{
    if (s_active == this) {
        s_active = nullptr;
    }
    ui::Page::Destroy();
}

lv_obj_t* Mf0Page::make_button(lv_obj_t* parent, const char* text, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                               lv_coord_t h, uint32_t color, lv_event_cb_t cb, void* user)
{
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_set_size(button, w, h);
    lv_obj_set_style_radius(button, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(button, lv_color_hex(color), LV_PART_MAIN);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, y);
    lv_obj_add_event_cb(button, cb, LV_EVENT_CLICKED, user);

    lv_obj_t* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, ui::FontSmall, LV_PART_MAIN);
    lv_obj_center(label);
    return button;
}

void Mf0Page::set_button_text(lv_obj_t* button, const char* text)
{
    if (button == nullptr) {
        return;
    }
    lv_obj_t* label = lv_obj_get_child(button, 0);
    if (label != nullptr) {
        lv_label_set_text(label, text);
    }
}

uint8_t Mf0Page::selectedPage() const
{
    return _page_spinbox != nullptr ? static_cast<uint8_t>(lv_spinbox_get_value(_page_spinbox)) : 0;
}

uint8_t Mf0Page::selectedCount() const
{
    return _count_spinbox != nullptr ? static_cast<uint8_t>(lv_spinbox_get_value(_count_spinbox)) : 1;
}

uint8_t Mf0Page::selectedCounter() const
{
    return _counter_spinbox != nullptr ? static_cast<uint8_t>(lv_spinbox_get_value(_counter_spinbox)) : 0;
}

void Mf0Page::updateLabels()
{
    if (_magic_btn != nullptr) {
        char text[48];
        snprintf(text, sizeof(text), "uid magic: %s", _magic_valid ? on_off(_magic) : "-");
        set_button_text(_magic_btn, text);
    }
    if (_detect_btn != nullptr) {
        char text[48];
        snprintf(text, sizeof(text), "detection: %s", _config_valid ? on_off(_config.detection) : "-");
        set_button_text(_detect_btn, text);
    }
    if (_write_mode_btn != nullptr) {
        char text[48];
        if (_config_valid) {
            snprintf(text, sizeof(text), "write mode: %u", (unsigned)_config.write_mode);
        } else {
            snprintf(text, sizeof(text), "write mode: -");
        }
        set_button_text(_write_mode_btn, text);
    }
    if (_tearing_btn != nullptr) {
        set_button_text(_tearing_btn, _reset_tearing ? "reset tearing: on" : "reset tearing: off");
    }
    if (_config_label != nullptr) {
        if (_config_valid) {
            lv_label_set_text_fmt(_config_label,
                                  "uid magic %s, detection %s, write mode %u, %u page(s)",
                                  on_off(_config.uid_mode), on_off(_config.detection), (unsigned)_config.write_mode,
                                  (unsigned)_page_count);
        } else {
            lv_label_set_text(_config_label, "(press 'read config')");
        }
    }
}

void Mf0Page::Refresh()
{
    updateLabels();
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

void Mf0Page::on_read_config(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    auto& client = self->_ctx.client();

    Client::Mf0EmulatorConfig config{};
    if (client.Mf0GetEmulatorConfig(&config) != SUCCESS) {
        self->_ctx.LogEvent("MF0_GET_EMULATOR_CONFIG failed");
        lv_label_set_text(self->_status_label, "read config failed");
        return;
    }
    self->_config       = config;
    self->_config_valid = true;

    bool magic = false;
    const uint16_t magic_status = client.Mf0GetUidMagicMode(&magic);
    self->_magic_valid          = (magic_status == SUCCESS);
    self->_magic                = magic ? 1 : 0;

    uint8_t pages = 0;
    if (client.Mf0GetPageCount(&pages) == SUCCESS) {
        self->_page_count = pages;
    }

    lv_label_set_text_fmt(self->_status_label,
                          "config read: uid magic %s, detection %s, write mode %u, %u page(s)",
                          on_off(self->_config.uid_mode), on_off(self->_config.detection),
                          (unsigned)self->_config.write_mode, (unsigned)self->_page_count);
    self->_ctx.LogEvent("mf0 config: uid magic %s, detection %s, write mode %u, %u pages",
                        on_off(self->_config.uid_mode), on_off(self->_config.detection),
                        (unsigned)self->_config.write_mode, (unsigned)self->_page_count);
    self->updateLabels();
}

void Mf0Page::on_toggle_magic(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    // The device is the source of truth: read, invert, write, read back.
    bool current = false;
    if (self->_ctx.client().Mf0GetUidMagicMode(&current) != SUCCESS) {
        lv_label_set_text(self->_status_label, "uid magic mode not supported by this firmware");
        return;
    }
    const bool wanted = !current;
    if (self->_ctx.client().Mf0SetUidMagicMode(wanted) != SUCCESS) {
        self->_ctx.LogEvent("MF0_NTAG_SET_UID_MAGIC_MODE failed");
        lv_label_set_text(self->_status_label, "set uid magic mode failed");
        return;
    }
    bool readback = false;
    if (self->_ctx.client().Mf0GetUidMagicMode(&readback) == SUCCESS && readback == wanted) {
        self->_magic       = wanted ? 1 : 0;
        self->_magic_valid = true;
        self->_config.uid_mode = wanted ? 1 : 0;
        lv_label_set_text_fmt(self->_status_label, "uid magic mode %s (verified)", wanted ? "on" : "off");
        self->_ctx.LogEvent("mf0 uid magic mode -> %s", wanted ? "on" : "off");
    } else {
        lv_label_set_text(self->_status_label, "wrote the magic mode but the read-back differs");
        self->_ctx.LogEvent("mf0 uid magic mode write not confirmed");
    }
    self->updateLabels();
}

void Mf0Page::on_toggle_detection(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    bool current = false;
    if (self->_ctx.client().Mf0GetDetectionEnable(&current) != SUCCESS) {
        lv_label_set_text(self->_status_label, "detection setting not supported by this firmware");
        return;
    }
    const bool wanted = !current;
    if (self->_ctx.client().Mf0SetDetectionEnable(wanted) != SUCCESS) {
        self->_ctx.LogEvent("MF0_NTAG_SET_DETECTION_ENABLE failed");
        lv_label_set_text(self->_status_label, "set detection failed");
        return;
    }
    bool readback = false;
    if (self->_ctx.client().Mf0GetDetectionEnable(&readback) == SUCCESS && readback == wanted) {
        self->_config.detection = wanted ? 1 : 0;
        self->_config_valid     = true;
        lv_label_set_text_fmt(self->_status_label, "detection %s (verified)", wanted ? "on" : "off");
        self->_ctx.LogEvent("mf0 detection -> %s", wanted ? "on" : "off");
    } else {
        lv_label_set_text(self->_status_label, "wrote detection but the read-back differs");
    }
    self->updateLabels();
}

void Mf0Page::on_cycle_write_mode(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t current = 0;
    if (self->_ctx.client().Mf0GetWriteMode(&current) != SUCCESS) {
        lv_label_set_text(self->_status_label, "write mode not readable");
        return;
    }
    // The emulated tag's write mode: 0 = read-only, 1 = writable. The device
    // validates the value, so only the two documented ones are cycled.
    const uint8_t wanted = (current == 0) ? 1 : 0;
    if (self->_ctx.client().Mf0SetWriteMode(wanted) != SUCCESS) {
        self->_ctx.LogEvent("MF0_NTAG_SET_WRITE_MODE failed");
        lv_label_set_text(self->_status_label, "set write mode failed");
        return;
    }
    uint8_t readback = 0;
    if (self->_ctx.client().Mf0GetWriteMode(&readback) == SUCCESS) {
        self->_config.write_mode = readback;
        self->_config_valid      = true;
        lv_label_set_text_fmt(self->_status_label, "write mode %u -> %u (read back %u)", (unsigned)current,
                              (unsigned)wanted, (unsigned)readback);
        self->_ctx.LogEvent("mf0 write mode %u -> %u", (unsigned)current, (unsigned)readback);
    }
    self->updateLabels();
}

void Mf0Page::on_reset_auth(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t status = 0;
    const uint16_t result = self->_ctx.client().Mf0ResetAuthCnt(&status);
    if (result == SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "auth counter reset (device status %u)", (unsigned)status);
        self->_ctx.LogEvent("mf0 auth counter reset, status %u", (unsigned)status);
    } else {
        lv_label_set_text(self->_status_label, "reset auth counter failed");
        self->_ctx.LogEvent("MF0_NTAG_RESET_AUTH_CNT failed: %s (0x%02X)", StatusText(result), result);
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

void Mf0Page::on_read_pages(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const uint8_t start = self->selectedPage();
    const uint8_t count = self->selectedCount();

    uint8_t data[64 * 4] = {};
    size_t length        = 0;
    const uint16_t status =
        self->_ctx.client().Mf0ReadEmuPageData(start, count, data, sizeof(data), &length);
    if (status != SUCCESS || length == 0) {
        lv_label_set_text_fmt(self->_status_label, "read pages failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("MF0_NTAG_READ_EMU_PAGE_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }

    // Show four pages per line with their page numbers, so the text lines up with
    // what the write field expects.
    char text[512];
    size_t at = 0;
    const size_t pages = length / 4;
    for (size_t i = 0; i < pages && at + 32 < sizeof(text); ++i) {
        char hex[16];
        ui::FormatHex(data + i * 4, 4, hex, sizeof(hex), "");
        const int r = snprintf(text + at, sizeof(text) - at, "%s%02X: %s", (i % 4 == 0 && i != 0) ? "\n" : " ",
                               (unsigned)(start + i), hex);
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(r);
    }
    lv_label_set_text(self->_pages_label, text);
    lv_label_set_text_fmt(self->_status_label, "read %u page(s) from page %u (%u bytes)", (unsigned)pages,
                          (unsigned)start, (unsigned)length);
    self->_ctx.LogEvent("mf0 read %u page(s) from %u", (unsigned)pages, (unsigned)start);
}

void Mf0Page::on_write_pages(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const char* text = lv_textarea_get_text(self->_pages_input);
    uint8_t data[64 * 4];
    size_t length = ui::ParseHex(text, data, sizeof(data));
    if (length == 0 || (length % 4) != 0) {
        lv_label_set_text(self->_status_label, "enter a whole number of 4 byte pages, e.g. 04112233");
        return;
    }

    const uint8_t start = self->selectedPage();
    const uint16_t status = self->_ctx.client().Mf0WriteEmuPageData(start, data, length);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "write pages failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("MF0_NTAG_WRITE_EMU_PAGE_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }

    // Read back and compare: a write that the device accepted but did not store
    // (read-only tag, wrong write mode) is otherwise invisible.
    uint8_t readback[64 * 4] = {};
    size_t readback_length   = 0;
    const uint16_t back =
        self->_ctx.client().Mf0ReadEmuPageData(start, static_cast<uint8_t>(length / 4), readback, sizeof(readback),
                                               &readback_length);
    if (back != SUCCESS || readback_length < length) {
        lv_label_set_text(self->_status_label, "wrote the pages but the read-back failed");
        self->_ctx.LogEvent("mf0 write not verified: read-back %s", StatusText(back));
        return;
    }
    if (memcmp(readback, data, length) == 0) {
        lv_label_set_text_fmt(self->_status_label, "wrote %u byte(s) at page %u (read-back matches)",
                              (unsigned)length, (unsigned)start);
        self->_ctx.LogEvent("mf0 wrote %u byte(s) at page %u, read-back matches", (unsigned)length, (unsigned)start);
    } else {
        lv_label_set_text(self->_status_label, "read-back differs - the tag is probably read-only (write mode 0)");
        self->_ctx.LogEvent("mf0 write read-back differs");
    }
}

// ---------------------------------------------------------------------------
// Version / signature
// ---------------------------------------------------------------------------

void Mf0Page::on_read_version(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t version[8] = {};
    const uint16_t status = self->_ctx.client().Mf0GetVersionData(version);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "read version failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[24];
    ui::FormatHex(version, sizeof(version), hex, sizeof(hex), "");
    lv_textarea_set_text(self->_version_input, hex);
    lv_label_set_text_fmt(self->_status_label, "GET_VERSION: %s", hex);
    self->_ctx.LogEvent("mf0 version: %s", hex);
}

void Mf0Page::on_write_version(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t version[8];
    if (ui::ParseHex(lv_textarea_get_text(self->_version_input), version, sizeof(version)) != sizeof(version)) {
        lv_label_set_text(self->_status_label, "the version is exactly 8 bytes (16 hex digits)");
        return;
    }
    const uint16_t status = self->_ctx.client().Mf0SetVersionData(version);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "write version failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("MF0_NTAG_SET_VERSION_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    uint8_t readback[8] = {};
    if (self->_ctx.client().Mf0GetVersionData(readback) == SUCCESS) {
        char hex[24];
        ui::FormatHex(readback, sizeof(readback), hex, sizeof(hex), "");
        if (memcmp(readback, version, sizeof(version)) == 0) {
            lv_label_set_text_fmt(self->_status_label, "version written and read back: %s", hex);
            self->_ctx.LogEvent("mf0 version written: %s", hex);
        } else {
            lv_label_set_text_fmt(self->_status_label, "version read back as %s (differs)", hex);
        }
    }
}

void Mf0Page::on_read_signature(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t signature[32] = {};
    const uint16_t status = self->_ctx.client().Mf0GetSignatureData(signature);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "read signature failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    char hex[72];
    ui::FormatHex(signature, sizeof(signature), hex, sizeof(hex), "");
    lv_textarea_set_text(self->_signature_input, hex);
    lv_label_set_text_fmt(self->_status_label, "signature read (%u bytes)", (unsigned)sizeof(signature));
    self->_ctx.LogEvent("mf0 signature: %s", hex);
}

void Mf0Page::on_write_signature(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint8_t signature[32];
    if (ui::ParseHex(lv_textarea_get_text(self->_signature_input), signature, sizeof(signature)) !=
        sizeof(signature)) {
        lv_label_set_text(self->_status_label, "the signature is exactly 32 bytes (64 hex digits)");
        return;
    }
    const uint16_t status = self->_ctx.client().Mf0SetSignatureData(signature);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_status_label, "write signature failed: %s (0x%02X)", StatusText(status), status);
        self->_ctx.LogEvent("MF0_NTAG_SET_SIGNATURE_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    uint8_t readback[32] = {};
    if (self->_ctx.client().Mf0GetSignatureData(readback) == SUCCESS) {
        const bool same = memcmp(readback, signature, sizeof(signature)) == 0;
        lv_label_set_text(self->_status_label,
                          same ? "signature written and read back identically"
                               : "signature read back differently");
        self->_ctx.LogEvent("mf0 signature written, read-back %s", same ? "matches" : "differs");
    }
}

// ---------------------------------------------------------------------------
// Counters / detection log
// ---------------------------------------------------------------------------

void Mf0Page::on_read_counter(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const uint8_t index = self->selectedCounter();
    uint32_t value      = 0;
    bool tearing        = false;
    const uint16_t status = self->_ctx.client().Mf0GetCounterData(index, &value, &tearing);
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_counter_label, "counter %u: read failed (%s)",
                              (unsigned)index, StatusText(status));
        return;
    }
    lv_label_set_text_fmt(self->_counter_label, "counter %u = %u%s", (unsigned)index, (unsigned)value,
                          tearing ? " (torn)" : "");
    // LVGL 9 has no lv_textarea_set_text_fmt(), so format into a buffer first.
    char value_text[16];
    snprintf(value_text, sizeof(value_text), "%u", (unsigned)value);
    lv_textarea_set_text(self->_counter_value_input, value_text);
    self->_ctx.LogEvent("mf0 counter %u = %u%s", (unsigned)index, (unsigned)value, tearing ? ", torn" : "");
}

void Mf0Page::on_write_counter(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    const char* text = lv_textarea_get_text(self->_counter_value_input);
    char* end        = nullptr;
    const unsigned long value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || value > 0xFFFFFFul) {
        lv_label_set_text(self->_counter_label, "enter a decimal counter value (0 .. 16777215)");
        return;
    }
    const uint8_t index = self->selectedCounter();
    const uint16_t status =
        self->_ctx.client().Mf0SetCounterData(index, self->_reset_tearing, static_cast<uint32_t>(value));
    if (status != SUCCESS) {
        lv_label_set_text_fmt(self->_counter_label, "counter %u: write failed (%s)", (unsigned)index,
                              StatusText(status));
        self->_ctx.LogEvent("MF0_NTAG_SET_COUNTER_DATA failed: %s (0x%02X)", StatusText(status), status);
        return;
    }
    // The counter is write-only in the protocol, so read it back to show the
    // value the device actually stored.
    uint32_t readback = 0;
    bool tearing      = false;
    if (self->_ctx.client().Mf0GetCounterData(index, &readback, &tearing) == SUCCESS) {
        lv_label_set_text_fmt(self->_counter_label, "counter %u = %u%s (wrote %lu)", (unsigned)index,
                              (unsigned)readback, tearing ? " (torn)" : "", value);
        self->_ctx.LogEvent("mf0 counter %u written %lu, read back %u", (unsigned)index, value,
                            (unsigned)readback);
    } else {
        lv_label_set_text_fmt(self->_counter_label, "counter %u written, read-back failed", (unsigned)index);
    }
}

void Mf0Page::on_toggle_tearing(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr) {
        return;
    }
    self->_reset_tearing = !self->_reset_tearing;
    self->updateLabels();
    lv_label_set_text_fmt(self->_status_label, "counter writes will %s the tearing flag",
                          self->_reset_tearing ? "reset" : "keep");
}

void Mf0Page::on_read_detect_log(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || !self->_ctx.connected()) {
        return;
    }
    uint32_t count = 0;
    if (self->_ctx.client().Mf0GetDetectionCount(&count) != SUCCESS) {
        lv_label_set_text(self->_detect_label, "detection log not supported by this firmware");
        return;
    }
    if (count == 0) {
        lv_label_set_text(self->_detect_label, "detection log: empty");
        return;
    }

    // The log holds 4 byte captured passwords (the PWD_AUTH the reader sent).
    uint8_t data[16 * 4] = {};
    size_t length        = 0;
    const uint16_t status = self->_ctx.client().Mf0GetDetectionLog(0, data, sizeof(data), &length);
    if (status != SUCCESS || length == 0) {
        lv_label_set_text_fmt(self->_detect_label, "detection log: %u record(s), read failed (%s)",
                              (unsigned)count, StatusText(status));
        return;
    }

    char text[512];
    size_t at = 0;
    const size_t records = length / 4;
    for (size_t i = 0; i < records && at + 24 < sizeof(text); ++i) {
        char hex[16];
        ui::FormatHex(data + i * 4, 4, hex, sizeof(hex), "");
        const int r = snprintf(text + at, sizeof(text) - at, "%s%s", i == 0 ? "" : "\n", hex);
        if (r <= 0 || static_cast<size_t>(r) >= sizeof(text) - at) {
            break;
        }
        at += static_cast<size_t>(r);
    }
    lv_label_set_text_fmt(self->_detect_label, "detection log (%u stored, showing %u):\n%s", (unsigned)count,
                          (unsigned)records, text);
    self->_ctx.LogEvent("mf0 detection log: %u stored, read %u", (unsigned)count, (unsigned)records);
}

// ---------------------------------------------------------------------------
// Input plumbing
// ---------------------------------------------------------------------------

void Mf0Page::on_page_step(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_page_spinbox == nullptr) {
        return;
    }
    const int delta = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    int32_t value   = lv_spinbox_get_value(self->_page_spinbox) + delta;
    if (value < 0) {
        value = 0;
    }
    if (value > 255) {
        value = 255;
    }
    lv_spinbox_set_value(self->_page_spinbox, value);
}

void Mf0Page::on_counter_step(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_counter_spinbox == nullptr) {
        return;
    }
    const int delta = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
    int32_t value   = lv_spinbox_get_value(self->_counter_spinbox) + delta;
    if (value < 0) {
        value = 0;
    }
    if (value > 2) {
        value = 2;
    }
    lv_spinbox_set_value(self->_counter_spinbox, value);
}

void Mf0Page::on_field_focus(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
    if (self == nullptr || self->_keyboard == nullptr) {
        return;
    }
    lv_keyboard_set_textarea(self->_keyboard, lv_event_get_target_obj(e));
    lv_obj_clear_flag(self->_keyboard, LV_OBJ_FLAG_HIDDEN);
}

void Mf0Page::on_keyboard_event(lv_event_t* e)
{
    auto* self = (e != nullptr) ? static_cast<Mf0Page*>(lv_event_get_user_data(e)) : s_active;
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

bool Mf0Page::OnKey(uint8_t hid_key_code, uint8_t modifier)
{
    // Keyboard shortcuts for the two read actions a user repeats most.
    if (hid_key_code == ui::key::kEnter) {
        on_read_pages(nullptr);
        return true;
    }
    const char c = ui::HidKeyToAscii(hid_key_code, modifier);
    if (c == 'r' || c == 'R') {
        on_read_config(nullptr);
        return true;
    }
    if (c == 'l' || c == 'L') {
        on_read_detect_log(nullptr);
        return true;
    }
    return false;
}

}  // namespace app
