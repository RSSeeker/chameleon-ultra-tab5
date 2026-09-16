// SPDX-License-Identifier: MIT

#include "ui.h"

#include <stdio.h>
#include <string.h>

#include <bsp/m5stack_tab5.h>

namespace ui {

const lv_font_t* FontSmall  = nullptr;
const lv_font_t* FontBody   = nullptr;
const lv_font_t* FontMedium = nullptr;
const lv_font_t* FontLarge  = nullptr;
const lv_font_t* FontTitle  = nullptr;

void InitFonts()
{
    // These are guaranteed by CONFIG_LV_FONT_MONTSERRAT_* in sdkconfig.defaults.
    FontSmall  = &lv_font_montserrat_14;
    FontBody   = &lv_font_montserrat_16;
    FontMedium = &lv_font_montserrat_20;
    FontLarge  = &lv_font_montserrat_28;
    FontTitle  = &lv_font_montserrat_32;
}

void Page::Destroy()
{
    if (_root != nullptr) {
        lv_obj_delete(_root);
        _root = nullptr;
    }
}

namespace {

/// HID modifier bits (USB HID, keyboard page).
constexpr uint8_t kModShift = 0x02;

/**
 * Unshifted characters indexed by HID usage id, USB HID Usage Tables section 10.
 *
 * 0x04..0x1D are a..z, 0x1E..0x26 are 1..9,0, 0x27..0x38 are the symbol row, and
 * a few more live above 0x64. Everything else maps to 0 (no character).
 */
char hid_unshifted(uint8_t code)
{
    if (code >= 0x04 && code <= 0x1D) {
        return static_cast<char>('a' + (code - 0x04));
    }
    switch (code) {
        case 0x1E: return '1';
        case 0x1F: return '2';
        case 0x20: return '3';
        case 0x21: return '4';
        case 0x22: return '5';
        case 0x23: return '6';
        case 0x24: return '7';
        case 0x25: return '8';
        case 0x26: return '9';
        case 0x27: return '0';
        case 0x28: return '\n';  // Enter
        case 0x2A: return '\b';  // Backspace
        case 0x2C: return ' ';   // Space
        case 0x2D: return '-';
        case 0x2E: return '=';
        case 0x2F: return '[';
        case 0x30: return ']';
        case 0x31: return '\\';
        case 0x33: return ';';
        case 0x34: return '\'';
        case 0x35: return '`';
        case 0x36: return ',';
        case 0x37: return '.';
        case 0x38: return '/';
        default: return 0;
    }
}

/// Shifted counterpart of a HID usage id, or 0 when unchanged / not shifted.
char hid_shifted(uint8_t code)
{
    if (code >= 0x04 && code <= 0x1D) {
        return static_cast<char>('A' + (code - 0x04));
    }
    switch (code) {
        case 0x1E: return '!';
        case 0x1F: return '@';
        case 0x20: return '#';
        case 0x21: return '$';
        case 0x22: return '%';
        case 0x23: return '^';
        case 0x24: return '&';
        case 0x25: return '*';
        case 0x26: return '(';
        case 0x27: return ')';
        case 0x2D: return '_';
        case 0x2E: return '+';
        case 0x2F: return '{';
        case 0x30: return '}';
        case 0x31: return '|';
        case 0x33: return ':';
        case 0x34: return '"';
        case 0x35: return '~';
        case 0x36: return '<';
        case 0x37: return '>';
        case 0x38: return '?';
        default: return 0;
    }
}

}  // namespace

char HidKeyToAscii(uint8_t hid_key_code, uint8_t modifier)
{
    if (modifier & kModShift) {
        const char c = hid_shifted(hid_key_code);
        if (c != 0) {
            return c;
        }
    }
    return hid_unshifted(hid_key_code);
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

bool Shell::Create()
{
    if (!bsp_display_lock(0)) {
        return false;
    }

    lv_obj_t* screen = lv_screen_active();
    lv_obj_set_style_bg_color(screen, lv_color_hex(theme::kBg), LV_PART_MAIN);
    lv_obj_set_style_pad_all(screen, 0, LV_PART_MAIN);
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_SCROLLABLE);

    // ---- title bar -------------------------------------------------------
    lv_obj_t* title = lv_label_create(screen);
    lv_label_set_text(title, "Chameleon Ultra");
    lv_obj_set_style_text_font(title, FontTitle, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kAccent), LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 20, 10);

    lv_obj_t* subtitle = lv_label_create(screen);
    lv_label_set_text(subtitle, "M5Stack Tab5");
    lv_obj_set_style_text_font(subtitle, FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(subtitle, lv_color_hex(theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(subtitle, LV_ALIGN_TOP_LEFT, 22, 46);

    // ---- status bar (top right) ------------------------------------------
    lv_obj_t* status = lv_obj_create(screen);
    lv_obj_set_size(status, 380, 62);
    lv_obj_align(status, LV_ALIGN_TOP_RIGHT, -16, 10);
    lv_obj_set_style_bg_color(status, lv_color_hex(theme::kSurface), LV_PART_MAIN);
    lv_obj_set_style_border_color(status, lv_color_hex(theme::kBorder), LV_PART_MAIN);
    lv_obj_set_style_radius(status, 10, LV_PART_MAIN);
    lv_obj_set_style_pad_all(status, 10, LV_PART_MAIN);
    lv_obj_clear_flag(status, LV_OBJ_FLAG_SCROLLABLE);

    _status_dot = lv_obj_create(status);
    lv_obj_set_size(_status_dot, 12, 12);
    lv_obj_set_style_radius(_status_dot, LV_RADIUS_CIRCLE, LV_PART_MAIN);
    lv_obj_set_style_bg_color(_status_dot, lv_color_hex(theme::kError), LV_PART_MAIN);
    lv_obj_set_style_border_width(_status_dot, 0, LV_PART_MAIN);
    lv_obj_align(_status_dot, LV_ALIGN_TOP_LEFT, 0, 6);

    _status_text = lv_label_create(status);
    lv_label_set_text(_status_text, "waiting for device");
    lv_obj_set_style_text_font(_status_text, FontSmall, LV_PART_MAIN);
    lv_obj_set_style_text_color(_status_text, lv_color_hex(theme::kText), LV_PART_MAIN);
    lv_obj_align(_status_text, LV_ALIGN_TOP_LEFT, 22, 2);

    _status_sub = lv_label_create(status);
    lv_label_set_text(_status_sub, "");
    lv_obj_set_style_text_font(_status_sub, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(_status_sub, lv_color_hex(theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(_status_sub, LV_ALIGN_TOP_LEFT, 22, 22);

    // ---- tab strip -------------------------------------------------------
    _tab_strip = lv_obj_create(screen);
    lv_obj_set_size(_tab_strip, 1250, 54);
    lv_obj_align(_tab_strip, LV_ALIGN_TOP_LEFT, 16, 78);
    lv_obj_set_style_bg_opa(_tab_strip, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_tab_strip, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_tab_strip, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_column(_tab_strip, 8, LV_PART_MAIN);
    lv_obj_set_flex_flow(_tab_strip, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(_tab_strip, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(_tab_strip, LV_OBJ_FLAG_SCROLLABLE);

    // ---- content area ----------------------------------------------------
    _content = lv_obj_create(screen);
    lv_obj_set_size(_content, 1250, 590);
    lv_obj_align(_content, LV_ALIGN_BOTTOM_LEFT, 16, -14);
    lv_obj_set_style_bg_opa(_content, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_border_width(_content, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(_content, 0, LV_PART_MAIN);
    lv_obj_clear_flag(_content, LV_OBJ_FLAG_SCROLLABLE);

    bsp_display_unlock();
    return true;
}

void Shell::AddPage(int index, Page* page, bool take_ownership)
{
    if (index < 0 || index >= kMaxTabs || page == nullptr) {
        return;
    }
    _slots[index].page  = page;
    _slots[index].owned = take_ownership;
}

void Shell::rebuild_tabs_locked()
{
    if (_tab_strip == nullptr) {
        return;
    }
    lv_obj_clean(_tab_strip);

    for (int i = 0; i < kMaxTabs; ++i) {
        Slot& slot = _slots[i];
        if (slot.page == nullptr) {
            continue;
        }

        lv_obj_t* tab = lv_button_create(_tab_strip);
        lv_obj_set_height(tab, 44);
        lv_obj_set_style_radius(tab, 10, LV_PART_MAIN);
        lv_obj_set_style_border_width(tab, 0, LV_PART_MAIN);
        lv_obj_set_style_shadow_width(tab, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_hor(tab, 20, LV_PART_MAIN);

        const bool active = (i == _current);
        lv_obj_set_style_bg_color(tab, lv_color_hex(active ? theme::kAccent : theme::kSurface), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(tab, LV_OPA_COVER, LV_PART_MAIN);

        lv_obj_t* label = lv_label_create(tab);
        lv_label_set_text(label, slot.page->title());
        lv_obj_set_style_text_font(label, FontBody, LV_PART_MAIN);
        lv_obj_set_style_text_color(label, lv_color_hex(active ? 0x0B1220 : theme::kText), LV_PART_MAIN);
        lv_obj_center(label);

        lv_obj_add_event_cb(
            tab,
            [](lv_event_t* e) {
                auto* self = static_cast<Shell*>(lv_event_get_user_data(e));
                const int idx = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target_obj(e));
                if (self != nullptr) {
                    self->ShowPage(idx);
                }
            },
            LV_EVENT_CLICKED, this);
        lv_obj_set_user_data(tab, (void*)(intptr_t)i);

        slot.tab = tab;
    }
}

void Shell::Finalize()
{
    if (!bsp_display_lock(0)) {
        return;
    }
    for (int i = 0; i < kMaxTabs; ++i) {
        if (_slots[i].page != nullptr) {
            ShowPage(i);
            break;
        }
    }
    bsp_display_unlock();
}

void Shell::ShowPage(int index)
{
    if (index < 0 || index >= kMaxTabs || _slots[index].page == nullptr) {
        return;
    }
    if (_current == index) {
        return;
    }

    const bool locked_here = bsp_display_lock(0);

    // Tear down the previous page so only one page's widgets exist at a time.
    if (_current >= 0 && _slots[_current].page != nullptr) {
        _slots[_current].page->OnLeave();
        _slots[_current].page->Destroy();
    }

    _current = index;
    rebuild_tabs_locked();

    Page* page = _slots[index].page;
    if (page->root() == nullptr) {
        page->Create(_content);
    }
    page->OnEnter();
    page->Refresh();

    if (locked_here) {
        bsp_display_unlock();
    }
}

void Shell::SetStatus(bool connected, const char* line1, const char* line2)
{
    snprintf(_status_line1, sizeof(_status_line1), "%s", line1 != nullptr ? line1 : "");
    snprintf(_status_line2, sizeof(_status_line2), "%s", line2 != nullptr ? line2 : "");

    if (!bsp_display_lock(1000)) {
        return;
    }
    if (_status_dot != nullptr) {
        lv_obj_set_style_bg_color(_status_dot, lv_color_hex(connected ? theme::kAccent : theme::kError), LV_PART_MAIN);
    }
    if (_status_text != nullptr) {
        lv_label_set_text(_status_text, _status_line1);
    }
    if (_status_sub != nullptr) {
        lv_label_set_text(_status_sub, _status_line2);
    }
    bsp_display_unlock();
}

void Shell::RefreshActive()
{
    if (_current < 0 || _slots[_current].page == nullptr) {
        return;
    }
    if (!bsp_display_lock(1000)) {
        return;
    }
    _slots[_current].page->Refresh();
    bsp_display_unlock();
}

bool Shell::ForwardKey(uint8_t hid_key_code, uint8_t modifier)
{
    if (_current < 0 || _slots[_current].page == nullptr) {
        return false;
    }
    if (!bsp_display_lock(1000)) {
        return false;
    }
    const bool consumed = _slots[_current].page->OnKey(hid_key_code, modifier);
    bsp_display_unlock();
    return consumed;
}

void Shell::PushLog(const char* line)
{
    for (int i = 0; i < kMaxTabs; ++i) {
        if (_slots[i].page != nullptr && _slots[i].page->title() != nullptr &&
            strcmp(_slots[i].page->title(), "Log") == 0) {
            // The log page pulls from a shared buffer instead of being pushed
            // into, so simply ask it to repaint if it is visible.
            if (_current == i) {
                RefreshActive();
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Hex helpers
//
// Shared by every page that takes hex from a text field. They used to be private
// copies; three copies of a parser is three places for a length or separator bug
// to hide, and "parse what the user typed" is exactly the kind of thing that
// wants one implementation.
// ---------------------------------------------------------------------------

size_t ParseHex(const char* text, uint8_t* out, size_t out_size)
{
    if (text == nullptr || out == nullptr) {
        return 0;
    }
    size_t n = 0;
    int hi   = -1;
    for (const char* p = text; *p != '\0'; ++p) {
        const char c = *p;
        int v;
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        } else {
            continue;  // separator: spaces, dashes, colons
        }
        if (hi < 0) {
            hi = v;
            continue;
        }
        if (n >= out_size) {
            break;
        }
        out[n++] = static_cast<uint8_t>((hi << 4) | v);
        hi       = -1;
    }
    return n;
}

void FormatHex(const uint8_t* data, size_t len, char* out, size_t out_size, const char* sep)
{
    if (out == nullptr || out_size == 0) {
        return;
    }
    out[0]         = '\0';
    size_t written = 0;
    for (size_t i = 0; i < len; ++i) {
        const int r = snprintf(out + written, out_size - written, "%s%02X", i == 0 ? "" : sep, data[i]);
        if (r <= 0 || static_cast<size_t>(r) >= out_size - written) {
            return;
        }
        written += static_cast<size_t>(r);
    }
}

lv_obj_t* MakeButton(lv_obj_t* parent, const char* text, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h,
                     uint32_t color, lv_event_cb_t cb, void* user)
{
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_set_size(button, w, h);
    lv_obj_set_style_radius(button, 8, LV_PART_MAIN);
    lv_obj_set_style_bg_color(button, lv_color_hex(color), LV_PART_MAIN);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, y);
    if (cb != nullptr) {
        lv_obj_add_event_cb(button, cb, LV_EVENT_CLICKED, user);
    }

    lv_obj_t* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, FontSmall, LV_PART_MAIN);
    lv_obj_center(label);
    return button;
}

void SetButtonText(lv_obj_t* button, const char* text)
{
    if (button == nullptr || text == nullptr) {
        return;
    }
    lv_obj_t* label = lv_obj_get_child(button, 0);
    if (label != nullptr) {
        lv_label_set_text(label, text);
    }
}

lv_obj_t* MakeField(lv_obj_t* parent, const char* caption, lv_coord_t x, lv_coord_t y, lv_coord_t width,
                    uint32_t max_length, lv_event_cb_t on_focus, void* user)
{
    lv_obj_t* label = lv_label_create(parent);
    lv_label_set_text(label, caption);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, lv_color_hex(theme::kTextFaint), LV_PART_MAIN);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, x, y);

    lv_obj_t* input = lv_textarea_create(parent);
    lv_textarea_set_one_line(input, true);
    lv_textarea_set_max_length(input, max_length);
    lv_obj_set_size(input, width, 42);
    lv_obj_set_style_text_font(input, FontSmall, LV_PART_MAIN);
    lv_obj_align(input, LV_ALIGN_TOP_LEFT, x, y + 16);
    if (on_focus != nullptr) {
        lv_obj_add_event_cb(input, on_focus, LV_EVENT_FOCUSED, user);
    }
    return input;
}

}  // namespace ui
