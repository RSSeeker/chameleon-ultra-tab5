// SPDX-License-Identifier: MIT
//
// Minimal LVGL UI toolkit: page base class and a navigation shell.
//
// Deliberately small: this port drives LVGL directly rather than pulling in an
// application framework, because every extra framework dependency on this board
// has to be vendored for offline builds and the UI here is a handful of screens.

#pragma once

#include <lvgl.h>

namespace ui {

/// Colour palette shared by every screen.
namespace theme {
constexpr uint32_t kBg        = 0x0E1116;  ///< window background
constexpr uint32_t kSurface   = 0x151A21;  ///< cards / list rows
constexpr uint32_t kSurfaceHi = 0x1D2530;  ///< hovered / selected row
constexpr uint32_t kBorder    = 0x263041;
constexpr uint32_t kText      = 0xE2E8F0;
constexpr uint32_t kTextDim   = 0x94A3B8;
constexpr uint32_t kTextFaint = 0x64748B;
constexpr uint32_t kAccent    = 0x4ADE80;  ///< ok / enabled
constexpr uint32_t kAccentDim = 0x22C55E;
constexpr uint32_t kWarn      = 0xFACC15;
constexpr uint32_t kError     = 0xF87171;
constexpr uint32_t kInfo      = 0x60A5FA;
constexpr uint32_t kMono      = 0x93C5FD;
}  // namespace theme

/// Fonts used across the UI (enabled via CONFIG_LV_FONT_MONTSERRAT_*).
extern const lv_font_t* FontSmall;
extern const lv_font_t* FontBody;
extern const lv_font_t* FontMedium;
extern const lv_font_t* FontLarge;
extern const lv_font_t* FontTitle;

/// Load the font pointers. Call once before building any screen.
void InitFonts();

/**
 * @brief Translate a HID keyboard usage id to a printable ASCII character.
 *
 * Covers the US layout letters, digits and the common symbols in both unshifted
 * and shifted form, which is what the nickname and hex fields need. Returns 0
 * when the key produces no character.
 */
char HidKeyToAscii(uint8_t hid_key_code, uint8_t modifier);

/// HID usage ids the UI reacts to directly.
namespace key {
constexpr uint8_t kEnter     = 0x28;
constexpr uint8_t kEscape    = 0x29;
constexpr uint8_t kBackspace = 0x2A;
constexpr uint8_t kDelete    = 0x4C;
}  // namespace key

/**
 * @brief Parse a hex string ("FF00AB", separators allowed and ignored).
 *
 * A trailing odd digit is dropped, so "ABC" yields one byte (0xAB) rather than a
 * partial value. Returns the number of bytes written.
 */
size_t ParseHex(const char* text, uint8_t* out, size_t out_size);

/// Format bytes as uppercase hex, `sep` between bytes ("" for none).
void FormatHex(const uint8_t* data, size_t len, char* out, size_t out_size, const char* sep = " ");

/**
 * @brief A rounded button with a centred label, positioned from the top left.
 *
 * The pages had grown three private copies of this; a label that is the button's
 * first child is also how a state button shows "on"/"off" without a second
 * widget, so the shape is worth fixing in one place.
 */
lv_obj_t* MakeButton(lv_obj_t* parent, const char* text, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h,
                     uint32_t color, lv_event_cb_t cb, void* user);

/// Replace the label of a button built by MakeButton().
void SetButtonText(lv_obj_t* button, const char* text);

/// A one line textarea preceded by a small caption, the shape every hex field
/// on these pages shares. `on_focus` is called with LV_EVENT_FOCUSED so the page
/// can raise its on-screen keyboard.
lv_obj_t* MakeField(lv_obj_t* parent, const char* caption, lv_coord_t x, lv_coord_t y, lv_coord_t width,
                    uint32_t max_length, lv_event_cb_t on_focus, void* user);

/**
 * @brief One full screen of the application.
 *
 * Create() builds widgets into the shell's content area; Destroy() releases
 * them. Refresh() is called when the page becomes visible and whenever the
 * application asks for an update (for example after a device event).
 */
class Page {
public:
    virtual ~Page() = default;

    /// Human readable tab title.
    virtual const char* title() const = 0;

    /**
     * @brief Build the page content.
     * @param parent container owned by the shell, already sized
     */
    virtual void Create(lv_obj_t* parent) = 0;

    /// Called when the page becomes the active tab.
    virtual void OnEnter()
    {
    }

    /// Called when another page takes over.
    virtual void OnLeave()
    {
    }

    /// Pull fresh state from the device / session and repaint.
    virtual void Refresh()
    {
    }

    /**
     * @brief Handle a physical keyboard key.
     *
     * @param hid_key_code HID usage id (USB HID Usage Tables, keyboard page)
     * @param modifier     HID modifier byte: bit0 ctrl, bit1 shift, bit2 alt
     * @return true when the page consumed the key
     */
    virtual bool OnKey(uint8_t hid_key_code, uint8_t modifier)
    {
        (void)hid_key_code;
        (void)modifier;
        return false;
    }

    /// Delete the widgets this page created.
    virtual void Destroy();

    lv_obj_t* root() const
    {
        return _root;
    }

protected:
    lv_obj_t* _root = nullptr;
};

/**
 * @brief Navigation shell: title bar, tab strip, status bar, page container.
 *
 * Owns one Page instance per tab. Only the active page's widgets exist, which
 * keeps the LVGL object count low on this board.
 */
class Shell {
public:
    /// Tab slots. Seven are in use (Slot, Device, Card, Keys, Emulate, NTAG,
    /// Log); the eighth is headroom for a tools page.
    static constexpr int kMaxTabs = 8;

    /// Status bar feed, updated from the transport layer.
    struct Status {
        bool connected  = false;
        const char* line1 = "waiting for device";
        const char* line2 = "";
    };

    /**
     * @brief Create the shell on the active screen.
     * @return false if the LVGL lock could not be taken
     */
    bool Create();

    /**
     * @brief Register a page in a tab slot.
     * @param index tab index, must be < kMaxTabs and unique
     */
    void AddPage(int index, Page* page, bool take_ownership = true);

    /// Build the tab strip and show the first page. Call after AddPage().
    void Finalize();

    /// Switch to a tab by index.
    void ShowPage(int index);

    /// Currently visible tab index, or -1.
    int currentIndex() const
    {
        return _current;
    }

    /**
     * @brief Update the status bar.
     *
     * Safe to call from any task: takes the LVGL lock itself.
     */
    void SetStatus(bool connected, const char* line1, const char* line2);

    /// Ask the active page to repaint. Safe to call from any task.
    void RefreshActive();

    /**
     * @brief Offer a physical keyboard key to the active page.
     *
     * @return true when the page consumed the key, in which case the caller must
     *         not also treat it as a shortcut
     */
    bool ForwardKey(uint8_t hid_key_code, uint8_t modifier);

    /// Append a line to the shared traffic log page (if present).
    void PushLog(const char* line);

    /// Container that pages build into.
    lv_obj_t* content() const
    {
        return _content;
    }

private:
    void rebuild_tabs_locked();

    struct Slot {
        Page* page     = nullptr;
        bool owned     = true;
        lv_obj_t* tab  = nullptr;
    };

    Slot _slots[kMaxTabs];
    int _current = -1;

    lv_obj_t* _content     = nullptr;
    lv_obj_t* _tab_strip   = nullptr;
    lv_obj_t* _status_dot  = nullptr;
    lv_obj_t* _status_text = nullptr;
    lv_obj_t* _status_sub  = nullptr;

    char _status_line1[64] = {};
    char _status_line2[64] = {};
};

}  // namespace ui
