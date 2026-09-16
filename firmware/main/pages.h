// SPDX-License-Identifier: MIT
//
// UI pages of the Chameleon client.

#pragma once

#include "chameleon_client.h"
#include "ui.h"

namespace app {

class Context;

/**
 * @brief Slot manager: enable/disable, tag type and active slot for all 8 slots.
 */
class SlotPage : public ui::Page {
public:
    explicit SlotPage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Slots";
    }

    void Create(lv_obj_t* parent) override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    struct Row {
        lv_obj_t* card        = nullptr;
        lv_obj_t* slot_label  = nullptr;
        lv_obj_t* nick_label  = nullptr;
        lv_obj_t* rename_btn  = nullptr;
        lv_obj_t* hf_dropdown = nullptr;
        lv_obj_t* lf_dropdown = nullptr;
        lv_obj_t* active_btn  = nullptr;
        lv_obj_t* state_label = nullptr;
    };

    /// Nickname editor: one shared dialog reused for every slot.
    struct NickEditor {
        lv_obj_t* dialog   = nullptr;
        lv_obj_t* input    = nullptr;
        lv_obj_t* keyboard = nullptr;
        int slot           = -1;
    };

    static void on_hf_changed(lv_event_t* e);
    static void on_lf_changed(lv_event_t* e);
    static void on_active_clicked(lv_event_t* e);
    static void on_rename_clicked(lv_event_t* e);
    static void on_nick_dialog_event(lv_event_t* e);

    void apply_tag_type(int slot, bool hf, uint16_t tag_type);
    void open_nick_editor(int slot);
    void close_nick_editor();
    void commit_nick();

    Context& _ctx;
    Row _rows[chameleon::kSlotCount];
    NickEditor _nick;

    /// Suppresses the dropdown callbacks while Refresh() is writing values.
    bool _updating = false;
};

/**
 * @brief Device information and settings.
 */
class DevicePage : public ui::Page {
public:
    explicit DevicePage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Device";
    }

    void Create(lv_obj_t* parent) override;
    void Refresh() override;

private:
    static void on_mode_clicked(lv_event_t* e);
    static void on_save_clicked(lv_event_t* e);
    static void on_animation_changed(lv_event_t* e);
    static void on_sleep_changed(lv_event_t* e);
    static void on_report_clicked(lv_event_t* e);

    Context& _ctx;

    lv_obj_t* _ident_label  = nullptr;
    lv_obj_t* _battery_label = nullptr;
    lv_obj_t* _mode_label   = nullptr;
    lv_obj_t* _mem_label    = nullptr;
    lv_obj_t* _mode_btn     = nullptr;
    lv_obj_t* _anim_dropdown = nullptr;
    lv_obj_t* _sleep_dropdown = nullptr;

    bool _updating = false;
};

/**
 * @brief Card operations: HF/LF scan, Mifare Classic block read/write.
 */
class CardPage : public ui::Page {
public:
    explicit CardPage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Cards";
    }

    void Create(lv_obj_t* parent) override;
    void Destroy() override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    static void on_scan(lv_event_t* e);
    static void on_clone(lv_event_t* e);
    static void on_reader_changed(lv_event_t* e);
    static void on_use_found_key(lv_event_t* e);
    static void on_key_focus(lv_event_t* e);
    static void on_keyboard_event(lv_event_t* e);
    static void on_read_block(lv_event_t* e);
    static void on_write_block(lv_event_t* e);
    static void on_block_step(lv_event_t* e);

    /// Card commands require reader mode; switch and report if needed.
    bool ensureReaderMode();

    /// Run the currently selected reader and render its result.
    void runScan();

    /// Clone the last scanned id onto a T55xx tag when the reader supports it.
    void cloneLastTag();

    Context& _ctx;

    lv_obj_t* _scan_hf_btn      = nullptr;
    lv_obj_t* _reader_dropdown  = nullptr;
    lv_obj_t* _clone_btn        = nullptr;
    lv_obj_t* _use_key_btn      = nullptr;
    lv_obj_t* _scan_hint        = nullptr;
    lv_obj_t* _detail_label     = nullptr;

    /// Last id read from a card, retained so it can be cloned onto a T55xx tag.
    uint8_t _last_id[16]   = {};
    size_t _last_id_length = 0;
    int _last_reader       = -1;  ///< index into kReaders; -1 when nothing scanned
    uint16_t _last_write_cmd = 0;  ///< write command matching the scanned card

    lv_obj_t* _keytype_dropdown = nullptr;
    lv_obj_t* _block_spinbox    = nullptr;
    lv_obj_t* _key_input        = nullptr;
    lv_obj_t* _data_input       = nullptr;
    lv_obj_t* _keyboard         = nullptr;
    lv_obj_t* _read_btn         = nullptr;
    lv_obj_t* _write_btn        = nullptr;
};

/**
 * @brief Mifare Classic key recovery: factory key check and the darkside attack.
 */
class KeysPage : public ui::Page {
public:
    explicit KeysPage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Keys";
    }

    void Create(lv_obj_t* parent) override;
    void Destroy() override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    static void on_check_keys(lv_event_t* e);
    static void on_darkside(lv_event_t* e);
    static void on_nested(lv_event_t* e);
    static void on_hardnested(lv_event_t* e);
    static void on_hardnested_slow(lv_event_t* e);
    static void on_export_nonces(lv_event_t* e);
    static void on_stop(lv_event_t* e);
    static void on_copy_key(lv_event_t* e);
    static void on_block_step(lv_event_t* e);

    /// Block number and key type currently selected.
    uint8_t selectedBlock() const;
    chameleon::MfcKeyType selectedKeyType() const;

    /// Repaint the progress text and the found key field.
    void updateLabels();

    Context& _ctx;

    /// Hardnested acquisition mode: false = the CLI's default fast mode, true =
    /// its --slow flag. Only meaningful between jobs, read when one starts.
    bool _slow = false;

    lv_obj_t* _block_spinbox    = nullptr;
    lv_obj_t* _keytype_dropdown = nullptr;
    lv_obj_t* _check_btn        = nullptr;
    lv_obj_t* _darkside_btn     = nullptr;
    lv_obj_t* _nested_btn       = nullptr;
    lv_obj_t* _hardnested_btn   = nullptr;
    lv_obj_t* _hn_slow_btn      = nullptr;
    lv_obj_t* _hn_slow_label    = nullptr;
    lv_obj_t* _hn_export_btn    = nullptr;
    lv_obj_t* _hn_info_label    = nullptr;
    lv_obj_t* _stop_btn         = nullptr;
    lv_obj_t* _copy_btn         = nullptr;
    lv_obj_t* _status_label     = nullptr;
    lv_obj_t* _result_label     = nullptr;
    lv_obj_t* _hint_label       = nullptr;
};

/**
 * @brief Configure the card the active slot emulates.
 *
 * The Chameleon's main job is to *be* a card, so this page edits the emulated
 * identity rather than reading a real one: the LF card number, the HF
 * anti-collision data (UID/ATQA/SAK/ATS) and the Mifare Classic block contents.
 * Everything here is device-side state, so "write then read back" verifies the
 * whole path without a physical card.
 */
class EmulatePage : public ui::Page {
public:
    explicit EmulatePage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Emulate";
    }

    void Create(lv_obj_t* parent) override;
    void Destroy() override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    static void on_read_card(lv_event_t* e);
    static void on_write_lf(lv_event_t* e);
    static void on_write_hf(lv_event_t* e);
    static void on_read_block(lv_event_t* e);
    static void on_write_block(lv_event_t* e);
    static void on_block_step(lv_event_t* e);
    static void on_field_focus(lv_event_t* e);
    static void on_keyboard_event(lv_event_t* e);

    // ---- classic emulator options ----
    static void on_read_options(lv_event_t* e);
    static void on_toggle(lv_event_t* e);      ///< one of the five on/off settings
    static void on_cycle_write_mode(lv_event_t* e);
    static void on_cycle_prng(lv_event_t* e);

    /// LF protocol of the active slot; false when the slot has no configurable LF id.
    bool activeLfProtocol(chameleon::Client::LfEmuProtocol* out, size_t* id_length) const;

    uint8_t selectedBlock() const;
    void updateSummary();
    /// Repaint the option buttons from the cached values.
    void updateOptions();

    /// Textarea the physical keyboard should type into, or null.
    lv_obj_t* focusedField() const;

    Context& _ctx;

    lv_obj_t* _summary_label = nullptr;
    lv_obj_t* _lf_input      = nullptr;
    lv_obj_t* _uid_input     = nullptr;
    lv_obj_t* _atqa_input    = nullptr;
    lv_obj_t* _sak_input     = nullptr;
    lv_obj_t* _ats_input     = nullptr;
    lv_obj_t* _block_spinbox = nullptr;
    lv_obj_t* _data_input    = nullptr;
    lv_obj_t* _status_label  = nullptr;
    lv_obj_t* _options_label = nullptr;
    lv_obj_t* _keyboard      = nullptr;
    lv_obj_t* _read_card_btn = nullptr;
    lv_obj_t* _write_lf_btn  = nullptr;
    lv_obj_t* _write_hf_btn  = nullptr;
    lv_obj_t* _read_block_btn = nullptr;
    lv_obj_t* _write_block_btn = nullptr;
    lv_obj_t* _options_btn[5]  = {};  ///< gen1a, gen2, block anti-coll, detection, use-mf1-coll
    lv_obj_t* _write_mode_btn  = nullptr;
    lv_obj_t* _prng_btn        = nullptr;

    /// Last values read from the device, used to draw the option buttons.
    chameleon::Client::Mf1EmulatorConfig _config = {};
    uint8_t _prng_type = 0;
    bool _options_valid = false;
};

/**
 * @brief MF0 / NTAG emulator: pages, version, signature, counters, config.
 *
 * The active slot can emulate an MF0UL/NTAG tag; this page is the host side of
 * that emulator (wave W3). Every write is followed by a read-back, because a
 * write the device accepts can still be dropped by a read-only tag.
 */
class Mf0Page : public ui::Page {
public:
    explicit Mf0Page(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "NTAG";
    }

    void Create(lv_obj_t* parent) override;
    void Destroy() override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    static void on_read_config(lv_event_t* e);
    static void on_toggle_magic(lv_event_t* e);
    static void on_toggle_detection(lv_event_t* e);
    static void on_cycle_write_mode(lv_event_t* e);
    static void on_reset_auth(lv_event_t* e);
    static void on_read_pages(lv_event_t* e);
    static void on_write_pages(lv_event_t* e);
    static void on_read_version(lv_event_t* e);
    static void on_write_version(lv_event_t* e);
    static void on_read_signature(lv_event_t* e);
    static void on_write_signature(lv_event_t* e);
    static void on_read_counter(lv_event_t* e);
    static void on_write_counter(lv_event_t* e);
    static void on_toggle_tearing(lv_event_t* e);
    static void on_read_detect_log(lv_event_t* e);
    static void on_page_step(lv_event_t* e);
    static void on_counter_step(lv_event_t* e);
    static void on_field_focus(lv_event_t* e);
    static void on_keyboard_event(lv_event_t* e);

    /// The button's label is always its first child; this is how the state
    /// buttons show "on"/"off" without a second widget per setting.
    static void set_button_text(lv_obj_t* button, const char* text);
    static lv_obj_t* make_button(lv_obj_t* parent, const char* text, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                                 lv_coord_t h, uint32_t color, lv_event_cb_t cb, void* user);

    uint8_t selectedPage() const;
    uint8_t selectedCount() const;
    uint8_t selectedCounter() const;

    /// Repaint the state buttons and the config summary.
    void updateLabels();

    Context& _ctx;

    lv_obj_t* _config_label     = nullptr;
    lv_obj_t* _read_config_btn  = nullptr;
    lv_obj_t* _magic_btn        = nullptr;
    lv_obj_t* _detect_btn       = nullptr;
    lv_obj_t* _write_mode_btn   = nullptr;
    lv_obj_t* _reset_auth_btn   = nullptr;
    lv_obj_t* _detect_log_btn   = nullptr;
    lv_obj_t* _page_spinbox     = nullptr;
    lv_obj_t* _count_spinbox    = nullptr;
    lv_obj_t* _read_pages_btn   = nullptr;
    lv_obj_t* _write_pages_btn  = nullptr;
    lv_obj_t* _pages_label      = nullptr;
    lv_obj_t* _pages_input      = nullptr;
    lv_obj_t* _status_label     = nullptr;
    lv_obj_t* _keyboard         = nullptr;
    lv_obj_t* _version_input    = nullptr;
    lv_obj_t* _read_version_btn = nullptr;
    lv_obj_t* _write_version_btn = nullptr;
    lv_obj_t* _signature_input  = nullptr;
    lv_obj_t* _read_signature_btn  = nullptr;
    lv_obj_t* _write_signature_btn = nullptr;
    lv_obj_t* _counter_spinbox  = nullptr;
    lv_obj_t* _counter_value_input = nullptr;
    lv_obj_t* _read_counter_btn = nullptr;
    lv_obj_t* _write_counter_btn = nullptr;
    lv_obj_t* _tearing_btn      = nullptr;
    lv_obj_t* _counter_label    = nullptr;
    lv_obj_t* _detect_label     = nullptr;

    /// Last config read from the device, and whether it is meaningful yet.
    chameleon::Client::Mf0EmulatorConfig _config = {};
    bool _config_valid = false;
    uint8_t _magic     = 0;
    bool _magic_valid  = false;
    uint8_t _page_count = 0;
    bool _reset_tearing = false;
};

/**
 * @brief Operations that are not tied to one card type: ISO14443-4 / EMV / SEOS
 * and the raw HF / LF escape hatches.
 *
 * Two panels share the tab. They exist because these commands were implemented,
 * payload-verified and then unreachable from the UI - tools/verify_payloads.py
 * section [4] lists exactly that set, and this page is where it gets closed.
 */
class ToolsPage : public ui::Page {
public:
    explicit ToolsPage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Tools";
    }

    void Create(lv_obj_t* parent) override;
    void Destroy() override;
    void Refresh() override;
    bool OnKey(uint8_t hid_key_code, uint8_t modifier) override;

private:
    // panel construction
    void create_t4t_panel(lv_obj_t* parent);
    void create_raw_panel(lv_obj_t* parent);
    void create_system_panel(lv_obj_t* parent);
    void showMode(int mode);

    // ISO14443-4 / EMV / SEOS
    static void on_t4_set_anticoll(lv_event_t* e);
    static void on_t4_get_anticoll(lv_event_t* e);
    static void on_t4_scan_keep(lv_event_t* e);
    static void on_t4_apdu_send(lv_event_t* e);
    static void on_t4_apdu_recv(lv_event_t* e);
    static void on_t4_add_static(lv_event_t* e);
    static void on_t4_clear_static(lv_event_t* e);
    static void on_t4_reader_apdu(lv_event_t* e);
    static void on_t4_emv(lv_event_t* e);
    static void on_seos_read(lv_event_t* e);
    static void on_seos_write(lv_event_t* e);
    static void on_seos_write_keys(lv_event_t* e);

    // raw HF / LF
    static void on_raw_flag(lv_event_t* e);
    static void on_raw_send(lv_event_t* e);
    static void on_trace_sniff(lv_event_t* e);
    static void on_trace_auth(lv_event_t* e);
    static void on_mfkey32(lv_event_t* e);
    static void on_t55_toggle_pwd(lv_event_t* e);
    static void on_t55_toggle_page(lv_event_t* e);
    static void on_t55_write(lv_event_t* e);
    static void on_ioprox_decode(lv_event_t* e);
    static void on_ioprox_compose(lv_event_t* e);
    static void on_lf_sniff(lv_event_t* e);

    static void on_mode(lv_event_t* e);
    static void on_field_focus(lv_event_t* e);
    static void on_keyboard_event(lv_event_t* e);

    // system / MF1 panel
    static void on_hf14a_config_read(lv_event_t* e);
    static void on_hf14a_config_write(lv_event_t* e);
    static void on_sys_sense(lv_event_t* e);
    static void on_sys_set_enabled(lv_event_t* e);
    static void on_sys_read_nick(lv_event_t* e);
    static void on_sys_delete_nick(lv_event_t* e);
    static void on_sys_delete_sense(lv_event_t* e);
    static void on_sys_set_data_default(lv_event_t* e);
    static void on_sys_save_slot_data(lv_event_t* e);
    static void on_sys_button(lv_event_t* e);
    static void on_sys_button_fn(lv_event_t* e);
    static void on_sys_write_button_fn(lv_event_t* e);
    static void on_sys_destructive(lv_event_t* e);
    static void on_mf1_detect_count(lv_event_t* e);
    static void on_mf1_detect_log(lv_event_t* e);
    static void on_mf1_detect_support(lv_event_t* e);
    static void on_mf1_check_keys(lv_event_t* e);
    static void on_mf1_value_op(lv_event_t* e);
    static void on_mf1_value_apply(lv_event_t* e);
    static void on_mf1_enc_nested(lv_event_t* e);
    static void on_keys_keys(lv_event_t* e);
    static void on_keys_type(lv_event_t* e);

    /// Decode and display a sniff / auth-trace buffer, and mirror it to the log.
    void show_trace(const uint8_t* buffer, size_t length, const char* what);
    /// Parse a hex field into bytes.
    size_t field_bytes(lv_obj_t* field, uint8_t* out, size_t out_size) const;
    /// Parse a decimal / 0x-prefixed field, clamped to `max`.
    unsigned field_uint(lv_obj_t* field, unsigned fallback, unsigned max) const;

    Context& _ctx;

    lv_obj_t* _mode_btn[3] = {};
    lv_obj_t* _panel[3]    = {};
    lv_obj_t* _keyboard    = nullptr;
    int _mode              = 0;

    // t4t panel
    lv_obj_t* _t4_uid        = nullptr;
    lv_obj_t* _t4_atqa       = nullptr;
    lv_obj_t* _t4_sak        = nullptr;
    lv_obj_t* _t4_ats        = nullptr;
    lv_obj_t* _t4_apdu_out   = nullptr;
    lv_obj_t* _t4_cmd        = nullptr;
    lv_obj_t* _t4_resp       = nullptr;
    lv_obj_t* _t4_log        = nullptr;
    lv_obj_t* _t4_reader_apdu = nullptr;
    lv_obj_t* _t4_reader_log = nullptr;
    lv_obj_t* _seos_data     = nullptr;
    lv_obj_t* _seos_oid      = nullptr;
    lv_obj_t* _seos_tag      = nullptr;
    lv_obj_t* _seos_div      = nullptr;
    lv_obj_t* _seos_alg      = nullptr;
    lv_obj_t* _seos_auth     = nullptr;
    lv_obj_t* _seos_privenc  = nullptr;
    lv_obj_t* _seos_privmac  = nullptr;
    lv_obj_t* _seos_log      = nullptr;

    // raw panel
    lv_obj_t* _raw_flag[6]   = {};
    uint8_t _raw_flags       = 0x07;
    lv_obj_t* _raw_data      = nullptr;
    lv_obj_t* _raw_timeout   = nullptr;
    lv_obj_t* _raw_bitlen    = nullptr;
    lv_obj_t* _raw_log       = nullptr;
    lv_obj_t* _trace_timeout = nullptr;
    lv_obj_t* _trace_block   = nullptr;
    lv_obj_t* _trace_key     = nullptr;
    lv_obj_t* _trace_log     = nullptr;
    lv_obj_t* _mfk_uid       = nullptr;
    /// Last sniff / auth-trace buffer, kept so mfkey32 can crack it.
    uint8_t _trace_buffer[1024] = {};
    size_t _trace_length        = 0;
    lv_obj_t* _t55_block     = nullptr;
    lv_obj_t* _t55_word      = nullptr;
    lv_obj_t* _t55_pwd       = nullptr;
    lv_obj_t* _t55_usepwd    = nullptr;
    lv_obj_t* _t55_page1     = nullptr;
    bool _t55_use_pwd        = false;
    bool _t55_page1_on       = false;
    lv_obj_t* _ioprox_raw    = nullptr;
    lv_obj_t* _ioprox_ver    = nullptr;
    lv_obj_t* _ioprox_fc     = nullptr;
    lv_obj_t* _ioprox_cn     = nullptr;
    lv_obj_t* _ioprox_log    = nullptr;
    lv_obj_t* _lf_timeout    = nullptr;
    lv_obj_t* _lf_log        = nullptr;

    // system panel
    lv_obj_t* _sys_bcc       = nullptr;
    lv_obj_t* _sys_cl2       = nullptr;
    lv_obj_t* _sys_cl3       = nullptr;
    lv_obj_t* _sys_rats      = nullptr;
    lv_obj_t* _sys_slot      = nullptr;
    lv_obj_t* _sys_sense_btn = nullptr;
    lv_obj_t* _sys_nick_btn  = nullptr;
    lv_obj_t* _sys_button_btn = nullptr;
    lv_obj_t* _sys_fn        = nullptr;
    lv_obj_t* _sys_reset_btn = nullptr;
    lv_obj_t* _sys_wipe_btn  = nullptr;
    lv_obj_t* _sys_log       = nullptr;
    chameleon::TagSenseType _sys_sense = chameleon::TagSenseType::HF;
    char _sys_current_button = 'A';
    /// Index of the destructive action waiting for a second press (-1 = none).
    int _sys_arm_pending = -1;

    // MF1 diagnostics / advanced panel
    lv_obj_t* _mf1_log        = nullptr;
    lv_obj_t* _keys_block     = nullptr;
    lv_obj_t* _keys_keys      = nullptr;
    lv_obj_t* _keys_type_btn  = nullptr;
    chameleon::MfcKeyType _keys_type = chameleon::MfcKeyType::A;
    lv_obj_t* _vb_src_block   = nullptr;
    lv_obj_t* _vb_src_key     = nullptr;
    lv_obj_t* _vb_op_btn      = nullptr;
    lv_obj_t* _vb_operand     = nullptr;
    lv_obj_t* _vb_dst_block   = nullptr;
    lv_obj_t* _vb_dst_key     = nullptr;
    int _vb_op_index          = 1;  ///< 0 decrement, 1 increment, 2 restore
    lv_obj_t* _enc_key        = nullptr;
    lv_obj_t* _enc_sectors    = nullptr;
    lv_obj_t* _enc_start      = nullptr;
    lv_obj_t* _mf1_adv_log    = nullptr;
};

/**
 * @brief Scrollable protocol / event log.
 */
class LogPage : public ui::Page {
public:
    explicit LogPage(Context& ctx) : _ctx(ctx)
    {
    }

    const char* title() const override
    {
        return "Log";
    }

    void Create(lv_obj_t* parent) override;
    void Refresh() override;

private:
    static void on_clear_clicked(lv_event_t* e);

    Context& _ctx;
    lv_obj_t* _label = nullptr;
};

}  // namespace app
