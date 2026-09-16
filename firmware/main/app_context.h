// SPDX-License-Identifier: MIT
//
// Shared application context.
//
// Owns the Chameleon session, the USB transport and the traffic log ring, so
// that UI pages can drive the device without depending on the app entry point
// and without a circular include.

#pragma once

#include <stddef.h>

#include "chameleon_client.h"
#include "hardnested_acquire.h"
#include "mfkey32.h"
#include "m5_tab5_keyboard.h"
#include "ui.h"
#include "usb_serial_host.h"

namespace app {

/// Lines retained in the shared traffic log.
constexpr size_t kLogLines = 200;
/// Maximum characters per log line.
constexpr size_t kLogLineLength = 96;

/// One entry of the traffic log.
struct LogEntry {
    bool tx;             ///< true: host -> device
    uint16_t cmd;
    uint16_t status;
    size_t data_length;
    bool is_event;       ///< free-form event line rather than a protocol frame
    char text[kLogLineLength];
};

class Context {
public:
    static Context& Get();

    // ---- lifecycle ------------------------------------------------------

    /**
     * @brief Build the UI shell and its pages.
     * @return false if the LVGL lock could not be taken
     */
    bool StartUi();

    /// Start the USB transport and the device query worker.
    void StartTransport();

    /// Tear everything down.
    void Stop();

    // ---- accessors ------------------------------------------------------

    chameleon::Client& client()
    {
        return _client;
    }

    ui::Shell& shell()
    {
        return _shell;
    }

    bool connected() const
    {
        return _connected;
    }

    /// True once device identity has been read successfully.
    bool deviceReady() const
    {
        return _device_ready;
    }

    /// Milliseconds since boot.
    uint32_t uptimeMs() const;

    // ---- traffic log ----------------------------------------------------

    /// Append a protocol frame record. Safe to call from any task.
    void LogFrame(bool tx, uint16_t cmd, uint16_t status, size_t data_length);

    /// Append a free-form event line. Safe to call from any task.
    void LogEvent(const char* fmt, ...) __attribute__((format(printf, 2, 3)));

    /**
     * @brief Copy log entries for rendering.
     *
     * Entries are copied oldest first. Returns the number written.
     */
    size_t CopyLog(LogEntry* out, size_t max_entries, size_t skip_oldest = 0) const;

    /// Total entries ever appended (monotonic).
    size_t logSequence() const
    {
        return _log_sequence;
    }

    /**
     * @brief Drop every retained log entry.
     *
     * Resets the ring but keeps the sequence monotonic so pages that cache the
     * sequence can still tell that the contents changed.
     */
    void ClearLog();

    // ---- device state refresh -------------------------------------------

    /**
     * @brief Re-read active slot + slot info and repaint the active page.
     *
     * Used after a mutation so the UI reflects the device's real state.
     */
    void RefreshSlotState();

    /// Re-read battery / identity and repaint.
    void RefreshDeviceState();

    // ---- key recovery jobs ----------------------------------------------
    //
    // Both attacks take tens of seconds (the darkside loop can run for minutes),
    // so they run on their own task and the UI polls the result. They share one
    // task: only one key job can be in flight at a time.

    /// What the key task is currently doing.
    enum class KeyJob : uint8_t {
        Idle      = 0,
        CheckKeys = 1,  ///< try the built-in factory key list on every sector
        Darkside  = 2,  ///< collect nonces and search for the key
        Nested    = 3,  ///< recover a target sector's key from a known one
        HardNested = 4, ///< acquire the nonce file a PC solves (no crack on device)
        Mfkey32   = 5,  ///< crack two eavesdropped authentications (no card needed)
    };

    /**
     * @brief Try the built-in factory key list against every sector.
     * @return false when a key job is already running or the device is offline
     */
    bool StartKeyCheck(uint8_t block, chameleon::MfcKeyType key_type);

    /**
     * @brief Run the darkside attack against one block.
     * @return false when a key job is already running or the device is offline
     */
    bool StartDarkside(uint8_t block, chameleon::MfcKeyType key_type);

    /**
     * @brief Recover the target sector's key from a known key on another sector.
     *
     * Mirrors the official CLI's recover_a_key(): MF1_DETECT_PRNG picks the
     * attack (0 static nested, 1 nested, 2 hardnested - not ported), the
     * matching acquire command collects the nonces, and the Tab5 cracks them
     * locally. Every candidate is confirmed with a real authentication before it
     * is reported.
     *
     * @param known_block   block the known key opens
     * @param known_type    key A or B for that block
     * @param known_key     6 byte key already known for that sector
     * @param target_block  block whose key is wanted
     * @param target_type   key A or B for the target
     */
    bool StartNested(uint8_t known_block, chameleon::MfcKeyType known_type, const uint8_t known_key[6],
                     uint8_t target_block, chameleon::MfcKeyType target_type);

    /**
     * @brief Acquire the nonces for a hardnested attack and write a nonce file.
     *
     * This is the client half of ChameleonUltra's `hf mf hardnested`: the device
     * collects nonces (MF1_HARDNESTED_ACQUIRE), the Tab5 tracks the first-byte
     * parity sum the way the official client does, and the result is a nonce file
     * for the PC-side solver. The solver itself is NOT run here - upstream's
     * candidate generation keeps 474 MiB of bitflip tables plus 1 GiB of
     * per-first-byte state bitarrays resident, 47x this board's PSRAM; see
     * docs/M5-KEY-RECOVERY.md section 6.
     *
     * The file is held in PSRAM until ExportHardNestedNonces() prints it.
     *
     * @param known_block   block the known key opens
     * @param known_type    key A or B for that block
     * @param known_key     6 byte key already known for that sector
     * @param target_block  block whose key is wanted (goes into the file header)
     * @param target_type   key A or B for the target
     * @param slow          the device's slow acquisition mode (CLI flag --slow)
     * @return false when a key job is already running, the device is offline, or
     *         the nonce buffer could not be allocated
     */
    bool StartHardNested(uint8_t known_block, chameleon::MfcKeyType known_type, const uint8_t known_key[6],
                         uint8_t target_block, chameleon::MfcKeyType target_type, bool slow);

    /// True once a hardnested acquisition produced a usable nonce file.
    bool hasHardNestedFile() const
    {
        return _hn_length > hardnested::kNonceFileHeaderSize;
    }

    /// Records in that file, and how the acquisition went.
    size_t hardNestedRecords() const;
    uint16_t hardNestedUniqueFirstBytes() const
    {
        return _hn_unique;
    }

    uint16_t hardNestedParitySum() const
    {
        return _hn_parity_sum;
    }

    /// Print the nonce file to the console as `[HN]` lines for
    /// tools/nonce_file_from_console.py. Returns the number of lines, 0 when
    /// there is nothing to export.
    size_t ExportHardNestedNonces();

    /**
     * @brief Recover a key from two eavesdropped authentications (mfkey32).
     *
     * This is the one recovery that needs no card: the material is (uid, nt,
     * nr_enc, ar_enc) from two authentications with an *unknown* key, which is
     * what a passive sniffer sees. The device cannot produce that here - see
     * docs/M5-KEY-RECOVERY.md section 5 - so the usual path is a trace captured
     * on a PC, but the algorithm and this entry point are complete.
     *
     * The result is NOT card-confirmed (there may be no card present at all), so
     * it is reported separately from foundKey().
     */
    bool StartMfkey32(uint32_t uid, const chameleon::crypto::AuthTrace& a, const chameleon::crypto::AuthTrace& b);

    /// True once mfkey32 has produced a key. The key is unverified by design.
    bool mfkey32Result(uint64_t* out_key) const;

    /// Abort a running key job (it stops before the next attempt).
    void StopKeyJob();

    KeyJob keyJob() const
    {
        return _key_job;
    }

    /// Human readable progress of the running job, e.g. "darkside attempt 7".
    const char* keyJobStatus() const
    {
        return _key_status;
    }

    /// True once an attack has produced a key the card confirmed.
    bool hasFoundKey() const
    {
        return _found_key_valid;
    }

    /// Copy the found key. Returns false when there is none.
    bool foundKey(uint8_t out[6]) const;

    /// Block and key type the found key was confirmed against, so it can be
    /// used as the "known" side of a nested attack.
    uint8_t foundKeyBlock() const
    {
        return _found_key_block;
    }

    chameleon::MfcKeyType foundKeyType() const
    {
        return _found_key_type;
    }

    /// Forget the found key.
    void clearFoundKey();

private:
    Context() = default;

    static bool transport_send(const uint8_t* frame, size_t len, void* user);
    static void transport_rx(const uint8_t* data, size_t len, void* user);
    static void transport_state(bool connected, void* user);
    static void device_query_task(void* arg);
    static void key_job_task(void* arg);
    static void on_log(const chameleon::LogLine& line, void* user);
    static void on_status(const char* text, void* user);
    static void on_connection(bool connected, void* user);

    void handle_connected();

    /**
     * @brief Repaint the shell's status bar from the current session state.
     *
     * Takes the LVGL lock itself. Must be called on every connection state
     * change, otherwise the status bar keeps showing its startup text.
     */
    void updateStatusBar();

    // ---- physical keyboard (M5Stack Tab5 Keyboard, optional accessory) ----

    /**
     * @brief Probe and open the Tab5 Keyboard on the external I2C bus.
     *
     * The accessory is hot-pluggable and optional, so a failure here only logs:
     * the touch UI keeps working.
     */
    void initKeyboard();

    /// Detach the keyboard and release it.
    void deinitKeyboard();

    /// True when the accessory answered on I2C.
    bool keyboardPresent() const
    {
        return _keyboard_ready;
    }

    /// Route a raw key to the active page.
    void handleKey(uint8_t hid_key_code, uint8_t modifier, bool pressed);

    /// Callback handed to the keyboard driver.
    static void onKeyboardEvent(m5_tab5_key_event_t event, void* arg);

    chameleon::Client _client;
    chameleon::UsbSerialHost _usb;
    ui::Shell _shell;

    /// Physical keyboard accessory, created lazily in initKeyboard().
    m5::M5Tab5Keyboard* _keyboard = nullptr;
    volatile bool _keyboard_ready = false;

    void* _connect_sem = nullptr;  ///< SemaphoreHandle_t, kept void* to avoid FreeRTOS in the header

    volatile bool _connected    = false;
    volatile bool _device_ready = false;

    // ---- log ring -------------------------------------------------------
    LogEntry _log[kLogLines] = {};
    size_t _log_head         = 0;  ///< index of the next slot to write
    size_t _log_sequence     = 0;  ///< total appended
    mutable void* _log_mutex = nullptr;

    // ---- key recovery jobs ----------------------------------------------

    /// Body of the shared key job. Runs on its own task.
    void runKeyCheck(uint8_t block, chameleon::MfcKeyType key_type);
    void runDarkside(uint8_t block, chameleon::MfcKeyType key_type);
    void runNested();

    /// Acquire the nonce file for a hardnested attack (runs on the key task).
    void runHardNested();

    /// Crack two eavesdropped authentications (runs on the key task: the search
    /// takes seconds and peaks around 18 MB of PSRAM).
    void runMfkey32();

    /// Record a key the card confirmed and tell the user.
    void publishFoundKey(const uint8_t key[6], const char* source);

    volatile KeyJob _key_job       = KeyJob::Idle;
    volatile bool _key_job_abort   = false;
    uint8_t _key_block             = 0;
    chameleon::MfcKeyType _key_type = chameleon::MfcKeyType::A;

    /// Nested job parameters, captured when the job starts.
    uint8_t _nested_known_block     = 0;
    chameleon::MfcKeyType _nested_known_type = chameleon::MfcKeyType::A;
    uint8_t _nested_known_key[6]    = {};

    // ---- hardnested acquisition ------------------------------------------
    //
    // The nonce file is built in PSRAM while it is acquired (the header first,
    // then each device response appended), so exporting needs no second buffer
    // and no copy. It has to outlive the job, because the user exports it after
    // the acquisition finishes.

    /// Nonce buffer, `hardnested::kMaxExportSize` bytes of PSRAM, or nullptr.
    uint8_t* _hn_file = nullptr;
    /// Bytes of _hn_file in use (header + whole records); 0 when there is none.
    size_t _hn_length = 0;
    /// Records in _hn_file, and how the last attempt went.
    size_t _hn_records     = 0;
    uint16_t _hn_unique    = 0;
    uint16_t _hn_parity_sum = 0;
    /// Slow acquisition mode (the CLI's --slow), chosen by the user.
    bool _hn_slow = false;

    /// Print one export line to the log/console. Matches hardnested::ExportSink.
    static void export_line_sink(void* user, const char* line);

    // ---- mfkey32 ----------------------------------------------------------

    /// Parameters captured when the job starts.
    uint32_t _mfk_uid = 0;
    chameleon::crypto::AuthTrace _mfk_a = {};
    chameleon::crypto::AuthTrace _mfk_b = {};
    /// Result, written by the task and read by the UI. Unverified by design.
    uint64_t _mfk_key        = 0;
    volatile bool _mfk_valid = false;
    volatile bool _mfk_done  = false;

    /// Progress text for the Jobs page; written by the task, read by the UI.
    char _key_status[64] = {};

    uint8_t _found_key[6]     = {};
    volatile bool _found_key_valid = false;
    uint8_t _found_key_block       = 0;
    chameleon::MfcKeyType _found_key_type = chameleon::MfcKeyType::A;
};

}  // namespace app
