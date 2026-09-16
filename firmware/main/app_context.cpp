// SPDX-License-Identifier: MIT

#include "app_context.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_timer.h>

#include <bsp/m5stack_tab5.h>
#include <driver/i2c_master.h>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include "darkside.h"
#include "nested.h"
#include "mfkey32.h"
#include "m5_tab5_keyboard.h"

#include "pages.h"

static const char* TAG = "app";

namespace app {

Context& Context::Get()
{
    static Context instance;
    return instance;
}

uint32_t Context::uptimeMs() const
{
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

// ---------------------------------------------------------------------------
// Traffic log
// ---------------------------------------------------------------------------

void Context::LogFrame(bool tx, uint16_t cmd, uint16_t status, size_t data_length)
{
    if (_log_mutex == nullptr) {
        return;
    }
    if (xSemaphoreTake(static_cast<SemaphoreHandle_t>(_log_mutex), pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    LogEntry& e  = _log[_log_head];
    e.tx         = tx;
    e.cmd        = cmd;
    e.status     = status;
    e.data_length = data_length;
    e.is_event   = false;
    e.text[0]    = '\0';

    if (tx) {
        snprintf(e.text, sizeof(e.text), "-> %-30s %u B", chameleon::CommandText(cmd), (unsigned)data_length);
    } else if (status == chameleon::SUCCESS) {
        snprintf(e.text, sizeof(e.text), "<- %-30s OK   %u B", chameleon::CommandText(cmd), (unsigned)data_length);
    } else {
        snprintf(e.text, sizeof(e.text), "<- %-30s %s (0x%02X)", chameleon::CommandText(cmd),
                 chameleon::StatusText(status), status);
    }

    _log_head = (_log_head + 1) % kLogLines;
    ++_log_sequence;

    xSemaphoreGive(static_cast<SemaphoreHandle_t>(_log_mutex));
}

void Context::LogEvent(const char* fmt, ...)
{
    if (_log_mutex == nullptr) {
        return;
    }
    if (xSemaphoreTake(static_cast<SemaphoreHandle_t>(_log_mutex), pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    LogEntry& e = _log[_log_head];
    e.tx        = false;
    e.cmd       = 0;
    e.status    = 0;
    e.data_length = 0;
    e.is_event  = true;

    va_list args;
    va_start(args, fmt);
    vsnprintf(e.text, sizeof(e.text), fmt, args);
    va_end(args);

    _log_head = (_log_head + 1) % kLogLines;
    ++_log_sequence;

    xSemaphoreGive(static_cast<SemaphoreHandle_t>(_log_mutex));

    // Mirror onto the serial console: the on-screen log is only visible to a
    // human at the device, so important events are duplicated here to keep them
    // observable (and testable) from the host.
    ESP_LOGI(TAG, "[log] %s", e.text);
}

size_t Context::CopyLog(LogEntry* out, size_t max_entries, size_t skip_oldest) const
{
    if (out == nullptr || max_entries == 0 || _log_mutex == nullptr) {
        return 0;
    }
    if (xSemaphoreTake(static_cast<SemaphoreHandle_t>(_log_mutex), pdMS_TO_TICKS(50)) != pdTRUE) {
        return 0;
    }

    const size_t available = (_log_sequence < kLogLines) ? _log_sequence : kLogLines;
    size_t written         = 0;

    for (size_t i = skip_oldest; i < available && written < max_entries; ++i) {
        // Oldest entry first: the ring holds the last `available` entries.
        const size_t oldest = (_log_sequence - available) % kLogLines;
        out[written]        = _log[(oldest + i) % kLogLines];
        ++written;
    }

    xSemaphoreGive(static_cast<SemaphoreHandle_t>(_log_mutex));
    return written;
}

void Context::ClearLog()
{
    if (_log_mutex == nullptr) {
        return;
    }
    if (xSemaphoreTake(static_cast<SemaphoreHandle_t>(_log_mutex), pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    for (size_t i = 0; i < kLogLines; ++i) {
        _log[i] = LogEntry{};
    }
    _log_head     = 0;
    _log_sequence = 0;

    xSemaphoreGive(static_cast<SemaphoreHandle_t>(_log_mutex));
}

// ---------------------------------------------------------------------------
// Transport glue
// ---------------------------------------------------------------------------

bool Context::transport_send(const uint8_t* frame, size_t len, void* user)
{
    auto* self = static_cast<Context*>(user);
    return self != nullptr && self->_usb.Write(frame, len);
}

void Context::transport_rx(const uint8_t* data, size_t len, void* user)
{
    auto* self = static_cast<Context*>(user);
    if (self != nullptr) {
        self->_client.OnTransportData(data, len);
    }
}

void Context::transport_state(bool connected, void* user)
{
    // Runs in the USB client task: no blocking work here. The queries are
    // blocking request/response round trips and are only pumped by this very
    // task, so they must happen on the dedicated worker.
    auto* self = static_cast<Context*>(user);
    if (self == nullptr) {
        return;
    }
    self->_connected = connected;
    xSemaphoreGive(static_cast<SemaphoreHandle_t>(self->_connect_sem));
}

void Context::on_log(const chameleon::LogLine& line, void* user)
{
    auto* self = static_cast<Context*>(user);
    if (self != nullptr) {
        self->LogFrame(line.tx, line.cmd, line.status, line.data_length);
    }
}

void Context::on_status(const char* text, void* user)
{
    (void)user;
    ESP_LOGI(TAG, "status: %s", text);
}

void Context::on_connection(bool connected, void* user)
{
    (void)user;
    Context::Get().LogEvent(connected ? "device attached" : "device detached");
}

void Context::updateStatusBar()
{
    if (!_connected) {
        _shell.SetStatus(false, "waiting for device", "attach Chameleon to USB-A");
        return;
    }

    const auto& info = _client.deviceInfo();
    char line1[64];
    char line2[64];

    if (info.valid) {
        snprintf(line1, sizeof(line1), "%s  fw %u.%u", info.device_model == 0 ? "Ultra" : "Lite",
                 info.app_version_major, info.app_version_minor);
    } else {
        snprintf(line1, sizeof(line1), "connected (no response)");
    }

    if (_client.batteryInfo().valid && _client.batteryInfo().voltage_mv > 0) {
        snprintf(line2, sizeof(line2), "battery %u%%   %u mV   slot %u", _client.batteryInfo().percentage,
                 _client.batteryInfo().voltage_mv, _client.activeSlot() + 1);
    } else {
        snprintf(line2, sizeof(line2), "slot %u", _client.activeSlot() + 1);
    }

    _shell.SetStatus(true, line1, line2);
}

void Context::handle_connected()
{
    _client.OnTransportState(true);

    const auto& info = _client.deviceInfo();
    if (info.valid) {
        LogEvent("device: %s app %u.%u", info.device_model == 0 ? "Ultra" : "Lite", info.app_version_major,
                 info.app_version_minor);
        _device_ready = true;
    } else {
        LogEvent("device did not answer GET_APP_VERSION");
    }

    if (_client.batteryInfo().valid) {
        LogEvent("battery %u%% (%u mV)%s", _client.batteryInfo().percentage, _client.batteryInfo().voltage_mv,
                 _client.batteryInfo().charging ? " charging" : "");
    }

    LogEvent("active slot %u, %d slots read", _client.activeSlot() + 1, chameleon::kSlotCount);
    updateStatusBar();
    _shell.RefreshActive();
}

void Context::device_query_task(void* arg)
{
    auto* self = static_cast<Context*>(arg);

    // Periodic refresh: the device keeps battery values at 0 until its own
    // measurement timer has fired (firmware ble_main.c), so a single read right
    // after attach is not enough. Re-read while connected and repaint.
    constexpr uint32_t kRefreshMs = 5000;

    for (;;) {
        if (xSemaphoreTake(static_cast<SemaphoreHandle_t>(self->_connect_sem), pdMS_TO_TICKS(kRefreshMs)) == pdTRUE) {
            if (!self->_connected) {
                self->_device_ready = false;
                self->_client.OnTransportState(false);
                self->LogEvent("device detached");
                self->updateStatusBar();
                self->_shell.RefreshActive();
                continue;
            }
            self->handle_connected();
            continue;
        }

        // Timed out: the device is still attached, poll its slow-changing state.
        if (self->_connected) {
            self->_client.FetchBattery();
            self->updateStatusBar();
            self->_shell.RefreshActive();
        }
    }
}

// ---------------------------------------------------------------------------
// Physical keyboard (optional M5Stack Tab5 Keyboard accessory)
//
// Wired to the external I2C bus: SDA=GPIO0, SCL=GPIO1, INT=GPIO50, address 0x6D.
// The accessory reports key events over I2C; the tab keys are mapped to page
// switching here. Absence of the accessory is not an error - touch keeps working.
// ---------------------------------------------------------------------------

namespace {

/// Tab shortcut keys (HID usage ids for "1".."6"), matching the page order
/// registered in StartUi(). The driver reports the same code whether or not
/// Shift is held, so the character above the digit key is not distinguished.
constexpr uint8_t kTabKeys[] = {0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23};  // 1 2 3 4 5 6
constexpr int kTabKeyCount = 6;

}  // namespace

void Context::onKeyboardEvent(m5_tab5_key_event_t event, void* arg)
{
    auto* self = static_cast<Context*>(arg);
    if (self == nullptr) {
        return;
    }
    if (event.type == M5_TAB5_KB_MODE_NORMAL) {
        // Normal mode reports the key matrix position (row/col), not a HID code.
        return;
    }
    self->handleKey(event.hid_key_code, event.hid_modifier, event.pressed);
}

void Context::handleKey(uint8_t hid_key_code, uint8_t modifier, bool pressed)
{
    (void)pressed;
    (void)modifier;

    if (!_keyboard_ready) {
        return;
    }

    // In HID mode the driver fills hid_key_code/hid_modifier and leaves
    // `pressed` at its default false, so key-down and key-up arrive with the
    // same shape: a non-zero key code is a press, 0x00 is the release that
    // follows it. Filtering on `pressed` therefore drops every keystroke.
    if (hid_key_code == 0x00) {
        return;
    }

    // Give the active page first refusal. A focused text field must win over the
    // tab hotkeys: the digits 1-4 are both shortcuts and legitimate input for a
    // nickname or a hex key, so routing the shortcut first made those characters
    // impossible to type.
    if (_shell.ForwardKey(hid_key_code, modifier)) {
        return;
    }

    for (int i = 0; i < kTabKeyCount; ++i) {
        if (hid_key_code == kTabKeys[i]) {
            _shell.ShowPage(i);
            return;
        }
    }
}

void Context::initKeyboard()
{
    if (_keyboard != nullptr) {
        return;
    }

    auto* kb = new m5::M5Tab5Keyboard();

    const m5_tab5_kb_err_t err = kb->begin(I2C_NUM_1, M5_TAB5_KB_DEFAULT_ADDR, M5_TAB5_KB_DEFAULT_SDA,
                                          M5_TAB5_KB_DEFAULT_SCL, M5_TAB5_KB_I2C_FREQ_100K,
                                          M5_TAB5_KB_DEFAULT_INT, M5_TAB5_KB_INT_MODE_HARDWARE);
    if (err != M5_TAB5_KB_OK) {
        ESP_LOGW(TAG, "Tab5 keyboard not present (err %d); touch only", (int)err);
        delete kb;
        return;
    }

    uint8_t version = 0;
    if (kb->getVersion(&version) == M5_TAB5_KB_OK) {
        ESP_LOGI(TAG, "Tab5 keyboard ready, fw 0x%02X", version);
        LogEvent("keyboard ready (fw 0x%02X)", version);
    } else {
        LogEvent("keyboard ready");
    }

    // Enable HID mode and install the callback in one call. Doing setMode()
    // followed by setKeyCallback() does not work: setKeyboardMode() resets the
    // internal callback to the driver's default printer, silently discarding
    // whatever was registered before it.
    if (kb->enableHIDMode(onKeyboardEvent, this) != M5_TAB5_KB_OK) {
        ESP_LOGW(TAG, "cannot switch keyboard to HID mode");
        kb->end();
        delete kb;
        return;
    }

    _keyboard       = kb;
    _keyboard_ready = true;
}

void Context::deinitKeyboard()
{
    if (_keyboard == nullptr) {
        return;
    }
    auto* kb = _keyboard;
    kb->end();
    delete kb;
    _keyboard       = nullptr;
    _keyboard_ready = false;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

bool Context::StartUi()
{
    _log_mutex = xSemaphoreCreateMutex();
    if (_log_mutex == nullptr) {
        ESP_LOGE(TAG, "cannot create log mutex");
        return false;
    }

    ui::InitFonts();

    if (!_shell.Create()) {
        ESP_LOGE(TAG, "cannot create UI shell");
        return false;
    }

    _shell.AddPage(0, new SlotPage(*this));
    _shell.AddPage(1, new DevicePage(*this));
    _shell.AddPage(2, new CardPage(*this));
    _shell.AddPage(3, new KeysPage(*this));
    _shell.AddPage(4, new EmulatePage(*this));
    _shell.AddPage(5, new Mf0Page(*this));
    _shell.AddPage(6, new LogPage(*this));
    _shell.AddPage(7, new ToolsPage(*this));
    _shell.Finalize();

    // The keyboard accessory is optional, so probe it after the UI exists: any
    // diagnostic then lands in the on-screen log.
    initKeyboard();

    if (bsp_display_lock(0)) {
        _shell.SetStatus(false, "waiting for device", "attach Chameleon to USB-A");
        bsp_display_unlock();
    }
    LogEvent("UI ready");
    return true;
}

void Context::StartTransport()
{
    chameleon::ClientCallbacks callbacks;
    callbacks.on_connection = on_connection;
    callbacks.on_log        = on_log;
    callbacks.on_status     = on_status;

    _client.SetTransport(transport_send, this);
    _client.SetCallbacks(callbacks);

    _connect_sem = xSemaphoreCreateBinary();
    if (_connect_sem == nullptr) {
        ESP_LOGE(TAG, "cannot create connect semaphore");
        return;
    }
    if (xTaskCreate(device_query_task, "cham_query", 8192, this, 4, nullptr) != pdTRUE) {
        ESP_LOGE(TAG, "cannot create device query task");
        return;
    }

    const esp_err_t err = _usb.Start(transport_rx, transport_state, this);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "USB CDC host start failed: %s", esp_err_to_name(err));
        LogEvent("USB host start FAILED");
        return;
    }
    LogEvent("USB host started");
}

void Context::Stop()
{
    StopKeyJob();
    deinitKeyboard();
    _usb.Stop();
}

// ---------------------------------------------------------------------------
// Key recovery jobs
//
// Both attacks are slow - the key check is one RF auth per (key, sector) pair
// and the darkside loop retries until it collects enough nonces - so they run on
// a task of their own and the UI polls keyJob()/keyJobStatus().
//
// Neither job ever reports a key the card has not confirmed: every candidate is
// put through MF1_AUTH_ONE_KEY_BLOCK first. A "recovered" key that fails auth is
// dropped, which is what keeps a wrong candidate from being presented as an
// answer.
// ---------------------------------------------------------------------------

namespace {

/// Factory/transport keys that are worth trying before any attack. This is a
/// convenience list for the UI, not a protocol constant: nothing breaks if it is
/// wrong or incomplete, a missing key just means "not found". The device
/// confirms every match, so an entry that does not fit the card simply fails.
constexpr uint8_t kFactoryKeys[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  // NXP transport key
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
    {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
    {0x48, 0x45, 0x58, 0x41, 0x43, 0x54},  // "HEXACT"
};
constexpr size_t kFactoryKeyCount = sizeof(kFactoryKeys) / sizeof(kFactoryKeys[0]);

/// Mask with every one of the 40 sectors enabled (MSB first, 80 bits).
constexpr uint8_t kAllSectorsMask[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/// Darkside attempts before giving up. The CLI allows 255; each attempt costs
/// up to sync_max device side retries, so this bound keeps a stuck attack from
/// running for an hour.
constexpr int kDarksideMaxAttempts = 60;
constexpr uint8_t kDarksideSyncMax  = 8;

/// Consecutive transient refusals (tag changed / no NACK) tolerated before the
/// attack gives up. A tag whose PRNG cannot be pinned down reports its own
/// status and stops immediately; this bound is for RF trouble.
constexpr int kDarksideMaxRefusals = 5;

/// Candidates verified per round before going back for more nonces. A parity
/// zero round can return thousands; trying them all over USB would dominate.
constexpr size_t kMaxCandidatesPerRound = 32;

void format_key(const uint8_t key[6], char* out, size_t out_size)
{
    snprintf(out, out_size, "%02X%02X%02X%02X%02X%02X", key[0], key[1], key[2], key[3], key[4], key[5]);
}

}  // namespace

bool Context::StartNested(uint8_t known_block, chameleon::MfcKeyType known_type, const uint8_t known_key[6],
                          uint8_t target_block, chameleon::MfcKeyType target_type)
{
    if (!_connected || _key_job != KeyJob::Idle || known_key == nullptr) {
        return false;
    }
    _nested_known_block = known_block;
    _nested_known_type  = known_type;
    memcpy(_nested_known_key, known_key, sizeof(_nested_known_key));
    _key_block     = target_block;
    _key_type      = target_type;
    _key_job_abort = false;
    _key_job       = KeyJob::Nested;
    if (xTaskCreate(key_job_task, "key_job", 8192, this, 3, nullptr) != pdTRUE) {
        _key_job = KeyJob::Idle;
        LogEvent("cannot start key job task");
        return false;
    }
    return true;
}

bool Context::StartKeyCheck(uint8_t block, chameleon::MfcKeyType key_type)
{
    if (!_connected || _key_job != KeyJob::Idle) {
        return false;
    }
    _key_block = block;
    _key_type  = key_type;
    _key_job_abort = false;
    _key_job   = KeyJob::CheckKeys;
    if (xTaskCreate(key_job_task, "key_job", 8192, this, 3, nullptr) != pdTRUE) {
        _key_job = KeyJob::Idle;
        LogEvent("cannot start key job task");
        return false;
    }
    return true;
}

bool Context::StartDarkside(uint8_t block, chameleon::MfcKeyType key_type)
{
    if (!_connected || _key_job != KeyJob::Idle) {
        return false;
    }
    _key_block = block;
    _key_type  = key_type;
    _key_job_abort = false;
    _key_job   = KeyJob::Darkside;
    if (xTaskCreate(key_job_task, "key_job", 8192, this, 3, nullptr) != pdTRUE) {
        _key_job = KeyJob::Idle;
        LogEvent("cannot start key job task");
        return false;
    }
    return true;
}

bool Context::StartHardNested(uint8_t known_block, chameleon::MfcKeyType known_type, const uint8_t known_key[6],
                              uint8_t target_block, chameleon::MfcKeyType target_type, bool slow)
{
    if (!_connected || _key_job != KeyJob::Idle || known_key == nullptr) {
        return false;
    }

    // One 64 KiB PSRAM buffer holds the whole nonce file (a 6 byte header and
    // then the device's 9 byte records back to back), so nothing has to be
    // copied when it is exported. Allocated once and kept, because the export
    // happens after the job finishes.
    if (_hn_file == nullptr) {
        _hn_file = static_cast<uint8_t*>(heap_caps_malloc(hardnested::kMaxExportSize, MALLOC_CAP_SPIRAM));
        if (_hn_file == nullptr) {
            LogEvent("hardnested: cannot allocate the %u byte nonce buffer in PSRAM",
                     (unsigned)hardnested::kMaxExportSize);
            return false;
        }
    }

    _nested_known_block = known_block;
    _nested_known_type  = known_type;
    memcpy(_nested_known_key, known_key, sizeof(_nested_known_key));
    _key_block     = target_block;
    _key_type      = target_type;
    _hn_slow       = slow;
    _hn_length     = 0;
    _hn_records    = 0;
    _hn_unique     = 0;
    _hn_parity_sum = 0;
    _key_job_abort = false;
    _key_job       = KeyJob::HardNested;
    if (xTaskCreate(key_job_task, "key_job", 8192, this, 3, nullptr) != pdTRUE) {
        _key_job = KeyJob::Idle;
        LogEvent("cannot start key job task");
        return false;
    }
    return true;
}

void Context::StopKeyJob()
{
    if (_key_job != KeyJob::Idle) {
        _key_job_abort = true;
    }
}

bool Context::foundKey(uint8_t out[6]) const
{
    if (!_found_key_valid || out == nullptr) {
        return false;
    }
    memcpy(out, _found_key, 6);
    return true;
}

void Context::clearFoundKey()
{
    _found_key_valid = false;
    memset(_found_key, 0, sizeof(_found_key));
}

void Context::publishFoundKey(const uint8_t key[6], const char* source)
{
    memcpy(_found_key, key, 6);
    _found_key_valid = true;
    // Remember where it was confirmed: that is the "known" side a later nested
    // attack needs.
    _found_key_block = _key_block;
    _found_key_type  = _key_type;

    char hex[16];
    format_key(key, hex, sizeof(hex));
    LogEvent("KEY FOUND %s: %s", hex, source != nullptr ? source : "");
    snprintf(_key_status, sizeof(_key_status), "found %s", hex);

    _shell.RefreshActive();
}

void Context::key_job_task(void* arg)
{
    auto* self = static_cast<Context*>(arg);
    if (self == nullptr) {
        vTaskDelete(nullptr);
        return;
    }

    const KeyJob job     = self->_key_job;
    const uint8_t block  = self->_key_block;
    const auto key_type  = self->_key_type;

    if (job == KeyJob::CheckKeys) {
        self->runKeyCheck(block, key_type);
    } else if (job == KeyJob::Darkside) {
        self->runDarkside(block, key_type);
    } else if (job == KeyJob::Nested) {
        self->runNested();
    } else if (job == KeyJob::HardNested) {
        self->runHardNested();
    } else if (job == KeyJob::Mfkey32) {
        self->runMfkey32();
    }

    self->_key_job = KeyJob::Idle;
    self->_shell.RefreshActive();
    vTaskDelete(nullptr);
}

void Context::runKeyCheck(uint8_t block, chameleon::MfcKeyType key_type)
{
    snprintf(_key_status, sizeof(_key_status), "checking %u factory keys", (unsigned)kFactoryKeyCount);
    LogEvent("key check: block %u, %u factory keys", block, (unsigned)kFactoryKeyCount);
    _shell.RefreshActive();

    uint8_t found[10] = {};
    uint8_t sector_keys[chameleon::Client::kMfcSectorCount][6] = {};
    size_t length = 0;

    const uint16_t status = _client.CheckKeysOfSectors(kAllSectorsMask, &kFactoryKeys[0][0], kFactoryKeyCount, found,
                                                       sector_keys, &length);
    if (status != chameleon::HF_TAG_OK && status != chameleon::HF_TAG_NO) {
        snprintf(_key_status, sizeof(_key_status), "check failed: %s", chameleon::StatusText(status));
        LogEvent("key check failed: %s (0x%02X)", chameleon::StatusText(status), status);
        return;
    }
    if (length < 10) {
        snprintf(_key_status, sizeof(_key_status), "no key found");
        LogEvent("key check: no factory key matched");
        return;
    }

    // The device reports one bit per checked sector in a 10 byte bitmap, MSB
    // first, and the matching key for each sector right after it.
    int matches = 0;
    uint8_t first[6] = {};
    for (size_t byte = 0; byte < 10; ++byte) {
        for (int bit = 7; bit >= 0; --bit) {
            const size_t sector = byte * 8 + (7 - bit);
            if (sector >= chameleon::Client::kMfcSectorCount) {
                break;
            }
            if (((found[byte] >> bit) & 1u) == 0) {
                continue;
            }
            ++matches;
            if (matches == 1) {
                memcpy(first, sector_keys[sector], 6);
            }
            char hex[16];
            format_key(sector_keys[sector], hex, sizeof(hex));
            LogEvent("sector %u key %s", (unsigned)sector, hex);
        }
    }

    if (matches == 0) {
        snprintf(_key_status, sizeof(_key_status), "no key found");
        LogEvent("key check: no factory key matched");
        return;
    }

    char hex[16];
    format_key(first, hex, sizeof(hex));
    snprintf(_key_status, sizeof(_key_status), "%d sectors unlocked, first key %s", matches, hex);

    // Keys are sector keys, so a key that unlocked some sector is not
    // necessarily the one for the block the user picked. Confirm before
    // reporting it as recovered.
    if (_client.AuthMifareKey(block, key_type, first) == chameleon::HF_TAG_OK) {
        publishFoundKey(first, "factory key list");
    } else {
        LogEvent("key check: keys unlock other sectors but not block %u", block);
    }
}

void Context::runDarkside(uint8_t block, chameleon::MfcKeyType key_type)
{
    LogEvent("darkside: block %u, up to %d attempts", block, kDarksideMaxAttempts);
    snprintf(_key_status, sizeof(_key_status), "darkside starting");
    _shell.RefreshActive();

    chameleon::crypto::DarksideSearch search;

    // Candidate buffer reused across rounds. A parity-zero round can produce
    // hundreds of thousands of keys, so only a slice is carried into the auth
    // check; the device is the authority anyway.
    uint64_t candidates[kMaxCandidatesPerRound];

    bool first_recover = true;
    int consecutive_refusals = 0;
    for (int attempt = 0; attempt < kDarksideMaxAttempts; ++attempt) {
        if (_key_job_abort || !_connected) {
            LogEvent("darkside aborted");
            snprintf(_key_status, sizeof(_key_status), "aborted");
            return;
        }

        snprintf(_key_status, sizeof(_key_status), "darkside attempt %d/%d", attempt + 1, kDarksideMaxAttempts);
        _shell.RefreshActive();

        chameleon::Client::DarksideResult result;
        const uint16_t status = _client.DarksideAcquire(block, key_type, first_recover, kDarksideSyncMax, &result);
        first_recover = false;

        if (status != chameleon::HF_TAG_OK) {
            // This is the frame status, not the attack status: the device could
            // not even run the attempt (no card, not a Classic card, RF error).
            // The official CLI aborts here as well, because its request
            // decorator expects HF_TAG_OK.
            LogEvent("darkside acquire failed: %s (0x%02X)", chameleon::StatusText(status), status);
            snprintf(_key_status, sizeof(_key_status), "acquire failed: %s", chameleon::StatusText(status));
            return;
        }
        if (!result.valid) {
            switch (result.status) {
                case chameleon::Client::DarksideStatus::LuckyAuthOk:
                    // The device's own first-recover step already opened the
                    // sector with a default key; the factory key check will name
                    // it, so there is nothing left to attack.
                    LogEvent("darkside: device already authenticated with a default key");
                    snprintf(_key_status, sizeof(_key_status), "default key worked - use check factory keys");
                    return;
                case chameleon::Client::DarksideStatus::CantFixNt:
                    // The tag's PRNG cannot be pinned down; retrying cannot help.
                    // This is the honest "this card is not vulnerable" answer.
                    LogEvent("darkside: tag PRNG is not predictable, attack cannot proceed");
                    snprintf(_key_status, sizeof(_key_status), "tag PRNG not predictable");
                    return;
                default:
                    // TagChanged / NoNakSent: transient RF trouble, worth another
                    // go - but not forever, so a card that simply is not
                    // answering does not burn the whole attempt budget.
                    ++consecutive_refusals;
                    LogEvent("darkside: %s (%d)", chameleon::Client::DarksideStatusText(result.status),
                             consecutive_refusals);
                    if (consecutive_refusals >= kDarksideMaxRefusals) {
                        snprintf(_key_status, sizeof(_key_status), "gave up: %s",
                                 chameleon::Client::DarksideStatusText(result.status));
                        LogEvent("darkside: giving up after %d refusals in a row", consecutive_refusals);
                        return;
                    }
                    continue;
            }
        }
        consecutive_refusals = 0;

        chameleon::crypto::DarksideNonce nonce;
        nonce.uid = result.uid;
        nonce.nt  = result.nt;
        nonce.nr  = result.nr;
        nonce.ar  = result.ar;
        nonce.ks  = result.ks;
        nonce.par = result.par;

        size_t total = 0;
        const size_t count = search.Feed(nonce, candidates, kMaxCandidatesPerRound, &total);
        if (count == 0) {
            continue;
        }

        char hex[16];
        for (size_t i = 0; i < count; ++i) {
            uint8_t key[6];
            // Recovered keys are 48 bit; the wire format is big endian.
            key[0] = (uint8_t)(candidates[i] >> 40);
            key[1] = (uint8_t)(candidates[i] >> 32);
            key[2] = (uint8_t)(candidates[i] >> 24);
            key[3] = (uint8_t)(candidates[i] >> 16);
            key[4] = (uint8_t)(candidates[i] >> 8);
            key[5] = (uint8_t)candidates[i];

            format_key(key, hex, sizeof(hex));
            if (_client.AuthMifareKey(block, key_type, key) == chameleon::HF_TAG_OK) {
                char source[64];
                snprintf(source, sizeof(source), "darkside, attempt %d", attempt + 1);
                publishFoundKey(key, source);
                return;
            }
        }
        LogEvent("darkside attempt %d: %u candidate(s), none confirmed", attempt + 1, (unsigned)total);
    }

    snprintf(_key_status, sizeof(_key_status), "no key after %d attempts", kDarksideMaxAttempts);
    LogEvent("darkside: no key after %d attempts", kDarksideMaxAttempts);
}

void Context::runNested()
{
    const uint8_t known_block = _nested_known_block;
    const auto known_type     = _nested_known_type;
    const uint8_t* known_key  = _nested_known_key;
    const uint8_t target_block = _key_block;
    const auto target_type     = _key_type;

    /// Nonces one acquisition can hand back. The CLI has no explicit cap; 32
    /// keeps the job's stack use small and is far more than an attack needs.
    constexpr size_t kMaxNonces = 32;
    /// NestedRecover() returns at most 50 candidates (upstream TRY_KEYS).
    constexpr size_t kMaxKeys = 64;

    char hex[16];
    format_key(known_key, hex, sizeof(hex));
    snprintf(_key_status, sizeof(_key_status), "nested: probing PRNG");
    _shell.RefreshActive();

    // Step 1: which attack does this card allow? (chameleon_cli_unit.py
    // recover_a_key -> mf1_detect_prng)
    uint8_t nt_level = 0;
    const uint16_t prng_status = _client.Mf1DetectPrng(&nt_level);
    if (prng_status != chameleon::HF_TAG_OK) {
        LogEvent("nested: MF1_DETECT_PRNG failed: %s (0x%02X)", chameleon::StatusText(prng_status), prng_status);
        snprintf(_key_status, sizeof(_key_status), "detect prng failed");
        return;
    }
    if (nt_level == 2) {
        // 2 = hardnested. The plain nested attack cannot work on a card with a
        // hardened PRNG, and the ciphertext-only attack that does needs a PC for
        // its candidate generation (see docs/M5-KEY-RECOVERY.md section 6), so
        // point at the acquisition button instead of pretending to attack.
        LogEvent("nested: card needs hardnested; use 'acquire hardnested nonces' and crack the file on a PC");
        snprintf(_key_status, sizeof(_key_status), "card needs hardnested - use acquire");
        return;
    }
    LogEvent("nested: nt level %u (%s), known key %s on block %u", (unsigned)nt_level,
             nt_level == 0 ? "static nested" : "nested", hex, (unsigned)known_block);

    uint64_t candidates[kMaxKeys];
    size_t candidate_count = 0;
    const char* source     = nt_level == 0 ? "static nested" : "nested";

    if (nt_level == 0) {
        // ---- static nested ----
        snprintf(_key_status, sizeof(_key_status), "static nested: acquiring");
        _shell.RefreshActive();

        chameleon::Client::StaticNestedNonce nonces[kMaxNonces];
        size_t count = 0;
        uint32_t uid = 0;
        const uint16_t status = _client.Mf1StaticNestedAcquire(known_block, known_type, known_key, target_block,
                                                               target_type, &uid, nonces, kMaxNonces, &count);
        if (status != chameleon::HF_TAG_OK || count == 0) {
            LogEvent("static nested acquire failed: %s (0x%02X), %u nonces", chameleon::StatusText(status), status,
                     (unsigned)count);
            snprintf(_key_status, sizeof(_key_status), "acquire failed: %s", chameleon::StatusText(status));
            return;
        }

        chameleon::crypto::StaticNestedPair pairs[kMaxNonces];
        for (size_t i = 0; i < count; ++i) {
            pairs[i].nt     = nonces[i].nt;
            pairs[i].nt_enc = nonces[i].nt_enc;
        }

        snprintf(_key_status, sizeof(_key_status), "static nested: cracking %u nonces", (unsigned)count);
        _shell.RefreshActive();
        chameleon::crypto::StaticNestedRecover(uid, static_cast<uint8_t>(target_type), pairs, count, candidates,
                                               kMaxKeys, &candidate_count);
    } else {
        // ---- plain nested ----
        snprintf(_key_status, sizeof(_key_status), "nested: measuring nonce distance");
        _shell.RefreshActive();

        uint32_t uid = 0;
        uint32_t dist = 0;
        const uint16_t dist_status = _client.Mf1DetectNtDist(known_block, known_type, known_key, &uid, &dist);
        if (dist_status != chameleon::HF_TAG_OK) {
            LogEvent("nested: MF1_DETECT_NT_DIST failed: %s (0x%02X)", chameleon::StatusText(dist_status),
                     dist_status);
            snprintf(_key_status, sizeof(_key_status), "distance detect failed");
            return;
        }

        snprintf(_key_status, sizeof(_key_status), "nested: acquiring");
        _shell.RefreshActive();

        chameleon::Client::NestedNonce nonces[kMaxNonces];
        size_t count = 0;
        const uint16_t status = _client.Mf1NestedAcquire(known_block, known_type, known_key, target_block,
                                                         target_type, nonces, kMaxNonces, &count);
        if (status != chameleon::HF_TAG_OK || count == 0) {
            LogEvent("nested acquire failed: %s (0x%02X), %u nonces", chameleon::StatusText(status), status,
                     (unsigned)count);
            snprintf(_key_status, sizeof(_key_status), "acquire failed: %s", chameleon::StatusText(status));
            return;
        }

        chameleon::crypto::NestedAcquireEntry entries[kMaxNonces];
        for (size_t i = 0; i < count; ++i) {
            entries[i].nt     = nonces[i].nt;
            entries[i].nt_enc = nonces[i].nt_enc;
            entries[i].par    = nonces[i].par;
        }

        LogEvent("nested: dist %u, cracking %u nonces", (unsigned)dist, (unsigned)count);
        snprintf(_key_status, sizeof(_key_status), "nested: cracking %u nonces", (unsigned)count);
        _shell.RefreshActive();
        chameleon::crypto::NestedRecoverFromAcquire(uid, dist, entries, count, candidates, kMaxKeys,
                                                    &candidate_count);
    }

    if (candidate_count == 0) {
        LogEvent("nested: no candidates found");
        snprintf(_key_status, sizeof(_key_status), "no candidates");
        return;
    }

    // Step 3: only the card can say which candidate is real.
    snprintf(_key_status, sizeof(_key_status), "verifying %u candidates", (unsigned)candidate_count);
    _shell.RefreshActive();

    for (size_t i = 0; i < candidate_count; ++i) {
        if (_key_job_abort || !_connected) {
            LogEvent("nested aborted while verifying");
            snprintf(_key_status, sizeof(_key_status), "aborted");
            return;
        }
        uint8_t key[6];
        key[0] = static_cast<uint8_t>(candidates[i] >> 40);
        key[1] = static_cast<uint8_t>(candidates[i] >> 32);
        key[2] = static_cast<uint8_t>(candidates[i] >> 24);
        key[3] = static_cast<uint8_t>(candidates[i] >> 16);
        key[4] = static_cast<uint8_t>(candidates[i] >> 8);
        key[5] = static_cast<uint8_t>(candidates[i]);

        if (_client.AuthMifareKey(target_block, target_type, key) == chameleon::HF_TAG_OK) {
            publishFoundKey(key, source);
            return;
        }
    }

    LogEvent("nested: tried %u candidates, the card confirmed none", (unsigned)candidate_count);
    snprintf(_key_status, sizeof(_key_status), "no key confirmed");
}

// ---------------------------------------------------------------------------
// hardnested nonce acquisition
// ---------------------------------------------------------------------------
//
// Ported from the official client, software/script/chameleon_cli_unit.py
// HFMFHardNested.recover_key(), minus the part that shells out to the PC solver:
//
//   * scan the card and put the last four UID bytes, the target block and the
//     target key type into the first six bytes of the nonce file
//   * call MF1_HARDNESTED_ACQUIRE over and over (up to 200 runs per attempt,
//     exactly the CLI's default), appending every response to the file and
//     tracking which of the 256 possible first bytes have been seen
//   * stop as soon as all 256 are covered; keep the attempt only if the parity
//     sum is one of the 19 legal Sum(a8) values, otherwise start over (up to 3
//     attempts, also the CLI's default)
//   * leave the file in PSRAM for ExportHardNestedNonces()
//
// The parity sum is not a property of the nonces but of this particular
// collection: an invalid sum means the attack would fail on data that looks
// fine, which is why upstream throws the whole collection away and retries.

void Context::runHardNested()
{
    const uint8_t known_block  = _nested_known_block;
    const auto known_type      = _nested_known_type;
    const uint8_t* known_key   = _nested_known_key;
    const uint8_t target_block = _key_block;
    const auto target_type     = _key_type;

    /// The CLI's --max-runs / --max-attempts defaults, read from its argparse
    /// setup, not guessed.
    constexpr int kMaxRuns     = 200;
    constexpr int kMaxAttempts = 3;

    /// One device response is at most 110 nonces = 55 records = 495 bytes
    /// (app_cmd.c caps the payload at 500 bytes, 9 per pair).
    constexpr size_t kRunCapacity = 512;

    if (_hn_file == nullptr) {
        LogEvent("hardnested: no nonce buffer");
        snprintf(_key_status, sizeof(_key_status), "no buffer");
        return;
    }

    char hex[16];
    format_key(known_key, hex, sizeof(hex));
    LogEvent("hardnested: known key %s on block %u, target block %u key %c, %s acquisition", hex,
             (unsigned)known_block, (unsigned)target_block, target_type == chameleon::MfcKeyType::B ? 'B' : 'A',
             _hn_slow ? "slow" : "fast");

    uint8_t run_buffer[kRunCapacity];
    size_t best_length  = 0;
    size_t best_records = 0;

    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        if (_key_job_abort) {
            LogEvent("hardnested aborted");
            snprintf(_key_status, sizeof(_key_status), "aborted");
            return;
        }

        snprintf(_key_status, sizeof(_key_status), "hardnested: scanning (attempt %d/%d)", attempt, kMaxAttempts);
        _shell.RefreshActive();

        // The file header needs the UID, so every attempt starts with a scan.
        chameleon::HfTag tag{};
        size_t tag_count = 0;
        const uint16_t scan_status = _client.ScanHf(&tag, 1, &tag_count);
        if (scan_status != chameleon::HF_TAG_OK || tag_count == 0) {
            LogEvent("hardnested: scan failed: %s (0x%02X)", chameleon::StatusText(scan_status), scan_status);
            snprintf(_key_status, sizeof(_key_status), "scan failed");
            return;
        }
        uint8_t uid4[4];
        if (!hardnested::UidForNonceFile(tag.uid, tag.uid_length, uid4)) {
            LogEvent("hardnested: cannot use a %u byte UID for the nonce file header",
                     (unsigned)tag.uid_length);
            snprintf(_key_status, sizeof(_key_status), "unsupported UID length");
            return;
        }

        _hn_file[0] = uid4[0];
        _hn_file[1] = uid4[1];
        _hn_file[2] = uid4[2];
        _hn_file[3] = uid4[3];
        _hn_file[4] = target_block;
        _hn_file[5] = static_cast<uint8_t>(target_type) & 0x01;
        size_t length  = hardnested::kNonceFileHeaderSize;
        size_t records = 0;

        hardnested::FirstByteTracker tracker;
        tracker.Reset();

        bool covered = false;
        int run = 0;
        for (; run < kMaxRuns; ++run) {
            if (_key_job_abort) {
                LogEvent("hardnested aborted after %d runs", run);
                snprintf(_key_status, sizeof(_key_status), "aborted");
                return;
            }

            size_t got = 0;
            const uint16_t status = _client.Mf1HardNestedAcquire(_hn_slow, known_block, known_type, known_key,
                                                                 target_block, target_type, run_buffer,
                                                                 sizeof(run_buffer), &got);
            if (status != chameleon::HF_TAG_OK) {
                // The CLI treats a failed run as "stop this attempt" rather than
                // as a fatal error: a card that slips off the antenna mid-run is
                // the normal case, not an exception.
                LogEvent("hardnested: run %d failed: %s (0x%02X)", run + 1, chameleon::StatusText(status), status);
                break;
            }

            const size_t whole = got / hardnested::kNonceFileRecordSize;
            if (whole == 0) {
                continue;
            }
            const size_t bytes = whole * hardnested::kNonceFileRecordSize;

            if (records + whole > hardnested::kMaxRecords) {
                LogEvent("hardnested: nonce buffer full at %u records without covering all 256 first bytes",
                         (unsigned)records);
                snprintf(_key_status, sizeof(_key_status), "buffer full");
                break;
            }

            memcpy(_hn_file + length, run_buffer, bytes);
            length += bytes;
            records += whole;
            tracker.AddRun(run_buffer, bytes);

            snprintf(_key_status, sizeof(_key_status), "hardnested: run %d, %u/%u first bytes, sum %u",
                     run + 1, (unsigned)tracker.uniqueCount(), (unsigned)hardnested::FirstByteTracker::kFirstByteCount,
                     (unsigned)tracker.paritySum());

            if (tracker.complete()) {
                covered = true;
                break;
            }
            // Only refresh the UI every few runs: each refresh takes the LVGL
            // lock, and the acquisition is a long sequence of short commands.
            if ((run % 5) == 0) {
                _shell.RefreshActive();
            }
        }

        if (!covered) {
            LogEvent("hardnested: attempt %d/%d ended after %d runs with %u/%u first bytes", attempt, kMaxAttempts,
                     run, (unsigned)tracker.uniqueCount(),
                     (unsigned)hardnested::FirstByteTracker::kFirstByteCount);
            if (attempt == kMaxAttempts) {
                snprintf(_key_status, sizeof(_key_status), "gave up: %u/%u first bytes",
                         (unsigned)tracker.uniqueCount(), (unsigned)hardnested::FirstByteTracker::kFirstByteCount);
                _hn_length = 0;
                _hn_records = 0;
                _hn_unique = tracker.uniqueCount();
                _hn_parity_sum = tracker.paritySum();
                return;
            }
            continue;
        }

        if (!tracker.sumIsValid()) {
            // All 256 first bytes seen, but the sum is impossible: the whole
            // collection has to go, exactly as the CLI does it.
            LogEvent("hardnested: attempt %d/%d covered all 256 first bytes but the parity sum %u is invalid, "
                     "retrying", attempt, kMaxAttempts, (unsigned)tracker.paritySum());
            if (attempt == kMaxAttempts) {
                snprintf(_key_status, sizeof(_key_status), "invalid sum %u after %d attempts",
                         (unsigned)tracker.paritySum(), kMaxAttempts);
                _hn_length = 0;
                _hn_records = 0;
                _hn_unique = tracker.uniqueCount();
                _hn_parity_sum = tracker.paritySum();
                return;
            }
            continue;
        }

        best_length  = length;
        best_records = records;
        _hn_unique     = tracker.uniqueCount();
        _hn_parity_sum = tracker.paritySum();
        break;
    }

    _hn_length  = best_length;
    _hn_records = best_records;

    if (_hn_length <= hardnested::kNonceFileHeaderSize) {
        LogEvent("hardnested: no nonces acquired");
        snprintf(_key_status, sizeof(_key_status), "no nonces");
        return;
    }

    const uint32_t crc = hardnested::Crc32(_hn_file, _hn_length);
    LogEvent("hardnested: %u records (%u nonces), parity sum %u, CRC32 %08X", (unsigned)_hn_records,
             (unsigned)(_hn_records * 2), (unsigned)_hn_parity_sum, (unsigned)crc);
    LogEvent("hardnested: press 'export nonces' and run tools/nonce_file_from_console.py on the capture");
    snprintf(_key_status, sizeof(_key_status), "%u records ready to export (sum %u)", (unsigned)_hn_records,
             (unsigned)_hn_parity_sum);
    _shell.RefreshActive();
}

size_t Context::hardNestedRecords() const
{
    return _hn_records;
}
// ---------------------------------------------------------------------------
// mfkey32
// ---------------------------------------------------------------------------
//
// The one recovery that needs no card and no known key: two eavesdropped
// authentications are enough. It is wired here despite the device being unable
// to produce such a trace by itself (docs/M5-KEY-RECOVERY.md section 5), because
// the algorithm is ported and verified and the entry point costs nothing - a
// trace from a PC sniffer, or a future firmware with passive sniffing, uses it
// as is.

bool Context::StartMfkey32(uint32_t uid, const chameleon::crypto::AuthTrace& a,
                           const chameleon::crypto::AuthTrace& b)
{
    if (_key_job != KeyJob::Idle) {
        return false;
    }
    // No card is involved, so this job does not need the device to be attached.
    _mfk_uid   = uid;
    _mfk_a     = a;
    _mfk_b     = b;
    _mfk_key   = 0;
    _mfk_valid = false;
    _mfk_done  = false;

    _key_job_abort = false;
    _key_job       = KeyJob::Mfkey32;
    if (xTaskCreate(key_job_task, "key_job", 8192, this, 3, nullptr) != pdTRUE) {
        _key_job = KeyJob::Idle;
        LogEvent("cannot start key job task");
        return false;
    }
    return true;
}

bool Context::mfkey32Result(uint64_t* out_key) const
{
    if (!_mfk_valid || out_key == nullptr) {
        return false;
    }
    *out_key = _mfk_key;
    return true;
}

void Context::runMfkey32()
{
    const uint32_t uid = _mfk_uid;
    const chameleon::crypto::AuthTrace a = _mfk_a;
    const chameleon::crypto::AuthTrace b = _mfk_b;

    const size_t needed = chameleon::crypto::Mfkey32RequiredBytes();
    const size_t free_bytes = chameleon::crypto::FreePsramBytes();
    LogEvent("mfkey32: uid %08X, needs %u KB, %u KB free", (unsigned)uid, (unsigned)(needed / 1024),
             (unsigned)(free_bytes / 1024));
    snprintf(_key_status, sizeof(_key_status), "mfkey32: searching");
    _shell.RefreshActive();

    uint64_t key = 0;
    const chameleon::crypto::KeyRecoveryStatus status = chameleon::crypto::Mfkey32(uid, a, b, &key);
    if (status == chameleon::crypto::KeyRecoveryStatus::Found) {
        _mfk_key   = key;
        _mfk_valid = true;
        char hex[16];
        snprintf(hex, sizeof(hex), "%012llX", (unsigned long long)key);
        // Deliberately not publishFoundKey(): this key was computed from an
        // eavesdropped trace, not confirmed by a card, and there may be no card
        // in the field at all.
        LogEvent("mfkey32: KEY %s (from the trace, not card-confirmed)", hex);
        snprintf(_key_status, sizeof(_key_status), "mfkey32 found %s", hex);
    } else if (status == chameleon::crypto::KeyRecoveryStatus::OutOfMemory) {
        LogEvent("mfkey32: not enough PSRAM (%u KB needed, %u KB free)", (unsigned)(needed / 1024),
                 (unsigned)(free_bytes / 1024));
        snprintf(_key_status, sizeof(_key_status), "mfkey32: out of memory");
    } else if (status == chameleon::crypto::KeyRecoveryStatus::BadArgument) {
        LogEvent("mfkey32: bad argument");
        snprintf(_key_status, sizeof(_key_status), "mfkey32: bad argument");
    } else {
        LogEvent("mfkey32: no key in this pair of authentications");
        snprintf(_key_status, sizeof(_key_status), "mfkey32: no key");
    }
    _mfk_done = true;
    _shell.RefreshActive();
}

void Context::export_line_sink(void* user, const char* line)
{
    auto* self = static_cast<Context*>(user);
    if (self != nullptr && line != nullptr) {
        // "%s" rather than passing `line` as the format: the offsets and hex in
        // it are harmless today, but a future line with a '%' would read
        // whatever happened to be on the stack.
        self->LogEvent("%s", line);
    }
}

size_t Context::ExportHardNestedNonces()
{
    if (_hn_file == nullptr || _hn_length <= hardnested::kNonceFileHeaderSize) {
        LogEvent("hardnested: nothing to export");
        return 0;
    }
    const uint32_t crc = hardnested::Crc32(_hn_file, _hn_length);
    const size_t lines = hardnested::FormatExport(_hn_file, _hn_length, crc, export_line_sink, this);
    if (lines == 0) {
        LogEvent("hardnested: export refused a %u byte file", (unsigned)_hn_length);
        return 0;
    }
    LogEvent("hardnested: exported %u lines; save the capture and run "
             "tools/nonce_file_from_console.py on it", (unsigned)lines);
    return lines;
}

// ---------------------------------------------------------------------------
// Device state refresh
// ---------------------------------------------------------------------------
void Context::RefreshSlotState()
{
    if (!_connected) {
        return;
    }
    _client.FetchActiveSlot();
    _client.FetchSlotInfo();
    _shell.RefreshActive();
}

void Context::RefreshDeviceState()
{
    if (!_connected) {
        return;
    }
    _client.FetchBattery();
    _shell.RefreshActive();
}

}  // namespace app
