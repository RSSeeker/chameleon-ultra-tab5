// SPDX-License-Identifier: MIT
//
// Chameleon Ultra session implementation.
//
// Payload layouts follow the firmware command processors in
// firmware/application/src/app_cmd.c, which is authoritative where the Python
// client disagrees. Notably:
//   SET_SLOT_TAG_TYPE  : 1 byte slot + big endian u16 tag type. The tag type
//                        itself determines whether the LF or HF type of the
//                        slot is replaced, so there is no sense byte.
//   SET_SLOT_ENABLE    : 1 byte slot + 1 byte sense + 1 byte enabled.
//   GET_SLOT_INFO      : 8 x (big endian u16 hf type, big endian u16 lf type).

#include "chameleon_client.h"

#include <stdio.h>
#include <string.h>

#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char* TAG = "chameleon";

namespace chameleon {
namespace {

/// Returned by Request() when the transport failed or the device went silent.
constexpr uint16_t kStatusTransportError = 0xFFFF;

/// Byte order helpers: the protocol is big endian throughout.
inline uint16_t ReadBe16(const uint8_t* p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t ReadBe32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void WriteBe16(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

}  // namespace

// ---------------------------------------------------------------------------
// Callbacks / plumbing
// ---------------------------------------------------------------------------

void Client::emitLog(bool tx, uint16_t cmd, uint16_t status, size_t data_length)
{
    if (_callbacks.on_log != nullptr) {
        LogLine line;
        line.tx          = tx;
        line.cmd         = cmd;
        line.status      = status;
        line.data_length = data_length;
        _callbacks.on_log(line, _callbacks.user);
    }
}

void Client::emitStatus(const char* text)
{
    if (_callbacks.on_status != nullptr) {
        _callbacks.on_status(text, _callbacks.user);
    }
}

void Client::frameCallback(const FrameParser::Frame& frame, void* user)
{
    auto* self = static_cast<Client*>(user);
    if (self != nullptr) {
        self->onFrame(frame);
    }
}

void Client::onFrame(const FrameParser::Frame& frame)
{
    emitLog(false, frame.cmd, frame.status, frame.data_length);
    completePending(frame);
}

void Client::completePending(const FrameParser::Frame& frame)
{
    if (!_pending) {
        // An unsolicited frame (or a late response to a timed out request).
        ESP_LOGD(TAG, "unmatched response cmd=%u status=%u", frame.cmd, frame.status);
        return;
    }
    if (frame.cmd != _pending_cmd) {
        ESP_LOGD(TAG, "response for cmd=%u while waiting for cmd=%u", frame.cmd, _pending_cmd);
        return;
    }

    _pending_status = frame.status;
    _pending_length = (frame.data_length <= sizeof(_pending_data)) ? frame.data_length : sizeof(_pending_data);
    if (_pending_length > 0 && frame.data != nullptr) {
        memcpy(_pending_data, frame.data, _pending_length);
    }
    _pending_answered = true;
}

void Client::OnTransportData(const uint8_t* data, size_t len)
{
    if (data == nullptr || len == 0) {
        return;
    }
    _parser.Push(data, len, frameCallback, this);
}

void Client::OnTransportState(bool connected)
{
    _connected = connected;
    _pending   = false;
    _parser.Reset();

    if (_callbacks.on_connection != nullptr) {
        _callbacks.on_connection(connected, _callbacks.user);
    }

    if (!connected) {
        _device_info.valid  = false;
        _battery_info.valid = false;
        return;
    }

    ESP_LOGI(TAG, "transport attached, querying device");

    if (!FetchAppVersion()) {
        emitStatus("device did not answer GET_APP_VERSION");
        return;
    }
    FetchDeviceIdentity();
    FetchBattery();
    FetchActiveSlot();
    FetchSlotInfo();
    ChangeDeviceMode(1);  // reader mode: the only mode useful for card operations
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

uint16_t Client::Request(uint16_t cmd, const uint8_t* data, size_t data_len, const uint8_t** response,
                         size_t* response_len, uint32_t timeout_ms)
{
    if (response != nullptr) {
        *response = nullptr;
    }
    if (response_len != nullptr) {
        *response_len = 0;
    }
    if (!_connected) {
        return kStatusTransportError;
    }
    if (!_send) {
        return kStatusTransportError;
    }

    if (timeout_ms == 0) {
        timeout_ms = kDefaultTimeoutMs;
    }

    // Frame into a member buffer so the caller's payload does not have to stay
    // alive (different task).
    const size_t frame_len = BuildFrame(_tx_frame, sizeof(_tx_frame), cmd, 0, data, data_len);
    if (frame_len == 0) {
        ESP_LOGE(TAG, "cannot build frame for cmd=%u len=%u", cmd, (unsigned)data_len);
        return kStatusTransportError;
    }

    _pending          = true;
    _pending_answered = false;
    _pending_status   = 0;
    _pending_length   = 0;
    _pending_cmd      = cmd;

    emitLog(true, cmd, 0, data_len);

    if (_send(_tx_frame, frame_len, _send_user) == false) {
        _pending = false;
        emitStatus("transport write failed");
        return kStatusTransportError;
    }

    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (!_pending_answered) {
        if (xTaskGetTickCount() > deadline) {
            _pending = false;
            ESP_LOGW(TAG, "timeout waiting for cmd=%u (%s)", cmd, CommandText(cmd));
            return kStatusTransportError;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    _pending = false;

    if (response != nullptr && _pending_length > 0) {
        *response = _pending_data;
    }
    if (response_len != nullptr) {
        *response_len = _pending_length;
    }
    return _pending_status;
}

uint16_t Client::Request(uint16_t cmd, uint16_t* status_out)
{
    const uint16_t status = Request(cmd, nullptr, 0, nullptr, nullptr, 0);
    if (status_out != nullptr) {
        *status_out = status;
    }
    return status;
}

// ---------------------------------------------------------------------------
// Typed commands
// ---------------------------------------------------------------------------

bool Client::FetchAppVersion()
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(GET_APP_VERSION, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 2) {
        ESP_LOGW(TAG, "GET_APP_VERSION -> %s (%u)", StatusText(status), status);
        return false;
    }
    _device_info.app_version_major = data[0];
    _device_info.app_version_minor = data[1];
    _device_info.valid             = true;

    char buf[64];
    snprintf(buf, sizeof(buf), "app version %u.%u", data[0], data[1]);
    emitStatus(buf);
    ESP_LOGI(TAG, "app version %u.%u", data[0], data[1]);
    return true;
}

bool Client::FetchDeviceIdentity()
{
    const uint8_t* data = nullptr;
    size_t len          = 0;

    // GET_GIT_VERSION returns an ASCII string of variable length.
    if (Request(GET_GIT_VERSION, nullptr, 0, &data, &len, 0) == SUCCESS && data != nullptr) {
        const size_t copy = (len > sizeof(_device_info.git_version) - 1) ? sizeof(_device_info.git_version) - 1 : len;
        memcpy(_device_info.git_version, data, copy);
        _device_info.git_version[copy] = '\0';
    }

    // GET_DEVICE_CHIP_ID returns 8 bytes (4 x u16) of chip id.
    if (Request(GET_DEVICE_CHIP_ID, nullptr, 0, &data, &len, 0) == SUCCESS && data != nullptr && len >= 8) {
        for (int i = 0; i < 4; ++i) {
            _device_info.chip_id[i] = ReadBe16(data + i * 2);
        }
    }

    // GET_DEVICE_ADDRESS returns 6 bytes of BLE MAC.
    if (Request(GET_DEVICE_ADDRESS, nullptr, 0, &data, &len, 0) == SUCCESS && data != nullptr && len >= 6) {
        memcpy(_device_info.device_address, data, 6);
    }

    // GET_DEVICE_MODEL: 0 = Ultra, 1 = Lite.
    if (Request(GET_DEVICE_MODEL, nullptr, 0, &data, &len, 0) == SUCCESS && data != nullptr && len >= 1) {
        _device_info.device_model = data[0];
    } else {
        _device_info.device_model = 0;  // pre-model firmware: assume Ultra
    }

    char buf[96];
    if (_device_info.device_address[0] != 0) {
        snprintf(buf, sizeof(buf), "model %s  ble %02X:%02X:%02X:%02X:%02X:%02X",
                 _device_info.device_model == 0 ? "Ultra" : "Lite", _device_info.device_address[0],
                 _device_info.device_address[1], _device_info.device_address[2], _device_info.device_address[3],
                 _device_info.device_address[4], _device_info.device_address[5]);
    } else {
        snprintf(buf, sizeof(buf), "model %s", _device_info.device_model == 0 ? "Ultra" : "Lite");
    }
    emitStatus(buf);
    return true;
}

bool Client::FetchBattery()
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_BATTERY_INFO, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr || len < 3) {
        return false;
    }
    _battery_info.voltage_mv = ReadBe16(data);
    _battery_info.percentage = data[2];
    _battery_info.valid      = true;

    if (!_battery_raw_logged) {
        _battery_raw_logged = true;
        char hex[3 * 8 + 1];
        const size_t n = (len < 8) ? len : 8;
        for (size_t i = 0; i < n; ++i) {
            snprintf(hex + i * 3, 4, "%02X ", data[i]);
        }
        hex[n * 3] = '\0';
        // The firmware keeps batt_lvl_in_milli_volts/percentage_batt_lvl at 0
        // until its battery measurement timer has fired once (ble_main.c), so
        // the first read after attach legitimately returns 0/0. Log the raw
        // payload once to distinguish that from a parsing error.
        ESP_LOGI(TAG, "GET_BATTERY_INFO raw: %s-> %u mV %u%%", hex, _battery_info.voltage_mv,
                 _battery_info.percentage);
    }
    return true;
}

bool Client::FetchActiveSlot()
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_ACTIVE_SLOT, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr || len < 1) {
        return false;
    }
    _active_slot = (data[0] < kSlotCount) ? data[0] : 0;
    return true;
}

bool Client::FetchSlotInfo()
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_SLOT_INFO, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr) {
        return false;
    }

    const size_t entries = len / 4;
    for (size_t i = 0; i < kSlotCount; ++i) {
        if (i < entries) {
            _slot_info[i].hf_tag_type = ReadBe16(data + i * 4);
            _slot_info[i].lf_tag_type = ReadBe16(data + i * 4 + 2);
            // A slot is "enabled" for a band when it emulates a real type there.
            _slot_info[i].enabled_hf = _slot_info[i].hf_tag_type != TAG_UNDEFINED;
            _slot_info[i].enabled_lf = _slot_info[i].lf_tag_type != TAG_UNDEFINED;
        } else {
            _slot_info[i] = SlotInfo{};
        }
    }
    return true;
}

bool Client::SetActiveSlot(uint8_t slot)
{
    if (slot >= kSlotCount) {
        return false;
    }
    const uint8_t payload = slot;
    const uint16_t status = Request(SET_ACTIVE_SLOT, &payload, 1, nullptr, nullptr, 0);
    if (status == SUCCESS) {
        _active_slot = slot;
        return true;
    }
    return false;
}

bool Client::SetSlotEnabled(uint8_t slot, TagSenseType sense, bool enabled)
{
    if (slot >= kSlotCount) {
        return false;
    }
    const uint8_t payload[3] = {slot, static_cast<uint8_t>(sense), static_cast<uint8_t>(enabled ? 1 : 0)};
    return Request(SET_SLOT_ENABLE, payload, sizeof(payload), nullptr, nullptr, 0) == SUCCESS;
}

bool Client::SetSlotTagType(uint8_t slot, TagSenseType sense, uint16_t tag_type)
{
    // The tag type value itself carries the band (LF types are < 1000), so the
    // firmware needs no sense byte. The sense argument is validated for the
    // caller's benefit only.
    if (slot >= kSlotCount) {
        return false;
    }
    const bool is_lf = (tag_type < TAG_TYPES_LF_END);
    if ((sense == TagSenseType::LF) != is_lf) {
        ESP_LOGW(TAG, "tag type %u does not match requested band", tag_type);
        return false;
    }

    uint8_t payload[3];
    payload[0] = slot;
    WriteBe16(payload + 1, tag_type);
    return Request(SET_SLOT_TAG_TYPE, payload, sizeof(payload), nullptr, nullptr, 0) == SUCCESS;
}

bool Client::SetSlotNick(uint8_t slot, TagSenseType sense, const char* nick)
{
    if (slot >= kSlotCount || nick == nullptr) {
        return false;
    }
    const size_t nick_len = strlen(nick);
    if (nick_len > 32) {
        ESP_LOGW(TAG, "nick too long (%u)", (unsigned)nick_len);
        return false;
    }

    uint8_t payload[2 + 32];
    payload[0] = slot;
    payload[1] = static_cast<uint8_t>(sense);
    memcpy(payload + 2, nick, nick_len);

    return Request(SET_SLOT_TAG_NICK, payload, 2 + nick_len, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::GetSlotNick(uint8_t slot, TagSenseType sense, char* out, size_t out_size)
{
    if (slot >= kSlotCount || out == nullptr || out_size == 0) {
        return false;
    }

    const uint8_t payload[2] = {slot, static_cast<uint8_t>(sense)};
    const uint8_t* data      = nullptr;
    size_t len               = 0;

    const uint16_t status = Request(GET_SLOT_TAG_NICK, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS) {
        return false;
    }

    const size_t copy = (len < out_size - 1) ? len : out_size - 1;
    if (copy > 0 && data != nullptr) {
        memcpy(out, data, copy);
    }
    out[copy] = '\0';
    return true;
}

bool Client::GetSleepTimeout(uint32_t* seconds)
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_SLEEP_TIMEOUT, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr) {
        return false;
    }
    if (seconds != nullptr) {
        *seconds = data[0];
    }
    return true;
}

bool Client::SetSleepTimeout(uint32_t seconds)
{
    if (seconds > 255) {
        return false;
    }
    const uint8_t payload = static_cast<uint8_t>(seconds);
    return Request(SET_SLEEP_TIMEOUT, &payload, 1, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::GetAnimationMode(uint8_t* mode)
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_ANIMATION_MODE, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr) {
        return false;
    }
    if (mode != nullptr) {
        *mode = data[0];
    }
    return true;
}

bool Client::SetAnimationMode(uint8_t mode)
{
    return Request(SET_ANIMATION_MODE, &mode, 1, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::SaveSettings()
{
    return Request(SAVE_SETTINGS, nullptr, 0, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::ChangeDeviceMode(uint8_t mode)
{
    return Request(CHANGE_DEVICE_MODE, &mode, 1, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::FetchDeviceMode(uint8_t* mode)
{
    const uint8_t* data = nullptr;
    size_t len          = 0;
    if (Request(GET_DEVICE_MODE, nullptr, 0, &data, &len, 0) != SUCCESS || data == nullptr || len < 1) {
        return false;
    }
    if (mode != nullptr) {
        *mode = data[0] ? 1 : 0;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Card operations (M3)
//
// Payload layouts are taken from software/script/chameleon_cmd.py and cross
// checked against the firmware processors in app_cmd.c.
// ---------------------------------------------------------------------------

uint16_t Client::ScanHf(HfTag* out, size_t max_tags, size_t* count)
{
    if (count != nullptr) {
        *count = 0;
    }
    if (out == nullptr || max_tags == 0) {
        return PAR_ERR;
    }

    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(HF14A_SCAN, nullptr, 0, &data, &len, 3000);
    if (status != HF_TAG_OK || data == nullptr) {
        return status;
    }

    // Raw dump once: the HF14A_SCAN payload is a variable length record list and
    // is the one place where a mis-parse is easy to miss visually.
    if (!_hf_scan_raw_logged) {
        _hf_scan_raw_logged = true;
        char hex[3 * 40 + 1];
        const size_t n = (len < 40) ? len : 40;
        for (size_t i = 0; i < n; ++i) {
            snprintf(hex + i * 3, 4, "%02X ", data[i]);
        }
        hex[n * 3] = '\0';
        ESP_LOGI(TAG, "HF14A_SCAN raw (%u bytes): %s", (unsigned)len, hex);
    }

    // Repeated records: uidlen[1] | uid[uidlen] | atqa[2] | sak[1] | atslen[1] | ats[atslen]
    size_t offset = 0;
    size_t found  = 0;
    while (offset < len && found < max_tags) {
        HfTag& tag = out[found];

        const uint8_t uid_len = data[offset++];
        if (uid_len == 0 || uid_len > sizeof(tag.uid) || offset + uid_len + 4 > len) {
            break;
        }
        memcpy(tag.uid, data + offset, uid_len);
        tag.uid_length = uid_len;
        offset += uid_len;

        memcpy(tag.atqa, data + offset, 2);
        offset += 2;
        tag.sak = data[offset++];

        const uint8_t ats_len = data[offset++];
        if (offset + ats_len > len || ats_len > sizeof(tag.ats)) {
            break;
        }
        if (ats_len > 0) {
            memcpy(tag.ats, data + offset, ats_len);
        }
        tag.ats_length = ats_len;
        offset += ats_len;

        ++found;
    }

    if (count != nullptr) {
        *count = found;
    }
    return status;
}

uint16_t Client::ScanEm410x(LfTag* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(EM410X_SCAN, nullptr, 0, &data, &len, 3000);
    if (status != LF_TAG_OK || data == nullptr || len < 2) {
        return status;
    }

    // tag_type[2] big endian, then 5 bytes (EM410X) or 13 bytes (Electra).
    out->tag_type = ReadBe16(data);
    const size_t id_len = (out->tag_type == EM410X_ELECTRA) ? 13 : 5;
    if (len < 2 + id_len) {
        return HF_ERR_STAT;
    }
    memcpy(out->id, data + 2, id_len);
    out->id_length = static_cast<uint8_t>(id_len);
    return status;
}

uint16_t Client::ReadMifareBlock(uint8_t block, MfcKeyType key_type, const uint8_t key[6], uint8_t out[16])
{
    if (key == nullptr || out == nullptr) {
        return PAR_ERR;
    }

    uint8_t payload[8];
    payload[0] = static_cast<uint8_t>(key_type);
    payload[1] = block;
    memcpy(payload + 2, key, 6);

    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(MF1_READ_ONE_BLOCK, payload, sizeof(payload), &data, &len, 0);
    if (status != HF_TAG_OK || data == nullptr || len < 16) {
        return status;
    }
    memcpy(out, data, 16);
    return status;
}

uint16_t Client::WriteMifareBlock(uint8_t block, MfcKeyType key_type, const uint8_t key[6], const uint8_t data[16])
{
    if (key == nullptr || data == nullptr) {
        return PAR_ERR;
    }

    uint8_t payload[24];
    payload[0] = static_cast<uint8_t>(key_type);
    payload[1] = block;
    memcpy(payload + 2, key, 6);
    memcpy(payload + 8, data, 16);

    return Request(MF1_WRITE_ONE_BLOCK, payload, sizeof(payload), nullptr, nullptr, 0);
}

uint16_t Client::AuthMifareKey(uint8_t block, MfcKeyType key_type, const uint8_t key[6])
{
    if (key == nullptr) {
        return PAR_ERR;
    }
    uint8_t payload[8];
    payload[0] = static_cast<uint8_t>(key_type);
    payload[1] = block;
    memcpy(payload + 2, key, 6);
    return Request(MF1_AUTH_ONE_KEY_BLOCK, payload, sizeof(payload), nullptr, nullptr, 0);
}

const char* Client::DarksideStatusText(DarksideStatus status)
{
    switch (status) {
        case DarksideStatus::Ok:
            return "success";
        case DarksideStatus::CantFixNt:
            return "cannot fix NT (unpredictable PRNG)";
        case DarksideStatus::LuckyAuthOk:
            return "a default key already worked";
        case DarksideStatus::NoNakSent:
            return "tag sent no NACK";
        case DarksideStatus::TagChanged:
            return "tag left the field";
        default:
            return "unknown";
    }
}

uint16_t Client::DarksideAcquire(uint8_t block, MfcKeyType key_type, bool first_recover, uint8_t sync_max,
                                 DarksideResult* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    *out = DarksideResult{};

    // type | block | first_recover | sync_max (chameleon_cmd.py mf1_darkside_acquire)
    const uint8_t payload[4] = {static_cast<uint8_t>(key_type), block, static_cast<uint8_t>(first_recover ? 1 : 0),
                                sync_max};

    const uint8_t* data = nullptr;
    size_t len          = 0;
    // The device spends up to sync_max attempts on this, and the CLI waits
    // sync_max * 10 seconds for it.
    const uint32_t timeout = static_cast<uint32_t>(sync_max) * 10000u;
    const uint16_t status  = Request(MF1_DARKSIDE_ACQUIRE, payload, sizeof(payload), &data, &len, timeout);
    if (status != HF_TAG_OK || data == nullptr || len == 0) {
        return status;
    }

    out->status = static_cast<DarksideStatus>(data[0]);
    if (out->status != DarksideStatus::Ok) {
        // A non-OK result carries only the status byte.
        return status;
    }
    if (len < 33) {
        return PAR_ERR;
    }

    // darkside_status | uid | nt | par(64) | ks(64) | nr | ar, big endian.
    const uint8_t* p = data + 1;
    auto rd32        = [](const uint8_t* q) {
        return (static_cast<uint32_t>(q[0]) << 24) | (static_cast<uint32_t>(q[1]) << 16) |
               (static_cast<uint32_t>(q[2]) << 8) | static_cast<uint32_t>(q[3]);
    };
    auto rd64 = [&rd32](const uint8_t* q) {
        return (static_cast<uint64_t>(rd32(q)) << 32) | static_cast<uint64_t>(rd32(q + 4));
    };

    out->uid = rd32(p);
    out->nt  = rd32(p + 4);
    out->par = rd64(p + 8);
    out->ks  = rd64(p + 16);
    out->nr  = rd32(p + 24);
    out->ar  = rd32(p + 28);
    out->valid = true;
    return status;
}

uint16_t Client::CheckKeysOfSectors(const uint8_t mask[10], const uint8_t* keys, size_t key_count, uint8_t found[10],
                                    uint8_t (*sector_keys)[6], size_t* out_length)
{
    if (mask == nullptr || keys == nullptr || found == nullptr || key_count < 1 || key_count > 83) {
        return PAR_ERR;
    }
    if (out_length != nullptr) {
        *out_length = 0;
    }

    uint8_t payload[10 + 6 * 83];
    memcpy(payload, mask, 10);
    memcpy(payload + 10, keys, key_count * 6);

    const uint8_t* data = nullptr;
    size_t len          = 0;
    // The CLI budgets 1 s plus 0.1 s per (key, sector bit) pair.
    size_t bits = 0;
    for (size_t i = 0; i < 10; ++i) {
        for (uint8_t b = mask[i]; b != 0; b >>= 1) {
            bits += (b & 1u);
        }
    }
    const uint32_t timeout = static_cast<uint32_t>(1000 + (bits + 1) * key_count * 100);

    const uint16_t status = Request(MF1_CHECK_KEYS_OF_SECTORS, payload, 10 + key_count * 6, &data, &len, timeout);
    if (out_length != nullptr) {
        *out_length = len;
    }
    if ((status != HF_TAG_OK && status != HF_TAG_NO) || data == nullptr) {
        return status;
    }
    // All sectors masked out: the device answers with an empty payload.
    if (len < 10) {
        return status;
    }

    memcpy(found, data, 10);
    if (sector_keys != nullptr && len >= 10 + 6 * kMfcSectorCount) {
        memcpy(sector_keys, data + 10, 6 * kMfcSectorCount);
    }
    return status;
}

uint16_t Client::CheckKeysOnBlock(uint8_t block, MfcKeyType key_type, const uint8_t* keys, size_t key_count,
                                  const uint8_t** out, size_t* out_length)
{
    if (keys == nullptr || key_count < 1 || key_count > 83) {
        return PAR_ERR;
    }
    if (out_length != nullptr) {
        *out_length = 0;
    }

    // Layout from app_cmd.c cmd_processor_mf1_check_keys_on_block, which accepts
    // only what it can parse:
    //     if (length < 9 || data[2] * 6 + 3 != length) return PAR_ERR;
    //     .block = data[0]; .key_type = data[1]; .keys_len = data[2];
    //     .keys = (mf1_key_t *) &data[3];
    // i.e. block | key_type | key_count | keys. chameleon_cmd.py's
    // mf1_check_keys_on_block() packs the same thing
    // (`struct.pack(f'!BBB{6*len(keys)}s', block, key_type, len(keys), ...)`).
    //
    // This used to send key_type | block | keys with no count byte, which the
    // device rejects outright: it reads data[2] as the key count, and the first
    // key byte is not a valid count. tools/verify_payloads.py caught it.
    uint8_t payload[3 + 6 * 83];
    payload[0] = block;
    payload[1] = static_cast<uint8_t>(key_type);
    payload[2] = static_cast<uint8_t>(key_count);
    memcpy(payload + 3, keys, key_count * 6);

    const uint8_t* data    = nullptr;
    size_t len             = 0;
    const uint32_t timeout = static_cast<uint32_t>(1000 + key_count * 200);
    const uint16_t status  = Request(MF1_CHECK_KEYS_ON_BLOCK, payload, 3 + key_count * 6, &data, &len, timeout);

    if (out != nullptr) {
        *out = data;
    }
    if (out_length != nullptr) {
        *out_length = len;
    }
    return status;
}

bool Client::SetHfAntiColl(const uint8_t* uid, uint8_t uid_length, const uint8_t atqa[2], uint8_t sak,
                           const uint8_t* ats, uint8_t ats_length)
{
    if (uid == nullptr || atqa == nullptr || uid_length == 0 || uid_length > 10 || ats_length > 32) {
        return false;
    }

    // uidlen[1] | uid | atqa[2] | sak[1] | atslen[1] | ats[atslen]
    uint8_t payload[1 + 10 + 2 + 1 + 1 + 32];
    size_t n = 0;
    payload[n++] = uid_length;
    memcpy(payload + n, uid, uid_length);
    n += uid_length;
    memcpy(payload + n, atqa, 2);
    n += 2;
    payload[n++] = sak;
    payload[n++] = ats_length;
    if (ats_length > 0 && ats != nullptr) {
        memcpy(payload + n, ats, ats_length);
        n += ats_length;
    }

    return Request(HF14A_SET_ANTI_COLL_DATA, payload, n, nullptr, nullptr, 0) == SUCCESS;
}

uint16_t Client::GetHfAntiColl(HfTag* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(HF14A_GET_ANTI_COLL_DATA, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS) {
        return status;
    }

    // A slot that has no emulated identity yet answers SUCCESS with an empty
    // payload (app_cmd.c returns data_frame_make(cmd, STATUS_SUCCESS, 0, NULL)
    // when get_coll_res_data() gives nothing). That is "nothing configured",
    // not an error, so report it as a successful read of a zero length UID and
    // let the caller offer to write one.
    if (len == 0 || data == nullptr) {
        *out = HfTag{};
        return SUCCESS;
    }
    if (len < 5) {
        // Anything else that is too short to hold uidlen|uid|atqa|sak|atslen is
        // a malformed reply and must not be silently accepted.
        return HF_ERR_STAT;
    }

    size_t offset         = 0;
    const uint8_t uid_len = data[offset++];
    if (uid_len > sizeof(out->uid) || offset + uid_len + 3 > len) {
        return HF_ERR_STAT;
    }
    memcpy(out->uid, data + offset, uid_len);
    out->uid_length = uid_len;
    offset += uid_len;

    memcpy(out->atqa, data + offset, 2);
    offset += 2;
    out->sak = data[offset++];

    if (offset < len) {
        const uint8_t ats_len = data[offset++];
        if (ats_len <= sizeof(out->ats) && offset + ats_len <= len) {
            memcpy(out->ats, data + offset, ats_len);
            out->ats_length = ats_len;
        }
    }
    return status;
}

bool Client::SetEm410xEmuId(const uint8_t* id, uint8_t id_length)
{
    if (id == nullptr || (id_length != 5 && id_length != 13)) {
        return false;
    }
    return Request(EM410X_SET_EMU_ID, id, id_length, nullptr, nullptr, 0) == SUCCESS;
}

uint16_t Client::GetEm410xEmuId(LfTag* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data = nullptr;
    size_t len          = 0;
    const uint16_t status = Request(EM410X_GET_EMU_ID, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 6) {
        return status;
    }

    out->tag_type = ReadBe16(data);
    const size_t id_len = (out->tag_type == EM410X_ELECTRA) ? 13 : 5;
    if (len < 2 + id_len) {
        return HF_ERR_STAT;
    }
    memcpy(out->id, data + 2, id_len);
    out->id_length = static_cast<uint8_t>(id_len);
    return status;
}

uint16_t Client::ReadEmuBlocks(uint8_t block_start, uint8_t block_count, uint8_t* out, size_t out_size,
                               size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t payload[2] = {block_start, block_count};
    const uint8_t* data      = nullptr;
    size_t len               = 0;
    const uint16_t status    = Request(MF1_READ_EMU_BLOCK_DATA, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

bool Client::WriteEmuBlocks(uint8_t block_start, const uint8_t* data, size_t length)
{
    if (data == nullptr || length == 0) {
        return false;
    }

    // block_start[1] | data[length]
    static uint8_t payload[1 + kMaxDataLength];
    if (length + 1 > sizeof(payload)) {
        return false;
    }
    payload[0] = block_start;
    memcpy(payload + 1, data, length);

    return Request(MF1_WRITE_EMU_BLOCK_DATA, payload, length + 1, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::MifareSupported()
{
    return Request(MF1_DETECT_SUPPORT, nullptr, 0, nullptr, nullptr, 0) == HF_TAG_OK;
}

// ---------------------------------------------------------------------------
// LF emulated card id
//
// Layouts read from software/script/chameleon_cmd.py: each SET takes the raw id
// bytes, each GET returns the same bytes (EM410X may prefix them with the 2 byte
// tag type), and all of them answer with STATUS_SUCCESS rather than HF_TAG_OK.
// ---------------------------------------------------------------------------

namespace {

struct LfEmuEntry {
    uint16_t set_cmd;
    uint16_t get_cmd;
    uint8_t id_length;
};

/// Indexed by Client::LfEmuProtocol.
constexpr LfEmuEntry kLfEmuTable[] = {
    {EM410X_SET_EMU_ID, EM410X_GET_EMU_ID, 5},          // Em410x (Electra uses 13)
    {HIDPROX_SET_EMU_ID, HIDPROX_GET_EMU_ID, 13},       // HidProx
    {VIKING_SET_EMU_ID, VIKING_GET_EMU_ID, 4},          // Viking
    {PAC_SET_EMU_ID, PAC_GET_EMU_ID, 8},                // Pac
    {IOPROX_SET_EMU_ID, IOPROX_GET_EMU_ID, 16},         // IoProx
    {JABLOTRON_SET_EMU_ID, JABLOTRON_GET_EMU_ID, 5},    // Jablotron
    {IDTECK_SET_EMU_ID, IDTECK_GET_EMU_ID, 8},          // Idteck
};
constexpr size_t kLfEmuCount = sizeof(kLfEmuTable) / sizeof(kLfEmuTable[0]);

constexpr size_t kEm410xElectraIdLength = 13;

}  // namespace

size_t Client::LfEmuIdLength(LfEmuProtocol protocol)
{
    const size_t index = static_cast<size_t>(protocol);
    return index < kLfEmuCount ? kLfEmuTable[index].id_length : 0;
}

bool Client::LfEmuProtocolForTagType(uint16_t lf_tag_type, LfEmuProtocol* out)
{
    if (out == nullptr) {
        return false;
    }
    switch (lf_tag_type) {
        case EM410X:
        case EM410X_16:
        case EM410X_32:
        case EM410X_64:
        case EM410X_ELECTRA:
            *out = LfEmuProtocol::Em410x;
            return true;
        case HIDProx:
            *out = LfEmuProtocol::HidProx;
            return true;
        case Viking:
            *out = LfEmuProtocol::Viking;
            return true;
        case PAC:
            *out = LfEmuProtocol::Pac;
            return true;
        case ioProx:
            *out = LfEmuProtocol::IoProx;
            return true;
        case Jablotron:
            *out = LfEmuProtocol::Jablotron;
            return true;
        case IDTECK:
            *out = LfEmuProtocol::Idteck;
            return true;
        default:
            return false;
    }
}

uint16_t Client::SetLfEmuId(LfEmuProtocol protocol, const uint8_t* id, size_t id_length)
{
    const size_t index = static_cast<size_t>(protocol);
    if (id == nullptr || index >= kLfEmuCount) {
        return PAR_ERR;
    }

    // EM410X is the one protocol with two valid lengths: the active slot decides
    // whether it is a plain EM410X (5) or an Electra (13).
    if (protocol == LfEmuProtocol::Em410x) {
        if (id_length != kLfEmuTable[index].id_length && id_length != kEm410xElectraIdLength) {
            return PAR_ERR;
        }
    } else if (id_length != kLfEmuTable[index].id_length) {
        return PAR_ERR;
    }

    return Request(kLfEmuTable[index].set_cmd, id, id_length, nullptr, nullptr, 0);
}

uint16_t Client::GetLfEmuId(LfEmuProtocol protocol, uint8_t* out, size_t out_size, size_t* out_length)
{
    const size_t index = static_cast<size_t>(protocol);
    if (out == nullptr || out_length == nullptr || index >= kLfEmuCount) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(kLfEmuTable[index].get_cmd, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len == 0) {
        return status;
    }

    size_t offset = 0;
    if (protocol == LfEmuProtocol::Em410x && len >= 2) {
        // chameleon_cmd.py tolerates both shapes: either tag_type[2] || id, or
        // the bare id. Only strip the prefix when it really is an EM410X type
        // and the remaining length matches that variant.
        const uint16_t tag_type = ReadBe16(data);
        const bool is_em410x     = (tag_type == EM410X || tag_type == EM410X_16 || tag_type == EM410X_32 ||
                                tag_type == EM410X_64);
        const bool is_electra    = (tag_type == EM410X_ELECTRA);
        const size_t expect      = is_electra ? kEm410xElectraIdLength : kLfEmuTable[index].id_length;
        if ((is_em410x || is_electra) && len == expect + 2) {
            offset = 2;
        }
    }

    const size_t copy = ((len - offset) < out_size) ? (len - offset) : out_size;
    memcpy(out, data + offset, copy);
    *out_length = copy;
    return status;
}

// ---------------------------------------------------------------------------
// MF1 emulator settings
//
// Seven settings share the same shape: GET answers one byte, SET sends one byte
// and is answered with STATUS_SUCCESS. Layouts from chameleon_cmd.py.
// ---------------------------------------------------------------------------

namespace {

struct Mf1ToggleEntry {
    uint16_t get_cmd;
    uint16_t set_cmd;
};

/// Indexed by Client::Mf1Toggle.
constexpr Mf1ToggleEntry kMf1Toggles[] = {
    {MF1_GET_GEN1A_MODE, MF1_SET_GEN1A_MODE},
    {MF1_GET_GEN2_MODE, MF1_SET_GEN2_MODE},
    {MF1_GET_BLOCK_ANTI_COLL_MODE, MF1_SET_BLOCK_ANTI_COLL_MODE},
    {MF1_GET_WRITE_MODE, MF1_SET_WRITE_MODE},
    {MF1_GET_FIELD_OFF_DO_RESET, MF1_SET_FIELD_OFF_DO_RESET},
    {MF1_GET_PRNG_TYPE, MF1_SET_PRNG_TYPE},
    {MF1_GET_DETECTION_ENABLE, MF1_SET_DETECTION_ENABLE},
};
constexpr size_t kMf1ToggleCount = sizeof(kMf1Toggles) / sizeof(kMf1Toggles[0]);

}  // namespace

uint16_t Client::GetMf1Toggle(Mf1Toggle which, uint8_t* out)
{
    const size_t index = static_cast<size_t>(which);
    if (out == nullptr || index >= kMf1ToggleCount) {
        return PAR_ERR;
    }

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(kMf1Toggles[index].get_cmd, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *out = data[0];
    return status;
}

uint16_t Client::SetMf1Toggle(Mf1Toggle which, uint8_t value)
{
    const size_t index = static_cast<size_t>(which);
    if (index >= kMf1ToggleCount) {
        return PAR_ERR;
    }
    return Request(kMf1Toggles[index].set_cmd, &value, 1, nullptr, nullptr, 0);
}

uint16_t Client::GetMf1EmulatorConfig(Mf1EmulatorConfig* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_GET_EMULATOR_CONFIG, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 5) {
        return status;
    }

    // app_cmd.c: detection, gen1a, gen2, use_mf1_coll_res, write mode.
    out->detection    = data[0];
    out->gen1a_magic  = data[1];
    out->gen2_magic   = data[2];
    out->use_mf1_coll = data[3];
    out->write_mode   = data[4];
    return status;
}

uint16_t Client::Mf1DetectPrng(uint8_t* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_DETECT_PRNG, nullptr, 0, &data, &len, 0);
    if (status != HF_TAG_OK || data == nullptr || len < 1) {
        return status;
    }
    *out = data[0];
    return status;
}

uint16_t Client::Mf1GetDetectionCount(uint32_t* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_GET_DETECTION_COUNT, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 4) {
        return status;
    }
    *out = ReadBe32(data);
    return status;
}

uint16_t Client::Mf1GetDetectionLog(uint32_t index, Mf1DetectionEntry* out, size_t max, size_t* count)
{
    if (out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    const uint8_t payload[4] = {static_cast<uint8_t>(index >> 24), static_cast<uint8_t>(index >> 16),
                                static_cast<uint8_t>(index >> 8), static_cast<uint8_t>(index)};
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_GET_DETECTION_LOG, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    // Records are 14 bytes: block, bitfield, uid[4], nt[4], nr[4], ar[4].
    constexpr size_t kRecordSize = 14;
    size_t n = 0;
    for (size_t offset = 0; offset + kRecordSize <= len && n < max; offset += kRecordSize) {
        const uint8_t* p = data + offset;
        out[n].block    = p[0];
        out[n].bitfield = p[1];
        memcpy(out[n].uid, p + 2, 4);
        memcpy(out[n].nt, p + 6, 4);
        memcpy(out[n].nr, p + 10, 4);
        memcpy(out[n].ar, p + 14, 4);
        ++n;
    }
    *count = n;
    return status;
}

// ---------------------------------------------------------------------------
// MF0 / NTAG emulator
// ---------------------------------------------------------------------------

uint16_t Client::Mf0SetUidMagicMode(bool enabled)
{
    const uint8_t payload = enabled ? 1 : 0;
    return Request(MF0_NTAG_SET_UID_MAGIC_MODE, &payload, 1, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetUidMagicMode(bool* enabled)
{
    if (enabled == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_UID_MAGIC_MODE, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *enabled = data[0] != 0;
    return status;
}

uint16_t Client::Mf0GetPageCount(uint8_t* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_PAGE_COUNT, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *out = data[0];
    return status;
}

uint16_t Client::Mf0ReadEmuPageData(uint8_t page_start, uint8_t page_count, uint8_t* out, size_t out_size,
                                    size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t payload[2] = {page_start, page_count};
    const uint8_t* data      = nullptr;
    size_t len               = 0;
    const uint16_t status    = Request(MF0_NTAG_READ_EMU_PAGE_DATA, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

uint16_t Client::Mf0WriteEmuPageData(uint8_t page_start, const uint8_t* data, size_t length)
{
    if (data == nullptr || length == 0 || length + 2 > kMaxDataLength) {
        return PAR_ERR;
    }
    // page_start | page_count | data (chameleon_cmd.py: pack('!BB') + data)
    static uint8_t payload[kMaxDataLength];
    const size_t pages = length / 4;
    payload[0]         = page_start;
    payload[1]         = static_cast<uint8_t>(pages);
    memcpy(payload + 2, data, length);
    return Request(MF0_NTAG_WRITE_EMU_PAGE_DATA, payload, length + 2, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetVersionData(uint8_t out[8])
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_VERSION_DATA, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 8) {
        return status;
    }
    memcpy(out, data, 8);
    return status;
}

uint16_t Client::Mf0SetVersionData(const uint8_t data[8])
{
    if (data == nullptr) {
        return PAR_ERR;
    }
    return Request(MF0_NTAG_SET_VERSION_DATA, data, 8, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetSignatureData(uint8_t out[32])
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_SIGNATURE_DATA, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 32) {
        return status;
    }
    memcpy(out, data, 32);
    return status;
}

uint16_t Client::Mf0SetSignatureData(const uint8_t data[32])
{
    if (data == nullptr) {
        return PAR_ERR;
    }
    return Request(MF0_NTAG_SET_SIGNATURE_DATA, data, 32, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetCounterData(uint8_t index, uint32_t* value, bool* tearing)
{
    if (value == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_COUNTER_DATA, &index, 1, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 4) {
        return status;
    }

    // chameleon_cmd.py: value is three LITTLE endian bytes, and the fourth byte
    // is 0xBD when the counter was torn.
    *value = static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
             (static_cast<uint32_t>(data[2]) << 16);
    if (tearing != nullptr) {
        *tearing = (data[3] == 0xBD);
    }
    return status;
}

uint16_t Client::Mf0SetCounterData(uint8_t index, bool reset_tearing, uint32_t value)
{
    // pack('!BBBB', index | (reset_tearing << 7), value & 0xFF, value >> 8, value >> 16)
    const uint8_t payload[4] = {static_cast<uint8_t>(index | (reset_tearing ? 0x80 : 0x00)),
                                static_cast<uint8_t>(value & 0xFF), static_cast<uint8_t>((value >> 8) & 0xFF),
                                static_cast<uint8_t>((value >> 16) & 0xFF)};
    return Request(MF0_NTAG_SET_COUNTER_DATA, payload, sizeof(payload), nullptr, nullptr, 0);
}

uint16_t Client::Mf0ResetAuthCnt(uint8_t* out)
{
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_RESET_AUTH_CNT, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    if (out != nullptr) {
        *out = data[0];
    }
    return status;
}

uint16_t Client::Mf0GetWriteMode(uint8_t* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_WRITE_MODE, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *out = data[0];
    return status;
}

uint16_t Client::Mf0SetWriteMode(uint8_t mode)
{
    return Request(MF0_NTAG_SET_WRITE_MODE, &mode, 1, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetEmulatorConfig(Mf0EmulatorConfig* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_EMULATOR_CONFIG, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 3) {
        return status;
    }
    // app_cmd.c: detection, uid mode, write mode.
    out->detection  = data[0];
    out->uid_mode   = data[1];
    out->write_mode = data[2];
    return status;
}

uint16_t Client::Mf0SetDetectionEnable(bool enabled)
{
    const uint8_t payload = enabled ? 1 : 0;
    return Request(MF0_NTAG_SET_DETECTION_ENABLE, &payload, 1, nullptr, nullptr, 0);
}

uint16_t Client::Mf0GetDetectionEnable(bool* enabled)
{
    if (enabled == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_DETECTION_ENABLE, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *enabled = data[0] == 1;
    return status;
}

uint16_t Client::Mf0GetDetectionCount(uint32_t* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_DETECTION_COUNT, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 4) {
        return status;
    }
    *out = ReadBe32(data);
    return status;
}

uint16_t Client::Mf0GetDetectionLog(uint32_t index, uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t payload[4] = {static_cast<uint8_t>(index >> 24), static_cast<uint8_t>(index >> 16),
                                static_cast<uint8_t>(index >> 8), static_cast<uint8_t>(index)};
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF0_NTAG_GET_DETECTION_LOG, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

// ---------------------------------------------------------------------------
// Remaining system commands
// ---------------------------------------------------------------------------

uint16_t Client::GetDeviceSettings(DeviceSettings* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_DEVICE_SETTINGS, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 19) {
        return status;
    }

    // chameleon_cmd.py: '!BBBBBBB6sB' -> version, animation, A, B, long A, long B,
    // ble pairing enable, 6 byte pairing key, sleep timeout.
    size_t offset               = 0;
    out->version                = data[offset++];
    out->animation_mode         = data[offset++];
    out->button_press_a         = data[offset++];
    out->button_press_b         = data[offset++];
    out->button_long_press_a    = data[offset++];
    out->button_long_press_b    = data[offset++];
    out->ble_pairing_enable     = data[offset++];
    memcpy(out->ble_pairing_key, data + offset, 6);
    offset += 6;
    out->sleep_timeout = data[offset];
    return status;
}

uint16_t Client::GetDeviceCapabilities(uint16_t* out, size_t max, size_t* count)
{
    if (out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_DEVICE_CAPABILITIES, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    size_t n = 0;
    for (size_t offset = 0; offset + 2 <= len && n < max; offset += 2) {
        out[n++] = ReadBe16(data + offset);
    }
    *count = n;
    return status;
}

uint16_t Client::GetEnabledSlots(EnabledSlot* out, size_t max, size_t* count)
{
    if (out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_ENABLED_SLOTS, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    size_t n = 0;
    for (size_t offset = 0; offset + 2 <= len && n < max; offset += 2) {
        out[n].hf = data[offset];
        out[n].lf = data[offset + 1];
        ++n;
    }
    *count = n;
    return status;
}

uint16_t Client::GetAllSlotNicks(SlotNicks* out, size_t max, size_t* count)
{
    if (out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_ALL_SLOT_NICKS, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    // Per slot: hf_len | hf bytes | lf_len | lf bytes, with the length byte
    // always consumed even when the text is absent or truncated.
    size_t offset = 0;
    size_t n      = 0;
    while (offset < len && n < max) {
        SlotNicks& entry = out[n];

        const size_t hf_len = data[offset++];
        if (hf_len > 0 && offset + hf_len <= len) {
            const size_t copy = (hf_len < sizeof(entry.hf) - 1) ? hf_len : sizeof(entry.hf) - 1;
            memcpy(entry.hf, data + offset, copy);
            entry.hf[copy] = '\0';
        }
        offset += hf_len;

        if (offset >= len) {
            break;
        }
        const size_t lf_len = data[offset++];
        if (lf_len > 0 && offset + lf_len <= len) {
            const size_t copy = (lf_len < sizeof(entry.lf) - 1) ? lf_len : sizeof(entry.lf) - 1;
            memcpy(entry.lf, data + offset, copy);
            entry.lf[copy] = '\0';
        }
        offset += lf_len;

        ++n;
    }
    *count = n;
    return status;
}

uint16_t Client::GetButtonPressConfig(uint8_t button, uint8_t* function)
{
    if (function == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_BUTTON_PRESS_CONFIG, &button, 1, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *function = data[0];
    return status;
}

uint16_t Client::SetButtonPressConfig(uint8_t button, uint8_t function)
{
    const uint8_t payload[2] = {button, function};
    return Request(SET_BUTTON_PRESS_CONFIG, payload, sizeof(payload), nullptr, nullptr, 0);
}

uint16_t Client::GetLongButtonPressConfig(uint8_t button, uint8_t* function)
{
    if (function == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(GET_LONG_BUTTON_PRESS_CONFIG, &button, 1, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 1) {
        return status;
    }
    *function = data[0];
    return status;
}

uint16_t Client::SetLongButtonPressConfig(uint8_t button, uint8_t function)
{
    const uint8_t payload[2] = {button, function};
    return Request(SET_LONG_BUTTON_PRESS_CONFIG, payload, sizeof(payload), nullptr, nullptr, 0);
}

bool Client::SetSlotDataDefault(uint8_t slot, uint16_t tag_type)
{
    const uint8_t payload[3] = {slot, static_cast<uint8_t>(tag_type >> 8), static_cast<uint8_t>(tag_type)};
    return Request(SET_SLOT_DATA_DEFAULT, payload, sizeof(payload), nullptr, nullptr, 0) == SUCCESS;
}

bool Client::SlotDataConfigSave()
{
    return Request(SLOT_DATA_CONFIG_SAVE, nullptr, 0, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::DeleteSlotTagNick(uint8_t slot, TagSenseType sense)
{
    const uint8_t payload[2] = {slot, static_cast<uint8_t>(sense)};
    return Request(DELETE_SLOT_TAG_NICK, payload, sizeof(payload), nullptr, nullptr, 0) == SUCCESS;
}

bool Client::DeleteSlotSenseType(uint8_t slot, TagSenseType sense)
{
    const uint8_t payload[2] = {slot, static_cast<uint8_t>(sense)};
    return Request(DELETE_SLOT_SENSE_TYPE, payload, sizeof(payload), nullptr, nullptr, 0) == SUCCESS;
}

bool Client::WipeFds()
{
    return Request(WIPE_FDS, nullptr, 0, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::ResetSettings()
{
    return Request(RESET_SETTINGS, nullptr, 0, nullptr, nullptr, 0) == SUCCESS;
}

// ---------------------------------------------------------------------------
// Remaining LF commands
// ---------------------------------------------------------------------------

uint16_t Client::IoProxDecodeRaw(const uint8_t raw8[8], uint8_t out[16])
{
    if (raw8 == nullptr || out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(IOPROX_DECODE_RAW, raw8, 8, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 16) {
        return status;
    }
    memcpy(out, data, 16);
    return status;
}

uint16_t Client::IoProxComposeId(uint8_t version, uint8_t facility, uint16_t card_number, uint8_t out[16])
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    // chameleon_cmd.py packs ">BBH".
    const uint8_t payload[4] = {version, facility, static_cast<uint8_t>(card_number >> 8),
                                static_cast<uint8_t>(card_number)};
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(IOPROX_COMPOSE_ID, payload, sizeof(payload), &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 16) {
        return status;
    }
    memcpy(out, data, 16);
    return status;
}

uint16_t Client::T55xxWriteBlock(uint8_t block, uint32_t word, bool use_password, uint32_t password, bool page1)
{
    // app_cmd.c cmd_processor_lf_t55xx_write:
    //   block | word[4] big endian | use_pwd | pwd[4] big endian | page1
    const uint8_t payload[11] = {
        block,
        static_cast<uint8_t>(word >> 24),
        static_cast<uint8_t>(word >> 16),
        static_cast<uint8_t>(word >> 8),
        static_cast<uint8_t>(word),
        static_cast<uint8_t>(use_password ? 1 : 0),
        static_cast<uint8_t>(password >> 24),
        static_cast<uint8_t>(password >> 16),
        static_cast<uint8_t>(password >> 8),
        static_cast<uint8_t>(password),
        static_cast<uint8_t>(page1 ? 1 : 0),
    };
    return Request(LF_T55XX_WRITE, payload, sizeof(payload), nullptr, nullptr, 3000);
}

// ---------------------------------------------------------------------------
// HF14A raw / sniff / auth trace
// ---------------------------------------------------------------------------

uint16_t Client::Hf14aScanKeep(HfTag* out, size_t max_tags, size_t* count)
{
    if (out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(HF14A_SCAN_KEEP, nullptr, 0, &data, &len, 0);
    if (status != HF_TAG_OK || data == nullptr) {
        return status;
    }

    // Records: uidlen | uid | atqa[2] | sak | atslen | ats, repeated.
    size_t offset = 0;
    size_t n      = 0;
    while (offset < len && n < max_tags) {
        const uint8_t uid_len = data[offset++];
        if (uid_len > 10 || offset + uid_len + 4 > len) {
            break;
        }
        HfTag& tag = out[n];
        memcpy(tag.uid, data + offset, uid_len);
        tag.uid_length = uid_len;
        offset += uid_len;
        memcpy(tag.atqa, data + offset, 2);
        offset += 2;
        tag.sak = data[offset++];
        const uint8_t ats_len = data[offset++];
        if (ats_len > 0 && ats_len <= sizeof(tag.ats) && offset + ats_len <= len) {
            memcpy(tag.ats, data + offset, ats_len);
            tag.ats_length = ats_len;
        }
        offset += ats_len;
        ++n;
    }
    *count = n;
    return status;
}

size_t Client::DecodeTraceFrame(const uint8_t* buffer, size_t length, size_t offset, bool* from_card,
                                const uint8_t** frame, size_t* frame_bytes)
{
    if (buffer == nullptr || frame == nullptr || frame_bytes == nullptr || offset + 2 > length) {
        return 0;
    }

    // [bits_be16][data, ceil(bits/8)]; bit 15 of the header means card -> reader.
    const uint16_t header = ReadBe16(buffer + offset);
    const size_t bits     = header & 0x7FFF;
    const size_t bytes    = (bits + 7) / 8;
    if (offset + 2 + bytes > length) {
        return 0;
    }

    if (from_card != nullptr) {
        *from_card = (header & 0x8000) != 0;
    }
    *frame      = buffer + offset + 2;
    *frame_bytes = bytes;
    return 2 + bytes;
}

uint16_t Client::Hf14aRaw(const Hf14aRawOptions& options, uint16_t resp_timeout_ms, uint16_t bitlen,
                          const uint8_t* data, size_t data_length, uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out_length != nullptr) {
        *out_length = 0;
    }
    if (data_length > 0 && data == nullptr) {
        return PAR_ERR;
    }
    // The CLI defaults bitlen to len(data) * 8 and rejects a bitlen that cannot
    // fit the buffer, so mirror that instead of sending something inconsistent.
    if (bitlen == 0) {
        bitlen = static_cast<uint16_t>(data_length * 8);
    } else if (data_length == 0 || bitlen > data_length * 8 || bitlen <= (data_length - 1) * 8) {
        return PAR_ERR;
    }
    const size_t total = 1 + 2 + 2 + data_length;
    if (total > kMaxDataLength) {
        return PAR_ERR;
    }

    // ctypes BigEndianStructure bitfields, MSB first:
    // activate | wait | append_crc | auto_select | keep | check_crc | reserved(2)
    const uint8_t options_byte = static_cast<uint8_t>((options.activate_rf_field ? 0x80 : 0) |
                                                      (options.wait_response ? 0x40 : 0) |
                                                      (options.append_crc ? 0x20 : 0) |
                                                      (options.auto_select ? 0x10 : 0) |
                                                      (options.keep_rf_field ? 0x08 : 0) |
                                                      (options.check_response_crc ? 0x04 : 0));

    static uint8_t payload[kMaxDataLength];
    payload[0] = options_byte;
    payload[1] = static_cast<uint8_t>(resp_timeout_ms >> 8);
    payload[2] = static_cast<uint8_t>(resp_timeout_ms);
    payload[3] = static_cast<uint8_t>(bitlen >> 8);
    payload[4] = static_cast<uint8_t>(bitlen);
    if (data_length > 0) {
        memcpy(payload + 5, data, data_length);
    }

    const uint8_t* reply   = nullptr;
    size_t reply_len       = 0;
    const uint32_t timeout = static_cast<uint32_t>(resp_timeout_ms) + 1000;
    const uint16_t status  = Request(HF14A_RAW, payload, total, &reply, &reply_len, timeout);
    if (status != HF_TAG_OK || reply == nullptr) {
        return status;
    }
    if (out != nullptr && out_length != nullptr) {
        const size_t copy = (reply_len < out_size) ? reply_len : out_size;
        memcpy(out, reply, copy);
        *out_length = copy;
    }
    return status;
}

uint16_t Client::Hf14aSniff(uint16_t timeout_ms, uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    if (timeout_ms > 30000) {
        timeout_ms = 30000;
    }

    const uint8_t payload[2] = {static_cast<uint8_t>(timeout_ms >> 8), static_cast<uint8_t>(timeout_ms)};
    const uint8_t* data      = nullptr;
    size_t len               = 0;
    const uint32_t timeout   = static_cast<uint32_t>(timeout_ms) + 5000;
    const uint16_t status    = Request(HF14A_SNIFF, payload, sizeof(payload), &data, &len, timeout);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

uint16_t Client::Hf14aAuthTrace(uint8_t block, MfcKeyType key_type, const uint8_t key[6], uint16_t timeout_ms,
                                uint8_t* out, size_t out_size, size_t* out_length)
{
    if (key == nullptr || out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    if (timeout_ms > 30000) {
        timeout_ms = 30000;
    }

    // key_type | block | key[6] | timeout_ms (big endian)
    const uint8_t payload[10] = {
        static_cast<uint8_t>(key_type), block, key[0], key[1], key[2], key[3], key[4], key[5],
        static_cast<uint8_t>(timeout_ms >> 8), static_cast<uint8_t>(timeout_ms),
    };
    const uint8_t* data    = nullptr;
    size_t len             = 0;
    const uint32_t timeout = static_cast<uint32_t>(timeout_ms / 1000) + 3000;
    const uint16_t status  = Request(HF14A_AUTH_TRACE, payload, sizeof(payload), &data, &len, timeout);
    if (status != HF_TAG_OK || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

// ---------------------------------------------------------------------------
// MF1 nonce acquisition
// ---------------------------------------------------------------------------

uint16_t Client::Mf1DetectNtDist(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                                 uint32_t* uid, uint32_t* distance)
{
    if (key_known == nullptr || uid == nullptr || distance == nullptr) {
        return PAR_ERR;
    }
    // chameleon_cmd.py packs '!BB6s' = type, block, key.
    uint8_t payload[8];
    payload[0] = static_cast<uint8_t>(type_known);
    payload[1] = block_known;
    memcpy(payload + 2, key_known, 6);

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_DETECT_NT_DIST, payload, sizeof(payload), &data, &len, 0);
    if (status != HF_TAG_OK || data == nullptr || len < 8) {
        return status;
    }
    *uid      = ReadBe32(data);
    *distance = ReadBe32(data + 4);
    return status;
}

uint16_t Client::Mf1NestedAcquire(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                                  uint8_t block_target, MfcKeyType type_target, NestedNonce* out, size_t max,
                                  size_t* count)
{
    if (key_known == nullptr || out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    // '!BB6sBB' = type_known, block_known, key, type_target, block_target
    uint8_t payload[10];
    payload[0] = static_cast<uint8_t>(type_known);
    payload[1] = block_known;
    memcpy(payload + 2, key_known, 6);
    payload[8] = static_cast<uint8_t>(type_target);
    payload[9] = block_target;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_NESTED_ACQUIRE, payload, sizeof(payload), &data, &len, 5000);
    if (status != HF_TAG_OK || data == nullptr) {
        return status;
    }

    // Records of '!IIB' = nt, nt_enc, par (9 bytes each).
    size_t n = 0;
    for (size_t offset = 0; offset + 9 <= len && n < max; offset += 9) {
        out[n].nt     = ReadBe32(data + offset);
        out[n].nt_enc = ReadBe32(data + offset + 4);
        out[n].par    = data[offset + 8];
        ++n;
    }
    *count = n;
    return status;
}

uint16_t Client::Mf1StaticNestedAcquire(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                                        uint8_t block_target, MfcKeyType type_target, uint32_t* uid,
                                        StaticNestedNonce* out, size_t max, size_t* count)
{
    if (key_known == nullptr || out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    uint8_t payload[10];
    payload[0] = static_cast<uint8_t>(type_known);
    payload[1] = block_known;
    memcpy(payload + 2, key_known, 6);
    payload[8] = static_cast<uint8_t>(type_target);
    payload[9] = block_target;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_STATIC_NESTED_ACQUIRE, payload, sizeof(payload), &data, &len, 5000);
    if (status != HF_TAG_OK || data == nullptr || len < 4) {
        return status;
    }

    // uid[4] then records of '!II' = nt, nt_enc.
    if (uid != nullptr) {
        *uid = ReadBe32(data);
    }
    size_t n = 0;
    for (size_t offset = 4; offset + 8 <= len && n < max; offset += 8) {
        out[n].nt     = ReadBe32(data + offset);
        out[n].nt_enc = ReadBe32(data + offset + 4);
        ++n;
    }
    *count = n;
    return status;
}

uint16_t Client::Mf1HardNestedAcquire(bool slow, uint8_t block_known, MfcKeyType type_known,
                                      const uint8_t key_known[6], uint8_t block_target, MfcKeyType type_target,
                                      uint8_t* out, size_t out_size, size_t* out_length)
{
    if (key_known == nullptr || out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    // '!BBB6sBB' = slow, type_known, block_known, key, type_target, block_target
    uint8_t payload[11];
    payload[0] = slow ? 1 : 0;
    payload[1] = static_cast<uint8_t>(type_known);
    payload[2] = block_known;
    memcpy(payload + 3, key_known, 6);
    payload[9]  = static_cast<uint8_t>(type_target);
    payload[10] = block_target;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    // The CLI allows 30 s for this one.
    const uint16_t status = Request(MF1_HARDNESTED_ACQUIRE, payload, sizeof(payload), &data, &len, 30000);
    if (status != HF_TAG_OK || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

uint16_t Client::Mf1EncNestedAcquire(const uint8_t backdoor_key[6], uint8_t sector_count, uint8_t starting_sector,
                                     uint32_t* out, size_t max, size_t* count)
{
    if (backdoor_key == nullptr || out == nullptr || count == nullptr) {
        return PAR_ERR;
    }
    *count = 0;

    // '!6sBB'
    uint8_t payload[8];
    memcpy(payload, backdoor_key, 6);
    payload[6] = sector_count;
    payload[7] = starting_sector;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(MF1_ENC_NESTED_ACQUIRE, payload, sizeof(payload), &data, &len, 30000);
    if (status != HF_TAG_OK && status != HF_TAG_NO) {
        return status;
    }
    if (data == nullptr) {
        return status;
    }

    // The CLI unpacks a leading '!I' and leaves the rest to the host tool.
    size_t n = 0;
    for (size_t offset = 0; offset + 4 <= len && n < max; offset += 4) {
        out[n++] = ReadBe32(data + offset);
    }
    *count = n;
    return status;
}

uint16_t Client::Mf1ManipulateValueBlock(uint8_t src_block, MfcKeyType src_type, const uint8_t src_key[6], uint8_t op,
                                         int32_t operand, uint8_t dst_block, MfcKeyType dst_type,
                                         const uint8_t dst_key[6])
{
    if (src_key == nullptr || dst_key == nullptr) {
        return PAR_ERR;
    }
    // '!BB6sBiBB6s' = src_type, src_block, src_key, operator, operand(int32),
    //                 dst_type, dst_block, dst_key
    uint8_t payload[24];
    payload[0] = static_cast<uint8_t>(src_type);
    payload[1] = src_block;
    memcpy(payload + 2, src_key, 6);
    payload[8]  = op;
    payload[9]  = static_cast<uint8_t>((static_cast<uint32_t>(operand) >> 24) & 0xFF);
    payload[10] = static_cast<uint8_t>((static_cast<uint32_t>(operand) >> 16) & 0xFF);
    payload[11] = static_cast<uint8_t>((static_cast<uint32_t>(operand) >> 8) & 0xFF);
    payload[12] = static_cast<uint8_t>(static_cast<uint32_t>(operand) & 0xFF);
    payload[13] = static_cast<uint8_t>(dst_type);
    payload[14] = dst_block;
    memcpy(payload + 15, dst_key, 6);

    return Request(MF1_MANIPULATE_VALUE_BLOCK, payload, 21, nullptr, nullptr, 0);
}

// ---------------------------------------------------------------------------
// ISO14443-4 T=CL emulation
// ---------------------------------------------------------------------------

bool Client::Hf14a4SetAntiColl(const uint8_t* uid, uint8_t uid_length, const uint8_t atqa[2], uint8_t sak,
                               const uint8_t* ats, uint8_t ats_length)
{
    if (uid == nullptr || atqa == nullptr || uid_length == 0 || uid_length > 10 || ats_length > 32) {
        return false;
    }
    // chameleon_cmd.py builds uid_size | uid | atqa | sak | ats_len | ats
    uint8_t payload[1 + 10 + 2 + 1 + 1 + 32];
    size_t n = 0;
    payload[n++] = uid_length;
    memcpy(payload + n, uid, uid_length);
    n += uid_length;
    memcpy(payload + n, atqa, 2);
    n += 2;
    payload[n++] = sak;
    payload[n++] = ats_length;
    if (ats_length > 0 && ats != nullptr) {
        memcpy(payload + n, ats, ats_length);
        n += ats_length;
    }
    return Request(HF14A_4_SET_ANTI_COLL, payload, n, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::Hf14a4ApduSend(const uint8_t* response, size_t length)
{
    if (response == nullptr || length == 0 || length + 2 > kMaxDataLength) {
        return false;
    }
    static uint8_t payload[kMaxDataLength];
    payload[0] = static_cast<uint8_t>((length >> 8) & 0xFF);
    payload[1] = static_cast<uint8_t>(length & 0xFF);
    memcpy(payload + 2, response, length);
    return Request(HF14A_4_APDU_SEND, payload, length + 2, nullptr, nullptr, 0) == SUCCESS;
}

uint16_t Client::Hf14a4ApduRecv(uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(HF14A_4_APDU_RECV, nullptr, 0, &data, &len, 2000);
    if (data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

bool Client::Hf14a4AddStaticResponse(const uint8_t* command, size_t command_length, const uint8_t* response,
                                     size_t response_length)
{
    if (command == nullptr || response == nullptr || command_length == 0 || command_length > 255 ||
        response_length > 4096 || command_length + response_length + 3 > kMaxDataLength) {
        return false;
    }
    // cmd_len | cmd | resp_len_be16 | resp
    static uint8_t payload[kMaxDataLength];
    payload[0] = static_cast<uint8_t>(command_length);
    memcpy(payload + 1, command, command_length);
    payload[1 + command_length]     = static_cast<uint8_t>((response_length >> 8) & 0xFF);
    payload[1 + command_length + 1] = static_cast<uint8_t>(response_length & 0xFF);
    memcpy(payload + 3 + command_length, response, response_length);
    return Request(HF14A_4_STATIC_RESP, payload, 3 + command_length + response_length, nullptr, nullptr, 0) == SUCCESS;
}

bool Client::Hf14a4ClearStaticResponses()
{
    const uint8_t payload = 0x00;
    return Request(HF14A_4_STATIC_RESP, &payload, 1, nullptr, nullptr, 0) == SUCCESS;
}

uint16_t Client::Hf14a4ReaderApdu(const uint8_t* apdu, size_t length, uint8_t* out, size_t out_size,
                                  size_t* out_length)
{
    if (apdu == nullptr || length == 0 || out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(HF14A_4_READER_APDU, apdu, length, &data, &len, 3000);
    if (data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

// ---------------------------------------------------------------------------
// HF14A configuration, EMV scan and bootloader entry
// ---------------------------------------------------------------------------

uint16_t Client::GetHf14aConfig(Hf14aConfig* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(HF14A_GET_CONFIG, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr || len < 4) {
        return status;
    }
    // chameleon_cmd.py unpacks '!bbbb' - four SIGNED bytes.
    out->bcc  = static_cast<int8_t>(data[0]);
    out->cl2  = static_cast<int8_t>(data[1]);
    out->cl3  = static_cast<int8_t>(data[2]);
    out->rats = static_cast<int8_t>(data[3]);
    return status;
}

uint16_t Client::SetHf14aConfig(const Hf14aConfig& in)
{
    const uint8_t payload[4] = {static_cast<uint8_t>(in.bcc), static_cast<uint8_t>(in.cl2),
                                static_cast<uint8_t>(in.cl3), static_cast<uint8_t>(in.rats)};
    return Request(HF14A_SET_CONFIG, payload, sizeof(payload), nullptr, nullptr, 0);
}

uint16_t Client::Hf14a4EmvScan(EmvScanResult* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    *out = EmvScanResult{};

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    // The CLI allows 10 s for the whole sequence.
    const uint16_t status = Request(HF14A_4_EMV_SCAN, nullptr, 0, &data, &len, 10000);
    if (status != HF_TAG_OK || data == nullptr || len < 5) {
        return status;
    }

    // uid_len | uid | atqa[2] | sak | ats_len | ats | num_apdus | pairs...
    size_t offset         = 0;
    const uint8_t uid_len = data[offset++];
    if (uid_len > 10 || offset + uid_len + 4 > len) {
        return HF_ERR_STAT;
    }
    memcpy(out->tag.uid, data + offset, uid_len);
    out->tag.uid_length = uid_len;
    offset += uid_len;
    memcpy(out->tag.atqa, data + offset, 2);
    offset += 2;
    out->tag.sak = data[offset++];
    const uint8_t ats_len = data[offset++];
    if (offset + ats_len > len) {
        return HF_ERR_STAT;
    }
    if (ats_len > 0 && ats_len <= sizeof(out->tag.ats)) {
        memcpy(out->tag.ats, data + offset, ats_len);
        out->tag.ats_length = ats_len;
    }
    offset += ats_len;

    if (offset >= len) {
        return status;
    }
    const uint8_t num_apdus = data[offset++];

    for (uint8_t i = 0; i < num_apdus && out->apdu_count < 16; ++i) {
        if (offset >= len) {
            break;
        }
        const uint8_t cmd_len = data[offset++];
        if (offset + cmd_len + 2 > len) {
            break;
        }
        EmvApdu& pair = out->apdus[out->apdu_count];
        if (cmd_len > sizeof(pair.command)) {
            break;
        }
        memcpy(pair.command, data + offset, cmd_len);
        pair.command_length = cmd_len;
        offset += cmd_len;

        // The response length is LITTLE endian here, unlike the rest of the protocol.
        const uint16_t resp_len = static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8));
        offset += 2;
        if (offset + resp_len > len || resp_len > sizeof(pair.response)) {
            break;
        }
        memcpy(pair.response, data + offset, resp_len);
        pair.response_length = resp_len;
        offset += resp_len;
        ++out->apdu_count;
    }
    return status;
}

void Client::EnterBootloader()
{
    // The device reboots into DFU and stops answering, so this is send-only:
    // waiting for a response would just burn the request timeout.
    const uint8_t* data = nullptr;
    size_t len          = 0;
    (void)Request(ENTER_BOOTLOADER, nullptr, 0, &data, &len, 200);
}

// ---------------------------------------------------------------------------
// SEOS
// ---------------------------------------------------------------------------

uint16_t Client::SeosReadEmuData(SeosEmuData* out)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    *out = SeosEmuData{};

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(SEOS_READ_EMU_DATA, nullptr, 0, &data, &len, 0);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }

    // Four length prefixed fields, then two algorithm bytes.
    // chameleon_cmd.py consumes them in this order, so an out of range length
    // means a malformed reply rather than something to clamp silently.
    size_t offset = 0;
    struct Target {
        uint8_t* bytes;
        uint8_t* length;
        size_t capacity;
    };
    const Target targets[4] = {
        {out->data, &out->data_length, sizeof(out->data)},
        {out->oid, &out->oid_length, sizeof(out->oid)},
        {out->tag, &out->tag_length, sizeof(out->tag)},
        {out->diversifier, &out->diversifier_length, sizeof(out->diversifier)},
    };
    for (const Target& target : targets) {
        if (offset >= len) {
            return HF_ERR_STAT;
        }
        const size_t field_len = data[offset++];
        if (offset + field_len > len || field_len > target.capacity) {
            return HF_ERR_STAT;
        }
        memcpy(target.bytes, data + offset, field_len);
        *target.length = static_cast<uint8_t>(field_len);
        offset += field_len;
    }
    if (offset + 2 > len) {
        return HF_ERR_STAT;
    }
    out->hash_alg = data[offset];
    out->encr_alg = data[offset + 1];
    return status;
}

uint16_t Client::SeosWriteEmuData(const SeosEmuData& in)
{
    const size_t total = 4 + in.data_length + in.oid_length + in.tag_length + in.diversifier_length + 2;
    if (total > kMaxDataLength) {
        return PAR_ERR;
    }

    static uint8_t payload[kMaxDataLength];
    size_t n = 0;
    auto put = [&payload, &n](const uint8_t* bytes, uint8_t length) {
        payload[n++] = length;
        if (length > 0) {
            memcpy(payload + n, bytes, length);
            n += length;
        }
    };
    put(in.data, in.data_length);
    put(in.oid, in.oid_length);
    put(in.tag, in.tag_length);
    put(in.diversifier, in.diversifier_length);
    payload[n++] = in.hash_alg;
    payload[n++] = in.encr_alg;

    return Request(SEOS_WRITE_EMU_DATA, payload, n, nullptr, nullptr, 0);
}

uint16_t Client::SeosWriteEmuKeys(const uint8_t* auth, size_t auth_length, const uint8_t* privenc,
                                  size_t privenc_length, const uint8_t* privmac, size_t privmac_length)
{
    if (auth == nullptr || privenc == nullptr || privmac == nullptr) {
        return PAR_ERR;
    }
    const size_t total = auth_length + privenc_length + privmac_length;
    if (total == 0 || total > kMaxDataLength) {
        return PAR_ERR;
    }

    static uint8_t payload[kMaxDataLength];
    memcpy(payload, auth, auth_length);
    memcpy(payload + auth_length, privenc, privenc_length);
    memcpy(payload + auth_length + privenc_length, privmac, privmac_length);

    return Request(SEOS_WRITE_EMU_KEYS, payload, total, nullptr, nullptr, 0);
}

// ---------------------------------------------------------------------------
// Generic LF card operations
//
// Every *_SCAN / *_WRITE_TO_T55XX command in this family has the same payload
// shape, so one pair of helpers covers HIDProx, ioProx, PAC, Viking, Jablotron
// and IDTECK instead of six near-identical methods.
// ---------------------------------------------------------------------------

namespace {

/// Password the tag is left with after a write.
/// Taken verbatim from chameleon_cmd.py: `new_key = b'\x20\x20\x66\x66'`.
constexpr uint8_t kT55xxNewKey[4] = {0x20, 0x20, 0x66, 0x66};

/// Passwords tried in order when unlocking a tag that is not already on
/// kT55xxNewKey. Taken verbatim from chameleon_cmd.py:
/// `old_keys = [b'\x51\x24\x36\x48', b'\x19\x92\x04\x27']`.
constexpr uint8_t kT55xxOldKeys[2][4] = {
    {0x51, 0x24, 0x36, 0x48},
    {0x19, 0x92, 0x04, 0x27},
};

}  // namespace

uint16_t Client::ScanLfCommand(uint16_t cmd, LfResult* out, const uint8_t* payload, size_t payload_len)
{
    if (out == nullptr) {
        return PAR_ERR;
    }
    out->length = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    // The firmware's read timeout is 500 ms per protocol; 4 s leaves room for
    // the retry a reader performs before giving up.
    const uint16_t status = Request(cmd, payload, payload_len, &data, &len, 4000);
    if (status != LF_TAG_OK || data == nullptr) {
        return status;
    }

    const size_t copy = (len < sizeof(out->data)) ? len : sizeof(out->data);
    memcpy(out->data, data, copy);
    out->length = copy;
    return status;
}

uint16_t Client::WriteT55xx(uint16_t cmd, const uint8_t* id, size_t id_length)
{
    if (id == nullptr || id_length == 0 || id_length > 16) {
        return PAR_ERR;
    }

    // id | new_key[4] | old_keys[2][4]
    uint8_t payload[16 + 4 + sizeof(kT55xxOldKeys)];
    memset(payload, 0, sizeof(payload));
    size_t n = 0;
    memcpy(payload + n, id, id_length);
    n += id_length;
    memcpy(payload + n, kT55xxNewKey, sizeof(kT55xxNewKey));
    n += sizeof(kT55xxNewKey);

    memcpy(payload + n, kT55xxOldKeys, sizeof(kT55xxOldKeys));
    n += sizeof(kT55xxOldKeys);

    return Request(cmd, payload, n, nullptr, nullptr, 3000);
}

uint16_t Client::AdcGenericRead(uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(ADC_GENERIC_READ, nullptr, 0, &data, &len, 0);
    if (status != LF_TAG_OK || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

uint16_t Client::LfSniff(uint16_t timeout_ms, uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    if (timeout_ms > 10000) {
        timeout_ms = 10000;
    }

    const uint8_t payload[2] = {static_cast<uint8_t>(timeout_ms >> 8), static_cast<uint8_t>(timeout_ms & 0xFF)};
    const uint8_t* data      = nullptr;
    size_t len               = 0;
    // The capture takes as long as the caller asked for, plus link overhead.
    const uint32_t timeout   = static_cast<uint32_t>(timeout_ms) + 2000;

    const uint16_t status = Request(LF_SNIFF, payload, sizeof(payload), &data, &len, timeout);
    if (status != SUCCESS || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

uint16_t Client::Em4x05Scan(uint32_t password, uint8_t* out, size_t out_size, size_t* out_length)
{
    if (out == nullptr || out_length == nullptr) {
        return PAR_ERR;
    }
    *out_length = 0;

    const uint8_t payload[4] = {
        static_cast<uint8_t>(password >> 24), static_cast<uint8_t>(password >> 16),
        static_cast<uint8_t>(password >> 8), static_cast<uint8_t>(password & 0xFF),
    };

    const uint8_t* data   = nullptr;
    size_t len            = 0;
    const uint16_t status = Request(EM4X05_SCAN, payload, sizeof(payload), &data, &len, 4000);
    if (status != LF_TAG_OK || data == nullptr) {
        return status;
    }
    const size_t copy = (len < out_size) ? len : out_size;
    memcpy(out, data, copy);
    *out_length = copy;
    return status;
}

bool Client::GetActiveSlotNick(char* out, size_t out_size)
{
    const uint8_t slot = _active_slot;
    // The active slot's HF nick is the useful one for the UI; fall back to LF.
    if (GetSlotNick(slot, TagSenseType::HF, out, out_size)) {
        return out[0] != '\0';
    }
    return GetSlotNick(slot, TagSenseType::LF, out, out_size);
}

}  // namespace chameleon
