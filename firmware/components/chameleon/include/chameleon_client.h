// SPDX-License-Identifier: MIT
//
// Chameleon Ultra session layer.
//
// Embedded equivalent of software/script/chameleon_com.py (transport framing,
// request/response correlation, timeouts) combined with the parts of
// chameleon_cmd.py that this device needs. Deliberately dependency free: the
// USB CDC host driver feeds bytes in, frames come out, one request is in flight
// at a time.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "chameleon_commands.h"
#include "chameleon_protocol.h"

namespace chameleon {

/// Device information returned by the system commands.
struct DeviceInfo {
    uint8_t app_version_major = 0;
    uint8_t app_version_minor = 0;
    uint8_t git_version[8]    = {};
    uint16_t chip_id[4]       = {};
    uint8_t device_address[6] = {};
    uint16_t device_model     = 0;
    uint32_t capabilities     = 0;
    bool valid                = false;
};

/// Battery information (GET_BATTERY_INFO).
struct BatteryInfo {
    uint16_t voltage_mv   = 0;
    uint8_t percentage    = 0;
    bool charging         = false;
    bool valid            = false;
};

/// Per-slot information from GET_SLOT_INFO.
struct SlotInfo {
    bool enabled_lf = false;
    bool enabled_hf = false;
    uint16_t lf_tag_type = 0;
    uint16_t hf_tag_type = 0;
};

/// One line of human readable traffic for the UI log.
struct LogLine {
    bool tx     = false;   ///< true for host -> device
    uint16_t cmd       = 0;
    uint16_t status    = 0;
    size_t data_length = 0;
};

/// Mifare Classic key type, as used in the auth/read/write payloads.
enum class MfcKeyType : uint8_t {
    A = 0x60,
    B = 0x61,
};

/// One ISO14443-A card found by HF14A_SCAN.
struct HfTag {
    uint8_t uid[10] = {};
    uint8_t uid_length = 0;
    uint8_t atqa[2]    = {};
    uint8_t sak        = 0;
    uint8_t ats[32]    = {};
    uint8_t ats_length = 0;
};

/// One LF card found by EM410X_SCAN.
struct LfTag {
    uint16_t tag_type  = 0;   ///< EM410X or EM410X_ELECTRA
    uint8_t id[13]     = {};  ///< 5 bytes for EM410X, 13 for Electra
    uint8_t id_length  = 0;
};

/// Callbacks used to push state changes into the UI / console.
struct ClientCallbacks {
    /// Transport attached / detached.
    void (*on_connection)(bool connected, void* user) = nullptr;
    /// One line of protocol traffic.
    void (*on_log)(const LogLine& line, void* user) = nullptr;
    /// Free-form status text (device model, errors, ...).
    void (*on_status)(const char* text, void* user) = nullptr;
    void* user = nullptr;
};

/**
 * @brief Chameleon session.
 *
 * Lifecycle: Construct, SetTransport(), SetCallbacks(), then feed received
 * bytes with OnTransportData() and signal link changes with
 * OnTransportState(). Request helpers are blocking with an explicit timeout and
 * must not be called from the transport receive callback.
 */
class Client {
public:
    /// Timeout used when a caller does not specify one.
    static constexpr uint32_t kDefaultTimeoutMs = 2000;

    /// Writes one complete frame to the transport. Returns false on failure.
    using SendFn = bool (*)(const uint8_t* frame, size_t len, void* user);

    Client() = default;
    ~Client() = default;

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    /**
     * @brief Bind the transport write path.
     *
     * Must be set before OnTransportState(true).
     */
    void SetTransport(SendFn send, void* user)
    {
        _send      = send;
        _send_user = user;
    }

    void SetCallbacks(const ClientCallbacks& callbacks)
    {
        _callbacks = callbacks;
    }

    /**
     * @brief Notify the session that the transport attached or detached.
     *
     * On attach the device is queried for its version, model and capabilities.
     */
    void OnTransportState(bool connected);

    /**
     * @brief Feed received transport bytes into the frame parser.
     *
     * Safe to call from the USB receive callback.
     */
    void OnTransportData(const uint8_t* data, size_t len);

    /**
     * @brief Send a command and wait for its response.
     *
     * @param cmd          command id
     * @param data         request payload, may be null
     * @param data_len     payload length, 0 when data is null
     * @param response     receives a pointer to the response payload
     * @param response_len receives the response payload length
     * @param timeout_ms   0 selects kDefaultTimeoutMs
     * @return uint16_t    status code, or 0xFFFF on transport error / timeout
     */
    uint16_t Request(uint16_t cmd, const uint8_t* data, size_t data_len, const uint8_t** response, size_t* response_len,
                     uint32_t timeout_ms = 0);

    /// Convenience overload for commands with no payload.
    uint16_t Request(uint16_t cmd, uint16_t* status_out = nullptr);

    bool IsConnected() const
    {
        return _connected;
    }

    const DeviceInfo& deviceInfo() const
    {
        return _device_info;
    }

    const BatteryInfo& batteryInfo() const
    {
        return _battery_info;
    }

    uint8_t activeSlot() const
    {
        return _active_slot;
    }

    const SlotInfo& slotInfo(int index) const
    {
        return _slot_info[index];
    }

    /// Number of frames rejected because of a framing / checksum error.
    uint32_t framingErrors() const
    {
        return _parser.errorCount();
    }

    // ---- typed commands -------------------------------------------------

    /// GET_APP_VERSION. Fills deviceInfo().
    bool FetchAppVersion();

    /// GET_DEVICE_MODEL, GET_DEVICE_CAPABILITIES, GET_DEVICE_CHIP_ID.
    bool FetchDeviceIdentity();

    /// GET_BATTERY_INFO.
    bool FetchBattery();

    /// GET_ACTIVE_SLOT.
    bool FetchActiveSlot();

    /// GET_SLOT_INFO.
    bool FetchSlotInfo();

    /**
     * @brief SET_ACTIVE_SLOT.
     * @param slot 0 based slot index (the wire protocol uses 0..7)
     */
    bool SetActiveSlot(uint8_t slot);

    /**
     * @brief SET_SLOT_ENABLE.
     */
    bool SetSlotEnabled(uint8_t slot, TagSenseType sense, bool enabled);

    /**
     * @brief SET_SLOT_TAG_TYPE.
     */
    bool SetSlotTagType(uint8_t slot, TagSenseType sense, uint16_t tag_type);

    /**
     * @brief SET_SLOT_TAG_NICK.
     */
    bool SetSlotNick(uint8_t slot, TagSenseType sense, const char* nick);

    /**
     * @brief GET_SLOT_TAG_NICK into a caller provided buffer.
     */
    bool GetSlotNick(uint8_t slot, TagSenseType sense, char* out, size_t out_size);

    /// GET_SLEEP_TIMEOUT / SET_SLEEP_TIMEOUT.
    bool GetSleepTimeout(uint32_t* seconds);
    bool SetSleepTimeout(uint32_t seconds);

    /// GET_ANIMATION_MODE / SET_ANIMATION_MODE.
    bool GetAnimationMode(uint8_t* mode);
    bool SetAnimationMode(uint8_t mode);

    /// SAVE_SETTINGS.
    bool SaveSettings();

    /// CHANGE_DEVICE_MODE (0 = tag/emulator, 1 = reader).
    bool ChangeDeviceMode(uint8_t mode);

    /// GET_DEVICE_MODE.
    bool FetchDeviceMode(uint8_t* mode);

    // ---- card operations (M3) -------------------------------------------

    /**
     * @brief HF14A_SCAN: look for ISO14443-A cards in the field.
     *
     * @param out          receives the found tags
     * @param max_tags     capacity of out
     * @param count        receives the number of tags written
     * @return uint16_t    status code (HF_TAG_OK on success)
     */
    uint16_t ScanHf(HfTag* out, size_t max_tags, size_t* count);

    /**
     * @brief EM410X_SCAN: read an EM410X / Electra card number.
     *
     * @return uint16_t  status code (LF_TAG_OK on success)
     */
    uint16_t ScanEm410x(LfTag* out);

    /**
     * @brief MF1_READ_ONE_BLOCK: read one 16 byte Mifare Classic block.
     *
     * @param block    absolute block number
     * @param key_type key A or B
     * @param key      6 byte key
     * @param out      receives 16 bytes
     */
    uint16_t ReadMifareBlock(uint8_t block, MfcKeyType key_type, const uint8_t key[6], uint8_t out[16]);

    /**
     * @brief MF1_WRITE_ONE_BLOCK: write one 16 byte Mifare Classic block.
     */
    uint16_t WriteMifareBlock(uint8_t block, MfcKeyType key_type, const uint8_t key[6], const uint8_t data[16]);

    /**
     * @brief MF1_AUTH_ONE_KEY_BLOCK: verify a key against one block's sector.
     */
    uint16_t AuthMifareKey(uint8_t block, MfcKeyType key_type, const uint8_t key[6]);

    // ---- key recovery ----------------------------------------------------

    /// Result codes of the device's darkside collection (MifareClassicDarksideStatus).
    enum class DarksideStatus : uint8_t {
        Ok          = 0,  ///< material collected, use the payload
        CantFixNt   = 1,  ///< tag PRNG is not predictable
        LuckyAuthOk = 2,  ///< a default key already worked, nothing to recover
        NoNakSent   = 3,  ///< tag never answered with NACK
        TagChanged  = 4,  ///< the card left the field mid attack
    };

    /// One MF1_DARKSIDE_ACQUIRE payload.
    struct DarksideResult {
        DarksideStatus status = DarksideStatus::CantFixNt;
        uint32_t uid          = 0;
        uint32_t nt           = 0;
        uint64_t par          = 0;  ///< 8 packed parity bytes
        uint64_t ks           = 0;  ///< 8 packed keystream nibbles
        uint32_t nr           = 0;
        uint32_t ar           = 0;
        bool valid            = false;  ///< true when status == Ok and every field is present
    };

    /// Human readable text for a DarksideStatus.
    static const char* DarksideStatusText(DarksideStatus status);

    /**
     * @brief MF1_DARKSIDE_ACQUIRE: collect the material for one attack attempt.
     *
     * @param block         target block
     * @param key_type      key A or B
     * @param first_recover true on the first attempt (the device then tries the
     *                      default keys as well, which is what the flag is for)
     * @param sync_max      device side attempt budget; scales the timeout
     */
    uint16_t DarksideAcquire(uint8_t block, MfcKeyType key_type, bool first_recover, uint8_t sync_max,
                             DarksideResult* out);

    /// Number of sectors the key check command covers.
    static constexpr size_t kMfcSectorCount = 40;

    /**
     * @brief MF1_CHECK_KEYS_OF_SECTORS: try a key list against every sector.
     *
     * @param mask        10 byte bitmap, bit set = that sector's key is checked
     * @param keys        6 byte keys, 1..83 of them
     * @param key_count   number of keys
     * @param found       receives the 10 byte result bitmap
     * @param sector_keys receives the key found per sector, may be null
     * @param out_length  receives the raw response length (0 when all masked out)
     */
    uint16_t CheckKeysOfSectors(const uint8_t mask[10], const uint8_t* keys, size_t key_count, uint8_t found[10],
                                uint8_t (*sector_keys)[6], size_t* out_length);

    /**
     * @brief MF1_CHECK_KEYS_ON_BLOCK: try a key list against one block.
     *
     * @param out receives a pointer to the response payload, owned by the client
     */
    uint16_t CheckKeysOnBlock(uint8_t block, MfcKeyType key_type, const uint8_t* keys, size_t key_count,
                              const uint8_t** out, size_t* out_length);

    // ---- remaining system commands ---------------------------------------

    /// GET_DEVICE_SETTINGS: one struct with every persisted setting.
    struct DeviceSettings {
        uint8_t version        = 0;
        uint8_t animation_mode = 0;
        uint8_t button_press_a = 0;
        uint8_t button_press_b = 0;
        uint8_t button_long_press_a = 0;
        uint8_t button_long_press_b = 0;
        uint8_t ble_pairing_enable  = 0;  ///< reported, but the BLE transport itself is out of scope
        uint8_t ble_pairing_key[6]  = {};
        uint8_t sleep_timeout       = 0;  ///< seconds
    };

    uint16_t GetDeviceSettings(DeviceSettings* out);

    /// GET_DEVICE_CAPABILITIES: a list of uint16 capability ids.
    uint16_t GetDeviceCapabilities(uint16_t* out, size_t max, size_t* count);

    /// GET_ENABLED_SLOTS: one {hf, lf} byte pair per slot.
    struct EnabledSlot {
        uint8_t hf = 0;
        uint8_t lf = 0;
    };

    uint16_t GetEnabledSlots(EnabledSlot* out, size_t max, size_t* count);

    /// GET_ALL_SLOT_NICKS: the nickname of every slot, per sense type.
    struct SlotNicks {
        char hf[32] = {};
        char lf[32] = {};
    };

    uint16_t GetAllSlotNicks(SlotNicks* out, size_t max, size_t* count);

    /**
     * @brief GET/SET_BUTTON_PRESS_CONFIG and the long press variant.
     *
     * @param button ASCII 'A' or 'B' (0x41 / 0x42). The device validates the
     *               byte with is_settings_button_type_valid(), which accepts the
     *               characters 'a'/'b'/'A'/'B' and nothing else - passing 0/1 is
     *               answered with PAR_ERR.
     */
    uint16_t GetButtonPressConfig(uint8_t button, uint8_t* function);
    uint16_t SetButtonPressConfig(uint8_t button, uint8_t function);
    uint16_t GetLongButtonPressConfig(uint8_t button, uint8_t* function);
    uint16_t SetLongButtonPressConfig(uint8_t button, uint8_t function);

    /// Button ids for the four calls above.
    static constexpr uint8_t kButtonA = 'A';
    static constexpr uint8_t kButtonB = 'B';

    /**
     * @brief MF1_SET_WRITE_MODE accepts 0..3 only.
     *
     * app_cmd.c rejects anything above 3 with PAR_ERR, even though
     * chameleon_commands.h lists five MfcWriteMode values and
     * MF1_GET_WRITE_MODE has been observed to answer 31 - the getter and the
     * setter disagree upstream, so the UI treats the read-back as a raw byte and
     * only ever writes 0..3.
     */
    static constexpr uint8_t kMf1WriteModeCount = 4;

    /// SET_SLOT_DATA_DEFAULT: reset a slot's stored data to the type's default.
    bool SetSlotDataDefault(uint8_t slot, uint16_t tag_type);

    /// SLOT_DATA_CONFIG_SAVE: commit slot configuration and data to flash.
    bool SlotDataConfigSave();

    /// DELETE_SLOT_TAG_NICK / DELETE_SLOT_SENSE_TYPE.
    bool DeleteSlotTagNick(uint8_t slot, TagSenseType sense);
    bool DeleteSlotSenseType(uint8_t slot, TagSenseType sense);

    /// WIPE_FDS: clear the flash data store (resets every slot and setting).
    bool WipeFds();

    /// RESET_SETTINGS.
    bool ResetSettings();

    // ---- remaining LF commands -------------------------------------------

    /**
     * @brief IOPROX_DECODE_RAW: raw 8 bytes -> the 16 byte ioProx card_data.
     *
     * Lets the UI build an ioProx id from its raw bitstream, which is the form
     * most people have (from another tool) rather than ver/fc/cn.
     */
    uint16_t IoProxDecodeRaw(const uint8_t raw8[8], uint8_t out[16]);

    /// IOPROX_COMPOSE_ID: ver/fc/cn -> the same 16 byte card_data.
    uint16_t IoProxComposeId(uint8_t version, uint8_t facility, uint16_t card_number, uint8_t out[16]);

    /**
     * @brief LF_T55XX_WRITE: write one raw 32 bit word to a T55xx block.
     *
     * This is the low level escape hatch next to the *_WRITE_TO_T55XX helpers:
     * the payload is block | word(4, big endian) | use_pwd | pwd(4) | page1.
     */
    uint16_t T55xxWriteBlock(uint8_t block, uint32_t word, bool use_password, uint32_t password, bool page1);

    /// EM4X05_READSNIFF is deliberately absent: the command id exists upstream
    /// but app_cmd.c has no handler for it (grep DATA_CMD_EM4X05_READSNIFF in the
    /// dispatch table) and chameleon_cmd.py has no method either, so there is
    /// nothing a client could call. EM4x05 reading goes through Em4x05Scan().

    // ---- HF14A raw / sniff / auth trace ----------------------------------

    /**
     * @brief HF14A_SCAN_KEEP: scan and leave the RF field on.
     *
     * The card stays powered in ISO14443-4 state so following Hf14aRaw() calls
     * can exchange APDUs without re-selecting.
     */
    uint16_t Hf14aScanKeep(HfTag* out, size_t max_tags, size_t* count);

    /// Bitfield for HF14A_RAW, matching the CLI's ctypes structure.
    struct Hf14aRawOptions {
        bool activate_rf_field  = true;
        bool wait_response      = true;
        bool append_crc         = false;
        bool auto_select        = false;
        bool keep_rf_field      = false;
        bool check_response_crc = false;
    };

    /**
     * @brief HF14A_RAW: send raw bytes to a 14A tag.
     *
     * Payload is options[1] | resp_timeout_ms(2) | bitlen(2) | data, exactly the
     * CLI's `bytes(cs) + struct.pack('!HH{n}s', ...)`.
     *
     * @param bitlen bits to send, 0 means "all of data"
     */
    uint16_t Hf14aRaw(const Hf14aRawOptions& options, uint16_t resp_timeout_ms, uint16_t bitlen, const uint8_t* data,
                      size_t data_length, uint8_t* out, size_t out_size, size_t* out_length);

    /**
     * @brief HF14A_SNIFF: capture reader frames while the slot emulates a tag.
     *
     * The reply is a packed frame list: [bits_be16][data, ceil(bits/8)] repeated,
     * with bit 15 of the header set for card->reader. Decoding it is the caller's
     * job (see docs: the CLI hands the same buffer to its log decoder).
     */
    uint16_t Hf14aSniff(uint16_t timeout_ms, uint8_t* out, size_t out_size, size_t* out_length);

    /**
     * @brief HF14A_AUTH_TRACE: run a full Crypto1 authentication and return the frames.
     *
     * Same packed frame format as Hf14aSniff. This is the device's only way to
     * hand out (nt, nr_enc, ar_enc), and it requires the sector key up front -
     * which is why mfkey32 still needed sniffing rather than this command.
     */
    uint16_t Hf14aAuthTrace(uint8_t block, MfcKeyType key_type, const uint8_t key[6], uint16_t timeout_ms,
                            uint8_t* out, size_t out_size, size_t* out_length);

    /// Decode one frame from a sniff / auth-trace buffer.
    /// @return bytes consumed, or 0 when the buffer is exhausted / malformed
    static size_t DecodeTraceFrame(const uint8_t* buffer, size_t length, size_t offset, bool* from_card,
                                   const uint8_t** frame, size_t* frame_bytes);

    // ---- MF1 nonce acquisition (feeds the nested attacks) -----------------

    /// MF1_DETECT_NT_DIST: how far apart the card's nonces are.
    uint16_t Mf1DetectNtDist(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6], uint32_t* uid,
                             uint32_t* distance);

    /// One {nt, nt_enc, par} triple from MF1_NESTED_ACQUIRE.
    struct NestedNonce {
        uint32_t nt     = 0;
        uint32_t nt_enc = 0;
        uint8_t par     = 0;
    };

    /// MF1_NESTED_ACQUIRE: collect the nonces the nested attack needs.
    uint16_t Mf1NestedAcquire(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                              uint8_t block_target, MfcKeyType type_target, NestedNonce* out, size_t max,
                              size_t* count);

    /// One {nt, nt_enc} pair from MF1_STATIC_NESTED_ACQUIRE.
    struct StaticNestedNonce {
        uint32_t nt     = 0;
        uint32_t nt_enc = 0;
    };

    /// MF1_STATIC_NESTED_ACQUIRE: collect nonces plus the card uid.
    uint16_t Mf1StaticNestedAcquire(uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                                    uint8_t block_target, MfcKeyType type_target, uint32_t* uid,
                                    StaticNestedNonce* out, size_t max, size_t* count);

    /**
     * @brief MF1_HARDNESTED_ACQUIRE: collect the nonce list for the hardnested attack.
     *
     * @param slow true for the slow (more thorough) acquisition
     * @param out  receives the raw nonce bytes; the device decides the layout
     */
    uint16_t Mf1HardNestedAcquire(bool slow, uint8_t block_known, MfcKeyType type_known, const uint8_t key_known[6],
                                  uint8_t block_target, MfcKeyType type_target, uint8_t* out, size_t out_size,
                                  size_t* out_length);

    /// MF1_ENC_NESTED_ACQUIRE: static encrypted nested against an unlocked backdoor.
    uint16_t Mf1EncNestedAcquire(const uint8_t backdoor_key[6], uint8_t sector_count, uint8_t starting_sector,
                                 uint32_t* out, size_t max, size_t* count);

    /// MF1_MANIPULATE_VALUE_BLOCK: increment / decrement / restore a value block.
    uint16_t Mf1ManipulateValueBlock(uint8_t src_block, MfcKeyType src_type, const uint8_t src_key[6], uint8_t op,
                                     int32_t operand, uint8_t dst_block, MfcKeyType dst_type,
                                     const uint8_t dst_key[6]);

    // ---- ISO14443-4 T=CL emulation ----------------------------------------

    /// HF14A_4_SET_ANTI_COLL: identity of the active T=CL slot.
    bool Hf14a4SetAntiColl(const uint8_t* uid, uint8_t uid_length, const uint8_t atqa[2], uint8_t sak,
                           const uint8_t* ats, uint8_t ats_length);

    /// HF14A_4_APDU_SEND: queue one response the emulated card will send.
    bool Hf14a4ApduSend(const uint8_t* response, size_t length);

    /// HF14A_4_APDU_RECV: fetch the next APDU a reader sent.
    uint16_t Hf14a4ApduRecv(uint8_t* out, size_t out_size, size_t* out_length);

    /// HF14A_4_STATIC_RESP: answer any APDU starting with `command` with `response`.
    bool Hf14a4AddStaticResponse(const uint8_t* command, size_t command_length, const uint8_t* response,
                                 size_t response_length);

    /// HF14A_4_STATIC_RESP with a single 0x00 byte clears the table.
    bool Hf14a4ClearStaticResponses();

    /// HF14A_4_READER_APDU: select a card and send one APDU without an USB gap.
    uint16_t Hf14a4ReaderApdu(const uint8_t* apdu, size_t length, uint8_t* out, size_t out_size, size_t* out_length);

    /// One command/response pair from an EMV scan.
    struct EmvApdu {
        uint8_t command[64] = {};
        uint8_t command_length = 0;
        uint8_t response[256]  = {};
        uint16_t response_length = 0;
    };

    /// Everything HF14A_4_EMV_SCAN reports.
    struct EmvScanResult {
        HfTag tag;
        EmvApdu apdus[16] = {};
        size_t apdu_count = 0;
    };

    /**
     * @brief HF14A_4_EMV_SCAN: full EMV sequence in one firmware call.
     *
     * The device runs field cycle, select, RATS, PPSE, SELECT AID, GPO and READ
     * RECORDs without returning to the host, because separate calls would drop
     * the field in between.
     */
    uint16_t Hf14a4EmvScan(EmvScanResult* out);

    // ---- HF14A configuration ----------------------------------------------

    /// HF14A_GET_CONFIG / SET_CONFIG: the four antenna and protocol options.
    struct Hf14aConfig {
        int8_t bcc  = 0;  ///< BCC handling
        int8_t cl2  = 0;  ///< cascade level 2 support
        int8_t cl3  = 0;  ///< cascade level 3 support
        int8_t rats = 0;  ///< RATS (ISO14443-4) support
    };

    uint16_t GetHf14aConfig(Hf14aConfig* out);
    uint16_t SetHf14aConfig(const Hf14aConfig& in);

    /**
     * @brief ENTER_BOOTLOADER: reboot the device into its DFU bootloader.
     *
     * Fire and forget: the device stops answering immediately, so there is no
     * response to wait for and the session must be treated as gone afterwards.
     * Not wired to any UI control - dropping the link is a deliberate action.
     */
    void EnterBootloader();

    // ---- SEOS -------------------------------------------------------------

    /// SEOS_READ_EMU_DATA: the four length prefixed fields plus the algorithm ids.
    struct SeosEmuData {
        uint8_t data[64]        = {};
        uint8_t data_length     = 0;
        uint8_t oid[32]         = {};
        uint8_t oid_length      = 0;
        uint8_t tag[16]         = {};
        uint8_t tag_length      = 0;
        uint8_t diversifier[32] = {};
        uint8_t diversifier_length = 0;
        uint8_t hash_alg        = 0;
        uint8_t encr_alg        = 0;
    };

    uint16_t SeosReadEmuData(SeosEmuData* out);

    /// SEOS_WRITE_EMU_DATA: same fields, each written with its length prefix.
    uint16_t SeosWriteEmuData(const SeosEmuData& in);

    /// SEOS_WRITE_EMU_KEYS: three fixed blobs concatenated verbatim.
    uint16_t SeosWriteEmuKeys(const uint8_t* auth, size_t auth_length, const uint8_t* privenc, size_t privenc_length,
                              const uint8_t* privmac, size_t privmac_length);

    /**
     * @brief HF14A_SET_ANTI_COLL_DATA: set UID/ATQA/SAK/ATS of the active HF slot.
     */
    bool SetHfAntiColl(const uint8_t* uid, uint8_t uid_length, const uint8_t atqa[2], uint8_t sak, const uint8_t* ats,
                       uint8_t ats_length);

    /**
     * @brief HF14A_GET_ANTI_COLL_DATA: read back the active HF slot's identity.
     */
    uint16_t GetHfAntiColl(HfTag* out);

    /**
     * @brief EM410X_SET_EMU_ID: set the card number the active LF slot emulates.
     *
     * @param id        5 bytes for EM410X, 13 for Electra
     * @param id_length 5 or 13
     */
    bool SetEm410xEmuId(const uint8_t* id, uint8_t id_length);

    /**
     * @brief EM410X_GET_EMU_ID: read the emulated EM410X card number.
     */
    uint16_t GetEm410xEmuId(LfTag* out);

    // ---- LF emulated card id (the other six LF protocols) ----------------

    /**
     * @brief LF protocols whose emulated card number the host can configure.
     *
     * Every one of them is a SET/GET pair with the same shape - the id bytes go
     * up, the same bytes come back - so one table covers them all instead of
     * twelve near-identical methods.
     */
    enum class LfEmuProtocol : uint8_t {
        Em410x = 0,
        HidProx,
        Viking,
        Pac,
        IoProx,
        Jablotron,
        Idteck,
    };

    /// Id length the protocol expects. EM410X accepts 5 (EM410X) or 13 (Electra).
    static size_t LfEmuIdLength(LfEmuProtocol protocol);

    /**
     * @brief SET_*_EMU_ID: set the card number the active slot emulates.
     *
     * @param protocol  which LF protocol's command to use
     * @param id        id bytes; length must match LfEmuIdLength() (EM410X may
     *                  be 5 or 13, chosen by the active slot's LF tag type)
     * @param id_length id length
     */
    uint16_t SetLfEmuId(LfEmuProtocol protocol, const uint8_t* id, size_t id_length);

    /**
     * @brief GET_*_EMU_ID: read back the emulated card number.
     *
     * @param out        receives the id bytes
     * @param out_size   capacity of out
     * @param out_length receives the number of id bytes read
     */
    uint16_t GetLfEmuId(LfEmuProtocol protocol, uint8_t* out, size_t out_size, size_t* out_length);

    /// Map an LF TagSpecificType to the protocol whose emu id commands apply.
    /// Returns false for tag types that have no host configurable id.
    static bool LfEmuProtocolForTagType(uint16_t lf_tag_type, LfEmuProtocol* out);

    // ---- MF1 emulator settings -------------------------------------------

    /**
     * @brief The one byte GET/SET setting pairs of the MF1 emulator.
     *
     * Six settings share the identical shape (a single byte, echoed by GET), so
     * one table drives all twelve commands instead of twelve wrappers.
     */
    enum class Mf1Toggle : uint8_t {
        Gen1aMagic   = 0,  ///< MF1_GET/SET_GEN1A_MODE
        Gen2Magic,         ///< MF1_GET/SET_GEN2_MODE
        BlockAntiColl,     ///< MF1_GET/SET_BLOCK_ANTI_COLL_MODE
        WriteMode,         ///< MF1_GET/SET_WRITE_MODE
        FieldOffReset,     ///< MF1_GET/SET_FIELD_OFF_DO_RESET
        PrngType,          ///< MF1_GET/SET_PRNG_TYPE
        Detection,         ///< MF1_GET/SET_DETECTION_ENABLE
    };

    /// Read one of the above. The raw byte is returned; 1 means enabled.
    uint16_t GetMf1Toggle(Mf1Toggle which, uint8_t* out);

    /// Write one of the above.
    uint16_t SetMf1Toggle(Mf1Toggle which, uint8_t value);

    /**
     * @brief MF1_GET_EMULATOR_CONFIG: the five settings in one round trip.
     *
     * Field order is the device's (app_cmd.c cmd_processor_mf1_get_emulator_config):
     * detection, gen1a, gen2, "use mf1 coll res", then the write mode byte.
     */
    struct Mf1EmulatorConfig {
        uint8_t detection      = 0;
        uint8_t gen1a_magic    = 0;
        uint8_t gen2_magic     = 0;
        uint8_t use_mf1_coll   = 0;  ///< emulate Mifare Classic anti-collision data
        uint8_t write_mode     = 0;
    };

    uint16_t GetMf1EmulatorConfig(Mf1EmulatorConfig* out);

    /// MF1_DETECT_PRNG: ask the device to classify the card's PRNG.
    uint16_t Mf1DetectPrng(uint8_t* out);

    /// One MF1_GET_DETECTION_LOG entry (a captured authentication).
    struct Mf1DetectionEntry {
        uint8_t block    = 0;
        uint8_t bitfield = 0;
        uint8_t uid[4]   = {};
        uint8_t nt[4]    = {};
        uint8_t nr[4]    = {};
        uint8_t ar[4]    = {};
    };

    /// MF1_GET_DETECTION_COUNT: how many authentication records are stored.
    uint16_t Mf1GetDetectionCount(uint32_t* out);

    /**
     * @brief MF1_GET_DETECTION_LOG: read records from an index.
     *
     * @param index  first record to read
     * @param out    receives the records
     * @param max    capacity of out
     * @param count  receives the number of records written
     */
    uint16_t Mf1GetDetectionLog(uint32_t index, Mf1DetectionEntry* out, size_t max, size_t* count);

    // ---- MF0 / NTAG emulator ---------------------------------------------

    uint16_t Mf0SetUidMagicMode(bool enabled);
    uint16_t Mf0GetUidMagicMode(bool* enabled);

    /// MF0_NTAG_GET_PAGE_COUNT (the emulated tag's page count).
    uint16_t Mf0GetPageCount(uint8_t* out);

    /// MF0_NTAG_READ/WRITE_EMU_PAGE_DATA: 4 byte pages.
    uint16_t Mf0ReadEmuPageData(uint8_t page_start, uint8_t page_count, uint8_t* out, size_t out_size, size_t* out_length);
    uint16_t Mf0WriteEmuPageData(uint8_t page_start, const uint8_t* data, size_t length);

    /// MF0_NTAG_GET/SET_VERSION_DATA: the 8 byte GET_VERSION response.
    uint16_t Mf0GetVersionData(uint8_t out[8]);
    uint16_t Mf0SetVersionData(const uint8_t data[8]);

    /// MF0_NTAG_GET/SET_SIGNATURE_DATA: the 32 byte ECC signature.
    uint16_t Mf0GetSignatureData(uint8_t out[32]);
    uint16_t Mf0SetSignatureData(const uint8_t data[32]);

    /**
     * @brief MF0_NTAG_GET_COUNTER_DATA.
     *
     * The device answers three little endian value bytes plus a tearing flag
     * byte (0xBD when the counter was torn), which chameleon_cmd.py reconstructs
     * as value | (flags[3] == 0xBD).
     */
    uint16_t Mf0GetCounterData(uint8_t index, uint32_t* value, bool* tearing);

    /// MF0_NTAG_SET_COUNTER_DATA. Bit 7 of the index byte carries reset_tearing.
    uint16_t Mf0SetCounterData(uint8_t index, bool reset_tearing, uint32_t value);

    /// MF0_NTAG_RESET_AUTH_CNT, returns the device's status byte.
    uint16_t Mf0ResetAuthCnt(uint8_t* out);

    uint16_t Mf0GetWriteMode(uint8_t* out);
    uint16_t Mf0SetWriteMode(uint8_t mode);

    /// MF0_NTAG_GET_EMULATOR_CONFIG: three bytes in one round trip.
    /// Field order is the device's (app_cmd.c cmd_processor_mf0_get_emulator_config).
    struct Mf0EmulatorConfig {
        uint8_t detection  = 0;
        uint8_t uid_mode   = 0;
        uint8_t write_mode = 0;
    };

    uint16_t Mf0GetEmulatorConfig(Mf0EmulatorConfig* out);

    uint16_t Mf0SetDetectionEnable(bool enabled);
    uint16_t Mf0GetDetectionEnable(bool* enabled);
    uint16_t Mf0GetDetectionCount(uint32_t* out);
    /// MF0_NTAG_GET_DETECTION_LOG: a list of 4 byte captured passwords.
    uint16_t Mf0GetDetectionLog(uint32_t index, uint8_t* out, size_t out_size, size_t* out_length);

    /**
     * @brief MF1_READ_EMU_BLOCK_DATA: read emulated Mifare Classic blocks.
     */
    uint16_t ReadEmuBlocks(uint8_t block_start, uint8_t block_count, uint8_t* out, size_t out_size,
                           size_t* out_length);

    /**
     * @brief MF1_WRITE_EMU_BLOCK_DATA: write emulated Mifare Classic blocks.
     */
    bool WriteEmuBlocks(uint8_t block_start, const uint8_t* data, size_t length);

    /// MF1_DETECT_SUPPORT: true when a Mifare Classic card is in the field.
    bool MifareSupported();

    // ---- generic LF card operations -------------------------------------

    /**
     * @brief Result of an LF scan, holding the raw device payload.
     *
     * The LF protocols all answer with a fixed-shape payload whose meaning
     * depends on the protocol, so it is returned raw and interpreted by the UI
     * rather than decoded here.
     */
    struct LfResult {
        uint8_t data[32] = {};
        size_t length   = 0;
    };

    /**
     * @brief Run an LF scan command.
     *
     * @param cmd         one of the *_SCAN commands (LF protocols answer LF_TAG_OK)
     * @param out         receives the raw payload
     * @param payload     optional request payload
     * @param payload_len payload length
     * @return uint16_t   status code
     *
     * HIDPROX_SCAN requires a one byte format hint: the firmware reads
     * `data[0]` without a null check, so sending an empty payload would fault
     * on the device. 0 means "try every known format".
     */
    uint16_t ScanLfCommand(uint16_t cmd, LfResult* out, const uint8_t* payload = nullptr, size_t payload_len = 0);

    /**
     * @brief Write a card id to a T55xx tag.
     *
     * Every *_WRITE_TO_T55XX command shares one payload shape, verified against
     * chameleon_cmd.py: `id[length] | new_key[4] | old_keys[4 * n]`. The first
     * key is the password the tag is left with, the rest are tried in order to
     * unlock a tag that is not on a known one.
     *
     * @param cmd        one of the *_WRITE_TO_T55XX commands
     * @param id         card id bytes (length depends on the protocol)
     * @param id_length  id length, must match what the firmware expects
     * @return uint16_t  status code
     */
    uint16_t WriteT55xx(uint16_t cmd, const uint8_t* id, size_t id_length);

    /// ADC_GENERIC_READ: raw ADC while the LF field is on.
    uint16_t AdcGenericRead(uint8_t* out, size_t out_size, size_t* out_length);

    /// LF_SNIFF: capture raw LF field samples for the given duration.
    uint16_t LfSniff(uint16_t timeout_ms, uint8_t* out, size_t out_size, size_t* out_length);

    /// EM4X05_SCAN: read an EM4x05/EM4x69 tag using the given 32-bit password.
    uint16_t Em4x05Scan(uint32_t password, uint8_t* out, size_t out_size, size_t* out_length);

    /// GET_SLOT_TAG_NICK into a caller buffer for the active slot.
    bool GetActiveSlotNick(char* out, size_t out_size);

private:
    /**
     * @brief Frame parser callback.
     */
    static void frameCallback(const FrameParser::Frame& frame, void* user);
    void onFrame(const FrameParser::Frame& frame);

    void emitLog(bool tx, uint16_t cmd, uint16_t status, size_t data_length);
    void emitStatus(const char* text);

    /// Mark the pending request as answered, copying the payload.
    void completePending(const FrameParser::Frame& frame);

    ClientCallbacks _callbacks;

    SendFn _send      = nullptr;
    void* _send_user  = nullptr;

    FrameParser _parser;

    bool _connected = false;

    // ---- pending request state (single outstanding request) -------------
    uint16_t _pending_cmd        = 0;
    volatile bool _pending       = false;
    bool _pending_answered       = false;
    uint16_t _pending_status     = 0;
    uint8_t _pending_data[kMaxDataLength] = {};
    size_t _pending_length       = 0;

    /// Reusable transmit buffer (the caller's payload is usually a local).
    uint8_t _tx_frame[kFrameOverhead + kMaxDataLength] = {};

    DeviceInfo _device_info;
    BatteryInfo _battery_info;
    bool _battery_raw_logged = false;
    bool _hf_scan_raw_logged = false;
    uint8_t _active_slot = 0;
    SlotInfo _slot_info[kSlotCount];
};

}  // namespace chameleon
