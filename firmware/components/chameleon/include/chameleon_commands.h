// SPDX-License-Identifier: MIT
//
// Chameleon Ultra command / status codes.
//
// Ported from software/script/chameleon_enum.py in the official ChameleonUltra
// repository. Only the commands this client actually issues are enumerated in
// full; the rest are kept so that received frames and status codes can be
// decoded and displayed.

#pragma once

#include <stdint.h>

namespace chameleon {

/// Device modes reported by GET_DEVICE_MODE.
enum class DeviceMode : uint8_t {
    Tag   = 0,
    Reader = 1,
};

/// Command ids (wire encoding is big endian).
enum Command : uint16_t {
    // ---- system ----
    GET_APP_VERSION          = 1000,
    CHANGE_DEVICE_MODE       = 1001,
    GET_DEVICE_MODE          = 1002,
    SET_ACTIVE_SLOT          = 1003,
    SET_SLOT_TAG_TYPE        = 1004,
    SET_SLOT_DATA_DEFAULT    = 1005,
    SET_SLOT_ENABLE          = 1006,
    SET_SLOT_TAG_NICK        = 1007,
    GET_SLOT_TAG_NICK        = 1008,
    SLOT_DATA_CONFIG_SAVE    = 1009,
    ENTER_BOOTLOADER         = 1010,
    GET_DEVICE_CHIP_ID       = 1011,
    GET_DEVICE_ADDRESS       = 1012,
    SAVE_SETTINGS            = 1013,
    RESET_SETTINGS           = 1014,
    SET_ANIMATION_MODE       = 1015,
    GET_ANIMATION_MODE       = 1016,
    GET_GIT_VERSION          = 1017,
    GET_ACTIVE_SLOT          = 1018,
    GET_SLOT_INFO            = 1019,
    WIPE_FDS                 = 1020,
    DELETE_SLOT_TAG_NICK     = 1021,
    GET_ENABLED_SLOTS        = 1023,
    DELETE_SLOT_SENSE_TYPE   = 1024,
    GET_BATTERY_INFO         = 1025,
    GET_BUTTON_PRESS_CONFIG  = 1026,
    SET_BUTTON_PRESS_CONFIG  = 1027,
    GET_LONG_BUTTON_PRESS_CONFIG = 1028,
    SET_LONG_BUTTON_PRESS_CONFIG = 1029,
    SET_BLE_PAIRING_KEY      = 1030,
    GET_BLE_PAIRING_KEY      = 1031,
    DELETE_ALL_BLE_BONDS     = 1032,
    GET_DEVICE_MODEL         = 1033,
    GET_DEVICE_SETTINGS      = 1034,
    GET_DEVICE_CAPABILITIES  = 1035,
    GET_BLE_PAIRING_ENABLE   = 1036,
    SET_BLE_PAIRING_ENABLE   = 1037,
    GET_ALL_SLOT_NICKS       = 1038,
    GET_SLEEP_TIMEOUT        = 1039,
    SET_SLEEP_TIMEOUT        = 1040,

    // ---- HF14A / Mifare ----
    HF14A_SCAN                  = 2000,
    MF1_DETECT_SUPPORT          = 2001,
    MF1_DETECT_PRNG             = 2002,
    MF1_STATIC_NESTED_ACQUIRE   = 2003,
    MF1_DARKSIDE_ACQUIRE        = 2004,
    MF1_DETECT_NT_DIST          = 2005,
    MF1_NESTED_ACQUIRE          = 2006,
    MF1_AUTH_ONE_KEY_BLOCK      = 2007,
    MF1_READ_ONE_BLOCK          = 2008,
    MF1_WRITE_ONE_BLOCK         = 2009,
    HF14A_RAW                   = 2010,
    MF1_MANIPULATE_VALUE_BLOCK  = 2011,
    MF1_CHECK_KEYS_OF_SECTORS   = 2012,
    MF1_HARDNESTED_ACQUIRE      = 2013,
    MF1_ENC_NESTED_ACQUIRE      = 2014,
    MF1_CHECK_KEYS_ON_BLOCK     = 2015,
    HF14A_SCAN_KEEP             = 2016,
    HF14A_AUTH_TRACE            = 2017,
    HF14A_SNIFF                 = 2020,
    HF14A_GET_CONFIG            = 2200,
    HF14A_SET_CONFIG            = 2201,

    // ---- LF ----
    EM410X_SCAN                 = 3000,
    EM410X_WRITE_TO_T55XX       = 3001,
    HIDPROX_SCAN                = 3002,
    HIDPROX_WRITE_TO_T55XX      = 3003,
    VIKING_SCAN                 = 3004,
    VIKING_WRITE_TO_T55XX       = 3005,
    EM410X_ELECTRA_WRITE_TO_T55XX = 3006,
    ADC_GENERIC_READ            = 3009,
    IOPROX_SCAN                 = 3010,
    IOPROX_WRITE_TO_T55XX       = 3011,
    IOPROX_DECODE_RAW           = 3012,
    IOPROX_COMPOSE_ID           = 3013,
    PAC_SCAN                    = 3014,
    PAC_WRITE_TO_T55XX          = 3015,
    LF_T55XX_WRITE              = 3016,
    IDTECK_WRITE_TO_T55XX       = 3018,
    JABLOTRON_SCAN              = 3019,
    JABLOTRON_WRITE_TO_T55XX    = 3020,
    EM4X05_SCAN                 = 3030,
    LF_SNIFF                    = 3031,
    EM4X05_READSNIFF            = 3032,

    // ---- emulator configuration ----
    MF1_WRITE_EMU_BLOCK_DATA    = 4000,
    HF14A_SET_ANTI_COLL_DATA    = 4001,
    MF1_SET_DETECTION_ENABLE    = 4004,
    MF1_GET_DETECTION_COUNT     = 4005,
    MF1_GET_DETECTION_LOG       = 4006,
    MF1_GET_DETECTION_ENABLE    = 4007,
    MF1_READ_EMU_BLOCK_DATA     = 4008,
    MF1_GET_EMULATOR_CONFIG     = 4009,
    MF1_GET_GEN1A_MODE          = 4010,
    MF1_SET_GEN1A_MODE          = 4011,
    MF1_GET_GEN2_MODE           = 4012,
    MF1_SET_GEN2_MODE           = 4013,
    MF1_GET_BLOCK_ANTI_COLL_MODE = 4014,
    MF1_SET_BLOCK_ANTI_COLL_MODE = 4015,
    MF1_GET_WRITE_MODE          = 4016,
    MF1_SET_WRITE_MODE          = 4017,
    HF14A_GET_ANTI_COLL_DATA    = 4018,
    MF0_NTAG_GET_UID_MAGIC_MODE = 4019,
    MF0_NTAG_SET_UID_MAGIC_MODE = 4020,
    MF0_NTAG_READ_EMU_PAGE_DATA = 4021,
    MF0_NTAG_WRITE_EMU_PAGE_DATA = 4022,
    MF0_NTAG_GET_VERSION_DATA   = 4023,
    MF0_NTAG_SET_VERSION_DATA   = 4024,
    MF0_NTAG_GET_SIGNATURE_DATA = 4025,
    MF0_NTAG_SET_SIGNATURE_DATA = 4026,
    MF0_NTAG_GET_COUNTER_DATA   = 4027,
    MF0_NTAG_SET_COUNTER_DATA   = 4028,
    MF0_NTAG_RESET_AUTH_CNT     = 4029,
    MF0_NTAG_GET_PAGE_COUNT     = 4030,
    MF0_NTAG_GET_WRITE_MODE     = 4031,
    MF0_NTAG_SET_WRITE_MODE     = 4032,
    MF0_NTAG_SET_DETECTION_ENABLE = 4033,
    MF0_NTAG_GET_DETECTION_COUNT = 4034,
    MF0_NTAG_GET_DETECTION_LOG  = 4035,
    MF0_NTAG_GET_DETECTION_ENABLE = 4036,
    MF0_NTAG_GET_EMULATOR_CONFIG = 4037,
    MF1_SET_FIELD_OFF_DO_RESET  = 4038,
    MF1_GET_FIELD_OFF_DO_RESET  = 4039,
    MF1_GET_PRNG_TYPE           = 4040,
    MF1_SET_PRNG_TYPE           = 4041,
    SEOS_READ_EMU_DATA          = 4042,
    SEOS_WRITE_EMU_DATA         = 4043,
    SEOS_WRITE_EMU_KEYS         = 4044,

    // ---- LF emulator id ----
    EM410X_SET_EMU_ID           = 5000,
    EM410X_GET_EMU_ID           = 5001,
    HIDPROX_SET_EMU_ID          = 5002,
    HIDPROX_GET_EMU_ID          = 5003,
    VIKING_SET_EMU_ID           = 5004,
    VIKING_GET_EMU_ID           = 5005,
    PAC_SET_EMU_ID              = 5006,
    PAC_GET_EMU_ID              = 5007,
    IOPROX_SET_EMU_ID           = 5008,
    IOPROX_GET_EMU_ID           = 5009,
    JABLOTRON_SET_EMU_ID        = 5010,
    JABLOTRON_GET_EMU_ID        = 5011,
    IDTECK_SET_EMU_ID           = 5012,
    IDTECK_GET_EMU_ID           = 5013,

    // ---- ISO14443-4 T=CL ----
    HF14A_4_APDU_RECV           = 6000,
    HF14A_4_APDU_SEND           = 6001,
    HF14A_4_SET_ANTI_COLL       = 6002,
    HF14A_4_STATIC_RESP         = 6003,
    HF14A_4_READER_APDU         = 6004,
    HF14A_4_EMV_SCAN            = 6005,
};

/// Status codes carried in every response frame.
enum Status : uint16_t {
    HF_TAG_OK            = 0x00,  ///< IC card operation succeeded
    HF_TAG_NO            = 0x01,  ///< IC card not found
    HF_ERR_STAT          = 0x02,  ///< Abnormal IC card communication
    HF_ERR_CRC           = 0x03,  ///< IC card communication verification abnormal
    HF_COLLISION         = 0x04,  ///< IC card conflict
    HF_ERR_BCC           = 0x05,  ///< IC card BCC error
    MF_ERR_AUTH          = 0x06,  ///< MF card verification failed
    HF_ERR_PARITY        = 0x07,  ///< IC card parity error
    HF_ERR_ATS           = 0x08,  ///< ATS should be present but card NAKed

    LF_TAG_OK            = 0x40,  ///< Low frequency operation succeeded
    LF_TAG_NO_FOUND      = 0x41,  ///< No valid LF tag found

    PAR_ERR              = 0x60,  ///< Bad parameters / bad API call
    DEVICE_MODE_ERROR    = 0x66,  ///< Command not valid in the current mode
    INVALID_CMD          = 0x67,  ///< Device does not support this command
    SUCCESS              = 0x68,  ///< Generic success
    NOT_IMPLEMENTED      = 0x69,
    FLASH_WRITE_FAIL     = 0x70,
    FLASH_READ_FAIL      = 0x71,
    INVALID_SLOT_TYPE    = 0x72,
};

/// Tag sense (frequency band) of a slot.
enum class TagSenseType : uint8_t {
    Undefined = 0,
    LF        = 1,
    HF        = 2,
};

/// Tag specific types used by SET_SLOT_TAG_TYPE.
enum TagSpecificType : uint16_t {
    TAG_UNDEFINED = 0,

    // LF (ASK tag-talk-first)
    EM410X        = 100,
    EM410X_16     = 101,
    EM410X_32     = 102,
    EM410X_64     = 103,
    EM410X_ELECTRA = 104,
    PAC           = 150,
    Viking        = 170,
    Jablotron     = 180,

    // LF (FSK tag-talk-first)
    HIDProx = 200,
    ioProx  = 201,

    // LF (PSK tag-talk-first)
    IDTECK = 310,

    TAG_TYPES_LF_END = 999,

    // HF: MIFARE Classic
    MIFARE_Mini   = 1000,
    MIFARE_1024   = 1001,
    MIFARE_2048   = 1002,
    MIFARE_4096   = 1003,

    // HF: MFUL / NTAG
    NTAG_213 = 1100,
    NTAG_215 = 1101,
    NTAG_216 = 1102,
    MF0ICU1  = 1103,
    MF0ICU2  = 1104,
    MF0UL11  = 1105,
    MF0UL21  = 1106,
    NTAG_210 = 1107,
    NTAG_212 = 1108,

    // HF: ISO14443-4 T=CL emulation
    HF14A_4 = 3000,
    SEOS    = 3001,
};

/// Button press functions, as used by GET/SET_BUTTON_PRESS_CONFIG.
enum ButtonPressFunction : uint8_t {
    BUTTON_NONE      = 0,
    BUTTON_NEXTSLOT  = 1,
    BUTTON_PREVSLOT  = 2,
    BUTTON_CLONE     = 3,
    BUTTON_BATTERY   = 4,
    BUTTON_FIELDGEN  = 5,
};

/// Animation mode of the device LED.
enum AnimationMode : uint8_t {
    ANIMATION_FULL      = 0,
    ANIMATION_MINIMAL   = 1,
    ANIMATION_NONE      = 2,
    ANIMATION_SYMMETRIC = 3,
};

/// Mifare Classic write modes.
enum MfcWriteMode : uint8_t {
    MFC_WRITE_NORMAL   = 0,
    MFC_WRITE_DENIED   = 1,
    MFC_WRITE_DECEIVE  = 2,
    MFC_WRITE_SHADOW   = 3,
    MFC_WRITE_SHADOW_REQ = 4,
};

/**
 * @brief Short human readable text for a status code.
 */
const char* StatusText(uint16_t status);

/**
 * @brief Short human readable name for a command id.
 */
const char* CommandText(uint16_t cmd);

/**
 * @brief Human readable name for a tag specific type.
 */
const char* TagTypeText(uint16_t tag_type);

}  // namespace chameleon
