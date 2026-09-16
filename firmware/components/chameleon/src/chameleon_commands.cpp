// SPDX-License-Identifier: MIT

#include "chameleon_commands.h"

#include <stddef.h>

namespace chameleon {
namespace {

struct StatusEntry {
    uint16_t code;
    const char* text;
};

const StatusEntry kStatusTable[] = {
    {HF_TAG_OK, "HF tag ok"},
    {HF_TAG_NO, "HF tag not found"},
    {HF_ERR_STAT, "HF status error"},
    {HF_ERR_CRC, "HF crc error"},
    {HF_COLLISION, "HF collision"},
    {HF_ERR_BCC, "HF bcc error"},
    {MF_ERR_AUTH, "MF auth failed"},
    {HF_ERR_PARITY, "HF parity error"},
    {HF_ERR_ATS, "HF ATS error"},
    {LF_TAG_OK, "LF tag ok"},
    {LF_TAG_NO_FOUND, "LF tag not found"},
    {PAR_ERR, "param error"},
    {DEVICE_MODE_ERROR, "device mode error"},
    {INVALID_CMD, "invalid cmd"},
    {SUCCESS, "success"},
    {NOT_IMPLEMENTED, "not implemented"},
    {FLASH_WRITE_FAIL, "flash write fail"},
    {FLASH_READ_FAIL, "flash read fail"},
    {INVALID_SLOT_TYPE, "invalid slot type"},
};

struct CommandEntry {
    uint16_t cmd;
    const char* text;
};

const CommandEntry kCommandTable[] = {
    {GET_APP_VERSION, "GET_APP_VERSION"},
    {CHANGE_DEVICE_MODE, "CHANGE_DEVICE_MODE"},
    {GET_DEVICE_MODE, "GET_DEVICE_MODE"},
    {SET_ACTIVE_SLOT, "SET_ACTIVE_SLOT"},
    {SET_SLOT_TAG_TYPE, "SET_SLOT_TAG_TYPE"},
    {SET_SLOT_DATA_DEFAULT, "SET_SLOT_DATA_DEFAULT"},
    {SET_SLOT_ENABLE, "SET_SLOT_ENABLE"},
    {SET_SLOT_TAG_NICK, "SET_SLOT_TAG_NICK"},
    {GET_SLOT_TAG_NICK, "GET_SLOT_TAG_NICK"},
    {SLOT_DATA_CONFIG_SAVE, "SLOT_DATA_CONFIG_SAVE"},
    {ENTER_BOOTLOADER, "ENTER_BOOTLOADER"},
    {GET_DEVICE_CHIP_ID, "GET_DEVICE_CHIP_ID"},
    {GET_DEVICE_ADDRESS, "GET_DEVICE_ADDRESS"},
    {SAVE_SETTINGS, "SAVE_SETTINGS"},
    {RESET_SETTINGS, "RESET_SETTINGS"},
    {SET_ANIMATION_MODE, "SET_ANIMATION_MODE"},
    {GET_ANIMATION_MODE, "GET_ANIMATION_MODE"},
    {GET_GIT_VERSION, "GET_GIT_VERSION"},
    {GET_ACTIVE_SLOT, "GET_ACTIVE_SLOT"},
    {GET_SLOT_INFO, "GET_SLOT_INFO"},
    {WIPE_FDS, "WIPE_FDS"},
    {DELETE_SLOT_TAG_NICK, "DELETE_SLOT_TAG_NICK"},
    {GET_ENABLED_SLOTS, "GET_ENABLED_SLOTS"},
    {DELETE_SLOT_SENSE_TYPE, "DELETE_SLOT_SENSE_TYPE"},
    {GET_BATTERY_INFO, "GET_BATTERY_INFO"},
    {GET_BUTTON_PRESS_CONFIG, "GET_BUTTON_PRESS_CONFIG"},
    {SET_BUTTON_PRESS_CONFIG, "SET_BUTTON_PRESS_CONFIG"},
    {GET_LONG_BUTTON_PRESS_CONFIG, "GET_LONG_BUTTON_PRESS_CONFIG"},
    {SET_LONG_BUTTON_PRESS_CONFIG, "SET_LONG_BUTTON_PRESS_CONFIG"},
    {SET_BLE_PAIRING_KEY, "SET_BLE_PAIRING_KEY"},
    {GET_BLE_PAIRING_KEY, "GET_BLE_PAIRING_KEY"},
    {DELETE_ALL_BLE_BONDS, "DELETE_ALL_BLE_BONDS"},
    {GET_DEVICE_MODEL, "GET_DEVICE_MODEL"},
    {GET_DEVICE_SETTINGS, "GET_DEVICE_SETTINGS"},
    {GET_DEVICE_CAPABILITIES, "GET_DEVICE_CAPABILITIES"},
    {GET_BLE_PAIRING_ENABLE, "GET_BLE_PAIRING_ENABLE"},
    {SET_BLE_PAIRING_ENABLE, "SET_BLE_PAIRING_ENABLE"},
    {GET_ALL_SLOT_NICKS, "GET_ALL_SLOT_NICKS"},
    {GET_SLEEP_TIMEOUT, "GET_SLEEP_TIMEOUT"},
    {SET_SLEEP_TIMEOUT, "SET_SLEEP_TIMEOUT"},

    {HF14A_SCAN, "HF14A_SCAN"},
    {MF1_DETECT_SUPPORT, "MF1_DETECT_SUPPORT"},
    {MF1_DETECT_PRNG, "MF1_DETECT_PRNG"},
    {MF1_STATIC_NESTED_ACQUIRE, "MF1_STATIC_NESTED_ACQUIRE"},
    {MF1_DARKSIDE_ACQUIRE, "MF1_DARKSIDE_ACQUIRE"},
    {MF1_DETECT_NT_DIST, "MF1_DETECT_NT_DIST"},
    {MF1_NESTED_ACQUIRE, "MF1_NESTED_ACQUIRE"},
    {MF1_AUTH_ONE_KEY_BLOCK, "MF1_AUTH_ONE_KEY_BLOCK"},
    {MF1_READ_ONE_BLOCK, "MF1_READ_ONE_BLOCK"},
    {MF1_WRITE_ONE_BLOCK, "MF1_WRITE_ONE_BLOCK"},
    {HF14A_RAW, "HF14A_RAW"},
    {MF1_MANIPULATE_VALUE_BLOCK, "MF1_MANIPULATE_VALUE_BLOCK"},
    {MF1_CHECK_KEYS_OF_SECTORS, "MF1_CHECK_KEYS_OF_SECTORS"},
    {MF1_HARDNESTED_ACQUIRE, "MF1_HARDNESTED_ACQUIRE"},
    {MF1_ENC_NESTED_ACQUIRE, "MF1_ENC_NESTED_ACQUIRE"},
    {MF1_CHECK_KEYS_ON_BLOCK, "MF1_CHECK_KEYS_ON_BLOCK"},
    {HF14A_SCAN_KEEP, "HF14A_SCAN_KEEP"},
    {HF14A_AUTH_TRACE, "HF14A_AUTH_TRACE"},
    {HF14A_SNIFF, "HF14A_SNIFF"},
    {HF14A_GET_CONFIG, "HF14A_GET_CONFIG"},
    {HF14A_SET_CONFIG, "HF14A_SET_CONFIG"},

    {EM410X_SCAN, "EM410X_SCAN"},
    {EM410X_WRITE_TO_T55XX, "EM410X_WRITE_TO_T55XX"},
    {HIDPROX_SCAN, "HIDPROX_SCAN"},
    {HIDPROX_WRITE_TO_T55XX, "HIDPROX_WRITE_TO_T55XX"},
    {VIKING_SCAN, "VIKING_SCAN"},
    {VIKING_WRITE_TO_T55XX, "VIKING_WRITE_TO_T55XX"},
    {EM410X_ELECTRA_WRITE_TO_T55XX, "EM410X_ELECTRA_WRITE_TO_T55XX"},
    {ADC_GENERIC_READ, "ADC_GENERIC_READ"},
    {IOPROX_SCAN, "IOPROX_SCAN"},
    {IOPROX_WRITE_TO_T55XX, "IOPROX_WRITE_TO_T55XX"},
    {IOPROX_DECODE_RAW, "IOPROX_DECODE_RAW"},
    {IOPROX_COMPOSE_ID, "IOPROX_COMPOSE_ID"},
    {PAC_SCAN, "PAC_SCAN"},
    {PAC_WRITE_TO_T55XX, "PAC_WRITE_TO_T55XX"},
    {LF_T55XX_WRITE, "LF_T55XX_WRITE"},
    {IDTECK_WRITE_TO_T55XX, "IDTECK_WRITE_TO_T55XX"},
    {JABLOTRON_SCAN, "JABLOTRON_SCAN"},
    {JABLOTRON_WRITE_TO_T55XX, "JABLOTRON_WRITE_TO_T55XX"},
    {EM4X05_SCAN, "EM4X05_SCAN"},
    {LF_SNIFF, "LF_SNIFF"},
    {EM4X05_READSNIFF, "EM4X05_READSNIFF"},

    {MF1_WRITE_EMU_BLOCK_DATA, "MF1_WRITE_EMU_BLOCK_DATA"},
    {HF14A_SET_ANTI_COLL_DATA, "HF14A_SET_ANTI_COLL_DATA"},
    {MF1_SET_DETECTION_ENABLE, "MF1_SET_DETECTION_ENABLE"},
    {MF1_GET_DETECTION_COUNT, "MF1_GET_DETECTION_COUNT"},
    {MF1_GET_DETECTION_LOG, "MF1_GET_DETECTION_LOG"},
    {MF1_READ_EMU_BLOCK_DATA, "MF1_READ_EMU_BLOCK_DATA"},
    {MF1_GET_EMULATOR_CONFIG, "MF1_GET_EMULATOR_CONFIG"},
    {MF1_SET_GEN1A_MODE, "MF1_SET_GEN1A_MODE"},
    {MF1_SET_GEN2_MODE, "MF1_SET_GEN2_MODE"},
    {MF1_SET_BLOCK_ANTI_COLL_MODE, "MF1_SET_BLOCK_ANTI_COLL_MODE"},
    {MF1_SET_WRITE_MODE, "MF1_SET_WRITE_MODE"},
    {HF14A_GET_ANTI_COLL_DATA, "HF14A_GET_ANTI_COLL_DATA"},
    {MF0_NTAG_SET_UID_MAGIC_MODE, "MF0_NTAG_SET_UID_MAGIC_MODE"},
    {MF0_NTAG_READ_EMU_PAGE_DATA, "MF0_NTAG_READ_EMU_PAGE_DATA"},
    {MF0_NTAG_WRITE_EMU_PAGE_DATA, "MF0_NTAG_WRITE_EMU_PAGE_DATA"},
    {MF0_NTAG_GET_PAGE_COUNT, "MF0_NTAG_GET_PAGE_COUNT"},
    {MF0_NTAG_SET_WRITE_MODE, "MF0_NTAG_SET_WRITE_MODE"},
    {MF1_SET_FIELD_OFF_DO_RESET, "MF1_SET_FIELD_OFF_DO_RESET"},
    {MF1_GET_PRNG_TYPE, "MF1_GET_PRNG_TYPE"},
    {MF1_SET_PRNG_TYPE, "MF1_SET_PRNG_TYPE"},
    {SEOS_READ_EMU_DATA, "SEOS_READ_EMU_DATA"},
    {SEOS_WRITE_EMU_DATA, "SEOS_WRITE_EMU_DATA"},
    {SEOS_WRITE_EMU_KEYS, "SEOS_WRITE_EMU_KEYS"},

    {EM410X_SET_EMU_ID, "EM410X_SET_EMU_ID"},
    {EM410X_GET_EMU_ID, "EM410X_GET_EMU_ID"},
    {HIDPROX_SET_EMU_ID, "HIDPROX_SET_EMU_ID"},
    {HIDPROX_GET_EMU_ID, "HIDPROX_GET_EMU_ID"},
    {VIKING_SET_EMU_ID, "VIKING_SET_EMU_ID"},
    {VIKING_GET_EMU_ID, "VIKING_GET_EMU_ID"},
    {PAC_SET_EMU_ID, "PAC_SET_EMU_ID"},
    {PAC_GET_EMU_ID, "PAC_GET_EMU_ID"},
    {IOPROX_SET_EMU_ID, "IOPROX_SET_EMU_ID"},
    {IOPROX_GET_EMU_ID, "IOPROX_GET_EMU_ID"},
    {JABLOTRON_SET_EMU_ID, "JABLOTRON_SET_EMU_ID"},
    {JABLOTRON_GET_EMU_ID, "JABLOTRON_GET_EMU_ID"},
    {IDTECK_SET_EMU_ID, "IDTECK_SET_EMU_ID"},
    {IDTECK_GET_EMU_ID, "IDTECK_GET_EMU_ID"},

    {HF14A_4_APDU_RECV, "HF14A_4_APDU_RECV"},
    {HF14A_4_APDU_SEND, "HF14A_4_APDU_SEND"},
    {HF14A_4_SET_ANTI_COLL, "HF14A_4_SET_ANTI_COLL"},
    {HF14A_4_STATIC_RESP, "HF14A_4_STATIC_RESP"},
    {HF14A_4_READER_APDU, "HF14A_4_READER_APDU"},
    {HF14A_4_EMV_SCAN, "HF14A_4_EMV_SCAN"},
};

}  // namespace

const char* StatusText(uint16_t status)
{
    for (const auto& entry : kStatusTable) {
        if (entry.code == status) {
            return entry.text;
        }
    }
    return "unknown status";
}

const char* CommandText(uint16_t cmd)
{
    for (const auto& entry : kCommandTable) {
        if (entry.cmd == cmd) {
            return entry.text;
        }
    }
    return "unknown cmd";
}

const char* TagTypeText(uint16_t tag_type)
{
    switch (tag_type) {
        case TAG_UNDEFINED:
            return "Undefined";
        case EM410X:
            return "EM410X";
        case EM410X_16:
            return "EM410X/16";
        case EM410X_32:
            return "EM410X/32";
        case EM410X_64:
            return "EM410X/64";
        case EM410X_ELECTRA:
            return "EM410X Electra";
        case HIDProx:
            return "HIDProx";
        case ioProx:
            return "ioProx";
        case PAC:
            return "PAC/Stanley";
        case Viking:
            return "Viking";
        case Jablotron:
            return "Jablotron";
        case IDTECK:
            return "IDTECK";
        case MIFARE_Mini:
            return "Mifare Mini";
        case MIFARE_1024:
            return "Mifare Classic 1K";
        case MIFARE_2048:
            return "Mifare Classic 2K";
        case MIFARE_4096:
            return "Mifare Classic 4K";
        case NTAG_213:
            return "NTAG213";
        case NTAG_215:
            return "NTAG215";
        case NTAG_216:
            return "NTAG216";
        case MF0ICU1:
            return "Mifare Ultralight";
        case MF0ICU2:
            return "Mifare Ultralight C";
        case MF0UL11:
            return "MF0UL11";
        case MF0UL21:
            return "MF0UL21";
        case NTAG_210:
            return "NTAG210";
        case NTAG_212:
            return "NTAG212";
        case HF14A_4:
            return "ISO14443-4 T=CL";
        case SEOS:
            return "SEOS";
        default:
            return "unknown tag type";
    }
}

}  // namespace chameleon
