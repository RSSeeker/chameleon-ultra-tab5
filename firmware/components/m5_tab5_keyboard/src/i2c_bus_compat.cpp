// SPDX-License-Identifier: MIT
//
// Implementation of the minimal i2c_bus shim - see i2c_bus.h for why it exists.
//
// Every function forwards to the ESP-IDF native i2c_master driver, so the
// driver gets real behaviour rather than stubs if a caller ever takes this path.
//
// The handle types are deliberately distinct structs rather than aliases of the
// i2c_master ones: the Tab5 keyboard driver overloads begin() on both spellings,
// and aliasing would collapse those overloads into duplicates.

#include "i2c_bus.h"

#include <stdlib.h>
#include <string.h>

struct i2c_bus_t {
    i2c_master_bus_handle_t bus;
};

struct i2c_bus_device_t {
    i2c_master_dev_handle_t dev;
};

extern "C" i2c_bus_device_handle_t i2c_bus_device_create(i2c_bus_handle_t bus, uint16_t addr, uint32_t clk_speed)
{
    if (bus == nullptr || bus->bus == nullptr) {
        return nullptr;
    }

    const i2c_device_config_t cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = addr,
        .scl_speed_hz    = clk_speed,
        .scl_wait_us     = 0,
        .flags           = {},
    };

    i2c_master_dev_handle_t dev = nullptr;
    if (i2c_master_bus_add_device(bus->bus, &cfg, &dev) != ESP_OK) {
        return nullptr;
    }

    auto* wrapper = static_cast<i2c_bus_device_t*>(calloc(1, sizeof(i2c_bus_device_t)));
    if (wrapper == nullptr) {
        i2c_master_bus_rm_device(dev);
        return nullptr;
    }
    wrapper->dev = dev;
    return wrapper;
}

extern "C" void i2c_bus_device_delete(i2c_bus_device_handle_t* dev)
{
    if (dev == nullptr || *dev == nullptr) {
        return;
    }
    i2c_master_bus_rm_device((*dev)->dev);
    free(*dev);
    *dev = nullptr;
}

extern "C" void i2c_bus_delete(i2c_bus_handle_t* bus)
{
    // The bus is owned by the caller in this project (the Tab5 BSP bus is shared
    // with the display and IO expanders), so only forget it here.
    if (bus != nullptr) {
        *bus = nullptr;
    }
}

extern "C" esp_err_t i2c_bus_read_byte(i2c_bus_device_handle_t dev, uint8_t reg, uint8_t* data)
{
    return i2c_bus_read_bytes(dev, reg, 1, data);
}

extern "C" esp_err_t i2c_bus_read_bytes(i2c_bus_device_handle_t dev, uint8_t reg, size_t len, uint8_t* data)
{
    if (dev == nullptr || data == nullptr) {
        return ESP_ERR_INVALID_ARG;
    }
    return i2c_master_transmit_receive(dev->dev, &reg, 1, data, len, -1);
}

extern "C" esp_err_t i2c_bus_write_byte(i2c_bus_device_handle_t dev, uint8_t reg, uint8_t data)
{
    return i2c_bus_write_bytes(dev, reg, 1, &data);
}

extern "C" esp_err_t i2c_bus_write_bytes(i2c_bus_device_handle_t dev, uint8_t reg, size_t len, const uint8_t* data)
{
    if (dev == nullptr || data == nullptr || len > 32) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t buffer[33];
    buffer[0] = reg;
    memcpy(buffer + 1, data, len);
    return i2c_master_transmit(dev->dev, buffer, len + 1, -1);
}
