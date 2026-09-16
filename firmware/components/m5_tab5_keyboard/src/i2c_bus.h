// SPDX-License-Identifier: MIT
//
// Minimal stand-in for the esp-idf-lib `i2c_bus` component.
//
// The M5Stack Tab5 Keyboard driver (m5_tab5_keyboard.cpp) supports four I2C
// wiring styles and pulls in the third party `espressif/i2c_bus` component for
// one of them. This project builds fully offline and that component is not in
// the local IDF component cache, so this header supplies just the surface the
// driver references, implemented directly over the ESP-IDF native i2c_master
// driver:
//
//   i2c_bus_device_create/delete   -> ctor/dtor around i2c_master_bus_add_device
//   i2c_bus_read_byte(s)           -> i2c_master_transmit_receive
//   i2c_bus_write_byte(s)          -> i2c_master_transmit
//
// Only these six symbols are needed; the rest of the esp-idf-lib API is not
// referenced by the driver. None of these code paths run in this firmware: the
// Tab5 keyboard is opened with the native
// `begin(i2c_port_t, addr, sda, scl, speed, intPin, mode)` overload, which uses
// the i2c_master driver exclusively.

#ifndef CHAMELEON_I2C_BUS_COMPAT_H
#define CHAMELEON_I2C_BUS_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#include <driver/i2c_master.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

// Distinct handle types: an alias of i2c_master_bus_handle_t would make the
// driver's overloads collide (they take both spellings).
typedef struct i2c_bus_t* i2c_bus_handle_t;

/// Device handle. The wrapper is allocated by i2c_bus_device_create().
typedef struct i2c_bus_device_t* i2c_bus_device_handle_t;

i2c_bus_device_handle_t i2c_bus_device_create(i2c_bus_handle_t bus, uint16_t addr, uint32_t clk_speed);
void i2c_bus_device_delete(i2c_bus_device_handle_t* dev);
void i2c_bus_delete(i2c_bus_handle_t* bus);

esp_err_t i2c_bus_read_byte(i2c_bus_device_handle_t dev, uint8_t reg, uint8_t* data);
esp_err_t i2c_bus_read_bytes(i2c_bus_device_handle_t dev, uint8_t reg, size_t len, uint8_t* data);
esp_err_t i2c_bus_write_byte(i2c_bus_device_handle_t dev, uint8_t reg, uint8_t data);
esp_err_t i2c_bus_write_bytes(i2c_bus_device_handle_t dev, uint8_t reg, size_t len, const uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif /* CHAMELEON_I2C_BUS_COMPAT_H */
