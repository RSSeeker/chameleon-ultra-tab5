// SPDX-License-Identifier: MIT
//
// Minimal USB CDC-ACM host driver.
//
// ESP-IDF 5.4 ships a USB host stack and a HID class driver, but the CDC-ACM
// class driver (espressif/usb_host_cdc_acm) is a managed component that is not
// available in this offline build. This is a compact replacement that covers
// exactly what the Chameleon Ultra needs: open the device, claim the CDC data
// interface, and stream bytes over its bulk endpoints.
//
// It deliberately does not implement the CDC control model beyond issuing
// SET_CONTROL_LINE_STATE / SET_LINE_CODING on open, plus optionally draining
// the notification (interrupt IN) endpoint. The Chameleon Ultra's firmware
// (firmware/application/src/usb_main.c) streams the same frame protocol over
// CDC-ACM that it uses over BLE and does not require the host to configure the
// line, so a plain bulk byte pipe is sufficient and correct.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <esp_err.h>

namespace chameleon {

/// Callback invoked with received bytes. Runs in the USB client task context.
using UsbSerialRxCallback = void (*)(const uint8_t* data, size_t len, void* user);

/// Callback invoked when the device is attached / detached.
using UsbSerialStateCallback = void (*)(bool connected, void* user);

class UsbSerialHost {
public:
    UsbSerialHost() = default;
    ~UsbSerialHost();

    UsbSerialHost(const UsbSerialHost&)            = delete;
    UsbSerialHost& operator=(const UsbSerialHost&) = delete;

    /**
     * @brief Install the USB host library and start the client task.
     *
     * @param rx_cb     called for every chunk received from the device
     * @param state_cb  called when the device connects / disconnects
     * @param user      opaque pointer passed to both callbacks
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t Start(UsbSerialRxCallback rx_cb, UsbSerialStateCallback state_cb, void* user);

    /**
     * @brief Detach from the device and stop the client task.
     *
     * The USB host library itself stays installed.
     */
    void Stop();

    /**
     * @brief Queue a buffer for transmission over the bulk OUT endpoint.
     *
     * Non-blocking from the caller's point of view: the buffer is copied and
     * handed to the transfer worker. Large writes are split into MPS-sized
     * chunks internally.
     *
     * @return true when the buffer was queued
     */
    bool Write(const uint8_t* data, size_t len);

    /**
     * @brief True while a Chameleon-like device is attached and claimed.
     */
    bool IsConnected() const;

    /**
     * @brief Vendor / product id of the attached device, 0 when detached.
     */
    void GetIds(uint16_t* vid, uint16_t* pid) const;

    /**
     * @brief Human readable description of the attached device, for the UI.
     */
    const char* GetDeviceName() const;

private:
    struct Impl;
    Impl* _impl = nullptr;
};

}  // namespace chameleon
