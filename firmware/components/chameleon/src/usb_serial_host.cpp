// SPDX-License-Identifier: MIT
//
// Minimal USB CDC-ACM host driver - see usb_serial_host.h for the rationale.
//
// Structure:
//   - one USB host client, driven by its own task
//   - device enumeration: find a configuration that exposes a CDC Communication
//     interface (class 0x02) together with a CDC Data interface (class 0x0A)
//   - claim both interfaces, then stream the bulk IN / bulk OUT endpoints
//
// The Chameleon Ultra exposes exactly this layout (USB CDC-ACM, VID/PID from the
// Nordic SDK, single configuration), but the driver does not require a specific
// VID/PID: any CDC-ACM device is accepted so a USB-serial adapter can be used
// for bring-up.

#include "usb_serial_host.h"

#include <string.h>

#include <esp_err.h>
#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

#include <usb/usb_host.h>
#include <usb/usb_helpers.h>

static const char* TAG = "usb_cdc";

namespace chameleon {
namespace {

/// Chunk size for bulk transfers. The Chameleon frame protocol caps payloads at
/// 4 KiB; 512 B chunks keep latency low and bound the internal buffers.
constexpr size_t kTransferSize = 512;

/// Depth of the pending-transmission queue.
constexpr size_t kTxQueueDepth = 8;

/// Bring-up instrumentation: dumps the device's descriptor tree and per-transfer
/// results. Enable while debugging the USB layer; keep off for normal operation.
constexpr bool kVerboseUsbLog = false;

/// How long usb_host_client_handle_events() blocks per iteration.
constexpr TickType_t kClientPollTicks = pdMS_TO_TICKS(10);

/// CDC class specific requests.
constexpr uint8_t kCdcSetLineCoding        = 0x20;
constexpr uint8_t kCdcSetControlLineState  = 0x22;

/// Class specific interface descriptor (bDescriptorType = CS_INTERFACE).
/// IDF only defines the radio control variant, so define the CDC one here.
constexpr uint8_t kDescriptorTypeCsInterface = 0x24;

struct TxChunk {
    uint8_t data[kTransferSize];
    size_t length;
};

/// Completion flag for a control transfer issued from the client task.
///
/// These requests are fired asynchronously and freed in their own callback.
/// They must never be waited on from the client task: control transfers only
/// complete inside usb_host_client_handle_events(), which is the loop the
/// client task itself runs, so blocking there would deadlock and leave the URB
/// stuck in the host controller (which then rejects every later submit with
/// ESP_ERR_INVALID_STATE).
struct CtrlTransferCtx {
    void* self          = nullptr;
    volatile bool* done = nullptr;
};

/// Everything the client task needs to know about the attached device.
struct ClaimedDevice {
    usb_device_handle_t handle = nullptr;

    bool valid = false;

    uint8_t comm_interface = 0;
    bool comm_claimed      = false;

    uint8_t data_interface = 0;
    bool data_claimed      = false;

    uint8_t ep_in           = 0;
    uint16_t ep_in_mps      = 0;
    uint8_t ep_out          = 0;
    uint16_t ep_out_mps     = 0;
    uint8_t ep_notify       = 0;
    uint16_t ep_notify_mps  = 0;

    uint16_t vid = 0;
    uint16_t pid = 0;
    char name[48] = {};
};

/**
 * @brief Walk a configuration descriptor and locate the CDC interfaces.
 *
 * Accepts the standard CDC layout: an interface with class 0x02 (Communication)
 * whose functional descriptors name a data interface of class 0x0A. Bulk IN and
 * bulk OUT endpoints are taken from the data interface.
 */
bool parse_cdc_interfaces(const usb_config_desc_t* config_desc, ClaimedDevice& dev)
{
    if (config_desc == nullptr) {
        return false;
    }

    const uint16_t total_length = config_desc->wTotalLength;

    int offset = 0;
    const usb_standard_desc_t* desc =
        usb_parse_next_descriptor(reinterpret_cast<const usb_standard_desc_t*>(config_desc), total_length, &offset);
    if (desc == nullptr) {
        return false;
    }

    // First pass: find the Communication interface, learn the data interface
    // number from the Union Functional Descriptor (subtype 0x06), and remember
    // the notification endpoint.
    const uint8_t* raw            = reinterpret_cast<const uint8_t*>(config_desc);
    bool found_comm               = false;

    while (desc != nullptr) {
        if (desc->bDescriptorType == USB_B_DESCRIPTOR_TYPE_INTERFACE) {
            const auto* intf = reinterpret_cast<const usb_intf_desc_t*>(desc);
            if (intf->bInterfaceClass == USB_CLASS_COMM && !found_comm) {
                dev.comm_interface = intf->bInterfaceNumber;
                found_comm         = true;
            } else if (intf->bInterfaceClass == USB_CLASS_COMM) {
                // A second comm interface: ignore, we only support one function.
            }
        } else if (desc->bDescriptorType == kDescriptorTypeCsInterface && found_comm) {
            // CDC functional descriptors: subtype is the byte after bDescriptorType.
            const uint8_t* cs   = reinterpret_cast<const uint8_t*>(desc);
            const uint8_t subtype = (desc->bLength >= 3) ? cs[2] : 0;
            if (subtype == 0x06 && desc->bLength >= 5) {
                // Union Functional Descriptor: cs[3] = control interface,
                // cs[4] = first subordinate (data) interface.
                dev.data_interface = cs[4];
            }
        } else if (desc->bDescriptorType == USB_B_DESCRIPTOR_TYPE_ENDPOINT && found_comm &&
                   dev.data_interface == 0 && dev.ep_out == 0) {
            // Notification endpoint on the comm interface (interrupt IN).
            const auto* ep = reinterpret_cast<const usb_ep_desc_t*>(desc);
            if (USB_EP_DESC_GET_XFERTYPE(ep) == USB_TRANSFER_TYPE_INTR && USB_EP_DESC_GET_EP_DIR(ep)) {
                dev.ep_notify      = ep->bEndpointAddress;
                dev.ep_notify_mps  = USB_EP_DESC_GET_MPS(ep);
            }
        }
        (void)raw;
        desc = usb_parse_next_descriptor(desc, total_length, &offset);
    }

    if (!found_comm) {
        ESP_LOGW(TAG, "no CDC communication interface found");
        return false;
    }

    // If the union descriptor was absent, fall back to the next interface.
    if (dev.data_interface == 0) {
        dev.data_interface = static_cast<uint8_t>(dev.comm_interface + 1);
    }

    // Second pass: collect the bulk endpoints of the data interface.
    offset = 0;
    desc   = usb_parse_next_descriptor(reinterpret_cast<const usb_standard_desc_t*>(config_desc), total_length, &offset);

    uint8_t current_interface = 0xFF;
    while (desc != nullptr) {
        if (desc->bDescriptorType == USB_B_DESCRIPTOR_TYPE_INTERFACE) {
            const auto* intf  = reinterpret_cast<const usb_intf_desc_t*>(desc);
            current_interface = intf->bInterfaceNumber;
        } else if (desc->bDescriptorType == USB_B_DESCRIPTOR_TYPE_ENDPOINT &&
                   current_interface == dev.data_interface) {
            const auto* ep = reinterpret_cast<const usb_ep_desc_t*>(desc);
            if (USB_EP_DESC_GET_XFERTYPE(ep) == USB_TRANSFER_TYPE_BULK) {
                if (USB_EP_DESC_GET_EP_DIR(ep)) {
                    dev.ep_in      = ep->bEndpointAddress;
                    dev.ep_in_mps  = USB_EP_DESC_GET_MPS(ep);
                } else {
                    dev.ep_out     = ep->bEndpointAddress;
                    dev.ep_out_mps = USB_EP_DESC_GET_MPS(ep);
                }
            }
        }
        desc = usb_parse_next_descriptor(desc, total_length, &offset);
    }

    if (dev.ep_in == 0 || dev.ep_out == 0) {
        ESP_LOGW(TAG, "CDC data interface %u lacks bulk endpoints (in=0x%02x out=0x%02x)", dev.data_interface, dev.ep_in,
                 dev.ep_out);
        return false;
    }

    // Dump every endpoint the device declares when bring-up instrumentation is
    // enabled. This makes it possible to confirm the endpoint numbers we picked
    // actually exist and belong to the interface we claimed.
    if (kVerboseUsbLog) {
        int off = 0;
        const usb_standard_desc_t* d =
            usb_parse_next_descriptor(reinterpret_cast<const usb_standard_desc_t*>(config_desc), total_length, &off);
        uint8_t cur = 0xFF;
        while (d != nullptr) {
            if (d->bDescriptorType == USB_B_DESCRIPTOR_TYPE_INTERFACE) {
                const auto* intf = reinterpret_cast<const usb_intf_desc_t*>(d);
                cur              = intf->bInterfaceNumber;
                ESP_LOGI(TAG, "  intf %u class 0x%02x sub 0x%02x proto 0x%02x endpoints %u", intf->bInterfaceNumber,
                         intf->bInterfaceClass, intf->bInterfaceSubClass, intf->bInterfaceProtocol,
                         intf->bNumEndpoints);
            } else if (d->bDescriptorType == USB_B_DESCRIPTOR_TYPE_ENDPOINT) {
                const auto* ep = reinterpret_cast<const usb_ep_desc_t*>(d);
                ESP_LOGI(TAG, "    ep 0x%02x type %u dir %u mps %u (intf %u)", ep->bEndpointAddress,
                         (unsigned)USB_EP_DESC_GET_XFERTYPE(ep), (unsigned)USB_EP_DESC_GET_EP_DIR(ep),
                         USB_EP_DESC_GET_MPS(ep), cur);
            }
            d = usb_parse_next_descriptor(d, total_length, &off);
        }
    }

    return true;
}

}  // namespace

struct UsbSerialHost::Impl {
    // ---- configuration from Start() -------------------------------------
    UsbSerialRxCallback rx_cb       = nullptr;
    UsbSerialStateCallback state_cb = nullptr;
    void* user                      = nullptr;

    // ---- task plumbing ---------------------------------------------------
    TaskHandle_t client_task  = nullptr;
    bool task_should_exit     = false;
    bool started              = false;

    usb_host_client_handle_t client = nullptr;

    SemaphoreHandle_t lock = nullptr;

    QueueHandle_t tx_queue = nullptr;

    // ---- attached device -------------------------------------------------
    ClaimedDevice device;
    volatile bool connected = false;

    // ---- transfers -------------------------------------------------------
    usb_transfer_t* rx_transfer = nullptr;

    /// Number of outstanding CDC control requests and whether they settled.
    volatile int ctrl_requests_left  = 0;
    volatile bool ctrl_requests_done = false;

    /// Set by claimDevice() (running inside the client event callback) to ask
    /// the client task loop to finish CDC setup once the control requests land.
    volatile bool finish_pending = false;

    /// Rate limit for RX failure logging.
    uint32_t rx_error_log_count = 0;

    /// Set when a transfer reports USB_TRANSFER_STATUS_NO_DEVICE.
    volatile bool device_gone = false;

    /// Set by a failed RX transfer; the task loop retries instead of the
    /// callback, so the event pump is never blocked by a retry loop.
    volatile bool rx_retry_pending = false;

    // A small pool of OUT transfers so a queued frame can be sent while the
    // previous one is still in flight.
    usb_transfer_t* tx_transfers[kTxQueueDepth] = {};
    QueueHandle_t tx_free = nullptr;

    // ---- helpers ---------------------------------------------------------

    void lockTake()
    {
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
        }
    }
    void lockGive()
    {
        if (lock) {
            xSemaphoreGive(lock);
        }
    }

    bool claimDevice(uint8_t dev_addr);
    void finishClaim();
    void releaseDevice();
    void onDeviceGone(usb_device_handle_t handle);

    void issueLineCoding();
    void submitRx();
    void handleRxDone(usb_transfer_t* transfer);
    void handleTxDone(usb_transfer_t* transfer);

    static void clientEventCb(const usb_host_client_event_msg_t* msg, void* arg);
    static void rxDoneCb(usb_transfer_t* transfer);
    static void txDoneCb(usb_transfer_t* transfer);
    static void ctrlDoneCb(usb_transfer_t* transfer);
    static void clientTaskEntry(void* arg);
};

// ---------------------------------------------------------------------------
// Control requests
// ---------------------------------------------------------------------------

void UsbSerialHost::Impl::issueLineCoding()
{
    // Two CDC class requests: SET_LINE_CODING (0x20) then
    // SET_CONTROL_LINE_STATE (0x22, DTR|RTS). Best effort: if the device stalls
    // them we still use the bulk pipe. They are issued asynchronously; see
    // CtrlTransferCtx for why they must not be waited on here.
    const uint8_t line_coding[7] = {
        0x00, 0xC2, 0x01, 0x00,  // dwDTERate = 115200 (little endian)
        0x00,                    // bCharFormat = 1 stop bit
        0x00,                    // bParityType = none
        0x08,                    // bDataBits  = 8
    };

    ctrl_requests_done = false;
    ctrl_requests_left = 2;

    struct Request {
        bool set_coding;
        uint8_t request;
        uint16_t value;
    };
    const Request requests[2] = {
        {true, kCdcSetLineCoding, 0},
        {false, kCdcSetControlLineState, 0x0003},  // DTR | RTS
    };

    for (const auto& req : requests) {
        usb_transfer_t* transfer = nullptr;
        if (usb_host_transfer_alloc(USB_SETUP_PACKET_SIZE + sizeof(line_coding), 0, &transfer) != ESP_OK) {
            if (--ctrl_requests_left == 0) {
                ctrl_requests_done = true;
            }
            continue;
        }

        auto* ctx   = new CtrlTransferCtx();
        ctx->self   = this;
        ctx->done   = &ctrl_requests_done;

        transfer->device_handle    = device.handle;
        transfer->bEndpointAddress = 0;
        transfer->callback         = ctrlDoneCb;
        transfer->context          = ctx;
        transfer->num_bytes        = USB_SETUP_PACKET_SIZE + (req.set_coding ? sizeof(line_coding) : 0);

        auto* setup = reinterpret_cast<usb_setup_packet_t*>(transfer->data_buffer);
        setup->bmRequestType = USB_BM_REQUEST_TYPE_DIR_OUT | USB_BM_REQUEST_TYPE_TYPE_CLASS |
                               USB_BM_REQUEST_TYPE_RECIP_INTERFACE;
        setup->bRequest = req.request;
        setup->wValue   = req.value;
        setup->wIndex   = device.comm_interface;
        setup->wLength  = req.set_coding ? sizeof(line_coding) : 0;
        if (req.set_coding) {
            memcpy(transfer->data_buffer + USB_SETUP_PACKET_SIZE, line_coding, sizeof(line_coding));
        }

        if (usb_host_transfer_submit_control(client, transfer) != ESP_OK) {
            ESP_LOGW(TAG, "CDC control request 0x%02X submit failed", req.request);
            delete ctx;
            usb_host_transfer_free(transfer);
            if (--ctrl_requests_left == 0) {
                ctrl_requests_done = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Device attach / detach
// ---------------------------------------------------------------------------

bool UsbSerialHost::Impl::claimDevice(uint8_t dev_addr)
{
    if (usb_host_device_open(client, dev_addr, &device.handle) != ESP_OK) {
        ESP_LOGW(TAG, "usb_host_device_open failed for addr %u", dev_addr);
        return false;
    }

    const usb_device_desc_t* device_desc = nullptr;
    if (usb_host_get_device_descriptor(device.handle, &device_desc) != ESP_OK || device_desc == nullptr) {
        ESP_LOGW(TAG, "no device descriptor");
        usb_host_device_close(client, device.handle);
        device.handle = nullptr;
        return false;
    }
    device.vid = device_desc->idVendor;
    device.pid = device_desc->idProduct;

    const usb_config_desc_t* config_desc = nullptr;
    if (usb_host_get_active_config_descriptor(device.handle, &config_desc) != ESP_OK || config_desc == nullptr) {
        ESP_LOGW(TAG, "no active configuration descriptor");
        usb_host_device_close(client, device.handle);
        device.handle = nullptr;
        return false;
    }

    if (!parse_cdc_interfaces(config_desc, device)) {
        usb_host_device_close(client, device.handle);
        device.handle  = nullptr;
        device.valid   = false;
        return false;
    }

    if (usb_host_interface_claim(client, device.handle, device.comm_interface, 0) != ESP_OK) {
        ESP_LOGW(TAG, "cannot claim CDC comm interface %u", device.comm_interface);
        usb_host_device_close(client, device.handle);
        device.handle = nullptr;
        return false;
    }
    device.comm_claimed = true;

    if (usb_host_interface_claim(client, device.handle, device.data_interface, 0) != ESP_OK) {
        ESP_LOGW(TAG, "cannot claim CDC data interface %u", device.data_interface);
        usb_host_interface_release(client, device.handle, device.comm_interface);
        device.comm_claimed = false;
        usb_host_device_close(client, device.handle);
        device.handle = nullptr;
        return false;
    }
    device.data_claimed = true;

    snprintf(device.name, sizeof(device.name), "USB %04X:%04X", device.vid, device.pid);

    ESP_LOGI(TAG, "%s: comm intf %u, data intf %u, bulk in 0x%02x (%u), bulk out 0x%02x (%u)", device.name,
             device.comm_interface, device.data_interface, device.ep_in, device.ep_in_mps, device.ep_out,
             device.ep_out_mps);

    // Note: device.valid stays false until the CDC control requests settle in
    // finishClaim(), so no bulk transfer is submitted before then.
    issueLineCoding();

    // Kick off the bulk IN transfer only once the CDC control requests have
    // settled: an outstanding control URB in the host controller makes later
    // submits fail with ESP_ERR_INVALID_STATE, so the RX must not race them.
    //
    // NOTE: control transfers only complete inside
    // usb_host_client_handle_events(). This function runs from the client
    // event callback, which is *inside* that function, so we must NOT wait here.
    // Instead the task loop picks this up via finish_pending and completes the
    // setup once the request callbacks have fired.
    ESP_LOGI(TAG, "%s: interfaces claimed, waiting for CDC control requests", device.name);
    finish_pending = true;
    return true;
}

void UsbSerialHost::Impl::finishClaim()
{
    // Called from the client task loop, so usb_host_client_handle_events() is
    // free to run and the control transfer callbacks can fire.
    if (ctrl_requests_left > 0) {
        return;  // still waiting for the CDC control requests
    }

    finish_pending = false;

    device.valid = true;
    submitRx();

    lockTake();
    connected = true;
    lockGive();

    ESP_LOGI(TAG, "claim complete: comm intf %u, data intf %u, bulk in 0x%02x (%u), bulk out 0x%02x (%u)",
             device.comm_interface, device.data_interface, device.ep_in, device.ep_in_mps, device.ep_out,
             device.ep_out_mps);

    if (state_cb) {
        state_cb(true, user);
    }
}

void UsbSerialHost::Impl::releaseDevice()
{
    if (device.handle == nullptr) {
        return;
    }

    // Cancel pending work before tearing the handles down.
    rx_retry_pending = false;
    device_gone      = false;

    // Cancel the in-flight IN transfer first so it does not fire against a
    // freed device handle.
    if (rx_transfer != nullptr) {
        usb_host_endpoint_halt(device.handle, device.ep_in);
        usb_host_endpoint_flush(device.handle, device.ep_in);
        usb_host_transfer_free(rx_transfer);
        rx_transfer = nullptr;
    }

    if (device.data_claimed) {
        usb_host_interface_release(client, device.handle, device.data_interface);
    }
    if (device.comm_claimed) {
        usb_host_interface_release(client, device.handle, device.comm_interface);
    }

    usb_host_device_close(client, device.handle);
    device = ClaimedDevice{};

    if (tx_free != nullptr) {
        xQueueReset(tx_free);
        for (size_t i = 0; i < kTxQueueDepth; ++i) {
            if (tx_transfers[i] != nullptr) {
                uint8_t dummy = 0;
                xQueueSend(tx_free, &dummy, 0);
            }
        }
    }
}

void UsbSerialHost::Impl::onDeviceGone(usb_device_handle_t handle)
{
    const bool ours = (device.handle == handle && device.handle != nullptr);
    if (!ours) {
        return;
    }

    device_gone = true;

    lockTake();
    const bool was_connected = connected;
    connected                = false;
    lockGive();

    releaseDevice();

    // Report the detach exactly once: the RX transfer also observes NO_DEVICE
    // and would otherwise produce a second notification.
    if (was_connected && state_cb) {
        state_cb(false, user);
    }
    ESP_LOGI(TAG, "CDC device detached");
}

// ---------------------------------------------------------------------------
// Bulk transfers
// ---------------------------------------------------------------------------

void UsbSerialHost::Impl::submitRx()
{
    if (!device.valid || device.handle == nullptr || task_should_exit) {
        return;
    }

    if (rx_transfer == nullptr) {
        if (usb_host_transfer_alloc(kTransferSize, 0, &rx_transfer) != ESP_OK || rx_transfer == nullptr) {
            ESP_LOGE(TAG, "cannot allocate RX transfer");
            return;
        }
        rx_transfer->callback         = rxDoneCb;
        rx_transfer->context          = this;
        rx_transfer->bEndpointAddress = device.ep_in;
        rx_transfer->device_handle    = device.handle;
    }

    rx_transfer->num_bytes = kTransferSize;
    const esp_err_t err    = usb_host_transfer_submit(rx_transfer);
    if (err != ESP_OK) {
        if (rx_error_log_count < 4) {
            ++rx_error_log_count;
            ESP_LOGW(TAG, "RX submit failed: %s (ep=0x%02x)", esp_err_to_name(err), device.ep_in);
        }
        // The task loop retries after a delay, keeping the event pump live.
        rx_retry_pending = true;
    }
}

void UsbSerialHost::Impl::handleRxDone(usb_transfer_t* transfer)
{
    if (transfer->status == USB_TRANSFER_STATUS_COMPLETED && transfer->actual_num_bytes > 0) {
        if (rx_cb) {
            rx_cb(transfer->data_buffer, static_cast<size_t>(transfer->actual_num_bytes), user);
        }
        submitRx();
        return;
    }

    // Log sparingly: a failing RX repeats and would flood the console.
    if (rx_error_log_count < 4) {
        ++rx_error_log_count;
        ESP_LOGW(TAG, "RX ended: status=%d bytes=%d (0=completed 4=stall 5=overflow 7=no_device)",
                 (int)transfer->status, transfer->actual_num_bytes);
    }

    // The device is gone. Stop retrying: the client event callback reports the
    // detach, and re-submitting here would busy-spin on a dead endpoint and
    // duplicate the detach notification.
    if (transfer->status == USB_TRANSFER_STATUS_NO_DEVICE) {
        device_gone = true;
        return;
    }

    if (!device.valid || device.handle == nullptr || task_should_exit) {
        return;
    }

    switch (transfer->status) {
        case USB_TRANSFER_STATUS_CANCELED:
            // Expected during releaseDevice(); do not retry.
            return;
        case USB_TRANSFER_STATUS_STALL:
            // Clear the halt condition, then retry on the next poll.
            usb_host_endpoint_clear(device.handle, device.ep_in);
            break;
        default:
            // Transient error: retry from the task loop rather than immediately,
            // so the event pump keeps running (blocking it starves control
            // transfers as well).
            break;
    }
    rx_retry_pending = true;
}

void UsbSerialHost::Impl::handleTxDone(usb_transfer_t* transfer)
{
    if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
        ESP_LOGW(TAG, "TX ended with status %d (%d/%d bytes)", (int)transfer->status, transfer->actual_num_bytes,
                 transfer->num_bytes);
    }

    // Return the transfer object to the free pool.
    if (tx_free != nullptr) {
        uint8_t dummy = 0;
        xQueueSend(tx_free, &dummy, 0);
    }
}

void UsbSerialHost::Impl::rxDoneCb(usb_transfer_t* transfer)
{
    auto* self = static_cast<Impl*>(transfer->context);
    if (self != nullptr) {
        self->handleRxDone(transfer);
    }
}

void UsbSerialHost::Impl::txDoneCb(usb_transfer_t* transfer)
{
    auto* self = static_cast<Impl*>(transfer->context);
    if (self != nullptr) {
        self->handleTxDone(transfer);
    }
}

void UsbSerialHost::Impl::ctrlDoneCb(usb_transfer_t* transfer)
{
    auto* ctx = static_cast<CtrlTransferCtx*>(transfer->context);
    if (ctx == nullptr) {
        return;
    }

    auto* self = static_cast<Impl*>(ctx->self);
    if (self != nullptr) {
        if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
            const auto* setup = reinterpret_cast<const usb_setup_packet_t*>(transfer->data_buffer);
            ESP_LOGW(TAG, "CDC control request 0x%02X finished with status %d", (unsigned)setup->bRequest,
                     (int)transfer->status);
        }
        if (ctx->done != nullptr && self->ctrl_requests_left > 0) {
            if (--self->ctrl_requests_left == 0) {
                *ctx->done = true;
            }
        }
    }

    delete ctx;
    usb_host_transfer_free(transfer);
}

// ---------------------------------------------------------------------------
// Client task
// ---------------------------------------------------------------------------

void UsbSerialHost::Impl::clientEventCb(const usb_host_client_event_msg_t* msg, void* arg)
{
    auto* self = static_cast<Impl*>(arg);
    if (self == nullptr || msg == nullptr) {
        return;
    }

    switch (msg->event) {
        case USB_HOST_CLIENT_EVENT_NEW_DEV:
            if (!self->device.valid) {
                self->claimDevice(msg->new_dev.address);
            } else {
                ESP_LOGI(TAG, "ignoring additional device at addr %u", msg->new_dev.address);
            }
            break;
        case USB_HOST_CLIENT_EVENT_DEV_GONE:
            self->onDeviceGone(msg->dev_gone.dev_hdl);
            break;
        default:
            break;
    }
}

void UsbSerialHost::Impl::clientTaskEntry(void* arg)
{
    auto* self = static_cast<Impl*>(arg);

    const usb_host_client_config_t client_config = {
        .is_synchronous    = false,
        .max_num_event_msg = 5,
        .async =
            {
                .client_event_callback = clientEventCb,
                .callback_arg          = self,
            },
    };

    if (usb_host_client_register(&client_config, &self->client) != ESP_OK) {
        ESP_LOGE(TAG, "usb_host_client_register failed");
        self->client = nullptr;
        self->client_task = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    while (!self->task_should_exit) {
        // Service client events. This is what drives control transfer
        // completion, so it must run even while a claim is pending.
        usb_host_client_handle_events(self->client, kClientPollTicks);

        // The device is claimed; finish CDC setup as soon as the control
        // requests have completed (see claimDevice / finish_pending).
        if (self->finish_pending && self->ctrl_requests_left == 0) {
            self->finishClaim();
        }

        // Retry plumbing for bulk IN, done here so the event pump stays live.
        if (self->rx_retry_pending && !self->task_should_exit) {
            self->rx_retry_pending = false;
            // Space retries out; a persistently failing endpoint would
            // otherwise spin this loop.
            vTaskDelay(pdMS_TO_TICKS(20));
            self->submitRx();
        }

        // Drain the transmission queue.
        TxChunk chunk;
        while (xQueueReceive(self->tx_queue, &chunk, 0) == pdTRUE) {
            if (!self->device.valid || self->device.handle == nullptr) {
                continue;  // device went away; drop
            }

            uint8_t index = 0;
            if (xQueueReceive(self->tx_free, &index, pdMS_TO_TICKS(200)) != pdTRUE) {
                ESP_LOGW(TAG, "TX pool exhausted, dropping %u bytes", (unsigned)chunk.length);
                continue;
            }

            usb_transfer_t* transfer = self->tx_transfers[index];
            if (transfer == nullptr) {
                uint8_t dummy = index;
                xQueueSend(self->tx_free, &dummy, 0);
                continue;
            }

            memcpy(transfer->data_buffer, chunk.data, chunk.length);
            transfer->num_bytes       = static_cast<int>(chunk.length);
            transfer->device_handle   = self->device.handle;
            transfer->bEndpointAddress = self->device.ep_out;

            if (usb_host_transfer_submit(transfer) != ESP_OK) {
                ESP_LOGW(TAG, "TX submit failed (%u bytes)", (unsigned)chunk.length);
                uint8_t dummy = index;
                xQueueSend(self->tx_free, &dummy, 0);
            }
        }
    }

    usb_host_client_deregister(self->client);
    self->client      = nullptr;
    self->client_task = nullptr;
    vTaskDelete(nullptr);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

UsbSerialHost::~UsbSerialHost()
{
    Stop();
    delete _impl;
    _impl = nullptr;
}

esp_err_t UsbSerialHost::Start(UsbSerialRxCallback rx_cb, UsbSerialStateCallback state_cb, void* user)
{
    if (_impl != nullptr && _impl->started) {
        return ESP_ERR_INVALID_STATE;
    }

    _impl = new Impl();
    if (_impl == nullptr) {
        return ESP_ERR_NO_MEM;
    }

    _impl->rx_cb    = rx_cb;
    _impl->state_cb = state_cb;
    _impl->user     = user;

    _impl->lock = xSemaphoreCreateMutex();
    _impl->tx_queue = xQueueCreate(kTxQueueDepth, sizeof(TxChunk));
    _impl->tx_free  = xQueueCreate(kTxQueueDepth, sizeof(uint8_t));
    if (_impl->lock == nullptr || _impl->tx_queue == nullptr || _impl->tx_free == nullptr) {
        return ESP_ERR_NO_MEM;
    }

    // Pre-allocate the OUT transfer pool.
    for (size_t i = 0; i < kTxQueueDepth; ++i) {
        if (usb_host_transfer_alloc(kTransferSize, 0, &_impl->tx_transfers[i]) != ESP_OK) {
            ESP_LOGE(TAG, "cannot allocate TX transfer %u", (unsigned)i);
            return ESP_ERR_NO_MEM;
        }
        _impl->tx_transfers[i]->callback         = Impl::txDoneCb;
        _impl->tx_transfers[i]->context          = _impl;
        _impl->tx_transfers[i]->bEndpointAddress = 0;  // set per transfer
        const uint8_t index                      = static_cast<uint8_t>(i);
        xQueueSend(_impl->tx_free, &index, 0);
    }

    // Install the USB host library. The Tab5 BSP also exposes
    // bsp_usb_host_start(), but we need control over the client so we do it
    // here; the BSP version installs no client.
    const usb_host_config_t host_config = {
        .skip_phy_setup = false,
        .intr_flags     = ESP_INTR_FLAG_LEVEL1,
    };
    const esp_err_t err = usb_host_install(&host_config);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "usb_host_install failed: %s", esp_err_to_name(err));
        return err;
    }

    // Library event task: required so the stack can free devices.
    xTaskCreate(
        [](void*) {
            while (true) {
                uint32_t flags = 0;
                usb_host_lib_handle_events(portMAX_DELAY, &flags);
                if (flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
                    usb_host_device_free_all();
                }
            }
        },
        "usb_lib", 4096, nullptr, 10, nullptr);

    if (xTaskCreate(Impl::clientTaskEntry, "usb_cdc", 8192, _impl, 5, &_impl->client_task) != pdTRUE) {
        ESP_LOGE(TAG, "cannot create USB CDC client task");
        return ESP_ERR_NO_MEM;
    }

    _impl->started = true;
    ESP_LOGI(TAG, "USB CDC host started");
    return ESP_OK;
}

void UsbSerialHost::Stop()
{
    if (_impl == nullptr || !_impl->started) {
        return;
    }

    _impl->task_should_exit = true;
    // Give the client task a chance to deregister cleanly.
    for (int i = 0; i < 100 && _impl->client_task != nullptr; ++i) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    for (size_t i = 0; i < kTxQueueDepth; ++i) {
        if (_impl->tx_transfers[i] != nullptr) {
            usb_host_transfer_free(_impl->tx_transfers[i]);
            _impl->tx_transfers[i] = nullptr;
        }
    }

    _impl->started = false;
}

bool UsbSerialHost::Write(const uint8_t* data, size_t len)
{
    if (_impl == nullptr || !_impl->started || data == nullptr || len == 0) {
        return false;
    }

    size_t sent = 0;
    while (sent < len) {
        TxChunk chunk;
        const size_t take = (len - sent > kTransferSize) ? kTransferSize : (len - sent);
        memcpy(chunk.data, data + sent, take);
        chunk.length = take;
        if (xQueueSend(_impl->tx_queue, &chunk, pdMS_TO_TICKS(100)) != pdTRUE) {
            ESP_LOGW(TAG, "TX queue full, dropping %u bytes", (unsigned)(len - sent));
            return false;
        }
        sent += take;
    }
    return true;
}

bool UsbSerialHost::IsConnected() const
{
    return _impl != nullptr && _impl->connected;
}

void UsbSerialHost::GetIds(uint16_t* vid, uint16_t* pid) const
{
    if (vid != nullptr) {
        *vid = (_impl != nullptr) ? _impl->device.vid : 0;
    }
    if (pid != nullptr) {
        *pid = (_impl != nullptr) ? _impl->device.pid : 0;
    }
}

const char* UsbSerialHost::GetDeviceName() const
{
    if (_impl == nullptr || !_impl->device.valid) {
        return "no device";
    }
    return _impl->device.name;
}

}  // namespace chameleon
