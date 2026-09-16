// SPDX-License-Identifier: MIT
//
// ChameleonUltra on M5Stack Tab5 - firmware entry point.
//
// Bring-up order matters on this board (ESP32-P4 + ESP32-C6 two-chip design):
//   1. NVS
//   2. BSP I2C + IO expander (touch reset, panel reset, USB-A 5V rail all hang
//      off the PI4IOE5V6408 expanders)
//   3. display + LVGL + GT911 touch
//   4. physical keyboard (optional accessory, hot-pluggable)
//   5. Chameleon transport (USB host CDC-ACM by default)
//   6. UI

#include <esp_err.h>
#include <esp_log.h>
#include <nvs_flash.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <bsp/m5stack_tab5.h>

#include "app_chameleon.h"

static const char* TAG = "main";

extern "C" void app_main(void)
{
    // Stage logs: the console is the only debug channel on this board, and a
    // hang inside a BSP call shows up as "the last stage printed" here.
    ESP_LOGW(TAG, "stage 1/6: chameleon tab5 port starting");

    // --- NVS -----------------------------------------------------------------
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGW(TAG, "stage 2/6: nvs ready");

    // --- I2C + IO expander + touch reset ------------------------------------
    // This ordering is required and is exactly what the working Tab5 firmware
    // does (see M5Tab5-UserDemo monitor logs: "i2c init", "reset tp",
    // "Detected ST7121 touch controller"):
    //
    //   1. bsp_i2c_init()                     - brings up the SYS I2C bus
    //   2. bsp_io_expander_pi4ioe_init()      - creates the PI4IOE device
    //                                           handles used by bsp_reset_tp()
    //   3. bsp_reset_tp()                     - pulses the touch controller
    //                                           reset via IO expander P4/P5
    //
    // Step 3 is NOT optional: without it the touch controller stays unresponsive
    // to I2C, bsp_detect_display_type() falls through to its ILI9881C default,
    // and esp_lcd_ili9881c then hangs forever reading the panel ID over the
    // MIPI-DSI DBI link (esp_lcd_ili9881c.c: panel_io_dbi_rx_param spins on the
    // DSI read FIFO that a non-ILI9881C panel never fills).
    ESP_ERROR_CHECK(bsp_i2c_init());
    bsp_io_expander_pi4ioe_init(bsp_i2c_get_handle());
    bsp_reset_tp();
    ESP_LOGW(TAG, "stage 2b/6: i2c + io expander + touch reset done");

    // --- Display, LVGL and touch --------------------------------------------
    // Display configuration mirrors the working Tab5 firmware
    // (M5Tab5-UserDemo hal_esp32.cpp): full screen sized buffers in PSRAM with
    // double buffering. This matters for two reasons:
    //   - the PPA based rotation needs cache line aligned buffers, and a large
    //     PSRAM allocation is guaranteed to be aligned (see the
    //     CONFIG_LV_DRAW_BUF_ALIGN comment in sdkconfig.defaults)
    //   - the portrait panel is driven in landscape, so a full screen buffer
    //     keeps the per-frame rotation cost predictable
    bsp_display_cfg_t disp_cfg = {
        .lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
        .buffer_size   = BSP_LCD_H_RES * BSP_LCD_V_RES,
        .double_buffer = true,
        .flags         = {
            .buff_dma    = true,
            .buff_spiram = true,
            .sw_rotate   = true,
        }};
    lv_display_t* display = bsp_display_start_with_config(&disp_cfg);
    if (display == nullptr) {
        ESP_LOGE(TAG, "bsp_display_start_with_config failed");
        return;
    }
    ESP_LOGW(TAG, "stage 3/6: display + lvgl + touch up (panel=%s)", bsp_display_get_panel_ic());

    // The panel is a 720x1280 portrait MIPI-DSI panel; the Chameleon UI is a
    // landscape table/keyboard layout, so rotate the LVGL display 90 degrees.
    // esp_lvgl_port performs this rotation with the PPA engine.
    lv_display_set_rotation(display, LV_DISPLAY_ROTATION_90);
    bsp_display_backlight_on();
    ESP_LOGW(TAG, "stage 4/6: rotated %dx%d, backlight on", (int)lv_display_get_horizontal_resolution(display),
             (int)lv_display_get_vertical_resolution(display));

    // --- Chameleon UI --------------------------------------------------------
    if (!chameleon_app::Start()) {
        ESP_LOGE(TAG, "chameleon_app::Start failed");
        return;
    }
    ESP_LOGW(TAG, "stage 5/6: ui built");

    // --- Chameleon transport -------------------------------------------------
    chameleon_app::StartTransport();
    ESP_LOGW(TAG, "stage 6/6: transport started, entering idle loop");

    // The LVGL task owns the UI; this task only supervises.
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
