idf_component_register(
    SRCS
        "main.cpp"
        "app_chameleon.cpp"
        "app_context.cpp"
        "ui.cpp"
        "pages.cpp"
        "pages_card.cpp"
        "pages_keys.cpp"
        "pages_emulate.cpp"
        "pages_mf0.cpp"
        "pages_tools.cpp"
        # hardnested_acquire.cpp is deliberately ESP-IDF free (it is compiled on
        # the host by tools/verify_hardnested_acquire.py), so it must stay out of
        # any target-only include path.
        "hardnested_acquire.cpp"
    INCLUDE_DIRS
        "."
    REQUIRES
        m5stack_tab5
        chameleon
        chameleon_crypto
        m5_tab5_keyboard
        lvgl__lvgl
        esp_driver_gpio
        esp_driver_i2c
        esp_timer
    PRIV_REQUIRES
        nvs_flash
        esp_lcd
        usb
        freertos
        # StartHardNested() puts the nonce buffer in PSRAM (heap_caps_malloc).
        heap
)
