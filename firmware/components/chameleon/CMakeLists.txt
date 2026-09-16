idf_component_register(
    SRCS
        "src/chameleon_protocol.cpp"
        "src/chameleon_commands.cpp"
        "src/chameleon_client.cpp"
        "src/sniff_decoder.cpp"
        "src/usb_serial_host.cpp"
    INCLUDE_DIRS
        "include"
    REQUIRES
        esp_driver_gpio
    PRIV_REQUIRES
        esp_timer
        freertos
        # USB host stack: this component implements its own CDC-ACM class
        # driver on top of the IDF USB Host Library (see usb_serial_host.h).
        usb
)
