# M5Stack Tab5 Keyboard (SKU A164)
#
# Vendored from M5Tab5-Keyboard-UserDemo (MIT). The upstream component declares a
# dependency on the third party espressif/i2c_bus component; this build is fully
# offline and that component is not available, so src/i2c_bus.h +
# src/i2c_bus_compat.cpp supply the handful of symbols the driver references,
# implemented over the native ESP-IDF i2c_master driver.
#
# The driver is opened with the native overload
# (begin(port, addr, sda, scl, speed, intPin, mode)), so the shimmed code paths
# are never taken at runtime.

idf_component_register(
    SRCS
        "src/m5_tab5_keyboard.cpp"
        "src/i2c_bus_compat.cpp"
    INCLUDE_DIRS
        "src"
    REQUIRES
        esp_driver_gpio
        esp_driver_i2c
)
