# ChameleonUltra on M5Stack Tab5
#
# Standalone ESP-IDF project (target: esp32p4).
# Port of the ChameleonUltra Python CLI (RfidResearchGroup/ChameleonUltra, software/)
# to the M5Stack Tab5 with touch + physical keyboard input, talking to the
# Chameleon Ultra over USB (CDC-ACM host) or BLE (experimental).
#
# Reference projects:
#   M5Tab5-UserDemo          -> BSP, display/touch bring-up, mooncake app framework
#   M5Tab5-Keyboard-UserDemo -> physical keyboard driver, USB host usage

cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(chameleon_tab5)
