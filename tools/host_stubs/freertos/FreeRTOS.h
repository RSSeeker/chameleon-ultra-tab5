// SPDX-License-Identifier: MIT
//
// Host-test stand-in for FreeRTOS, used by tools/verify_client.py.
//
// chameleon_client.cpp only needs the tick API: Request() polls for the response
// with a deadline. On the host the transport answers synchronously, so the delay
// is a no-op and a monotonic microsecond counter is enough for the deadline.
//
// Not part of the firmware build.

#pragma once

#include <stdint.h>
#include <time.h>

typedef uint32_t TickType_t;

#define configTICK_RATE_HZ 1000
#define portTICK_PERIOD_MS 1
#define pdMS_TO_TICKS(ms)  ((TickType_t)(ms))

static inline uint64_t host_tick_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static inline TickType_t xTaskGetTickCount(void)
{
    return (TickType_t)host_tick_ms();
}

static inline void vTaskDelay(TickType_t ticks)
{
    (void)ticks;
}
