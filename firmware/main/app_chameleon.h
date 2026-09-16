// SPDX-License-Identifier: MIT
//
// Chameleon application facade. Owns the UI root and the Chameleon session.
//
// Stage 1 (current): bring-up shell that proves display + touch + USB CDC and
// shows live transport state. The navigation shell, slot manager and card
// operations are layered on top of this in the next stages.

#pragma once

namespace chameleon_app {

/**
 * @brief Build the UI.
 *
 * Must be called with the LVGL display already initialised. Takes the LVGL
 * lock internally.
 *
 * @return true on success
 */
bool Start();

/**
 * @brief Start the Chameleon transport layer (USB CDC host).
 *
 * Called after Start(); the UI observes the transport through callbacks, so
 * this can be started independently of the UI being ready.
 */
void StartTransport();

/**
 * @brief Tear everything down (transport + UI).
 */
void Stop();

}  // namespace chameleon_app
