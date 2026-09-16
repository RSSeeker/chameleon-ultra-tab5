// SPDX-License-Identifier: MIT
//
// Chameleon application facade.
//
// All state lives in app::Context (see app_context.h); this file only exposes
// the entry points that main.cpp drives, so the UI pages never need to include
// the app header (which would be circular).

#include "app_chameleon.h"

#include "app_context.h"

bool chameleon_app::Start()
{
    return app::Context::Get().StartUi();
}

void chameleon_app::StartTransport()
{
    app::Context::Get().StartTransport();
}

void chameleon_app::Stop()
{
    app::Context::Get().Stop();
}
