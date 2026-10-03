#pragma once

#include "platform.h"
#include <Windows.h>

namespace wininspect::mcp
{
Checked<NativeProcessIdentity> capture_held_process(HANDLE process);
}
