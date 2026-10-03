#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
int serve_local_broker(std::wstring_view profile, std::wstring_view root = {});
int connect_local_control(std::wstring_view profile, std::wstring_view root = {});
}
