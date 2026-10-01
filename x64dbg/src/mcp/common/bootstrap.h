#pragma once

#include "platform.h"

namespace wininspect::mcp
{
enum class NativeComponent { Broker, Connector, WorkerAdapter };
Checked<Json> component_build_info(NativeComponent component);
int native_component_main(NativeComponent component, int argc, wchar_t** argv);
}
