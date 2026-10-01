#include "worker.h"
#include "bootstrap.h"

namespace wininspect::mcp
{
Checked<Json> worker_build_info()
{
    return component_build_info(NativeComponent::WorkerAdapter);
}
}
