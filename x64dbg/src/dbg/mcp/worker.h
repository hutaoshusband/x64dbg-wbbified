#pragma once

#include "contracts.h"
#include "worker_registry.h"

namespace wininspect::mcp
{
Checked<Json> worker_build_info();
Checked<Json> register_worker(LocalPipe& pipe, const NativeProcessIdentity& expectedBroker, std::string_view brokerBuildId,
    const InstanceId& instance, WorkerMode mode, std::uint32_t timeoutMs);
}
