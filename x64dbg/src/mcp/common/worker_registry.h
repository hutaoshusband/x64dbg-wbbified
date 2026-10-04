#pragma once

#include "local_pipe.h"
#include <map>
#include <mutex>

namespace wininspect::mcp
{
enum class WorkerMode { Gui, Headless };

class WorkerRegistry
{
public:
    WorkerRegistry();
    Checked<InstanceId> reserve(HANDLE trustedProcess, const NativeProcessIdentity& expected, std::string_view buildId, WorkerMode mode);
    Checked<Json> admit(LocalPipe& pipe, const InstanceId& instance, std::uint32_t timeoutMs);
    Checked<bool> unregister(const InstanceId& instance);
    Json registered_workers();
private:
    struct Entry;
    NativeProcessIdentity owner_;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Entry>> entries_;
};

std::string worker_mode_name(WorkerMode mode);
Json worker_registration_envelope(const InstanceId& instance, std::uint64_t brokerGeneration, const Json& payload);
}
