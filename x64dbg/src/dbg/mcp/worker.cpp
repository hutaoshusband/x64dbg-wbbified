#include "worker.h"
#include "bootstrap.h"
#include "build_identity.h"
#include "lifecycle.h"

namespace wininspect::mcp
{
Checked<Json> worker_build_info()
{
    return component_build_info(NativeComponent::WorkerAdapter);
}

Checked<Json> register_worker(LocalPipe& pipe, const NativeProcessIdentity& expectedBroker, std::string_view brokerBuildId,
    const InstanceId& instance, WorkerMode mode, std::uint32_t timeoutMs)
{
    try
    {
        if(instance.value.empty() || instance.value.size() > 184) throw ContractError{"invalid_argument", "instanceId", "Worker instance identity is invalid"};
        const auto mode_name = worker_mode_name(mode);
        auto handshake = pipe.handshake(expectedBroker, brokerBuildId, timeoutMs);
        if(const auto* error = std::get_if<ContractError>(&handshake)) return *error;
        const Json request = {{"instanceId", instance.value}, {"component", "worker_adapter"}, {"buildId", BuildId}, {"requestedMode", mode_name}};
        auto sent = pipe.send(IpcMessageKind::Request, 2, worker_registration_envelope(instance, expectedBroker.creationTime, request), timeoutMs);
        if(const auto* error = std::get_if<ContractError>(&sent)) return *error;
        auto received = pipe.receive(timeoutMs);
        if(const auto* error = std::get_if<ContractError>(&received)) return *error;
        const auto& frame = std::get<IpcFrame>(received);
        const Json expected = {{"instanceId", instance.value}, {"requestedMode", mode_name}, {"registrationState", "registered"}, {"engineReady", false},
            {"process", native_process_json(pipe.owner())}, {"buildId", BuildId}};
        if(frame.header.kind != IpcMessageKind::Response || frame.header.requestId != 2 ||
            frame.envelope != worker_registration_envelope(instance, expectedBroker.creationTime, expected))
            throw ContractError{"worker_registration_mismatch", "", "Worker admission reply does not match its actual process or reserved instance"};
        auto acknowledged = pipe.send(IpcMessageKind::Request, 2,
            worker_registration_envelope(instance, expectedBroker.creationTime, {{"registered", true}}), timeoutMs);
        if(const auto* error = std::get_if<ContractError>(&acknowledged)) return *error;
        return expected;
    }
    catch(const ContractError& error) { pipe.close(); return error; }
}
}
