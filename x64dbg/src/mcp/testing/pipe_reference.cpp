#include "pipe_reference.h"
#include "local_pipe.h"
#include "build_identity.h"
#include "lifecycle.h"
#include "worker_registry.h"
#include "worker.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>

using namespace wininspect::mcp;

namespace
{
template<typename Value>
Value require_pipe_value(Checked<Value> value)
{
    if(const auto* error = std::get_if<ContractError>(&value)) throw *error;
    return std::get<Value>(std::move(value));
}

std::filesystem::path reference_path(const Json& input, const char* field)
{
    return std::filesystem::path(require_pipe_value(launch_utf16(input.at(field).get<std::string>())));
}

void write_receipt(const std::filesystem::path& path, const Json& value)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << value.dump();
    file.flush();
    if(!file) throw std::runtime_error("Cannot write private pipe fixture receipt");
}

NativeProcessIdentity expected_identity(const Json& value)
{
    if(const auto error = validate_contract("NativeProcessIdentity", value)) throw *error;
    const auto& image = value.at("image");
    return {value.at("pid").get<std::uint32_t>(), require_pipe_value(parse_decimal64(value.at("creationTime").get<std::string>())),
        value.at("sessionId").get<std::uint32_t>(), value.at("userSid").get<std::string>(), value.at("logonSid").get<std::string>(),
        value.at("integrity").get<std::string>(), value.at("elevated").get<bool>(), value.at("architecture") == "x64" ? Architecture::X64 : Architecture::X32,
        {image.at("path").get<std::string>(), image.at("sha256").get<std::string>(), require_pipe_value(parse_decimal64(image.at("size").get<std::string>())),
            image.at("volumeSerial").get<std::uint32_t>(), require_pipe_value(parse_decimal64(image.at("fileIndex").get<std::string>()))}};
}
}

Json local_pipe_reference(const Json& input)
{
    try
    {
        const auto role = input.at("role").get<std::string>();
        const auto installation = input.at("installation").get<std::string>();
        const auto profile = input.at("profile").get<std::string>();
        const auto channel = input.at("channel").get<std::string>();
        const auto timeout = input.at("timeoutMs").get<std::uint32_t>();
        auto pipe = require_pipe_value(role == "client" ? LocalPipe::connect(installation, profile, channel, timeout) : LocalPipe::create_first(installation, profile, channel));
        const auto native_name = require_pipe_value(launch_utf8(pipe->name()));
        if(role == "first") return {{"valid", true}, {"name", native_name}};
        if(role != "server" && role != "client") throw ContractError{"invalid_argument", "role", "Unknown pipe fixture role"};
        if(role == "server")
        {
            write_receipt(reference_path(input, "readyPath"), {{"name", native_name}, {"identity", native_process_json(pipe->owner())}, {"buildId", BuildId}});
            require_pipe_value(pipe->accept(timeout));
        }
        const auto peer = require_pipe_value(pipe->observe_peer());
        require_pipe_value(pipe->handshake(expected_identity(input.at("expectedPeer")), input.at("expectedBuildId").get<std::string>(), timeout));
        const Json context = {{"brokerGeneration", decimal64(role == "server" ? pipe->owner().creationTime : peer.creationTime)}};
        const auto envelope = [&](const Json& payload) -> Json { return {{"context", context}, {"deadlineUtcMs", "0"}, {"authenticationContextId", "fixture-channel"}, {"payload", payload}}; };
        Json observed;
        if(role == "server")
        {
            const auto request = require_pipe_value(pipe->receive(timeout));
            const auto& payload = request.envelope.at("payload");
            const auto schema = closed_object_schema({{"left", bounded_integer_schema(0, 1000)}, {"right", bounded_integer_schema(0, 1000)},
                {"text", string_schema("utf8-text", 400000)}}, {"left", "right", "text"});
            if(auto error = validate_schema(schema, payload)) throw *error;
            if(request.header.kind != IpcMessageKind::Request || request.header.requestId != 42) throw ContractError{"invalid_frame", "", "Fixture request correlation is invalid"};
            observed = {{"value", payload.at("left").get<std::uint32_t>() * payload.at("right").get<std::uint32_t>()},
                {"textSha256", require_pipe_value(sha256_bytes(payload.at("text").get<std::string>()))}};
            write_receipt(reference_path(input, "witnessPath"), observed);
            require_pipe_value(pipe->send(IpcMessageKind::Response, 42, envelope(observed), timeout));
            const auto release = reference_path(input, "releasePath");
            const auto expires = GetTickCount64() + 10000;
            while(!std::filesystem::exists(release) && GetTickCount64() < expires) Sleep(10);
            if(!std::filesystem::exists(release)) throw ContractError{"ipc_timeout", "", "Private fixture release was not observed"};
        }
        else
        {
            require_pipe_value(pipe->send(IpcMessageKind::Request, 42, envelope(input.at("payload")), timeout));
            const auto response = require_pipe_value(pipe->receive(timeout));
            if(response.header.kind != IpcMessageKind::Response || response.header.requestId != 42) throw ContractError{"invalid_frame", "", "Fixture response correlation is invalid"};
            observed = response.envelope.at("payload");
        }
        return {{"valid", true}, {"peer", native_process_json(peer)}, {"owner", native_process_json(pipe->owner())}, {"name", native_name}, {"observed", observed}};
    }
    catch(const ContractError& error)
    {
        return {{"valid", false}, {"error", error_json(error)}};
    }
}

Json worker_registry_reference(const Json& input)
{
    struct ProcessCloser { void operator()(void* value) const { if(value) CloseHandle(value); } };
    try
    {
        const auto role = input.at("role").get<std::string>();
        const auto expected = expected_identity(input.at("expectedPeer"));
        if(input.at("requestedMode") != "gui" && input.at("requestedMode") != "headless") throw ContractError{"invalid_argument", "requestedMode", "Worker fixture mode is invalid"};
        const auto mode = input.at("requestedMode") == "gui" ? WorkerMode::Gui : WorkerMode::Headless;
        const auto timeout = input.at("timeoutMs").get<std::uint32_t>();
        const auto peer_build = input.at("expectedBuildId").get<std::string>();
        if(role == "client")
        {
            auto pipe = require_pipe_value(LocalPipe::connect(input.at("installation").get<std::string>(), input.at("profile").get<std::string>(), input.at("channel").get<std::string>(), timeout));
            const auto admitted = require_pipe_value(register_worker(*pipe, expected, peer_build, {input.at("instanceId").get<std::string>()}, mode, timeout));
            write_receipt(reference_path(input, "admittedPath"), admitted);
            const auto release = reference_path(input, "releasePath");
            const auto expires = GetTickCount64() + 10000;
            while(!std::filesystem::exists(release) && GetTickCount64() < expires) Sleep(10);
            if(!std::filesystem::exists(release)) throw ContractError{"ipc_timeout", "", "Worker fixture release was not observed"};
            return {{"valid", true}, {"admitted", admitted}};
        }
        if(role != "server" && role != "reserve") throw ContractError{"invalid_argument", "role", "Unknown worker registry fixture role"};
        const std::unique_ptr<void, ProcessCloser> process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expected.pid));
        if(!process) throw ContractError{"process_identity_unavailable", "", "Cannot open the private worker generation"};
        WorkerRegistry registry;
        const auto instance = require_pipe_value(registry.reserve(process.get(), expected, peer_build, mode));
        if(role == "reserve") return {{"valid", true}, {"instanceId", instance.value}, {"workers", registry.registered_workers()}};
        const auto duplicate = registry.reserve(process.get(), expected, peer_build, mode);
        if(!std::holds_alternative<ContractError>(duplicate)) throw ContractError{"internal_error", "", "Duplicate worker reservation was accepted"};
        auto pipe = require_pipe_value(LocalPipe::create_first(input.at("installation").get<std::string>(), input.at("profile").get<std::string>(), input.at("channel").get<std::string>()));
        write_receipt(reference_path(input, "readyPath"), {{"name", require_pipe_value(launch_utf8(pipe->name()))}, {"identity", native_process_json(pipe->owner())},
            {"buildId", BuildId}, {"instanceId", instance.value}});
        require_pipe_value(pipe->accept(timeout));
        const auto admitted = require_pipe_value(registry.admit(*pipe, instance, timeout));
        require_pipe_value(pipe->send(IpcMessageKind::Response, 2, worker_registration_envelope(instance, pipe->owner().creationTime, admitted), timeout));
        const auto acknowledgment = require_pipe_value(pipe->receive(timeout));
        if(acknowledgment.header.kind != IpcMessageKind::Request || acknowledgment.header.requestId != 2 || acknowledgment.envelope !=
            worker_registration_envelope(instance, pipe->owner().creationTime, {{"registered", true}})) throw ContractError{"invalid_frame", "", "Worker reply was not acknowledged"};
        const auto replay = registry.admit(*pipe, instance, timeout);
        if(!std::holds_alternative<ContractError>(replay)) throw ContractError{"internal_error", "", "Consumed worker reservation was accepted"};
        const auto registered = registry.registered_workers();
        if(registered != Json::array({admitted})) throw ContractError{"internal_error", "", "Worker registry did not retain its actual admitted generation"};
        Json explicit_removal = nullptr;
        if(input.value("explicitRemoval", false))
        {
            require_pipe_value(registry.unregister(instance));
            const auto repeated = registry.unregister(instance);
            const auto stale = registry.admit(*pipe, instance, timeout);
            const auto replacement = require_pipe_value(registry.reserve(process.get(), expected, peer_build, mode));
            if(replacement.value == instance.value || !std::holds_alternative<ContractError>(repeated) || !std::holds_alternative<ContractError>(stale))
                throw ContractError{"internal_error", "", "Retired worker reservation was reused"};
            explicit_removal = {{"repeatedRemoval", error_json(std::get<ContractError>(repeated))}, {"retiredAdmission", error_json(std::get<ContractError>(stale))},
                {"replacementId", replacement.value}, {"workers", registry.registered_workers()}};
            require_pipe_value(registry.unregister(replacement));
        }
        write_receipt(reference_path(input, "witnessPath"), {{"value", 42}, {"admitted", admitted}, {"workers", registered},
            {"duplicateRefusal", error_json(std::get<ContractError>(duplicate))}, {"replayRefusal", error_json(std::get<ContractError>(replay))}, {"explicitRemoval", explicit_removal}});
        if(WaitForSingleObject(process.get(), 10000) != WAIT_OBJECT_0) throw ContractError{"ipc_timeout", "", "Worker fixture did not exit"};
        DWORD code = 0;
        if(!GetExitCodeProcess(process.get(), &code) || code != 0) throw ContractError{"internal_error", "", "Worker fixture did not exit normally"};
        const auto after = registry.registered_workers();
        if(!after.empty()) throw ContractError{"internal_error", "", "Terminal worker generation remained registered"};
        return {{"valid", true}, {"admitted", admitted}, {"afterExit", after}, {"workerExitCode", code}};
    }
    catch(const ContractError& error) { return {{"valid", false}, {"error", error_json(error)}}; }
}
