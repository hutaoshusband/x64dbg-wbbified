#include "pipe_reference.h"
#include "local_pipe.h"
#include "build_identity.h"
#include "lifecycle.h"
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
