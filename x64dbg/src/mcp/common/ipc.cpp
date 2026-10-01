#include "ipc.h"

namespace wininspect::mcp
{
namespace
{
std::uint64_t read_little(std::string_view bytes, std::size_t offset, std::size_t length)
{
    std::uint64_t value = 0;
    for(std::size_t index = 0; index < length; ++index)
        value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + index])) << (index * 8);
    return value;
}

void write_little(std::string& bytes, std::size_t offset, std::size_t length, std::uint64_t value)
{
    for(std::size_t index = 0; index < length; ++index)
        bytes[offset + index] = static_cast<char>((value >> (index * 8)) & 255);
}
}

Checked<IpcHeader> decode_ipc_header(std::string_view bytes)
{
    if(bytes.size() != IpcHeaderBytes || bytes.substr(0, 4) != "WIMC")
        return ContractError{"invalid_frame", "", "IPC header is truncated or has invalid magic"};
    if(read_little(bytes, 4, 2) != IpcWireVersion)
        return ContractError{"wire_version_mismatch", "", "IPC wire version is unsupported"};
    const auto kind = read_little(bytes, 6, 2);
    const auto total_length = read_little(bytes, 8, 4);
    const auto request_id = read_little(bytes, 16, 8);
    if(kind < 1 || kind > 7 || read_little(bytes, 12, 4) != 0 || (!request_id && kind != static_cast<std::uint16_t>(IpcMessageKind::Event)))
        return ContractError{"invalid_frame", "", "IPC kind, reserved flags or correlation identity is invalid"};
    if(total_length < IpcHeaderBytes + 2 || total_length > MaximumFrameBytes)
        return ContractError{"frame_limit", "", "IPC total frame length exceeds its bound"};
    return IpcHeader{static_cast<IpcMessageKind>(kind), static_cast<std::uint32_t>(total_length), request_id};
}

Checked<IpcFrame> decode_ipc_frame(std::string_view bytes)
{
    if(bytes.size() < IpcHeaderBytes)
        return ContractError{"invalid_frame", "", "IPC header is truncated"};
    auto header = decode_ipc_header(bytes.substr(0, IpcHeaderBytes));
    if(const auto* error = std::get_if<ContractError>(&header))
        return *error;
    const auto value = std::get<IpcHeader>(header);
    if(bytes.size() != value.totalLength)
        return ContractError{"invalid_frame", "", "IPC body is truncated or contains trailing bytes"};
    auto body = parse_bounded_json(bytes.substr(IpcHeaderBytes));
    if(const auto* error = std::get_if<ContractError>(&body))
        return *error;
    auto envelope = std::get<Json>(std::move(body));
    if(auto error = validate_contract("IpcEnvelope", envelope))
        return *error;
    return IpcFrame{value, std::move(envelope)};
}

Checked<std::string> encode_ipc_frame(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope)
{
    if(auto error = validate_contract("IpcEnvelope", envelope))
        return *error;
    std::string body;
    try
    {
        body = envelope.dump();
    }
    catch(const Json::exception&)
    {
        return ContractError{"invalid_json", "", "IPC body contains invalid JSON text"};
    }
    if(body.size() > MaximumFrameBytes - IpcHeaderBytes)
        return ContractError{"frame_limit", "", "IPC encoded body exceeds its bound"};
    if(const auto parsed = parse_bounded_json(body); std::holds_alternative<ContractError>(parsed))
        return std::get<ContractError>(parsed);
    std::string bytes(IpcHeaderBytes, '\0');
    bytes.replace(0, 4, "WIMC");
    write_little(bytes, 4, 2, IpcWireVersion);
    write_little(bytes, 6, 2, static_cast<std::uint16_t>(kind));
    write_little(bytes, 8, 4, body.size() + IpcHeaderBytes);
    write_little(bytes, 16, 8, requestId);
    if(const auto header = decode_ipc_header(bytes); std::holds_alternative<ContractError>(header))
        return std::get<ContractError>(header);
    bytes += body;
    return bytes;
}

Json ipc_header_json(const IpcHeader& header)
{
    return {{"wireVersion", IpcWireVersion}, {"kind", static_cast<std::uint16_t>(header.kind)},
        {"totalLength", header.totalLength}, {"requestId", decimal64(header.requestId)}};
}
}
