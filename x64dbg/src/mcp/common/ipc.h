#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
constexpr std::uint16_t IpcWireVersion = 1;
constexpr std::size_t IpcHeaderBytes = 24;
enum class IpcMessageKind : std::uint16_t { Hello = 1, HelloReply, Request, Response, Event, Cancel, Close };
struct IpcHeader { IpcMessageKind kind; std::uint32_t totalLength; std::uint64_t requestId; };
struct IpcFrame { IpcHeader header; Json envelope; };

Checked<IpcHeader> decode_ipc_header(std::string_view bytes);
Checked<IpcFrame> decode_ipc_frame(std::string_view bytes);
Checked<std::string> encode_ipc_frame(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope);
Json ipc_header_json(const IpcHeader& header);
}
