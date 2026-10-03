#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
struct NativeImageIdentity
{
    std::string path;
    std::string sha256;
    std::uint64_t size;
    std::uint32_t volumeSerial;
    std::uint64_t fileIndex;
};

struct NativeProcessIdentity
{
    std::uint32_t pid;
    std::uint64_t creationTime;
    std::uint32_t sessionId;
    std::string userSid;
    std::string logonSid;
    std::string integrity;
    bool elevated;
    Architecture architecture;
    NativeImageIdentity image;
};

Checked<std::string> sha256_bytes(std::string_view bytes);
Checked<NativeProcessIdentity> capture_current_process();
Json native_process_json(const NativeProcessIdentity& identity);
}
