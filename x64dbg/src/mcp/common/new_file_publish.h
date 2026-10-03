#pragma once

#include "contracts.h"
#include <Windows.h>
#include <memory>

namespace wininspect::mcp
{
struct PublishedFile
{
    std::string sha256;
    std::uint64_t size;
    std::uint32_t volumeSerial;
    std::uint64_t fileIndex;
};

class PreparedNewFile
{
public:
    static Checked<std::unique_ptr<PreparedNewFile>> stage(const std::wstring& directory, std::string_view bytes);
    ~PreparedNewFile();
    PreparedNewFile(const PreparedNewFile&) = delete;
    PreparedNewFile& operator=(const PreparedNewFile&) = delete;
    Checked<PublishedFile> publish(const std::wstring& filename);
    Checked<bool> discard();
    const std::wstring& temporaryPath() const { return temporaryPath_; }
private:
    PreparedNewFile() = default;
    HANDLE directoryHandle_ = INVALID_HANDLE_VALUE;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::wstring directory_, temporaryPath_;
    PublishedFile identity_{};
    bool published_ = false;
    bool deletionPending_ = false;
};
}
