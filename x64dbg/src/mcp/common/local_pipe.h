#pragma once

#include "ipc.h"
#include "process_peer.h"
#include <memory>

namespace wininspect::mcp
{
class LocalPipe
{
public:
    ~LocalPipe();
    LocalPipe(const LocalPipe&) = delete;
    LocalPipe& operator=(const LocalPipe&) = delete;
    static Checked<std::unique_ptr<LocalPipe>> create_first(std::string_view installation, std::string_view profile, std::string_view channel);
    static Checked<std::unique_ptr<LocalPipe>> connect(std::string_view installation, std::string_view profile, std::string_view channel, std::uint32_t timeoutMs);
    Checked<bool> accept(std::uint32_t timeoutMs);
    Checked<NativeProcessIdentity> observe_peer();
    Checked<bool> handshake(const NativeProcessIdentity& expectedPeer, std::string_view expectedBuildId, std::uint32_t timeoutMs);
    Checked<IpcFrame> receive(std::uint32_t timeoutMs);
    Checked<bool> send(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope, std::uint32_t timeoutMs);
    const std::wstring& name() const { return name_; }
    const NativeProcessIdentity& owner() const { return owner_; }
    void close();
private:
    LocalPipe(std::string installation, std::string profile, std::string channel, NativeProcessIdentity owner, std::wstring name);
    static Checked<std::unique_ptr<LocalPipe>> prepare(std::string_view installation, std::string_view profile, std::string_view channel);
    Checked<bool> transfer(char* bytes, std::size_t size, bool writing, ULONGLONG deadline);
    Checked<IpcFrame> read_frame(ULONGLONG deadline);
    Checked<bool> write_frame(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope, ULONGLONG deadline);
    Checked<bool> peer_live();
    std::string installation_, profile_, channel_;
    NativeProcessIdentity owner_;
    std::wstring name_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE peerProcess_ = nullptr;
    std::optional<NativeProcessIdentity> peer_;
    bool server_ = false;
    bool connected_ = false;
    bool ready_ = false;
};
}
