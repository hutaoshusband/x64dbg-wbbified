#include "local_pipe.h"
#include "build_identity.h"
#include "lifecycle.h"
#include <bcrypt.h>
#include <sddl.h>
#include <algorithm>
#include <array>

namespace wininspect::mcp
{
namespace
{
struct CloseNativeHandle { void operator()(void* value) const { if(value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct FreeLocalMemory { void operator()(void* value) const { LocalFree(value); } };

ContractError pipe_error(const char* operation, DWORD error = GetLastError())
{
    return {"ipc_failure", "", std::string(operation) + " failed with Win32 error " + std::to_string(error)};
}

bool digest_id(std::string_view value)
{
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}

Checked<ULONGLONG> pipe_deadline(std::uint32_t timeout)
{
    if(!timeout || timeout > 60000) return ContractError{"invalid_argument", "timeoutMs", "Pipe timeout must be between 1 and 60000 milliseconds"};
    return GetTickCount64() + timeout;
}

DWORD remaining_time(ULONGLONG deadline)
{
    const auto now = GetTickCount64();
    return now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
}

Checked<bool> complete_io(HANDLE pipe, OVERLAPPED& operation, ULONGLONG deadline, DWORD& completed)
{
    const auto waited = WaitForSingleObject(operation.hEvent, remaining_time(deadline));
    if(waited != WAIT_OBJECT_0)
    {
        const auto error = waited == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &completed, TRUE);
        return ContractError{waited == WAIT_TIMEOUT ? "ipc_timeout" : "ipc_failure", "", "Pipe operation canceled and drained with Win32 error " + std::to_string(error)};
    }
    if(!GetOverlappedResult(pipe, &operation, &completed, FALSE)) return pipe_error("GetOverlappedResult");
    return true;
}

Checked<std::string> pipe_nonce()
{
    std::array<unsigned char, 32> bytes{};
    if(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return ContractError{"ipc_failure", "", "Pipe nonce generation failed"};
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for(const auto byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}

Json hello_schema()
{
    return with_contract_definitions(closed_object_schema({{"phase", enum_schema({"hello", "reply", "ack"})},
        {"installation", string_schema("sha256", 64)}, {"profile", string_schema("sha256", 64)}, {"channel", string_schema("sha256", 64)},
        {"buildId", string_schema("sha256", 64)}, {"identity", reference_schema("NativeProcessIdentity")},
        {"nonce", string_schema("sha256", 64)}, {"peerNonce", string_schema("sha256", 64)}},
        {"phase", "installation", "profile", "channel", "buildId", "identity", "nonce", "peerNonce"}));
}
}

LocalPipe::LocalPipe(std::string installation, std::string profile, std::string channel, NativeProcessIdentity owner, std::wstring name) :
    installation_(std::move(installation)), profile_(std::move(profile)), channel_(std::move(channel)), owner_(std::move(owner)), name_(std::move(name)) {}

LocalPipe::~LocalPipe() { close(); }

void LocalPipe::close()
{
    ready_ = connected_ = false;
    peer_.reset();
    if(peerProcess_) { CloseHandle(peerProcess_); peerProcess_ = nullptr; }
    if(pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
}

Checked<std::unique_ptr<LocalPipe>> LocalPipe::prepare(std::string_view installation, std::string_view profile, std::string_view channel)
{
    if(!digest_id(installation) || !digest_id(profile) || !digest_id(channel))
        return ContractError{"invalid_argument", "", "Installation, profile and channel identities must be SHA-256 strings"};
    auto identity = capture_current_process();
    if(const auto* error = std::get_if<ContractError>(&identity)) return *error;
    auto owner = std::get<NativeProcessIdentity>(std::move(identity));
    const Json namespace_data = {{"installation", installation}, {"profile", profile}, {"channel", channel},
        {"userSid", owner.userSid}, {"logonSid", owner.logonSid}, {"sessionId", owner.sessionId}, {"wireVersion", IpcWireVersion}};
    auto digest = sha256_bytes(namespace_data.dump());
    if(const auto* error = std::get_if<ContractError>(&digest)) return *error;
    const auto& key = std::get<std::string>(digest);
    std::wstring name = L"\\\\.\\pipe\\wininspect-mcp-";
    name.append(key.begin(), key.end());
    return std::unique_ptr<LocalPipe>(new LocalPipe(std::string(installation), std::string(profile), std::string(channel), std::move(owner), std::move(name)));
}

Checked<std::unique_ptr<LocalPipe>> LocalPipe::create_first(std::string_view installation, std::string_view profile, std::string_view channel)
{
    auto prepared = prepare(installation, profile, channel);
    if(const auto* error = std::get_if<ContractError>(&prepared)) return *error;
    auto pipe = std::get<std::unique_ptr<LocalPipe>>(std::move(prepared));
    auto sid = launch_utf16(pipe->owner_.logonSid);
    if(const auto* error = std::get_if<ContractError>(&sid)) return *error;
    const auto descriptor = L"D:P(A;;0x00120083;;;" + std::get<std::wstring>(sid) + L")";
    PSECURITY_DESCRIPTOR raw_security = nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1, &raw_security, nullptr)) return pipe_error("ConvertStringSecurityDescriptorToSecurityDescriptorW");
    const std::unique_ptr<void, FreeLocalMemory> security(raw_security);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw_security, FALSE};
    pipe->pipe_ = CreateNamedPipeW(pipe->name_.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes);
    if(pipe->pipe_ == INVALID_HANDLE_VALUE) return pipe_error("CreateNamedPipeW");
    pipe->server_ = true;
    return pipe;
}

Checked<std::unique_ptr<LocalPipe>> LocalPipe::connect(std::string_view installation, std::string_view profile, std::string_view channel, std::uint32_t timeoutMs)
{
    const auto checked_deadline = pipe_deadline(timeoutMs);
    if(const auto* error = std::get_if<ContractError>(&checked_deadline)) return *error;
    const auto deadline = std::get<ULONGLONG>(checked_deadline);
    auto prepared = prepare(installation, profile, channel);
    if(const auto* error = std::get_if<ContractError>(&prepared)) return *error;
    auto pipe = std::get<std::unique_ptr<LocalPipe>>(std::move(prepared));
    for(;;)
    {
        if(!remaining_time(deadline)) return ContractError{"ipc_timeout", "", "Pipe connection deadline expired"};
        pipe->pipe_ = CreateFileW(pipe->name_.c_str(), FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if(pipe->pipe_ != INVALID_HANDLE_VALUE) break;
        const auto error = GetLastError();
        if(error != ERROR_PIPE_BUSY) return pipe_error("CreateFileW", error);
        if(!WaitNamedPipeW(pipe->name_.c_str(), remaining_time(deadline))) return pipe_error("WaitNamedPipeW");
    }
    pipe->connected_ = true;
    return pipe;
}

Checked<bool> LocalPipe::accept(std::uint32_t timeoutMs)
{
    if(!server_ || connected_ || pipe_ == INVALID_HANDLE_VALUE) return ContractError{"ipc_closed", "", "Pipe listener state does not permit acceptance"};
    const auto deadline = pipe_deadline(timeoutMs);
    if(const auto* error = std::get_if<ContractError>(&deadline)) return *error;
    const std::unique_ptr<void, CloseNativeHandle> event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if(!event) return pipe_error("CreateEventW");
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    if(!ConnectNamedPipe(pipe_, &operation))
    {
        const auto error = GetLastError();
        if(error != ERROR_PIPE_CONNECTED)
        {
            if(error != ERROR_IO_PENDING) { close(); return pipe_error("ConnectNamedPipe", error); }
            DWORD completed = 0;
            auto completion = complete_io(pipe_, operation, std::get<ULONGLONG>(deadline), completed);
            if(const auto* failure = std::get_if<ContractError>(&completion)) { auto retained = *failure; close(); return retained; }
        }
    }
    connected_ = true;
    return true;
}

Checked<NativeProcessIdentity> LocalPipe::observe_peer()
{
    if(!connected_ || pipe_ == INVALID_HANDLE_VALUE) return ContractError{"ipc_closed", "", "Pipe is not connected"};
    ULONG pid = 0;
    const auto query = server_ ? GetNamedPipeClientProcessId : GetNamedPipeServerProcessId;
    if(!query(pipe_, &pid) || !pid) { auto error = pipe_error("GetNamedPipeProcessId"); close(); return error; }
    const std::unique_ptr<void, CloseNativeHandle> process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if(!process) { auto error = pipe_error("OpenProcess"); close(); return error; }
    auto identity = capture_held_process(process.get());
    if(const auto* failure = std::get_if<ContractError>(&identity)) { auto error = *failure; close(); return error; }
    ULONG checked_pid = 0;
    if(!query(pipe_, &checked_pid) || checked_pid != pid) { close(); return ContractError{"ipc_peer_mismatch", "", "Pipe endpoint changed during peer observation"}; }
    if(peer_ && native_process_json(*peer_) != native_process_json(std::get<NativeProcessIdentity>(identity)))
    { close(); return ContractError{"ipc_peer_mismatch", "", "Pipe peer identity changed during observation"}; }
    HANDLE retained = nullptr;
    if(!DuplicateHandle(GetCurrentProcess(), process.get(), GetCurrentProcess(), &retained, 0, FALSE, DUPLICATE_SAME_ACCESS))
    { auto error = pipe_error("DuplicateHandle"); close(); return error; }
    if(peerProcess_) CloseHandle(peerProcess_);
    peerProcess_ = retained;
    peer_ = std::get<NativeProcessIdentity>(identity);
    return *peer_;
}

Checked<bool> LocalPipe::peer_live()
{
    if(!peer_ || !peerProcess_ || !connected_) return ContractError{"ipc_closed", "", "Pipe has no retained peer generation"};
    auto identity = capture_held_process(peerProcess_);
    if(const auto* failure = std::get_if<ContractError>(&identity)) { auto error = *failure; close(); return error; }
    if(native_process_json(std::get<NativeProcessIdentity>(identity)) != native_process_json(*peer_))
    { close(); return ContractError{"ipc_peer_mismatch", "", "Retained peer identity changed"}; }
    return true;
}

Checked<bool> LocalPipe::transfer(char* bytes, std::size_t size, bool writing, ULONGLONG deadline)
{
    const std::unique_ptr<void, CloseNativeHandle> event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if(!event) return pipe_error("CreateEventW");
    std::size_t offset = 0;
    while(offset < size)
    {
        if(!remaining_time(deadline)) { close(); return ContractError{"ipc_timeout", "", "Pipe transfer deadline expired"}; }
        ResetEvent(event.get());
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        DWORD completed = 0;
        const auto count = static_cast<DWORD>((std::min)(size - offset, std::size_t(65536)));
        const auto success = writing ? WriteFile(pipe_, bytes + offset, count, &completed, &operation) : ReadFile(pipe_, bytes + offset, count, &completed, &operation);
        if(!success)
        {
            const auto error = GetLastError();
            if(error != ERROR_IO_PENDING) { close(); return pipe_error(writing ? "WriteFile" : "ReadFile", error); }
            const auto completion = complete_io(pipe_, operation, deadline, completed);
            if(const auto* failure = std::get_if<ContractError>(&completion)) { auto error = *failure; close(); return error; }
        }
        if(!completed || completed > count) { close(); return ContractError{"ipc_closed", "", "Pipe transfer ended before its frame completed"}; }
        offset += completed;
    }
    return true;
}

Checked<IpcFrame> LocalPipe::read_frame(ULONGLONG deadline)
{
    std::string bytes(IpcHeaderBytes, '\0');
    auto read = transfer(bytes.data(), bytes.size(), false, deadline);
    if(const auto* error = std::get_if<ContractError>(&read)) return *error;
    const auto header = decode_ipc_header(bytes);
    if(const auto* failure = std::get_if<ContractError>(&header)) { auto error = *failure; close(); return error; }
    const auto size = std::get<IpcHeader>(header).totalLength;
    bytes.resize(size);
    read = transfer(bytes.data() + IpcHeaderBytes, size - IpcHeaderBytes, false, deadline);
    if(const auto* error = std::get_if<ContractError>(&read)) return *error;
    auto frame = decode_ipc_frame(bytes);
    if(std::holds_alternative<ContractError>(frame)) close();
    return frame;
}

Checked<bool> LocalPipe::write_frame(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope, ULONGLONG deadline)
{
    auto bytes = encode_ipc_frame(kind, requestId, envelope);
    if(const auto* error = std::get_if<ContractError>(&bytes)) return *error;
    auto& value = std::get<std::string>(bytes);
    return transfer(value.data(), value.size(), true, deadline);
}

Checked<bool> LocalPipe::handshake(const NativeProcessIdentity& expectedPeer, std::string_view expectedBuildId, std::uint32_t timeoutMs)
{
    if(ready_ || !digest_id(expectedBuildId)) return ContractError{"invalid_argument", "", "Pipe handshake state or expected build is invalid"};
    const auto checked_deadline = pipe_deadline(timeoutMs);
    if(const auto* error = std::get_if<ContractError>(&checked_deadline)) return *error;
    const auto deadline = std::get<ULONGLONG>(checked_deadline);
    auto actual = observe_peer();
    if(const auto* error = std::get_if<ContractError>(&actual)) return *error;
    if(native_process_json(std::get<NativeProcessIdentity>(actual)) != native_process_json(expectedPeer) || expectedPeer.userSid != owner_.userSid ||
       expectedPeer.logonSid != owner_.logonSid || expectedPeer.sessionId != owner_.sessionId || expectedPeer.elevated || expectedPeer.integrity != "medium" || owner_.elevated || owner_.integrity != "medium")
    { close(); return ContractError{"ipc_peer_mismatch", "", "Actual pipe peer does not match the ordinary local admission policy"}; }
    auto nonce_value = pipe_nonce();
    if(const auto* error = std::get_if<ContractError>(&nonce_value)) return *error;
    const auto nonce = std::get<std::string>(nonce_value);
    const auto generation = decimal64(server_ ? owner_.creationTime : peer_->creationTime);
    std::string client_nonce;
    const auto envelope = [&](const char* phase, const std::string& peerNonce) -> Json
    {
        return {{"context", {{"brokerGeneration", generation}}}, {"deadlineUtcMs", "0"}, {"authenticationContextId", "pipe-" + client_nonce},
            {"payload", {{"phase", phase}, {"installation", installation_}, {"profile", profile_}, {"channel", channel_}, {"buildId", BuildId},
                {"identity", native_process_json(owner_)}, {"nonce", nonce}, {"peerNonce", peerNonce}}}};
    };
    const auto receive_hello = [&](IpcMessageKind kind, const char* phase, const std::string& echoed, bool initial) -> Checked<std::string>
    {
        auto received = read_frame(deadline);
        if(const auto* error = std::get_if<ContractError>(&received)) return *error;
        const auto& frame = std::get<IpcFrame>(received);
        const auto& value = frame.envelope.at("payload");
        if(auto error = validate_schema(hello_schema(), value)) { close(); return *error; }
        if(initial) client_nonce = value.at("nonce").get<std::string>();
        if(frame.header.kind != kind || frame.header.requestId != 1 || value.at("phase") != phase || value.at("installation") != installation_ ||
           value.at("profile") != profile_ || value.at("channel") != channel_ || value.at("buildId").get<std::string>() != expectedBuildId ||
           value.at("identity") != native_process_json(*peer_) || value.at("peerNonce") != echoed ||
           frame.envelope.at("context") != Json{{"brokerGeneration", generation}} || frame.envelope.at("deadlineUtcMs") != "0" ||
           frame.envelope.at("authenticationContextId") != "pipe-" + client_nonce)
        { close(); return ContractError{"ipc_handshake_mismatch", "", "Pipe handshake identity, namespace, build, nonce or correlation is incompatible"}; }
        return value.at("nonce").get<std::string>();
    };
    if(server_)
    {
        const auto hello = receive_hello(IpcMessageKind::Hello, "hello", std::string(64, '0'), true);
        if(const auto* error = std::get_if<ContractError>(&hello)) return *error;
        const auto sent = write_frame(IpcMessageKind::HelloReply, 1, envelope("reply", client_nonce), deadline);
        if(const auto* error = std::get_if<ContractError>(&sent)) return *error;
        const auto ack = receive_hello(IpcMessageKind::Hello, "ack", nonce, false);
        if(const auto* error = std::get_if<ContractError>(&ack)) return *error;
        if(std::get<std::string>(ack) != client_nonce) { close(); return ContractError{"ipc_handshake_mismatch", "", "Pipe acknowledgment does not match its initial nonce"}; }
    }
    else
    {
        client_nonce = nonce;
        const auto sent = write_frame(IpcMessageKind::Hello, 1, envelope("hello", std::string(64, '0')), deadline);
        if(const auto* error = std::get_if<ContractError>(&sent)) return *error;
        const auto reply = receive_hello(IpcMessageKind::HelloReply, "reply", nonce, false);
        if(const auto* error = std::get_if<ContractError>(&reply)) return *error;
        const auto ack = write_frame(IpcMessageKind::Hello, 1, envelope("ack", std::get<std::string>(reply)), deadline);
        if(const auto* error = std::get_if<ContractError>(&ack)) return *error;
    }
    const auto live = peer_live();
    if(const auto* error = std::get_if<ContractError>(&live)) return *error;
    ready_ = true;
    return true;
}

Checked<IpcFrame> LocalPipe::receive(std::uint32_t timeoutMs)
{
    if(!ready_) return ContractError{"ipc_closed", "", "Pipe handshake is not complete"};
    const auto deadline = pipe_deadline(timeoutMs);
    if(const auto* error = std::get_if<ContractError>(&deadline)) return *error;
    const auto live = peer_live();
    if(const auto* error = std::get_if<ContractError>(&live)) return *error;
    auto frame = read_frame(std::get<ULONGLONG>(deadline));
    if(const auto* error = std::get_if<ContractError>(&frame)) return *error;
    const auto retained = peer_live();
    if(const auto* error = std::get_if<ContractError>(&retained)) return *error;
    return frame;
}

Checked<bool> LocalPipe::send(IpcMessageKind kind, std::uint64_t requestId, const Json& envelope, std::uint32_t timeoutMs)
{
    if(!ready_) return ContractError{"ipc_closed", "", "Pipe handshake is not complete"};
    const auto deadline = pipe_deadline(timeoutMs);
    if(const auto* error = std::get_if<ContractError>(&deadline)) return *error;
    const auto live = peer_live();
    if(const auto* error = std::get_if<ContractError>(&live)) return *error;
    return write_frame(kind, requestId, envelope, std::get<ULONGLONG>(deadline));
}
}
