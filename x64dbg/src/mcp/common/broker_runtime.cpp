#include "broker_runtime.h"
#include "broker_profile.h"
#include "local_pipe.h"
#include "build_identity.h"
#include "lifecycle.h"
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <io.h>
#include <fcntl.h>

namespace wininspect::mcp
{
namespace
{
struct HandleCloser { void operator()(void* value) const { if(value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct LocalCloser { void operator()(void* value) const { LocalFree(value); } };
using Handle = std::unique_ptr<void, HandleCloser>;

template<typename Value>
Value checked_value(Checked<Value> result)
{
    if(const auto* error = std::get_if<ContractError>(&result)) throw *error;
    return std::get<Value>(std::move(result));
}

ContractError runtime_error(const char* operation)
{
    return {"broker_start_failed", "", std::string(operation) + " failed with Win32 error " + std::to_string(GetLastError())};
}

struct RuntimeProfile
{
    NativeProcessIdentity owner;
    std::filesystem::path directory;
    std::string installation, profile, endpointProfile, channel, lockKey;
    std::unique_ptr<BrokerProfile> storage;
};

RuntimeProfile runtime_profile(std::wstring_view profile, std::wstring_view root)
{
    auto owner = checked_value(capture_current_process());
    if(owner.integrity != "medium" || owner.elevated) throw ContractError{"permission_denied", "", "Local broker controls require ordinary user rights"};
    const auto profile_id = checked_value(launch_utf8(profile));
    if(profile_id.size() != 64 || profile_id.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw ContractError{"invalid_argument", "profile", "A local profile identifier must be a lowercase SHA-256 string"};
    auto directory = std::filesystem::path(checked_value(launch_utf16(owner.image.path))).parent_path();
    Handle handle(CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if(!handle || handle.get() == INVALID_HANDLE_VALUE) throw runtime_error("Open installation directory");
    std::wstring final_path(32768, L'\0');
    const auto length = GetFinalPathNameByHandleW(handle.get(), final_path.data(), static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if(!length || length >= final_path.size()) throw runtime_error("Resolve installation directory");
    final_path.resize(length);
    directory = final_path;
    const auto installation = checked_value(sha256_bytes(checked_value(launch_utf8(final_path))));
    auto storage = checked_value(BrokerProfile::open(owner, profile_id, root));
    const auto endpoint_profile = checked_value(sha256_bytes(Json{{"profile", profile_id}, {"root", checked_value(launch_utf8(storage->root()))}}.dump()));
    const Json key = {{"installation", installation}, {"profile", endpoint_profile}, {"userSid", owner.userSid},
        {"logonSid", owner.logonSid}, {"sessionId", owner.sessionId}, {"wireVersion", IpcWireVersion}};
    return {std::move(owner), std::move(directory), installation, profile_id, endpoint_profile,
        checked_value(sha256_bytes("ordinary-local-control-v1")), checked_value(sha256_bytes(key.dump())), std::move(storage)};
}

class BrokerLock
{
public:
    explicit BrokerLock(const RuntimeProfile& profile)
    {
        const auto sid = checked_value(launch_utf16(profile.owner.logonSid));
        const auto descriptor = L"D:P(A;;0x00120001;;;" + sid + L")";
        PSECURITY_DESCRIPTOR raw = nullptr;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1, &raw, nullptr)) throw runtime_error("Build broker lock security");
        const std::unique_ptr<void, LocalCloser> security(raw);
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw, FALSE};
        const auto key = checked_value(launch_utf16(profile.lockKey));
        const auto name = L"Local\\wininspect-mcp-broker-" + key;
        handle_.reset(CreateMutexExW(&attributes, name.c_str(), 0, SYNCHRONIZE | MUTEX_MODIFY_STATE | READ_CONTROL));
        if(!handle_) throw runtime_error("Create broker lock");
        const auto waited = WaitForSingleObject(handle_.get(), 0);
        if(waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED)
            throw ContractError{"broker_already_running", "", "This installation/profile/logon already has a broker owner"};
        owned_ = true;
    }
    ~BrokerLock() { if(owned_) ReleaseMutex(handle_.get()); }
    BrokerLock(const BrokerLock&) = delete;
    BrokerLock& operator=(const BrokerLock&) = delete;
private:
    Handle handle_;
    bool owned_ = false;
};

std::string expected_image_hash(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if(!file) throw ContractError{"broker_image_unavailable", "", "The paired native component is unavailable"};
    const auto size = file.tellg();
    if(size <= 0 || size > 64 * 1024 * 1024) throw ContractError{"broker_image_unavailable", "", "The paired component exceeds its image bound"};
    std::string bytes(static_cast<std::size_t>(size), '\0');
    file.seekg(0);
    if(!file.read(bytes.data(), size)) throw ContractError{"broker_image_unavailable", "", "The paired component image is incomplete"};
    return checked_value(sha256_file_bytes(bytes));
}

NativeProcessIdentity admit_component(LocalPipe& pipe, const RuntimeProfile& profile, const wchar_t* filename)
{
    auto peer = checked_value(pipe.observe_peer());
    const auto path = profile.directory / filename;
    if(peer.architecture != profile.owner.architecture || peer.image.sha256 != expected_image_hash(path))
        throw ContractError{"ipc_peer_mismatch", "", "Local control peer is not the paired installed native component"};
    const auto peer_path = std::filesystem::path(checked_value(launch_utf16(peer.image.path)));
    if(!std::filesystem::equivalent(peer_path, path)) throw ContractError{"ipc_peer_mismatch", "", "Local control peer image belongs to another installation"};
    checked_value(pipe.handshake(peer, BuildId, 5000));
    return peer;
}

Json control_envelope(std::uint64_t generation, const Json& payload)
{
    return {{"context", {{"brokerGeneration", decimal64(generation)}}}, {"deadlineUtcMs", "0"},
        {"authenticationContextId", "ordinary-local-control"}, {"payload", payload}};
}

void validate_control_frame(const IpcFrame& frame, IpcMessageKind kind, std::uint64_t generation)
{
    if(frame.header.kind != kind || frame.header.requestId != 2 || frame.envelope.at("context") != Json{{"brokerGeneration", decimal64(generation)}} ||
        frame.envelope.at("deadlineUtcMs") != "0" || frame.envelope.at("authenticationContextId") != "ordinary-local-control")
        throw ContractError{"invalid_frame", "", "Local control frame correlation or context is invalid"};
}

void start_broker(const RuntimeProfile& profile)
{
    const auto application = (profile.directory / L"wininspect-mcp.exe").wstring();
    const auto application_text = checked_value(launch_utf8(application));
    TargetLaunchRequest launch;
    launch.instanceId = {"broker-bootstrap"};
    launch.file = AbsoluteFile{application_text};
    launch.arguments = std::vector<std::string>{"--serve-local", "--profile", profile.profile, "--profile-root", checked_value(launch_utf8(profile.storage->root()))};
    auto plan = checked_value(prepare_windows_launch(launch, application_text, {}));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if(!CreateProcessW(application.c_str(), plan.commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, profile.directory.c_str(), &startup, &process)) throw runtime_error("Start ordinary broker");
    const Handle thread(process.hThread), child(process.hProcess);
}

std::unique_ptr<LocalPipe> broker_channel(const RuntimeProfile& profile)
{
    const auto deadline = GetTickCount64() + 10000;
    bool started = false;
    for(;;)
    {
        auto result = LocalPipe::connect(profile.installation, profile.endpointProfile, profile.channel, 500);
        if(auto* pipe = std::get_if<std::unique_ptr<LocalPipe>>(&result))
        {
            admit_component(**pipe, profile, L"wininspect-mcp.exe");
            return std::move(*pipe);
        }
        if(!started) { start_broker(profile); started = true; }
        if(GetTickCount64() >= deadline) throw std::get<ContractError>(result);
        Sleep(20);
    }
}

Json control_request(const RuntimeProfile& profile, const Json& request)
{
    if(auto error = validate_schema(closed_object_schema({{"operation", enum_schema({"status", "shutdown"})}}, {"operation"}), request)) throw *error;
    const auto existing_configuration = profile.storage->configuration(profile.installation, false);
    if(const auto* error = std::get_if<ContractError>(&existing_configuration); error && error->code != "profile_record_missing") throw *error;
    auto pipe = broker_channel(profile);
    const auto peer = checked_value(pipe->observe_peer());
    const auto configuration = checked_value(profile.storage->configuration(profile.installation, false));
    const Json expected_registration = {{"schemaVersion", 1}, {"installation", profile.installation}, {"profile", profile.profile}, {"buildId", BuildId},
        {"wireVersion", IpcWireVersion}, {"process", native_process_json(peer)}, {"configuredHttpPort", configuration.at("httpPort")}, {"port", nullptr}};
    const auto registration = checked_value(profile.storage->registration(profile.lockKey, peer));
    if(registration != expected_registration) throw ContractError{"profile_registration_mismatch", "", "Durable broker registration does not match the actual live pipe generation"};
    checked_value(pipe->send(IpcMessageKind::Request, 2, control_envelope(peer.creationTime, request), 5000));
    const auto response = checked_value(pipe->receive(5000));
    validate_control_frame(response, IpcMessageKind::Response, peer.creationTime);
    const auto& payload = response.envelope.at("payload");
    if(payload.at("broker") != native_process_json(peer) || payload.at("installation") != profile.installation || payload.at("profile") != profile.profile ||
        payload.at("buildId") != BuildId || payload.at("operation") != request.at("operation") || payload.at("configuration") != configuration || payload.at("registration") != registration)
        throw ContractError{"ipc_peer_mismatch", "", "Broker registration does not match its retained physical endpoint"};
    Handle shutdown_process;
    if(request.at("operation") == "shutdown")
    {
        shutdown_process.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, peer.pid));
        if(!shutdown_process) throw runtime_error("Retain broker shutdown generation");
        if(native_process_json(checked_value(capture_held_process(shutdown_process.get()))) != native_process_json(peer))
            throw ContractError{"ipc_peer_mismatch", "", "Broker shutdown handle does not match the admitted generation"};
    }
    checked_value(pipe->send(IpcMessageKind::Request, 2, control_envelope(peer.creationTime, {{"acknowledged", true}}), 5000));
    if(shutdown_process)
    {
        if(WaitForSingleObject(shutdown_process.get(), 5000) != WAIT_OBJECT_0)
            throw ContractError{"ipc_timeout", "", "The admitted broker has not completed shutdown"};
        DWORD exit_code = 0;
        if(!GetExitCodeProcess(shutdown_process.get(), &exit_code) || exit_code != 0)
            throw ContractError{"broker_shutdown_failed", "", "The admitted broker did not exit normally"};
    }
    return payload;
}
}

int serve_local_broker(std::wstring_view profile_id, std::wstring_view root)
{
    const auto profile = runtime_profile(profile_id, root);
    const BrokerLock lock(profile);
    const auto configuration = checked_value(profile.storage->configuration(profile.installation, true));
    auto pipe = checked_value(LocalPipe::create_first(profile.installation, profile.endpointProfile, profile.channel));
    const Json registration = {{"schemaVersion", 1}, {"installation", profile.installation}, {"profile", profile.profile}, {"buildId", BuildId}, {"wireVersion", IpcWireVersion},
        {"process", native_process_json(profile.owner)}, {"configuredHttpPort", configuration.at("httpPort")}, {"port", nullptr}};
    checked_value(profile.storage->publish_registration(profile.lockKey, profile.owner, registration));
    bool stopping = false;
    while(!stopping)
    {
        try
        {
            checked_value(pipe->accept(60000));
            admit_component(*pipe, profile, L"wininspect-mcp-connect.exe");
            const auto frame = checked_value(pipe->receive(5000));
            validate_control_frame(frame, IpcMessageKind::Request, profile.owner.creationTime);
            const auto& request = frame.envelope.at("payload");
            if(auto error = validate_schema(closed_object_schema({{"operation", enum_schema({"status", "shutdown"})}}, {"operation"}), request)) throw *error;
            const Json response = {{"broker", native_process_json(profile.owner)}, {"installation", profile.installation}, {"profile", profile.profile},
                {"buildId", BuildId}, {"operation", request.at("operation")}, {"debuggerInstances", Json::array()}, {"operationalTools", Json::array()},
                {"configuration", configuration}, {"registration", registration}};
            checked_value(pipe->send(IpcMessageKind::Response, 2, control_envelope(profile.owner.creationTime, response), 5000));
            const auto acknowledgment = checked_value(pipe->receive(5000));
            validate_control_frame(acknowledgment, IpcMessageKind::Request, profile.owner.creationTime);
            if(acknowledgment.envelope.at("payload") != Json{{"acknowledged", true}}) throw ContractError{"invalid_frame", "", "Local control reply was not acknowledged"};
            stopping = request.at("operation") == "shutdown";
        }
        catch(const ContractError& error)
        {
            std::cerr << Json{{"code", error.code}, {"message", error.message}}.dump() << '\n';
        }
        pipe.reset();
        if(!stopping) pipe = checked_value(LocalPipe::create_first(profile.installation, profile.endpointProfile, profile.channel));
    }
    return 0;
}

int connect_local_control(std::wstring_view profile_id, std::wstring_view root)
{
    const auto profile = runtime_profile(profile_id, root);
    if(_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1)
        throw ContractError{"ipc_failure", "", "Cannot select UTF-8 local-control byte streams"};
    std::string line;
    for(;;)
    {
        line.clear();
        char byte = 0;
        while(std::cin.get(byte) && byte != '\n')
        {
            if(line.size() == 4096) throw ContractError{"payload_limit", "", "Local control input exceeds its 4096-byte bound"};
            line.push_back(byte);
        }
        if(line.empty() && std::cin.eof()) break;
        if(!line.empty() && line.back() == '\r') line.pop_back();
        const auto request = checked_value(parse_bounded_json(line));
        const auto response = control_request(profile, request);
        std::cout << response.dump() << '\n' << std::flush;
        if(request.at("operation") == "shutdown") break;
    }
    if(!std::cin.eof() && std::cin.fail()) throw ContractError{"ipc_failure", "", "Local control input stream failed"};
    return 0;
}
}
