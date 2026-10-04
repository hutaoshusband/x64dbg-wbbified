#include "worker_registry.h"
#include "lifecycle.h"
#include <bcrypt.h>
#include <array>

namespace wininspect::mcp
{
namespace
{
constexpr ULONGLONG WorkerReservationLifetimeMs = 60000;
constexpr std::size_t MaximumWorkerRegistrations = 128;
template<typename Value>
Value registration_value(Checked<Value> value)
{
    if(const auto* error = std::get_if<ContractError>(&value)) throw *error;
    return std::get<Value>(std::move(value));
}

bool digest_valid(std::string_view value)
{
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}

void validate_registration_frame(const IpcFrame& frame, IpcMessageKind kind, const InstanceId& instance, std::uint64_t generation)
{
    if(frame.header.kind != kind || frame.header.requestId != 2 || frame.envelope.at("context") != Json{{"brokerGeneration", decimal64(generation)}} ||
        frame.envelope.at("deadlineUtcMs") != "0" || frame.envelope.at("authenticationContextId") != "worker-register-" + instance.value)
        throw ContractError{"invalid_frame", "", "Worker registration correlation or broker generation is invalid"};
}
}

struct WorkerRegistry::Entry
{
    ~Entry() { if(process) CloseHandle(process); }
    HANDLE process = nullptr;
    NativeProcessIdentity expected;
    std::string buildId;
    WorkerMode mode = WorkerMode::Headless;
    ULONGLONG expires = 0;
    bool registered = false;
};

std::string worker_mode_name(WorkerMode mode)
{
    if(mode == WorkerMode::Gui) return "gui";
    if(mode == WorkerMode::Headless) return "headless";
    throw ContractError{"invalid_argument", "mode", "Worker mode is invalid"};
}

Json worker_registration_envelope(const InstanceId& instance, std::uint64_t brokerGeneration, const Json& payload)
{
    return {{"context", {{"brokerGeneration", decimal64(brokerGeneration)}}}, {"deadlineUtcMs", "0"},
        {"authenticationContextId", "worker-register-" + instance.value}, {"payload", payload}};
}

WorkerRegistry::WorkerRegistry() : owner_(registration_value(capture_current_process()))
{
    if(owner_.integrity != "medium" || owner_.elevated) throw ContractError{"permission_denied", "", "Ordinary worker registration requires an ordinary owner"};
}

Checked<InstanceId> WorkerRegistry::reserve(HANDLE trustedProcess, const NativeProcessIdentity& expected, std::string_view buildId, WorkerMode mode)
{
    try
    {
        if(!digest_valid(buildId)) throw ContractError{"invalid_argument", "buildId", "Worker build identity must be a SHA-256 digest"};
        worker_mode_name(mode);
        const auto trusted = registration_value(capture_held_process(trustedProcess));
        if(native_process_json(trusted) != native_process_json(expected))
            throw ContractError{"worker_identity_mismatch", "", "Supplied worker generation differs from the trusted process handle"};
        auto entry = std::make_shared<Entry>();
        if(!DuplicateHandle(GetCurrentProcess(), trustedProcess, GetCurrentProcess(), &entry->process, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0))
            throw ContractError{"process_identity_unavailable", "", "Cannot retain the trusted worker generation"};
        const auto actual = registration_value(capture_held_process(entry->process));
        if(native_process_json(actual) != native_process_json(expected) || actual.pid == owner_.pid || actual.userSid != owner_.userSid ||
            actual.logonSid != owner_.logonSid || actual.sessionId != owner_.sessionId || actual.integrity != "medium" || actual.elevated)
            throw ContractError{"worker_identity_mismatch", "", "Trusted worker generation does not match the ordinary owner policy"};
        entry->expected = actual;
        entry->buildId = buildId;
        entry->mode = mode;
        entry->expires = GetTickCount64() + WorkerReservationLifetimeMs;
        std::array<unsigned char, 32> nonce{};
        if(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            throw ContractError{"registration_unavailable", "", "Worker instance identity generation failed"};
        const InstanceId instance{"worker-" + registration_value(sha256_bytes(std::string_view(reinterpret_cast<const char*>(nonce.data()), nonce.size())))};
        const std::lock_guard<std::mutex> lock(mutex_);
        for(auto item = entries_.begin(); item != entries_.end();)
        {
            if(WaitForSingleObject(item->second->process, 0) != WAIT_TIMEOUT || (!item->second->registered && GetTickCount64() >= item->second->expires))
                item = entries_.erase(item);
            else
                ++item;
        }
        for(const auto& item : entries_)
            if(item.second->expected.pid == actual.pid && item.second->expected.creationTime == actual.creationTime)
                throw ContractError{"worker_already_reserved", "", "This worker generation already has an instance reservation"};
        if(entries_.size() >= MaximumWorkerRegistrations) throw ContractError{"resource_limit", "", "Worker reservation limit reached"};
        if(!entries_.emplace(instance.value, std::move(entry)).second) throw ContractError{"registration_unavailable", "", "Worker instance identity collided"};
        return instance;
    }
    catch(const ContractError& error) { return error; }
}

Checked<Json> WorkerRegistry::admit(LocalPipe& pipe, const InstanceId& instance, std::uint32_t timeoutMs)
{
    try
    {
        std::shared_ptr<Entry> entry;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto found = entries_.find(instance.value);
            if(found == entries_.end()) throw ContractError{"worker_registration_missing", "", "Worker instance reservation is absent"};
            entry = found->second;
            if(entry->registered) throw ContractError{"worker_already_registered", "", "Worker instance reservation was already consumed"};
            if(GetTickCount64() >= entry->expires) throw ContractError{"registration_expired", "", "Worker instance reservation expired"};
        }
        if(native_process_json(pipe.owner()) != native_process_json(owner_)) throw ContractError{"worker_identity_mismatch", "", "Worker registry and pipe have different owners"};
        if(native_process_json(registration_value(pipe.observe_peer())) != native_process_json(entry->expected))
            throw ContractError{"worker_identity_mismatch", "", "Physical worker endpoint differs from its retained reservation"};
        registration_value(pipe.handshake(entry->expected, entry->buildId, timeoutMs));
        const auto frame = registration_value(pipe.receive(timeoutMs));
        validate_registration_frame(frame, IpcMessageKind::Request, instance, owner_.creationTime);
        const auto& payload = frame.envelope.at("payload");
        if(payload != Json{{"instanceId", instance.value}, {"component", "worker_adapter"}, {"buildId", entry->buildId}, {"requestedMode", worker_mode_name(entry->mode)}})
            throw ContractError{"worker_registration_mismatch", "", "Worker registration differs from its trusted reservation"};
        if(native_process_json(registration_value(capture_held_process(entry->process))) != native_process_json(entry->expected))
            throw ContractError{"worker_identity_mismatch", "", "Worker generation changed before admission"};
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto found = entries_.find(instance.value);
            if(found == entries_.end() || found->second != entry || entry->registered || GetTickCount64() >= entry->expires)
                throw ContractError{"worker_registration_missing", "", "Worker reservation changed during admission"};
            entry->registered = true;
        }
        return Json{{"instanceId", instance.value}, {"requestedMode", worker_mode_name(entry->mode)}, {"registrationState", "registered"}, {"engineReady", false},
            {"process", native_process_json(entry->expected)}, {"buildId", entry->buildId}};
    }
    catch(const ContractError& error) { pipe.close(); return error; }
}

Checked<bool> WorkerRegistry::unregister(const InstanceId& instance)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if(!entries_.erase(instance.value)) return ContractError{"worker_registration_missing", "", "Worker instance is already absent"};
    return true;
}

Json WorkerRegistry::registered_workers()
{
    Json result = Json::array();
    const std::lock_guard<std::mutex> lock(mutex_);
    for(auto item = entries_.begin(); item != entries_.end();)
    {
        const auto& entry = item->second;
        if(WaitForSingleObject(entry->process, 0) != WAIT_TIMEOUT || (!entry->registered && GetTickCount64() >= entry->expires))
        {
            item = entries_.erase(item);
            continue;
        }
        if(entry->registered)
            result.push_back({{"instanceId", item->first}, {"requestedMode", worker_mode_name(entry->mode)}, {"registrationState", "registered"}, {"engineReady", false},
                {"process", native_process_json(entry->expected)}, {"buildId", entry->buildId}});
        ++item;
    }
    return result;
}
}
