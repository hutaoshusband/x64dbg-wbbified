#pragma once

#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace wininspect::mcp
{
using Json = nlohmann::json;

constexpr std::uint32_t ContractVersion = 1;
constexpr std::size_t MaximumFrameBytes = 8 * 1024 * 1024;
constexpr std::uint32_t MaximumPayloadBytes = 1024 * 1024;
constexpr std::uint32_t DefaultPageLimit = 100;
constexpr std::uint32_t MaximumPageLimit = 1000;
constexpr std::uint32_t DefaultTimeoutMs = 60000;
constexpr std::uint32_t MaximumTimeoutMs = 60000;
constexpr int MaximumJsonDepth = 64;
constexpr std::size_t MaximumJsonEvents = 100000;
constexpr std::size_t MaximumHexDigits = 16;
constexpr std::size_t MaximumDecimalDigits = 20;

struct InstanceId { std::string value; };
struct TargetId { std::string value; };
struct LeaseId { std::string value; };
struct JobId { std::string value; };
struct ClientId { std::string value; };
struct OperationId { std::string value; };

enum class Architecture { X32, X64 };
enum class Executor { Broker, Engine, Gui, ScriptHost };
enum class Effect { Inspect, Execute, Modify, FileExport, FileReplace, Elevate, Configure };
enum class BrokerState { Stopped, Starting, Listening, Draining, Failed };
enum class InstanceState { Requested, AwaitingUserConsent, Starting, Ready, Closing, Disconnected, Crashed, Closed };
enum class TargetState { None, Loading, Attaching, Running, Pausing, Paused, Stopping, Detached, Exited, Failed };
enum class JobState { Queued, Running, WaitingForDebugger, WaitingForEvent, AwaitingUserConsent, Cancelling, Completed, Cancelled, Failed, InterruptedByUser, Unknown };
enum class Outcome { Completed, Accepted, PartialFailure, Cancelled, Failed, Unknown };

struct ContractError
{
    std::string code;
    std::string path;
    std::string message;
};

template<typename Value>
using Checked = std::variant<Value, ContractError>;

struct TargetRef
{
    InstanceId instanceId;
    TargetId targetId;
    std::uint64_t targetGeneration;
};

struct PausedContext
{
    TargetRef target;
    std::uint64_t stopEpoch;
    std::optional<std::uint32_t> threadId;
};

struct MutationContext
{
    PausedContext paused;
    LeaseId leaseId;
    std::optional<std::string> idempotencyKey;
};

struct AbsoluteAddress { std::uint64_t value; };
struct ModuleAddress { std::string moduleId; std::uint64_t rva; };
struct ExpressionAddress { std::string expression; };
using AddressRef = std::variant<AbsoluteAddress, ModuleAddress, ExpressionAddress>;

struct AddressRange
{
    AddressRef address;
    std::uint32_t size;
};

struct Page
{
    std::optional<std::string> cursor;
    std::uint32_t limit = DefaultPageLimit;
};

struct Deadline
{
    std::uint32_t timeoutMs = DefaultTimeoutMs;
};

struct ContractDefinition
{
    std::string name;
    std::string description;
    Json schema;
};

const std::vector<ContractDefinition>& contract_registry();
Json compiled_contracts();
std::optional<ContractError> validate_contract(std::string_view name, const Json& input);
Checked<Json> parse_bounded_json(std::string_view input);
Checked<std::uint64_t> parse_hex64(std::string_view input);
Checked<std::uint64_t> parse_decimal64(std::string_view input);
std::string hex64(std::uint64_t value);
std::string decimal64(std::uint64_t value);
Checked<AddressRef> parse_address(const Json& input);
Checked<TargetRef> parse_target(const Json& input);
Checked<PausedContext> parse_paused_context(const Json& input);
Checked<MutationContext> parse_mutation_context(const Json& input);
Checked<Page> parse_page(const Json& input);
Checked<Deadline> parse_deadline(const Json& input);
Checked<std::uint64_t> checked_range_last_address(std::uint64_t address, std::uint32_t size, Architecture architecture);
Json error_json(const ContractError& error);
}
