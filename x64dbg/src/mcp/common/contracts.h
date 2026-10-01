#pragma once

#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
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
struct NamespaceId { std::string value; };
struct LibraryObjectId { std::string value; };
struct RevisionId { std::string value; };
struct EventCursor { std::string value; };

enum class Architecture { X32, X64 };
enum class Executor { Broker, Engine, Gui, ScriptHost };
enum class Effect { Inspect, Execute, Modify, FileExport, FileReplace, Elevate, Configure };
enum class BrokerState { Stopped, Starting, Listening, Draining, Failed };
enum class InstanceState { Requested, AwaitingUserConsent, Starting, Ready, Closing, Disconnected, Crashed, Closed };
enum class TargetState { None, Loading, Attaching, Running, Pausing, Paused, Stopping, Detached, Exited, Failed };
enum class JobState { Queued, Running, WaitingForDebugger, WaitingForEvent, AwaitingUserConsent, Cancelling, Completed, Cancelled, Failed, InterruptedByUser, Unknown };
enum class Outcome { Completed, Accepted, PartialFailure, Cancelled, Failed, Unknown };
enum class DomainErrorCode { DebuggerUnavailable, TargetRequired, TargetRunning, StaleContext, LeaseConflict, ElevationRequired, ElevationDenied, PermissionDenied, ExpectedBytesMismatch, FileHashMismatch, UnsupportedMapping, PartialFailure, TimeoutUnknown, ResourceLimit, UnsupportedCapability, EventGap, IdempotencyConflict, InvalidArgument, InternalError };
enum class VerificationStatus { Verified, Unverified, Pending, Failed, Unknown };
enum class RetryPolicy { Never, AfterRefresh, AfterReconciliation };
enum class EffectStatus { Applied, Restored, Failed, Unknown };

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

struct LibraryRef
{
    NamespaceId namespaceId;
    LibraryObjectId objectId;
    RevisionId revision;
};

struct RecoveryRoute
{
    std::string capabilityId;
    RetryPolicy retry;
    std::string reason;
};

struct DomainError
{
    DomainErrorCode code;
    std::string message;
    std::string path;
    std::optional<RecoveryRoute> recovery;
};

struct VerificationEvidence
{
    std::string kind;
    std::string source;
    std::string summary;
    std::optional<std::string> artifactId;
    std::optional<std::string> sha256;
};

struct Verification
{
    VerificationStatus status;
    std::vector<VerificationEvidence> evidence;
    std::optional<RecoveryRoute> followUp;
};

struct ResultWarning
{
    std::string code;
    std::string message;
};

struct ResultTimings
{
    std::uint64_t startedUtcMs;
    std::uint64_t elapsedUs;
    std::uint64_t queueUs;
};

struct BrokerContext { std::uint64_t brokerGeneration; };
using ResultContext = std::variant<BrokerContext, InstanceId, TargetRef, PausedContext>;

struct ResultHeader
{
    OperationId operationId;
    ResultContext context;
    std::uint64_t stateVersion;
    Verification verification;
    std::vector<ResultWarning> warnings;
    ResultTimings timings;
    std::optional<JobId> jobId;
};

struct EffectObservation
{
    std::string stepId;
    EffectStatus status;
    std::string summary;
};

struct ResultPagination
{
    std::uint64_t snapshotVersion;
    bool complete;
    std::optional<std::string> nextCursor;
};

template<typename Data> struct CompletedResult { Data data; bool partial = false; std::optional<ResultPagination> page; };
struct AcceptedResult { JobId jobId; };
template<typename Data> struct PartialFailureResult { std::optional<Data> data; DomainError error; std::vector<EffectObservation> effects; RecoveryRoute recovery; };
struct FailedResult { DomainError error; };
template<typename Data> struct CancelledResult { std::optional<Data> data; std::vector<EffectObservation> effects; };
template<typename Data> struct UnknownResult { std::optional<Data> data; DomainError error; RecoveryRoute reconciliation; std::vector<EffectObservation> effects; };
template<typename Data> using ResultOutcome = std::variant<CompletedResult<Data>, AcceptedResult, PartialFailureResult<Data>, FailedResult, CancelledResult<Data>, UnknownResult<Data>>;
template<typename Data> struct OperationResult { ResultHeader header; ResultOutcome<Data> outcome; };

struct ContractDefinition
{
    std::string name;
    std::string description;
    Json schema;
};

const std::vector<ContractDefinition>& contract_registry();
Json compiled_contracts();
Json contract_schema(std::string_view name);
Json string_schema(std::string format, std::size_t maximum = 128, std::size_t minimum = 1);
Json bounded_integer_schema(std::uint32_t minimum, std::uint32_t maximum, std::optional<std::uint32_t> fallback = {});
Json closed_object_schema(Json properties, Json required);
Json enum_schema(Json values);
Json bounded_array_schema(Json items, std::size_t maximum, std::size_t minimum = 0, bool unique = false);
Json result_schema(Json data, bool allowUnverified = false);
std::optional<ContractError> validate_schema(const Json& schema, const Json& input);
Json result_header_json(const ResultHeader& header);
Json domain_error_json(const DomainError& error);
Json recovery_json(const RecoveryRoute& recovery);

template<typename Data>
Json result_json(const OperationResult<Data>& result)
{
    auto value = result_header_json(result.header);
    std::visit([&](const auto& outcome)
    {
        using Result = std::decay_t<decltype(outcome)>;
        value["partial"] = false;
        if constexpr(std::is_same_v<Result, CompletedResult<Data>>)
        {
            value["outcome"] = "completed";
            value["data"] = outcome.data;
            value["partial"] = outcome.partial;
            if(outcome.page)
            {
                value["page"] = {{"snapshotVersion", decimal64(outcome.page->snapshotVersion)}, {"complete", outcome.page->complete}};
                if(outcome.page->nextCursor)
                    value["page"]["nextCursor"] = *outcome.page->nextCursor;
            }
        }
        else if constexpr(std::is_same_v<Result, AcceptedResult>)
        {
            value["outcome"] = "accepted";
            value["data"] = nullptr;
            value["jobId"] = outcome.jobId.value;
        }
        else if constexpr(std::is_same_v<Result, FailedResult>)
        {
            value["outcome"] = "failed";
            value["data"] = nullptr;
            value["error"] = domain_error_json(outcome.error);
        }
        else
        {
            value["data"] = outcome.data ? Json(*outcome.data) : Json(nullptr);
            if constexpr(std::is_same_v<Result, UnknownResult<Data>>)
            {
                value["outcome"] = "unknown";
                value["error"] = domain_error_json(outcome.error);
                value["reconciliation"] = recovery_json(outcome.reconciliation);
                value["partial"] = !outcome.effects.empty();
            }
            else
            {
                if constexpr(std::is_same_v<Result, PartialFailureResult<Data>>)
                {
                    value["outcome"] = "partial_failure";
                    value["partial"] = true;
                    value["error"] = domain_error_json(outcome.error);
                    value["recovery"] = recovery_json(outcome.recovery);
                }
                else
                    value["outcome"] = "cancelled";
            }
            value["effects"] = Json::array();
            constexpr const char* statuses[] = {"applied", "restored", "failed", "unknown"};
            for(const auto& effect : outcome.effects)
                value["effects"].push_back({{"stepId", effect.stepId}, {"status", statuses[static_cast<std::size_t>(effect.status)]}, {"summary", effect.summary}});
        }
    }, result.outcome);
    return value;
}
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
