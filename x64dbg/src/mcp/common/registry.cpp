#include "registry.h"
#include "build_identity.h"
#include "lifecycle.h"
#include "platform.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <limits>
#include <windows.h>

namespace wininspect::mcp
{
namespace
{
Json descriptor_schema()
{
    const auto id = string_schema("opaque-id");
    const auto schema_document = Json{{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}};
    const auto annotations = closed_object_schema({{"readOnlyHint", {{"type", "boolean"}}}, {"destructiveHint", {{"type", "boolean"}}},
        {"idempotentHint", {{"type", "boolean"}}}, {"openWorldHint", {{"type", "boolean"}}}}, {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"});
    return closed_object_schema({{"capabilityId", id}, {"name", id}, {"description", string_schema("utf8-text", 4096)},
        {"domain", id}, {"provider", id}, {"schemaVersion", {{"const", ContractVersion}}}, {"inputSchema", schema_document},
        {"outputSchema", schema_document}, {"effects", bounded_array_schema(enum_schema({"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"}), 7, 1, true)},
        {"effectConditions", bounded_array_schema(closed_object_schema({{"field", id}, {"equals", string_schema("utf8-text", 128)},
            {"effects", bounded_array_schema(enum_schema({"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"}), 7, 1, true)}}, {"field", "equals", "effects"}), 16)},
        {"effectResolution", {{"const", "native_classifier"}}},
        {"executor", enum_schema({"broker", "engine", "gui", "script_host"})}, {"stateRequirement", enum_schema({"broker", "instance_ready", "target_present", "target_paused"})},
        {"architectureRequirement", enum_schema({"any", "x32", "x64"})}, {"completionPredicate", string_schema("utf8-text", 4096)},
        {"recovery", bounded_array_schema(id, 16)}, {"acceptanceIds", bounded_array_schema(id, 66, 1, true)},
        {"nativeSource", string_schema("utf8-text", 1024)}, {"availability", enum_schema({"planned", "implemented"})},
        {"operational", {{"const", false}}}, {"annotations", annotations}},
        {"capabilityId", "name", "description", "domain", "provider", "schemaVersion", "inputSchema", "outputSchema", "effects", "effectConditions", "executor", "stateRequirement", "architectureRequirement", "completionPredicate", "recovery", "acceptanceIds", "nativeSource", "availability", "operational", "annotations"});
}

Json page_input(Json properties = Json::object(), Json required = Json::array())
{
    auto schema = contract_schema("Page");
    schema["properties"].update(properties);
    schema["required"] = std::move(required);
    return schema;
}

Json filtered_input(bool search)
{
    Json properties = {{"domain", string_schema("opaque-id")}};
    Json required = Json::array();
    if(search)
    {
        properties["query"] = string_schema("utf8-text", 256);
        required.push_back("query");
    }
    else
    {
        properties["provider"] = string_schema("opaque-id");
        properties["availability"] = enum_schema({"planned", "implemented"});
    }
    return page_input(std::move(properties), std::move(required));
}

std::string lowercase_ascii(std::string value)
{
    for(auto& character : value)
        if(character >= 'A' && character <= 'Z')
            character = static_cast<char>(character - 'A' + 'a');
    return value;
}

struct SearchMatch
{
    const ToolDefinition* tool;
    std::uint32_t score;
};

std::size_t json_event_bound(const Json& value)
{
    if(!value.is_structured())
        return 1;
    std::size_t events = 3;
    for(const auto& child : value)
        events += json_event_bound(child) + (value.is_object() ? 1 : 0);
    return events;
}

Checked<Json> registry_page(const Json& input, bool search)
{
    const auto& tools = tool_registry();
    const auto query = search ? lowercase_ascii(input.at("query").get<std::string>()) : std::string{};
    Json filter = input;
    filter.erase("cursor");
    filter.erase("limit");
    const auto cursor_prefix = std::string("registry:") + BuildId + ":" + (search ? "search:" : "list:") + filter.dump() + ":";
    std::vector<SearchMatch> matches;
    for(const auto& tool : tools)
    {
        if(input.contains("domain") && input.at("domain") != tool.domain)
            continue;
        if(input.contains("provider") && input.at("provider") != tool.provider)
            continue;
        if(input.contains("availability") && input.at("availability") != (tool.handler ? "implemented" : "planned"))
            continue;
        std::uint32_t score = 0;
        if(search)
        {
            const auto name = lowercase_ascii(tool.name);
            if(name == query)
                score = 3;
            else if(name.find(query) != std::string::npos)
                score = 2;
            else if(lowercase_ascii(tool.description).find(query) != std::string::npos)
                score = 1;
            else
                continue;
        }
        matches.push_back({&tool, score});
    }
    std::sort(matches.begin(), matches.end(), [](const SearchMatch& left, const SearchMatch& right)
    {
        return left.score > right.score || (left.score == right.score && left.tool->name < right.tool->name);
    });
    std::size_t offset = 0;
    if(input.contains("cursor"))
    {
        const auto& cursor = input.at("cursor").get_ref<const std::string&>();
        if(cursor.compare(0, cursor_prefix.size(), cursor_prefix) != 0)
            return ContractError{"stale_context", "/cursor", "Registry cursor belongs to a different compiled snapshot or query"};
        const auto after = std::find_if(matches.begin(), matches.end(), [&](const SearchMatch& match) { return match.tool->name == cursor.substr(cursor_prefix.size()); });
        if(after == matches.end())
            return ContractError{"invalid_argument", "/cursor", "Registry cursor does not match this filtered result"};
        offset = static_cast<std::size_t>(after - matches.begin()) + 1;
    }
    const auto limit = input.value("limit", DefaultPageLimit);
    const auto requested_end = std::min(matches.size(), offset + limit);
    auto end = offset;
    std::size_t encoded_bytes = 4096;
    std::size_t events = 512;
    Json rows = Json::array();
    for(; end < requested_end; ++end)
    {
        auto row = search ? Json{{"capabilityId", matches[end].tool->name}, {"description", matches[end].tool->description}, {"score", matches[end].score}}
                          : tool_descriptor(*matches[end].tool);
        const auto row_bytes = row.dump().size() + 1;
        const auto row_events = json_event_bound(row);
        if(row_bytes > MaximumPayloadBytes - encoded_bytes || row_events > MaximumJsonEvents - events)
        {
            if(rows.empty())
                return ContractError{"resource_limit", "", "A capability descriptor exceeds the bounded catalog page"};
            break;
        }
        encoded_bytes += row_bytes;
        events += row_events;
        rows.push_back(std::move(row));
    }
    Json data = {{"snapshotId", BuildId}, {"items", rows}, {"complete", end == matches.size()}};
    if(end < matches.size())
        data["nextCursor"] = cursor_prefix + matches[end - 1].tool->name;
    return data;
}

Checked<Json> list_capabilities(const Json& input)
{
    return registry_page(input, false);
}

Checked<Json> search_capabilities(const Json& input)
{
    return registry_page(input, true);
}

Checked<Json> describe_capability(const Json& input)
{
    const auto* tool = find_tool(input.at("capabilityId").get<std::string>());
    if(!tool)
        return ContractError{"unsupported_capability", "/capabilityId", "Capability is not declared in the compiled registry"};
    return Json{{"capability", tool_descriptor(*tool)}};
}

Checked<std::string> local_installation_id(std::string_view imagePath)
{
    const auto image = launch_utf16(imagePath);
    if(const auto* error = std::get_if<ContractError>(&image))
        return *error;
    const auto directory = std::filesystem::path(std::get<std::wstring>(image)).parent_path();
    HANDLE raw = CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if(!raw || raw == INVALID_HANDLE_VALUE)
        return ContractError{"broker_start_failed", "", "Open installation directory failed with Win32 error " + std::to_string(GetLastError())};
    std::wstring final_path(32768, L'\0');
    const auto length = GetFinalPathNameByHandleW(raw, final_path.data(), static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(raw);
    if(!length || length >= final_path.size())
        return ContractError{"broker_start_failed", "", "Resolve installation directory failed with Win32 error " + std::to_string(GetLastError())};
    final_path.resize(length);
    const auto utf8 = launch_utf8(final_path);
    if(const auto* error = std::get_if<ContractError>(&utf8))
        return *error;
    return sha256_bytes(std::get<std::string>(utf8));
}

Checked<Json> server_info(const Json& input)
{
    (void)input;
    const auto identity = capture_current_process();
    if(const auto* error = std::get_if<ContractError>(&identity))
        return *error;
    const auto& owner = std::get<NativeProcessIdentity>(identity);
    const auto installation = local_installation_id(owner.image.path);
    if(const auto* error = std::get_if<ContractError>(&installation))
        return *error;
    return Json{{"buildId", BuildId},
        {"broker", Json{{"pid", owner.pid}, {"creationTime", decimal64(owner.creationTime)}, {"generation", decimal64(owner.creationTime)},
            {"installationId", std::get<std::string>(installation)}, {"imageSha256", owner.image.sha256}, {"sessionId", owner.sessionId}}},
        {"protocolProfiles", Json::array({"2024-11-05-suite"})},
        {"endpoint", Json{{"transport", "stdio"}, {"redactedAddress", "stdio"}}},
        {"limits", Json{{"frameBytes", MaximumFrameBytes}, {"payloadBytes", MaximumPayloadBytes},
            {"pageLimit", MaximumPageLimit}, {"timeoutMs", MaximumTimeoutMs}}}};
}

Checked<Json> server_health(const Json& input)
{
    (void)input;
    const auto identity = capture_current_process();
    if(const auto* error = std::get_if<ContractError>(&identity))
        return *error;
    return Json{{"broker", Json{{"status", "ready"}, {"failure", nullptr}}},
        {"ipc", Json{{"status", "unavailable"},
            {"failure", Json{{"code", "unsupported_capability"}, {"message", "No local IPC channel is configured in stdio mode"}, {"path", ""}}}}},
        {"store", Json{{"status", "unavailable"},
            {"failure", Json{{"code", "unsupported_capability"}, {"message", "No profile store is bound in stdio mode"}, {"path", ""}}}}}};
}

Json page_output(Json item)
{
    const auto properties = Json{{"snapshotId", string_schema("sha256", 64)}, {"items", bounded_array_schema(std::move(item), MaximumPageLimit)},
        {"complete", {{"type", "boolean"}}}, {"nextCursor", string_schema("utf8-text", 4096)}};
    auto complete = closed_object_schema(properties, {"snapshotId", "items", "complete"});
    complete["properties"].erase("nextCursor");
    complete["properties"]["complete"] = {{"const", true}};
    auto more = closed_object_schema(properties, {"snapshotId", "items", "complete", "nextCursor"});
    more["properties"]["complete"] = {{"const", false}};
    more["properties"]["items"]["minItems"] = 1;
    return {{"oneOf", Json::array({complete, more})}};
}
}

ToolDefinition define_tool(std::string name, std::string description, std::string domain, Json input, Json data,
    std::vector<Effect> effects, Executor executor, StateRequirement state, ArchitectureRequirement architecture,
    std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptanceIds,
    std::string nativeSource, bool idempotent, bool openWorld, RegistryHandler handler, std::vector<EffectCondition> effectConditions, bool nativeClassifiedEffects)
{
    input = with_contract_definitions(std::move(input));
    input["$schema"] = "https://json-schema.org/draft/2020-12/schema";
    input["$id"] = "urn:wininspect:mcp:tool:v1:" + name + ":input";
    auto output = result_schema(std::move(data));
    output["$id"] = "urn:wininspect:mcp:tool:v1:" + name + ":output";
    return {std::move(name), std::move(description), std::move(domain), "wininspect.native", std::move(input), std::move(output),
        std::move(effects), executor, state, architecture, std::move(completion), std::move(recovery), std::move(acceptanceIds),
        std::move(nativeSource), idempotent, openWorld, handler, std::move(effectConditions), nativeClassifiedEffects};
}

const std::vector<ToolDefinition>& tool_registry()
{
    static const auto registry = []
    {
        const auto id = string_schema("opaque-id");
        const auto decimal = contract_schema("Decimal64");
        const auto empty = closed_object_schema(Json::object(), Json::array());
        const auto descriptor = descriptor_schema();
        const auto lease_duration = bounded_integer_schema(1, MaximumTimeoutMs, 30000);
        auto target_lease = contract_schema("TargetRef");
        target_lease["properties"]["leaseId"] = id;
        target_lease["required"].push_back("leaseId");
        auto acquire = contract_schema("TargetRef");
        acquire["properties"]["durationMs"] = lease_duration;
        acquire["properties"]["purpose"] = string_schema("utf8-text", 1024);
        acquire["properties"]["idempotencyKey"] = id;
        acquire["required"].push_back("purpose");
        auto renew = target_lease;
        renew["properties"]["durationMs"] = lease_duration;
        renew["properties"]["idempotencyKey"] = id;
        auto release = target_lease;
        release["properties"]["idempotencyKey"] = id;
        const auto lease = closed_object_schema({{"leaseId", id}, {"target", contract_schema("TargetRef")}, {"expiresUtcMs", decimal}}, {"leaseId", "target", "expiresUtcMs"});
        const auto defaults = closed_object_schema({{"defaultInstance", contract_schema("InstanceRef")}, {"defaultTarget", contract_schema("TargetRef")}}, Json::array());
        const auto grant = closed_object_schema({{"clientId", id}, {"profileId", id}, {"effects", bounded_array_schema(enum_schema({"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"}), 7, 0, true)},
            {"namespaces", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"compatibilityDefaults", defaults}, {"leases", bounded_array_schema(lease, MaximumPageLimit)}},
            {"clientId", "profileId", "effects", "namespaces", "compatibilityDefaults", "leases"});
        const auto health_part = closed_object_schema({{"status", enum_schema({"ready", "degraded", "unavailable"})},
            {"failure", Json{{"oneOf", Json::array({contract_schema("DomainError"), {{"type", "null"}}})}}}}, {"status", "failure"});
        const auto broker = closed_object_schema({{"pid", bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max())}, {"creationTime", decimal},
            {"generation", decimal}, {"installationId", id}, {"imageSha256", string_schema("sha256", 64)}, {"sessionId", bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max())}},
            {"pid", "creationTime", "generation", "installationId", "imageSha256", "sessionId"});
        const auto info = closed_object_schema({{"buildId", string_schema("sha256", 64)}, {"broker", broker},
            {"protocolProfiles", bounded_array_schema(enum_schema({"2024-11-05-suite", "2025-03-26", "2025-11-25", "2026-07-28"}), 4, 1, true)},
            {"endpoint", closed_object_schema({{"transport", enum_schema({"stdio", "loopback_http"})}, {"redactedAddress", string_schema("utf8-text", 1024)}}, {"transport", "redactedAddress"})},
            {"limits", closed_object_schema({{"frameBytes", {{"const", MaximumFrameBytes}}}, {"payloadBytes", {{"const", MaximumPayloadBytes}}}, {"pageLimit", {{"const", MaximumPageLimit}}}, {"timeoutMs", {{"const", MaximumTimeoutMs}}}}, {"frameBytes", "payloadBytes", "pageLimit", "timeoutMs"})}},
            {"buildId", "broker", "protocolProfiles", "endpoint", "limits"});
        const auto search_item = closed_object_schema({{"capabilityId", id}, {"description", string_schema("utf8-text", 4096)}, {"score", bounded_integer_schema(1, 3)}}, {"capabilityId", "description", "score"});
        std::vector<ToolDefinition> tools;
        const auto add = [&](std::string name, std::string description, std::string domain, Json input, Json output, std::vector<Effect> effects,
                             StateRequirement state, std::string completion, std::vector<std::string> recovery, bool idempotent, RegistryHandler handler)
        {
            const auto source = handler ? "src/mcp/common/registry.cpp" : "planned:broker";
            const std::vector<std::string> acceptance = domain == "control" ? std::vector<std::string>{"A-08", "A-09", "A-48", "A-50"} : domain == "client" ? std::vector<std::string>{"A-08", "A-09", "A-50"} : std::vector<std::string>{"A-05", "A-06", "A-07", "A-08", "A-09", "A-64"};
            tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output),
                std::move(effects), Executor::Broker, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery),
                acceptance, source, idempotent, false, handler));
        };
        add("server_info", "Return the actual broker/build identity, supported protocol profiles, redacted endpoint and enforced limits.", "server", empty, info, {Effect::Inspect}, StateRequirement::Broker,
            "Broker process identity and actual listening profile are observed from the owning process.", {"server_health"}, true, server_info);
        add("server_health", "Inspect broker, worker-channel and store health with bounded failure causes and no credential values.", "server", empty,
            closed_object_schema({{"broker", health_part}, {"ipc", health_part}, {"store", health_part}}, {"broker", "ipc", "store"}), {Effect::Inspect}, StateRequirement::Broker,
            "Each health component is checked against its actual resource and current failure state.", {"server_info"}, true, server_health);
        add("capabilities_list", "List deterministic declared capabilities, including unavailable providers, schemas and completion requirements.", "capabilities", filtered_input(false), page_output(descriptor), {Effect::Inspect}, StateRequirement::Broker,
            "Every matching compiled descriptor appears exactly once across the requested snapshot pages.", {"capabilities_describe"}, true, list_capabilities);
        add("capabilities_describe", "Read the versioned schemas, effects, executor, native source, recovery and availability of one capability.", "capabilities",
            closed_object_schema({{"capabilityId", id}}, {"capabilityId"}), closed_object_schema({{"capability", descriptor}}, {"capability"}), {Effect::Inspect}, StateRequirement::Broker,
            "Returned descriptor equals the selected canonical compiled registry entry.", {"capabilities_list"}, true, describe_capability);
        add("capabilities_search", "Search capability names and descriptions with deterministic ranking; complete listing remains available.", "capabilities", filtered_input(true), page_output(search_item), {Effect::Inspect}, StateRequirement::Broker,
            "Matching entries are ordered by exact-name, name-substring, description-substring and then stable capability ID.", {"capabilities_list"}, true, search_capabilities);
        add("client_context_get", "Read the authenticated client's grant, profile, namespaces, compatibility defaults and owned leases.", "client", empty, grant, {Effect::Inspect}, StateRequirement::Broker,
            "Grant and lease state are read for the authenticated credential without another client's data.", {"client_context_set"}, true, nullptr);
        add("client_context_set", "Validate and update only the authenticated credential's compatibility defaults without changing global debugger selection.", "client", defaults, grant, {Effect::Configure}, StateRequirement::Broker,
            "Referenced identities are resolved and credential-local defaults are reread after the update.", {"client_context_get"}, true, nullptr);
        add("control_acquire", "Acquire a short target-generation lease for the authenticated client or return an explicit ownership conflict.", "control", acquire, lease, {Effect::Configure}, StateRequirement::TargetPresent,
            "Lease ownership and expiry are stored for the actual current target generation.", {"control_release", "target_state"}, false, nullptr);
        add("control_renew", "Renew an existing lease for its authenticated owner and current target generation.", "control", renew, lease, {Effect::Configure}, StateRequirement::TargetPresent,
            "Current owner, generation and expiry are checked and the renewed expiry is reread.", {"control_release", "target_state"}, false, nullptr);
        add("control_release", "Release the authenticated client's lease and reconcile pending work before claiming mutation authority is gone.", "control", release,
            closed_object_schema({{"leaseId", id}, {"released", {{"const", true}}}, {"pendingReconciled", {{"const", true}}}}, {"leaseId", "released", "pendingReconciled"}), {Effect::Configure}, StateRequirement::TargetPresent,
            "Released lease cannot authorize new mutations and previously accepted work is reconciled.", {"target_state"}, true, nullptr);
        append_lifecycle_tools(tools);
        append_execution_tools(tools);
        append_inspection_tools(tools);
        append_memory_tools(tools);
        append_breakpoint_trace_tools(tools);
        append_assembly_file_tools(tools);
        append_module_analysis_tools(tools);
        append_database_settings_tools(tools);
        append_provider_ui_tools(tools);
        append_library_script_tools(tools);
        append_job_event_artifact_tools(tools);
        std::sort(tools.begin(), tools.end(), [](const ToolDefinition& left, const ToolDefinition& right) { return left.name < right.name; });
        return tools;
    }();
    return registry;
}

const ToolDefinition* find_tool(std::string_view name)
{
    const auto& registry = tool_registry();
    const auto entry = std::lower_bound(registry.begin(), registry.end(), name, [](const ToolDefinition& tool, std::string_view key) { return tool.name < key; });
    return entry != registry.end() && entry->name == name ? &*entry : nullptr;
}

Json tool_descriptor(const ToolDefinition& tool)
{
    constexpr const char* effects[] = {"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"};
    constexpr const char* executors[] = {"broker", "engine", "gui", "script_host"};
    constexpr const char* states[] = {"broker", "instance_ready", "target_present", "target_paused"};
    constexpr const char* architectures[] = {"any", "x32", "x64"};
    Json effect_names = Json::array();
    for(const auto effect : tool.effects)
        effect_names.push_back(effects[static_cast<std::size_t>(effect)]);
    Json conditions = Json::array();
    for(const auto& condition : tool.effectConditions)
    {
        Json required = Json::array();
        for(const auto effect : condition.effects)
            required.push_back(effects[static_cast<std::size_t>(effect)]);
        conditions.push_back({{"field", condition.field}, {"equals", condition.equals}, {"effects", required}});
    }
    auto possible_effects = tool.effects;
    for(const auto& condition : tool.effectConditions)
        possible_effects.insert(possible_effects.end(), condition.effects.begin(), condition.effects.end());
    const auto destructive = std::any_of(possible_effects.begin(), possible_effects.end(), [](Effect effect)
    {
        return effect == Effect::Modify || effect == Effect::FileReplace || effect == Effect::Execute;
    });
    Json descriptor = {{"capabilityId", tool.name}, {"name", tool.name}, {"description", tool.description}, {"domain", tool.domain}, {"provider", tool.provider},
        {"schemaVersion", ContractVersion}, {"inputSchema", tool.inputSchema}, {"outputSchema", tool.outputSchema}, {"effects", effect_names}, {"effectConditions", conditions},
        {"executor", executors[static_cast<std::size_t>(tool.executor)]}, {"stateRequirement", states[static_cast<std::size_t>(tool.state)]},
        {"architectureRequirement", architectures[static_cast<std::size_t>(tool.architecture)]}, {"completionPredicate", tool.completion},
        {"recovery", tool.recovery}, {"acceptanceIds", tool.acceptanceIds}, {"nativeSource", tool.nativeSource},
        {"availability", tool.handler ? "implemented" : "planned"}, {"operational", false},
        {"annotations", {{"readOnlyHint", tool.effects == std::vector<Effect>{Effect::Inspect} && tool.effectConditions.empty()}, {"destructiveHint", destructive}, {"idempotentHint", tool.idempotent}, {"openWorldHint", tool.openWorld}}}};
    if(tool.nativeClassifiedEffects)
        descriptor["effectResolution"] = "native_classifier";
    return descriptor;
}

Checked<std::vector<Effect>> required_tool_effects(std::string_view name, const Json& input)
{
    if(auto error = validate_tool_input(name, input))
        return *error;
    const auto* tool = find_tool(name);
    if(tool->nativeClassifiedEffects)
        return ContractError{"unsupported_capability", "", "Effective permissions require the resolved native provider/action classifier"};
    auto effects = tool->effects;
    for(const auto& condition : tool->effectConditions)
        if(input.contains(condition.field) && input.at(condition.field) == condition.equals)
            for(const auto effect : condition.effects)
                if(std::find(effects.begin(), effects.end(), effect) == effects.end())
                    effects.push_back(effect);
    return effects;
}

Json compiled_tool_registry()
{
    Json entries = Json::array();
    for(const auto& tool : tool_registry())
        entries.push_back(tool_descriptor(tool));
    return {{"schemaVersion", ContractVersion}, {"buildId", BuildId}, {"tools", entries}, {"operationalTools", Json::array()}};
}

std::optional<ContractError> validate_tool_input(std::string_view name, const Json& input)
{
    const auto* tool = find_tool(name);
    return tool ? validate_schema(tool->inputSchema, input) : ContractError{"unsupported_capability", "", "Tool is not declared in the compiled registry"};
}

std::optional<ContractError> validate_tool_output(std::string_view name, const Json& output)
{
    const auto* tool = find_tool(name);
    return tool ? validate_schema(tool->outputSchema, output) : ContractError{"unsupported_capability", "", "Tool is not declared in the compiled registry"};
}

Checked<Json> call_registry_tool(std::string_view name, const Json& input, const RegistryCallContext& context)
{
    const auto* tool = find_tool(name);
    if(auto error = validate_tool_input(name, input))
        return *error;
    if(!tool->handler)
        return ContractError{"unsupported_capability", "", "Declared capability has no implemented native handler"};
    if(tool->nativeClassifiedEffects || tool->effects != std::vector<Effect>{Effect::Inspect} || !tool->effectConditions.empty() || tool->executor != Executor::Broker || tool->state != StateRequirement::Broker)
        return ContractError{"unsupported_capability", "", "Registry metadata dispatch only executes broker inspection handlers"};
    const auto started = std::chrono::steady_clock::now();
    const auto utc = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto result = tool->handler(input);
    if(const auto* error = std::get_if<ContractError>(&result))
        return *error;
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count();
    ResultHeader header{context.operationId, BrokerContext{context.brokerGeneration}, context.stateVersion,
        {VerificationStatus::Verified, {{"registry_observation", "compiled_registry", tool->completion, {}, {}}}, {}}, {},
        {static_cast<std::uint64_t>(utc), static_cast<std::uint64_t>(elapsed), 0}};
    auto output = result_json(OperationResult<Json>{std::move(header), CompletedResult<Json>{std::get<Json>(std::move(result)), false, {}}});
    if(auto error = validate_tool_output(name, output))
        return ContractError{"invalid_result", error->path, "Native handler produced a result outside its declared output schema"};
    return output;
}
}
