#include "lifecycle.h"
#include "registry.h"
#include "schema_helpers.h"
#include <limits>

namespace wininspect::mcp
{
namespace
{
Json nullable(Json schema)
{
    return {{"oneOf", Json::array({std::move(schema), {{"type", "null"}}})}};
}

Json initial_stop_schema()
{
    return {{"oneOf", Json::array({enum_schema({"configured", "system_breakpoint", "entry_point"}),
        closed_object_schema({{"name", string_schema("opaque-id")}}, {"name"})})}, {"default", "configured"}};
}

Json launch_fields(Json base)
{
    base["properties"].update({{"cwd", string_schema("windows-absolute-path", 32767)}, {"environment", launch_environment_schema()},
        {"initialStop", initial_stop_schema()}, {"initScript", reference_schema("LibraryRef")}});
    return base;
}

Json instance_input(Json properties = Json::object(), Json required = Json::array())
{
    auto schema = contract_schema("InstanceRef");
    schema["properties"].update(properties);
    for(const auto& field : required)
        schema["required"].push_back(field);
    return schema;
}

Json target_input(Json properties = Json::object(), Json required = Json::array(), bool mutation = false)
{
    auto schema = contract_schema("TargetRef");
    schema["properties"].update(properties);
    for(const auto& field : required)
        schema["required"].push_back(field);
    if(mutation)
    {
        schema["properties"]["leaseId"] = string_schema("opaque-id");
        schema["properties"]["idempotencyKey"] = string_schema("opaque-id");
        schema["required"].push_back("leaseId");
    }
    return schema;
}

Json page_data(Json item)
{
    return closed_object_schema({{"items", bounded_array_schema(std::move(item), MaximumPageLimit)},
        {"page", reference_schema("ResultPagination")}}, {"items", "page"});
}

Json setting_schema(bool observed)
{
    Json properties = {{"section", string_schema("utf8-text", 128)}, {"key", string_schema("utf8-text", 128)}, {"value", typed_setting_value_schema()}};
    Json required = {"section", "key", "value"};
    if(observed)
    {
        properties["storage"] = enum_schema({"current", "persistent", "both"});
        properties["requiresRestart"] = {{"type", "boolean"}};
        properties["nativeWidth"] = enum_schema({32, 64});
        required.push_back("storage");
        required.push_back("requiresRestart");
    }
    return closed_object_schema(std::move(properties), std::move(required));
}

Json image_identity()
{
    return closed_object_schema({{"path", string_schema("windows-absolute-path", 32767)}, {"sha256", string_schema("sha256", 64)},
        {"size", reference_schema("Decimal64")}}, {"path", "sha256"});
}

Json process_identity()
{
    return closed_object_schema({{"pid", bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max())},
        {"creationTime", nullable(reference_schema("Decimal64"))}, {"image", nullable(image_identity())},
        {"architecture", enum_schema({"x32", "x64", "unknown"})}, {"integrity", enum_schema({"low", "medium", "high", "system", "unknown"})}},
        {"pid", "creationTime", "image", "architecture", "integrity"});
}

Json target_observation()
{
    const auto stop = closed_object_schema({{"kind", enum_schema({"none", "system_breakpoint", "entry_point", "breakpoint", "exception", "step", "user_pause", "requested_stop", "exit", "detach", "unknown"})},
        {"eventCursor", string_schema("utf8-text", 4096)}, {"breakpointId", string_schema("opaque-id")}, {"exceptionCode", reference_schema("Hex64")},
        {"firstChance", {{"type", "boolean"}}}}, {"kind"});
    return closed_object_schema({{"target", reference_schema("TargetRef")}, {"state", nullable(enum_schema({"none", "loading", "attaching", "running", "pausing", "paused", "stopping", "detached", "exited", "failed"}))},
        {"certainty", enum_schema({"observed", "last_known", "unknown"})}, {"stopEpoch", reference_schema("Decimal64")},
        {"stopReason", stop}, {"ipHex", nullable(reference_schema("Hex64"))}, {"threadId", nullable(bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max()))},
        {"pendingJobId", nullable(string_schema("opaque-id"))}, {"process", nullable(process_identity())},
        {"allThreadsStopped", {{"type", "boolean"}}}, {"exitCode", nullable(bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max()))}},
        {"target", "state", "certainty", "stopEpoch", "stopReason", "ipHex", "threadId", "pendingJobId", "process", "allThreadsStopped", "exitCode"});
}

Json snapshot_data()
{
    const auto register_value = closed_object_schema({{"name", string_schema("opaque-id")}, {"group", enum_schema({"general", "flags", "segments", "debug", "x87", "mmx", "sse", "avx", "avx512"})},
        {"widthBits", bounded_integer_schema(1, 512)}, {"bytesHex", nullable(string_schema("hex-bytes", 128))},
        {"validity", enum_schema({"valid", "unavailable", "unsupported"})}, {"reason", nullable(string_schema("utf8-text", 4096))}},
        {"name", "group", "widthBits", "bytesHex", "validity", "reason"});
    const auto module = closed_object_schema({{"moduleId", string_schema("opaque-id")}, {"name", string_schema("utf8-text", 1024)},
        {"baseHex", reference_schema("Hex64")}, {"size", reference_schema("Decimal64")}, {"image", nullable(image_identity())}}, {"moduleId", "name", "baseHex", "size", "image"});
    const auto breakpoint = closed_object_schema({{"breakpointId", string_schema("opaque-id")}, {"kind", string_schema("opaque-id")},
        {"addressHex", nullable(reference_schema("Hex64"))}, {"enabled", {{"type", "boolean"}}}, {"hits", reference_schema("Decimal64")}}, {"breakpointId", "kind", "addressHex", "enabled", "hits"});
    const auto frame = closed_object_schema({{"index", bounded_integer_schema(0, MaximumPageLimit)}, {"ipHex", reference_schema("Hex64")},
        {"spHex", reference_schema("Hex64")}, {"returnHex", nullable(reference_schema("Hex64"))}, {"symbol", nullable(string_schema("utf8-text", 4096))},
        {"source", enum_schema({"unwind", "frame_pointer", "scan", "engine", "unknown"})}}, {"index", "ipHex", "spHex", "returnHex", "symbol", "source"});
    return closed_object_schema({{"state", target_observation()}, {"consistency", enum_schema({"paused", "best_effort"})},
        {"capturedParts", bounded_array_schema(enum_schema({"registers", "modules", "breakpoints", "stack"}), 4, 1, true)},
        {"registers", bounded_array_schema(register_value, 512)}, {"modules", page_data(module)}, {"breakpoints", page_data(breakpoint)},
        {"stack", page_data(frame)}, {"complete", {{"type", "boolean"}}}}, {"state", "consistency", "capturedParts", "complete"});
}
}

Json launch_environment_schema()
{
    auto mode = enum_schema({"inherit", "replace"});
    mode["default"] = "inherit";
    return closed_object_schema({{"mode", mode}, {"changes", bounded_array_schema(closed_object_schema({
        {"name", string_schema("windows-environment-name", MaximumWindowsCommandUnits)},
        {"value", nullable(string_schema("utf8-text", MaximumWindowsCommandUnits, 0))}}, {"name", "value"}), MaximumEnvironmentChanges)}}, {"changes"});
}

Json launch_argument_forms(Json base, bool required)
{
    auto argv = base;
    argv["properties"]["argv"] = bounded_array_schema(string_schema("utf8-text", MaximumWindowsCommandUnits, 0), MaximumLaunchArguments);
    if(required)
        argv["required"].push_back("argv");
    auto raw = base;
    raw["properties"]["rawCommandLine"] = string_schema("windows-command-line", MaximumWindowsCommandUnits, 0);
    raw["required"].push_back("rawCommandLine");
    return {{"oneOf", Json::array({argv, raw})}};
}

Json launch_overrides_schema()
{
    return launch_argument_forms(launch_fields(closed_object_schema(Json::object(), Json::array())), false);
}

Json target_open_schema()
{
    auto base = launch_fields(instance_input({{"idempotencyKey", string_schema("opaque-id")}}));
    Json choices = Json::array();
    const auto references = contract_schema("FileRef");
    for(const auto& reference : references.at("oneOf"))
    {
        auto schema = base;
        schema["properties"].update(reference.at("properties"));
        for(const auto& field : reference.at("required"))
            schema["required"].push_back(field);
        const auto forms = launch_argument_forms(std::move(schema), false);
        for(const auto& form : forms.at("oneOf"))
            choices.push_back(form);
    }
    return {{"oneOf", std::move(choices)}};
}

void append_lifecycle_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto architecture = enum_schema({"x32", "x64"});
    const auto mode = enum_schema({"gui", "headless"});
    const auto process = process_identity();
    const auto instance = closed_object_schema({{"instanceId", id}, {"workerGeneration", decimal}, {"architecture", architecture}, {"mode", mode},
        {"state", enum_schema({"requested", "awaiting_user_consent", "starting", "ready", "closing", "disconnected", "crashed", "closed"})},
        {"engineReady", {{"type", "boolean"}}}, {"process", nullable(process)}, {"buildId", string_schema("sha256", 64)},
        {"installationId", id}, {"profileId", id}}, {"instanceId", "workerGeneration", "architecture", "mode", "state", "engineReady", "process", "buildId", "installationId", "profileId"});
    auto instances_input = contract_schema("Page");
    instances_input["properties"].update({{"architecture", architecture}, {"mode", mode}});
    auto processes_input = contract_schema("Page");
    processes_input["properties"].update({{"name", string_schema("utf8-text", 1024)}, {"architecture", architecture}});
    auto process_row = process;
    process_row["properties"]["attachAvailable"] = {{"type", "boolean"}};
    process_row["properties"]["limitations"] = bounded_array_schema(reference_schema("DomainError"), 16);
    process_row["required"].push_back("attachAvailable");
    process_row["required"].push_back("limitations");
    const auto settings_data = closed_object_schema({{"instanceId", id}, {"version", decimal}, {"settings", bounded_array_schema(setting_schema(true), MaximumPageLimit)},
        {"complete", {{"type", "boolean"}}}}, {"instanceId", "version", "settings", "complete"});
    const auto command_line_data = closed_object_schema({{"target", reference_schema("TargetRef")}, {"version", decimal},
        {"nextLaunch", launch_overrides_schema()}, {"actualCommandLine", nullable(string_schema("windows-command-line", MaximumWindowsCommandUnits, 0))},
        {"currentProcessUpdated", {{"type", "boolean"}}}}, {"target", "version", "nextLaunch", "actualCommandLine", "currentProcessUpdated"});
    const auto add = [&](std::string name, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, StateRequirement state, std::string completion, std::vector<std::string> recovery,
        std::vector<std::string> acceptance, std::string source, bool idempotent, bool openWorld = false,
        std::vector<EffectCondition> conditions = {})
    {
        const auto domain = name.compare(0, 9, "debugger_") == 0 ? "debugger" : name == "processes_list" ? "processes" : "target";
        tools.push_back(define_tool(std::move(name), std::move(description), domain, std::move(input), std::move(output), std::move(effects),
            executor, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance),
            "planned:" + source, idempotent, openWorld, nullptr, std::move(conditions)));
    };
    add("debugger_instances", "List live and stale debugger instances with exact process identity, rights, architecture and engine readiness.", instances_input, page_data(instance),
        {Effect::Inspect}, Executor::Broker, StateRequirement::Broker, "Matching live/stale registration records reconcile to actual worker process identities.", {"debugger_start", "server_health"}, {"A-01", "A-02", "A-10"}, "broker/instances", true);
    add("debugger_start", "Start the selected ordinary or administrator GUI/headless engine. Administrator requests require an additional elevation grant and real visible Windows consent.",
        closed_object_schema({{"architecture", architecture}, {"mode", mode}, {"privilege", enum_schema({"user", "administrator"})}, {"installationId", id}, {"profileId", id}, {"idempotencyKey", id}}, {"architecture", "mode", "privilege"}),
        closed_object_schema({{"instance", instance}, {"launchJobId", id}}, {"instance", "launchJobId"}), {Effect::Execute}, Executor::Broker, StateRequirement::Broker,
        "Requested engine is registered and ready with observed process architecture/integrity; pending consent or launch is accepted rather than completed.", {"job_get", "debugger_instances"}, {"A-01", "A-11", "A-14", "A-15", "A-16"}, "broker/worker_launch", false, true,
        {{"privilege", "administrator", {Effect::Elevate}}});
    add("debugger_focus", "Focus the actual GUI instance; a headless instance returns explicit unavailability.", instance_input(),
        closed_object_schema({{"instanceId", id}, {"visible", {{"type", "boolean"}}}, {"focused", {{"type", "boolean"}}}}, {"instanceId", "visible", "focused"}), {Effect::Configure}, Executor::Gui, StateRequirement::InstanceReady,
        "Actual GUI visibility/focus is observed after dispatch on the GUI owner thread.", {"debugger_instances"}, {"A-11", "A-51"}, "src/gui/Src/MainWindow.cpp", true);
    add("debugger_close", "Close one instance under an explicit target disposition policy while preserving broker availability.",
        instance_input({{"targetPolicy", enum_schema({"stop", "detach", "require_none"})}, {"idempotencyKey", id}}, {"targetPolicy"}),
        closed_object_schema({{"instanceId", id}, {"closed", {{"const", true}}}, {"targetDisposition", enum_schema({"none", "exited", "detached"})}, {"brokerListening", {{"const", true}}}}, {"instanceId", "closed", "targetDisposition", "brokerListening"}),
        {Effect::Execute}, Executor::Broker, StateRequirement::InstanceReady, "Target policy is observed and the exact instance unregisters without shutting down the broker.", {"operation_reconcile", "debugger_instances"}, {"A-02", "A-03", "A-13"}, "broker/instances", false);
    add("debugger_settings_get", "Read typed current/persistent settings with versions, native widths and restart requirements.", instance_input({{"section", string_schema("utf8-text", 128)}}), settings_data,
        {Effect::Inspect}, Executor::Engine, StateRequirement::InstanceReady, "Requested settings are read from their actual native storage/provider with explicit coverage.", {"debugger_settings_get"}, {"A-38", "A-51"}, "src/bridge/bridgemain.cpp", true);
    add("debugger_settings_set", "Apply compare-versioned typed setting changes and reread the values; restart or elevation is never implicit.",
        instance_input({{"changes", bounded_array_schema(setting_schema(false), MaximumPageLimit, 1)}, {"expectedVersion", decimal}, {"idempotencyKey", id}}, {"changes", "expectedVersion"}), settings_data,
        {Effect::Configure}, Executor::Engine, StateRequirement::InstanceReady, "Expected native version matches and every changed value is reread with its persistence/restart state.", {"debugger_settings_get", "operation_reconcile"}, {"A-38", "A-48", "A-51"}, "src/bridge/bridgemain.cpp", false);
    add("processes_list", "List process IDs, creation times, image identities, architecture and actual attach availability/rights limitations.", processes_input, page_data(process_row),
        {Effect::Inspect}, Executor::Broker, StateRequirement::Broker, "Each reported process row comes from current OS inspection; inaccessible identity fields are explicitly unknown.", {"processes_list", "target_attach"}, {"A-10", "A-13"}, "broker/processes", true);
    add("target_open", "Open an explicitly identified executable or artifact with argv or a complete raw Windows command line, cwd and isolated environment changes. initScript uses a pinned library revision and its own intersected permissions.", target_open_schema(), target_observation(),
        {Effect::Execute}, Executor::Engine, StateRequirement::InstanceReady, "Actual created process identity and its requested initial stop/state match the intended launch; queued creation alone is accepted.", {"target_state", "operation_reconcile"}, {"A-11", "A-12", "A-13"}, "src/dbg/debugger.cpp", false, true);
    add("target_attach", "Attach to the exact PID/creation-time/image identity with the selected initial stop; PID reuse or insufficient integrity fails before attach.",
        instance_input({{"pid", bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max())}, {"creationTime", decimal}, {"expectedImage", image_identity()}, {"initialStop", initial_stop_schema()}, {"idempotencyKey", id}}, {"pid", "creationTime"}), target_observation(),
        {Effect::Execute}, Executor::Engine, StateRequirement::InstanceReady, "Attach callback and observed process identity match the request and actual target generation.", {"target_state", "operation_reconcile"}, {"A-10", "A-13", "A-16"}, "src/dbg/commands/cmd-debug-control.cpp", false, true);
    add("target_state", "Read the identified target's execution state, stop reason, context, pending job and observed-versus-uncertain identity.", target_input(), target_observation(),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Requested target generation resolves to a correlated current observation or explicitly uncertain retained state.", {"target_state", "operation_reconcile"}, {"A-13", "A-48", "A-50"}, "src/dbg/debugger.cpp", true);
    add("target_snapshot", "Capture one bounded correlated registers/modules/breakpoints/stack snapshot with explicit consistency, validity and completeness.",
        target_input({{"parts", bounded_array_schema(enum_schema({"registers", "modules", "breakpoints", "stack"}), 4, 1, true)}, {"consistency", enum_schema({"paused", "best_effort"})}}), snapshot_data(),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Selected parts belong to the same identified target/stop snapshot; holes, limits and running-state uncertainty are reported.", {"target_state", "target_snapshot"}, {"A-17", "A-18", "A-19", "A-22", "A-50"}, "src/dbg/debugger.cpp", true);
    add("target_stop", "Stop the identified target under an explicit exit policy and observe its actual process disposition.",
        target_input({{"exitPolicy", enum_schema({"terminate", "require_exited"})}}, Json::array(), true), target_observation(),
        {Effect::Execute}, Executor::Engine, StateRequirement::TargetPresent, "Debug loop termination and real target exit disposition are observed; request acceptance alone does not complete stop.", {"target_state", "operation_reconcile"}, {"A-13", "A-48"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("target_detach", "Detach the identified target under an explicit continuation policy and observe target liveness after debugger removal.",
        target_input({{"resumePolicy", enum_schema({"resume", "preserve_suspension"})}}, Json::array(), true), target_observation(),
        {Effect::Execute}, Executor::Engine, StateRequirement::TargetPresent, "Actual detach event and requested target continuation/suspend disposition are independently observed.", {"target_state", "operation_reconcile"}, {"A-13", "A-48", "A-50"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("target_restart", "Restart with a new target generation, preserving existing launch parameters except explicit overrides.",
        target_input({{"launchOverrides", launch_overrides_schema()}}, Json::array(), true), target_observation(), {Effect::Execute}, Executor::Engine, StateRequirement::TargetPresent,
        "Old target disposition and new created identity/generation/initial stop are observed with the requested preserved or overridden arguments.", {"target_state", "operation_reconcile"}, {"A-12", "A-13", "A-48"}, "src/dbg/commands/cmd-debug-control.cpp", false, true);
    add("target_command_line_get", "Read actual launch settings and the observed current process command line where access permits.", target_input(), command_line_data,
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Launch settings/version and available process command line are read from the identified target.", {"target_command_line_get", "target_state"}, {"A-12", "A-13"}, "src/dbg/debugger.cpp", true);
    add("target_command_line_set", "Set explicit argv or complete raw command line for the next launch under a version precondition; any supported current-process change is reported separately.",
        launch_argument_forms(target_input({{"expectedVersion", decimal}}, {"expectedVersion"}, true), true), command_line_data, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Expected launch version matches and next-launch settings are reread; current-process update is reported only when observed and explicitly supported.", {"target_command_line_get", "operation_reconcile"}, {"A-12", "A-13", "A-48"}, "src/dbg/debugger.cpp", false);
}
}
