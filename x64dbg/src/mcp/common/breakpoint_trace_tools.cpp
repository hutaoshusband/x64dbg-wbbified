#include "registry.h"
#include "inspection_types.h"
#include "patch_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json breakpoint_options(bool observed)
{
    const auto text = string_schema("utf8-text", 4096, 0);
    Json properties = {{"name", string_schema("utf8-text", 1024, 0)}, {"enabled", {{"type", "boolean"}}}, {"singleShot", {{"type", "boolean"}}},
        {"silent", {{"type", "boolean"}}}, {"fastResume", {{"type", "boolean"}}}, {"breakCondition", text}, {"logText", text}, {"logCondition", text},
        {"commandText", text}, {"commandCondition", text}, {"logFile", nullable_schema(reference_schema("FileRef"))}};
    Json required = observed ? Json{"name", "enabled", "singleShot", "silent", "fastResume", "breakCondition", "logText", "logCondition", "commandText", "commandCondition", "logFile"} : Json::array();
    return closed_object_schema(std::move(properties), std::move(required));
}

Json breakpoint_forms(Json base, bool observed)
{
    const auto address = reference_schema("AddressRef");
    const auto options = breakpoint_options(observed);
    auto code = contract_schema("Hex64");
    code["maxLength"] = 10;
    auto hardwareExecute = extend_object_schema(options, {{"access", {{"const", "execute"}}}, {"size", {{"const", 1}}}}, {"access", "size"});
    auto hardwareData = extend_object_schema(options, {{"access", enum_schema({"write", "read_write"})}, {"size", enum_schema({1, 2, 4, 8})}}, {"access", "size"});
    const auto hardware = Json{{"oneOf", Json::array({hardwareExecute, hardwareData})}};
    const auto memory = extend_object_schema(options, {{"access", enum_schema({"read", "write", "execute", "any"})},
        {"overlapPolicy", enum_schema({"reject", "preserve"})}}, observed ? Json{"access", "overlapPolicy"} : Json::array());
    const auto software = extend_object_schema(options, {{"encoding", enum_schema({"int3", "long_int3", "ud2"})}}, observed ? Json{"encoding"} : Json::array());
    const auto module = extend_object_schema(options, {{"event", enum_schema({"load", "unload", "either"})}}, observed ? Json{"event"} : Json::array());
    const auto exception = extend_object_schema(options, {{"chance", enum_schema({"first", "second", "either"})}}, observed ? Json{"chance"} : Json::array());
    const auto moduleLocation = Json{{"oneOf", Json::array({closed_object_schema({{"moduleId", string_schema("opaque-id")}}, {"moduleId"}),
        closed_object_schema({{"moduleName", string_schema("utf8-text", 1024)}}, {"moduleName"})})}};
    struct Form { const char* kind; Json location; Json options; };
    Json choices = Json::array();
    for(const auto& form : std::vector<Form>{{"software", address, software}, {"hardware", address, hardware}, {"memory", reference_schema("AddressRange"), memory},
        {"module", moduleLocation, module}, {"exception", closed_object_schema({{"codeHex", code}}, {"codeHex"}), exception}})
    {
        auto required = Json{"kind", "location"};
        if(observed)
            required.push_back("options");
        choices.push_back(extend_object_schema(base, {{"kind", {{"const", form.kind}}}, {"location", form.location}, {"options", form.options}}, required));
    }
    return {{"oneOf", std::move(choices)}};
}

Json trace_limits()
{
    auto instructions = closed_object_schema({{"maxInstructions", positive_decimal_schema()}, {"maxWallTimeMs", bounded_integer_schema(1, MaximumTimeoutMs)},
        {"maxArtifactBytes", positive_decimal_schema()}}, {"maxInstructions"});
    auto time = instructions;
    time["properties"].erase("maxInstructions");
    time["required"] = Json{"maxWallTimeMs"};
    return {{"oneOf", Json::array({instructions, time})}};
}
}

void append_breakpoint_trace_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto hex = reference_schema("Hex64");
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto kinds = enum_schema({"software", "hardware", "memory", "module", "exception"});
    const auto mutation = [&](Json properties = Json::object(), Json required = Json::array())
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        required.push_back("leaseId");
        return context_schema("TargetRef", std::move(properties), std::move(required));
    };
    const auto record = breakpoint_forms(closed_object_schema({{"breakpointId", id}, {"revision", id}, {"target", reference_schema("TargetRef")},
        {"addressHex", nullable_schema(hex)}, {"hits", decimal}, {"active", boolSchema}, {"nativeTypeHex", hex},
        {"hardwareSlot", nullable_schema(bounded_integer_schema(0, 3))}, {"creatorClientId", nullable_schema(id)},
        {"state", enum_schema({"installed", "disabled", "unloaded", "failed", "unknown"})}},
        {"breakpointId", "revision", "target", "addressHex", "hits", "active", "nativeTypeHex", "hardwareSlot", "creatorClientId", "state"}), true);
    const auto ids = bounded_array_schema(id, MaximumPageLimit, 1, true);
    const auto disposition = closed_object_schema({{"breakpointId", id}, {"status", enum_schema({"changed", "removed", "unchanged", "failed", "unknown"})},
        {"observed", nullable_schema(record)}, {"error", nullable_schema(reference_schema("DomainError"))}}, {"breakpointId", "status", "observed", "error"});
    const auto dispositions = closed_object_schema({{"items", bounded_array_schema(disposition, MaximumPageLimit)}, {"complete", boolSchema}}, {"items", "complete"});
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent)
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + source, idempotent, false));
    };
    add("breakpoints_list", "breakpoints", "List every native breakpoint kind with full condition/action/logging/hit and installation state.",
        with_page_schema(context_schema("TargetRef", {{"kind", kinds}})), paged_data_schema(record), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "All selected actual native breakpoint records are enumerated with correlated pages and explicit installation/unknown state.",
        {"breakpoints_list", "target_state"}, {"A-25", "A-26"}, "src/dbg/breakpoint.cpp", true);
    add("breakpoints_create", "breakpoints", "Install one typed native breakpoint. Hardware execute size is one; data sizes are 1/2/4/8 with resolved alignment/target-width preflight. Memory overlap policy preserves or rejects ownership conflicts. Embedded commands/providers require separate effect/grant preflight.",
        breakpoint_forms(context_schema("MutationContext"), false), record, {Effect::Modify}, Executor::Engine, StateRequirement::TargetPaused,
        "The actual requested native breakpoint is installed/reread with verified type/size/access/alignment, slot/range ownership and creator-bound callback permissions.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-26", "A-30", "A-48"}, "src/dbg/commands/cmd-breakpoint-control.cpp", false);
    auto changes = breakpoint_options(false);
    changes = extend_object_schema(changes, {{"size", enum_schema({1, 2, 4, 8})}, {"access", enum_schema({"execute", "write", "read_write", "read", "any"})},
        {"encoding", enum_schema({"int3", "long_int3", "ud2"})}, {"event", enum_schema({"load", "unload", "either"})},
        {"chance", enum_schema({"first", "second", "either"})}, {"overlapPolicy", enum_schema({"reject", "preserve"})}}, Json::array());
    changes["not"] = {{"const", Json::object()}};
    add("breakpoints_update", "breakpoints", "Compare revision and change native breakpoint fields after validating the existing kind and embedded command/provider effects.",
        mutation({{"breakpointId", id}, {"changes", changes}, {"expectedRevision", id}}, {"breakpointId", "changes", "expectedRevision"}), record,
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent, "Expected native revision/type-specific preflight matches and every changed field is reread with actual trap/page/debug-register state.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-26", "A-30", "A-48"}, "src/dbg/commands/cmd-conditional-breakpoint-control.cpp", false);
    add("breakpoints_delete", "breakpoints", "Remove exact breakpoint IDs while preserving original bytes, other owners' page guards and debug-register state.", mutation({{"breakpointIds", ids}}, {"breakpointIds"}), dispositions,
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent, "Each requested breakpoint is absent or has an exact failure; restored bytes/pages/registers and remaining ownership are observed.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-30", "A-31"}, "src/dbg/commands/cmd-breakpoint-control.cpp", false);
    add("breakpoints_enable", "breakpoints", "Set explicit enabled state for exact breakpoint IDs, validating native install constraints and preserving overlapping owners.",
        mutation({{"breakpointIds", ids}, {"enabled", boolSchema}}, {"breakpointIds", "enabled"}), dispositions, {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent,
        "Each exact breakpoint's enabled and native installation/trap state is reread; limits, conflicts and partial effects are explicit.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-30", "A-48"}, "src/dbg/commands/cmd-breakpoint-control.cpp", false);
    add("breakpoints_toggle", "breakpoints", "Compare expected enabled state before toggling one exact native breakpoint.",
        mutation({{"breakpointId", id}, {"expectedEnabled", boolSchema}}, {"breakpointId", "expectedEnabled"}), record, {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent,
        "Expected enabled state matches and the opposite native enabled/installation state is observed, or conflict is reported without a blind toggle.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-48"}, "src/dbg/commands/cmd-breakpoint-control.cpp", false);
    add("breakpoints_reset_hits", "breakpoints", "Reset actual native hit counters for exact breakpoint IDs.", mutation({{"breakpointIds", ids}}, {"breakpointIds"}), dispositions,
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent, "Selected native hit counters are reread as zero and unselected counters remain intact.",
        {"breakpoints_list", "operation_reconcile"}, {"A-26", "A-48"}, "src/dbg/breakpoint.cpp", false);
    add("breakpoints_clear", "breakpoints", "Clear selected native breakpoint kinds and preserve unrelated kinds/overlap ownership.", mutation({{"kind", kinds}}), dispositions,
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent, "Selected breakpoints are absent and exact remaining catalog/bytes/page/debug-register state is observed; partial failures remain explicit.",
        {"breakpoints_list", "operation_reconcile"}, {"A-25", "A-30", "A-31"}, "src/dbg/commands/cmd-breakpoint-control.cpp", false);
    const auto limits = trace_limits();
    const auto indexing = closed_object_schema({{"state", enum_schema({"pending", "running", "complete", "failed"})}, {"entries", decimal},
        {"error", nullable_schema(reference_schema("DomainError"))}}, {"state", "entries", "error"});
    const auto trace = closed_object_schema({{"traceId", id}, {"target", reference_schema("TargetRef")}, {"jobId", id}, {"mode", enum_schema({"into", "over"})},
        {"state", enum_schema({"queued", "running", "stopping", "stopped", "indexing", "completed", "failed", "unknown"})}, {"executedInstructions", decimal},
        {"producedEntries", decimal}, {"limits", limits}, {"recording", boolSchema}, {"artifact", nullable_schema(managed_artifact_schema())}, {"indexing", indexing},
        {"stopReason", enum_schema({"none", "condition", "instruction_limit", "wall_time_limit", "breakpoint", "exception", "manual", "target_exit", "interrupted", "fault", "unknown"})}},
        {"traceId", "target", "jobId", "mode", "state", "executedInstructions", "producedEntries", "limits", "recording", "artifact", "indexing", "stopReason"});
    add("trace_start", "trace", "Start actual into/over conditional tracing under a paused thread lease with at least an instruction or wall-time ceiling and managed recording destination.",
        context_schema("MutationContext", {{"mode", enum_schema({"into", "over"})}, {"stopCondition", string_schema("utf8-text", 4096)}, {"limits", limits},
            {"record", closed_object_schema({{"enabled", boolSchema}, {"fields", bounded_array_schema(enum_schema({"instructions", "registers", "memory"}), 3, 1, true)}}, {"enabled"})}, {"namespaceId", id}},
            {"mode", "stopCondition", "limits", "namespaceId"}, true), trace, {Effect::Execute, Effect::FileExport}, Executor::Engine, StateRequirement::TargetPaused,
        "Actual trace execution/recording belongs to the pinned context/job; terminal condition/limits/intervention and artifact/index coverage are observed without treating queued work as complete.",
        {"trace_state", "target_state", "operation_reconcile"}, {"A-24", "A-26", "A-37", "A-48"}, "src/dbg/commands/cmd-tracing.cpp", false);
    add("trace_stop", "trace", "Stop the owned target trace job/recorder and retain final artifact indexing progress.",
        context_schema("TargetRef", {{"traceId", id}, {"idempotencyKey", id}}, {"traceId"}), trace, {Effect::Execute}, Executor::Engine, StateRequirement::TargetPresent,
        "The exact recorder/job stops at an actual target context; recording closure and final indexing outcome are observed or retained as a pending job.",
        {"trace_state", "operation_reconcile"}, {"A-37", "A-48", "A-50"}, "src/dbg/TraceRecord.cpp", false);
    add("trace_state", "trace", "Read trace job limits/progress, actual terminal reason and current/final artifact indexing state.", context_schema("TargetRef", {{"traceId", id}}, {"traceId"}), trace,
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Actual owned trace progress/state and recorder/index coverage are correlated to the identified target generation.",
        {"trace_state", "target_state"}, {"A-37", "A-48"}, "src/dbg/TraceRecord.cpp", true);
    const auto reader = closed_object_schema({{"traceArtifactId", id}, {"sha256", string_schema("sha256", 64)}, {"architecture", enum_schema({"x32", "x64"})},
        {"formatVersion", string_schema("utf8-text", 128)}, {"entries", decimal}, {"indexing", indexing}}, {"traceArtifactId", "sha256", "architecture", "formatVersion", "entries", "indexing"});
    add("trace_open", "trace", "Open a hash-identified compatible native trace in the actual instance reader and retain indexing state.", file_forms(context_schema("InstanceRef")), reader,
        {Effect::Configure}, Executor::Gui, StateRequirement::InstanceReady, "The selected reader has loaded the actual compatible trace identity/architecture and reports observed indexing progress or errors.",
        {"trace_read", "operation_reconcile"}, {"A-37", "A-51"}, "src/gui/Src/Tracer/TraceFileReader.cpp", false);
    const auto entry = closed_object_schema({{"index", decimal}, {"threadId", bounded_integer_schema(1, 0xffffffff)}, {"instruction", nullable_schema(decoded_instruction_schema())},
        {"registers", bounded_array_schema(register_write_value_schema(), 512)}, {"memory", bounded_array_schema(closed_object_schema({{"addressHex", hex},
            {"beforeBytesHex", nullable_schema(string_schema("hex-bytes", MaximumPayloadBytes * 2))}, {"afterBytesHex", nullable_schema(string_schema("hex-bytes", MaximumPayloadBytes * 2))}}, {"addressHex", "beforeBytesHex", "afterBytesHex"}), MaximumPageLimit)},
        {"complete", boolSchema}}, {"index", "threadId", "instruction", "registers", "memory", "complete"});
    const auto rows = extend_object_schema(paged_data_schema(entry), {{"traceArtifactId", id}, {"traceSha256", string_schema("sha256", 64)}, {"coverage", indexing}}, {"traceArtifactId", "traceSha256", "coverage"});
    add("trace_read", "trace", "Read indexed native trace entries with exact instruction/context/memory-delta source identity and bounded field selection.",
        with_page_schema(closed_object_schema({{"traceArtifactId", id}, {"fields", bounded_array_schema(enum_schema({"instructions", "registers", "memory"}), 3, 1, true)}}, {"traceArtifactId"})), rows,
        {Effect::Inspect}, Executor::Broker, StateRequirement::Broker, "Entries and selected fields come from the authorized hash-pinned source trace/index with correlated complete/partial pages.",
        {"trace_read", "trace_open"}, {"A-37"}, "src/gui/Src/Tracer/TraceFileReader.cpp", true);
    add("trace_search", "trace", "Search the actual indexed trace with a typed instruction/register/memory query and retain source/scan coverage.",
        with_page_schema(closed_object_schema({{"traceArtifactId", id}, {"query", closed_object_schema({{"field", enum_schema({"instruction", "register", "memory", "thread"})},
            {"expression", string_schema("utf8-text", 4096)}}, {"field", "expression"})}}, {"traceArtifactId", "query"})), rows,
        {Effect::Inspect}, Executor::Broker, StateRequirement::Broker, "Matched actual source-trace positions satisfy the admitted pure query and retain exact indexing/search coverage and pagination.",
        {"trace_read", "trace_search"}, {"A-37"}, "src/gui/Src/Tracer/TraceFileSearch.cpp", true);
    add("trace_export", "trace", "Export a bounded trace selection into a hashed managed artifact with exact source identity and entry count.",
        closed_object_schema({{"traceArtifactId", id}, {"range", closed_object_schema({{"first", decimal}, {"count", positive_decimal_schema()}}, {"first", "count"})},
            {"format", enum_schema({"native", "jsonl", "text"})}, {"namespaceId", id}, {"idempotencyKey", id}}, {"traceArtifactId", "format", "namespaceId"}),
        extend_object_schema(managed_artifact_schema(), {{"traceArtifactId", id}, {"sourceSha256", string_schema("sha256", 64)}, {"entries", decimal}, {"complete", boolSchema}}, {"traceArtifactId", "sourceSha256", "entries", "complete"}),
        {Effect::Inspect, Effect::FileExport}, Executor::Broker, StateRequirement::Broker, "Requested authorized trace selection is durably published/reread/hash-verified with exact included entry count and source/index coverage.",
        {"library_file_read", "trace_read", "operation_reconcile"}, {"A-37", "A-40"}, "src/gui/Src/Tracer/TraceFileReader.cpp", false);
}
}
