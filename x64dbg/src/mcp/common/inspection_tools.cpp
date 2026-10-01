#include "registry.h"
#include "inspection_types.h"
#include "schema_helpers.h"
#include <limits>

namespace wininspect::mcp
{
void append_inspection_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto hex = reference_schema("Hex64");
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096);
    const auto threadId = bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max());
    const auto consistency = enum_schema({"paused", "best_effort"});
    const auto expression = closed_object_schema({{"expression", text}, {"value", nullable_schema(expression_value_schema())},
        {"error", nullable_schema(reference_schema("DomainError"))}, {"errorOffset", nullable_schema(bounded_integer_schema(0, 4096))}},
        {"expression", "value", "error", "errorOffset"});
    const auto expressions = closed_object_schema({{"context", {{"oneOf", Json::array({reference_schema("InstanceRef"), reference_schema("TargetRef"), reference_schema("PausedContext")})}}},
        {"items", bounded_array_schema(expression, MaximumPageLimit, 1)}, {"complete", {{"type", "boolean"}}}}, {"context", "items", "complete"});
    const auto watch = closed_object_schema({{"watchId", id}, {"expression", text}, {"type", enum_schema({"unsigned", "signed", "float", "text", "raw"})},
        {"display", enum_schema({"hex", "decimal", "binary", "text", "native"})}, {"trigger", enum_schema({"none", "changed", "true", "false"})}},
        {"watchId", "expression", "type", "display", "trigger"});
    const auto observedWatch = extend_object_schema(watch, {{"revision", id}, {"evaluation", expression}}, {"revision", "evaluation"});
    const auto pointer = closed_object_schema({{"level", bounded_integer_schema(0, 64)}, {"addressHex", hex},
        {"bytesHex", nullable_schema(string_schema("hex-bytes", 16))}, {"valueHex", nullable_schema(hex)},
        {"region", nullable_schema(memory_region_schema())}, {"error", nullable_schema(reference_schema("DomainError"))}},
        {"level", "addressHex", "bytesHex", "valueHex", "region", "error"});
    const auto structure = decoded_structure_schema();
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent, ArchitectureRequirement architecture = ArchitectureRequirement::Any)
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            Executor::Engine, state, architecture, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + source, idempotent, false));
    };
    add("registers_read", "registers", "Read real general/flag/segment/debug/control and x87/MMX/SSE/AVX/AVX-512 groups with native widths, aliases, SIMD lanes and feature validity.",
        context_schema("TargetRef", {{"threadId", threadId}, {"groups", bounded_array_schema(enum_schema({"general", "flags", "segments", "debug", "control", "x87", "mmx", "sse", "avx", "avx512"}), 10, 1, true)}, {"consistency", consistency}}), register_snapshot_schema(),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Values are captured from the actual identified thread context; unavailable/unsupported register groups and running consistency are explicit.",
        {"target_state", "threads_context"}, {"A-17", "A-18", "A-27"}, "src/dbg/_scriptapi_register.cpp", true);
    add("registers_write", "registers", "Compare expected values and write typed scalar/masked or raw wide-register values to the selected paused thread; validate widths and overlapping aliases before effects.",
        context_schema("MutationContext", {{"values", bounded_array_schema(register_write_value_schema(), 512, 1)}, {"expectedValues", bounded_array_schema(register_write_value_schema(), 512, 1)}}, {"values"}, true), register_snapshot_schema(),
        {Effect::Modify}, StateRequirement::TargetPaused, "Every admitted register/flag value is actually reread at its native width; partial writes/restoration and the resulting context epoch are recorded.",
        {"registers_read", "operation_reconcile"}, {"A-17", "A-18", "A-27", "A-48"}, "src/dbg/_scriptapi_register.cpp", false);
    add("expression_evaluate", "expressions", "Evaluate a pure typed expression in an explicit instance or target context, including idle arithmetic; reject side-effectful or unknown-purity extension functions.",
        instance_or_target_forms({{"expression", text}, {"threadId", threadId}, {"expectedEpoch", decimal}}, {"expression"}), expressions,
        {Effect::Inspect}, StateRequirement::InstanceReady, "Native evaluation under one valid context yields exact typed hex/decimal/value or an explicit located error without invoking unclassified effectful providers.",
        {"target_state", "capabilities_describe"}, {"A-17", "A-21", "A-48"}, "src/dbg/expressionfunctions.cpp", true);
    add("expressions_evaluate", "expressions", "Evaluate a bounded ordered expression batch under one context after classifying every provider's purity.",
        instance_or_target_forms({{"expressions", bounded_array_schema(text, MaximumPageLimit, 1)}, {"threadId", threadId}}, {"expressions"}), expressions,
        {Effect::Inspect}, StateRequirement::InstanceReady, "One correlated context produces one ordered result/error per requested pure expression; context changes cannot silently mix values.",
        {"target_state", "capabilities_describe"}, {"A-17", "A-21", "A-48"}, "src/dbg/expressionfunctions.cpp", true);
    add("watches_list", "watches", "List saved typed watch expressions, display and trigger metadata, revisions and actual evaluation results.", with_page_schema(context_schema("TargetRef")), paged_data_schema(observedWatch),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Actual debugger watch records and safe evaluation observations are read with correlated paging.",
        {"watches_list", "target_state"}, {"A-26", "A-38"}, "src/dbg/watch.cpp", true);
    add("watches_set", "watches", "Save a compare-revisioned watch bound to a target lease; expression/trigger effects require purity validation.",
        context_schema("TargetRef", {{"leaseId", id}, {"idempotencyKey", id}, {"watch", watch}, {"expectedRevision", id}}, {"leaseId", "watch"}), observedWatch,
        {Effect::Configure}, StateRequirement::TargetPresent, "Expected revision matches and native watch metadata is reread with its actual safe evaluation and new revision.",
        {"watches_list", "operation_reconcile"}, {"A-26", "A-38", "A-48"}, "src/dbg/watch.cpp", false);
    add("watches_delete", "watches", "Remove the identified watch under the target control lease.",
        context_schema("TargetRef", {{"leaseId", id}, {"idempotencyKey", id}, {"watchId", id}}, {"leaseId", "watchId"}),
        closed_object_schema({{"watchId", id}, {"removed", {{"const", true}}}}, {"watchId", "removed"}),
        {Effect::Configure}, StateRequirement::TargetPresent, "The watch is absent from actual native watch state after owner-thread removal.",
        {"watches_list", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/watch.cpp", false);
    add("stack_read", "stack", "Read bounded thread frames, actual return sites/symbols and optional bytes; label unwind source and heuristic uncertainty.",
        with_page_schema(context_schema("TargetRef", {{"threadId", threadId}, {"frames", bounded_integer_schema(1, MaximumPageLimit)}, {"includeBytes", {{"type", "boolean"}}}})), paged_data_schema(stack_frame_schema()),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Frames and optional bytes come from the actual identified thread snapshot; heuristic results and missing/unreadable frames retain explicit uncertainty.",
        {"threads_context", "target_state"}, {"A-21", "A-22", "A-27"}, "src/dbg/stackinfo.cpp", true);
    const auto argumentLocation = Json{{"oneOf", Json::array({closed_object_schema({{"register", id}}, {"register"}),
        closed_object_schema({{"addressHex", hex}}, {"addressHex"})})}};
    const auto argument = closed_object_schema({{"index", bounded_integer_schema(0, 255)}, {"type", nullable_schema(id)},
        {"location", argumentLocation},
        {"bytesHex", nullable_schema(string_schema("hex-bytes", 8192))}, {"value", nullable_schema(expression_value_schema())}, {"error", nullable_schema(reference_schema("DomainError"))}},
        {"index", "type", "location", "bytesHex", "value", "error"});
    add("arguments_read", "stack", "Read actual register/stack argument locations under a pinned paused thread and requested supported calling convention/types.",
        context_schema("PausedContext", {{"convention", enum_schema({"native", "cdecl", "stdcall", "fastcall", "thiscall", "win64"})}, {"count", bounded_integer_schema(1, 256)}, {"types", bounded_array_schema(id, 256, 1)}}, {"count"}, true),
        closed_object_schema({{"context", reference_schema("PausedContext")}, {"convention", id}, {"items", bounded_array_schema(argument, 256, 1)}, {"complete", {{"type", "boolean"}}}}, {"context", "convention", "items", "complete"}),
        {Effect::Inspect}, StateRequirement::TargetPaused, "Requested supported ABI and type widths resolve to actual source locations/raw values; unsupported ABI/layout or unreadable arguments are explicit.",
        {"registers_read", "stack_read", "target_state"}, {"A-21", "A-27"}, "src/dbg/stackinfo.cpp", true);
    add("pointers_follow", "memory", "Follow bounded pointer dereferences with explicit target pointer width and exact failed-level/region evidence.",
        address_forms(context_schema("TargetRef", {{"depth", bounded_integer_schema(1, 64)}, {"pointerWidth", enum_schema({32, 64})}}, {"depth"})),
        closed_object_schema({{"pointerWidth", enum_schema({32, 64})}, {"items", bounded_array_schema(pointer, 64, 1)}, {"complete", {{"type", "boolean"}}}}, {"pointerWidth", "items", "complete"}),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Each level contains actual source bytes and pointer/region or its precise error; resolved address overflow and unreadable/cyclic termination are reported.",
        {"memory_read", "memory_map", "target_state"}, {"A-19", "A-21"}, "src/dbg/memory.cpp", true);
    add("process_peb", "structures", "Decode the real target PEB from its source address using a supported architecture-specific native layout; unknown members remain explicit.",
        context_schema("TargetRef"), structure, {Effect::Inspect}, StateRequirement::TargetPresent,
        "Actual PEB source address/layout and captured fields match the target architecture with explicit unreadable/unsupported members.",
        {"structures_decode", "target_state"}, {"A-19", "A-21"}, "src/dbg/debugger.cpp", true);
    add("thread_teb", "structures", "Decode the exact thread's TEB fields/source addresses and last-error metadata with actual architecture/layout validity.",
        context_schema("TargetRef", {{"threadId", threadId}}, {"threadId"}), structure, {Effect::Inspect}, StateRequirement::TargetPresent,
        "TEB belongs to the identified target thread and every field uses a supported native layout/source address; inaccessible or unknown data is explicit.",
        {"threads_list", "structures_decode", "target_state"}, {"A-19", "A-21", "A-27"}, "src/dbg/thread.cpp", true);
    const auto handler = closed_object_schema({{"index", bounded_integer_schema(0, MaximumPageLimit)}, {"recordHex", hex}, {"handlerHex", hex},
        {"nextHex", hex}, {"valid", {{"type", "boolean"}}}}, {"index", "recordHex", "handlerHex", "nextHex", "valid"});
    add("seh_chain", "exceptions", "Read the selected paused x32 thread's actual structured exception handler chain; x64 returns an explicit architecture error.",
        context_schema("PausedContext", Json::object(), Json::array(), true),
        closed_object_schema({{"context", reference_schema("PausedContext")}, {"items", bounded_array_schema(handler, MaximumPageLimit)},
            {"termination", enum_schema({"end", "unreadable", "cycle", "limit", "invalid"})}, {"complete", {{"type", "boolean"}}}}, {"context", "items", "termination", "complete"}),
        {Effect::Inspect}, StateRequirement::TargetPaused, "Real x32 chain records and exact termination are observed for the selected thread; unsupported x64 is never an empty success.",
        {"threads_context", "target_state"}, {"A-21", "A-22"}, "src/dbg/exhandlerinfo.cpp", true, ArchitectureRequirement::X32);
    add("unwind_info", "exceptions", "Read actual x64 function-table/unwind/scope records at a resolved target address; unsupported records retain explicit validity.",
        address_forms(context_schema("TargetRef")), structure, {Effect::Inspect}, StateRequirement::TargetPresent,
        "Actual x64 function table and unwind/scope bytes are decoded by a supported native provider with source addresses and explicit unknown members.",
        {"stack_read", "structures_decode", "target_state"}, {"A-21", "A-22"}, "src/dbg/module.cpp", true, ArchitectureRequirement::X64);
    const auto type = closed_object_schema({{"typeId", id}, {"name", text}, {"size", nullable_schema(decimal)}, {"provider", id},
        {"architecture", enum_schema({"any", "x32", "x64"})}, {"kind", enum_schema({"primitive", "pointer", "array", "structure", "union", "enum", "unknown"})}},
        {"typeId", "name", "size", "provider", "architecture", "kind"});
    auto list = instance_or_target_forms({{"query", string_schema("utf8-text", 256)}}, Json::array());
    for(auto& form : list.at("oneOf"))
        form = with_page_schema(std::move(form));
    add("structures_list", "structures", "List actual available primitive/type/structure definitions and provider/layout identities in an instance or target context.", list, paged_data_schema(type),
        {Effect::Inspect}, StateRequirement::InstanceReady, "Native registered definitions/providers are enumerated with exact sizes/architecture where known and complete correlated pages.",
        {"structures_list", "capabilities_describe"}, {"A-21", "A-36"}, "src/dbg/types.cpp", true);
    add("structures_decode", "structures", "Decode a known native type at a resolved target address with bounded recursive depth and explicit unreadable/unknown fields.",
        address_forms(context_schema("TargetRef", {{"typeId", id}, {"depth", bounded_integer_schema(1, 16, 4)}}, {"typeId"})), structure,
        {Effect::Inspect}, StateRequirement::TargetPresent, "Known provider/layout and target width determine every field/source offset; recursion bounds, holes and unknown members are reported without guessed layout.",
        {"structures_list", "memory_read", "target_state"}, {"A-19", "A-21", "A-36"}, "src/dbg/types.cpp", true);
}
}
