#include "registry.h"
#include "inspection_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_memory_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto hex = reference_schema("Hex64");
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096);
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto bytes = string_schema("hex-bytes", MaximumPayloadBytes * 2);
    auto protection = contract_schema("Hex64");
    protection["maxLength"] = 10;
    const auto encoding = enum_schema({"utf8", "utf16le", "ansi"});
    const auto consistency = enum_schema({"paused", "best_effort"});
    const auto coverage = memory_coverage_schema();
    const auto region = memory_region_schema();
    const auto range = reference_schema("AddressRange");
    const auto ranges = bounded_array_schema(range, MaximumPageLimit, 1);
    const auto ranged = [&](std::string_view context, Json properties = Json::object(), Json required = Json::array())
    {
        const auto fields = contract_schema("AddressRange");
        auto schema = context_schema(context, std::move(properties), std::move(required));
        return extend_object_schema(std::move(schema), fields.at("properties"), fields.at("required"));
    };
    const auto searchOutput = [&](Json item)
    {
        return extend_object_schema(paged_data_schema(std::move(item)), {{"coverage", coverage}}, {"coverage"});
    };
    const auto artifact = extend_object_schema(managed_artifact_schema(), {{"coverage", coverage}, {"consistency", consistency}}, {"coverage", "consistency"});
    const auto allocation = closed_object_schema({{"allocationId", id}, {"target", reference_schema("TargetRef")}, {"addressHex", hex},
        {"size", positive_decimal_schema()}, {"protection", protection}, {"owned", boolSchema}, {"region", region}},
        {"allocationId", "target", "addressHex", "size", "protection", "owned", "region"});
    const auto match = closed_object_schema({{"addressHex", hex}, {"size", positive_decimal_schema()}, {"bytesHex", bytes}}, {"addressHex", "size", "bytesHex"});
    const auto string = closed_object_schema({{"addressHex", hex}, {"encoding", encoding}, {"text", string_schema("utf8-text", MaximumPayloadBytes, 0)},
        {"byteSize", decimal}, {"terminated", boolSchema}, {"truncated", boolSchema}, {"decoding", enum_schema({"valid", "invalid", "incomplete"})}},
        {"addressHex", "encoding", "text", "byteSize", "terminated", "truncated", "decoding"});
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent)
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            Executor::Engine, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + source, idempotent, false));
    };
    const auto filter = closed_object_schema({{"state", enum_schema({"committed", "reserved", "free"})}, {"type", enum_schema({"private", "mapped", "image"})},
        {"moduleId", id}, {"readable", boolSchema}}, Json::array());
    add("memory_map", "memory", "Enumerate real committed/reserved/free memory regions, protections and module/mapped identities with bounded paging.",
        with_page_schema(context_schema("TargetRef", {{"filter", filter}})), paged_data_schema(region), {Effect::Inspect}, StateRequirement::TargetPresent,
        "OS/native engine memory map for the exact target is observed with correlated paging and explicit unknown protection/mapping fields.",
        {"memory_map", "target_state"}, {"A-19"}, "src/dbg/memory.cpp", true);
    add("memory_read", "memory", "Read a bounded resolved address range with exact bytes, actual read spans/holes and explicit paused or best-effort consistency.",
        ranged("TargetRef", {{"encoding", enum_schema({"hex", "base64"})}, {"consistency", consistency}}),
        closed_object_schema({{"addressHex", hex}, {"requestedSize", bounded_integer_schema(1, MaximumPayloadBytes)}, {"encoding", enum_schema({"hex", "base64"})},
            {"encodedBytes", string_schema("utf8-text", MaximumPayloadBytes * 2, 0)}, {"coverage", coverage}, {"consistency", consistency}, {"partial", boolSchema}},
            {"addressHex", "requestedSize", "encoding", "encodedBytes", "coverage", "consistency", "partial"}),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Resolved target-width range is checked; only actually captured bytes are returned with exact spans, holes, partial flag and capture consistency.",
        {"memory_map", "target_state"}, {"A-19", "A-48"}, "src/dbg/_scriptapi_memory.cpp", true);
    add("memory_read_string", "memory", "Read a bounded string in explicit encoding and preserve termination, truncation and decoding outcomes.",
        address_forms(context_schema("TargetRef", {{"encoding", encoding}, {"maxBytes", bounded_integer_schema(1, MaximumPayloadBytes)}}, {"encoding", "maxBytes"})),
        extend_object_schema(string, {{"coverage", coverage}}, {"coverage"}), {Effect::Inspect}, StateRequirement::TargetPresent,
        "Actual source bytes and selected decoding produce the string; termination, odd/truncated units, invalid bytes and unreadable spans are reported explicitly.",
        {"memory_read", "memory_map"}, {"A-19", "A-21"}, "src/dbg/memory.cpp", true);
    add("memory_write", "memory", "Compare expected bytes or a hashed byte range and write exact bytes at one resolved address under a paused target lease; executable writes never invoke code.",
        address_forms(context_schema("MutationContext", {{"bytes", bytes}, {"expectedBytes", reference_schema("ExpectedBytes")}}, {"bytes", "expectedBytes"})),
        closed_object_schema({{"addressHex", hex}, {"requestedBytes", positive_decimal_schema()}, {"writtenBytes", decimal}, {"observedBytesHex", nullable_schema(bytes)},
            {"coverage", coverage}, {"restoration", enum_schema({"not_needed", "restored", "partial", "failed", "unknown"})}},
            {"addressHex", "requestedBytes", "writtenBytes", "observedBytesHex", "coverage", "restoration"}),
        {Effect::Modify}, StateRequirement::TargetPaused, "Expected byte range matches before effects; actual write/reread and any partial-write restoration are recorded with breakpoint overlap preserved.",
        {"memory_read", "patch_sets_list", "operation_reconcile"}, {"A-20", "A-30", "A-31", "A-48"}, "src/dbg/_scriptapi_memory.cpp", false);
    add("memory_allocate", "memory", "Allocate target memory with explicit size/protection and optional preferred address, recording allocation ownership; allocation never invokes code.",
        context_schema("MutationContext", {{"size", positive_decimal_schema()}, {"protection", protection}, {"preferredAddress", reference_schema("AddressRef")}}, {"size", "protection"}), allocation,
        {Effect::Modify}, StateRequirement::TargetPaused, "Actual allocated address/rounded size/protection and target-width bounds are observed and bound to a unique ownership record.",
        {"memory_map", "memory_free", "operation_reconcile"}, {"A-20", "A-48"}, "src/dbg/_scriptapi_memory.cpp", false);
    add("memory_free", "memory", "Release only the identified owned target allocation and inspect region state after release.",
        context_schema("MutationContext", {{"allocationId", id}}, {"allocationId"}),
        closed_object_schema({{"allocationId", id}, {"addressHex", hex}, {"released", boolSchema}, {"ownershipReleased", boolSchema}, {"regionAfter", nullable_schema(region)}},
            {"allocationId", "addressHex", "released", "ownershipReleased", "regionAfter"}),
        {Effect::Modify}, StateRequirement::TargetPaused, "Owned allocation belongs to the exact target generation, native release and actual post-release region state are observed, and ownership is reconciled.",
        {"memory_map", "operation_reconcile"}, {"A-20", "A-48"}, "src/dbg/_scriptapi_memory.cpp", false);
    const auto protectionPage = closed_object_schema({{"addressHex", hex}, {"size", positive_decimal_schema()}, {"oldProtection", protection},
        {"newProtection", nullable_schema(protection)}, {"status", enum_schema({"changed", "unchanged", "restored", "failed", "unknown"})}},
        {"addressHex", "size", "oldProtection", "newProtection", "status"});
    add("memory_protection_set", "memory", "Compare expected protection across the resolved range and change protection under a paused lease; executable protection never invokes code.",
        ranged("MutationContext", {{"protection", protection}, {"expectedProtection", protection}}, {"protection", "expectedProtection"}),
        closed_object_schema({{"pages", bounded_array_schema(protectionPage, MaximumPageLimit, 1)}, {"complete", boolSchema}}, {"pages", "complete"}),
        {Effect::Modify}, StateRequirement::TargetPaused, "Every affected native page passes expected-protection preflight and its actual old/new or restored protection is observed, preserving guard/breakpoint ownership.",
        {"memory_map", "operation_reconcile"}, {"A-20", "A-30", "A-31"}, "src/dbg/_scriptapi_memory.cpp", false);
    add("memory_search_pattern", "memory", "Search explicit bounded ranges with native byte/nibble wildcard grammar and correlated result pages.",
        with_page_schema(context_schema("TargetRef", {{"ranges", ranges}, {"pattern", text}}, {"ranges", "pattern"})), searchOutput(match),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Native pattern preflight succeeds and every match address/byte sequence is read from the actual target; inaccessible/scanned coverage and pagination remain explicit.",
        {"memory_read", "memory_map"}, {"A-19", "A-36"}, "src/dbg/memory.cpp", true);
    add("memory_search_text", "memory", "Search explicit ranges for text under selected encoding and case semantics, reporting actual matched bytes and inaccessible coverage.",
        with_page_schema(context_schema("TargetRef", {{"ranges", ranges}, {"text", text}, {"encoding", encoding}, {"caseSensitive", boolSchema}}, {"ranges", "text", "encoding"})), searchOutput(match),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Selected encoding/case comparison matches actual captured target bytes; holes, scan limits and result pages are correlated to the same scan.",
        {"memory_read", "memory_map"}, {"A-19", "A-36"}, "src/dbg/memory.cpp", true);
    add("memory_strings", "memory", "Enumerate strings in bounded ranges and selected encodings with source byte sizes and explicit scan coverage.",
        with_page_schema(context_schema("TargetRef", {{"ranges", ranges}, {"encodings", bounded_array_schema(encoding, 3, 1, true)}, {"minLength", bounded_integer_schema(1, 4096, 4)}}, {"ranges"})), searchOutput(string),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Each string is decoded from actual target bytes; source addresses/sizes, invalid encodings, holes and remaining scan pages are explicit.",
        {"memory_read_string", "memory_map"}, {"A-19", "A-36"}, "src/dbg/memory.cpp", true);
    add("memory_dump", "memory", "Capture a resolved bounded range into a hashed managed artifact in the authorized namespace, with actual holes and consistency retained.",
        ranged("TargetRef", {{"namespaceId", id}, {"name", string_schema("utf8-text", 1024)}, {"idempotencyKey", id}}, {"namespaceId"}), artifact,
        {Effect::Inspect, Effect::FileExport}, StateRequirement::TargetPresent, "Managed artifact is durably published and reread/hash-verified; captured spans, holes and consistency describe the actual dump without claiming runnable PE validity.",
        {"library_file_read", "memory_read", "operation_reconcile"}, {"A-19", "A-34", "A-40"}, "src/dbg/memory.cpp", false);
    add("memory_dumpable_regions", "memory", "List actual readable region candidates and per-region capture constraints for an optional module.",
        with_page_schema(context_schema("TargetRef", {{"moduleId", id}})),
        paged_data_schema(extend_object_schema(region, {{"constraints", bounded_array_schema(text, 16)}}, {"constraints"})),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Readable candidates are observed from the actual target map/module bounds; constraints and unavailable ranges are explicit.",
        {"memory_map", "memory_read"}, {"A-19", "A-34"}, "src/dbg/memory.cpp", true);
    const auto layout = closed_object_schema({{"format", enum_schema({"raw", "mapped", "rebuilt"})}, {"layout", enum_schema({"valid", "invalid", "unsupported", "unknown"})},
        {"imports", enum_schema({"valid", "invalid", "unsupported", "unknown"})}, {"relocations", enum_schema({"valid", "invalid", "unsupported", "unknown"})},
        {"runnable", enum_schema({"verified", "unverified", "unsupported"})}, {"limitations", bounded_array_schema(text, 32)}}, {"format", "layout", "imports", "relocations", "runnable", "limitations"});
    add("modules_dump", "modules", "Export the identified module in raw, mapped or rebuilt layout into a managed artifact with explicit PE/import/relocation validity.",
        context_schema("TargetRef", {{"moduleId", id}, {"format", enum_schema({"raw", "mapped", "rebuilt"})}, {"namespaceId", id}, {"idempotencyKey", id}}, {"moduleId", "format", "namespaceId"}),
        extend_object_schema(artifact, {{"moduleId", id}, {"validity", layout}}, {"moduleId", "validity"}),
        {Effect::Inspect, Effect::FileExport}, StateRequirement::TargetPresent, "Actual selected module/layout is captured, published and hash-verified; mapping/import/relocation limitations are explicit and runnable validity requires independent execution evidence.",
        {"memory_dumpable_regions", "library_file_read", "operation_reconcile"}, {"A-19", "A-23", "A-34", "A-40"}, "src/dbg/module.cpp", false);
    const auto handle = closed_object_schema({{"valueHex", hex}, {"type", nullable_schema(string_schema("utf8-text", 256))},
        {"name", nullable_schema(text)}, {"accessHex", nullable_schema(protection)}, {"provider", id}, {"limitations", bounded_array_schema(reference_schema("DomainError"), 16)}},
        {"valueHex", "type", "name", "accessHex", "provider", "limitations"});
    add("handles_list", "handles", "List actual target handles supported by the native provider and available rights; unavailable fields/errors remain explicit.",
        with_page_schema(context_schema("TargetRef", {{"type", string_schema("utf8-text", 256)}})), paged_data_schema(handle),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Native handle enumeration for the identified process supplies actual values/provider and rights limitations without inventing unavailable names/types.",
        {"handles_list", "target_state"}, {"A-19", "A-21"}, "src/dbg/handles.cpp", true);
    const auto heap = closed_object_schema({{"heapId", id}, {"baseHex", nullable_schema(hex)}, {"size", nullable_schema(decimal)},
        {"flagsHex", nullable_schema(protection)}, {"provider", id}, {"regions", bounded_array_schema(region, MaximumPageLimit)},
        {"complete", boolSchema}, {"limitations", bounded_array_schema(reference_schema("DomainError"), 16)}},
        {"heapId", "baseHex", "size", "flagsHex", "provider", "regions", "complete", "limitations"});
    add("heaps_list", "heaps", "List actual supported native heap/region data and provider with explicit coverage/rights limitations.", with_page_schema(context_schema("TargetRef")), paged_data_schema(heap),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Actual target heap records and regions come from a supported native provider; unsupported/unreadable fields and incomplete coverage are retained.",
        {"memory_map", "target_state"}, {"A-19", "A-21"}, "src/dbg/handles.cpp", true);
}
}
