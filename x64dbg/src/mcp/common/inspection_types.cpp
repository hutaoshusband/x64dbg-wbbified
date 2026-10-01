#include "inspection_types.h"
#include "schema_helpers.h"
#include <limits>

namespace wininspect::mcp
{
namespace
{
Json thread_id() { return bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max()); }
Json id() { return string_schema("opaque-id"); }
Json hex() { return reference_schema("Hex64"); }
Json decimal() { return reference_schema("Decimal64"); }
Json text() { return string_schema("utf8-text", 4096); }
Json protection()
{
    auto schema = contract_schema("Hex64");
    schema["maxLength"] = 10;
    return schema;
}
}

Json register_snapshot_schema()
{
    const auto groups = enum_schema({"general", "flags", "segments", "debug", "control", "x87", "mmx", "sse", "avx", "avx512"});
    const auto lane = closed_object_schema({{"widthBits", bounded_integer_schema(1, 64)}, {"interpretation", enum_schema({"unsigned", "signed", "float", "raw"})},
        {"values", bounded_array_schema(string_schema("utf8-text", 128), 64)}}, {"widthBits", "interpretation", "values"});
    const auto value = closed_object_schema({{"name", id()}, {"group", groups}, {"widthBits", bounded_integer_schema(1, 512)},
        {"bytesHex", nullable_schema(string_schema("hex-bytes", 128))}, {"aliases", bounded_array_schema(id(), 32, 0, true)},
        {"lanes", bounded_array_schema(lane, 16)}, {"validity", enum_schema({"valid", "unavailable", "unsupported"})},
        {"reason", nullable_schema(text())}}, {"name", "group", "widthBits", "bytesHex", "aliases", "lanes", "validity", "reason"});
    const auto feature = closed_object_schema({{"name", id()}, {"available", {{"type", "boolean"}}}, {"enabled", {{"type", "boolean"}}},
        {"source", id()}}, {"name", "available", "enabled", "source"});
    return closed_object_schema({{"context", {{"oneOf", Json::array({reference_schema("TargetRef"), reference_schema("PausedContext")})}}}, {"architecture", enum_schema({"x32", "x64"})},
        {"consistency", enum_schema({"paused", "best_effort"})}, {"groups", bounded_array_schema(groups, 10, 1, true)},
        {"registers", bounded_array_schema(value, 512)}, {"features", bounded_array_schema(feature, 64)}, {"complete", {{"type", "boolean"}}}},
        {"context", "architecture", "consistency", "groups", "registers", "features", "complete"});
}

Json register_write_value_schema()
{
    return {{"oneOf", Json::array({closed_object_schema({{"name", id()}, {"valueHex", hex()}, {"maskHex", hex()}}, {"name", "valueHex"}),
        closed_object_schema({{"name", id()}, {"bytesHex", string_schema("hex-bytes", 128)}}, {"name", "bytesHex"})})}};
}

Json stack_frame_schema()
{
    return closed_object_schema({{"index", bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max())}, {"ipHex", hex()}, {"spHex", hex()},
        {"returnHex", nullable_schema(hex())}, {"symbol", nullable_schema(text())}, {"moduleId", nullable_schema(id())},
        {"source", enum_schema({"unwind", "frame_pointer", "scan", "engine", "unknown"})}, {"certainty", enum_schema({"verified", "heuristic", "unknown"})},
        {"bytesHex", nullable_schema(string_schema("hex-bytes", 8192))}}, {"index", "ipHex", "spHex", "returnHex", "symbol", "moduleId", "source", "certainty", "bytesHex"});
}

Json memory_region_schema()
{
    return closed_object_schema({{"baseHex", hex()}, {"size", positive_decimal_schema()}, {"allocationBaseHex", nullable_schema(hex())},
        {"state", enum_schema({"committed", "reserved", "free", "unknown"})}, {"protectionHex", nullable_schema(protection())},
        {"type", enum_schema({"private", "mapped", "image", "unknown"})}, {"moduleId", nullable_schema(id())},
        {"mappedPath", nullable_schema(string_schema("windows-absolute-path", 32767))}, {"readable", {{"type", "boolean"}}}},
        {"baseHex", "size", "allocationBaseHex", "state", "protectionHex", "type", "moduleId", "mappedPath", "readable"});
}

Json memory_coverage_schema()
{
    const auto span = closed_object_schema({{"addressHex", hex()}, {"size", positive_decimal_schema()}, {"protectionHex", nullable_schema(protection())},
        {"status", enum_schema({"read", "unreadable", "unmapped", "changed", "not_requested"})}, {"error", nullable_schema(reference_schema("DomainError"))}},
        {"addressHex", "size", "protectionHex", "status", "error"});
    return closed_object_schema({{"requestedBytes", decimal()}, {"capturedBytes", decimal()}, {"spans", bounded_array_schema(span, MaximumPageLimit)},
        {"complete", {{"type", "boolean"}}}}, {"requestedBytes", "capturedBytes", "spans", "complete"});
}

Json expression_value_schema()
{
    return {{"oneOf", Json::array({
        closed_object_schema({{"kind", {{"const", "unsigned"}}}, {"hex", hex()}, {"decimal", decimal()}, {"widthBits", bounded_integer_schema(1, 64)}}, {"kind", "hex", "decimal", "widthBits"}),
        closed_object_schema({{"kind", {{"const", "text"}}}, {"text", string_schema("utf8-text", 4096, 0)}}, {"kind", "text"}),
        closed_object_schema({{"kind", {{"const", "bytes"}}}, {"bytesHex", string_schema("hex-bytes", 8192)}}, {"kind", "bytesHex"}),
        closed_object_schema({{"kind", {{"const", "boolean"}}}, {"value", {{"type", "boolean"}}}}, {"kind", "value"})})}};
}

Json exception_observation_schema()
{
    auto code = contract_schema("Hex64");
    code["maxLength"] = 10;
    return closed_object_schema({{"active", {{"type", "boolean"}}}, {"codeHex", nullable_schema(code)}, {"addressHex", nullable_schema(hex())},
        {"chance", enum_schema({"none", "first", "second", "unknown"})}, {"handling", enum_schema({"configured", "debugger", "debuggee", "unknown"})},
        {"name", nullable_schema(text())}, {"information", bounded_array_schema(hex(), 15)}}, {"active", "codeHex", "addressHex", "chance", "handling", "name", "information"});
}

Json execution_observation_schema()
{
    return closed_object_schema({{"target", reference_schema("TargetRef")}, {"state", enum_schema({"running", "paused", "exited", "detached"})},
        {"stopEpoch", decimal()}, {"threadId", nullable_schema(thread_id())}, {"ipHex", nullable_schema(hex())},
        {"eventCursor", string_schema("utf8-text", 4096)}, {"eventSequence", decimal()},
        {"stopReason", enum_schema({"none", "breakpoint", "exception", "step", "return", "user_pause", "exit", "detach", "other"})},
        {"breakpointId", nullable_schema(id())}, {"exception", nullable_schema(exception_observation_schema())}, {"exitCode", nullable_schema(bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max()))},
        {"completedSteps", decimal()}, {"reachedCondition", {{"type", "boolean"}}}, {"allThreadsStopped", {{"type", "boolean"}}}},
        {"target", "state", "stopEpoch", "threadId", "ipHex", "eventCursor", "eventSequence", "stopReason", "breakpointId", "exception", "exitCode", "completedSteps", "reachedCondition", "allThreadsStopped"});
}

Json event_condition_schema()
{
    Json choices = Json::array();
    for(const auto* kind : {"paused", "exit"})
        choices.push_back(closed_object_schema({{"kind", {{"const", kind}}}}, {"kind"}));
    choices.push_back(closed_object_schema({{"kind", {{"const", "breakpoint"}}}, {"breakpointId", id()}}, {"kind", "breakpointId"}));
    auto code = contract_schema("Hex64");
    code["maxLength"] = 10;
    choices.push_back(closed_object_schema({{"kind", {{"const", "exception"}}}, {"codeHex", code}, {"chance", enum_schema({"first", "second", "either"})}}, {"kind", "codeHex"}));
    choices.push_back(closed_object_schema({{"kind", {{"const", "address"}}}, {"address", reference_schema("AddressRef")}}, {"kind", "address"}));
    choices.push_back(closed_object_schema({{"kind", {{"const", "thread_exit"}}}, {"threadId", thread_id()}, {"creationIdentity", decimal()}}, {"kind", "threadId"}));
    return {{"oneOf", std::move(choices)}};
}

Json managed_artifact_schema()
{
    return closed_object_schema({{"artifactId", id()}, {"namespaceId", id()}, {"revision", id()}, {"sha256", string_schema("sha256", 64)},
        {"size", decimal()}, {"mediaType", string_schema("utf8-text", 128)}, {"source", string_schema("utf8-text", 4096)}},
        {"artifactId", "namespaceId", "revision", "sha256", "size", "mediaType", "source"});
}

Json decoded_structure_schema()
{
    auto field = closed_object_schema({{"name", string_schema("utf8-text", 1024)}, {"typeId", id()}, {"offsetHex", hex()}, {"size", decimal()},
        {"status", enum_schema({"valid", "unreadable", "unsupported", "unknown"})}, {"value", nullable_schema(expression_value_schema())},
        {"children", bounded_array_schema(reference_schema("DecodedField"), MaximumPageLimit)}}, {"name", "typeId", "offsetHex", "size", "status", "value", "children"});
    auto schema = closed_object_schema({{"typeId", id()}, {"addressHex", hex()}, {"size", decimal()}, {"fields", bounded_array_schema(reference_schema("DecodedField"), MaximumPageLimit)},
        {"complete", {{"type", "boolean"}}}, {"provider", id()}}, {"typeId", "addressHex", "size", "fields", "complete", "provider"});
    schema["$defs"] = {{"DecodedField", std::move(field)}};
    return schema;
}
}
