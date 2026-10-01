#include "analysis_types.h"
#include "patch_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json id() { return string_schema("opaque-id"); }
Json hex() { return reference_schema("Hex64"); }
Json decimal() { return reference_schema("Decimal64"); }
Json text() { return string_schema("utf8-text", 4096); }
Json bool_schema() { return {{"type", "boolean"}}; }
}

Json module_section_schema()
{
    auto flags = contract_schema("Hex64");
    flags["maxLength"] = 10;
    return closed_object_schema({{"name", string_schema("utf8-text", 128, 0)}, {"addressHex", hex()}, {"rvaHex", hex()}, {"virtualSize", decimal()},
        {"rawOffset", nullable_schema(decimal())}, {"rawSize", nullable_schema(decimal())}, {"characteristicsHex", nullable_schema(flags)},
        {"protectionHex", nullable_schema(flags)}, {"mapping", enum_schema({"valid", "ambiguous", "unmapped", "unreadable", "unknown"})}},
        {"name", "addressHex", "rvaHex", "virtualSize", "rawOffset", "rawSize", "characteristicsHex", "protectionHex", "mapping"});
}

Json module_observation_schema()
{
    const auto image = closed_object_schema({{"path", string_schema("windows-absolute-path", 32767)}, {"sha256", nullable_schema(string_schema("sha256", 64))},
        {"size", nullable_schema(decimal())}}, {"path", "sha256", "size"});
    return closed_object_schema({{"moduleId", id()}, {"target", reference_schema("TargetRef")}, {"loadGeneration", decimal()}, {"name", string_schema("utf8-text", 1024)},
        {"baseHex", hex()}, {"size", positive_decimal_schema()}, {"entryHex", nullable_schema(hex())}, {"image", nullable_schema(image)},
        {"architecture", enum_schema({"x32", "x64", "unknown"})}, {"loaded", bool_schema()}, {"sections", paged_data_schema(module_section_schema())},
        {"provider", id()}, {"limitations", bounded_array_schema(reference_schema("DomainError"), 16)}},
        {"moduleId", "target", "loadGeneration", "name", "baseHex", "size", "entryHex", "image", "architecture", "loaded", "sections", "provider", "limitations"});
}

Json symbol_observation_schema()
{
    return closed_object_schema({{"symbolId", id()}, {"moduleId", nullable_schema(id())}, {"providerId", id()}, {"name", text()},
        {"undecoratedName", nullable_schema(text())}, {"kind", enum_schema({"import", "export", "debug", "user", "unknown"})}, {"addressHex", nullable_schema(hex())},
        {"rvaHex", nullable_schema(hex())}, {"size", nullable_schema(decimal())}, {"resolved", bool_schema()},
        {"sourceFile", nullable_schema(string_schema("utf8-text", 32767))}, {"line", nullable_schema(bounded_integer_schema(1, 0xffffffff))}},
        {"symbolId", "moduleId", "providerId", "name", "undecoratedName", "kind", "addressHex", "rvaHex", "size", "resolved", "sourceFile", "line"});
}

Json analysis_function_schema()
{
    return closed_object_schema({{"functionId", id()}, {"moduleId", nullable_schema(id())}, {"startHex", hex()}, {"endHex", hex()}, {"name", nullable_schema(text())},
        {"kind", enum_schema({"manual", "automatic", "heuristic", "unknown"})}, {"source", id()}, {"analysisVersion", decimal()},
        {"instructionCount", nullable_schema(decimal())}, {"parentFunctionId", nullable_schema(id())}, {"certainty", enum_schema({"verified", "heuristic", "unknown"})}},
        {"functionId", "moduleId", "startHex", "endHex", "name", "kind", "source", "analysisVersion", "instructionCount", "parentFunctionId", "certainty"});
}

Json analysis_edge_schema()
{
    return closed_object_schema({{"fromBlockId", id()}, {"toBlockId", nullable_schema(id())}, {"targetHex", nullable_schema(hex())},
        {"kind", enum_schema({"fallthrough", "branch", "call", "return", "exception", "indirect", "unknown"})},
        {"resolution", enum_schema({"resolved", "unresolved", "external", "error"})}}, {"fromBlockId", "toBlockId", "targetHex", "kind", "resolution"});
}

Json analysis_block_schema()
{
    return closed_object_schema({{"blockId", id()}, {"functionId", id()}, {"startHex", hex()}, {"endHex", hex()},
        {"instructions", bounded_array_schema(decoded_instruction_schema(), MaximumPageLimit)}, {"edges", bounded_array_schema(analysis_edge_schema(), MaximumPageLimit)},
        {"complete", bool_schema()}, {"analysisVersion", decimal()}}, {"blockId", "functionId", "startHex", "endHex", "instructions", "edges", "complete", "analysisVersion"});
}

Json native_encoding_schema()
{
    return enum_schema({"unknown", "byte", "word", "dword", "fword", "qword", "tbyte", "oword", "mmword", "xmmword", "ymmword", "zmmword", "real4", "real8", "real10", "ascii", "unicode", "code", "junk", "middle"});
}

Json analysis_encoding_observation_schema()
{
    const auto entry = closed_object_schema({{"addressHex", hex()}, {"size", positive_decimal_schema()}, {"encoding", native_encoding_schema()},
        {"source", id()}, {"valid", bool_schema()}}, {"addressHex", "size", "encoding", "source", "valid"});
    return closed_object_schema({{"target", reference_schema("TargetRef")}, {"databaseVersion", decimal()}, {"items", bounded_array_schema(entry, MaximumPageLimit)},
        {"complete", bool_schema()}}, {"target", "databaseVersion", "items", "complete"});
}

Json annotation_forms(Json base, bool observed)
{
    if(observed)
        base = extend_object_schema(std::move(base), {{"annotationId", id()}, {"revision", id()}, {"target", reference_schema("TargetRef")}, {"addressHex", hex()},
            {"moduleId", nullable_schema(id())}, {"rvaHex", nullable_schema(hex())}, {"origin", enum_schema({"manual", "automatic", "provider", "unknown"})},
            {"present", bool_schema()}, {"databaseVersion", decimal()}},
            {"annotationId", "revision", "target", "addressHex", "moduleId", "rvaHex", "origin", "present", "databaseVersion"});
    auto color = contract_schema("Hex64");
    color["maxLength"] = 10;
    Json choices = Json::array();
    for(const auto& entry : std::vector<std::pair<std::string, Json>>{{"label", text()}, {"comment", string_schema("utf8-text", 4096, 0)}, {"bookmark", bool_schema()}, {"color", color}})
        choices.push_back(extend_object_schema(base, {{"kind", {{"const", entry.first}}}, {"value", entry.second}}, {"kind", "value"}));
    return {{"oneOf", std::move(choices)}};
}

Json database_observation_schema()
{
    const auto module = closed_object_schema({{"moduleId", id()}, {"imageSha256", nullable_schema(string_schema("sha256", 64))}, {"loadGeneration", decimal()}},
        {"moduleId", "imageSha256", "loadGeneration"});
    return closed_object_schema({{"target", reference_schema("TargetRef")}, {"version", decimal()}, {"loadedVersion", nullable_schema(decimal())},
        {"savedVersion", nullable_schema(decimal())}, {"dirty", bool_schema()}, {"file", nullable_schema(reference_schema("FileRef"))},
        {"sha256", nullable_schema(string_schema("sha256", 64))}, {"modules", bounded_array_schema(module, MaximumPageLimit)}, {"provider", id()},
        {"counts", bounded_array_schema(closed_object_schema({{"kind", id()}, {"count", decimal()}}, {"kind", "count"}), MaximumPageLimit)}, {"complete", bool_schema()}},
        {"target", "version", "loadedVersion", "savedVersion", "dirty", "file", "sha256", "modules", "provider", "counts", "complete"});
}
}
