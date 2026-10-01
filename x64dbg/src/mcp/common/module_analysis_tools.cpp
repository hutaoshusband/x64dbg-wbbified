#include "registry.h"
#include "analysis_types.h"
#include "inspection_types.h"
#include "patch_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_module_analysis_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto hex = reference_schema("Hex64");
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096);
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto module = module_observation_schema();
    const auto mutation = [&](Json properties = Json::object(), Json required = Json::array())
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        required.push_back("leaseId");
        return context_schema("TargetRef", std::move(properties), std::move(required));
    };
    const auto ranged = [&](Json base)
    {
        const auto range = contract_schema("AddressRange");
        return extend_object_schema(std::move(base), range.at("properties"), range.at("required"));
    };
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent, bool openWorld = false, std::vector<EffectCondition> conditions = {})
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + source,
            idempotent, openWorld, nullptr, std::move(conditions)));
    };
    add("modules_list", "modules", "List actual module load generations, source image identity/path, base/size and correlated native section observations.",
        with_page_schema(context_schema("TargetRef")), paged_data_schema(module), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Native module lifecycle records and actual image/map facts belong to the exact target generation; inaccessible fields and bounded section coverage remain explicit.",
        {"modules_list", "target_state"}, {"A-19", "A-23"}, "src/dbg/module.cpp", true);
    add("modules_sections", "modules", "Read actual module VA/RVA/virtual/raw section extents, protections and unambiguous or unavailable backing mappings.",
        context_schema("TargetRef", {{"moduleId", id}}, {"moduleId"}),
        closed_object_schema({{"moduleId", id}, {"loadGeneration", decimal}, {"items", bounded_array_schema(module_section_schema(), MaximumPageLimit)}, {"complete", boolSchema}}, {"moduleId", "loadGeneration", "items", "complete"}),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Every reported section comes from the identified actual loaded module/header/map; missing raw data and ambiguous/virtual-only mappings are explicit.",
        {"modules_list", "modules_analyze_pe"}, {"A-19", "A-23", "A-34"}, "src/dbg/module.cpp", true);
    const auto import = closed_object_schema({{"moduleId", id}, {"name", nullable_schema(text)}, {"ordinal", nullable_schema(decimal)}, {"iatAddressHex", hex},
        {"providerName", string_schema("utf8-text", 1024)}, {"resolvedProviderId", nullable_schema(id)}, {"resolvedAddressHex", nullable_schema(hex)}, {"resolved", boolSchema}},
        {"moduleId", "name", "ordinal", "iatAddressHex", "providerName", "resolvedProviderId", "resolvedAddressHex", "resolved"});
    add("modules_imports", "modules", "List native named/ordinal imports with actual IAT source addresses and observed provider resolutions.",
        with_page_schema(context_schema("TargetRef", {{"moduleId", id}}, {"moduleId"})), paged_data_schema(import), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual native import records/IAT reads determine name/ordinal and resolved provider/address; unresolved imports remain explicit with correlated coverage.",
        {"modules_list", "symbols_list"}, {"A-23"}, "src/dbg/module.cpp", true);
    const auto exported = closed_object_schema({{"moduleId", id}, {"name", nullable_schema(text)}, {"ordinal", decimal}, {"rvaHex", hex},
        {"addressHex", nullable_schema(hex)}, {"forwarder", nullable_schema(text)}, {"resolved", boolSchema}}, {"moduleId", "name", "ordinal", "rvaHex", "addressHex", "forwarder", "resolved"});
    add("modules_exports", "modules", "List actual native exports, ordinals, source RVAs and forwarder strings without treating a forwarder as executable bytes.",
        with_page_schema(context_schema("TargetRef", {{"moduleId", id}}, {"moduleId"})), paged_data_schema(exported), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Native export table entries and source bytes determine addresses/forwarders and resolution; ordinal-only/invalid/unresolved entries remain explicit.",
        {"modules_list", "symbols_list"}, {"A-23", "A-34"}, "src/dbg/module.cpp", true);
    Json peForms = Json::array({context_schema("TargetRef", {{"moduleId", id}})});
    const auto fileForms = file_forms(closed_object_schema(Json::object(), Json::array()));
    for(const auto& form : fileForms.at("oneOf"))
        peForms.push_back(form);
    const auto fact = closed_object_schema({{"name", id}, {"offset", decimal}, {"size", decimal}, {"bytesHex", nullable_schema(string_schema("hex-bytes", 8192))},
        {"value", nullable_schema(expression_value_schema())}, {"status", enum_schema({"valid", "invalid", "unreadable", "unsupported", "unknown"})}}, {"name", "offset", "size", "bytesHex", "value", "status"});
    add("modules_analyze_pe", "modules", "Parse actual target-module or file PE bytes with source identity and field/parse validity; absence of moduleId selects the observed main image.",
        {{"oneOf", peForms}}, closed_object_schema({{"sourceKind", enum_schema({"target", "file"})}, {"module", nullable_schema(module)}, {"file", nullable_schema(file_observation_schema())},
            {"facts", bounded_array_schema(fact, MaximumPageLimit)}, {"errors", bounded_array_schema(reference_schema("DomainError"), 32)}, {"complete", boolSchema}},
            {"sourceKind", "module", "file", "facts", "errors", "complete"}), {Effect::Inspect}, Executor::Broker, StateRequirement::Broker,
        "Actual captured header/directory bytes determine PE facts with pinned source identity; target reads dispatch to its owner and parse holes/failures remain explicit.",
        {"file_inspect", "modules_list"}, {"A-23", "A-34"}, "src/dbg/module.cpp", true, true);
    const auto candidate = closed_object_schema({{"addressHex", hex}, {"moduleId", id}, {"rank", bounded_integer_schema(0, MaximumPageLimit)},
        {"score", bounded_integer_schema(0, 10000)}, {"method", id}, {"rationale", bounded_array_schema(text, 32, 1)}, {"verification", reference_schema("Verification")}},
        {"addressHex", "moduleId", "rank", "score", "method", "rationale", "verification"});
    add("modules_oep_candidates", "modules", "Rank provider-declared OEP hypotheses/PE entry candidates with explicit method, rationale and independent validation state.",
        context_schema("TargetRef", {{"moduleId", id}, {"method", id}}, {"moduleId"}), closed_object_schema({{"items", bounded_array_schema(candidate, MaximumPageLimit)}, {"complete", boolSchema}}, {"items", "complete"}),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Supported provider observations produce labeled hypotheses; a score never promotes a candidate to verified without independent execution evidence.",
        {"modules_analyze_pe", "target_state"}, {"A-39"}, "src/dbg/module.cpp", true);
    const auto symbol = symbol_observation_schema();
    const auto symbolKinds = enum_schema({"import", "export", "debug", "user", "unknown"});
    add("symbols_list", "symbols", "List native import/export/debug/user symbols with exact provider provenance, source locations and resolved/unresolved states.",
        with_page_schema(context_schema("TargetRef", {{"moduleId", id}, {"kind", symbolKinds}})), paged_data_schema(symbol), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Native providers and user annotations yield actual correlated symbol records; unknown size/source/resolution remains explicit.",
        {"symbols_list", "modules_list"}, {"A-23", "A-38"}, "src/dbg/symbolinfo.cpp", true);
    add("symbols_search", "symbols", "Search actual symbols under bounded module/provider context with explicit unresolved matches.",
        with_page_schema(context_schema("TargetRef", {{"query", string_schema("utf8-text", 256)}, {"moduleId", id}} , {"query"})), paged_data_schema(symbol),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Matching native/provider names and observed addresses/source identities are enumerated with correlated pages and explicit unresolved entries.",
        {"symbols_list", "symbols_search"}, {"A-23"}, "src/dbg/symbolinfo.cpp", true);
    const auto provider = closed_object_schema({{"moduleId", id}, {"providerId", id}, {"kind", enum_schema({"pdb", "export", "user", "unknown"})},
        {"source", nullable_schema(reference_schema("FileRef"))}, {"sha256", nullable_schema(string_schema("sha256", 64))}, {"signature", nullable_schema(string_schema("utf8-text", 128))},
        {"age", nullable_schema(bounded_integer_schema(0, 0xffffffff))}, {"moduleMatch", enum_schema({"matched", "mismatched", "unknown"})}, {"loaded", boolSchema}, {"networkUsed", boolSchema}},
        {"moduleId", "providerId", "kind", "source", "sha256", "signature", "age", "moduleMatch", "loaded", "networkUsed"});
    add("symbols_load", "symbols", "Load an actual hash/module-matched symbol provider from a file or explicit store; network access requires explicit allowance and effective grants.",
        context_schema("TargetRef", {{"moduleId", id}, {"source", {{"oneOf", Json::array({reference_schema("FileRef"), closed_object_schema({{"kind", {{"const", "store"}}},
            {"location", string_schema("utf8-text", 32767)}}, {"kind", "location"})})}}}, {"networkAllowed", boolSchema}, {"idempotencyKey", id}}, {"moduleId"}), provider,
        {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent, "Admitted source/provider loads and actual signature/age/module match are observed; downloads cannot occur implicitly and mismatch remains an error.",
        {"symbols_list", "modules_list", "operation_reconcile"}, {"A-23", "A-48"}, "src/dbg/symbolinfo.cpp", false, true);
    add("symbols_unload", "symbols", "Unload one exact native symbol provider while retaining user annotations and other providers.",
        context_schema("TargetRef", {{"moduleId", id}, {"providerId", id}, {"idempotencyKey", id}}, {"moduleId", "providerId"}), provider, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "The exact provider is actually absent/unloaded and remaining provider/user-annotation state is observed; unsupported unload is explicit.",
        {"symbols_list", "operation_reconcile"}, {"A-23", "A-38", "A-48"}, "src/dbg/module.cpp", false);
    const auto modes = enum_schema({"linear", "control_flow", "exception_directory", "recursive", "xrefs", "advanced", "nukem"});
    add("analysis_start", "analysis", "Run a selected native analysis over an explicit module/range under its lease, preserving analysis/provider/version and queued versus finished state.",
        mutation({{"moduleId", id}, {"mode", modes}, {"range", reference_schema("AddressRange")}}, {"moduleId", "mode"}),
        closed_object_schema({{"target", reference_schema("TargetRef")}, {"moduleId", id}, {"analysisId", id}, {"analysisVersion", decimal}, {"mode", modes},
            {"jobId", nullable_schema(id)}, {"state", enum_schema({"queued", "running", "completed", "cancelled", "failed", "unknown"})}, {"complete", boolSchema}},
            {"target", "moduleId", "analysisId", "analysisVersion", "mode", "jobId", "state", "complete"}), {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual analysis finishes against the admitted source/context and native database markers/version are reread; queued, interrupted or unresolved work remains explicit.",
        {"analysis_functions", "database_info", "operation_reconcile"}, {"A-36", "A-38", "A-48"}, "src/dbg/commands/cmd-analysis.cpp", false);
    add("analysis_functions", "analysis", "List actual native function boundaries, classifications/names and analysis-source versions with explicit uncertainty.",
        with_page_schema(context_schema("TargetRef", {{"moduleId", id}})), paged_data_schema(analysis_function_schema()), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual native/manual records determine boundaries and source versions; heuristic classifications and unknown instruction counts are not fabricated.",
        {"analysis_start", "database_info"}, {"A-36", "A-38"}, "src/dbg/function.cpp", true);
    add("analysis_blocks", "analysis", "Read actual function blocks/instructions/edges, retaining unresolved or external control-flow targets.",
        with_page_schema(context_schema("TargetRef", {{"functionId", id}}, {"functionId"})), paged_data_schema(analysis_block_schema()), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Captured native analysis and decoded bytes determine actual block/edge records; unresolved indirect targets and partial coverage remain explicit.",
        {"analysis_functions", "analysis_start"}, {"A-36"}, "src/dbg/analysis/controlflowanalysis.cpp", true);
    add("analysis_graph", "analysis", "Read actual structured CFG and optionally publish a rendered artifact without inventing unresolved targets.",
        context_schema("TargetRef", {{"functionId", id}, {"format", enum_schema({"structured", "svg", "png"})}}, {"functionId"}),
        closed_object_schema({{"functionId", id}, {"analysisVersion", decimal}, {"blocks", bounded_array_schema(analysis_block_schema(), MaximumPageLimit)},
            {"edges", bounded_array_schema(analysis_edge_schema(), MaximumPageLimit)}, {"unresolvedEdges", decimal}, {"artifact", nullable_schema(managed_artifact_schema())}, {"complete", boolSchema}},
            {"functionId", "analysisVersion", "blocks", "edges", "unresolvedEdges", "artifact", "complete"}), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Structured native graph/bytes preserve unresolved edge evidence; optional rendering is durably published/hash-reread and does not make uncertain analysis complete.",
        {"analysis_blocks", "analysis_functions"}, {"A-36", "A-40"}, "src/dbg/analysis/controlflowanalysis.cpp", true, false,
        {{"format", "svg", {Effect::FileExport}}, {"format", "png", {Effect::FileExport}}});
    const auto reference = closed_object_schema({{"fromHex", hex}, {"toHex", nullable_schema(hex)}, {"kind", enum_schema({"code", "data", "call", "jump", "unknown"})},
        {"source", id}, {"analysisVersion", decimal}, {"resolved", boolSchema}}, {"fromHex", "toHex", "kind", "source", "analysisVersion", "resolved"});
    add("analysis_references", "analysis", "Read native/search-derived code/data/call/jump references with exact source version and resolution/coverage.",
        address_forms(with_page_schema(context_schema("TargetRef", {{"direction", enum_schema({"to", "from"})}, {"kinds", bounded_array_schema(enum_schema({"code", "data", "call", "jump", "unknown"}), 5, 1, true)}}, {"direction"}))),
        paged_data_schema(reference), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Actual native/search facts determine reference addresses/kinds; unresolved targets and remaining bounded search coverage are explicit.",
        {"analysis_start", "analysis_functions"}, {"A-36"}, "src/dbg/xrefs.cpp", true);
    const auto loop = closed_object_schema({{"loopId", id}, {"functionId", nullable_schema(id)}, {"startHex", hex}, {"endHex", hex}, {"parentLoopId", nullable_schema(id)},
        {"depth", bounded_integer_schema(0, MaximumPageLimit)}, {"manual", boolSchema}, {"instructionCount", nullable_schema(decimal)}, {"analysisVersion", decimal}},
        {"loopId", "functionId", "startHex", "endHex", "parentLoopId", "depth", "manual", "instructionCount", "analysisVersion"});
    add("analysis_loops", "analysis", "List actual loop boundaries, parent/nesting and manual/source-version metadata.", with_page_schema(context_schema("TargetRef", {{"functionId", id}})), paged_data_schema(loop),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Native loop records determine actual boundaries/depth/parent and source version with correlated paging.",
        {"analysis_functions", "database_info"}, {"A-36", "A-38"}, "src/dbg/loop.cpp", true);
    add("analysis_encoding_get", "analysis", "Read actual native code/data encoding classifications over a resolved bounded range, including every declared ENCODETYPE.",
        ranged(context_schema("TargetRef")), analysis_encoding_observation_schema(), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual native encoding-map spans and source version are read without substituting a generic code/data label or guessing unreadable regions.",
        {"analysis_encoding_get", "database_info"}, {"A-36", "A-38"}, "src/dbg/encodemap.cpp", true);
    add("analysis_encoding_set", "analysis", "Set a selected native encoding classification under the target lease and reread map/disassembly state.",
        ranged(mutation({{"encoding", native_encoding_schema()}}, {"encoding"})), analysis_encoding_observation_schema(), {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Resolved range/provider checks pass and actual encoding-map values/database version and resulting decode interpretation are observed.",
        {"analysis_encoding_get", "disassembly_read", "operation_reconcile"}, {"A-36", "A-38", "A-48"}, "src/dbg/encodemap.cpp", false);
    for(const auto* name : {"analysis_function_set", "analysis_argument_set"})
        add(name, "analysis", "Set an explicit compare-context native manual/automatic function or argument boundary range and retain database state.",
            mutation({{"range", reference_schema("AddressRange")}, {"kind", enum_schema({"manual", "automatic"})}}, {"range"}), database_observation_schema(), {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
            "Actual resolved native range/overlap checks pass; requested boundaries/category and changed database version are reread without altering unrelated records.",
            {"database_info", "analysis_functions", "operation_reconcile"}, {"A-36", "A-38", "A-48"}, name == std::string("analysis_function_set") ? "src/dbg/function.cpp" : "src/dbg/argument.cpp", false);
    add("analysis_range_delete", "analysis", "Delete exact native function/argument/loop/analysis records in the admitted range under its lease.",
        mutation({{"kind", enum_schema({"function", "argument", "loop", "encoding", "xref", "analysis"})}, {"range", reference_schema("AddressRange")}}, {"kind", "range"}), database_observation_schema(),
        {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent, "Selected native records are absent/reread with exact version and preserved unrelated/manual categories; partial effects remain explicit.",
        {"database_info", "analysis_functions", "operation_reconcile"}, {"A-36", "A-38", "A-48"}, "src/dbg/commands/cmd-analysis.cpp", false);
}
}
