#include "registry.h"
#include "patch_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_assembly_file_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto hex = reference_schema("Hex64");
    const auto decimal = reference_schema("Decimal64");
    const auto sha = string_schema("sha256", 64);
    const auto bytes = string_schema("hex-bytes", MaximumPayloadBytes * 2);
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto source = string_schema("utf8-text", MaximumPayloadBytes);
    const auto architecture = enum_schema({"x32", "x64"});
    const auto destination = string_schema("windows-absolute-path", 32767);
    const auto mode = enum_schema({"save_as", "replace"});
    const auto pageSet = paged_data_schema(patch_set_schema());
    const auto mutation = [&](Json properties = Json::object(), Json required = Json::array())
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        required.push_back("leaseId");
        return context_schema("TargetRef", std::move(properties), std::move(required));
    };
    const auto disassembly = closed_object_schema({{"architecture", architecture}, {"originHex", hex},
        {"items", bounded_array_schema(decoded_instruction_schema(), MaximumPageLimit)}, {"bytesConsumed", decimal}, {"complete", boolSchema},
        {"source", closed_object_schema({{"kind", enum_schema({"target", "buffer"})}, {"sha256", nullable_schema(sha)},
            {"context", nullable_schema(reference_schema("TargetRef"))}}, {"kind", "sha256", "context"})}},
        {"architecture", "originHex", "items", "bytesConsumed", "complete", "source"});
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string nativeSource, bool idempotent, bool openWorld = false, std::vector<EffectCondition> conditions = {})
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + nativeSource,
            idempotent, openWorld, nullptr, std::move(conditions)));
    };
    const auto detail = enum_schema({"basic", "full"});
    const auto count = bounded_integer_schema(1, MaximumPageLimit, 16);
    const auto targetForms = address_forms(context_schema("TargetRef", {{"count", count}, {"detail", detail}}));
    Json decodeChoices = targetForms.at("oneOf");
    decodeChoices.push_back(closed_object_schema({{"architecture", architecture}, {"bytes", bytes}, {"origin", hex}, {"count", count}, {"detail", detail}}, {"architecture", "bytes", "origin"}));
    add("disassembly_read", "disassembly", "Decode actual target bytes at a resolved address or supplied bytes at an explicit architecture/origin, preserving operands/branches/labels and decode failures.",
        {{"oneOf", decodeChoices}}, disassembly, {Effect::Inspect}, Executor::Broker, StateRequirement::Broker,
        "Selected source bytes and target width/origin determine actual instruction boundaries/operands; target reads dispatch to its owner and preserve holes/context.",
        {"memory_read", "target_state"}, {"A-19", "A-21", "A-28"}, "src/dbg/disasm_helper.cpp", true);
    const auto boundary = enum_schema({"database", "analysis", "unwind", "heuristic", "explicit"});
    add("disassembly_function", "disassembly", "Read native function boundary evidence and paged decoded instructions at a resolved target address with explicit boundary source/uncertainty.",
        address_forms(with_page_schema(context_schema("TargetRef", {{"boundarySource", boundary}}))),
        extend_object_schema(paged_data_schema(decoded_instruction_schema()), {{"startHex", hex}, {"endHex", hex}, {"boundarySource", boundary},
            {"certainty", enum_schema({"verified", "heuristic", "unknown"})}}, {"startHex", "endHex", "boundarySource", "certainty"}),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Native/requested boundaries and their evidence determine actual decoded source instructions; heuristic or unresolved boundaries remain labeled.",
        {"analysis_functions", "memory_read", "target_state"}, {"A-21", "A-36"}, "src/dbg/disasm_helper.cpp", true);
    add("assembly_encode", "assembly", "Encode instruction/block source at explicit architecture/origin using a source-owned pure backend; native symbol/provider effects require separate admission.",
        closed_object_schema({{"architecture", architecture}, {"origin", hex}, {"source", source}, {"mode", enum_schema({"instruction", "block"})}}, {"architecture", "origin", "source", "mode"}),
        encoded_block_schema(), {Effect::Inspect}, Executor::Broker, StateRequirement::Broker,
        "Actual backend encoding produces exact bytes/boundaries/labels at the requested origin without target mutation; errors identify the source line/span and produce no patch.",
        {"assembly_encode", "capabilities_describe"}, {"A-28", "A-29"}, "src/dbg/assemble.cpp", true);
    const auto following = closed_object_schema({{"addressHex", hex}, {"expectedBytesHex", bytes}, {"observedBytesHex", nullable_schema(bytes)}, {"unchanged", boolSchema}},
        {"addressHex", "expectedBytesHex", "observedBytesHex", "unchanged"});
    add("assembly_apply", "assembly", "Preflight encoded source/span and expected bytes, then apply a tracked runtime patch with explicit none/NOP fill and preserved following bytes; no implicit code invocation.",
        address_forms(context_schema("MutationContext", {{"source", source}, {"span", bounded_integer_schema(1, MaximumPayloadBytes)},
            {"expectedBytes", reference_schema("ExpectedBytes")}, {"fill", enum_schema({"none", "nop"})}}, {"source", "span", "expectedBytes", "fill"})),
        closed_object_schema({{"patch", patch_set_schema()}, {"encoding", encoded_block_schema()}, {"disassembly", disassembly}, {"followingBytes", following}},
            {"patch", "encoding", "disassembly", "followingBytes"}),
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPaused, "Encoding fits admitted span and expected bytes before effects; actual tracked bytes/readback/disassembly and unchanged following bytes are verified with breakpoint overlap preserved.",
        {"patch_sets_read", "memory_read", "operation_reconcile"}, {"A-28", "A-29", "A-30", "A-31"}, "src/dbg/assemble.cpp", false);
    const auto plannedRange = closed_object_schema({{"address", reference_schema("AddressRef")}, {"replacementBytesHex", bytes}, {"expectedBytes", reference_schema("ExpectedBytes")}},
        {"address", "replacementBytesHex", "expectedBytes"});
    add("patch_sets_create", "patches", "Create an immutable compare-validated patch plan with module identities and logical original bytes, without installing the planned ranges.",
        mutation({{"name", string_schema("utf8-text", 1024)}, {"ranges", bounded_array_schema(plannedRange, MaximumPageLimit, 1)}}, {"name", "ranges"}), patch_set_schema(),
        {Effect::Modify}, Executor::Engine, StateRequirement::TargetPresent, "Every resolved range/module/expected logical original is preflighted and a pinned immutable plan is retained; overlaps and unresolved mappings fail before writes.",
        {"patch_sets_read", "memory_read"}, {"A-30", "A-31", "A-48"}, "src/dbg/patches.cpp", false);
    add("patch_sets_list", "patches", "List native/managed tracked patch sets, revisions, ownership and observed range state.", with_page_schema(context_schema("TargetRef")), pageSet,
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Tracked native state reconciles with exact retained set revisions/ranges and correlated complete/partial pages.",
        {"patch_sets_list", "target_state"}, {"A-30", "A-31"}, "src/dbg/patches.cpp", true);
    add("patch_sets_read", "patches", "Read one exact patch set/revision with originals/replacements, module VA/RVA, overlaps, ownership and actual native tracking state.",
        context_schema("TargetRef", {{"patchSetId", id}, {"revision", id}}, {"patchSetId"}), patch_set_schema(), {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Requested retained revision and every actually observed tracked range belong to the identified target/module identities; conflicts remain explicit.",
        {"patch_sets_list", "memory_read"}, {"A-30", "A-31", "A-48"}, "src/dbg/patches.cpp", true);
    add("patch_apply_runtime", "patches", "Apply the exact immutable patch set revision under a paused lease with all-range preflight and verified rollback/partial effects.",
        context_schema("MutationContext", {{"patchSetId", id}, {"revision", id}}, {"patchSetId", "revision"}), patch_set_schema(), {Effect::Modify}, Executor::Engine, StateRequirement::TargetPaused,
        "All expected originals/module contexts pass before writes; every admitted range is reread or exact failed/applied/restored ranges and recovery are retained.",
        {"patch_sets_read", "operation_reconcile"}, {"A-30", "A-31", "A-48"}, "src/dbg/patches.cpp", false);
    add("patch_restore_runtime", "patches", "Compare the exact tracked revision and restore runtime originals while preserving traps and conflicting user changes.",
        context_schema("MutationContext", {{"patchSetId", id}, {"expectedRevision", id}}, {"patchSetId", "expectedRevision"}), patch_set_schema(), {Effect::Modify}, Executor::Engine, StateRequirement::TargetPaused,
        "Expected tracking/bytes match and actual original bytes/native tracking are restored; conflicting or failed ranges remain retained with precise recovery.",
        {"patch_sets_read", "operation_reconcile"}, {"A-30", "A-31", "A-48"}, "src/dbg/patches.cpp", false);
    add("patch_restore_all", "patches", "Restore the admitted selected patch sets under a paused lease and retain conflicting or user-owned changes.",
        context_schema("MutationContext", {{"selection", bounded_array_schema(id, MaximumPageLimit, 1, true)}}), pageSet, {Effect::Modify}, Executor::Engine, StateRequirement::TargetPaused,
        "Every selected compatible range is restored/reread and native tracking updated; unselected/conflicting ranges remain intact and partial recovery is explicit.",
        {"patch_sets_list", "operation_reconcile"}, {"A-30", "A-31", "A-48"}, "src/dbg/patches.cpp", false);
    add("patch_export_file", "patches", "Export an exact patch revision through unambiguous module/file mapping to save-as or explicit replacement with source hash preflight and durable backup/journal.",
        file_forms(context_schema("TargetRef", {{"patchSetId", id}, {"revision", id}, {"destination", destination}, {"mode", mode}, {"expectedSha256", sha}, {"idempotencyKey", id}},
            {"patchSetId", "revision", "destination", "mode", "expectedSha256"})), file_transaction_schema(), {Effect::Inspect, Effect::FileExport}, Executor::Broker, StateRequirement::TargetPresent,
        "Hash-pinned source/module mapping admits exact changed offsets; durable publication/readback preserves all other bytes and reports backup/signature impact; runnable validity requires fresh independent execution.",
        {"file_inspect", "file_patch_undo", "operation_reconcile"}, {"A-32", "A-33", "A-34", "A-35"}, "src/dbg/patches.cpp", false, true,
        {{"mode", "replace", {Effect::FileReplace}}});
    add("file_inspect", "files", "Inspect the exact file/artifact hash, size, PE architecture/sections/mapping/overlay and signature status without inventing unsupported metadata.",
        file_forms(closed_object_schema(Json::object(), Json::array())), file_observation_schema(), {Effect::Inspect}, Executor::Broker, StateRequirement::Broker,
        "Handle-read source identity/hash and actual parsed PE/raw mapping facts agree; malformed/ambiguous mappings and unverified signature status are explicit.",
        {"file_inspect"}, {"A-34", "A-35"}, "src/dbg/module.cpp", true, true);
    const auto fileChange = closed_object_schema({{"positionHex", hex}, {"replacementBytesHex", bytes}, {"expectedBytesHex", bytes}}, {"positionHex", "replacementBytesHex", "expectedBytesHex"});
    const auto plan = closed_object_schema({{"planId", id}, {"planDigest", sha}, {"source", file_observation_schema()}, {"addressMode", enum_schema({"offset", "rva"})},
        {"changes", bounded_array_schema(closed_object_schema({{"fileOffset", decimal}, {"rvaHex", nullable_schema(hex)}, {"originalBytesHex", bytes}, {"replacementBytesHex", bytes}},
            {"fileOffset", "rvaHex", "originalBytesHex", "replacementBytesHex"}), MaximumPageLimit, 1)}, {"moduleIdentity", nullable_schema(sha)},
        {"signatureImpact", enum_schema({"unchanged", "invalidated", "removed", "unknown"})}}, {"planId", "planDigest", "source", "addressMode", "changes", "moduleIdentity", "signatureImpact"});
    add("file_patch_plan", "files", "Create an authenticated immutable file patch plan after source hash, exact expected bytes, bounds and offset/RVA mapping preflight.",
        file_forms(closed_object_schema({{"expectedSha256", sha}, {"changes", bounded_array_schema(fileChange, MaximumPageLimit, 1)}, {"addressMode", enum_schema({"offset", "rva"})}},
            {"expectedSha256", "changes", "addressMode"})), plan, {Effect::Inspect}, Executor::Broker, StateRequirement::Broker,
        "Exact handle-bound file hash and all expected bytes/maps match; an authenticated source-bound digest seals the admitted immutable changed offsets without modifying a file.",
        {"file_inspect", "file_patch_plan"}, {"A-31", "A-34", "A-35"}, "src/dbg/patches.cpp", true, true);
    add("file_patch_apply", "files", "Apply only an authenticated pinned file plan to save-as or explicitly replace, with durable publication/readback, backup and journal.",
        closed_object_schema({{"planId", id}, {"planDigest", sha}, {"destination", destination}, {"mode", mode}, {"idempotencyKey", id}}, {"planId", "planDigest", "destination", "mode"}),
        file_transaction_schema(), {Effect::FileExport}, Executor::Broker, StateRequirement::Broker,
        "Authenticated plan and current source/destination identities pass preflight; published hash/changed offsets/unchanged bytes and backup journal are verified or exact partial/crash recovery is retained.",
        {"file_inspect", "file_patch_undo", "operation_reconcile"}, {"A-32", "A-33", "A-34", "A-35"}, "src/dbg/filehelper.cpp", false, true,
        {{"mode", "replace", {Effect::FileReplace}}});
    add("file_patch_undo", "files", "Compare the exact current file hash and restore the retained transaction backup through durable publication; preserve conflicting external changes.",
        closed_object_schema({{"transactionId", id}, {"expectedCurrentSha256", sha}, {"idempotencyKey", id}}, {"transactionId", "expectedCurrentSha256"}), file_transaction_schema(),
        {Effect::FileReplace}, Executor::Broker, StateRequirement::Broker, "Expected current identity/hash matches, exact backup bytes/hash are durably restored and reread, or conflict/partial recovery is retained without blind overwrite.",
        {"file_inspect", "operation_reconcile"}, {"A-33", "A-35", "A-48"}, "src/dbg/filehelper.cpp", false, true);
    const auto fileRange = closed_object_schema({{"offset", decimal}, {"size", bounded_integer_schema(1, MaximumPayloadBytes)}}, {"offset", "size"});
    add("file_compare", "files", "Compare exact identified left/right files in bounded offset ranges with correlated paged byte differences.",
        with_page_schema(closed_object_schema({{"left", reference_schema("FileRef")}, {"right", reference_schema("FileRef")}, {"ranges", bounded_array_schema(fileRange, MaximumPageLimit, 1)}}, {"left", "right"})),
        extend_object_schema(paged_data_schema(closed_object_schema({{"offset", decimal}, {"leftBytesHex", nullable_schema(bytes)}, {"rightBytesHex", nullable_schema(bytes)}},
            {"offset", "leftBytesHex", "rightBytesHex"})), {{"left", file_observation_schema()}, {"right", file_observation_schema()}}, {"left", "right"}),
        {Effect::Inspect}, Executor::Broker, StateRequirement::Broker, "Actual handle-bound file hashes/bytes determine exact paged differences including unequal length, with correlated source identities.",
        {"file_inspect", "file_compare"}, {"A-32", "A-34", "A-35"}, "src/dbg/filehelper.cpp", true, true);
    auto exportNew = closed_object_schema({{"artifactId", id}, {"destination", destination}, {"overwrite", {{"const", false}}}, {"expectedDestinationSha256", sha}, {"idempotencyKey", id}},
        {"artifactId", "destination", "overwrite"});
    auto exportReplace = exportNew;
    exportReplace["properties"]["overwrite"] = {{"const", "replace"}};
    exportReplace["required"].push_back("expectedDestinationSha256");
    add("file_export", "files", "Export the exact authorized managed artifact revision/hash to an explicit destination; replacement requires a separate file-replace effect and destination preflight.",
        {{"oneOf", Json::array({exportNew, exportReplace})}}, file_transaction_schema(), {Effect::FileExport}, Executor::Broker, StateRequirement::Broker,
        "Exact authorized artifact bytes are durably published and hash-reread; existing destination replacement requires its checked identity/hash and backup/journal, with precise failure recovery.",
        {"file_inspect", "file_patch_undo", "operation_reconcile"}, {"A-32", "A-33", "A-35", "A-40"}, "src/dbg/filehelper.cpp", false, true,
        {{"overwrite", "replace", {Effect::FileReplace}}});
}
}
