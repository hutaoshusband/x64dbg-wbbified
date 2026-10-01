#include "registry.h"
#include "analysis_types.h"
#include "inspection_types.h"
#include "lifecycle.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json library_or_file_forms(Json base)
{
    auto forms = file_forms(base).at("oneOf");
    const auto library = contract_schema("LibraryRef");
    forms.push_back(extend_object_schema(std::move(base), library.at("properties"), library.at("required")));
    return {{"oneOf", std::move(forms)}};
}

Json favorite_forms(bool observed)
{
    const auto text = string_schema("utf8-text", 4096);
    auto base = closed_object_schema({{"favoriteId", string_schema("opaque-id")}, {"name", text},
        {"description", string_schema("utf8-text", 4096, 0)}, {"shortcut", string_schema("utf8-text", 128, 0)}}, {"favoriteId", "name"});
    if(observed)
        base = extend_object_schema(std::move(base), {{"actionId", string_schema("opaque-id")}, {"effects", effect_list_schema()},
            {"classification", enum_schema({"known", "unknown"})}, {"enabled", {{"type", "boolean"}}},
            {"disabledReason", nullable_schema(text)}}, {"description", "shortcut", "actionId", "effects", "classification", "enabled", "disabledReason"});
    return {{"oneOf", Json::array({
        extend_object_schema(base, {{"kind", {{"const", "command"}}}, {"commandText", text}}, {"kind", "commandText"}),
        extend_object_schema(base, {{"kind", {{"const", "tool"}}}, {"file", reference_schema("FileRef")},
            {"rawCommandLine", string_schema("windows-command-line", MaximumWindowsCommandUnits, 0)},
            {"cwd", string_schema("windows-absolute-path", 32767)}}, {"kind", "file"}),
        extend_object_schema(base, {{"kind", {{"const", "script"}}}, {"script", {{"oneOf", Json::array({reference_schema("LibraryRef"), reference_schema("FileRef")})}}}}, {"kind", "script"})
    })}};
}
}

void append_database_settings_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096);
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto mergePolicy = enum_schema({"reject", "keep_existing", "replace"});
    const auto annotationKinds = enum_schema({"label", "comment", "bookmark", "color"});
    const auto database = database_observation_schema();
    const auto annotation = annotation_forms(closed_object_schema(Json::object(), Json::array()), true);
    const auto mutation = [&](Json properties = Json::object(), Json required = Json::array())
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        required.push_back("leaseId");
        return context_schema("TargetRef", std::move(properties), std::move(required));
    };
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent)
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance), "planned:" + source,
            idempotent, false, nullptr));
    };
    add("annotations_list", "annotations", "Read actual native labels/comments/bookmarks/colors with manual/automatic provenance and database revisions.",
        with_page_schema(context_schema("TargetRef", {{"kind", annotationKinds}, {"range", reference_schema("AddressRange")}})), paged_data_schema(annotation),
        {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent, "Native per-category records and module/source identities are actually enumerated; automatic/manual origins, missing data and pagination remain explicit.",
        {"database_info", "annotations_list"}, {"A-38"}, "src/dbg/commands/cmd-user-database.cpp", true);
    Json setForms = Json::array();
    const auto values = annotation_forms(mutation({{"expectedRevision", id}}), false);
    for(const auto& value : values.at("oneOf"))
    {
        const auto locations = address_forms(value);
        for(const auto& location : locations.at("oneOf"))
            setForms.push_back(location);
    }
    add("annotations_set", "annotations", "Set one native annotation at an exact resolved location with optional revision comparison under its lease.",
        {{"oneOf", std::move(setForms)}}, annotation, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "The resolved native annotation value/type/source and new database revision are reread; conflicting expected revisions reject before effects and unrelated annotation types remain unchanged.",
        {"annotations_list", "database_info", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/commands/cmd-user-database.cpp", false);
    const auto recordResult = closed_object_schema({{"recordId", id}, {"annotationId", nullable_schema(id)}, {"kind", annotationKinds},
        {"status", enum_schema({"applied", "removed", "kept", "conflict", "failed", "unknown"})}, {"revision", nullable_schema(id)},
        {"error", nullable_schema(reference_schema("DomainError"))}}, {"recordId", "annotationId", "kind", "status", "revision", "error"});
    const auto changed = closed_object_schema({{"database", database}, {"records", bounded_array_schema(recordResult, MaximumPageLimit)},
        {"preservedKinds", bounded_array_schema(annotationKinds, 4, 0, true)}, {"complete", boolSchema}}, {"database", "records", "preservedKinds", "complete"});
    add("annotations_delete", "annotations", "Remove exact annotation IDs under the target lease while preserving other categories and reporting per-record conflicts/effects.",
        mutation({{"annotationIds", bounded_array_schema(id, MaximumPageLimit, 1, true)}}, {"annotationIds"}), changed, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Each owned/native source record is actually absent or explicitly failed/conflicted; preserved types and new database version are independently reread.",
        {"annotations_list", "database_info", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/commands/cmd-user-database.cpp", false);
    add("annotations_import", "annotations", "Import pinned library or file annotations under an explicit merge policy and target/module identity validation.",
        library_or_file_forms(mutation({{"mergePolicy", mergePolicy}}, {"mergePolicy"})), changed, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual hash/revision-pinned source records are matched to native target modules and conflicts are resolved only by the admitted policy; per-record effects and final database revisions are reread.",
        {"annotations_list", "database_info", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/commands/cmd-user-database.cpp", false);
    const auto selection = closed_object_schema({{"annotationIds", bounded_array_schema(id, MaximumPageLimit, 1, true)},
        {"kinds", bounded_array_schema(annotationKinds, 4, 1, true)}, {"range", reference_schema("AddressRange")}}, Json::array());
    add("annotations_export", "annotations", "Publish selected actual annotation records to an owned managed artifact with pinned module identities and source database revision.",
        context_schema("TargetRef", {{"selection", selection}, {"namespaceId", id}}, {"namespaceId"}),
        closed_object_schema({{"artifact", managed_artifact_schema()}, {"database", database}, {"recordCount", decimal}, {"complete", boolSchema}},
            {"artifact", "database", "recordCount", "complete"}), {Effect::Inspect, Effect::FileExport}, Executor::Engine, StateRequirement::TargetPresent,
        "Captured actual selected records/module identities are durably published and exact bytes/hash/count are reread; bounded partial selection is explicit.",
        {"annotations_list", "database_info", "operation_reconcile"}, {"A-38", "A-40", "A-48"}, "src/dbg/commands/cmd-user-database.cpp", true);
    add("database_save", "database", "Save actual native database records to a declared destination or managed default with durable hash/path/version evidence.",
        context_schema("TargetRef", {{"destination", string_schema("windows-absolute-path", 32767)}, {"idempotencyKey", id}}), database,
        {Effect::Configure, Effect::FileExport}, Executor::Engine, StateRequirement::TargetPresent,
        "Native serialization completes and actual persisted file identity/hash/records are reread; saved version and dirty state reflect verified publication, with restart/reload proof required for persistence acceptance.",
        {"database_info", "database_load", "operation_reconcile"}, {"A-38", "A-40", "A-48"}, "src/dbg/database.cpp", false);
    add("database_load", "database", "Load actual file database records under its lease with optional explicit merge policy and target/module match checks.",
        file_forms(mutation({{"mergePolicy", mergePolicy}})), database, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Hash-pinned actual database source and matching target/module identities are admitted before native effects; loaded records/version, conflicts and preserved unrelated state are reread.",
        {"database_info", "annotations_list", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/database.cpp", false);
    const auto categories = enum_schema({"labels", "comments", "bookmarks", "colors", "functions", "arguments", "loops", "xrefs", "encodings", "breakpoints", "modules", "watches", "notes", "init_script", "plugins", "command_line"});
    add("database_clear", "database", "Clear selected actual native database categories under its lease with explicit preserved categories and unsupported provider behavior.",
        mutation({{"kinds", bounded_array_schema(categories, 16, 1, true)}}), database, {Effect::Configure}, Executor::Engine, StateRequirement::TargetPresent,
        "Only selected supported native categories are actually cleared/reread; unknown plugin-owned records reject or report explicit partial effects and final database version/counts are observed.",
        {"database_info", "annotations_list", "operation_reconcile"}, {"A-38", "A-48"}, "src/dbg/database.cpp", false);
    add("database_info", "database", "Read actual native database loaded/saved versions, dirty state, file/hash/module identities and provider-category counts.",
        context_schema("TargetRef"), database, {Effect::Inspect}, Executor::Engine, StateRequirement::TargetPresent,
        "Actual native/database coordinator records and current persisted source identity determine versions/dirty/counts; missing saved/loaded observations remain unknown.",
        {"database_info", "target_state"}, {"A-38"}, "src/dbg/database.cpp", true);
    const auto setting = closed_object_schema({{"settingId", id}, {"section", string_schema("utf8-text", 128)}, {"key", string_schema("utf8-text", 128)},
        {"value", typed_setting_value_schema()}, {"valueSchema", {{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}}},
        {"storage", enum_schema({"current", "persistent", "both"})}, {"requiresRestart", boolSchema}, {"nativeWidth", enum_schema({32, 64})},
        {"provider", id}, {"effects", effect_list_schema()}, {"enabled", boolSchema}, {"disabledReason", nullable_schema(text)}},
        {"settingId", "section", "key", "value", "valueSchema", "storage", "requiresRestart", "nativeWidth", "provider", "effects", "enabled", "disabledReason"});
    const auto filter = closed_object_schema({{"provider", id}, {"section", string_schema("utf8-text", 128)}, {"domain", id}}, Json::array());
    add("settings_list", "settings", "List actual supported debugger/GUI/provider options, typed values and schemas with effect/restart requirements on their GUI owner.",
        with_page_schema(context_schema("InstanceRef", {{"filter", filter}})), paged_data_schema(setting), {Effect::Inspect}, Executor::Gui, StateRequirement::InstanceReady,
        "Actual native GUI/bridge/provider settings and value schemas are enumerated on their owner with version/current/persistent distinctions; unavailable options remain explicit.",
        {"settings_list", "debugger_settings_get"}, {"A-19", "A-38", "A-40"}, "src/gui/Src/Utils/Configuration.cpp", true);
    const auto settingChange = closed_object_schema({{"settingId", id}, {"value", typed_setting_value_schema()}}, {"settingId", "value"});
    add("settings_apply", "settings", "Apply compared-version native GUI/bridge/provider settings without silent restart or privileged side effects.",
        context_schema("InstanceRef", {{"changes", bounded_array_schema(settingChange, MaximumPageLimit, 1)}, {"expectedVersion", decimal}, {"idempotencyKey", id}}, {"changes", "expectedVersion"}),
        closed_object_schema({{"instanceId", id}, {"version", decimal}, {"items", bounded_array_schema(setting, MaximumPageLimit)},
            {"pendingRestartIds", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"persisted", boolSchema}, {"complete", boolSchema}},
            {"instanceId", "version", "items", "pendingRestartIds", "persisted", "complete"}), {Effect::Configure}, Executor::Gui, StateRequirement::InstanceReady,
        "Version/provider/value validation and effective nested effects/grants pass before changes; actual owner-applied values/persistent bytes are reread, conflicts and pending restart requirements are explicit.",
        {"settings_list", "debugger_settings_get", "operation_reconcile"}, {"A-19", "A-38", "A-40", "A-48"}, "src/gui/Src/Utils/Configuration.cpp", false);
    const auto favorites = closed_object_schema({{"instanceId", id}, {"version", decimal}, {"entries", bounded_array_schema(favorite_forms(true), MaximumPageLimit)},
        {"persisted", boolSchema}, {"complete", boolSchema}}, {"instanceId", "version", "entries", "persisted", "complete"});
    add("favorites_list", "favorites", "Read actual native command/tool/script favorites and their action identities/effect classification on the GUI owner.",
        context_schema("InstanceRef"), favorites, {Effect::Inspect}, Executor::Gui, StateRequirement::InstanceReady,
        "Actual favorite storage and discovered actions agree on command/tool/script source and shortcut; unknown execution effects disable invocation until classification/grants are resolved.",
        {"favorites_list", "settings_list"}, {"A-19", "A-40", "A-48"}, "src/gui/Src/Gui/FavouriteTools.cpp", true);
    add("favorites_set", "favorites", "Persist compared-version native favorite entries and expose matching classified actions without executing stored commands/tools/scripts.",
        context_schema("InstanceRef", {{"entries", bounded_array_schema(favorite_forms(false), MaximumPageLimit)}, {"expectedVersion", decimal}, {"idempotencyKey", id}}, {"entries", "expectedVersion"}),
        favorites, {Effect::Configure}, Executor::Gui, StateRequirement::InstanceReady,
        "Compared version and actual native shortcut/provider validation pass before persistence; actual stored entries and matching discovered action/effect identities are reread, with restart proof required for persistence acceptance.",
        {"favorites_list", "settings_list", "operation_reconcile"}, {"A-19", "A-38", "A-40", "A-48"}, "src/gui/Src/Gui/FavouriteTools.cpp", false);
}
}
