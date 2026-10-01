#include "registry.h"
#include "library_script_types.h"
#include "provider_ui_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_library_script_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto sha = string_schema("sha256", 64);
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096, 0);
    const auto boolean = Json{{"type", "boolean"}};
    const auto library = library_object_schema();
    const auto script = script_revision_schema();
    const auto native = native_script_state_schema();
    const auto path = virtual_path_schema();
    const auto engine = string_schema("utf8-text", 256);
    const auto targetContext = Json{{"oneOf", Json::array({reference_schema("TargetRef"), reference_schema("PausedContext")})}};
    const std::vector<Effect> classified = {Effect::Inspect, Effect::Execute, Effect::Modify, Effect::FileExport, Effect::FileReplace, Effect::Elevate, Effect::Configure};
    const auto object = [&](Json properties, Json required) { return closed_object_schema(std::move(properties), std::move(required)); };
    const auto lref = [&](Json properties = Json::object(), Json required = Json::array())
    {
        return context_schema("LibraryRef", std::move(properties), std::move(required));
    };
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance, bool idempotent,
        Executor executor = Executor::Broker, bool nativeEffects = false, std::vector<EffectCondition> conditions = {})
    {
        const auto source = executor == Executor::Engine ? "src/dbg/simplescript.cpp" : "src/mcp/broker/main.cpp";
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, executor == Executor::Engine ? StateRequirement::InstanceReady : StateRequirement::Broker, ArchitectureRequirement::Any,
            std::move(completion), std::move(recovery), std::move(acceptance), std::string("planned:") + source, idempotent, nativeEffects, nullptr, std::move(conditions), nativeEffects));
    };
    const auto namespaceRecord = object({{"namespaceId", id}, {"name", text}, {"visibility", enum_schema({"private", "shared"})},
        {"ownerClientId", nullable_schema(id)}, {"access", enum_schema({"read", "read_write"})}, {"version", decimal}, {"quota", library_quota_schema()}},
        {"namespaceId", "name", "visibility", "ownerClientId", "access", "version", "quota"});
    add("library_namespaces", "library", "List authorized private/shared namespaces and their actual access, quota and ownership without exposing other clients.",
        object(Json::object(), Json::array()), object({{"items", bounded_array_schema(namespaceRecord, MaximumPageLimit)}, {"complete", boolean}}, {"items", "complete"}), {Effect::Inspect},
        "Actual credential-local ownership/grants determine the complete namespace/access/quota observation; identifiers alone never authorize later reads.",
        {"library_quota"}, {"A-40", "A-42", "A-43"}, true);
    add("library_files_list", "library", "List authorized virtual files with immutable revisions, exact hashes, sizes, types and retained references.",
        with_page_schema(object({{"namespaceId", id}, {"path", path}}, {"namespaceId"})), paged_data_schema(library), {Effect::Inspect},
        "A coherent namespace metadata version yields every matching current file exactly once across bounded pages; trashed and unauthorized revisions do not leak.",
        {"library_file_read", "library_search"}, {"A-40", "A-42", "A-43"}, true);
    add("library_file_read", "library", "Read an exact authorized immutable library revision as a bounded byte chunk with whole and chunk hashes.",
        lref({{"offset", decimal}, {"length", bounded_integer_schema(1, 1048576, 65536)}}, Json::array()), library_chunk_schema(), {Effect::Inspect},
        "Actual pinned revision bytes, offset/length, EOF and chunk hash agree; quota and authorization apply independently and no partial blob is presented as published.",
        {"library_files_list", "library_file_read"}, {"A-40", "A-41", "A-42"}, true);
    add("library_file_write", "library", "Publish an immutable revision from bounded inline content or a hash-pinned authorized artifact under optimistic current-revision checks.",
        object({{"namespaceId", id}, {"virtualPath", path}, {"content", library_content_schema()}, {"expectedRevision", nullable_schema(id)},
            {"kind", id}, {"mediaType", text}, {"tags", bounded_array_schema(string_schema("utf8-text", 256), 128, 0, true)}, {"idempotencyKey", id}}, {"namespaceId", "virtualPath", "content"}), library, {Effect::Configure},
        "Actual source bytes/hash, namespace ownership, safe handle-bound storage path and quota pass before recoverable blob publication and atomic metadata commit; reread and restart retain the new revision.",
        {"library_file_read", "library_quota", "operation_reconcile"}, {"A-40", "A-41", "A-42", "A-43"}, false);
    add("library_file_rename", "library", "Rename a compared library revision within the same authorized namespace while retaining immutable content/history and conflicts.",
        lref({{"newVirtualPath", path}, {"expectedRevision", id}, {"idempotencyKey", id}}, {"newVirtualPath", "expectedRevision"}), library, {Effect::Configure},
        "Compared current revision and safe destination name pass before atomic metadata rename; actual new name/history/hash are reread and conflicting names or newer revisions are preserved.",
        {"library_files_list", "library_file_read", "operation_reconcile"}, {"A-40", "A-42", "A-43"}, false);
    add("library_file_delete", "library", "Move a compared library object into recoverable trash while preserving pinned revisions and active job/evidence references.",
        lref({{"expectedRevision", id}, {"idempotencyKey", id}}, {"expectedRevision"}), library_trash_schema(), {Effect::Configure},
        "Actual matching object metadata is durably trashed without reclaiming referenced content; trash identity/restoration and retained revision are reread.",
        {"library_file_restore", "library_quota", "operation_reconcile"}, {"A-40", "A-43", "A-48"}, false);
    add("library_file_restore", "library", "Restore an authorized trash entry to its previous or explicit safe virtual name without silently replacing a conflict.",
        object({{"namespaceId", id}, {"trashId", id}, {"destination", path}, {"idempotencyKey", id}}, {"namespaceId", "trashId"}), library, {Effect::Configure},
        "Actual trash ownership/content and destination conflict checks pass before atomic restore; exact retained revision/hash/name are reread, with conflicting live content untouched.",
        {"library_file_read", "library_files_list", "operation_reconcile"}, {"A-40", "A-42", "A-43"}, false);
    const auto match = object({{"object", library}, {"source", enum_schema({"metadata", "content"})}, {"offset", nullable_schema(decimal)},
        {"snippet", text}, {"snippetTruncated", boolean}}, {"object", "source", "offset", "snippet", "snippetTruncated"});
    add("library_search", "library", "Search authorized metadata/content with bounded query, exact revision matches and explicit snippets/continuation.",
        with_page_schema(object({{"namespaceId", id}, {"query", string_schema("utf8-text", 4096)}, {"kind", id}}, {"namespaceId", "query"})), paged_data_schema(match), {Effect::Inspect},
        "Actual authorized revision/index state determines matching metadata/content offsets; incomplete search or snippets are explicit, and cross-namespace content is never returned.",
        {"library_file_read", "library_files_list"}, {"A-40", "A-42"}, true);
    add("library_import", "library", "Import a granted handle-bound file or authorized artifact after exact source hash, virtual destination, size and namespace checks.",
        file_forms(object({{"namespaceId", id}, {"name", path}, {"kind", id}, {"expectedSha256", sha}, {"idempotencyKey", id}}, {"namespaceId", "name", "kind", "expectedSha256"})), library, {Effect::Configure},
        "Actual source identity/hash remains stable across the bounded read; quota and storage publication preserve exact imported bytes in a durable independent revision without a workspace dependency.",
        {"library_file_read", "library_quota", "operation_reconcile"}, {"A-40", "A-41", "A-42", "A-43"}, false);
    auto exportNew = lref({{"destination", string_schema("windows-absolute-path", 32767)}, {"overwrite", {{"const", false}}}, {"expectedDestinationSha256", sha}, {"idempotencyKey", id}}, {"destination", "overwrite"});
    auto exportReplace = exportNew;
    exportReplace["properties"]["overwrite"] = {{"const", "replace"}};
    exportReplace["required"].push_back("expectedDestinationSha256");
    const auto exported = object({{"revision", reference_schema("LibraryRef")}, {"destination", string_schema("windows-absolute-path", 32767)},
        {"sha256", sha}, {"size", decimal}, {"replaced", boolean}, {"backupArtifactId", nullable_schema(id)}, {"journalId", id}, {"verified", boolean}},
        {"revision", "destination", "sha256", "size", "replaced", "backupArtifactId", "journalId", "verified"});
    add("library_export", "library", "Export an exact authorized library revision to a granted destination; explicit replacement compares its hash and retains backup/journal.",
        {{"oneOf", Json::array({exportNew, exportReplace})}}, exported, {Effect::FileExport},
        "Actual immutable source bytes are durably published and destination hash-reread through handle-bound checks; replacements retain a restorable backup and truthful partial recovery.",
        {"library_file_read", "file_inspect", "operation_reconcile"}, {"A-40", "A-41", "A-42", "A-43"}, false, Executor::Broker, false,
        {{"overwrite", "replace", {Effect::FileReplace}}});
    add("library_quota", "library", "Read actual namespace/profile usage, reserved/retained/pinned content, limits and bounded safe cleanup candidates.",
        object({{"namespaceId", id}}, {"namespaceId"}), library_quota_schema(), {Effect::Inspect},
        "Actual durable metadata/blob/upload accounting yields coherent quota facts; no live-job or retained-evidence revision is offered as reclaimable.",
        {"library_files_list", "library_file_read"}, {"A-40", "A-41", "A-43"}, true);
    add("scripts_list", "scripts", "List authorized script revisions with actual engine/API/target requirements, compatibility, tags and static diagnostics.",
        with_page_schema(object({{"namespaceId", id}, {"engine", engine}, {"tags", bounded_array_schema(string_schema("utf8-text", 256), 128, 0, true)}}, {"namespaceId"})), paged_data_schema(script), {Effect::Inspect},
        "Every matching authorized script revision is enumerated with exact stored manifest/hash and current provider compatibility; validation does not imply execution.",
        {"scripts_read", "scripts_validate"}, {"A-40", "A-44", "A-46", "A-47", "A-52"}, true);
    add("scripts_create", "scripts", "Create durable script source from bounded inline UTF-8 or a pinned artifact, with a closed manifest and pinned dependency revisions.",
        object({{"namespaceId", id}, {"name", path}, {"engine", engine}, {"source", script_source_schema()}, {"manifest", script_manifest_schema()}, {"idempotencyKey", id}},
            {"namespaceId", "name", "engine", "source"}), script, {Effect::Configure},
        "Authorized source bytes pass actual UTF-8/size/manifest checks and durably publish an immutable revision; diagnostics distinguish valid, invalid, unsupported and unvalidated source without executing it.",
        {"scripts_read", "scripts_validate", "operation_reconcile"}, {"A-40", "A-41", "A-42", "A-43", "A-46", "A-47"}, false);
    add("scripts_update", "scripts", "Publish a new script revision after expected-current comparison, retaining previous source and pinned manifest/dependencies.",
        lref({{"source", script_source_schema()}, {"manifest", script_manifest_schema()}, {"expectedRevision", id}, {"idempotencyKey", id}}, {"source", "expectedRevision"}), script, {Effect::Configure},
        "Actual compared current revision and authorized content produce an atomic new revision; previous source/history and active execution pins survive and conflicts do not overwrite newer metadata.",
        {"scripts_read", "scripts_revisions", "operation_reconcile"}, {"A-40", "A-43", "A-48"}, false);
    add("scripts_read", "scripts", "Read exact authorized script metadata and UTF-8 source or a whole hash-pinned source artifact for larger revisions.",
        lref(), object({{"script", script}, {"source", script_source_schema()}, {"complete", boolean}}, {"script", "source", "complete"}), {Effect::Inspect},
        "Actual immutable source/hash/manifest/dependencies agree; large source remains available through bounded authorized artifact reads rather than truncation or workspace files.",
        {"library_file_read", "artifacts_read", "scripts_revisions"}, {"A-40", "A-41", "A-42"}, true);
    add("scripts_revisions", "scripts", "List complete authorized immutable history for one script with exact previous revision links and retention state.",
        with_page_schema(object({{"namespaceId", id}, {"scriptId", id}}, {"namespaceId", "scriptId"})), paged_data_schema(script), {Effect::Inspect},
        "A stable history snapshot returns every retained revision exactly once, including referenced/trash history, with ownership and cursor version checked.",
        {"scripts_read", "library_quota"}, {"A-40", "A-43"}, true);
    add("scripts_validate", "scripts", "Validate an exact revision's syntax/API/dependencies/target requirements and effective bounded budget without running source.",
        lref({{"targetContext", targetContext}}, Json::array()), script_validation_schema(), {Effect::Inspect},
        "Actual engine/parser/provider and immutable dependencies determine diagnostics, limits and classified effects; validation reports executed=false and cannot satisfy runtime or OS containment acceptance.",
        {"scripts_read", "script_languages", "target_state"}, {"A-44", "A-46", "A-47", "A-52"}, true);
    const auto runProperties = Json{{"instanceId", id}, {"targetContext", targetContext}, {"parameters", provider_arguments_schema()},
        {"limits", script_limits_schema()}, {"leaseId", id}, {"idempotencyKey", id}};
    add("scripts_run", "scripts", "Run an exact pinned authorized script revision as a durable job after actual engine/manifest/provider and host-call authority resolution.",
        lref(runProperties, Json::array()), script_run_schema(), classified,
        "The real selected native/workflow/JS/provider engine executes under actual intersected grants/context/lease/budgets; retained step/effect/canary/artifact evidence determines outcome, not job creation.",
        {"job_get", "job_cancel", "operation_reconcile", "scripts_read"}, {"A-08", "A-09", "A-44", "A-45", "A-46", "A-47", "A-48", "A-50", "A-52"}, false, Executor::Broker, true);
    add("scripts_delete", "scripts", "Recoverably delete compared script metadata while retaining immutable revisions pinned by jobs, dependencies or evidence.",
        lref({{"expectedRevision", id}, {"idempotencyKey", id}}, {"expectedRevision"}), library_trash_schema(), {Effect::Configure},
        "Actual expected-current comparison and ownership pass before durable trash publication; active exact revision execution continues from its retained pin and restore preserves source/hash.",
        {"library_file_restore", "scripts_revisions", "operation_reconcile"}, {"A-40", "A-43", "A-48"}, false);
    const auto language = object({{"engine", engine}, {"name", text}, {"providerId", id}, {"providerBuildId", nullable_schema(sha)}, {"apiVersion", id},
        {"available", boolean}, {"disabledReason", nullable_schema(text)}, {"architecture", enum_schema({"any", "x32", "x64"})},
        {"executor", enum_schema({"broker", "engine", "gui", "script_host"})}, {"trustedCode", boolean},
        {"containment", enum_schema({"none", "restricted_process", "unverified"})}, {"manifestSchema", schema_document_schema()},
        {"limits", script_limits_schema()}, {"controls", bounded_array_schema(id, 128, 0, true)}},
        {"engine", "name", "providerId", "providerBuildId", "apiVersion", "available", "disabledReason", "architecture", "executor", "trustedCode", "containment", "manifestSchema", "limits", "controls"});
    add("script_languages", "scripts", "Discover actual native, workflow, JS and registered provider languages, API/limits/controls and truthful trusted-code or containment status.",
        context_schema("InstanceRef"), object({{"items", bounded_array_schema(language, MaximumPageLimit)}, {"complete", boolean}}, {"items", "complete"}), {Effect::Inspect},
        "Actual language/provider registrations and source-built runner state determine availability; a JS VM alone cannot be reported as OS containment and native providers retain debugger privileges.",
        {"plugins_actions", "scripts_validate"}, {"A-44", "A-47", "A-52"}, true, Executor::Engine);
    add("native_script_load", "scripts", "Load a pinned authorized native script revision through private materialization and actual per-instance runtime ownership.",
        context_schema("InstanceRef", {{"library", reference_schema("LibraryRef")}, {"leaseId", id}, {"idempotencyKey", id}}, {"library"}), native, classified,
        "Actual source hash/revision and trusted-code authority bind private staged content to the native runtime; loaded lines, branches/errors/IP and owner identity are reread without claiming execution.",
        {"native_script_state", "native_script_control", "operation_reconcile"}, {"A-08", "A-44", "A-45", "A-48", "A-50"}, false, Executor::Engine, true);
    auto controlBase = context_schema("InstanceRef", {{"leaseId", id}, {"expectedRuntimeId", id}, {"expectedVersion", decimal}, {"idempotencyKey", id}});
    const auto run = extend_object_schema(controlBase, {{"action", {{"const", "run"}}}, {"line", bounded_integer_schema(1, 0xffffffff)}}, {"action"});
    const auto setIp = extend_object_schema(controlBase, {{"action", {{"const", "set_ip"}}}, {"line", bounded_integer_schema(1, 0xffffffff)}}, {"action", "line"});
    const auto other = extend_object_schema(std::move(controlBase), {{"action", enum_schema({"step", "abort", "unload"})}}, {"action"});
    add("native_script_control", "scripts", "Run/run-to-line, step, abort, unload or set IP on the actually owned native runtime with resolved effects and observed transitions.",
        {{"oneOf", Json::array({run, setIp, other})}}, native, classified,
        "Actual runtime revision/owner/state and effect/grant/lease preflight precede native control; observed runtime completion/termination determines outcome and abort never kills an unrelated target.",
        {"native_script_state", "job_get", "operation_reconcile"}, {"A-08", "A-44", "A-45", "A-48", "A-50"}, false, Executor::Engine, true);
    add("native_script_breakpoint", "scripts", "Compare the exact loaded revision and change an actual native script-line breakpoint under runtime ownership/effect checks.",
        context_schema("InstanceRef", {{"line", bounded_integer_schema(1, 0xffffffff)}, {"enabled", boolean}, {"expectedRevision", id}, {"leaseId", id}}, {"line", "enabled", "expectedRevision"}), native, classified,
        "Actual owned loaded revision/line and effective authority pass before breakpoint control; the native runtime breakpoint/enabled state is reread with its resulting version.",
        {"native_script_state", "operation_reconcile"}, {"A-08", "A-44", "A-45", "A-50"}, false, Executor::Engine, true);
    add("native_script_state", "scripts", "Read actual native script ownership, pinned source, runtime IP, paged lines/branches/breakpoints, status and errors.",
        with_page_schema(context_schema("InstanceRef")), native, {Effect::Inspect},
        "Actual owner/runtime state yields coherent line/branch/breakpoint/IP/error/version observations; unloaded and running states remain distinct and unavailable data is explicit.",
        {"scripts_read", "job_get", "native_script_state"}, {"A-44", "A-45", "A-50"}, true, Executor::Engine);
    const auto workflowContext = object({{"instanceId", id}, {"targetContext", targetContext}, {"leaseId", id}}, Json::array());
    add("workflows_run", "scripts", "Run an exact pinned declarative workflow with explicit context, parameters, bounded loops/waits and retained per-step failure policy.",
        lref({{"context", workflowContext}, {"parameters", provider_arguments_schema()}, {"limits", script_limits_schema()}, {"idempotencyKey", id}}, {"context"}), script_run_schema(), classified,
        "Actual authorized pinned workflow/dependencies execute typed steps under per-call context/grants/lease checks; declared rollback/independent continuation and observed step effects persist, without blind replay after crash.",
        {"job_get", "job_cancel", "operation_reconcile", "scripts_read"}, {"A-08", "A-09", "A-46", "A-48", "A-50"}, false, Executor::Broker, true);
}
}
