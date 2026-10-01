#include "registry.h"
#include "inspection_types.h"
#include "provider_ui_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_provider_ui_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto text = string_schema("utf8-text", 4096, 0);
    const auto boolSchema = Json{{"type", "boolean"}};
    const auto arguments = provider_arguments_schema();
    const auto action = native_action_schema();
    const auto outcome = native_action_outcome_schema();
    const auto view = ui_view_schema();
    const auto dialog = ui_dialog_schema();
    const std::vector<Effect> classified = {Effect::Inspect, Effect::Execute, Effect::Modify, Effect::FileExport, Effect::FileReplace, Effect::Elevate, Effect::Configure};
    const auto invocation = [&](Json properties, Json required)
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        Json forms = Json::array();
        for(const auto* context : {"InstanceRef", "TargetRef", "PausedContext"})
            forms.push_back(with_deadline_schema(context_schema(context, properties, required)));
        return Json{{"oneOf", std::move(forms)}};
    };
    const auto guiInvocation = [&](Json properties, Json required)
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        return with_deadline_schema(context_schema("InstanceRef", std::move(properties), std::move(required)));
    };
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        Executor executor, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent, bool nativeEffects = false, std::vector<EffectCondition> conditions = {})
    {
        input["$defs"] = ui_value_definitions();
        output["$defs"] = ui_value_definitions();
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            executor, StateRequirement::InstanceReady, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance),
            "planned:" + source, idempotent, nativeEffects, nullptr, std::move(conditions), nativeEffects));
    };
    add("commands_list", "commands", "List actual native commands/aliases with provider/build identity, syntax, context/effects and completion requirements.",
        with_page_schema(context_schema("InstanceRef", {{"category", id}, {"provider", id}})), paged_data_schema(native_command_schema()), {Effect::Inspect}, Executor::Engine,
        "Actual command registrations and native classifications are enumerated completely with bounded pages; unknown/disabled providers remain explicit.",
        {"commands_describe", "plugins_actions"}, {"A-51", "A-52", "A-53"}, "src/dbg/command.cpp", true);
    add("commands_describe", "commands", "Read one actual command's native syntax/aliases/provider, argument schema, owner/context/effects and verification route.",
        context_schema("InstanceRef", {{"commandId", id}}, {"commandId"}), native_command_schema(), {Effect::Inspect}, Executor::Engine,
        "Descriptor belongs to the actual registered command/provider build; missing parser/classification/completion coverage disables unsafe invocation rather than guessing syntax or results.",
        {"commands_list", "plugins_actions"}, {"A-51", "A-52", "A-53"}, "src/dbg/command.cpp", true);
    add("commands_execute", "commands", "Dispatch an entire native command only after native parser/provider classification of every component, context, grant and lease; declared effects are potential effects.",
        invocation({{"command", string_schema("utf8-text", 32766)}}, {"command"}),
        closed_object_schema({{"commandId", id}, {"callbackResult", nullable_schema(boolSchema)}, {"queued", boolSchema}, {"output", string_schema("utf8-text", 65536, 0)},
            {"outputTruncated", boolSchema}, {"eventCursor", nullable_schema(string_schema("utf8-text", 4096))}, {"action", outcome}},
            {"commandId", "callbackResult", "queued", "output", "outputTruncated", "eventCursor", "action"}), classified, Executor::Engine,
        "Whole-line native classification precedes every effect; actual callback/output/events are captured, queued acceptance stays accepted, and unknown postconditions require unverified follow-up or reconciliation.",
        {"commands_describe", "target_state", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-51", "A-53"}, "src/dbg/command.cpp", false, true);
    const auto plugin = native_plugin_schema();
    add("plugins_list", "plugins", "Read loaded/available native plugins with actual binary/provider identity and explicit missing semantic routes.",
        with_page_schema(context_schema("InstanceRef")), paged_data_schema(plugin), {Effect::Inspect}, Executor::Engine,
        "Actual loaded module/plugin records and declared available images match architecture/build/hash observations; unavailable/opaque actions remain open gaps.",
        {"plugins_actions", "debugger_instances"}, {"A-19", "A-52"}, "src/dbg/plugin_loader.cpp", true);
    add("plugins_actions", "plugins", "List one exact native plugin's commands, menus, expression/script providers and declared schemas/context/effects.",
        with_page_schema(context_schema("InstanceRef", {{"pluginId", id}}, {"pluginId"})), paged_data_schema(action), {Effect::Inspect}, Executor::Engine,
        "Actual source/runtime registrations belong to the observed plugin build; all provider kinds are included and unresolved argument/effect/completion bindings stay explicitly unavailable.",
        {"plugins_list", "commands_describe", "ui_actions_list"}, {"A-51", "A-52"}, "src/dbg/plugin_loader.cpp", true);
    add("plugins_invoke", "plugins", "Invoke an exact native plugin action after provider/build argument, context, permission and lease resolution; caller arguments cannot authorize effects.",
        invocation({{"pluginId", id}, {"actionId", id}, {"arguments", arguments}}, {"pluginId", "actionId", "arguments"}), outcome, classified, Executor::Engine,
        "The actual provider action runs on its resolved native owner only after full preflight; provider-specific postconditions and observed effects determine completion, jobs or explicit uncertainty.",
        {"plugins_actions", "target_state", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-50", "A-52"}, "src/dbg/plugin_loader.cpp", false, true);
    add("plugins_load", "plugins", "Load an explicitly hash-pinned trusted native plugin with actual architecture/dependency/provider identity; opaque code needs native trusted-code preflight.",
        file_forms(guiInvocation({{"expectedSha256", string_schema("sha256", 64)}, {"targetContext", ui_context_schema()}}, {"expectedSha256"})), plugin, classified, Executor::Engine,
        "Trusted-code grant, actual source/dependency hashes, native loading policy and current target/lease constraints pass before loading; actual loaded image/capabilities are reread and partial registration is reconciled.",
        {"plugins_list", "plugins_actions", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-52"}, "src/dbg/plugin_loader.cpp", false, true);
    add("plugins_unload", "plugins", "Unload one compared-build native plugin only after classifying teardown, callbacks, outstanding jobs/handles and affected target authority.",
        guiInvocation({{"pluginId", id}, {"expectedBuildId", string_schema("sha256", 64)}, {"targetContext", ui_context_schema()}}, {"pluginId", "expectedBuildId"}), plugin, classified, Executor::Engine,
        "Actual matching plugin teardown completes or reports its native limitation; owned jobs/handles/callback registrations and remaining provider state are reconciled before claiming unload.",
        {"plugins_list", "plugins_actions", "operation_reconcile"}, {"A-48", "A-50", "A-52"}, "src/dbg/plugin_loader.cpp", false, true);
    add("ui_actions_list", "ui", "List actual semantic actions with language/theme-independent IDs, enabled reasons, native fields/schemas, executor and effects.",
        with_page_schema(context_schema("InstanceRef", {{"view", id}, {"context", ui_context_schema()}})), paged_data_schema(action), {Effect::Inspect}, Executor::Gui,
        "Source/runtime action bindings and current owner state determine actual availability and complete pages; opening an inaccessible dialog cannot close a semantic parity row.",
        {"ui_views_list", "ui_dialogs_list"}, {"A-19", "A-50", "A-51", "A-52"}, "src/gui/Src/Gui/MainWindow.cpp", true);
    add("ui_action_invoke", "ui", "Invoke a resolved semantic GUI action with explicit native context/arguments and compared UI version, including operation-owned pending dialogs/jobs.",
        guiInvocation({{"actionId", id}, {"context", ui_context_schema()}, {"arguments", arguments}, {"expectedUiVersion", decimal}}, {"actionId", "context", "arguments"}), outcome, classified, Executor::Gui,
        "Native action/context/field schema, effective grants/leases and UI version pass before owner dispatch; actual action postcondition or owned pending interaction is observed, with user interruption preserved.",
        {"ui_actions_list", "ui_dialog_read", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-50", "A-51"}, "src/gui/Src/Gui/MainWindow.cpp", false, true);
    add("ui_views_list", "ui", "List every actual native view, stable provider identity, visibility, version and supported structured data/actions.",
        with_page_schema(context_schema("InstanceRef")), paged_data_schema(view), {Effect::Inspect}, Executor::Gui,
        "Actual GUI/provider views are enumerated with current visibility/version and action/data schemas; lazy/disabled/shipped views and unresolved bindings stay visible.",
        {"ui_actions_list", "ui_view_read"}, {"A-19", "A-51", "A-52"}, "src/gui/Src/Gui/MainWindow.cpp", true);
    const auto cell = closed_object_schema({{"columnId", id}, {"value", nullable_schema(ui_value_schema())}, {"displayText", text},
        {"status", enum_schema({"valid", "unreadable", "unsupported", "unknown"})}, {"error", nullable_schema(reference_schema("DomainError"))}}, {"columnId", "value", "displayText", "status", "error"});
    const auto row = closed_object_schema({{"rowId", id}, {"parentRowId", nullable_schema(id)}, {"path", bounded_array_schema(id, 64)},
        {"cells", bounded_array_schema(cell, MaximumPageLimit)}, {"childIds", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"childPage", nullable_schema(reference_schema("ResultPagination"))}},
        {"rowId", "parentRowId", "path", "cells", "childIds", "childPage"});
    const auto column = closed_object_schema({{"columnId", id}, {"name", text}, {"valueSchema", nullable_schema(schema_document_schema())},
        {"visible", boolSchema}, {"order", bounded_integer_schema(0, 0xffffffff)}}, {"columnId", "name", "valueSchema", "visible", "order"});
    add("ui_view_read", "ui", "Read actual structured table/tree/text/byte/provider model data, exact typed values, row hierarchy and selection/version on the GUI owner.",
        with_page_schema(context_schema("InstanceRef", {{"viewId", id}, {"query", arguments}}, {"viewId"})),
        closed_object_schema({{"view", view}, {"columns", bounded_array_schema(column, MaximumPageLimit)}, {"rows", paged_data_schema(row)},
            {"selection", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"value", nullable_schema(ui_value_schema())}, {"complete", boolSchema}},
            {"view", "columns", "rows", "selection", "value", "complete"}), {Effect::Inspect}, Executor::Gui,
        "Pure provider query and actual owner model snapshots yield coherent versioned data; exact integer/floating bits and unreadable/unavailable values survive encoding, with bounded hierarchy/continuation rather than silent truncation.",
        {"ui_views_list", "ui_view_read", "target_snapshot"}, {"A-19", "A-51", "A-52"}, "src/gui/Src/BasicView/AbstractTableView.cpp", true);
    const auto location = Json{{"oneOf", Json::array({reference_schema("AddressRef"), closed_object_schema({{"rowId", id}}, {"rowId"}),
        closed_object_schema({{"textOffset", decimal}}, {"textOffset"}), closed_object_schema({{"artifactId", id}, {"offset", decimal}}, {"artifactId", "offset"}),
        closed_object_schema({{"providerLocation", arguments}}, {"providerLocation"})})}};
    add("ui_view_navigate", "ui", "Navigate/select an actual view location through its semantic native handler while preserving target/source identity and user changes.",
        context_schema("InstanceRef", {{"viewId", id}, {"location", location}, {"selection", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"context", ui_context_schema()}, {"idempotencyKey", id}}, {"viewId", "location"}), view,
        {Effect::Configure}, Executor::Gui, "Actual view location/selection and resulting version are reread; stale source/target or unavailable navigation rejects and manual user control remains usable.",
        {"ui_view_read", "ui_views_list"}, {"A-50", "A-51"}, "src/gui/Src/Gui/MainWindow.cpp", false);
    add("ui_view_configure", "ui", "Configure actual provider filter/sort/columns/layout under a compared model version and resolved native effects.",
        guiInvocation({{"viewId", id}, {"changes", arguments}, {"expectedVersion", decimal}}, {"viewId", "changes", "expectedVersion"}), view, classified, Executor::Gui,
        "Actual provider change schema and effective effects/context/grants pass before owner mutation; model/configuration/version are reread and provider side effects or pending persistence remain explicit.",
        {"ui_view_read", "ui_views_list", "operation_reconcile"}, {"A-48", "A-50", "A-51", "A-52"}, "src/gui/Src/BasicView/AbstractTableView.cpp", false, true);
    add("ui_dialogs_list", "ui", "List actual operation-owned native dialogs with field/control state, validation, versions and pending OS-consent classification.",
        with_page_schema(context_schema("InstanceRef")), paged_data_schema(dialog), {Effect::Inspect}, Executor::Gui,
        "Authorized actual dialog ownership and source bindings are observed; pending native fields and user-controlled OS consent remain distinct and inaccessible fields remain an open parity gap.",
        {"ui_dialog_read", "job_get"}, {"A-09", "A-48", "A-50", "A-51"}, "src/gui/Src/Gui/MainWindow.cpp", true);
    add("ui_dialog_read", "ui", "Read an exact operation-owned native dialog's values, schemas, validation/control state and version with bounded field pages.",
        with_page_schema(context_schema("InstanceRef", {{"dialogId", id}}, {"dialogId"})), dialog, {Effect::Inspect}, Executor::Gui,
        "Actual owner/operation/dialog identity and GUI-thread field values are observed; another client's dialogs and secret/OS-consent controls are not exposed or made writable.",
        {"ui_dialogs_list", "ui_dialog_read", "job_get"}, {"A-09", "A-48", "A-50", "A-51"}, "src/gui/Src/Bridge/Bridge.cpp", true);
    const auto fieldValue = closed_object_schema({{"fieldId", id}, {"value", ui_value_schema()}}, {"fieldId", "value"});
    add("ui_dialog_update", "ui", "Supply typed values to actual operation-owned native fields under a compared version and classified native field effects.",
        guiInvocation({{"dialogId", id}, {"values", bounded_array_schema(fieldValue, MaximumPageLimit, 1)}, {"expectedVersion", decimal}}, {"dialogId", "values", "expectedVersion"}), dialog, classified, Executor::Gui,
        "Native field schema/ownership/version and effective grants/leases pass before setters/signals; actual accepted values and validation are reread. User-controlled OS consent cannot be updated through this route.",
        {"ui_dialog_read", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-50", "A-51"}, "src/gui/Src/Bridge/Bridge.cpp", false, true);
    add("ui_dialog_submit", "ui", "Complete an exact operation-owned native dialog action with current version, resolved effects and actual accept/cancel/job outcome.",
        guiInvocation({{"dialogId", id}, {"action", id}, {"expectedVersion", decimal}}, {"dialogId", "action", "expectedVersion"}), outcome, classified, Executor::Gui,
        "Actual semantic action and final validation run under resolved native grants/leases; callback/effect/job outcome determines completion. OS consent stays pending until the human decision, never an agent-submitted approval.",
        {"ui_dialog_read", "job_get", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-50", "A-51"}, "src/gui/Src/Bridge/Bridge.cpp", false, true);
    auto clipboardInput = context_schema("InstanceRef", {{"source", ui_context_schema()}, {"format", id}}, {"source", "format", "destination"});
    const auto artifactInput = extend_object_schema(clipboardInput, {{"destination", {{"const", "artifact"}}}, {"namespaceId", id}}, Json::array());
    const auto clipboardDestination = extend_object_schema(std::move(clipboardInput), {{"destination", {{"const", "clipboard"}}}, {"expectedClipboardSequence", decimal}}, Json::array());
    add("ui_clipboard_export", "ui", "Export exact selected native view data to an owned artifact or explicitly update the user-visible OS clipboard with classified destination effects.",
        {{"oneOf", Json::array({artifactInput, clipboardDestination})}},
        closed_object_schema({{"destination", enum_schema({"artifact", "clipboard"})}, {"artifact", nullable_schema(managed_artifact_schema())}, {"clipboardSequence", nullable_schema(decimal)},
            {"sourceVersion", decimal}, {"format", id}, {"size", decimal}, {"sha256", string_schema("sha256", 64)}, {"complete", boolSchema}},
            {"destination", "artifact", "clipboardSequence", "sourceVersion", "format", "size", "sha256", "complete"}), {Effect::Inspect}, Executor::Gui,
        "Actual selected/source-version data determines exact exported bytes/hash; artifact publication is verified or explicit clipboard sequence/content is reread, with stale user changes and partial source coverage preserved.",
        {"ui_view_read", "artifacts_read", "operation_reconcile"}, {"A-40", "A-41", "A-48", "A-50", "A-51"}, "src/gui/Src/BasicView/AbstractTableView.cpp", true, false,
        {{"destination", "artifact", {Effect::FileExport}}, {"destination", "clipboard", {Effect::Configure}}});
    add("ui_capture", "ui", "Publish an optional actual native view image artifact with source/version and geometry; structured model data remains its independent semantic route.",
        context_schema("InstanceRef", {{"viewId", id}, {"namespaceId", id}}, {"namespaceId"}),
        closed_object_schema({{"artifact", managed_artifact_schema()}, {"viewId", nullable_schema(id)}, {"sourceVersion", decimal},
            {"width", bounded_integer_schema(1, 0xffffffff)}, {"height", bounded_integer_schema(1, 0xffffffff)}, {"devicePixelRatio", string_schema("utf8-text", 32)}, {"complete", boolSchema}},
            {"artifact", "viewId", "sourceVersion", "width", "height", "devicePixelRatio", "complete"}), {Effect::Inspect, Effect::FileExport}, Executor::Gui,
        "Actual authorized GUI pixels/geometry/version are captured and durably hash-verified; image capture supplements actual model/action evidence and cannot close inaccessible semantic operations.",
        {"ui_view_read", "artifacts_read"}, {"A-40", "A-41", "A-51"}, "src/gui/Src/Gui/MainWindow.cpp", true);
}
}
