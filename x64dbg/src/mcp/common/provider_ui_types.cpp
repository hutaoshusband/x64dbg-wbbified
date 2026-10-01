#include "provider_ui_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json id() { return string_schema("opaque-id"); }
Json decimal() { return reference_schema("Decimal64"); }
Json text() { return string_schema("utf8-text", 4096, 0); }
Json bool_schema() { return {{"type", "boolean"}}; }
}

Json schema_document_schema()
{
    return {{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}};
}

Json provider_arguments_schema()
{
    return {{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}};
}

Json ui_value_schema()
{
    return reference_schema("UiValue");
}

Json ui_value_definitions()
{
    const auto value = reference_schema("UiValue");
    const auto member = closed_object_schema({{"name", string_schema("utf8-text", 4096, 0)}, {"value", value}}, {"name", "value"});
    Json choices = Json::array({closed_object_schema({{"kind", {{"const", "null"}}}}, {"kind"}),
        closed_object_schema({{"kind", {{"const", "boolean"}}}, {"value", bool_schema()}}, {"kind", "value"}),
        closed_object_schema({{"kind", {{"const", "integer"}}}, {"bitsHex", reference_schema("Hex64")}, {"widthBits", bounded_integer_schema(1, 64)}, {"signed", bool_schema()}}, {"kind", "bitsHex", "widthBits", "signed"}),
        closed_object_schema({{"kind", {{"const", "text"}}}, {"text", string_schema("utf8-text", 65536, 0)}}, {"kind", "text"}),
        closed_object_schema({{"kind", {{"const", "bytes"}}}, {"bytesHex", {{"oneOf", Json::array({{{"const", ""}}, string_schema("hex-bytes", 131072)})}}}}, {"kind", "bytesHex"}),
        closed_object_schema({{"kind", {{"const", "address"}}}, {"addressHex", reference_schema("Hex64")}}, {"kind", "addressHex"}),
        closed_object_schema({{"kind", {{"const", "array"}}}, {"items", bounded_array_schema(value, MaximumPageLimit)}}, {"kind", "items"}),
        closed_object_schema({{"kind", {{"const", "object"}}}, {"members", bounded_array_schema(member, MaximumPageLimit)}}, {"kind", "members"})});
    for(const auto width : {32, 64})
        choices.push_back(closed_object_schema({{"kind", {{"const", "float"}}}, {"widthBits", {{"const", width}}},
            {"bytesHex", string_schema("hex-bytes", width / 4, width / 4)}}, {"kind", "widthBits", "bytesHex"}));
    return {{"UiValue", {{"oneOf", std::move(choices)}}}};
}

Json ui_context_schema()
{
    const auto target = Json{{"oneOf", Json::array({reference_schema("TargetRef"), reference_schema("PausedContext")})}};
    return closed_object_schema({{"viewId", id()}, {"target", target}, {"address", reference_schema("AddressRef")},
        {"selection", bounded_array_schema(id(), MaximumPageLimit, 0, true)}, {"threadId", bounded_integer_schema(1, 0xffffffff)},
        {"sourceVersion", decimal()}, {"attributes", provider_arguments_schema()}}, Json::array());
}

Json native_action_schema()
{
    return closed_object_schema({{"actionId", id()}, {"providerId", id()}, {"providerBuildId", nullable_schema(string_schema("sha256", 64))},
        {"name", text()}, {"kind", enum_schema({"command", "menu", "expression", "script", "setting", "dialog", "view", "unknown"})},
        {"aliases", bounded_array_schema(string_schema("utf8-text", 1024), 128, 0, true)}, {"syntax", string_schema("utf8-text", 8192, 0)},
        {"argumentsSchema", nullable_schema(schema_document_schema())}, {"resultSchema", nullable_schema(schema_document_schema())},
        {"contextRequirement", enum_schema({"instance", "target", "paused", "thread_paused", "dynamic"})},
        {"executor", enum_schema({"broker", "engine", "gui", "script_host"})}, {"effects", effect_list_schema()},
        {"classification", enum_schema({"known", "unknown"})}, {"leaseRequired", bool_schema()}, {"privilege", enum_schema({"user", "administrator", "either", "unknown"})},
        {"enabled", bool_schema()}, {"disabledReason", nullable_schema(text())}, {"completionPredicate", nullable_schema(text())},
        {"recovery", bounded_array_schema(id(), 16)}},
        {"actionId", "providerId", "providerBuildId", "name", "kind", "aliases", "syntax", "argumentsSchema", "resultSchema", "contextRequirement", "executor", "effects",
            "classification", "leaseRequired", "privilege", "enabled", "disabledReason", "completionPredicate", "recovery"});
}

Json native_action_outcome_schema()
{
    return closed_object_schema({{"actionId", id()}, {"providerId", id()}, {"providerBuildId", nullable_schema(string_schema("sha256", 64))},
        {"operationId", id()}, {"jobId", nullable_schema(id())}, {"dialogId", nullable_schema(id())},
        {"state", enum_schema({"queued", "running", "pending_input", "completed", "cancelled", "failed", "unknown"})},
        {"result", nullable_schema(ui_value_schema())}, {"effects", bounded_array_schema(reference_schema("EffectObservation"), MaximumPageLimit)},
        {"verification", reference_schema("Verification")}, {"complete", bool_schema()}},
        {"actionId", "providerId", "providerBuildId", "operationId", "jobId", "dialogId", "state", "result", "effects", "verification", "complete"});
}

Json native_command_schema()
{
    return extend_object_schema(native_action_schema(), {{"commandId", id()}, {"category", id()}}, {"commandId", "category"});
}

Json native_plugin_schema()
{
    return closed_object_schema({{"pluginId", id()}, {"providerBuildId", nullable_schema(string_schema("sha256", 64))}, {"name", text()},
        {"image", nullable_schema(reference_schema("FileRef"))}, {"sha256", nullable_schema(string_schema("sha256", 64))},
        {"architecture", enum_schema({"x32", "x64", "unknown"})}, {"version", nullable_schema(text())}, {"sdkVersion", nullable_schema(bounded_integer_schema(0, 0xffffffff))},
        {"loaded", bool_schema()}, {"available", bool_schema()}, {"trustedCodeRequired", {{"const", true}}}, {"actionsCount", decimal()},
        {"missingRoutes", bounded_array_schema(id(), MaximumPageLimit)}, {"limitations", bounded_array_schema(reference_schema("DomainError"), 32)}},
        {"pluginId", "providerBuildId", "name", "image", "sha256", "architecture", "version", "sdkVersion", "loaded", "available", "trustedCodeRequired", "actionsCount", "missingRoutes", "limitations"});
}

Json ui_view_schema()
{
    return closed_object_schema({{"instanceId", id()}, {"viewId", id()}, {"providerId", id()}, {"name", text()}, {"kind", id()},
        {"visible", bool_schema()}, {"enabled", bool_schema()}, {"disabledReason", nullable_schema(text())}, {"version", decimal()},
        {"target", nullable_schema(reference_schema("TargetRef"))}, {"querySchema", nullable_schema(schema_document_schema())},
        {"configurationSchema", nullable_schema(schema_document_schema())}, {"actions", paged_data_schema(native_action_schema())}, {"complete", bool_schema()}},
        {"instanceId", "viewId", "providerId", "name", "kind", "visible", "enabled", "disabledReason", "version", "target", "querySchema", "configurationSchema", "actions", "complete"});
}

Json ui_dialog_schema()
{
    const auto validation = closed_object_schema({{"fieldId", nullable_schema(id())}, {"code", id()}, {"message", text()}}, {"fieldId", "code", "message"});
    const auto field = closed_object_schema({{"fieldId", id()}, {"name", text()}, {"controlKind", id()}, {"value", nullable_schema(ui_value_schema())},
        {"valueSchema", nullable_schema(schema_document_schema())}, {"enabled", bool_schema()}, {"visible", bool_schema()}, {"writable", bool_schema()},
        {"validation", bounded_array_schema(validation, 32)}}, {"fieldId", "name", "controlKind", "value", "valueSchema", "enabled", "visible", "writable", "validation"});
    return closed_object_schema({{"instanceId", id()}, {"dialogId", id()}, {"operationId", id()}, {"ownerClientId", id()}, {"providerId", id()},
        {"version", decimal()}, {"state", enum_schema({"open", "validating", "pending_consent", "submitted", "cancelled", "closed", "failed", "unknown"})},
        {"interaction", enum_schema({"native_fields", "os_consent"})}, {"title", text()}, {"fields", paged_data_schema(field)},
        {"actions", bounded_array_schema(native_action_schema(), 64)}, {"validation", bounded_array_schema(validation, 32)}, {"complete", bool_schema()}},
        {"instanceId", "dialogId", "operationId", "ownerClientId", "providerId", "version", "state", "interaction", "title", "fields", "actions", "validation", "complete"});
}
}
