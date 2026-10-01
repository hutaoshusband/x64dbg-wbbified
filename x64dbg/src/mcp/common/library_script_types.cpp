#include "library_script_types.h"
#include "lifecycle.h"
#include "schema_helpers.h"
#include "provider_ui_types.h"
#include <algorithm>
#include <string_view>

namespace wininspect::mcp
{
namespace
{
Json id() { return string_schema("opaque-id"); }
Json decimal() { return reference_schema("Decimal64"); }
Json sha() { return string_schema("sha256", 64); }
Json boolean() { return {{"type", "boolean"}}; }
Json text() { return string_schema("utf8-text", 4096, 0); }
Json empty_or_bytes(std::size_t maximum)
{
    return {{"oneOf", Json::array({{{"const", ""}}, string_schema("hex-bytes", maximum)})}};
}
}

bool safe_virtual_path(std::string_view value)
{
    const auto converted = launch_utf16(value);
    const auto* wide = std::get_if<std::wstring>(&converted);
    if(!wide || wide->empty() || wide->size() > 4096)
        return false;
    if(std::any_of(wide->begin(), wide->end(), [](wchar_t character)
    {
        return character < 32 || std::wstring_view(L"<>:\"\\|?*").find(character) != std::wstring_view::npos;
    }))
        return false;
    std::size_t start = 0;
    unsigned components = 0;
    while(start <= wide->size())
    {
        const auto separator = wide->find(L'/', start);
        const auto end = separator == std::wstring::npos ? wide->size() : separator;
        const auto component = std::wstring_view(*wide).substr(start, end - start);
        if(component.empty() || component.size() > 255 || component == L"." || component == L".." ||
            component.back() == L'.' || component.back() == L' ' || ++components > 64)
            return false;
        auto stem = component.substr(0, component.find(L'.'));
        while(!stem.empty() && stem.back() == L' ')
            stem.remove_suffix(1);
        std::wstring upper(stem);
        for(auto& character : upper)
            if(character >= L'a' && character <= L'z')
                character -= L'a' - L'A';
        if(upper == L"CON" || upper == L"PRN" || upper == L"AUX" || upper == L"NUL" || upper == L"CLOCK$" || upper == L"CONIN$" || upper == L"CONOUT$")
            return false;
        if(upper.size() == 4 && (upper.substr(0, 3) == L"COM" || upper.substr(0, 3) == L"LPT") &&
            ((upper[3] >= L'1' && upper[3] <= L'9') || upper[3] == L'\u00b9' || upper[3] == L'\u00b2' || upper[3] == L'\u00b3'))
            return false;
        if(separator == std::wstring::npos)
            return true;
        start = separator + 1;
    }
    return false;
}

Json virtual_path_schema()
{
    return string_schema("library-virtual-path", 4096);
}

Json script_source_schema()
{
    return {{"oneOf", Json::array({string_schema("utf8-text", 65536, 0),
        closed_object_schema({{"artifactId", id()}, {"sha256", sha()}}, {"artifactId", "sha256"})})}};
}

Json library_content_schema()
{
    return {{"oneOf", Json::array({
        closed_object_schema({{"encoding", {{"const", "utf8"}}}, {"text", string_schema("utf8-text", 65536, 0)}}, {"encoding", "text"}),
        closed_object_schema({{"encoding", {{"const", "hex"}}}, {"bytesHex", empty_or_bytes(131072)}}, {"encoding", "bytesHex"}),
        closed_object_schema({{"artifactId", id()}, {"sha256", sha()}}, {"artifactId", "sha256"})})}};
}

Json library_object_schema()
{
    return extend_object_schema(contract_schema("LibraryRef"), {{"virtualPath", virtual_path_schema()}, {"kind", id()}, {"mediaType", text()},
        {"size", decimal()}, {"sha256", sha()}, {"createdAtUtc", string_schema("utf8-text", 64)}, {"metadataVersion", decimal()},
        {"tags", bounded_array_schema(string_schema("utf8-text", 256), 128, 0, true)}, {"pinnedReferences", decimal()}, {"trashed", boolean()}},
        {"virtualPath", "kind", "mediaType", "size", "sha256", "createdAtUtc", "metadataVersion", "tags", "pinnedReferences", "trashed"});
}

Json library_trash_schema()
{
    return closed_object_schema({{"trashId", id()}, {"object", library_object_schema()}, {"deletedAtUtc", string_schema("utf8-text", 64)},
        {"recoverable", boolean()}, {"retainedRevision", reference_schema("LibraryRef")}}, {"trashId", "object", "deletedAtUtc", "recoverable", "retainedRevision"});
}

Json library_chunk_schema()
{
    return closed_object_schema({{"object", library_object_schema()}, {"offset", decimal()}, {"length", bounded_integer_schema(0, 1048576)},
        {"bytesHex", empty_or_bytes(2097152)}, {"chunkSha256", sha()}, {"eof", boolean()}}, {"object", "offset", "length", "bytesHex", "chunkSha256", "eof"});
}

Json library_quota_schema()
{
    return closed_object_schema({{"namespaceId", id()}, {"usedBytes", decimal()}, {"reservedBytes", decimal()}, {"retainedBytes", decimal()},
        {"pinnedBytes", decimal()}, {"namespaceLimit", decimal()}, {"profileUsedBytes", decimal()}, {"profileLimit", decimal()},
        {"scriptSourceLimit", decimal()}, {"artifactLimit", decimal()}, {"chunkLimit", bounded_integer_schema(1, 1048576)},
        {"cleanupCandidates", bounded_array_schema(reference_schema("LibraryRef"), MaximumPageLimit)}, {"complete", boolean()}},
        {"namespaceId", "usedBytes", "reservedBytes", "retainedBytes", "pinnedBytes", "namespaceLimit", "profileUsedBytes", "profileLimit", "scriptSourceLimit", "artifactLimit", "chunkLimit", "cleanupCandidates", "complete"});
}

Json script_limits_schema()
{
    return closed_object_schema({{"memoryBytes", bounded_integer_schema(1, 67108864, 67108864)}, {"cpuMs", bounded_integer_schema(1, 30000, 30000)},
        {"wallMs", bounded_integer_schema(1, 300000, 300000)}, {"hostCalls", bounded_integer_schema(1, 10000, 10000)},
        {"logBytes", bounded_integer_schema(1, 8388608, 8388608)}, {"steps", bounded_integer_schema(1, 100000, 10000)},
        {"loopIterations", bounded_integer_schema(1, 100000, 10000)}, {"waitMs", bounded_integer_schema(1, 60000, 30000)}}, Json::array());
}

Json script_manifest_schema()
{
    const auto module = closed_object_schema({{"name", text()}, {"sha256", nullable_schema(sha())}}, {"name", "sha256"});
    const auto requirements = closed_object_schema({{"architecture", enum_schema({"any", "x32", "x64"})},
        {"context", enum_schema({"none", "instance", "target", "paused", "thread_paused"})},
        {"modules", bounded_array_schema(module, MaximumPageLimit)}, {"features", bounded_array_schema(id(), 128, 0, true)}}, {"architecture", "context", "modules", "features"});
    const auto api = closed_object_schema({{"apiId", id()}, {"version", id()}}, {"apiId", "version"});
    return closed_object_schema({{"manifestVersion", {{"const", "1"}}}, {"apiRequirements", bounded_array_schema(api, 128, 0, true)},
        {"dependencies", bounded_array_schema(reference_schema("LibraryRef"), MaximumPageLimit, 0, true)}, {"targetRequirements", requirements},
        {"effects", effect_list_schema()}, {"parametersSchema", schema_document_schema()}, {"limits", script_limits_schema()},
        {"failurePolicy", enum_schema({"stop", "declared_rollback", "independent_continuation"})}, {"tags", bounded_array_schema(string_schema("utf8-text", 256), 128, 0, true)}},
        {"manifestVersion", "apiRequirements", "dependencies", "targetRequirements", "effects", "parametersSchema", "limits", "failurePolicy", "tags"});
}

Json script_diagnostics_schema()
{
    const auto diagnostic = closed_object_schema({{"severity", enum_schema({"info", "warning", "error"})}, {"code", id()}, {"message", text()},
        {"line", nullable_schema(bounded_integer_schema(1, 0xffffffff))}, {"column", nullable_schema(bounded_integer_schema(1, 0xffffffff))},
        {"stepId", nullable_schema(id())}}, {"severity", "code", "message", "line", "column", "stepId"});
    return paged_data_schema(diagnostic);
}

Json script_revision_schema()
{
    return closed_object_schema({{"object", library_object_schema()}, {"scriptId", id()}, {"name", virtual_path_schema()}, {"engine", string_schema("utf8-text", 256)},
        {"engineBuildId", nullable_schema(sha())}, {"apiVersion", id()}, {"manifest", script_manifest_schema()},
        {"previousRevision", nullable_schema(id())}, {"diagnostics", script_diagnostics_schema()}, {"validationStatus", enum_schema({"valid", "invalid", "unvalidated", "unsupported", "unknown"})},
        {"trustedCode", boolean()}, {"complete", boolean()}},
        {"object", "scriptId", "name", "engine", "engineBuildId", "apiVersion", "manifest", "previousRevision", "diagnostics", "validationStatus", "trustedCode", "complete"});
}

Json script_validation_schema()
{
    return closed_object_schema({{"revision", reference_schema("LibraryRef")}, {"engine", string_schema("utf8-text", 256)}, {"engineBuildId", nullable_schema(sha())},
        {"status", enum_schema({"valid", "invalid", "unsupported", "unknown"})}, {"diagnostics", script_diagnostics_schema()},
        {"dependencies", bounded_array_schema(reference_schema("LibraryRef"), MaximumPageLimit)}, {"resolvedEffects", effect_list_schema()},
        {"classification", enum_schema({"known", "unknown"})}, {"limits", script_limits_schema()}, {"executed", {{"const", false}}}, {"complete", boolean()}},
        {"revision", "engine", "engineBuildId", "status", "diagnostics", "dependencies", "resolvedEffects", "classification", "limits", "executed", "complete"});
}

Json script_run_schema()
{
    const auto step = closed_object_schema({{"stepId", id()}, {"capabilityId", id()}, {"operationId", nullable_schema(id())},
        {"state", enum_schema({"pending", "running", "completed", "failed", "cancelled", "unknown", "rolled_back", "skipped"})},
        {"resultArtifactId", nullable_schema(id())}, {"error", nullable_schema(reference_schema("DomainError"))}, {"verification", reference_schema("Verification")}},
        {"stepId", "capabilityId", "operationId", "state", "resultArtifactId", "error", "verification"});
    return closed_object_schema({{"jobId", id()}, {"revision", reference_schema("LibraryRef")}, {"engine", string_schema("utf8-text", 256)},
        {"state", enum_schema({"queued", "running", "waiting_for_debugger", "waiting_for_event", "awaiting_user_consent", "cancelling", "completed", "cancelled", "failed", "interrupted_by_user", "unknown"})},
        {"context", nullable_schema(reference_schema("ResultContext"))}, {"steps", paged_data_schema(step)},
        {"artifacts", bounded_array_schema(id(), MaximumPageLimit, 0, true)}, {"logsArtifactId", nullable_schema(id())},
        {"verification", reference_schema("Verification")}, {"complete", boolean()}},
        {"jobId", "revision", "engine", "state", "context", "steps", "artifacts", "logsArtifactId", "verification", "complete"});
}

Json native_script_state_schema()
{
    const auto line = closed_object_schema({{"line", bounded_integer_schema(1, 0xffffffff)}, {"text", string_schema("utf8-text", 65536, 0)},
        {"kind", enum_schema({"command", "branch", "label", "comment", "empty", "unknown"})}, {"branchTarget", nullable_schema(bounded_integer_schema(1, 0xffffffff))},
        {"breakpoint", boolean()}, {"enabled", boolean()}, {"error", nullable_schema(text())}}, {"line", "text", "kind", "branchTarget", "breakpoint", "enabled", "error"});
    return closed_object_schema({{"instanceId", id()}, {"ownerClientId", nullable_schema(id())}, {"runtimeId", nullable_schema(id())},
        {"revision", nullable_schema(reference_schema("LibraryRef"))}, {"version", decimal()},
        {"state", enum_schema({"unloaded", "loading", "ready", "running", "paused", "aborting", "completed", "failed", "unknown"})},
        {"ipLine", nullable_schema(bounded_integer_schema(1, 0xffffffff))}, {"lineCount", decimal()}, {"lines", paged_data_schema(line)},
        {"error", nullable_schema(reference_schema("DomainError"))}, {"jobId", nullable_schema(id())}, {"trustedCode", {{"const", true}}},
        {"complete", boolean()}}, {"instanceId", "ownerClientId", "runtimeId", "revision", "version", "state", "ipLine", "lineCount", "lines", "error", "jobId", "trustedCode", "complete"});
}
}
