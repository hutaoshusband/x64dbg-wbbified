#include "job_event_artifact_types.h"
#include "inspection_types.h"
#include "provider_ui_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json id() { return string_schema("opaque-id"); }
Json decimal() { return reference_schema("Decimal64"); }
Json boolean() { return {{"type", "boolean"}}; }
Json text() { return string_schema("utf8-text", 4096, 0); }
Json cursor() { return string_schema("utf8-text", 4096); }
}

Json job_record_schema()
{
    const auto progress = closed_object_schema({{"phase", id()}, {"completed", decimal()}, {"total", nullable_schema(decimal())}, {"description", text()}}, {"phase", "completed", "total", "description"});
    auto interactionBase = closed_object_schema({{"kind", enum_schema({"gui_dialog", "debugger", "event"})},
        {"instanceId", nullable_schema(id())}, {"dialogId", nullable_schema(id())}, {"description", text()}, {"userControlled", boolean()}},
        {"kind", "instanceId", "dialogId", "description", "userControlled"});
    auto consent = interactionBase;
    consent["properties"]["kind"] = {{"const", "os_consent"}};
    consent["properties"]["userControlled"] = {{"const", true}};
    const auto interaction = Json{{"oneOf", Json::array({std::move(interactionBase), std::move(consent)})}};
    const auto step = closed_object_schema({{"stepId", id()}, {"capabilityId", id()}, {"operationId", nullable_schema(id())},
        {"state", enum_schema({"pending", "running", "completed", "failed", "cancelled", "unknown", "rolled_back", "skipped"})},
        {"verification", reference_schema("Verification")}, {"error", nullable_schema(reference_schema("DomainError"))}, {"resultArtifactId", nullable_schema(id())}},
        {"stepId", "capabilityId", "operationId", "state", "verification", "error", "resultArtifactId"});
    const auto result = closed_object_schema({{"outcome", enum_schema({"completed", "accepted", "partial_failure", "cancelled", "failed", "unknown"})},
        {"dataArtifactId", nullable_schema(id())}, {"error", nullable_schema(reference_schema("DomainError"))}}, {"outcome", "dataArtifactId", "error"});
    return closed_object_schema({{"jobId", id()}, {"operationId", id()}, {"ownerClientId", id()}, {"profileId", id()}, {"capabilityId", id()},
        {"version", decimal()}, {"state", job_state_schema()}, {"context", nullable_schema(reference_schema("ResultContext"))},
        {"createdUtcMs", decimal()}, {"updatedUtcMs", decimal()}, {"deadlineUtcMs", nullable_schema(decimal())}, {"startingEventCursor", nullable_schema(cursor())},
        {"progress", progress}, {"steps", paged_data_schema(step)}, {"pendingInteraction", nullable_schema(interaction)}, {"result", nullable_schema(result)},
        {"effects", bounded_array_schema(reference_schema("EffectObservation"), MaximumPageLimit)}, {"verification", reference_schema("Verification")},
        {"pinnedRevisions", bounded_array_schema(reference_schema("LibraryRef"), MaximumPageLimit, 0, true)}, {"artifactIds", bounded_array_schema(id(), MaximumPageLimit, 0, true)},
        {"cancellationRequested", boolean()}, {"reconciliationRequired", boolean()}, {"complete", boolean()}},
        {"jobId", "operationId", "ownerClientId", "profileId", "capabilityId", "version", "state", "context", "createdUtcMs", "updatedUtcMs", "deadlineUtcMs", "startingEventCursor",
            "progress", "steps", "pendingInteraction", "result", "effects", "verification", "pinnedRevisions", "artifactIds", "cancellationRequested", "reconciliationRequired", "complete"});
}

Json event_filter_schema()
{
    return closed_object_schema({{"types", bounded_array_schema(id(), 128, 0, true)}, {"operationId", id()}, {"threadId", bounded_integer_schema(1, 0xffffffff)},
        {"moduleId", id()}, {"jobId", id()}}, Json::array());
}

Json event_record_schema()
{
    return closed_object_schema({{"cursor", cursor()}, {"sequence", decimal()}, {"utcMs", decimal()}, {"instanceId", id()},
        {"target", nullable_schema(reference_schema("TargetRef"))}, {"sourceThreadId", nullable_schema(bounded_integer_schema(1, 0xffffffff))},
        {"type", id()}, {"providerId", id()}, {"operationId", nullable_schema(id())}, {"jobId", nullable_schema(id())},
        {"payload", provider_arguments_schema()}, {"artifactId", nullable_schema(id())}},
        {"cursor", "sequence", "utcMs", "instanceId", "target", "sourceThreadId", "type", "providerId", "operationId", "jobId", "payload", "artifactId"});
}

Json event_page_schema()
{
    const auto gap = closed_object_schema({{"requestedCursor", cursor()}, {"oldestAvailableCursor", cursor()}, {"missingFromSequence", nullable_schema(decimal())},
        {"missingThroughSequence", nullable_schema(decimal())}, {"snapshotRoute", reference_schema("RecoveryRoute")}},
        {"requestedCursor", "oldestAvailableCursor", "missingFromSequence", "missingThroughSequence", "snapshotRoute"});
    return closed_object_schema({{"items", bounded_array_schema(event_record_schema(), MaximumPageLimit)}, {"nextCursor", cursor()},
        {"snapshotVersion", decimal()}, {"gap", nullable_schema(gap)}, {"complete", boolean()}}, {"items", "nextCursor", "snapshotVersion", "gap", "complete"});
}

Json artifact_record_schema()
{
    const auto provenance = closed_object_schema({{"operationId", nullable_schema(id())}, {"jobId", nullable_schema(id())},
        {"context", nullable_schema(reference_schema("ResultContext"))}, {"sourceArtifactIds", bounded_array_schema(id(), MaximumPageLimit, 0, true)}},
        {"operationId", "jobId", "context", "sourceArtifactIds"});
    return extend_object_schema(managed_artifact_schema(), {{"name", string_schema("utf8-text", 4096)}, {"kind", id()}, {"ownerClientId", id()},
        {"createdUtcMs", decimal()}, {"metadataVersion", decimal()}, {"provenance", provenance}, {"referencedJobs", bounded_array_schema(id(), MaximumPageLimit, 0, true)},
        {"retainedEvidence", boolean()}, {"trashed", boolean()}},
        {"name", "kind", "ownerClientId", "createdUtcMs", "metadataVersion", "provenance", "referencedJobs", "retainedEvidence", "trashed"});
}

Json artifact_upload_schema()
{
    const auto range = closed_object_schema({{"offset", decimal()}, {"length", bounded_integer_schema(1, 1048576)}, {"chunkSha256", string_schema("sha256", 64)}}, {"offset", "length", "chunkSha256"});
    return closed_object_schema({{"uploadId", id()}, {"namespaceId", id()}, {"ownerClientId", id()}, {"name", string_schema("utf8-text", 4096)}, {"kind", id()},
        {"size", decimal()}, {"sha256", string_schema("sha256", 64)}, {"receivedBytes", decimal()}, {"version", decimal()}, {"expiresUtcMs", decimal()},
        {"state", enum_schema({"allocated", "receiving", "verifying", "published", "expired", "cancelled", "failed", "unknown"})},
        {"chunkLimit", bounded_integer_schema(1, 1048576)}, {"ranges", paged_data_schema(range)}, {"artifactId", nullable_schema(id())}, {"complete", boolean()}},
        {"uploadId", "namespaceId", "ownerClientId", "name", "kind", "size", "sha256", "receivedBytes", "version", "expiresUtcMs", "state", "chunkLimit", "ranges", "artifactId", "complete"});
}
}
