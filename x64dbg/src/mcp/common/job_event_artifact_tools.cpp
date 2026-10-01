#include "registry.h"
#include "inspection_types.h"
#include "job_event_artifact_types.h"
#include "library_script_types.h"
#include "provider_ui_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
void append_job_event_artifact_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto sha = string_schema("sha256", 64);
    const auto boolean = Json{{"type", "boolean"}};
    const auto text = string_schema("utf8-text", 4096, 0);
    const auto cursor = string_schema("utf8-text", 4096);
    const auto job = job_record_schema();
    const auto artifact = artifact_record_schema();
    const auto upload = artifact_upload_schema();
    const auto object = [&](Json properties, Json required) { return closed_object_schema(std::move(properties), std::move(required)); };
    const auto add = [&](std::string name, std::string domain, std::string description, Json input, Json output, std::vector<Effect> effects,
        std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance, bool idempotent, bool nativeEffects = false)
    {
        tools.push_back(define_tool(std::move(name), std::move(description), std::move(domain), std::move(input), std::move(output), std::move(effects),
            Executor::Broker, StateRequirement::Broker, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance),
            "planned:src/mcp/broker/main.cpp", idempotent, nativeEffects, nullptr, {}, nativeEffects));
    };
    add("jobs_list", "jobs", "List only authorized current/history jobs with durable identity/version, actual state, observed progress and last known outcome.",
        with_page_schema(object({{"state", job_state_schema()}, {"instanceId", id}}, Json::array())), paged_data_schema(job), {Effect::Inspect},
        "Credential/profile/namespace authority determines every returned job and referenced artifact; consistent bounded history pages preserve unknown/interrupted outcomes instead of inventing completion.",
        {"job_get", "operation_reconcile"}, {"A-08", "A-48", "A-50", "A-66"}, true);
    add("job_get", "jobs", "Read an authorized job's exact persisted version, steps, pending human/native interaction, effects, pinned references and verification.",
        context_schema("JobRef"), job, {Effect::Inspect},
        "Actual persisted journal and current observable owner state determine the returned job; possessing an ID cannot expose another client/profile's content and pending UAC remains human-controlled.",
        {"job_wait", "operation_reconcile"}, {"A-08", "A-09", "A-48", "A-50", "A-66"}, true);
    const auto waitFields = Json{{"afterVersion", decimal}, {"timeoutMs", bounded_integer_schema(1, 60000, 30000)}};
    add("job_wait", "jobs", "Wait at an authorized job version for a later state or a bounded timeout without holding scheduler locks or replaying work.",
        context_schema("JobRef", waitFields), object({{"job", job}, {"changed", boolean}, {"timedOut", boolean}}, {"job", "changed", "timedOut"}), {Effect::Inspect},
        "Version-aware registration cannot miss an intervening update; actual changed/final/pending state or timeout is returned within the bound, with client disconnect distinct from cancellation.",
        {"job_get", "operation_reconcile"}, {"A-09", "A-48", "A-49", "A-50"}, true);
    const std::vector<Effect> classified = {Effect::Inspect, Effect::Execute, Effect::Modify, Effect::FileExport, Effect::FileReplace, Effect::Elevate, Effect::Configure};
    add("job_cancel", "jobs", "Request cancellation of an actually owned job after resolving its native stop/rollback/consent authority; report observed termination or reconciliation.",
        context_schema("JobRef", {{"reason", text}, {"idempotencyKey", id}}),
        object({{"job", job}, {"requestAccepted", boolean}, {"terminationObserved", boolean}}, {"job", "requestAccepted", "terminationObserved"}), classified,
        "Future owned work stops and actual native/runtime cancellation is observed or remains cancelling/unknown; committed file effects require separate undo, late consent cannot authorize cancelled work, and unrelated processes remain untouched.",
        {"job_get", "job_wait", "operation_reconcile"}, {"A-08", "A-09", "A-45", "A-48", "A-50"}, false, true);
    const auto observation = object({{"kind", id}, {"context", nullable_schema(reference_schema("ResultContext"))}, {"source", text},
        {"state", enum_schema({"observed", "unavailable", "conflict", "unknown"})}, {"sha256", nullable_schema(sha)}, {"artifactId", nullable_schema(id)},
        {"data", provider_arguments_schema()}}, {"kind", "context", "source", "state", "sha256", "artifactId", "data"});
    add("operation_reconcile", "jobs", "Reconcile an authorized operation journal against actual target/file/runtime state after timeout, crash or disconnect without resuming a mutation.",
        object({{"operationId", id}}, {"operationId"}),
        object({{"operationId", id}, {"journalId", id}, {"version", decimal}, {"jobId", nullable_schema(id)},
            {"state", enum_schema({"pending", "reconciled", "partial", "unknown"})}, {"context", nullable_schema(reference_schema("ResultContext"))},
            {"effects", bounded_array_schema(reference_schema("EffectObservation"), MaximumPageLimit)}, {"observations", paged_data_schema(observation)},
            {"verification", reference_schema("Verification")}, {"recovery", bounded_array_schema(reference_schema("RecoveryRoute"), 16)},
            {"resumedMutation", {{"const", false}}}, {"complete", boolean}},
            {"operationId", "journalId", "version", "jobId", "state", "context", "effects", "observations", "verification", "recovery", "resumedMutation", "complete"}), {Effect::Inspect},
        "Actual journal/source/target-generation/current-file observations classify applied/restored/conflicting/unknown effects and safe follow-up; reconciliation never silently retries or resumes the original mutation.",
        {"job_get", "target_state", "file_inspect", "operation_reconcile"}, {"A-08", "A-35", "A-43", "A-48", "A-50", "A-66"}, true);
    add("events_read", "events", "Read ordered authorized instance/target metadata events after an opaque cursor with filters, bounded pages and explicit eviction gaps.",
        instance_or_target_forms(with_page_schema(object({{"afterCursor", cursor}, {"types", bounded_array_schema(id, 128, 0, true)}}, Json::array())).at("properties"), Json::array()),
        event_page_schema(), {Effect::Inspect},
        "Actual retained sequence/cursor identity yields coherent ordered events and continuation; evicted/stale boundaries return an explicit gap plus snapshot reconciliation instead of silently dropping matching events.",
        {"events_read", "target_snapshot", "operation_reconcile"}, {"A-08", "A-49", "A-50", "A-65", "A-66"}, true);
    auto eventWait = object({{"afterCursor", cursor}, {"filter", event_filter_schema()}, {"timeoutMs", bounded_integer_schema(1, 60000, 30000)}}, {"afterCursor", "filter"});
    add("events_wait", "events", "Wait after an authorized opaque instance/target cursor for a matching future event or a bounded timeout/gap.",
        instance_or_target_forms(eventWait.at("properties"), eventWait.at("required")),
        extend_object_schema(event_page_schema(), {{"matched", boolean}, {"timedOut", boolean}}, {"matched", "timedOut"}), {Effect::Inspect},
        "Atomic cursor/filter registration observes events arriving between run and wait; target generations, eviction, cancellation and timeout are explicit, and event callbacks never block on a slow waiter.",
        {"events_read", "target_snapshot", "operation_reconcile"}, {"A-08", "A-49", "A-50", "A-65"}, true);
    add("events_clear", "events", "Explicitly change authorized event retention before a cursor while preserving active wait boundaries, mutation journals and acceptance evidence.",
        context_schema("InstanceRef", {{"beforeCursor", cursor}}, {"beforeCursor"}),
        object({{"instanceId", id}, {"removedEvents", decimal}, {"oldestAvailableCursor", cursor}, {"version", decimal}, {"affectedWaits", decimal},
            {"journalsPreserved", {{"const", true}}}, {"retainedEvidencePreserved", {{"const", true}}}},
            {"instanceId", "removedEvents", "oldestAvailableCursor", "version", "affectedWaits", "journalsPreserved", "retainedEvidencePreserved"}), {Effect::Configure},
        "Actual eligible ring events are removed with precise new cursor/gap observations for waiters; operation journals, pinned content and retained acceptance evidence remain durable and independently readable.",
        {"events_read", "target_snapshot"}, {"A-08", "A-43", "A-48", "A-49", "A-66"}, false);
    add("artifacts_list", "artifacts", "List authorized immutable artifacts with actual hash/size/kind/provenance, job/evidence references and retention state.",
        with_page_schema(object({{"namespaceId", id}, {"kind", id}}, {"namespaceId"})), paged_data_schema(artifact), {Effect::Inspect},
        "Actual namespace grants and stable metadata version yield every matching published artifact exactly once; unpublished uploads and other clients' private content stay unavailable.",
        {"artifacts_read", "library_quota"}, {"A-08", "A-40", "A-41", "A-42", "A-43"}, true);
    add("artifacts_create", "artifacts", "Publish an immutable artifact from bounded inline UTF-8/hex or a hash-pinned authorized source artifact under namespace quota and ownership checks.",
        object({{"namespaceId", id}, {"name", string_schema("utf8-text", 4096)}, {"kind", id}, {"content", library_content_schema()}, {"idempotencyKey", id}}, {"namespaceId", "name", "kind", "content"}), artifact, {Effect::Configure},
        "Actual whole source bytes/hash pass ownership/size/quota checks and recoverable blob/metadata publication; only the durable reread verified object becomes a visible artifact.",
        {"artifacts_read", "library_quota", "operation_reconcile"}, {"A-40", "A-41", "A-42", "A-43"}, false);
    add("artifacts_upload_begin", "artifacts", "Reserve a bounded owned upload for declared exact size/hash/kind with expiry and retained namespace quota accounting.",
        object({{"namespaceId", id}, {"name", string_schema("utf8-text", 4096)}, {"size", decimal}, {"sha256", sha}, {"kind", id}, {"idempotencyKey", id}}, {"namespaceId", "name", "size", "sha256", "kind"}), upload, {Effect::Configure},
        "Actual owner/grants/configured artifact/profile quotas admit the reservation before allocation; private upload identity/expiry and maximum 1 MiB chunk size are observed, without premature publication.",
        {"library_quota", "artifacts_upload_chunk", "operation_reconcile"}, {"A-08", "A-41", "A-42", "A-43"}, false);
    add("artifacts_upload_chunk", "artifacts", "Accept one exact offset and lowercase hex byte chunk with its hash into the owned upload; identical retransmissions are idempotent.",
        object({{"uploadId", id}, {"offset", decimal}, {"bytes", string_schema("hex-bytes", 2097152)}, {"chunkSha256", sha}}, {"uploadId", "offset", "bytes", "chunkSha256"}),
        object({{"upload", upload}, {"acceptedOffset", decimal}, {"acceptedLength", bounded_integer_schema(1, 1048576)}, {"chunkSha256", sha}, {"retransmission", boolean}},
            {"upload", "acceptedOffset", "acceptedLength", "chunkSha256", "retransmission"}), {Effect::Configure},
        "Actual bytes/hash and checked offset arithmetic fit the owned unexpired reservation; exact previously accepted content retransmits safely, conflicting overlaps/gaps/size/hash errors do not publish a partial blob.",
        {"artifacts_upload_finish", "library_quota", "operation_reconcile"}, {"A-08", "A-41", "A-42", "A-43", "A-48"}, true);
    add("artifacts_upload_finish", "artifacts", "Verify complete owned upload coverage and the whole declared hash before durable immutable artifact publication.",
        object({{"uploadId", id}}, {"uploadId"}), artifact, {Effect::Configure},
        "Actual complete coverage/whole hash, owner/expiry/quota and recoverable blob transaction pass; durable artifact bytes/metadata are reread, and incomplete or mismatched content remains unpublished.",
        {"artifacts_read", "library_quota", "operation_reconcile"}, {"A-08", "A-41", "A-42", "A-43", "A-48"}, true);
    const auto bytes = Json{{"oneOf", Json::array({{{"const", ""}}, string_schema("hex-bytes", 2097152)})}};
    add("artifacts_read", "artifacts", "Read an exact authorized immutable artifact chunk with whole identity/provenance, offset/length, EOF and chunk hash.",
        object({{"artifactId", id}, {"offset", decimal}, {"length", bounded_integer_schema(1, 1048576, 65536)}}, {"artifactId"}),
        object({{"artifact", artifact}, {"offset", decimal}, {"length", bounded_integer_schema(0, 1048576)}, {"bytesHex", bytes}, {"chunkSha256", sha}, {"eof", boolean}},
            {"artifact", "offset", "length", "bytesHex", "chunkSha256", "eof"}), {Effect::Inspect},
        "Actual authorized published artifact bytes agree with immutable identity/offset/chunk hash; zero-byte EOF is explicit, and opaque/resource references never become arbitrary filesystem authority.",
        {"artifacts_list", "artifacts_read"}, {"A-08", "A-41", "A-42", "A-43"}, true);
    const auto deleted = object({{"artifactId", id}, {"sha256", sha}, {"status", enum_schema({"trashed", "retained", "conflict", "missing", "failed", "unknown"})},
        {"trashId", nullable_schema(id)}, {"referencedJobs", bounded_array_schema(id, MaximumPageLimit, 0, true)}, {"retainedEvidence", boolean}, {"error", nullable_schema(reference_schema("DomainError"))}},
        {"artifactId", "sha256", "status", "trashId", "referencedJobs", "retainedEvidence", "error"});
    add("artifacts_delete", "artifacts", "Compare corresponding immutable artifact IDs/hashes and move eligible owned metadata into recoverable trash, retaining active job/evidence dependencies.",
        object({{"artifactIds", bounded_array_schema(id, MaximumPageLimit, 1, true)}, {"expectedHashes", bounded_array_schema(sha, MaximumPageLimit, 1)}, {"idempotencyKey", id}}, {"artifactIds", "expectedHashes"}),
        object({{"items", bounded_array_schema(deleted, MaximumPageLimit)}, {"journalId", id}, {"complete", boolean}}, {"items", "journalId", "complete"}), {Effect::Configure},
        "Actual one-to-one expected hashes/ownership and reference preflight precede durable trash changes; pinned/evidence content remains valid and every conflict/partial/unknown outcome is retained without destructive garbage collection.",
        {"artifacts_list", "library_file_restore", "operation_reconcile"}, {"A-08", "A-40", "A-41", "A-43", "A-48"}, false);
    const auto scope = Json{{"oneOf", Json::array({object({{"kind", enum_schema({"broker", "profile"})}}, {"kind"}),
        object({{"kind", {{"const", "instance"}}}, {"instanceId", id}}, {"kind", "instanceId"}),
        object({{"kind", {{"const", "operation"}}}, {"operationId", id}}, {"kind", "operationId"})})}};
    const auto inventory = object({{"kind", id}, {"source", text}, {"sha256", sha}, {"size", decimal}, {"containsTargetContent", boolean}, {"redacted", boolean}},
        {"kind", "source", "sha256", "size", "containsTargetContent", "redacted"});
    add("diagnostics_export", "diagnostics", "Publish a redacted authorized diagnostic bundle with explicit source/content inventory and separately requested target content selection.",
        object({{"scope", scope}, {"namespaceId", id}, {"includeTargetContent", {{"type", "boolean"}, {"default", false}}}}, {"scope", "namespaceId", "includeTargetContent"}),
        object({{"artifact", artifact}, {"scope", scope}, {"includeTargetContent", boolean}, {"inventory", paged_data_schema(inventory)},
            {"credentialsRedacted", {{"const", true}}}, {"manifestSha256", sha}, {"complete", boolean}},
            {"artifact", "scope", "includeTargetContent", "inventory", "credentialsRedacted", "manifestSha256", "complete"}), {Effect::Inspect, Effect::FileExport},
        "Actual authorized scope/content selection yields an inventory/hash-verified durable bundle; credentials remain redacted and target bytes appear only with explicit corresponding grants/selection, with partial/unavailable sources recorded.",
        {"artifacts_read", "job_get", "operation_reconcile"}, {"A-08", "A-41", "A-42", "A-48", "A-66"}, false);
}
}
