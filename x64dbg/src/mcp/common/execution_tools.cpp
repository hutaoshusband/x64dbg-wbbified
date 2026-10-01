#include "registry.h"
#include "inspection_types.h"
#include "schema_helpers.h"
#include <limits>

namespace wininspect::mcp
{
void append_execution_tools(std::vector<ToolDefinition>& tools)
{
    const auto id = string_schema("opaque-id");
    const auto decimal = reference_schema("Decimal64");
    const auto hex = reference_schema("Hex64");
    const auto threadId = bounded_integer_schema(1, std::numeric_limits<std::uint32_t>::max());
    const auto count = bounded_integer_schema(1, 1000000, 1);
    const auto exceptionMode = enum_schema({"configured", "skip", "debugger", "debuggee"});
    const auto observation = execution_observation_schema();
    const auto mutate = [&](Json properties = Json::object(), Json required = Json::array())
    {
        properties["leaseId"] = id;
        properties["idempotencyKey"] = id;
        required.push_back("leaseId");
        return context_schema("TargetRef", std::move(properties), std::move(required));
    };
    const auto thread = closed_object_schema({{"threadId", threadId}, {"creationIdentity", nullable_schema(decimal)},
        {"name", nullable_schema(string_schema("utf8-text", 1024))}, {"state", enum_schema({"running", "paused", "suspended", "exited", "unknown"})},
        {"suspendCount", nullable_schema(bounded_integer_schema(0, std::numeric_limits<std::uint32_t>::max()))},
        {"selected", {{"type", "boolean"}}}, {"ipHex", nullable_schema(hex)}, {"tebHex", nullable_schema(hex)}},
        {"threadId", "creationIdentity", "name", "state", "suspendCount", "selected", "ipHex", "tebHex"});
    const auto suspension = closed_object_schema({{"target", reference_schema("TargetRef")}, {"thread", thread},
        {"previousCount", nullable_schema(decimal)}, {"observedCount", nullable_schema(decimal)}, {"ownedSuspend", nullable_schema(id)},
        {"ownershipReleased", {{"type", "boolean"}}}}, {"target", "thread", "previousCount", "observedCount", "ownedSuspend", "ownershipReleased"});
    auto code = contract_schema("Hex64");
    code["maxLength"] = 10;
    const auto rule = closed_object_schema({{"range", closed_object_schema({{"firstHex", code}, {"lastHex", code}}, {"firstHex", "lastHex"})},
        {"breakOn", enum_schema({"first_chance", "second_chance", "never"})}, {"log", {{"type", "boolean"}}},
        {"handledBy", enum_schema({"debugger", "debuggee"})}}, {"range", "breakOn", "log", "handledBy"});
    const auto policy = closed_object_schema({{"instanceId", id}, {"version", decimal}, {"rules", bounded_array_schema(rule, MaximumPageLimit)},
        {"complete", {{"type", "boolean"}}}}, {"instanceId", "version", "rules", "complete"});
    const auto add = [&](std::string name, std::string description, Json input, Json output, std::vector<Effect> effects,
        StateRequirement state, std::string completion, std::vector<std::string> recovery, std::vector<std::string> acceptance,
        std::string source, bool idempotent)
    {
        const auto domain = name.compare(0, 10, "execution_") == 0 ? "execution" : name.compare(0, 8, "threads_") == 0 ? "threads" : "exceptions";
        tools.push_back(define_tool(std::move(name), std::move(description), domain, std::move(input), std::move(output), std::move(effects),
            Executor::Engine, state, ArchitectureRequirement::Any, std::move(completion), std::move(recovery), std::move(acceptance),
            "planned:" + source, idempotent, false));
    };
    add("execution_resume", "Resume the matching paused thread context under an explicit exception mode and optional new-event wait condition.",
        with_deadline_schema(context_schema("MutationContext", {{"exceptionMode", exceptionMode}, {"waitCondition", event_condition_schema()}}, Json::array(), true)), observation,
        {Effect::Execute}, StateRequirement::TargetPaused, "Actual resume is observed; a requested wait completes only on its matching newer event, otherwise the retained job/state explains interruption or deadline.",
        {"execution_wait", "target_state", "operation_reconcile"}, {"A-24", "A-48", "A-50"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("execution_pause", "Request pause of the identified running target without requiring a stale paused context.", mutate(), observation,
        {Effect::Execute}, StateRequirement::TargetPresent, "A new actual pause epoch/stop event is observed, or exit before pause is reported distinctly.",
        {"target_state", "operation_reconcile"}, {"A-24", "A-48", "A-50"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    for(const auto* name : {"execution_step_into", "execution_step_over"})
        add(name, name == std::string("execution_step_into") ? "Step into calls on the matching paused thread with bounded count and configured exception handling." : "Step over calls on the matching paused thread with bounded count and configured exception handling.",
            context_schema("MutationContext", {{"count", count}, {"exceptionMode", exceptionMode}}, Json::array(), true), observation,
            {Effect::Execute}, StateRequirement::TargetPaused, "Each completed step belongs to a newer observed context; actual completed count, IP and intervening breakpoint/exception/exit are retained.",
            {"target_state", "operation_reconcile"}, {"A-24", "A-48", "A-50"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("execution_step_out", "Run until the selected thread returns to its caller, preserving earlier stop or exit outcomes.",
        with_deadline_schema(context_schema("MutationContext", {{"returnPolicy", closed_object_schema({{"thread", {{"const", "selected"}}}, {"exceptionMode", exceptionMode}}, {"thread"})}}, Json::array(), true)), observation,
        {Effect::Execute}, StateRequirement::TargetPaused, "The selected caller continuation is observed or an earlier breakpoint/exception/exit is identified; temporary state is reconciled on interruption.",
        {"target_state", "operation_reconcile"}, {"A-24", "A-25", "A-48"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("execution_run_to", "Run to a resolved address using an owned temporary breakpoint and optional pure condition.",
        address_forms(with_deadline_schema(context_schema("MutationContext", {{"condition", string_schema("utf8-text", 4096)}}, Json::array(), true))), observation,
        {Effect::Execute}, StateRequirement::TargetPaused, "The operation's own temporary breakpoint is hit at the resolved address; other stops, exit, timeout and temporary-breakpoint cleanup are recorded distinctly.",
        {"target_state", "breakpoints_list", "operation_reconcile"}, {"A-24", "A-25", "A-26"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("execution_skip_instruction", "Advance the selected instruction pointer without executing instructions after comparing the expected IP.",
        context_schema("MutationContext", {{"expectedIp", hex}, {"count", count}}, {"expectedIp"}, true), observation,
        {Effect::Modify}, StateRequirement::TargetPaused, "Expected IP and decoder widths match; the actual selected-thread IP reread reflects exactly the skipped instructions and a new context epoch.",
        {"registers_read", "target_state", "operation_reconcile"}, {"A-17", "A-24", "A-48"}, "src/dbg/commands/cmd-debug-control.cpp", false);
    add("execution_wait", "Observe a matching event newer than the supplied cursor without executing the target.",
        with_deadline_schema(context_schema("TargetRef", {{"afterCursor", string_schema("utf8-text", 4096)}, {"condition", event_condition_schema()}}, {"afterCursor", "condition"})), observation,
        {Effect::Inspect}, StateRequirement::TargetPresent, "A matching newer event/context is observed; event gaps, actual exit and deadline outcomes are explicit and never reuse an earlier pause.",
        {"target_state", "operation_reconcile"}, {"A-24", "A-48", "A-50"}, "src/dbg/debugger.cpp", true);
    add("threads_list", "List actual thread creation identities, known suspend counts and the selected context with bounded paging.", with_page_schema(context_schema("TargetRef")), paged_data_schema(thread),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Native thread records reconcile to the identified target; unavailable counts/identities are explicit and every page is correlated.",
        {"threads_list", "target_state"}, {"A-27", "A-50"}, "src/dbg/thread.cpp", true);
    add("threads_select", "Select the requested real thread using the current target stop epoch and invalidate the former selection context.",
        context_schema("MutationContext", Json::object(), Json::array(), true),
        closed_object_schema({{"context", reference_schema("PausedContext")}, {"thread", thread}}, {"context", "thread"}),
        {Effect::Configure}, StateRequirement::TargetPaused, "Requested thread belongs to the target and becomes selected; the returned epoch/context reflects the actual selection change.",
        {"threads_list", "threads_context", "operation_reconcile"}, {"A-27", "A-48", "A-50"}, "src/dbg/commands/cmd-thread-control.cpp", false);
    add("threads_suspend", "Suspend the exact target thread, optionally pinning its creation identity, and record this operation's suspend ownership.",
        mutate({{"threadId", threadId}, {"creationIdentity", decimal}}, {"threadId"}), suspension,
        {Effect::Execute}, StateRequirement::TargetPresent, "The exact thread's actual suspend change/count is observed and an ownership token is retained for balanced resume.",
        {"threads_list", "threads_resume", "operation_reconcile"}, {"A-27", "A-48", "A-50"}, "src/dbg/commands/cmd-thread-control.cpp", false);
    add("threads_resume", "Resume a target thread while preserving suspend counts owned by other operations or callers.",
        mutate({{"threadId", threadId}, {"ownedSuspend", id}}, {"threadId"}), suspension,
        {Effect::Execute}, StateRequirement::TargetPresent, "Only the authorized owned count is released; actual before/after count and remaining suspension are observed without force-clearing other owners.",
        {"threads_list", "operation_reconcile"}, {"A-27", "A-48", "A-50"}, "src/dbg/commands/cmd-thread-control.cpp", false);
    add("threads_context", "Read the identified thread's architecture-correct registers and bounded stack with explicit consistency and validity.",
        context_schema("TargetRef", {{"threadId", threadId}, {"consistency", enum_schema({"paused", "best_effort"})}}, {"threadId"}),
        closed_object_schema({{"thread", thread}, {"registers", register_snapshot_schema()}, {"stack", paged_data_schema(stack_frame_schema())}}, {"thread", "registers", "stack"}),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Register/stack observations refer to the exact real thread and capture context; running or unsupported groups retain explicit uncertainty.",
        {"target_state", "threads_list"}, {"A-17", "A-18", "A-21", "A-27"}, "src/dbg/thread.cpp", true);
    add("exceptions_state", "Read the current native exception code, chance, source address and handling decision for the identified target.", context_schema("TargetRef"), exception_observation_schema(),
        {Effect::Inspect}, StateRequirement::TargetPresent, "Reported exception/chance/handling belongs to the current target event; absence or unknown fields are represented explicitly.",
        {"target_state", "exceptions_policy_get"}, {"A-22", "A-24", "A-26"}, "src/dbg/debugger.cpp", true);
    add("exceptions_policy_get", "Read the complete native exception policy ranges, break chance, logging and debugger/debuggee handling.", context_schema("InstanceRef"), policy,
        {Effect::Inspect}, StateRequirement::InstanceReady, "Configured exception rules/version are read from native storage with explicit coverage.",
        {"exceptions_policy_get"}, {"A-22", "A-26", "A-38"}, "src/dbg/debugger.cpp", true);
    add("exceptions_policy_set", "Compare-version and set closed exception handling rules; range ordering/overlap and next-event applicability require native preflight.",
        context_schema("InstanceRef", {{"rules", bounded_array_schema(rule, MaximumPageLimit)}, {"expectedVersion", decimal}, {"idempotencyKey", id}}, {"rules", "expectedVersion"}), policy,
        {Effect::Configure}, StateRequirement::InstanceReady, "Expected version matches, changed rules are reread from native state and their applicable next-event handling is recorded.",
        {"exceptions_policy_get", "operation_reconcile"}, {"A-22", "A-26", "A-38", "A-48"}, "src/dbg/debugger.cpp", false);
}
}
