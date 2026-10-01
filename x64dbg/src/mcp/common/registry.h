#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
enum class StateRequirement { Broker, InstanceReady, TargetPresent, TargetPaused };
enum class ArchitectureRequirement { Any, X32, X64 };

struct RegistryCallContext
{
    OperationId operationId;
    std::uint64_t brokerGeneration;
    std::uint64_t stateVersion;
};

using RegistryHandler = Checked<Json> (*)(const Json& input);

struct ToolDefinition
{
    std::string name;
    std::string description;
    std::string domain;
    std::string provider;
    Json inputSchema;
    Json outputSchema;
    std::vector<Effect> effects;
    Executor executor;
    StateRequirement state;
    ArchitectureRequirement architecture;
    std::string completion;
    std::vector<std::string> recovery;
    std::vector<std::string> acceptanceIds;
    std::string nativeSource;
    bool idempotent;
    bool openWorld;
    RegistryHandler handler;
};

const std::vector<ToolDefinition>& tool_registry();
const ToolDefinition* find_tool(std::string_view name);
Json tool_descriptor(const ToolDefinition& tool);
Json compiled_tool_registry();
std::optional<ContractError> validate_tool_input(std::string_view name, const Json& input);
std::optional<ContractError> validate_tool_output(std::string_view name, const Json& output);
Checked<Json> call_registry_tool(std::string_view name, const Json& input, const RegistryCallContext& context);
}
