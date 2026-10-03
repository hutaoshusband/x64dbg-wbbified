#pragma once

#include "registry.h"

namespace wininspect::mcp
{
enum class LegacyBindingKind { Canonical, InstanceOrTargetState, ProtocolEcho };

struct LegacyAliasDefinition
{
    std::string name;
    std::string description;
    Json inputSchema;
    Json capturedAnnotations;
    std::string originalRoute;
    std::string compatibilityPredicate;
    LegacyBindingKind bindingKind;
    std::vector<const ToolDefinition*> canonicalBindings;
};

const std::vector<LegacyAliasDefinition>& legacy_alias_registry();
const LegacyAliasDefinition* find_legacy_alias(std::string_view name);
Json legacy_alias_descriptor(const LegacyAliasDefinition& alias);
Json compiled_legacy_registry();
std::optional<ContractError> validate_legacy_alias_input(std::string_view name, const Json& input);
Checked<Json> normalize_legacy_alias_input(std::string_view name, const Json& input);
}
