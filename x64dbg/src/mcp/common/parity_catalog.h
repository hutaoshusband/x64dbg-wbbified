#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json compiled_parity_metadata();
Checked<Json> parity_records_page(const Json& input);
Checked<Json> describe_parity_operation(std::string_view actionId);
Checked<Json> resolve_parity_inventory_id(std::string_view inventoryId);
}
