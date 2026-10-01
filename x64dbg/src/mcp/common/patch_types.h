#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json decoded_instruction_schema();
Json encoded_block_schema();
Json patch_range_schema();
Json patch_set_schema();
Json file_observation_schema();
Json file_transaction_schema();
}
