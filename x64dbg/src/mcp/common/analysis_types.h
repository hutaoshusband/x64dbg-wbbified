#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json module_section_schema();
Json module_observation_schema();
Json symbol_observation_schema();
Json analysis_function_schema();
Json analysis_block_schema();
Json analysis_edge_schema();
Json native_encoding_schema();
Json analysis_encoding_observation_schema();
Json annotation_forms(Json base, bool observed);
Json database_observation_schema();
}
