#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json register_snapshot_schema();
Json register_write_value_schema();
Json stack_frame_schema();
Json memory_region_schema();
Json memory_coverage_schema();
Json expression_value_schema();
Json exception_observation_schema();
Json execution_observation_schema();
Json event_condition_schema();
Json managed_artifact_schema();
Json decoded_structure_schema();
}
