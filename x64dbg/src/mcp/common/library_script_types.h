#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
bool safe_virtual_path(std::string_view value);
Json virtual_path_schema();
Json library_content_schema();
Json script_source_schema();
Json library_object_schema();
Json library_trash_schema();
Json library_chunk_schema();
Json library_quota_schema();
Json script_limits_schema();
Json script_manifest_schema();
Json script_diagnostics_schema();
Json script_revision_schema();
Json script_validation_schema();
Json script_run_schema();
Json native_script_state_schema();
}
