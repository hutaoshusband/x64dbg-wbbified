#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
// Newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio transport).
// Serves only the registry tools with an implemented native handler; every
// other declared capability keeps its planned descriptor and a ContractError.
// stdin EOF ends the session with exit code 0.
int serve_mcp_stdio();
}
