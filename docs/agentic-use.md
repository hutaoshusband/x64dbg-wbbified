# Agentic use — x64dbg-wbbified MCP

This repo is usable by AI agents **today** via a stdio MCP bridge that owns an
isolated debugger (Checkpoint 1), while the native in-process MCP server is
built checkpointwise toward the same contract (Checkpoint 2+).

## Quick start

Requirements: Windows 10/11 x64, Python 3.11+ (stdlib only, no pip install).

```powershell
# 1. Protocol self-check, no debugger needed (seconds)
python tools/mcp_stdio_bridge.py --self-test

# 2. Real debugger launch + tool catalog + Echo + idle state (~1 min)
python tools/mcp_stdio_bridge.py --smoke-test --arch x64

# 3. Print an exact config snippet for your client
python tools/mcp_stdio_bridge.py --print-config cursor
```

If both checks print `passed`, any MCP-capable agent can drive the debugger.

## Client setup

The bridge speaks newline-delimited JSON-RPC on stdio and starts/stops its
own debugger, so clients only need the command. Replace the paths with the
output of `--print-config` on your machine.

Claude Desktop (`%APPDATA%/Claude/claude_desktop_config.json`) and Cursor
(`.cursor/mcp.json`) share one shape — see
[mcp/cursor.example.json](../mcp/cursor.example.json). Claude Code uses
`.mcp.json` at the project root
([example](../mcp/claude-code.example.json)). VS Code uses `.vscode/mcp.json`
with `"type": "stdio"` ([example](../mcp/vscode.example.json)).

After adding the server, restart the client (or reconnect MCP servers) and ask
the agent to list its `x64dbg` tools. It should see 81 tools: the 80 backend
tools (e.g. `Echo`, `LoadBinary`, `GetDebugState`, `Disassemble`,
`SetBreakpoint`) plus the bridge-native `BridgeInfo`.

Some clients lazy-load tools: if a call fails with "unknown tool" for a name
that `ListCommandsByCategory` advertises, use the client's tool search to load
that tool first and retry. All 80 backend tools are callable — the bridge
forwards `tools/list` verbatim in a single page, so a missing tool is always a
client-side loading state, never a server gap.

## What the agent gets

- 80 debugger tools over MCP: launch/attach, breakpoints, stepping,
  registers, memory, disassembly/assembly, modules, threads, call stack,
  PEB, expression evaluation, event log, raw debugger commands.
  Full verbatim reference: [legacy-tool-catalog.md](legacy-tool-catalog.md).
- Bridge-native `BridgeInfo` tool: bridge/backend versions, debugger PID,
  active profile (PEB hiding, loader breaks) and host notes. The `initialize`
  response also carries these as `instructions`.
- Anti-detection defaults: the owned debugger starts with `HideDebugger=1`
  (PEB hiding). Pass `--show-debugger` to disable it for a run.
- Loader breaks off by default: TLS/DLL/thread stops are disabled in the
  fresh profile while the system and entry-point stops stay on, so one `run`
  after `LoadBinary` lands on the entry point. Pass `--loader-breaks stock`
  to restore x64dbg defaults (needed if you must break inside TLS callbacks).
- Bare `.RVA` addresses: `Disassemble` and every other `address` argument
  accept current-module-relative `.5E000` form; the bridge resolves it against
  `GetDebugState` + `ListModules` before forwarding. `mod.RVA` and absolute
  addresses pass through unchanged.
- Event journal: the backend ring buffer only records generic lines
  ("Breakpoint hit", "DLL loaded"). Every tool result already ends with a
  `[state]` trailer, and `GetEventLog` additionally carries a bridge journal
  pairing each observed session event with the address it was seen at.
- One session per bridge process: the debugger starts when the agent host
  spawns the bridge and is closed when the session ends.

Environment note: the debugger runs natively on Windows (see `BridgeInfo`
for the build). Odd module names in `ListModules` (Windhawk mods, shell
extensions, AV DLLs) are third-party DLLs injected into the debug target by
software on the host — not emulation. They load extra code into every target,
so loader noise or unexpected stops usually come from there.

Typical first tasks to give an agent:

1. `LoadBinary` with an absolute `filePath`, then `GetDebugState`.
2. `AnalyzeCode` on the module, then `Disassemble` at the entry point.
3. `SetBreakpoint` + `run`, inspect with `GetAllRegisters` / `ReadMemory`.
4. `GetEventLog` when something unexpected happens.

## How it works (isolation and security)

- Each bridge run stages a private copy of `WinTools/x64` under
  `%LOCALAPPDATA%/x64dbg-wbbified/Agentic/agentic-*/` plus a fresh profile.
  The repository and `WinTools` are never modified.
- The backend HTTP endpoint binds `127.0.0.1` on a random free port with a
  random 256-bit bearer token. The token never appears on stdout or in logs.
- The bridge verifies the listener PID equals the owned debugger PID before
  sending the token anywhere.
- The debugger and any debuggee it spawns are bound to an owned Windows job
  object (`KILL_ON_CLOSE`); closing stdin ends the whole tree.
- Scope: local x64 only. x32 fails explicitly — the shipped x32 deployment
  has no MCP plugin yet. Remote exposure of the backend port is unsupported.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Legacy MCP baseline plugin is unavailable for x32` | Expected: use `--arch x64`. |
| `Owned MCP endpoint did not become ready` | Debugger GUI failed to start (missing VC++ runtime, Qt conflict). Run the smoke test and check stderr; ensure no stale `wininspect.exe` holds the profile. |
| `MCP listener does not belong to the owned debugger process` | Port race or another listener grabbed the port. Retry; the port is random per run. |
| Agent sees no tools | Client config path/typo, or the client needs a restart/reconnect. Validate with `--smoke-test` outside the client first. |
| Debuggee detects the debugger | Default hiding covers PEB checks; ScyllaHide options in the staged `plugins/` dir can be tuned per run. Attach/pause with hiding enabled is a known open engine gate (see `tests/README.md`). |

## Roadmap checkpoints

- [x] **Checkpoint 1 (this bridge):** stdio MCP for agents via the legacy
  x64 plugin — isolated staging, owned lifecycle, 80 tools.
- [x] **Checkpoint 2:** native broker stdio transport (`wininspect-mcp.exe
  --serve-stdio`) serving the first five implemented tools (`server_info`,
  `server_health`, `capabilities_list/describe/search`) from the compiled
  200-tool registry. Verified by `test_native_stdio_transport`; the other
  195 tools stay planned with zero live debugger operations.
- [ ] **Checkpoint 3:** native worker lifecycle — real debugger
  instances, launch/attach, target state through the registered worker.
- [ ] **Checkpoint 4+:** native inspection, execution control, breakpoints,
  memory and patch parity per `tests/native_mcp/parity-manifest.json`.

Native progress is gated by `python tests/run_tests.py --phase mcp-contracts
--arch all`. The bridge does not change native contracts or tests.
