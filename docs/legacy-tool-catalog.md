# Legacy MCP tool catalog (Checkpoint 1 endpoint)

Captured live from `x64dbg-MCP Server 1.3` via the stdio bridge.
80 tools. Input schemas are verbatim backend contracts; see
`tests/native_mcp/legacy-manifest.json` for the pinned manifest and
canonical native routes.

## AllocateMemory

Allocates a block of memory in the target process.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `size` | yes | integer | Number of bytes to allocate. |
| `protection` | no | string | Memory protection: rwx, rw, rx, r (default rw). |

## AnalyzeCode

Runs x64dbg code analysis on a module or address range. This populates the function list, enables GetFunctions/GetReferences/DisassembleFunction. Must be run before those tools return useful results.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | no | string | Address or module to analyze. If omitted, analyzes the current module. |
| `type` | no | string | Analysis type: 'function' (analr - analyze single function), 'module' (anal - analyze module), 'controlflow' (cfanal - control flow analysis). Default: module. |

## AnalyzeModule

Shows PE structure analysis: sections, entry point, image size, characteristics.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name (e.g. kernel32, ntdll). |

## Assemble

Assembles an instruction at a specific address, replacing existing bytes.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Address to assemble at. |
| `instruction` | yes | string | Assembly instruction (e.g. nop, mov eax 1, jmp 0x401000). |

## AttachProcess

Attaches the debugger to a running process by PID.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `pid` | yes | integer | Process ID to attach to. |

## ClearEventLog

Clears the event log ring buffer.

No arguments.

## CommentOrLabelAtAddress

Adds a comment or a label at a specific address in the disassembly.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Hex address. |
| `value` | yes | string | The comment or label text. |
| `mode` | no | string | 'Comment' or 'Label'. |

## DeleteAllBreakpoints

Removes all breakpoints (normal, hardware, and memory).

No arguments.

## DeleteBookmark

Deletes a bookmark at the specified address.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## DeleteBreakpoint

Removes a breakpoint at an address or API symbol.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `target` | yes | string | Hex address or API symbol of the breakpoint to remove. |

## DeleteExceptionBreakpoint

Removes an exception breakpoint, restoring default handling for that exception code.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `exceptionCode` | yes | string | Exception code in hex to delete. |

## DetectOEP

Attempts to detect the Original Entry Point for packed executables by analyzing section characteristics.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name (e.g. kernel32, ntdll). |

## DisableBreakpoint

Disables a breakpoint at a given address without deleting it.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## Disassemble

Disassembles instructions at an address. Returns instruction mnemonics with addresses. Default: 10 instructions from current IP.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | no | string | Address or expression (default: current IP). |
| `count` | no | integer | Number of instructions (default 10, max 100). |

## DisassembleFunction

Disassembles an entire function by finding its start/end boundaries from the analysis database.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## DumpMemory

Saves a memory region to a file on disk.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Start address. |
| `size` | yes | integer | Bytes to dump. |
| `filePath` | yes | string | Output file path on disk. |

## DumpModule

Dumps an entire loaded module to a file on disk.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name to dump. |
| `filePath` | yes | string | Output file path. |

## Echo

Echoes the input back to the client.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `message` | yes | string | Message to echo. |

## EnableBreakpoint

Enables a breakpoint at a given address.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## EvalExpression

Evaluates an x64dbg expression (address, register, arithmetic, symbol) and returns the result in hex and decimal.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `expression` | yes | string | x64dbg expression (e.g. cip, eax+4, kernel32:CreateFileA). |

## ExecuteDebuggerCommand

Executes a native x64dbg command string (like 'erun', 'analr', 'graph'). This is for x64dbg-internal commands ONLY — do NOT pass MCP tool names here. MCP tools (WaitForEvent, GetDebugState, Disassemble, etc.) must be called directly as tools.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `command` | yes | string | The x64dbg command to execute. |

## FindPattern

Scans module memory for a byte pattern with ?? wildcards. Returns matching addresses. Example: FindPattern pattern='E8 ?? ?? ?? ?? 85 C0 74'

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `pattern` | yes | string | Hex bytes with ?? wildcards, e.g. 'E8 ?? ?? ?? ?? 85 C0'. |
| `module` | no | string | Module to scan (default: main exe). |
| `maxResults` | no | integer | Max results (default 10). |

## FollowPointer

Dereferences a pointer chain N levels deep, showing each level's address and value with module info.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Starting address or expression. |
| `depth` | no | integer | Dereference depth (default 1, max 16). |

## FreeMemory

Frees a previously allocated memory block in the target process.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Base address of the allocated block to free. |

## GetAllRegisters

Returns the current values of all general-purpose registers. Takes no arguments.

No arguments.

## GetArguments

Reads function arguments from the stack (x32: [ESP+4]...) or registers (x64: RCX,RDX,R8,R9...) at the current position.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `count` | no | integer | Number of args to read (default 4, max 16). |

## GetCallStack

Returns the current thread's call stack. Takes no arguments.

No arguments.

## GetCurrentAddress

Returns the current instruction pointer (EIP/RIP), the module it belongs to, and its label/comment. Takes no arguments.

No arguments.

## GetDebugState

Returns the current debugger state: whether a binary is loaded, whether it is running or paused, the PID, current instruction pointer, and current module. Always available. Takes no arguments.

No arguments.

## GetDumpableRegions

Lists memory regions that can be dumped (committed, readable) for a module or the entire process.

No arguments.

## GetEventLog

Returns the last N debugger events (exceptions, breakpoints, DLL loads, thread events, etc.). Keeps the last 64 events in a ring buffer. Use this to see what happened in x64dbg.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `count` | no | integer | Number of most recent events to return (default: all, max 64). |

## GetExports

Shows the export table of a loaded module.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name (e.g. kernel32, ntdll). |

## GetFunctions

Lists analyzed functions in a module with start addresses, sizes, and labels. Requires prior analysis (Ctrl+A in x64dbg).

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name (e.g. kernel32, ntdll). |

## GetImports

Shows the import table of a loaded module.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name (e.g. kernel32, ntdll). |

## GetMemoryMap

Returns the memory map showing all memory regions with base address, size, protection, and module info.

No arguments.

## GetPEB

Reads key fields from the Process Environment Block: image base, being debugged, heaps, NtGlobalFlag, image path, command line.

No arguments.

## GetPatches

Lists all memory patches applied to the debugged process.

No arguments.

## GetReferences

Finds code references (CALL/JMP) to a target address within a module.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address to find references to. |
| `module` | no | string | Module to search in (default: main exe). |

## GetSEHChain

Walks the Structured Exception Handler chain (x32 only) and shows each handler's address and module.

No arguments.

## GetStrings

Scans a module's memory for ASCII strings and returns them with their addresses.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | no | string | Module to scan (default: main exe). |
| `minLength` | no | integer | Min string length (default 4). |

## GetThreads

Lists all threads in the debugged process with IDs, instruction pointers, and names.

No arguments.

## ListBookmarks

Lists all bookmarks with addresses and labels.

No arguments.

## ListBreakpoints

Lists all active breakpoints (software, hardware, and memory).

No arguments.

## ListCommandsByCategory

Lists the available MCP tools, optionally filtered to a single category.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `category` | no | string | Optional category filter. |

## ListModules

Lists all loaded modules (DLLs/EXE) with base addresses and sizes.

No arguments.

## ListSymbols

Lists exported symbols of a module.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `module` | yes | string | Module name to list symbols from. |

## LoadBinary

Loads an executable into the debugger for a new debugging session. Equivalent to File > Open in the GUI. If a session is already active it is terminated first. The debuggee pauses at the system breakpoint.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `filePath` | yes | string | Absolute file path of the executable to debug. |
| `arguments` | no | string | Optional command-line arguments. |

## PauseDebug

Pauses (suspends) the running debuggee, equivalent to Debug > Pause (F12). Takes no arguments.

No arguments.

## ReadMemory

Reads raw bytes from the target process memory and returns a hex dump with ASCII. Example: ReadMemory address=0x7FF600001000, size=128

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Hex address or expression to read from. |
| `size` | no | integer | Number of bytes to read (max 4096). |

## ResetHitCount

Resets the hit counter of a breakpoint at the given address to zero.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## RestartDebug

Restarts the current debugging session from the beginning. Takes no arguments.

No arguments.

## RestorePatches

Restores all patched bytes back to their original values.

No arguments.

## ResumeThread

Resumes a suspended thread by its thread ID.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `threadId` | yes | integer | Thread ID to operate on. |

## RunToAddress

Sets a temporary breakpoint at the target address, resumes execution, and waits for the debuggee to hit it.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Address to run to. |
| `timeoutMs` | no | integer | Timeout ms (default 30000). |

## SaveDatabase

Saves the x64dbg database (labels, comments, breakpoints, analysis) for the current module. Persists your work across sessions.

No arguments.

## SearchForStrings

Searches process memory for a specific text string and returns the addresses where it occurs.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `searchText` | yes | string | The literal text to search for. |
| `encoding` | no | string | Character encoding: UTF-8 or UTF-16. |

## SearchSymbols

Searches for symbols (labels) matching a pattern in a module.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `pattern` | yes | string | Symbol name pattern to search for (substring match). |
| `module` | no | string | Module to search in (default: all modules). |

## SetBookmark

Sets a bookmark at the specified address.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## SetBreakpoint

Sets a software execution breakpoint (INT3) at an address or API symbol.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `target` | yes | string | Hex address or API symbol to break on. |

## SetBreakpointCommand

Sets an x64dbg command to execute when a breakpoint at the given address is hit. Use for logging breakpoints (e.g., 'log {x:eax}' to log register values on hit).

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Breakpoint address. |
| `command` | yes | string | x64dbg command to run on hit (e.g. 'log {x:eax}', 'msg {utf8@[esp+4]}'). |

## SetBreakpointFastResume

Makes a breakpoint auto-resume after hit without pausing. Combined with SetBreakpointCommand, creates logging breakpoints that record state at thousands of call sites without stopping.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Breakpoint address. |
| `enable` | no | boolean | true to enable fast resume, false to disable. |

## SetConditionalBreakpoint

Sets a breakpoint with a condition expression and optional log text.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Breakpoint address. |
| `condition` | yes | string | Break condition expression, e.g. 'eax==0'. |
| `log` | no | string | Log format string (optional). |

## SetExceptionBreakpoint

Controls how an exception code is handled: break into debugger or pass to application. Use this to ignore Delphi (0EEDFADE), C++ (E06D7363), or other framework exceptions during startup, or to break on specific exceptions like ILLEGAL_INSTRUCTION (C000001D).

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `exceptionCode` | yes | string | Exception code in hex (e.g. C000001D, 0EEDFADE, E06D7363). |
| `chance` | no | integer | 1 = first-chance, 2 = second-chance, 3 = both (default 1). |
| `action` | no | string | break = break into debugger, ignore = pass to application (default break). |

## SetHardwareBreakpoint

Sets a hardware breakpoint using debug registers (DR0-DR3). Supports read, write, and execute types.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Address for the hardware breakpoint. |
| `type` | no | string | Type: r (read), w (write), x (execute, default). |
| `size` | no | integer | Size: 1, 2, 4, or 8 (default 1). |

## SetMemoryBreakpoint

Sets a memory breakpoint at an address. Triggers when memory is accessed (read/write/execute). Uses guard pages — slower than hardware breakpoints but no DR register limit.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Address for the memory breakpoint. |
| `type` | no | string | Type: r (read/access), w (write), x (execute). Default: access (any). |
| `singleshoot` | no | boolean | If true, breakpoint is removed after first hit (default false). |

## SetRegister

Sets the value of a CPU register.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `register` | yes | string | Register name (e.g. eax, ecx, eip). |
| `value` | yes | string | Value to set (hex or decimal). |

## StepInto

Executes a single instruction, stepping INTO any call encountered (F7). Takes no arguments.

No arguments.

## StepOut

Runs until the current function returns to its caller (Ctrl+F9). Takes no arguments.

No arguments.

## StepOver

Executes a single instruction, stepping OVER any call/subroutine entirely (F8). Takes no arguments.

No arguments.

## StopDebug

Terminates the current debugging session and closes the debuggee process. Takes no arguments.

No arguments.

## SuspendThread

Suspends a thread by its thread ID.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `threadId` | yes | integer | Thread ID to operate on. |

## SwitchThread

Switches the debugger's active thread context to a different thread.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `threadId` | yes | integer | Thread ID to switch to. |

## ToggleBreakpoint

Toggles a breakpoint between enabled and disabled.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Target address or expression. |

## TraceInto

Single-steps N instructions recording the address and disassembly of each. Max 100.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `count` | no | integer | Instructions to trace (default 10, max 100). |

## TraceOver

Steps N instructions stepping OVER calls (like TraceInto but without diving into subroutines). Records address and disassembly of each step.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `count` | no | integer | Instructions to trace (default 10, max 100). |

## WaitForEvent

Blocks until a debugger event fires (breakpoint hit, paused, resumed, exception, session start/stop) or timeout. Returns all events that occurred. Use this to monitor debugger state changes in real-time over HTTP — call it after 'run' or while waiting for the user to interact with the debugger.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `timeoutMs` | no | integer | Maximum wait time in milliseconds (default 30000, max 120000). |

## WaitForPause

Blocks until the debuggee stops running (hits a breakpoint, exception, or exits). Returns the reason for the pause and the current address. Use after 'run' to wait for the target to break.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `timeoutMs` | no | integer | Maximum wait time in milliseconds. |

## WatchExpressions

Evaluates multiple x64dbg expressions at once and returns all results. Pass comma-separated expressions.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `expressions` | yes | string | Comma-separated x64dbg expressions to evaluate. |

## WriteMemToAddress

Patches memory by writing raw hex bytes to an address. WARNING: this modifies the live process. Example: WriteMemToAddress address=0x12345678, byteString=0F FF 90

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `address` | yes | string | Hex address to write to. |
| `byteString` | yes | string | Hex bytes to write, e.g. '0F FF 90'. |

## run

Resumes execution and waits for the target to pause (breakpoint, exception, or exit). Blocks until a pause event occurs or timeout. Use timeoutMs to control how long to wait (default 120s). Always returns the reason for the pause and current state.

| Argument | Required | Type | Notes |
| --- | --- | --- | --- |
| `timeoutMs` | no | integer | Maximum time to wait for target to pause after resuming (default 300000ms = 5 minutes, max 600000ms = 10 minutes). The tool blocks until a breakpoint/exception fires or timeout. |
