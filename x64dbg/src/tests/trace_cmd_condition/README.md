# Native trace and graph reference

The original target mode and `test.txt` remain available. The selected reference mode executes four direct calls, alternating even and odd branches. The actual target stores 9, 12, 14 and 17, sums them to 52, returns 17 from the assembly function and exits with 52 after its C++ check.

`test.into.txt` steps through each executed callee instruction; `test.over.txt` steps over each complete call. Both stop before `TraceDone` executes. The fixture phase adds recording commands with an absolute private output path. The native plugin checks the known instruction order, raw event PID/TID, the final stop, actual registers and memory effects. Its callbacks publish bounded records without debugger calls or I/O. Paused commands check native graph blocks, branch/fallthrough edges, the loop and returns. Bridge graph allocations are released through the bridge conversion API. Graph instruction bytes are reported only through their decoded length.

Use the existing public launcher:

```
python -B tests/run_tests.py --phase fixtures --arch all --engine all --case test_native_trace_oracles
python -B tests/run_tests.py --phase native --arch all --engine TitanEngine --case trace_cmd_condition/into --case trace_cmd_condition/over
```

The fixture phase runs a normal target first, then records both trace modes in fresh owned debugger processes and isolated profiles. The imported `trace_checks.py` admits exact source PE instructions, exports and x32 relocation fields. It parses the retained trace independently and compares each opcode, pre-instruction register state, relevant ZF state, memory access, thread and ordered callback against the source reference. Native graph output is compared with the same source PE facts. Register words, graph addresses and recorded memory values are written as hex strings in the independent report. All files and generated scripts stay in the private evidence directory.

Immediately before every CALL, a target instruction writes `11223344` to the next stack slot. The trace must pair that exact old value with the actual return address at the same slot. DWORD data accesses are checked at their declared four-byte width; CALL/RET stack accesses use the architecture's pointer width. Trace-into has 58/x64 or 57/x32 recorded instructions; trace-over has 34/x64 or 33/x32. The unexecuted stop instruction is the final callback and is absent from the file.

Thirteen corrupted file/output controls per trace must be rejected. They exercise opcode, thread, initial register, memory address/value, register delta, truncation, missing instruction, architecture, source hash, graph edge, callback order and final-stop failures. The header's MurmurHash3 value is recomputed from the exact source file using the native architecture's variant and seed. These are validator controls; they do not execute modified target instructions. Native runtime mutation controls are recorded separately during checkpoint verification.

This reference covers the declared near CALL loop and two three-block native function graphs. It does not establish every stack instruction, exception trace, append/paging case, GUI trace reader, indirect call graph, trace transport, cancellation, library persistence or MCP handler.
