# Stale software-breakpoint events

This test starts 64 threads on the same short `INT3` breakpoint and disables it after the first hit.

On x64, the restored instruction is a blocking `syscall`. Its internal single-step takes 250 ms, exceeding the old two-timeout lifetime of the recently-deleted-breakpoint cache while other breakpoint events are deferred by safe stepping.

The run and step variants fail if a deferred breakpoint event reaches x64dbg's generic exception handler or the debuggee's VEH. The x86 build exercises the same multithreaded deletion path with a fast instruction.

The isolated test profile disables PEB hiding and DLL TLS stops. A native test plugin requires one real initial system breakpoint before scenario installation, at least two actual breakpoint events at the allocated instruction, no generic breakpoint exception, and the real process exit result. Both scripts also verify all 64 completed workers and zero instruction failures.

The normal oracle is selected through `WININSPECT_TEST_NORMAL=1` in the child environment and reports ready/completed workers, instruction failures, escaped breakpoints, completed phase and the actual wait result. Run it through the shared `tests/run_tests.py --phase fixtures --case test_native_stale_breakpoint_oracles` launcher. PEB-hiding behavior and initial system-breakpoint classification remain separate engine checks.
