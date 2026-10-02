# random_dll

Port of `src/test/random_dll` as an automated regression test scaffold for issue #3599.

Intended coverage:

- breakpoint command text that starts with `$` and must be formatted before execution
- dynamically generated `bpdll` commands using the current DLL path
- `scriptcmd call onrandomdll` callback execution while the script is running
- the resulting DLL-breakpoint / DllMain break sequence from the dynamically created librarian breakpoints

Current status:

- scaffolded, but **not enabled in the default suite yet**
- the automated source breakpoint/command path still does not reproduce the manual README scenario deterministically in headless
- keep this folder as WIP for a later dedicated pass on issue #3599

The separate `random_dll/modules` case is enabled. It checks two byte-identical DLL copies under a Unicode directory, known exported function returns, the executed process-ID import, module entry/size/sections, and load/unload callbacks. Releasing an extra reference must keep the first DLL loaded with no detach. Releasing its final reference must execute detach and remove it from the debugger module list before the second DLL loads. Windows may reuse the same base address for both copies; event order and fixture index distinguish them.

The target normally retains the original scaffold behavior. `WININSPECT_TEST_NORMAL=1` selects the deterministic reference and borrows the prepared directory named by `WININSPECT_TEST_MODULE_DIRECTORY`. The shared suite prepares and hashes those copies, checks all 34 output fields against independent PE facts and known canaries, and retains them in its private evidence store. The native script selects the reference at the actual target entry, uses an owned temporary directory, and verifies its removal after the actual exit code 43. It disables unrelated DLL TLS stops and debugger hiding in the isolated profile.

The original `test.disabled.txt` remains disabled. The deterministic module reference does not establish the original issue #3599 script callback behavior.

The owned temporary directory includes the actual process ID because the temporary file name is released before directory creation and another process can receive the same base name. `WININSPECT_TEST_MODULE_OWNED=1` selects that same owned path for the normal reference. The shared module case runs sixteen such ordinary targets concurrently, checks every DLL canary and detach, binds distinct directories to actual process identities and verifies complete directory removal. Its prepared borrowed copies must remain unchanged.
