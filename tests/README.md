# Debugger verification suite

Run `python tests/run_tests.py` from the repository root. This is the shared entry point for baseline, fixture, inventory, build and native regression checks. Helper modules and the inventory fixture are not separate test launchers.

## Phases

| Phase | Outcome checked |
| --- | --- |
| `baseline` | Existing external MCP functional suite and isolated PEB hiding controls |
| `functional` | Existing functional cases without the extra PEB control processes |
| `defects` | Actual target argument delivery and executable assembly patch; known external failures remain failures |
| `contracts` | Authenticated responses for every catalog tool with empty arguments and no target |
| `surface` | GUI-thread inventory of menus, widgets, commands and script providers; shipped plugin resource dialogs, menus and configuration keys |
| `fixtures` | Five fixture executables run normally with independent expected markers, arguments and exit codes |
| `inventory` | Source registration/form candidates reconciled with the captured legacy catalog and optional runtime surface |
| `build` | Fresh Release source builds of the GUI debugger, headless debugger and existing native fixtures |
| `native` | Existing headless regression bundles, preserving their assertion failures and process exit results |

`--arch x64`, `--arch x32` and `--arch all` select architectures. `--case` can be repeated; baseline case selections accept globs, while native selections use existing native bundle IDs. `--engine` selects TitanEngine, GleeBug, StaticEngine or all available backends for the native phase. `--list` lists cases without launching or writing artifacts. `--timeout` bounds requests and execution waits between 1 and 60 seconds. Defaults are x64, baseline, and 45 seconds.

```powershell
python tests/run_tests.py --phase fixtures --arch all
python tests/run_tests.py --phase build --arch all
python tests/run_tests.py --phase native --arch all --case commandparser --case script_run_exit
python tests/run_tests.py --phase contracts
python tests/run_tests.py --phase surface
python tests/run_tests.py --phase defects
```

For source inventory, supply the exact captured catalog. Include a captured runtime snapshot to add shipped runtime operations and, when present beside it, `plugin-resources.json`. Registry refresh is explicit:

```powershell
python tests/run_tests.py --phase inventory --catalog C:/private-run/x64/legacy-catalog.json --runtime-surface C:/private-run/x64/runtime-surface-paused.json --refresh-registries
```

The legacy manifest records the observed external plugin contracts and canonical migration destinations. The parity manifest records source and runtime discovery candidates. Its rows remain planned until actual agent routes satisfy the independent native parity predicates. Candidate totals do not establish complete semantic parity. Dynamic context menus, lazy dialogs, provider effects and state classifications still need reconciliation.

## Isolation and retained evidence

Each run creates a private directory beneath `%LOCALAPPDATA%/x64dbg-wbbified/Verification`. `--output` can select another directory outside the repository. Fixtures, objects, logs, patched targets, profiles and copied deployments stay there. The suite builds targets with an explicit `asInvoker` manifest for both architectures.

External phases copy the selected `WinTools/<arch>` deployment, use a new user directory and random authentication token, verify the HTTP listener PID, and retain process creation identity and loaded module hashes. Job ownership and process-specific shutdown bound cleanup to the owned debugger and its targets. Deployment hashes before and after the run verify that personal files were unchanged.

The x64 external plugin is the available behavioral baseline. The shipped x32 plugin directory has no corresponding MCP plugin; external x32 verification fails explicitly until that artifact is available. Normal fixtures and source-built native regressions support both architectures independently.

Build phases use new out-of-tree CMake directories. Existing local Qt SDKs may supply the configured Qt package, while build output remains in the debugger's ignored `bin/<arch>` directory. No obsolete cached source directory is reused. Build receipts retain actual commands, source inputs and artifact hashes.

Evidence includes requests without authentication headers, catalog contracts, target markers, compiler output, fixture hashes, process modules and verification summaries. Failed and unexecuted requested cases remain visible. A contracts or inventory pass verifies capture/reconciliation; it does not claim that the external tool's behavior or a native replacement is correct.

## Native log compatibility

The inherited regression runner recognizes both upstream `[x64dbg-test]` and fork `[wi-test]` final markers. A reported failure remains a failure; successful parser recognition cannot override a failed assertion, missing final marker, timeout or unsuccessful process exit. Existing native drivers and checker modules remain authoritative for their individual bundles.

Native test scripts are staged with `configure_file(COPYONLY)`. CMake tracks their contents and refreshes the runtime copies when a script changes, including builds that require no C++ recompilation. Tests therefore execute the current source script instead of a copy left over from the last link step.
