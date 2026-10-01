import argparse
from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

import cases
from wi_driver import McpError, ROOT, SuiteEnvironment, WinInspect, build_debugger, build_targets, read_kv, write_json


def run_fixture_oracles(environment, results):
    expected_markers = {"exitmark": {"marker": "done"}, "bpmain": {"marker": "done", "hits": "2"},
                        "probe": {"BeingDebugged": "0"}, "patch_canary": {"value": "7"}}
    expected_exits = {"exitmark": 42, "bpmain": 0, "probe": 0, "patch_canary": 7, "launch_arguments": 17}
    intended_arguments = ["", "two words", 'a"b', "trail\\", "comma,value", "{braces}", "Hu Tao \u2764", "run"]
    observations = {}
    for name, expected_exit in expected_exits.items():
        command = [environment.fixture(name)]
        if name == "launch_arguments":
            command.extend(intended_arguments)
        process = subprocess.run(command, cwd=environment.targets, capture_output=True, timeout=10,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        assert process.returncode == expected_exit, f"Normal fixture {name} exited with {process.returncode}"
        observed = read_kv(environment.marker(name))
        if name == "launch_arguments":
            actual_arguments = [bytes.fromhex(observed[f"argv{index}"]).decode("utf-16-le")
                                for index in range(1, int(observed["argc"]))]
            assert actual_arguments == intended_arguments, f"Normal argument fixture differs: {actual_arguments!r}"
        else:
            for field, value in expected_markers[name].items():
                assert observed.get(field) == value, f"Normal fixture {name} differs: {observed}"
        observations[name] = {"exitCode": process.returncode, "marker": observed}
    results.append({"name": "test_fixture_oracles", "status": "verified", "oracle": observations})
    print(f"[VERIFIED] Five normal {environment.architecture} fixture outcomes", flush=True)


def run_case(function, debugger, results):
    started = time.monotonic()
    result = {"name": function.__name__, "status": "verified"}
    try:
        oracle = function(debugger)
        if oracle is not None:
            result["oracle"] = oracle
    except Exception as error:
        result.update(status="failed", error=str(error))
    finally:
        result["targetMarkers"] = {marker.name: read_kv(marker)
                                   for marker in debugger.environment.targets.glob("*_result.txt")}
        try:
            debugger.safe_stop()
        except Exception as error:
            result.update(status="failed", cleanupError=str(error))
    result["seconds"] = round(time.monotonic() - started, 3)
    results.append(result)
    print(f"[{result['status'].upper()}] {result['name']} ({result['seconds']:.1f}s)", flush=True)
    if result.get("error"):
        print(result["error"], flush=True)


def run_functional(environment, selected, results, timeout):
    debugger = WinInspect(environment, timeout=timeout)
    try:
        server = debugger.start()
        print(f"Owned debugger ready: {server.get('name')} {server.get('version')}", flush=True)
        debugger.list_tools()
        for function in selected:
            run_case(function, debugger, results)
    finally:
        debugger.stop()


def run_native_surface(environment, results, timeout):
    from inventory import capture_native_runtime_surface
    debugger = WinInspect(environment, plugin_profile="native", timeout=timeout)
    result = {"name": "test_native_runtime_surface_inventory", "status": "verified"}
    try:
        result["oracle"] = capture_native_runtime_surface(debugger)
    except Exception as error:
        result.update(status="failed", error=str(error))
    finally:
        debugger.stop()
    if debugger.record is not None and debugger.record.get("exitCode") != 0:
        result.update(status="failed", cleanupError=f"Native debugger exited with {debugger.record.get('exitCode')}")
    results.append(result)
    print(f"[{result['status'].upper()}] {result['name']}", flush=True)
    if result.get("error"):
        print(result["error"], flush=True)


def run_hide_case(environment, hidden, results, timeout):
    debugger = WinInspect(environment, plugin_profile="legacy-only", hide_debugger=hidden, timeout=timeout)
    result = {"name": "test_peb_autohide_on" if hidden else "test_peb_autohide_control", "status": "verified"}
    started = time.monotonic()
    try:
        debugger.start()
        debugger.wipe_markers()
        response = debugger.load(debugger.fixture("probe"))
        assert "SUCCESS" in response, response[:200]
        marker = debugger.marker("probe")
        state = debugger.resume_until(marker=marker)
        assert Path(marker).exists(), f"Probe marker missing: {state['last']}"
        observed = read_kv(marker)
        result["oracle"] = observed
        being_debugged = int(observed["BeingDebugged"])
        global_flags = int(observed["NtGlobalFlag"], 16)
        assert being_debugged == int(not hidden), str(observed)
        if hidden:
            assert global_flags & 0x70 == 0, str(observed)
    except Exception as error:
        result.update(status="failed", error=str(error))
    finally:
        debugger.stop()
    result["seconds"] = round(time.monotonic() - started, 3)
    results.append(result)
    print(f"[{result['status'].upper()}] {result['name']} ({result['seconds']:.1f}s)", flush=True)
    if result.get("error"):
        print(result["error"], flush=True)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Isolated WinInspect verification suite")
    parser.add_argument("--phase", choices=("baseline", "functional", "defects", "contracts", "surface", "fixtures", "inventory", "build", "native", "mcp-contracts"), default="baseline")
    parser.add_argument("--arch", choices=("x64", "x32", "all"), default="x64")
    parser.add_argument("--case", action="append", default=[], help="Select a case name or glob; repeatable")
    parser.add_argument("--deploy", type=Path, help="Read-only source deployment for one architecture")
    parser.add_argument("--output", type=Path, help="Private evidence root outside the repository")
    parser.add_argument("--timeout", type=float, default=45, help="Bound each request and run wait in seconds")
    parser.add_argument("--list", action="store_true", help="List cases without launching or writing files")
    parser.add_argument("--catalog", type=Path, help="Captured legacy catalog for inventory reconciliation")
    parser.add_argument("--runtime-surface", type=Path, action="append", default=[],
                        help="Captured GUI and plugin surface for parity reconciliation; repeatable")
    parser.add_argument("--surface-provider", choices=("legacy", "native"), default="legacy",
                        help="Observe shipped legacy or source-built native GUI surface")
    parser.add_argument("--refresh-registries", action="store_true", help="Update the source parity candidate registry")
    parser.add_argument("--engine", choices=("TitanEngine", "GleeBug", "StaticEngine", "all"), default="TitanEngine")
    parser.add_argument("--cmake", type=Path, help="CMake executable for the mcp-contracts source build")
    arguments = parser.parse_args()
    if not 1 <= arguments.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if arguments.deploy and arguments.arch == "all":
        parser.error("--deploy requires one architecture")
    if arguments.phase == "inventory" and not arguments.catalog:
        parser.error("--phase inventory requires --catalog")
    if arguments.refresh_registries and arguments.phase != "inventory":
        parser.error("--refresh-registries requires --phase inventory")
    if arguments.surface_provider == "native" and arguments.phase != "surface":
        parser.error("--surface-provider native requires --phase surface")
    if arguments.cmake:
        if arguments.phase != "mcp-contracts":
            parser.error("--cmake requires --phase mcp-contracts")
        arguments.cmake = arguments.cmake.expanduser().resolve()
        if not arguments.cmake.is_file():
            parser.error("--cmake must identify an existing executable file")
    return arguments


def run_native_suite(arguments, run_root):
    architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
    engines = ("TitanEngine", "GleeBug", "StaticEngine") if arguments.engine == "all" else (arguments.engine,)
    results = []
    for architecture in architectures:
        for engine in engines:
            command = [sys.executable, str(ROOT / "x64dbg" / "src" / "tests" / "run.py"),
                       "--arch", architecture, "--engine", engine, "--timeout", str(int(arguments.timeout)),
                       "--artifacts-dir", str(run_root / architecture / engine)]
            if arguments.list:
                command.append("--list")
            command.extend(arguments.case)
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace",
                                     env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            print(process.stdout, flush=True)
            results.append({"architecture": architecture, "engine": engine, "exitCode": process.returncode,
                            "command": command, "stdout": process.stdout})
    write_json(run_root / "native-summary.json", results)
    return int(any(result["exitCode"] for result in results))


def main():
    arguments = parse_arguments()
    if arguments.phase == "native" and arguments.list:
        command = [sys.executable, str(ROOT / "x64dbg" / "src" / "tests" / "run.py"), "--arch",
                   "x64" if arguments.arch == "all" else arguments.arch, "--list", *arguments.case]
        return subprocess.run(command).returncode
    functions = {"defects": cases.DEFECT_CASES, "contracts": cases.CONTRACT_CASES,
                 "surface": cases.SURFACE_CASES}.get(arguments.phase, cases.CASES)
    names = [function.__name__ for function in functions]
    native_surface = arguments.phase == "surface" and arguments.surface_provider == "native"
    if native_surface:
        names = ["test_native_runtime_surface_inventory"]
    if arguments.phase in ("fixtures", "inventory"):
        names = ["test_fixture_oracles" if arguments.phase == "fixtures" else "test_source_inventory"]
    if arguments.phase in ("native", "build"):
        names = [arguments.phase]
    if arguments.phase == "mcp-contracts":
        from native_contracts import CASE_NAMES
        names = list(CASE_NAMES)
    if arguments.phase == "baseline":
        names.extend(("test_peb_autohide_on", "test_peb_autohide_control"))
    selected_names = [name for name in names if not arguments.case or
                      any(fnmatch.fnmatchcase(name, pattern) for pattern in arguments.case)]
    if not selected_names and arguments.phase not in ("native", "build"):
        raise McpError("No cases match the selection")
    if arguments.list:
        print("\n".join(selected_names))
        return 0
    private_root = arguments.output or Path(os.environ["LOCALAPPDATA"]) / "x64dbg-wbbified" / "Verification"
    private_root = private_root.resolve()
    if private_root.is_relative_to(ROOT):
        raise McpError("Evidence must stay outside the project workspace")
    private_root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="wp01-" if arguments.phase == "mcp-contracts" else "wp00-", dir=private_root))
    print(f"Private evidence: {run_root}", flush=True)
    if arguments.phase == "native":
        return run_native_suite(arguments, run_root)
    if arguments.phase == "build":
        architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
        for architecture in architectures:
            build_debugger(run_root, architecture)
        return 0
    if arguments.phase == "mcp-contracts":
        from native_contracts import build_contract_fixture, run_contract_checks
        architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
        results = []
        catalogs = []
        for architecture in architectures:
            try:
                binary = build_contract_fixture(run_root, architecture, arguments.cmake)
                checks, catalog = run_contract_checks(binary, run_root / architecture, architecture, arguments.case, arguments.timeout)
                results.extend(checks)
                catalogs.append(catalog)
            except Exception as error:
                results.append({"architecture": architecture, "name": "environment", "status": "failed", "error": str(error)})
                print(f"[FAILED] {architecture}: {error}", flush=True)
        if len(catalogs) == 2 and (catalogs[0]["contracts"] != catalogs[1]["contracts"] or catalogs[0]["tools"] != catalogs[1]["tools"]):
            results.append({"name": "cross_architecture_contracts", "status": "failed", "error": "Compiled schemas differ"})
        write_json(run_root / "summary.json", {"phase": arguments.phase, "results": results})
        return int(any(result["status"] != "verified" for result in results))
    if arguments.phase == "inventory":
        from inventory import run_inventory
        outcome = run_inventory(run_root, arguments.catalog, arguments.refresh_registries, arguments.runtime_surface)
        write_json(run_root / "summary.json", outcome)
        print(f"Reconciled {outcome['legacy']['count']} legacy tools; parity candidates: {outcome['categories']}", flush=True)
        print("Runtime provider reconciliation remains pending", flush=True)
        return 0
    architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
    results = []
    for architecture in architectures:
        deployment = ROOT / "x64dbg" / "bin" / architecture if native_surface else ROOT / "WinTools" / architecture
        environment = SuiteEnvironment(run_root / architecture, architecture, arguments.deploy or deployment)
        architecture_results = []
        try:
            if not native_surface:
                build_targets(environment)
            if arguments.phase == "surface":
                from inventory import build_inventory_fixture
                build_inventory_fixture(environment, "native" if native_surface else "shipped")
            if native_surface:
                run_native_surface(environment, architecture_results, arguments.timeout)
            if arguments.phase == "fixtures":
                run_fixture_oracles(environment, architecture_results)
            functional = [function for function in functions if function.__name__ in selected_names]
            if functional:
                run_functional(environment, functional, architecture_results, arguments.timeout)
            for hidden, name in ((True, "test_peb_autohide_on"), (False, "test_peb_autohide_control")):
                if name in selected_names:
                    run_hide_case(environment, hidden, architecture_results, arguments.timeout)
        except Exception as error:
            architecture_results.append({"name": "environment", "status": "failed", "error": str(error)})
            print(f"[FAILED] {architecture}: {error}", flush=True)
        finally:
            executed = {result["name"] for result in architecture_results}
            for name in selected_names:
                if name not in executed:
                    architecture_results.append({"name": name, "status": "verification_pending",
                                                 "reason": "The environment failed before this case executed"})
            environment.retain(architecture_results, arguments.phase)
        results.extend({**result, "architecture": architecture} for result in architecture_results)
    failed = [result for result in results if result["status"] != "verified"]
    write_json(run_root / "summary.json", {"schemaVersion": 1, "observedAtUtc": datetime.now(timezone.utc).isoformat(),
               "phase": arguments.phase, "requestedCases": selected_names, "results": results})
    print(f"Result: {len(results) - len(failed)}/{len(results)} verified; evidence: {run_root}", flush=True)
    return int(bool(failed))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except McpError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
