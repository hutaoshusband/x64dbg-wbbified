import argparse
import ctypes
from datetime import datetime, timezone
import fnmatch
import os
import re
from pathlib import Path
import sys
import subprocess
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

import cases
from wi_driver import CREATE_SUSPENDED, McpError, OwnedJob, ROOT, SuiteEnvironment, WinInspect, build_debugger, build_targets, file_identity, loaded_modules, process_identity, read_kv, resume_suspended_process, write_json


def native_fixture_identity(environment, name):
    binary = ROOT / "x64dbg" / "bin" / environment.architecture / "tests" / f"{name}.exe"
    if not binary.is_file():
        raise McpError("Native fixtures are missing; run --phase build for the selected architecture")
    binary_identity = file_identity(binary)
    image = binary.read_bytes()
    assert len(image) >= 64 and image[:2] == b"MZ", f"Native fixture {name} has no PE header"
    pe_offset = int.from_bytes(image[0x3c:0x40], "little")
    assert pe_offset <= len(image) - 6 and image[pe_offset:pe_offset + 4] == b"PE\0\0"
    machine = int.from_bytes(image[pe_offset + 4:pe_offset + 6], "little")
    assert machine == (0x8664 if environment.architecture == "x64" else 0x14c), f"Native fixture {name} has the wrong architecture"
    return binary, binary_identity, machine


def run_native_argument_oracles(environment, results):
    intended_arguments = ["Hu Tao \u2764\ufe0f", 'quoted "word"\\']
    observations = []
    normal_environment = {**os.environ, "WININSPECT_TEST_NORMAL": "1"}
    for name in ("cmdline_init", "cmdline_setcommandline"):
        binary, binary_identity, machine = native_fixture_identity(environment, name)
        command = [str(binary), *intended_arguments]
        ownership = OwnedJob()
        process = None
        try:
            process = subprocess.Popen(command, cwd=environment.targets, env=normal_environment,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            identity = process_identity(process)
            ownership.assign(process)
            stdout, stderr = process.communicate(timeout=10)
        finally:
            if process is not None and process.poll() is None:
                ownership.close()
                process.kill()
                process.communicate()
            ownership.close()
        stdout_path = environment.root / f"{name}-normal.txt"
        stdout_path.write_bytes(stdout)
        observed = read_kv(stdout_path)
        assert process.returncode == 0 and not stderr, f"Normal native fixture {name} failed"
        assert {key: observed[key] for key in ("ready", "startupCallback", "crtArgc", "winArgc")} == {
            "ready": "1", "startupCallback": "1", "crtArgc": "3", "winArgc": "3"}
        decoded = {key: bytes.fromhex(observed[key]).decode("utf-16-le")
                   for key in ("commandLine", "crtArgv1", "crtArgv2", "winArgv1", "winArgv2")}
        assert [decoded["crtArgv1"], decoded["crtArgv2"]] == intended_arguments
        assert [decoded["winArgv1"], decoded["winArgv2"]] == intended_arguments
        assert decoded["commandLine"] == subprocess.list2cmdline(command)
        assert file_identity(binary) == binary_identity
        observations.append({"name": name, "binary": binary_identity, "command": command, "processIdentity": identity,
                             "exitCode": process.returncode, "stdout": file_identity(stdout_path), "observed": observed,
                             "intendedArguments": intended_arguments, "machine": machine, "debuggerUsed": False})
    results.append({"name": "test_native_argument_oracles", "status": "verified", "oracle": observations})
    print(f"[VERIFIED] Two normal native {environment.architecture} argument outcomes", flush=True)


def run_native_guard_page_oracles(environment, results):
    binary, binary_identity, machine = native_fixture_identity(environment, "guard_page")
    receipt = run_owned_native_command([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1"}, 10)
    assert receipt["exitCode"] == 0 and not receipt["timedOut"], "Normal guard-page fixture failed"
    stdout = environment.root / "guard-page-normal.txt"
    stdout.write_text(receipt["stdout"], encoding="utf-8", newline="\n")
    observed = dict(line.split("=", 1) for line in receipt["stdout"].splitlines() if "=" in line)
    expected = {"ready": "1", "completed": "1", "value": "1", "exceptionCount": "1", "exceptionCode": "80000001",
                "exceptionAtPage": "1", "protection": "00000040", "pageBytes": "6a0158c3"}
    assert observed == expected, f"Normal guard-page outcome differs: {observed}"
    assert file_identity(binary) == binary_identity
    results.append({"name": "test_native_guard_page_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "receipt": receipt, "stdout": file_identity(stdout),
        "expected": expected, "observed": observed, "debuggerUsed": False}})
    print(f"[VERIFIED] Normal native {environment.architecture} guard-page outcome", flush=True)


def run_native_stale_breakpoint_oracles(environment, results):
    binary, binary_identity, machine = native_fixture_identity(environment, "swbp_stale")
    receipt = run_owned_native_command([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1"}, 15)
    write_json(environment.root / "stale-breakpoint-normal.json", receipt)
    assert receipt["exitCode"] == 0 and not receipt["timedOut"], "Normal stale-breakpoint fixture failed"
    expected = {"readyWorkers": "64", "completedWorkers": "64", "failedWorkers": "0", "escapedBreakpoints": "0",
                "phase": "2", "waitSucceeded": "1"}
    lines = receipt["stdout"].splitlines()
    assert len(lines) == len(expected) and all(line.count("=") == 1 for line in lines), "Worker summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert observed == expected, f"Normal worker outcomes differ: {observed}"
    assert file_identity(binary) == binary_identity
    results.append({"name": "test_native_stale_breakpoint_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "receipt": receipt, "expected": expected,
        "observed": observed, "debuggerUsed": False}})
    print(f"[VERIFIED] Normal native {environment.architecture} restored-instruction workers", flush=True)


def run_native_execution_oracles(environment, results):
    binary, binary_identity, machine = native_fixture_identity(environment, "scriptcmd_call")
    receipt = run_owned_native_command([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1"}, 15)
    write_json(environment.root / "execution-canary-normal.json", receipt)
    assert receipt["exitCode"] == 42 and not receipt["timedOut"], "Normal execution canary failed"
    expected = {"phase": "2", "originalValue": "3", "base": "7", "loops": "4", "outerCalls": "4", "innerCalls": "4",
                "evenBranches": "2", "oddBranches": "2", "result": "42"}
    lines = receipt["stdout"].splitlines()
    assert len(lines) == len(expected) and all(line.count("=") == 1 for line in lines), "Execution summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert observed == expected, f"Normal execution outcomes differ: {observed}"
    assert file_identity(binary) == binary_identity
    results.append({"name": "test_native_execution_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "receipt": receipt, "expected": expected,
        "observed": observed, "debuggerUsed": False}})
    print(f"[VERIFIED] Normal native {environment.architecture} nested execution canary", flush=True)


def run_native_register_oracles(environment, results):
    binary, binary_identity, machine = native_fixture_identity(environment, "issue3803")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetEnabledXStateFeatures
    query.argtypes = []
    query.restype = ctypes.c_ulonglong
    enabled_features = query()
    register_count = 16 if environment.architecture == "x64" else 8
    prefix = 0x1020304000000000 if environment.architecture == "x64" else 0
    observations = []
    for sse_only in (False, True):
        child_environment = {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_REGISTER_SSE": "1" if sse_only else "0"}
        receipt = run_owned_native_command([str(binary)], child_environment, 15)
        write_json(environment.root / f"register-context-normal-{'sse' if sse_only else 'available'}.json", receipt)
        assert receipt["exitCode"] == 69 and not receipt["timedOut"], "Normal register target failed"
        lines = receipt["stdout"].splitlines()
        assert len(lines) == 6 + register_count * 3 and all(line.count("=") == 1 for line in lines), "Register summary fields are malformed"
        observed = dict(line.split("=", 1) for line in lines)
        stack = int(observed["stack"], 16)
        assert stack != 0 and stack & 15 == 0 and stack < (1 << (64 if environment.architecture == "x64" else 32)), "Register probe stack is invalid"
        avx_available = not sse_only and enabled_features & 6 == 6
        expected = {"phase": "3", "avxAvailable": "1" if avx_available else "0", "flags": "45", "mxcsr": "1f80",
                    "stack": f"{stack:x}", "verified": "1"}
        for index in range(register_count):
            expected[f"gpr{index}"] = f"{stack if index == 7 else prefix + 0x11223300 + index:x}"
            expected[f"xmm{index}"] = bytes(((index * 32 + lane) ^ 0x5A) & 255 for lane in range(16)).hex()
            expected[f"ymm{index}"] = bytes(((index * 32 + lane) ^ 0x5A) & 255 for lane in range(32)).hex() if avx_available else bytes(32).hex()
        assert observed == expected, f"Normal executed register values differ: {observed}"
        assert file_identity(binary) == binary_identity
        observations.append({"sseOnly": sse_only, "receipt": receipt, "observed": observed, "expected": expected})
    results.append({"name": "test_native_register_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "enabledXStateFeatures": enabled_features,
        "observations": observations, "debuggerUsed": False}})
    print(f"[VERIFIED] Two normal native {environment.architecture} register context references", flush=True)


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


def run_native_memory_oracles(environment, results):
    binary, binary_identity, machine = native_fixture_identity(environment, "membp")
    expected_exits = {1: 255, 2: 510, 3: 90, 4: 345, 5: 51, 6: 102, 7: 188, 8: 100, 9: 255, 10: 510,
                      11: 102, 12: 180, 16: 510, 17: 102, 18: 180, 19: 255, 20: 90, 21: 100, 22: 165, 48: 104}
    observations = []
    modes = [(str(mode), code, True) for mode, code in expected_exits.items()]
    modes.extend((value, 238, True) for value in (None, "15", "not-a-mode", "9" * 40))
    modes.append(("1", 0, False))
    for mode, expected_exit, normal in modes:
        child_environment = dict(os.environ)
        child_environment.pop("WININSPECT_TEST_NORMAL", None)
        child_environment.pop("WININSPECT_TEST_MEMORY_MODE", None)
        if normal:
            child_environment["WININSPECT_TEST_NORMAL"] = "1"
        if mode is not None:
            child_environment["WININSPECT_TEST_MEMORY_MODE"] = mode
        receipt = run_owned_native_command([str(binary)], child_environment, 10)
        assert receipt["exitCode"] == expected_exit and not receipt["timedOut"], f"Normal memory mode {mode!r} differs: {receipt}"
        assert not receipt["stdout"], f"Memory fixture unexpectedly emitted output: {receipt['stdout']}"
        observations.append({"mode": mode, "normalSelected": normal, "expectedExitCode": expected_exit, "receipt": receipt})
    assert file_identity(binary) == binary_identity
    results.append({"name": "test_native_memory_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "observations": observations, "debuggerUsed": False}})
    print(f"[VERIFIED] Twenty-five normal native {environment.architecture} memory exit references", flush=True)


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
    parser.add_argument("--phase", choices=("baseline", "functional", "defects", "contracts", "surface", "fixtures", "inventory", "build", "native", "runner", "mcp-contracts"), default="baseline")
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
    parser.add_argument("--cmake", type=Path, help="CMake executable for the native or mcp-contracts source build")
    parser.add_argument("--msvc-toolset", help="Exact installed MSVC toolset version for the native or mcp-contracts source build")
    parser.add_argument("--unity-build", action="store_true", help="Enable global CMake unity compilation for the mcp-contracts source build")
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
        if arguments.phase not in ("build", "mcp-contracts"):
            parser.error("--cmake requires --phase build or mcp-contracts")
        arguments.cmake = arguments.cmake.expanduser().resolve()
        if not arguments.cmake.is_file():
            parser.error("--cmake must identify an existing executable file")
    if arguments.msvc_toolset:
        if arguments.phase not in ("build", "mcp-contracts"):
            parser.error("--msvc-toolset requires --phase build or mcp-contracts")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", arguments.msvc_toolset):
            parser.error("--msvc-toolset must be an exact numeric version")
    if arguments.unity_build and arguments.phase != "mcp-contracts":
        parser.error("--unity-build requires --phase mcp-contracts")
    return arguments


def run_owned_native_command(command, environment, timeout, required_modules=()):
    timed_out = False
    process = None
    identity = None
    startup_thread = None
    startup_observation = {}
    assigned = False
    failure = None
    stdout = ""
    modules = []
    deadline = time.monotonic() + timeout
    expected_modules = {str(Path(path).resolve()).lower() for path in required_modules}
    with OwnedJob() as ownership:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", env=environment,
                                       creationflags=subprocess.CREATE_NO_WINDOW | CREATE_SUSPENDED)
            identity = process_identity(process)
            ownership.assign(process)
            assigned = True
            startup_thread = resume_suspended_process(process, startup_observation)
            try:
                while expected_modules and not modules and process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        observed_modules = loaded_modules(process)
                        if expected_modules <= {item["path"].lower() for item in observed_modules}:
                            modules = observed_modules
                    except OSError:
                        pass
                    if not modules:
                        time.sleep(0.02)
                stdout, _ = process.communicate(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                ownership.close()
                process.kill()
                stdout, _ = process.communicate()
                stdout += "\n[NATIVE RUNNER TIMEOUT]\n"
        except Exception as error:
            failure = error
        finally:
            if failure is not None:
                ownership.close()
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    stdout, _ = process.communicate()
            elif process is not None and process.poll() is None:
                ownership.close()
                process.kill()
                stdout, _ = process.communicate()
    receipt = {"command": command, "processIdentity": identity, "startupThread": startup_thread,
               "startupObservation": startup_observation, "jobAssigned": assigned,
               "exitCode": process.returncode if process is not None else None,
               "stdout": stdout, "timedOut": timed_out,
               "terminalObserved": process is not None and process.poll() is not None, "jobClosed": True}
    if failure is not None:
        receipt["error"] = str(failure)
        failure.runnerReceipt = receipt
        raise failure
    if expected_modules:
        receipt["loadedModules"] = modules
    return receipt


def run_native_suite(arguments, run_root):
    architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
    engines = ("TitanEngine", "GleeBug", "StaticEngine") if arguments.engine == "all" else (arguments.engine,)
    results = []
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    environment.pop("WININSPECT_TEST_NORMAL", None)
    environment.pop("WININSPECT_TEST_REGISTER_SSE", None)
    environment.pop("WININSPECT_TEST_TRACE_MODE", None)
    environment.pop("WININSPECT_TEST_PATCH_MODE", None)
    for architecture in architectures:
        for engine in engines:
            command = [sys.executable, str(ROOT / "x64dbg" / "src" / "tests" / "run.py"),
                       "--arch", architecture, "--engine", engine, "--timeout", str(int(arguments.timeout)),
                       "--artifacts-dir", str(run_root / architecture / engine)]
            command.extend(arguments.case)
            stage = "discovery"
            discovery = None
            try:
                discovery = run_owned_native_command([*command, "--list"], environment, min(arguments.timeout, 30))
                if discovery["exitCode"] or discovery["timedOut"]:
                    result = {**discovery, "stage": stage}
                else:
                    selected_cases = discovery["stdout"].splitlines()
                    stage = "execution"
                    result = run_owned_native_command(command, environment, arguments.timeout * len(selected_cases) + 30)
                    result.update({"stage": stage, "selectedCases": selected_cases, "discovery": discovery})
            except Exception as error:
                if not hasattr(error, "runnerReceipt"):
                    raise
                result = {**error.runnerReceipt, "stage": stage}
                if discovery is not None:
                    result.update(discovery=discovery, selectedCases=selected_cases)
            print(result["stdout"], flush=True)
            if result.get("error"):
                print(f"[FAILED] {architecture} {engine} {stage}: {result['error']}", flush=True)
            results.append({"architecture": architecture, "engine": engine, **result})
            write_json(run_root / "native-summary.json", results)
    write_json(run_root / "native-summary.json", results)
    return int(any(result.get("error") or result["exitCode"] or result["timedOut"] for result in results))


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
    if arguments.phase == "fixtures":
        names = ["test_fixture_oracles", "test_native_argument_oracles", "test_native_guard_page_oracles", "test_native_memory_oracles",
                 "test_native_database_oracles", "test_native_stale_breakpoint_oracles", "test_native_execution_oracles", "test_native_register_oracles",
                 "test_native_module_oracles", "test_native_exception_oracles", "test_native_thread_oracles", "test_native_trace_oracles", "test_native_patch_oracles",
                 "test_native_file_patch_oracles", "test_native_script_oracles", "test_native_breakin_oracles", "test_native_gui_action_oracles"]
    if arguments.phase == "runner":
        names = ["test_native_runner_ownership"]
    if arguments.phase == "inventory":
        names = ["test_source_inventory", "test_parity_registry_refresh"]
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
    if arguments.phase == "inventory" and (arguments.refresh_registries or arguments.runtime_surface) and "test_source_inventory" not in selected_names:
        raise McpError("Registry refresh and runtime surface reconciliation require test_source_inventory")
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
    if arguments.phase == "runner":
        from runner_checks import run_runner_checks
        results = run_runner_checks(run_owned_native_command, run_root, run_native_suite)
        write_json(run_root / "summary.json", {"phase": arguments.phase, "results": results})
        return int(any(result["status"] != "verified" for result in results))
    if arguments.phase == "native":
        return run_native_suite(arguments, run_root)
    if arguments.phase == "build":
        architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
        for architecture in architectures:
            build_debugger(run_root, architecture, arguments.cmake, arguments.msvc_toolset)
        return 0
    if arguments.phase == "mcp-contracts":
        from native_contracts import build_contract_fixture, run_contract_checks
        architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
        results = []
        catalogs = []
        for architecture in architectures:
            try:
                binary = build_contract_fixture(run_root, architecture, arguments.cmake, arguments.msvc_toolset, arguments.unity_build)
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
        results = []
        if "test_parity_registry_refresh" in selected_names:
            results.append(cases.test_parity_registry_refresh(run_root, arguments.catalog))
            print("[VERIFIED] test_parity_registry_refresh", flush=True)
        outcome = {}
        if "test_source_inventory" in selected_names:
            outcome = run_inventory(run_root, arguments.catalog, arguments.refresh_registries, arguments.runtime_surface)
            results.append({"name": "test_source_inventory", "status": "verified", **outcome})
            print(f"Reconciled {outcome['legacy']['count']} legacy tools; parity candidates: {outcome['categories']}", flush=True)
            print("Runtime provider behavioral acceptance remains pending", flush=True)
        write_json(run_root / "summary.json", {**outcome, "phase": arguments.phase, "results": results})
        return 0
    architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
    results = []
    for architecture in architectures:
        deployment = ROOT / "x64dbg" / "bin" / architecture if native_surface else ROOT / "WinTools" / architecture
        environment = SuiteEnvironment(run_root / architecture, architecture, arguments.deploy or deployment)
        architecture_results = []
        try:
            if not native_surface and (arguments.phase != "fixtures" or "test_fixture_oracles" in selected_names):
                build_targets(environment)
            if arguments.phase == "surface":
                from inventory import build_inventory_fixture
                build_inventory_fixture(environment, "native" if native_surface else "shipped")
            if native_surface:
                run_native_surface(environment, architecture_results, arguments.timeout)
            if arguments.phase == "fixtures":
                if "test_fixture_oracles" in selected_names:
                    run_fixture_oracles(environment, architecture_results)
                if "test_native_argument_oracles" in selected_names:
                    run_native_argument_oracles(environment, architecture_results)
                if "test_native_gui_action_oracles" in selected_names:
                    from inventory import run_gui_action_oracles
                    run_gui_action_oracles(environment, architecture_results, arguments.timeout)
                if "test_native_guard_page_oracles" in selected_names:
                    run_native_guard_page_oracles(environment, architecture_results)
                if "test_native_memory_oracles" in selected_names:
                    run_native_memory_oracles(environment, architecture_results)
                if "test_native_stale_breakpoint_oracles" in selected_names:
                    run_native_stale_breakpoint_oracles(environment, architecture_results)
                if "test_native_execution_oracles" in selected_names:
                    run_native_execution_oracles(environment, architecture_results)
                if "test_native_register_oracles" in selected_names:
                    run_native_register_oracles(environment, architecture_results)
                if "test_native_module_oracles" in selected_names:
                    from module_checks import run_module_oracles
                    run_module_oracles(environment, architecture_results, native_fixture_identity, run_owned_native_command)
                if "test_native_exception_oracles" in selected_names:
                    from exception_checks import run_exception_oracles
                    run_exception_oracles(environment, architecture_results, native_fixture_identity, run_owned_native_command)
                if "test_native_breakin_oracles" in selected_names:
                    from breakin_checks import run_breakin_oracles
                    run_breakin_oracles(environment, architecture_results, native_fixture_identity, run_owned_native_command)
                if "test_native_thread_oracles" in selected_names:
                    from thread_checks import run_thread_oracles
                    run_thread_oracles(environment, architecture_results, native_fixture_identity, run_owned_native_command)
                if "test_native_trace_oracles" in selected_names:
                    from trace_checks import run_trace_oracles
                    run_trace_oracles(environment, architecture_results, arguments.engine, arguments.timeout, native_fixture_identity, run_owned_native_command)
                if "test_native_patch_oracles" in selected_names:
                    from patch_checks import run_patch_oracles
                    run_patch_oracles(environment, architecture_results, arguments.engine, arguments.timeout, native_fixture_identity, run_owned_native_command)
                if "test_native_file_patch_oracles" in selected_names:
                    from file_patch_checks import run_file_patch_oracles
                    run_file_patch_oracles(environment, architecture_results, arguments.engine, arguments.timeout, native_fixture_identity, run_owned_native_command)
                if "test_native_script_oracles" in selected_names:
                    from script_checks import run_script_oracles
                    run_script_oracles(environment, architecture_results, arguments.engine, arguments.timeout, native_fixture_identity, run_owned_native_command)
                if "test_native_database_oracles" in selected_names:
                    from database_checks import run_database_oracles
                    run_database_oracles(environment, architecture_results, arguments.engine, arguments.timeout,
                                         native_fixture_identity, run_owned_native_command)
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
