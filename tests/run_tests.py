import argparse
from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cases
from wi_driver import McpError, ROOT, SuiteEnvironment, WinInspect, build_targets, read_kv, write_json


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
    parser.add_argument("--phase", choices=("baseline", "functional"), default="baseline")
    parser.add_argument("--arch", choices=("x64", "x32", "all"), default="x64")
    parser.add_argument("--case", action="append", default=[], help="Select a case name or glob; repeatable")
    parser.add_argument("--deploy", type=Path, help="Read-only source deployment for one architecture")
    parser.add_argument("--output", type=Path, help="Private evidence root outside the repository")
    parser.add_argument("--timeout", type=float, default=45, help="Bound each request and run wait in seconds")
    parser.add_argument("--list", action="store_true", help="List cases without launching or writing files")
    arguments = parser.parse_args()
    if not 1 <= arguments.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if arguments.deploy and arguments.arch == "all":
        parser.error("--deploy requires one architecture")
    return arguments


def main():
    arguments = parse_arguments()
    names = [function.__name__ for function in cases.CASES]
    if arguments.phase == "baseline":
        names.extend(("test_peb_autohide_on", "test_peb_autohide_control"))
    selected_names = [name for name in names if not arguments.case or
                      any(fnmatch.fnmatchcase(name, pattern) for pattern in arguments.case)]
    if not selected_names:
        raise McpError("No cases match the selection")
    if arguments.list:
        print("\n".join(selected_names))
        return 0
    private_root = arguments.output or Path(os.environ["LOCALAPPDATA"]) / "x64dbg-wbbified" / "Verification"
    private_root = private_root.resolve()
    if private_root.is_relative_to(ROOT):
        raise McpError("Evidence must stay outside the project workspace")
    private_root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="wp00-", dir=private_root))
    print(f"Private evidence: {run_root}", flush=True)
    architectures = ("x64", "x32") if arguments.arch == "all" else (arguments.arch,)
    results = []
    for architecture in architectures:
        environment = SuiteEnvironment(run_root / architecture, architecture,
                                       arguments.deploy or ROOT / "WinTools" / architecture)
        architecture_results = []
        try:
            build_targets(environment)
            functional = [function for function in cases.CASES if function.__name__ in selected_names]
            if functional:
                run_functional(environment, functional, architecture_results, arguments.timeout)
            for hidden, name in ((True, "test_peb_autohide_on"), (False, "test_peb_autohide_control")):
                if name in selected_names:
                    run_hide_case(environment, hidden, architecture_results, arguments.timeout)
        except Exception as error:
            architecture_results.append({"name": "environment", "status": "failed", "error": str(error)})
            print(f"[FAILED] {architecture}: {error}", flush=True)
        finally:
            environment.retain(architecture_results)
        executed = {result["name"] for result in architecture_results}
        for name in selected_names:
            if name not in executed:
                architecture_results.append({"name": name, "status": "verification_pending",
                                             "reason": "The environment failed before this case executed"})
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
