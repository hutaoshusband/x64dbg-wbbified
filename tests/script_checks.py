import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

from wi_driver import CREATE_SUSPENDED, McpError, OwnedJob, ROOT, file_identity, loaded_modules, process_identity, resume_suspended_process, write_json


CONTROL_SCRIPT = "varnew $workflow_counter, 0\ninc $workflow_counter\ninc $workflow_counter\ninc $workflow_counter\nret\n"


def run_script_session(command, operations, child, timeout, required):
    output = []
    messages = queue.Queue()
    capture = {"bytes": 0, "truncated": False, "readerError": None}
    deadline = time.monotonic() + timeout
    process, reader, identity, startup_thread, language = None, None, None, None, None
    modules = []
    failure = None
    timed_out = False
    with OwnedJob() as ownership:
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", env=child,
                                       creationflags=subprocess.CREATE_NO_WINDOW | CREATE_SUSPENDED)
            identity = process_identity(process)
            ownership.assign(process)
            startup_thread = resume_suspended_process(process)

            def read_output():
                try:
                    for line in iter(lambda: process.stdout.readline(16384), ""):
                        capture["bytes"] += len(line.encode("utf-8"))
                        if capture["bytes"] <= 2 * 1024 * 1024:
                            output.append(line)
                            messages.put(line)
                        else:
                            capture["truncated"] = True
                except (OSError, ValueError) as error:
                    capture["readerError"] = str(error)
                finally:
                    messages.put(None)

            reader = threading.Thread(target=read_output)
            reader.start()

            def receive():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Script observation exceeded its deadline")
                line = messages.get(timeout=remaining)
                if line is None:
                    raise McpError("Debugger ended before the requested script observation")
                return line

            while language is None:
                match = re.fullmatch(r"SCRIPT_PROVIDER id=(\d+) thread=(\d+)\n", receive())
                if match:
                    language = int(match[1])
            modules = loaded_modules(process)
            assert {str(path).lower() for path in required} <= {entry["path"].lower() for entry in modules}, "Script provider/core modules differ from the selected artifacts"
            for operation in operations:
                process.stdin.write(f"{language}>{operation}\n")
                process.stdin.flush()
                while not receive().startswith("SCRIPT_OBSERVE command=" + operation + " "):
                    pass
            process.stdin.write("exit\n")
            process.stdin.flush()
            process.stdin.close()
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (TimeoutError, queue.Empty, subprocess.TimeoutExpired) as error:
            timed_out = True
            failure = str(error) or "Script observation timed out"
        except (AssertionError, OSError, McpError) as error:
            failure = str(error)
        finally:
            if process is not None and process.poll() is None:
                ownership.close()
                process.kill()
                process.wait(timeout=5)
            if reader is not None:
                reader.join(timeout=5)
                if reader.is_alive():
                    failure = "Script output reader did not terminate"
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                if process.stdout is not None and (reader is None or not reader.is_alive()):
                    process.stdout.close()
            if capture["readerError"]:
                failure = capture["readerError"]
    return {"command": command, "processIdentity": identity, "startupThread": startup_thread,
            "exitCode": process.returncode if process is not None else None, "stdout": "".join(output), "loadedModules": modules,
            "terminalObserved": process is not None and process.poll() is not None, "jobClosed": True, "timedOut": timed_out,
            "error": failure, "outputTruncated": capture["truncated"], "languageId": language, "requestedCommands": operations}


def check_script_session(receipt, operations, expected):
    assert receipt["exitCode"] == 0 and receipt["terminalObserved"] and receipt["jobClosed"] and not receipt["timedOut"] and not receipt["error"] and not receipt["outputTruncated"], "Native script session did not terminate with complete observations"
    output = receipt["stdout"]
    providers = re.findall(r"^SCRIPT_PROVIDER id=(\d+) thread=(\d+)$", output, re.MULTILINE)
    assert providers == [(str(receipt["languageId"]), str(receipt["startupThread"]))], "Script control did not execute in its actual GUI owner"
    assert receipt["requestedCommands"] == operations, "Script request sequence differs from its independent plan"
    observed = re.findall(r"^SCRIPT_OBSERVE command=(.+) result=([01]) counter=(\d+) thread=(\d+)$", output, re.MULTILINE)
    assert observed == [(operation, str(result), str(counter), str(receipt["startupThread"])) for operation, (result, counter) in zip(operations, expected)], "Native script effects, actual stop/resume or invalid-input nonmutation differs"
    assert len(operations) == len(expected) == len(observed), "Script observations omit or repeat a command"
    assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Script reference loaded an external MCP dependency"
    return [{"command": operation, "providerResult": bool(result), "actualCounter": counter} for operation, (result, counter) in zip(operations, expected)]


def script_negative_controls(receipt, operations, expected):
    observed = []
    for name, changed in (("wrong_counter", {"stdout": receipt["stdout"].replace("counter=0", "counter=99", 1)}),
                          ("missing_provider", {"stdout": receipt["stdout"].replace("SCRIPT_PROVIDER ", "IGNORED_PROVIDER ", 1)}),
                          ("missing_command", {"stdout": receipt["stdout"].replace("SCRIPT_OBSERVE ", "IGNORED_COMMAND ", 1)}),
                          ("wrong_owner_thread", {"startupThread": receipt["startupThread"] + 1}),
                          ("missing_terminal", {"terminalObserved": False}), ("truncated_capture", {"outputTruncated": True})):
        try:
            check_script_session({**receipt, **changed}, operations, expected)
        except (AssertionError, ValueError, KeyError) as error:
            observed.append({"name": name, "status": "rejected", "error": str(error), "scriptExecuted": False})
        else:
            raise AssertionError(f"Script negative control was admitted: {name}")
    return observed


def run_script_oracles(environment, results, selected_engine, timeout, fixture_identity, run_owned):
    if selected_engine == "StaticEngine":
        raise McpError("Native script runtime references require TitanEngine or GleeBug")
    engines = ("TitanEngine", "GleeBug") if selected_engine == "all" else (selected_engine,)
    binary, identity, machine = fixture_identity(environment, "script_run_exit")
    runtime = binary.parent.parent
    plugin = runtime / "tests/script_run_exit" / ("script_run_exit.dp64" if machine == 0x8664 else "script_run_exit.dp32")
    source = ROOT / "x64dbg/src/tests/script_run_exit/control.txt"
    assert source.read_text(encoding="utf-8") == CONTROL_SCRIPT and plugin.is_file(), "Native script control fixture is missing or differs"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    normal = run_owned([str(binary)], {**child, "WININSPECT_TEST_NORMAL": "1"}, timeout)
    write_json(environment.root / "script-normal.json", normal)
    assert normal["exitCode"] == 0 and normal["terminalObserved"] and normal["jobClosed"] and not normal["timedOut"] and not normal["stdout"], "Existing normal script target changed"
    cases = [("optional_destination", ["scriptrun .3", "scriptrun"], [(0, 1), (1, 3)]),
             ("legacy_extra_argument", ["scriptrun .3, 0", "scriptrun"], [(0, 1), (1, 3)]),
             ("direct_bridge_destination", ["runapi .3", "scriptrun"], [(1, 1), (1, 3)]),
             ("complete_script", ["scriptrun"], [(1, 3)]),
             ("invalid_destination", ["scriptrun unknown_limit_value", "scriptrun"], [(0, 0), (1, 3)])]
    observations = []
    for engine in engines:
        for name, commands, outcomes in cases:
            scope = environment.root / "script" / engine / name
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            engine_id = 0 if engine == "TitanEngine" else 1
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
            script = scope / "\u63a7\u5236.txt"
            script.write_text(CONTROL_SCRIPT, encoding="utf-8", newline="\n")
            operations, expected = ["load " + str(script), *commands], [(1, 0), *outcomes]
            receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, timeout,
                                         [plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"])
            write_json(scope / "receipt.json", receipt)
            reference = check_script_session(receipt, operations, expected)
            controls = script_negative_controls(receipt, operations, expected)
            observations.append({"engine": engine, "name": name, "script": file_identity(script), "operations": operations,
                                 "expected": expected, "receipt": receipt, "reference": reference, "negativeControls": controls})
        scope = environment.root / "script" / engine / "owned_timeout"
        profile = scope / "userdir"
        profile.mkdir(parents=True)
        engine_id = 0 if engine == "TitanEngine" else 1
        (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
        script = scope / "bounded-control.txt"
        script.write_text("varnew $workflow_counter, 0\nloop:\ninc $workflow_counter\njmp loop\n", encoding="utf-8", newline="\n")
        operations = ["load " + str(script), "scriptrun"]
        receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, min(timeout, 3),
                                     [plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"])
        write_json(scope / "receipt.json", receipt)
        assert receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"] and receipt["error"] and not receipt["outputTruncated"], "Actual unbounded script control was not terminated by its owned deadline"
        assert re.findall(r"^SCRIPT_OBSERVE command=(.+) result=([01]) counter=(\d+) thread=(\d+)$", receipt["stdout"], re.MULTILINE) == [(operations[0], "1", "0", str(receipt["startupThread"]))], "Timeout control failed before its script actually loaded or invented a completion"
        try:
            check_script_session(receipt, operations, [(1, 0), (1, 3)])
        except AssertionError as error:
            timeout_control = {"name": "actual_owned_timeout", "status": "rejected", "error": str(error), "scriptExecuted": True}
        else:
            raise AssertionError("An actually timed-out script was admitted")
        observations.append({"engine": engine, "name": "owned_timeout", "script": file_identity(script), "operations": operations,
                             "receipt": receipt, "negativeControls": [timeout_control]})
        print(f"[VERIFIED] Native {environment.architecture} {engine} optional script destination, Bridge control, exact resume and invalid-input nonmutation", flush=True)
    assert file_identity(binary) == identity, "Script runtime reference changed the existing target"
    results.append({"name": "test_native_script_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourceScript": file_identity(source), "normal": normal, "observations": observations,
        "openGates": ["target workflow and artifact", "script step/branch/breakpoint/IP", "abort/unload/reentrancy/ownership", "library workflow and JavaScript", "platform matrix"]}})
