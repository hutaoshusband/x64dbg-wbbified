import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid

from wi_driver import CREATE_SUSPENDED, KERNEL, McpError, OwnedJob, ROOT, file_identity, loaded_modules, process_identity, resume_suspended_process, write_json


CONTROL_SCRIPT = "varnew $workflow_counter, 0\ninc $workflow_counter\ninc $workflow_counter\ninc $workflow_counter\nret\n"
BRANCH_SCRIPT = "varnew $workflow_counter, 0\nloop:\ninc $workflow_counter\ncmp $workflow_counter, .3\njne loop\nret\n"
LOOP_SCRIPT = "varnew $workflow_counter, 0\nloop:\ninc $workflow_counter\njmp loop\n"
QUEUED_SCRIPT = "varnew $workflow_counter, .99\nloop:\ninc $workflow_counter\njmp loop\n"
WORKER_SCRIPT = "varnew $workflow_counter, 0\ninc $workflow_counter\nscriptunloadprobe\ninc $workflow_counter\nret\n"
INVALID_SCRIPTS = [("missing_file", None, "FileHelper::ReadAllText failed..."),
                   ("empty_label", ":\nret\n", "Empty label detected on line 1!"),
                   ("duplicate_label", "repeat:\nrepeat:\nret\n", 'Duplicate label "repeat" detected on lines 1 and 2!'),
                   ("missing_branch", "jmp missing\nret\n", 'Invalid branch label "missing" detected on line 1!')]


def run_script_session(command, operations, child, timeout, required, required_messages=()):
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
            for message in required_messages:
                while not any(line.rstrip("\r\n") == message for line in output):
                    receive()
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


def script_observations(receipt, operations):
    assert receipt["exitCode"] == 0 and receipt["terminalObserved"] and receipt["jobClosed"] and not receipt["timedOut"] and not receipt["error"] and not receipt["outputTruncated"], "Native script session did not terminate with complete observations"
    output = receipt["stdout"]
    providers = re.findall(r"^SCRIPT_PROVIDER id=(\d+) thread=(\d+)$", output, re.MULTILINE)
    assert providers == [(str(receipt["languageId"]), str(receipt["startupThread"]))], "Script control did not execute in its actual GUI owner"
    assert receipt["requestedCommands"] == operations, "Script request sequence differs from its independent plan"
    observed = re.findall(r"^SCRIPT_OBSERVE command=(.+) result=([01]) counter=(\d+) thread=(\d+)$", output, re.MULTILINE)
    assert len(observed) == len(operations) and [item[0] for item in observed] == operations and all(int(item[3]) == receipt["startupThread"] for item in observed), "Script observations omit, repeat or misattribute a command"
    assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Script reference loaded an external MCP dependency"
    return observed


def check_script_session(receipt, operations, expected, branches=(), parse_message=None):
    observed = script_observations(receipt, operations)
    assert observed == [(operation, str(result), str(counter), str(receipt["startupThread"])) for operation, (result, counter) in zip(operations, expected)], "Native script effects, actual stop/resume or invalid-input nonmutation differs"
    assert len(operations) == len(expected) == len(observed), "Script observations omit or repeat a command"
    metadata = re.findall(r"^SCRIPT_BRANCH result=([01]) type=(\d+) destination=(\d+) label=(\S*)$", receipt["stdout"], re.MULTILINE)
    assert metadata == [(str(result), str(kind), str(destination), label) for result, kind, destination, label in branches], "Native script branch metadata differs from its source label, type or executable destination"
    if parse_message is not None:
        assert receipt["stdout"].splitlines().count(parse_message) == 1, "Native script parse diagnostic differs from its declared invalid source"
    return [{"command": operation, "providerResult": bool(result), "actualCounter": counter} for operation, (result, counter) in zip(operations, expected)]


def check_script_interruption(receipt, operations, kind):
    observed = script_observations(receipt, operations)
    counters = [int(item[2]) for item in observed]
    owner = receipt["startupThread"]
    output = receipt["stdout"]
    assert all(item[1] == "1" for item in observed) and counters[0] == 0, "Script interruption command or initial nonmutation failed"
    assert counters[-3:] == [0, 0, 3] and operations[-3] == "vardel $workflow_counter" and operations[-1] == "scriptrun", "Unloaded script runtime did not execute the fresh finite script"
    active = re.findall(r"^SCRIPT_ACTIVE counter=(\d+) thread=(\d+)$", output, re.MULTILINE)
    interrupted = re.findall(r"^SCRIPT_(ABORT|UNLOAD) active=(\d+) stopped=(\d+) stable=(\d+) line=(\d+) debugging=([01]) thread=(\d+)$", output, re.MULTILINE)
    queued = re.findall(r"^SCRIPT_QUEUED worker=(\d+) owner=(\d+) counter=(\d+) released=([01])$", output, re.MULTILINE)
    drained = re.findall(r"^SCRIPT_QUEUE_DRAIN callback=([01]) wrapper=([01]) line=(\d+) thread=(\d+)$", output, re.MULTILINE)
    worker = re.findall(r"^SCRIPT_WORKER_UNLOAD before=(\d+) after=(\d+) line=(\d+) thread=(\d+)$", output, re.MULTILINE)
    assert not re.findall(r"^SCRIPT_BRANCH ", output, re.MULTILINE), "Interruption reference reported unrelated branch observations"
    if kind in ("abort", "active_unload"):
        assert len(active) == len(interrupted) == 1 and not queued and not drained and not worker, "Active script interruption observations differ"
        event, started, stopped, stable, line, debugging, thread = interrupted[0]
        assert int(active[0][0]) >= 16 and int(active[0][1]) == owner and started == active[0][0], "Infinite script did not actually execute before interruption"
        assert int(started) <= counters[1] <= int(stopped) and stopped == stable and int(thread) == owner and debugging == "0", "Interrupted script continued to execute or changed owner/session"
        assert counters[2] == int(stopped), "Observed interruption counter differs from the stable native counter"
        if kind == "abort":
            assert event == "ABORT" and line == "0" and counters[3] == int(stopped) and operations[2:4] == ["abortapi", "unloadapi"], "Abort did not retain the script until explicit unload"
        else:
            assert event == "UNLOAD" and line == "4" and operations[2] == "activeunloadapi", "Active unload did not clear its line map"
    elif kind in ("queued_run", "queued_step"):
        assert not active and not interrupted and not worker and len(queued) == len(drained) == 1, "Queued unload observations differ"
        thread, gui, counter, released = queued[0]
        assert int(thread) > 0 and int(thread) != owner and int(gui) == owner and counter == "0" and released == "0", "Script execution was not held on the actual worker before unload"
        assert drained == [("1", "0", "4", str(owner))], "Worker callback did not finish with canceled command and cleared map"
        assert counters[1] == 0 and operations[1] == ("queuedrununloadapi" if kind == "queued_run" else "queuedstepunloadapi"), "Pending script execution ran after unload was requested"
    else:
        assert kind == "worker" and not active and not interrupted and not queued and not drained and len(worker) == 1, "Worker unload observations differ"
        before, after, line, thread = worker[0]
        assert before == after == "1" and line == "0" and int(thread) > 0 and int(thread) != owner, "Worker unload destroyed a borrowed script reference or executed the following increment"
        assert counters[1] == 1 and operations[1] == "workerunloadapi", "Deferred worker unload did not finish before its queue barriers"
    return [{"command": item[0], "providerResult": item[1] == "1", "actualCounter": int(item[2])} for item in observed]


def interruption_negative_controls(receipt, operations, kind):
    output = receipt["stdout"]
    candidates = [("missing_terminal", {"terminalObserved": False}), ("truncated_capture", {"outputTruncated": True}),
                  ("wrong_owner", {"startupThread": receipt["startupThread"] + 1}),
                  ("missing_effect", {"stdout": output.replace("SCRIPT_OBSERVE ", "IGNORED_COMMAND ", 1)}),
                  ("wrong_finite_reuse", {"stdout": output.replace("command=scriptrun result=1 counter=3", "command=scriptrun result=1 counter=4", 1)})]
    if kind in ("abort", "active_unload"):
        candidates.extend((("missing_active_execution", {"stdout": output.replace("SCRIPT_ACTIVE ", "IGNORED_ACTIVE ", 1)}),
                           ("continued_execution", {"stdout": re.sub(r"stable=\d+", "stable=0", output, count=1)}),
                           ("wrong_line_map", {"stdout": re.sub(r"line=\d+ debugging=", "line=3 debugging=", output, count=1)})))
    elif kind in ("queued_run", "queued_step"):
        candidates.extend((("released_worker", {"stdout": output.replace("released=0", "released=1", 1)}),
                           ("executed_pending_script", {"stdout": output.replace("counter=0 released=0", "counter=99 released=0", 1)}),
                           ("invented_command_success", {"stdout": output.replace("callback=1 wrapper=0", "callback=1 wrapper=1", 1)})))
    else:
        candidates.extend((("early_map_clear", {"stdout": output.replace("after=1 line=0", "after=1 line=4", 1)}),
                           ("continued_worker_execution", {"stdout": output.replace("before=1 after=1", "before=1 after=2", 1)})))
    rejected = []
    for name, changed in candidates:
        assert any(receipt[key] != value for key, value in changed.items()), f"Interruption negative control did not change evidence: {name}"
        try:
            check_script_interruption({**receipt, **changed}, operations, kind)
        except (AssertionError, ValueError, KeyError) as error:
            rejected.append({"name": name, "status": "rejected", "error": str(error), "scriptExecuted": False})
        else:
            raise AssertionError(f"Script interruption negative control was admitted: {name}")
    return rejected


def run_gui_script_session(runtime, plugin, scope, child, timeout, engine, scenario="unload"):
    assert scenario in ("unload", "reload"), "Unknown Qt script scenario"
    KERNEL.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    KERNEL.CreateEventW.restype = wintypes.HANDLE
    KERNEL.SetEvent.argtypes = [wintypes.HANDLE]
    KERNEL.SetEvent.restype = wintypes.BOOL
    profile = scope / "userdir"
    profile.mkdir(parents=True)
    (profile / "wininspect.ini").write_text(f"[Engine]\nDebugEngine={0 if engine == 'TitanEngine' else 1}\nNoConsoleWindow=1\nNoScriptTimeout=1\n[Misc]\nLoadLastSession=0\n", encoding="utf-8")
    output_path = scope / "observed.txt"
    event_name = "Local\\WininspectGuiReentry-" + str(uuid.uuid4())
    child = dict(child)
    for name in ("QTDIR", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML_IMPORT_PATH", "QML2_IMPORT_PATH", "WININSPECT_TEST_NORMAL"):
        child.pop(name, None)
    queued, finite = scope / "\u6392\u961f.txt", scope / "\u590d\u7528.txt"
    queued.write_text(QUEUED_SCRIPT, encoding="utf-8", newline="\n")
    finite.write_text(CONTROL_SCRIPT, encoding="utf-8", newline="\n")
    child.update(WI_REENTRY_OUTPUT=str(output_path), WI_REENTRY_EVENT=event_name, WI_REENTRY_QUEUED=str(queued), WI_REENTRY_FINITE=str(finite))
    command = [str(runtime / "wininspect.exe"), "-userdir", str(profile), "-plugin", str(plugin), "-c",
               "scriptguireentryreload" if scenario == "reload" else "scriptguireentry"]
    engine_path = runtime / ("TitanEngine.dll" if engine == "TitanEngine" else "GleeBug/TitanEngine.dll")
    required = [file_identity(runtime / name) for name in ("wininspect.exe", "wingui.dll", "wininspect.dll", "winbridge.dll", "Qt5Widgets.dll")]
    required.extend((file_identity(plugin), file_identity(engine_path)))
    process, reader, identity, startup, event = None, None, None, None, None
    modules, output = [], []
    capture = {"bytes": 0, "truncated": False, "readerError": None}
    deadline = time.monotonic() + timeout
    failure, timed_out, observation_truncated = None, False, False
    with OwnedJob() as ownership:
        try:
            event = KERNEL.CreateEventW(None, True, False, event_name)
            if not event or ctypes.get_last_error() == 183:
                raise McpError("GUI reference could not own a fresh capture gate")
            startup_info = subprocess.STARTUPINFO()
            startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup_info.wShowWindow = 0
            process = subprocess.Popen(command, cwd=scope, env=child, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       startupinfo=startup_info, creationflags=subprocess.CREATE_NO_WINDOW | CREATE_SUSPENDED)
            identity = process_identity(process)
            ownership.assign(process)
            startup = resume_suspended_process(process)

            def read_output():
                try:
                    for data in iter(lambda: process.stdout.read(16384), b""):
                        capture["bytes"] += len(data)
                        if capture["bytes"] <= 2 * 1024 * 1024:
                            output.append(data)
                        else:
                            capture["truncated"] = True
                except (OSError, ValueError) as error:
                    capture["readerError"] = str(error)

            reader = threading.Thread(target=read_output)
            reader.start()
            while time.monotonic() < deadline and process.poll() is None:
                if output_path.is_file():
                    if output_path.stat().st_size > 65536:
                        observation_truncated = True
                        raise McpError("GUI script observations exceeded their bound")
                    if "phase=ready " in output_path.read_text(encoding="utf-8"):
                        break
                time.sleep(0.02)
            else:
                raise TimeoutError("Owned Qt GUI did not reach its capture gate")
            modules = loaded_modules(process)
            assert all(item in modules for item in required), "Qt GUI reference loaded different source-built artifacts"
            assert KERNEL.SetEvent(event), "GUI capture gate could not resume its owned probe"
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired) as error:
            timed_out = True
            failure = str(error)
        except (AssertionError, OSError, UnicodeError, McpError) as error:
            failure = str(error)
        finally:
            if event:
                KERNEL.CloseHandle(event)
            if process is not None and process.poll() is None:
                ownership.close()
                process.kill()
                process.wait(timeout=5)
            if reader is not None:
                reader.join(timeout=5)
                if reader.is_alive():
                    failure = "GUI output reader did not terminate"
            if process is not None and process.stdout is not None and (reader is None or not reader.is_alive()):
                process.stdout.close()
            if capture["readerError"]:
                failure = capture["readerError"]
    observed = ""
    if output_path.is_file():
        observation_truncated |= output_path.stat().st_size > 65536
        with output_path.open("rb") as stream:
            observed = stream.read(65536).decode("utf-8", errors="replace")
    return {"scenario": scenario, "command": command, "processIdentity": identity, "startupThread": startup,
            "exitCode": process.returncode if process is not None else None, "terminalObserved": process is not None and process.poll() is not None,
            "jobClosed": True, "timedOut": timed_out, "error": failure, "stdout": b"".join(output).decode("utf-8", errors="replace"),
            "outputTruncated": capture["truncated"], "observationTruncated": observation_truncated,
            "observed": observed, "loadedModules": modules, "requiredModules": required,
            "queuedScript": file_identity(queued), "finiteScript": file_identity(finite),
            "observationFile": file_identity(output_path) if output_path.is_file() else None}


def check_gui_script_session(receipt):
    scenario = receipt.get("scenario", "unload")
    assert scenario in ("unload", "reload"), "Unknown captured Qt script scenario"
    assert receipt["exitCode"] == 0 and receipt["terminalObserved"] and receipt["jobClosed"] and not receipt["timedOut"] and not receipt["error"] and not receipt["outputTruncated"] and not receipt["observationTruncated"], "Qt script reference did not terminate with complete observations"
    assert receipt["requiredModules"] and all(item in receipt["loadedModules"] for item in receipt["requiredModules"]), "Qt script source/loaded-module identities differ"
    assert not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Qt script reference loaded an external MCP dependency"
    rows = re.findall(r"^GUI_REENTRY phase=(\w+) pid=(\d+) thread=(\d+) owner=(\d+) worker=(\d+) nestedThread=(\d+) nestedCount=(\d+) outer=([01]) counter=(\d+) line=(\d+) completed=([01])$", receipt["observed"], re.MULTILINE)
    phases = (["ready", "worker_completed", "reload_enter", "nested_enter", "nested_leave", "reload_canceled", "reloaded", "reused", "finished"]
              if scenario == "reload" else
              ["ready", "queued", "outer_enter", "nested_enter", "nested_leave", "outer_leave", "wrapper_canceled", "reset", "reloaded", "reused", "finished"])
    assert [row[0] for row in rows] == phases and len(receipt["observed"].splitlines()) == len(phases), "Qt script omitted, repeated or changed an actual event"
    pid, owner = receipt["processIdentity"]["pid"], receipt["startupThread"]
    assert all(int(row[1]) == pid and int(row[2]) == owner and row[2] == row[3] for row in rows), "Qt script event belongs to a different PID or GUI owner"
    worker = int(rows[1][4])
    assert worker > 0 and worker != owner and rows[0][4] == "0" and all(int(row[4]) == worker for row in rows[1:]), "Qt script worker was missing, replaced or confused with the GUI owner"
    expected = [(0, 0, 0, 0, 4, 0), (0, 0, 0, 0, 0, 0), (0, 0, 1, 0, 0, 0),
                (owner, 1, 1, 0, 0, 0), (owner, 1, 1, 0, 4, 1), (owner, 1, 1, 0, 4, 1),
                (owner, 1, 0, 0, 4, 1), (owner, 1, 0, 0, 4, 1), (owner, 1, 0, 0, 0, 1),
                (owner, 1, 0, 3, 0, 1), (owner, 1, 0, 3, 4, 1)]
    if scenario == "reload":
        expected = [(0, 0, 0, 0, 4, 0), (0, 0, 0, 0, 4, 1), (0, 0, 1, 0, 4, 1),
                    (owner, 1, 1, 0, 0, 1), (owner, 1, 1, 0, 4, 1), (owner, 1, 1, 0, 4, 1),
                    (owner, 1, 0, 0, 0, 1), (owner, 1, 0, 3, 0, 1), (owner, 1, 0, 3, 4, 1)]
    assert [tuple(int(value) for value in row[5:]) for row in rows] == expected, "Qt nested unload, pending nonmutation, callback completion or finite reuse differs"
    return [{"phase": row[0], "counter": int(row[8]), "lineType": int(row[9]), "guiThread": int(row[2]), "workerThread": int(row[4]), "nestedCount": int(row[6])} for row in rows]


def gui_script_negative_controls(receipt):
    output = receipt["observed"]
    reload = receipt.get("scenario") == "reload"
    canceled = "reload_canceled" if reload else "wrapper_canceled"
    candidates = [("missing_terminal", {"terminalObserved": False}), ("truncated_stdout", {"outputTruncated": True}),
                  ("truncated_observations", {"observationTruncated": True}), ("wrong_owner", {"startupThread": receipt["startupThread"] + 1}),
                  ("wrong_process", {"processIdentity": {**receipt["processIdentity"], "pid": receipt["processIdentity"]["pid"] + 1}}),
                  ("missing_nested_call", {"observed": output.replace("phase=nested_enter", "phase=omitted", 1)}),
                  ("repeated_event", {"observed": output + output.splitlines()[0] + "\n"}),
                  ("wrong_worker", {"observed": re.sub(r"worker=[1-9]\d*", "worker=" + str(receipt["startupThread"]), output)}),
                  ("wrong_nested_owner", {"observed": re.sub(r"nestedThread=[1-9]\d*", "nestedThread=0", output)}),
                  ("missing_outer_wait", {"observed": output.replace("outer=1", "outer=0", 1)}),
                  ("pending_code_executed", {"observed": output.replace("counter=0 line=0", "counter=99 line=0", 1)}),
                  ("missing_worker_completion", {"observed": output.replace("completed=1", "completed=0", 1)}),
                  ("invented_load_completion" if reload else "invented_wrapper_success",
                   {"observed": output.replace("phase=" + canceled, "phase=reload_completed" if reload else "phase=wrapper_success", 1)}),
                  ("wrong_finite_reuse", {"observed": output.replace("counter=3", "counter=4", 1)}),
                  ("missing_final_clear", {"observed": re.sub(r"(phase=finished .+ line=)4", r"\g<1>0", output)}),
                  ("missing_gui_artifact", {"loadedModules": [item for item in receipt["loadedModules"] if Path(item["path"]).name.lower() != "wingui.dll"]})]
    rejected = []
    for name, changed in candidates:
        assert any(receipt[key] != value for key, value in changed.items()), f"Qt negative control did not change evidence: {name}"
        try:
            check_gui_script_session({**receipt, **changed})
        except (AssertionError, ValueError, KeyError) as error:
            rejected.append({"name": name, "status": "rejected", "error": str(error), "scriptExecuted": False})
        else:
            raise AssertionError(f"Qt script negative control was admitted: {name}")
    return rejected


def run_gui_script_oracles(environment, runtime, plugin, engines, timeout):
    stage = environment.root / "script-gui-runtime"
    stage.mkdir()
    for source in runtime.iterdir():
        if source.is_file() and source.suffix.lower() in (".exe", ".dll"):
            shutil.copy2(source, stage / source.name)
    for name in ("platforms", "iconengines", "imageformats", "styles", "GleeBug"):
        if (runtime / name).is_dir():
            shutil.copytree(runtime / name, stage / name)
    (stage / "plugins").mkdir()
    references = []
    for engine in engines:
        for scenario in ("unload", "reload"):
            scope = environment.root / "script-gui" / engine / scenario
            receipt = run_gui_script_session(stage, plugin, scope, os.environ, timeout, engine, scenario)
            write_json(scope / "receipt.json", receipt)
            reference = check_gui_script_session(receipt)
            controls = gui_script_negative_controls(receipt)
            references.append({"engine": engine, "name": "gui_reentrant_" + scenario, "receipt": receipt, "reference": reference, "negativeControls": controls})
            print(f"[VERIFIED] Native {environment.architecture} {engine} actual Qt GUI nested {scenario}, canceled pending step, finite reuse and exit 0", flush=True)
    return references


def script_negative_controls(receipt, operations, expected, branches=(), parse_message=None):
    observed = []
    candidates = [("wrong_counter", {"stdout": receipt["stdout"].replace("counter=0", "counter=99", 1)}),
                  ("missing_provider", {"stdout": receipt["stdout"].replace("SCRIPT_PROVIDER ", "IGNORED_PROVIDER ", 1)}),
                  ("missing_command", {"stdout": receipt["stdout"].replace("SCRIPT_OBSERVE ", "IGNORED_COMMAND ", 1)}),
                  ("wrong_owner_thread", {"startupThread": receipt["startupThread"] + 1}),
                  ("missing_terminal", {"terminalObserved": False}), ("truncated_capture", {"outputTruncated": True})]
    if branches:
        candidates.extend((("wrong_branch_type", {"stdout": receipt["stdout"].replace("type=2 destination=3", "type=1 destination=3", 1)}),
                           ("wrong_branch_destination", {"stdout": receipt["stdout"].replace("destination=3 label=loop", "destination=2 label=loop", 1)}),
                           ("wrong_branch_label", {"stdout": receipt["stdout"].replace("label=loop", "label=wrong", 1)})))
    if parse_message is not None:
        candidates.extend((("missing_parse_error", {"stdout": receipt["stdout"].replace(parse_message, "", 1)}),
                           ("wrong_parse_error", {"stdout": receipt["stdout"].replace(parse_message, "Wrong parse diagnostic", 1)})))
    for name, changed in candidates:
        try:
            check_script_session({**receipt, **changed}, operations, expected, branches, parse_message)
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
    branch_source = source.with_name("branch.txt")
    assert source.read_text(encoding="utf-8") == CONTROL_SCRIPT and branch_source.read_text(encoding="utf-8") == BRANCH_SCRIPT and plugin.is_file(), "Native script control fixture is missing or differs"
    interruption_sources = {"loop": source.with_name("loop.txt"), "queued": source.with_name("queued.txt"), "worker": source.with_name("worker.txt")}
    for name, text in (("loop", LOOP_SCRIPT), ("queued", QUEUED_SCRIPT), ("worker", WORKER_SCRIPT)):
        assert interruption_sources[name].read_text(encoding="utf-8") == text, "Native script interruption source differs"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    normal = run_owned([str(binary)], {**child, "WININSPECT_TEST_NORMAL": "1"}, timeout)
    write_json(environment.root / "script-normal.json", normal)
    assert normal["exitCode"] == 0 and normal["terminalObserved"] and normal["jobClosed"] and not normal["timedOut"] and not normal["stdout"], "Existing normal script target changed"
    cases = [("optional_destination", ["scriptrun .3", "scriptrun"], [(0, 1), (1, 3)]),
             ("legacy_extra_argument", ["scriptrun .3, 0", "scriptrun"], [(0, 1), (1, 3)]),
             ("direct_bridge_destination", ["runapi .3", "scriptrun"], [(1, 1), (1, 3)]),
             ("complete_script", ["scriptrun"], [(1, 3)]),
             ("invalid_destination", ["scriptrun unknown_limit_value", "scriptrun"], [(0, 0), (1, 3)]),
             ("step_and_set_ip", ["stepapi", "stepapi", "setipapi .4", "stepapi", "runapi 0", "unloadapi"],
              [(1, 0), (1, 1), (1, 1), (1, 2), (1, 2), (1, 2)]),
             ("script_breakpoint", ["bptoggleapi .3", "bpgetapi .3", "runapi 0", "bptoggleapi .3", "bpgetapi .3", "runapi 0", "unloadapi"],
              [(1, 0), (1, 0), (1, 1), (1, 1), (0, 1), (1, 3), (1, 3)]),
             ("script_branch", ["branchapi .5", "runapi 0", "unloadapi"], [(1, 0), (1, 3), (1, 3)])]
    observations = []
    for engine in engines:
        for name, commands, outcomes in cases:
            scope = environment.root / "script" / engine / name
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            engine_id = 0 if engine == "TitanEngine" else 1
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
            script = scope / "\u63a7\u5236.txt"
            selected_source = branch_source if name == "script_branch" else source
            script.write_text(selected_source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
            operations, expected = ["load " + str(script), *commands], [(1, 0), *outcomes]
            branches = [(1, 2, 3, "loop")] if name == "script_branch" else []
            receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, timeout,
                                         [plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"])
            write_json(scope / "receipt.json", receipt)
            reference = check_script_session(receipt, operations, expected, branches)
            controls = script_negative_controls(receipt, operations, expected, branches)
            observations.append({"engine": engine, "name": name, "script": file_identity(script), "sourceScript": file_identity(selected_source), "operations": operations, "expectedBranches": branches,
                                 "expected": expected, "receipt": receipt, "reference": reference, "negativeControls": controls})
        interruptions = [("abort", "loop", ["startloopapi", "abortapi", "unloadapi"]),
                         ("active_unload", "loop", ["startloopapi", "activeunloadapi"]),
                         ("queued_run", "queued", ["queuedrununloadapi"]),
                         ("queued_step", "queued", ["queuedstepunloadapi"]),
                         ("worker", "worker", ["workerunloadapi"])]
        for kind, source_name, commands in interruptions:
            scope = environment.root / "script" / engine / kind
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            engine_id = 0 if engine == "TitanEngine" else 1
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\nNoScriptTimeout=1\n", encoding="utf-8")
            script = scope / "\u63a7\u5236.txt"
            finite = scope / "\u590d\u7528.txt"
            selected_source = interruption_sources[source_name]
            script.write_text(selected_source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
            finite.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
            operations = ["load " + str(script), *commands, "vardel $workflow_counter", "load " + str(finite), "scriptrun"]
            receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, timeout,
                                         [plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"])
            write_json(scope / "receipt.json", receipt)
            reference = check_script_interruption(receipt, operations, kind)
            controls = interruption_negative_controls(receipt, operations, kind)
            observations.append({"engine": engine, "name": kind, "script": file_identity(script), "sourceScript": file_identity(selected_source),
                                 "finiteScript": file_identity(finite), "operations": operations, "receipt": receipt, "reference": reference, "negativeControls": controls})
        for name, text, message in INVALID_SCRIPTS:
            scope = environment.root / "script" / engine / name
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            engine_id = 0 if engine == "TitanEngine" else 1
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
            script, finite = scope / "invalid.txt", scope / "\u590d\u7528.txt"
            if text is not None:
                script.write_text(text, encoding="utf-8", newline="\n")
            finite.write_text(CONTROL_SCRIPT, encoding="utf-8", newline="\n")
            operations = ['scriptexec "' + str(script) + '"', "scriptrun", "unloadapi", "load " + str(finite), "scriptrun"]
            expected = [(0, 0), (0, 0), (1, 0), (1, 0), (1, 3)]
            receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, timeout,
                                         [plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"], (message,))
            write_json(scope / "receipt.json", receipt)
            reference = check_script_session(receipt, operations, expected, parse_message=message)
            controls = script_negative_controls(receipt, operations, expected, parse_message=message)
            observations.append({"engine": engine, "name": name, "declaredSource": text, "parseMessage": message,
                                 "script": file_identity(script) if script.is_file() else None, "finiteScript": file_identity(finite),
                                 "operations": operations, "expected": expected, "expectedBranches": [], "receipt": receipt,
                                 "reference": reference, "negativeControls": controls})
        scope = environment.root / "script" / engine / "owned_timeout"
        profile = scope / "userdir"
        profile.mkdir(parents=True)
        engine_id = 0 if engine == "TitanEngine" else 1
        (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
        script = scope / "bounded-control.txt"
        script.write_text(LOOP_SCRIPT, encoding="utf-8", newline="\n")
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
        print(f"[VERIFIED] Native {environment.architecture} {engine} script controls, active abort/unload, canceled queued run/step, deferred worker unload, finite reuse and owned deadline", flush=True)
    gui_observations = run_gui_script_oracles(environment, runtime, plugin, engines, timeout)
    assert file_identity(binary) == identity, "Script runtime reference changed the existing target"
    results.append({"name": "test_native_script_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourceScript": file_identity(source), "branchSourceScript": file_identity(branch_source),
        "interruptionSources": {name: file_identity(path) for name, path in interruption_sources.items()}, "normal": normal, "observations": observations, "guiObservations": gui_observations,
        "openGates": ["target workflow and artifact", "remaining GUI reentrancy and multi-session ownership", "unload while debug-event yielded", "library workflow and JavaScript", "platform matrix"]}})
