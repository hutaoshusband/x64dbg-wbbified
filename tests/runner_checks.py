from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import json
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from wi_driver import KERNEL, McpError, OwnedJob, file_identity, process_identity, write_json


KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
KERNEL.WaitForSingleObject.restype = wintypes.DWORD
KERNEL.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
KERNEL.GetExitCodeProcess.restype = wintypes.BOOL
KERNEL.SuspendThread.argtypes = [wintypes.HANDLE]
KERNEL.SuspendThread.restype = wintypes.DWORD

RUNNER_FIXTURE = """import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(sys.argv[2])
mode = sys.argv[1]
if mode == "child":
    (root / "child-started").write_text(str(os.getpid()))
    time.sleep(60)
else:
    (root / "runner-started").write_text(str(os.getpid()))
    output = None if mode == "pipe" else subprocess.DEVNULL
    if mode != "startup":
        child = subprocess.Popen([sys.executable, "-B", __file__, "child", str(root)],
                                 stdout=output, stderr=output)
        (root / "child-pid").write_text(str(child.pid))
    deadline = time.monotonic() + 10
    while not (root / "release").exists():
        if time.monotonic() >= deadline:
            os._exit(97)
        time.sleep(0.01)
    os._exit(0 if mode == "pipe" else 37)
"""


def wait_for_path(path, future):
    deadline = time.monotonic() + 10
    while not path.exists():
        if future.done():
            raise McpError(f"Runner exited before publishing {path.name}: {future.result()}")
        if time.monotonic() >= deadline:
            raise McpError(f"Runner did not publish {path.name}")
        time.sleep(0.01)


def observe_terminal(handle, identity):
    observed = process_identity(type("ProcessHandle", (), {"pid": identity["pid"], "_handle": handle})())
    assert observed == identity
    assert KERNEL.WaitForSingleObject(handle, 5000) == 0, f"Owned process remains alive: {identity}"
    exit_code = wintypes.DWORD()
    if not KERNEL.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        raise ctypes.WinError(ctypes.get_last_error())
    return {"processIdentity": observed, "terminalObserved": True, "exitCode": exit_code.value}


def run_runner_checks(run_command, run_root, run_suite):
    result = {"name": "test_native_runner_ownership", "status": "verified", "observations": []}
    fixture = run_root / "runner-fixture.py"
    fixture.write_text(RUNNER_FIXTURE, encoding="utf-8", newline="\n")
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    try:
        for mode in ("abrupt", "pipe"):
            root = run_root / mode
            root.mkdir()
            handles = []
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_command, [sys.executable, "-B", str(fixture), mode, str(root)], environment, 3)
                try:
                    wait_for_path(root / "child-pid", future)
                    wait_for_path(root / "child-started", future)
                    identities = []
                    for marker in ("runner-started", "child-pid"):
                        pid = int((root / marker).read_text())
                        handle = KERNEL.OpenProcess(0x101000, False, pid)
                        if not handle:
                            raise ctypes.WinError(ctypes.get_last_error())
                        handles.append(handle)
                        identities.append(process_identity(type("ProcessHandle", (), {"pid": pid, "_handle": handle})()))
                    (root / "release").touch()
                    receipt = future.result(timeout=10)
                    assert receipt["processIdentity"] == identities[0]
                    assert receipt["exitCode"] == (0 if mode == "pipe" else 37)
                    assert receipt["timedOut"] == (mode == "pipe")
                    assert receipt["jobClosed"] and receipt["terminalObserved"]
                    assert receipt["startupObservation"]["previousSuspendCount"] == 1
                    assert receipt["startupObservation"]["processIdentity"] == identities[0]
                    terminals = [observe_terminal(handle, identity) for handle, identity in zip(handles, identities)]
                    result["observations"].append({"mode": mode, "receipt": receipt, "terminalProcesses": terminals})
                finally:
                    (root / "release").touch()
                    for handle in handles:
                        KERNEL.CloseHandle(handle)
        for reject in (False, True):
            root = run_root / ("rejected" if reject else "suspended")
            root.mkdir()
            owned_processes = []

            class ObservedJob(OwnedJob):
                def assign(self, process):
                    owned_processes.append(process)
                    time.sleep(0.2)
                    assert not (root / "runner-started").exists(), "Runner executed before job assignment"
                    if reject:
                        raise McpError("Injected job assignment failure")
                    super().assign(process)

            command = [sys.executable, "-B", "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                       str(root / "runner-started")]
            with patch.dict(run_command.__globals__, {"OwnedJob": ObservedJob}):
                if reject:
                    try:
                        run_command(command, environment, 3)
                    except McpError as error:
                        assert str(error) == "Injected job assignment failure"
                        receipt = error.runnerReceipt
                        assert not receipt["jobAssigned"] and receipt["startupObservation"] == {}
                    else:
                        raise AssertionError("Rejected assignment started a runner")
                else:
                    receipt = run_command(command, environment, 3)
                    assert receipt["exitCode"] == 0 and not receipt["timedOut"]
            assert (root / "runner-started").exists() == (not reject)
            terminal = observe_terminal(int(owned_processes[0]._handle), process_identity(owned_processes[0]))
            assert receipt["processIdentity"] == terminal["processIdentity"]
            assert receipt["jobClosed"] and receipt["terminalObserved"]
            result["observations"].append({"mode": root.name, "receipt": receipt, "terminalProcesses": [terminal],
                                           "effectObserved": not reject})
        native_resume = KERNEL.ResumeThread
        for previous_count in (0, 1, 2):
            root = run_root / f"startup-count-{previous_count}"
            root.mkdir()
            owned_processes = []
            control = {"expectedPreviousCount": previous_count, "calls": []}

            class ObservedStartupJob(OwnedJob):
                def assign(self, process):
                    owned_processes.append(process)
                    assert not (root / "runner-started").exists()
                    super().assign(process)

            def controlled_resume(thread):
                control["ownerPid"] = KERNEL.GetProcessIdOfThread(thread)
                assert control["ownerPid"] == owned_processes[0].pid
                if previous_count == 0:
                    early = native_resume(thread)
                    control["earlyResumePreviousCount"] = early
                    assert early == 1
                    deadline = time.monotonic() + 2
                    while not (root / "runner-started").exists():
                        assert time.monotonic() < deadline, "Early resumed fixture did not execute"
                        time.sleep(0.01)
                    assert int((root / "runner-started").read_text()) == control["ownerPid"]
                elif previous_count == 2:
                    extra = KERNEL.SuspendThread(thread)
                    control["extraSuspendPreviousCount"] = extra
                    assert extra == 1
                actual = native_resume(thread)
                control["calls"].append(actual)
                if previous_count == 2:
                    still_suspended = KERNEL.SuspendThread(thread)
                    control["remainingSuspendCount"] = still_suspended
                    assert still_suspended == 1
                    assert native_resume(thread) == 2
                    time.sleep(0.1)
                    assert not (root / "runner-started").exists()
                return actual

            mode = "startup" if previous_count == 0 else "single"
            command = [sys.executable, "-B", str(fixture), mode, str(root)] if previous_count == 0 else [
                sys.executable, "-B", "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                str(root / "runner-started")]
            with patch.dict(run_command.__globals__, {"OwnedJob": ObservedStartupJob}), patch.object(KERNEL, "ResumeThread", controlled_resume):
                if previous_count == 1:
                    receipt = run_command(command, environment, 3)
                    assert receipt["exitCode"] == 0 and not receipt["timedOut"]
                else:
                    try:
                        run_command(command, environment, 3)
                    except McpError as error:
                        assert str(error) == f"Runner startup thread was not suspended exactly once: observed {previous_count}"
                        receipt = error.runnerReceipt
                    else:
                        raise AssertionError("Unexpected suspend count admitted")
            assert control["calls"] == [previous_count]
            identity = process_identity(owned_processes[0])
            startup = receipt["startupObservation"]
            assert receipt["processIdentity"] == identity == startup["processIdentity"]
            assert startup["previousSuspendCount"] == previous_count
            assert startup["ownerPid"] == identity["pid"]
            assert startup["threadIds"] == [startup["threadId"]]
            assert startup["stage"] == ("complete" if previous_count == 1 else "resume-thread")
            assert receipt["jobAssigned"] and receipt["jobClosed"] and receipt["terminalObserved"]
            assert (root / "runner-started").exists() == (previous_count != 2)
            terminal = observe_terminal(int(owned_processes[0]._handle), identity)
            result["observations"].append({"mode": root.name, "control": control, "receipt": receipt,
                                           "terminalProcesses": [terminal], "effectObserved": previous_count != 2})
        for architecture in ("x64", "x32"):
            for failed_stage, failed_call in (("discovery", 1), ("execution", 2)):
                root = run_root / f"native-{architecture}-{failed_stage}"
                root.mkdir()
                owned_processes = []
                transitions = []

                class ObservedSuiteJob(OwnedJob):
                    def assign(self, process):
                        owned_processes.append(process)
                        super().assign(process)

                def controlled_suite_resume(thread):
                    index = len(transitions) + 1
                    extra = KERNEL.SuspendThread(thread) if index == failed_call else None
                    if extra is not None:
                        assert extra == 1
                    actual = native_resume(thread)
                    transitions.append({"ownerPid": KERNEL.GetProcessIdOfThread(thread),
                                        "extraSuspendPreviousCount": extra, "previousSuspendCount": actual})
                    return actual

                arguments = SimpleNamespace(arch=architecture, engine="TitanEngine", timeout=3, case=["cmdline_init"])
                with patch.dict(run_command.__globals__, {"OwnedJob": ObservedSuiteJob}), patch.object(KERNEL, "ResumeThread", controlled_suite_resume):
                    status = run_suite(arguments, root)
                assert status == 1, "Native phase accepted a failed startup"
                records = json.loads((root / "native-summary.json").read_text())
                assert len(records) == 1
                receipt = records[0]
                assert receipt["stage"] == failed_stage
                assert receipt["architecture"] == architecture and receipt["engine"] == "TitanEngine"
                assert receipt["error"] == "Runner startup thread was not suspended exactly once: observed 2"
                assert receipt["startupObservation"]["previousSuspendCount"] == 2
                assert receipt["processIdentity"] == process_identity(owned_processes[-1])
                assert receipt["startupObservation"]["processIdentity"] == receipt["processIdentity"]
                assert receipt["startupObservation"]["ownerPid"] == receipt["processIdentity"]["pid"]
                assert receipt["terminalObserved"] and receipt["jobAssigned"] and receipt["jobClosed"]
                assert len(owned_processes) == failed_call == len(transitions)
                assert transitions[-1]["previousSuspendCount"] == 2
                assert not receipt["timedOut"]
                if failed_stage == "execution":
                    assert receipt["selectedCases"] == ["cmdline_init"]
                    assert receipt["discovery"]["exitCode"] == 0
                    assert receipt["discovery"]["startupObservation"]["previousSuspendCount"] == 1
                terminals = [observe_terminal(int(process._handle), process_identity(process)) for process in owned_processes]
                result["observations"].append({"mode": root.name, "transitions": transitions,
                                               "receipt": receipt, "phaseExitCode": status,
                                               "terminalProcesses": terminals})
    except Exception as error:
        result.update(status="failed", error=str(error))
    result["fixture"] = file_identity(fixture)
    write_json(run_root / "runner-ownership.json", result)
    print(f"[{result['status'].upper()}] {result['name']}", flush=True)
    if result.get("error"):
        print(result["error"], flush=True)
    return [result]
