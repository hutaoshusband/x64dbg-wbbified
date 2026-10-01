from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import os
import sys
import time
from unittest.mock import patch

from wi_driver import KERNEL, McpError, OwnedJob, file_identity, process_identity, write_json


KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
KERNEL.WaitForSingleObject.restype = wintypes.DWORD
KERNEL.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
KERNEL.GetExitCodeProcess.restype = wintypes.BOOL

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


def run_runner_checks(run_command, run_root):
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
                    else:
                        raise AssertionError("Rejected assignment started a runner")
                else:
                    receipt = run_command(command, environment, 3)
                    assert receipt["exitCode"] == 0 and not receipt["timedOut"]
            assert (root / "runner-started").exists() == (not reject)
            terminal = observe_terminal(int(owned_processes[0]._handle), process_identity(owned_processes[0]))
            result["observations"].append({"mode": root.name, "terminalProcesses": [terminal],
                                           "effectObserved": not reject})
    except Exception as error:
        result.update(status="failed", error=str(error))
    result["fixture"] = file_identity(fixture)
    write_json(run_root / "runner-ownership.json", result)
    print(f"[{result['status'].upper()}] {result['name']}", flush=True)
    if result.get("error"):
        print(result["error"], flush=True)
    return [result]
