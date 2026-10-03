import ctypes
from ctypes import wintypes
from pathlib import Path
import re
import time

import pefile

from wi_driver import KERNEL, McpError, file_identity, process_identity


def owned_gui_windows(gui):
    identity = process_identity(gui)
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.EnumWindows.restype = wintypes.BOOL
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetWindowTextW.restype = ctypes.c_int
    user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetClassNameW.restype = ctypes.c_int
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.IsWindowVisible.restype = wintypes.BOOL
    observed = []

    @callback_type
    def collect(window, unused):
        pid = wintypes.DWORD()
        owner = user.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value == gui.pid:
            title, class_name = ctypes.create_unicode_buffer(512), ctypes.create_unicode_buffer(256)
            user.GetWindowTextW(window, title, len(title))
            user.GetClassNameW(window, class_name, len(class_name))
            observed.append({"handle": int(window), "title": title.value, "class": class_name.value, "thread": owner,
                             "processIdentity": identity, "visible": bool(user.IsWindowVisible(window))})
        return True

    assert user.EnumWindows(collect, 0) and len(observed) <= 64, "Owned Qt windows could not be captured within their bound"
    assert process_identity(gui) == identity, "Qt generation changed during its window capture"
    return observed


def observe_script_error(output, gui, owner, deadline, capture):
    while time.monotonic() < deadline and gui.poll() is None:
        dialogs = [window for window in owned_gui_windows(gui) if window["title"].startswith("Error on line ") and window["visible"]]
        if dialogs:
            break
        time.sleep(0.01)
    else:
        raise TimeoutError("Actual failed script command did not produce its owned Qt error dialog")
    assert len(dialogs) == 1 and dialogs[0]["title"] == "Error on line 0004!" and dialogs[0]["class"] == "Qt5QWindowIcon" and dialogs[0]["thread"] == owner, "Actual command error dialog differs"
    dialog = dialogs[0]
    assert dialog in owned_gui_windows(gui), "Owned error dialog changed before explicit acknowledgement"
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.PostMessageW.restype = wintypes.BOOL
    assert user.PostMessageW(dialog["handle"], 0x0010, 0, 0), "Owned command error could not be acknowledged"
    capture.update(dialog=dialog, acknowledged=True)


def yield_script(target):
    return ('varnew $workflow_counter, 0\nscriptguireentryblock\n'
            'settingset Engine, HideDebugger, 0\nsettingset Events, TlsCallbacks, 0\n'
            'settingset Events, SystemBreakpoint, 1\nsettingset Events, EntryBreakpoint, 1\n'
            'init "' + str(target) + '"\nvarnew $startup_stops, 0\nawait_entry:\n'
            'cmp cip, patch_canary:entry\nje entry_ready\ninc $startup_stops\n'
            'cmp $startup_stops, .64\njb advance_startup\nret\nadvance_startup:\n'
            'run\njmp await_entry\nentry_ready:\nmov dword:[patch_canary:gPatchMode], 2\n'
            'bp patch_canary:PatchReady\nrun\ninc $workflow_counter\nret\n')


def yield_target_model(target):
    with pefile.PE(str(target)) as image:
        assert image.FILE_HEADER.Machine in (0x8664, 0x14C), "Yield target architecture differs"
        exports = {symbol.name.decode("ascii").lstrip("_"): symbol.address for symbol in image.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name}
        names = ("PatchReady", "PatchValue", "gPatchMode", "gPatchPhase", "gPatchCompleted", "gPatchPid", "gPatchThread", "gPatchImageBase")
        assert all(name in exports for name in names), "Yield target source exports differ"
        code = image.get_data(exports["PatchValue"], 6).hex()
        assert code == "b807000000c3", "Yield reference lacks the independently declared MOV-7/RET canary"
        return {"artifact": file_identity(target), "machine": image.FILE_HEADER.Machine,
                "pointerSize": 8 if image.FILE_HEADER.Machine == 0x8664 else 4,
                "exports": {name: exports[name] for name in names}, "code": code}


def read_script_observations(path):
    try:
        if not path.is_file():
            return ""
        with path.open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise McpError("GUI script observations exceeded their bound")
        return data.decode("utf-8")
    except PermissionError:
        return ""


def yield_target_rows(text):
    rows = []
    for line in text.splitlines():
        if line.startswith("YIELD_TARGET "):
            fields = [item.split("=", 1) for item in line.split()[1:]]
            assert all(len(item) == 2 for item in fields) and len({item[0] for item in fields}) == len(fields), "Yield target fields repeat or omit values"
            rows.append(dict(fields))
    return rows


def configure_target_reads():
    KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    KERNEL.OpenProcess.restype = wintypes.HANDLE
    KERNEL.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    KERNEL.ReadProcessMemory.restype = wintypes.BOOL
    KERNEL.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    KERNEL.GetExitCodeProcess.restype = wintypes.BOOL
    KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    KERNEL.WaitForSingleObject.restype = wintypes.DWORD
    KERNEL.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    KERNEL.QueryFullProcessImageNameW.restype = wintypes.BOOL
    KERNEL.GetProcessId.argtypes = [wintypes.HANDLE]
    KERNEL.GetProcessId.restype = wintypes.DWORD


def capture_native_target(handle, fields, model, state_fields=("gPatchMode", "gPatchPhase", "gPatchCompleted", "gPatchPid", "gPatchThread", "gPatchImageBase"), call_values=False):
    pid = KERNEL.GetProcessId(handle)
    identity = process_identity(type("TargetHandle", (), {"pid": pid, "_handle": handle})())
    assert identity == {"pid": int(fields["pid"]), "creationTime": fields["creation"]}, "Independent target handle belongs to a different generation"
    path, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
    if not KERNEL.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    artifact = file_identity(Path(path.value))
    assert artifact == model["artifact"], "Actual target executable differs from its private source-built image"
    base = int(fields["base"], 16)

    def read(address, count):
        data, copied = (ctypes.c_ubyte * count)(), ctypes.c_size_t()
        if not KERNEL.ReadProcessMemory(handle, address, data, count, ctypes.byref(copied)) or copied.value != count:
            raise ctypes.WinError(ctypes.get_last_error())
        return bytes(data)

    values = {name: int.from_bytes(read(base + model["exports"][name], model["pointerSize"] if name == "gPatchImageBase" else 4), "little")
              for name in state_fields}
    code = read(base + model["exports"]["PatchValue"], 6).hex()
    thread = KERNEL.OpenThread(0x40, False, values["gPatchThread"])
    if not thread:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        thread_owner = KERNEL.GetProcessIdOfThread(thread)
    finally:
        KERNEL.CloseHandle(thread)
    exit_code = wintypes.DWORD()
    if not KERNEL.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        raise ctypes.WinError(ctypes.get_last_error())
    snapshot = {"phase": fields["phase"], "processIdentity": identity, "artifact": artifact, "base": base,
                "values": values, "code": code, "wait": KERNEL.WaitForSingleObject(handle, 0),
                "exitCode": exit_code.value, "threadOwner": thread_owner}
    if call_values:
        snapshot["callValues"] = [int.from_bytes(read(base + model["exports"]["gPatchValues"] + index * 4, 4), "little") for index in range(3)]
    return snapshot


def observe_script_yield(output, gui, events, model, deadline, capture, scenario="yield"):
    configure_target_reads()
    capture.update(snapshots=[], terminalObserved=False, exitCode=None)
    handle = None
    try:
        for phase, event in zip(("yielded", "aborted" if scenario == "yield_abort" else "unloaded"), events):
            while time.monotonic() < deadline and gui.poll() is None:
                rows = [row for row in yield_target_rows(read_script_observations(output)) if row.get("phase") == phase]
                if rows:
                    assert len(rows) == 1, "Yield observer found a repeated target snapshot"
                    fields = rows[0]
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError("Actual target did not reach its held " + phase + " observation")
            pid = int(fields["pid"])
            if handle is None:
                handle = KERNEL.OpenProcess(0x101010, False, pid)
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
            snapshot = capture_native_target(handle, fields, model)
            snapshot["guiWindows"] = owned_gui_windows(gui)
            capture["snapshots"].append(snapshot)
            assert KERNEL.SetEvent(event), "Owned target observation gate could not resume"
        remaining = max(0, int((deadline - time.monotonic()) * 1000))
        wait = KERNEL.WaitForSingleObject(handle, remaining)
        capture["wait"] = wait
        if wait != 0:
            raise TimeoutError("Explicit native continue did not produce an actual target exit")
        exit_code = wintypes.DWORD()
        if not KERNEL.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        capture.update(terminalObserved=True, exitCode=exit_code.value)
    finally:
        if handle:
            KERNEL.CloseHandle(handle)


def check_script_yield(receipt):
    assert receipt["scenario"] in ("yield", "yield_abort"), "Captured Qt scenario is not a yielded target reference"
    user_abort = receipt["scenario"] == "yield_abort"
    after_phase, after_line = ("aborted", "0") if user_abort else ("unloaded", "4")
    assert receipt["exitCode"] == 0 and receipt["terminalObserved"] and receipt["jobClosed"] and not receipt["timedOut"] and not receipt["error"] and not receipt["outputTruncated"] and not receipt["observationTruncated"], "Yielded Qt reference did not terminate with complete observations"
    assert receipt["requiredModules"] and all(item in receipt["loadedModules"] for item in receipt["requiredModules"]), "Yielded reference loaded different source-built artifacts"
    assert not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Yielded reference loaded an external MCP dependency"
    output, owner = receipt["observed"], receipt["startupThread"]
    rows = yield_target_rows(output)
    assert len(rows) == 2 and [row["phase"] for row in rows] == ["yielded", after_phase], "Yielded target snapshots omit or repeat an observation"
    before, after = rows
    expected = {"alive": "258", "exit": "259", "debugging": "1", "context": "1", "copied": "6", "bytes": "b807000000c3",
                "mode": "2", "targetPhase": "1", "completed": "0", "scriptCounter": "0", "hit": "1", "left": "0", "expired": "0"}
    keys = {"phase", "guiPid", "owner", "worker", "callback", "pid", "creation", "targetThread", "sdkIp", "osIp", "ready", "base", "value", "startupStops", "line", *expected}
    assert set(before) == set(after) == keys and all(before[key] == value for key, value in expected.items()), "Yielded target liveness, context, unchanged code or nonexecution differs"
    assert {key: value for key, value in before.items() if key not in ("phase", "line")} == {key: value for key, value in after.items() if key not in ("phase", "line")}, "Script unload altered its held target, context, source or counter"
    assert before["line"] == "0" and after["line"] == after_line and 0 <= int(before["startupStops"]) < 64, "Yield termination did not retain or clear its source map after bounded actual startup"
    pid, worker, callback = (int(before[key]) for key in ("pid", "worker", "callback"))
    assert int(before["guiPid"]) == receipt["processIdentity"]["pid"] and int(before["owner"]) == owner and pid != receipt["processIdentity"]["pid"], "Yield target/debugger identity or GUI owner differs"
    assert len({owner, worker, callback}) == 3 and min(owner, worker, callback) > 0, "GUI, script worker and actual debug callback are not distinct native threads"
    model, capture = receipt["yieldTargetModel"], receipt["yieldCapture"]
    base = int(before["base"], 16)
    assert model["machine"] in (0x8664, 0x14C) and model["pointerSize"] == (8 if model["machine"] == 0x8664 else 4), "Yield target pointer architecture differs"
    assert 0 < base < 2 ** (8 * model["pointerSize"]) and model["code"] == before["bytes"], "Yield target code differs from its admitted PE source"
    assert int(before["ready"], 16) == base + model["exports"]["PatchReady"] and int(before["value"], 16) == base + model["exports"]["PatchValue"], "Yield target export addresses differ from the independently mapped PE"
    assert before["sdkIp"] == before["osIp"] == before["ready"], "Actual Windows and debugger IP do not identify the held target function"
    assert not capture.get("error") and capture["terminalObserved"] and capture["wait"] == 0 and capture["exitCode"] == 7, "Independent target handle did not observe explicit native exit 7"
    assert [row["phase"] for row in capture["snapshots"]] == ["yielded", after_phase], "Independent OS observations omit the before/after boundary"
    for snapshot in capture["snapshots"]:
        assert snapshot["processIdentity"] == {"pid": pid, "creationTime": before["creation"]} and snapshot["artifact"] == model["artifact"] and snapshot["base"] == base, "Independent OS target generation or executable differs"
        assert snapshot["wait"] == 258 and snapshot["exitCode"] == 259 and snapshot["code"] == model["code"], "Independent OS target was resumed, killed or patched by unload"
        assert snapshot["values"] == {"gPatchMode": 2, "gPatchPhase": 1, "gPatchCompleted": 0, "gPatchPid": pid, "gPatchThread": int(before["targetThread"]), "gPatchImageBase": base} and snapshot["threadOwner"] == pid, "Independent OS target mode, phase, executed count or thread ownership differs"
        assert snapshot["guiWindows"] and all(window["processIdentity"] == receipt["processIdentity"] for window in snapshot["guiWindows"]), "Qt window capture belongs to a different debugger generation"
        assert not any(window["title"].startswith("Error on line ") for window in snapshot["guiWindows"]), "Yielded cancellation produced an actual Qt command error"
    phases = ["ready", "pause_observed", "delete_enter", "delete_leave", "continue_enter", "continue_leave", "reloaded", "reused", "finished"]
    events = re.findall(r"^GUI_REENTRY phase=(\w+) pid=(\d+) thread=(\d+) owner=(\d+) worker=(\d+) nestedThread=(\d+) nestedCount=(\d+) outer=([01]) counter=(\d+) line=(\d+) completed=([01])$", output, re.MULTILINE)
    assert [row[0] for row in events] == phases and all(int(row[1]) == receipt["processIdentity"]["pid"] and int(row[2]) == owner and row[2] == row[3] for row in events), "Yielded GUI events omit, repeat or change owner"
    expected_events = [(0, 0, 0, 0, 0, 4, 0)] + [(worker, 0, 0, 0, 0, int(after_line), 1)] * 5 + [(worker, 0, 0, 0, 0, 0, 1), (worker, 0, 0, 0, 3, 0, 1), (worker, 0, 0, 0, 3, 4, 1)]
    assert [tuple(int(value) for value in row[4:]) for row in events] == expected_events, "Yielded script resumed canceled source, lost worker completion or failed finite reuse/clearing"
    exit_line = "YIELD_EXIT removed=1 resumed=1 wait=0 actual=1 exit=7 callbackExit=7 observed=1 left=1 expired=0 debugging=0 counter=0"
    expected_order = ["GUI_REENTRY"] + ["YIELD_TARGET"] * 2 + ["GUI_REENTRY"] * 5 + ["YIELD_EXIT"] + ["GUI_REENTRY"] * 3
    assert output.splitlines().count(exit_line) == 1 and [line.split()[0] for line in output.splitlines()] == expected_order, "Explicit native deletion/continue/callback/OS exit sequence differs"
    return {"targetIdentity": capture["snapshots"][0]["processIdentity"], "unchangedCode": model["code"], "targetExitCode": 7,
            "guiOwner": owner, "scriptWorker": worker, "debugCallback": callback, "finiteCounter": 3, "lineType": 4}


def yield_negative_controls(receipt):
    output, capture = receipt["observed"], receipt["yieldCapture"]
    candidates = [("missing_terminal", {"terminalObserved": False}), ("truncated_observations", {"observationTruncated": True}),
                  ("wrong_owner", {"startupThread": receipt["startupThread"] + 1}),
                  ("missing_target_snapshot", {"observed": output.replace("phase=aborted" if receipt["scenario"] == "yield_abort" else "phase=unloaded", "phase=omitted", 1)}),
                  ("killed_target", {"observed": output.replace("alive=258", "alive=0", 1)}),
                  ("wrong_windows_context", {"observed": re.sub(r"osIp=[0-9a-f]+", "osIp=0", output, count=1)}),
                  ("patched_target", {"observed": output.replace("bytes=b807000000c3", "bytes=b82a000000c3", 1)}),
                  ("executed_target", {"observed": output.replace("completed=0 scriptCounter", "completed=1 scriptCounter", 1)}),
                  ("resumed_script", {"observed": output.replace("scriptCounter=0", "scriptCounter=1", 1)}),
                  ("wrong_retained_map", {"observed": re.sub(r"(YIELD_TARGET phase=aborted .+ line=)0", r"\g<1>4", output)}) if receipt["scenario"] == "yield_abort" else
                  ("missing_unload", {"observed": re.sub(r"(YIELD_TARGET phase=unloaded .+ line=)4", r"\g<1>0", output)}),
                  ("wrong_target_thread", {"observed": re.sub(r"targetThread=\d+", "targetThread=0", output)}),
                  ("expired_callback", {"observed": output.replace("expired=0", "expired=1", 1)}),
                  ("missing_pause_transition", {"observed": output.replace("phase=pause_observed", "phase=pause_missing", 1)}),
                  ("wrong_target_exit", {"yieldCapture": {**capture, "exitCode": 42}}),
                  ("missing_independent_after", {"yieldCapture": {**capture, "snapshots": capture["snapshots"][:1]}}),
                  ("wrong_os_generation", {"yieldCapture": {**capture, "snapshots": [{**capture["snapshots"][0], "processIdentity": {"pid": 0, "creationTime": "0"}}, capture["snapshots"][1]]}}),
                  ("wrong_os_code", {"yieldCapture": {**capture, "snapshots": [capture["snapshots"][0], {**capture["snapshots"][1], "code": "b82a000000c3"}]}}),
                  ("wrong_os_thread_owner", {"yieldCapture": {**capture, "snapshots": [{**capture["snapshots"][0], "threadOwner": 0}, capture["snapshots"][1]]}}),
                  ("wrong_pe_rva", {"yieldTargetModel": {**receipt["yieldTargetModel"], "exports": {**receipt["yieldTargetModel"]["exports"], "PatchReady": 0}}}),
                  ("invented_callback_exit", {"observed": output.replace("callbackExit=7", "callbackExit=42", 1)}),
                  ("wrong_finite_reuse", {"observed": output.replace("counter=3", "counter=2", 1)}),
                  ("missing_final_clear", {"observed": re.sub(r"(phase=finished .+ line=)4", r"\g<1>0", output)}),
                  ("repeated_event", {"observed": output + output.splitlines()[0] + "\n"}),
                  ("missing_gui_artifact", {"loadedModules": [item for item in receipt["loadedModules"] if Path(item["path"]).name.lower() != "wingui.dll"]})]
    rejected = []
    for name, changed in candidates:
        assert any(receipt[key] != value for key, value in changed.items()), "Yield negative control did not change evidence: " + name
        try:
            check_script_yield({**receipt, **changed})
        except (AssertionError, ValueError, KeyError) as error:
            rejected.append({"name": name, "status": "rejected", "error": str(error), "scriptExecuted": False})
        else:
            raise AssertionError("Yielded script negative control was admitted: " + name)
    return rejected
