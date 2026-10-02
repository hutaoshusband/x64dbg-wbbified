import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import shutil
import uuid

import pefile

from script_checks import CONTROL_SCRIPT, check_script_session, run_script_session
from script_yield_checks import capture_native_target, configure_target_reads, yield_target_model
from wi_driver import KERNEL, file_identity, write_json


WORKFLOW_PHASES = ("initial", "before", "patched", "executed", "restored", "complete")
WORKFLOW_STATES = ("gPatchMode", "gPatchMutation", "gPatchPhase", "gPatchCompleted", "gPatchVerified", "gPatchPid", "gPatchThread", "gPatchImageBase")


def workflow_script(target):
    return ('varnew $workflow_counter, 0\nsettingset Engine, HideDebugger, 0\nsettingset Events, TlsCallbacks, 0\n'
            'settingset Events, SystemBreakpoint, 1\nsettingset Events, EntryBreakpoint, 1\n'
            'init "' + str(target) + '"\nvarnew $startup_stops, 0\nawait_entry:\n'
            'cmp cip, patch_canary:entry\nje entry_ready\ninc $startup_stops\n'
            'cmp $startup_stops, .64\njb advance_startup\nret\nadvance_startup:\nrun\njmp await_entry\nentry_ready:\n'
            'mov dword:[patch_canary:gPatchMode], 1\nmov dword:[patch_canary:gPatchMutation], 1\n'
            'workflowbegin\nbp patch_canary:PatchReady\nbp patch_canary:PatchFinish\nrun\n'
            'workflowobserve initial\ninc $workflow_counter\nrun\nworkflowobserve before\n'
            'workflowpatch\nworkflowobserve patched\nworkflowpersist\ninc $workflow_counter\nrun\n'
            'workflowobserve executed\nworkflowrestore\nworkflowobserve restored\ninc $workflow_counter\n'
            'bpd patch_canary:PatchReady\nrun\nworkflowobserve complete\nbpd patch_canary:PatchFinish\nrun\nret\n')


def workflow_target_model(target):
    model = yield_target_model(target)
    assert model["artifact"]["size"] <= 2 * 1024 * 1024, "Workflow source image exceeds its bounded fixture size"
    with pefile.PE(str(target)) as image:
        exports = {symbol.name.decode("ascii").lstrip("_"): symbol.address for symbol in image.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name}
        for name in ("PatchFinish", "gPatchMutation", "gPatchVerified", "gPatchValues"):
            assert name in exports, "Workflow target source exports differ"
            model["exports"][name] = exports[name]
        model["patchOffset"] = image.get_offset_from_rva(exports["PatchValue"]) + 1
    return model


class WorkflowObserver:
    def __init__(self, model, child):
        self.model = model
        self.child = child
        self.events = {}
        self.handle = None
        self.capture = {"snapshots": [], "exit": None}

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None
        for event in self.events.values():
            KERNEL.CloseHandle(event)
        self.events.clear()

    def __enter__(self):
        configure_target_reads()
        KERNEL.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        KERNEL.CreateEventW.restype = wintypes.HANDLE
        KERNEL.SetEvent.argtypes = [wintypes.HANDLE]
        KERNEL.SetEvent.restype = wintypes.BOOL
        try:
            for phase in WORKFLOW_PHASES:
                name = "Local\\WininspectScriptWorkflow-" + str(uuid.uuid4())
                event = KERNEL.CreateEventW(None, True, False, name)
                if event:
                    self.events[phase] = event
                if not event or ctypes.get_last_error() == 183:
                    raise OSError("Workflow could not own a fresh target observation gate")
                self.child["WI_WORKFLOW_GATE_" + phase] = name
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, kind, error, trace):
        self.close()

    def observe(self, line, process, deadline):
        if line.startswith("WORKFLOW_TARGET "):
            fields = dict(item.split("=", 1) for item in line.split()[1:])
            phase = fields["phase"]
            assert phase in self.events and phase not in [row["phase"] for row in self.capture["snapshots"]], "Workflow repeated or changed its held observation phase"
            if self.handle is None:
                self.handle = KERNEL.OpenProcess(0x101010, False, int(fields["pid"]))
                if not self.handle:
                    raise ctypes.WinError(ctypes.get_last_error())
            self.capture["snapshots"].append(capture_native_target(self.handle, fields, self.model, WORKFLOW_STATES, True))
            assert KERNEL.SetEvent(self.events[phase]), "Workflow target observation gate could not resume"
        elif line.startswith("WORKFLOW_EXIT "):
            assert self.handle and self.capture["exit"] is None, "Workflow exit omits its admitted target or repeats"
            exit_code = wintypes.DWORD()
            if not KERNEL.GetExitCodeProcess(self.handle, ctypes.byref(exit_code)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.capture["exit"] = {"wait": KERNEL.WaitForSingleObject(self.handle, 0), "exitCode": exit_code.value}


def run_workflow_session(runtime, plugin, scope, engine, timeout, run_owned):
    profile = scope / "userdir"
    profile.mkdir(parents=True)
    (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={0 if engine == 'TitanEngine' else 1}\nNoConsoleWindow=1\nNoScriptTimeout=1\n", encoding="utf-8")
    target, saved, report = scope / "patch_canary.exe", scope / "generated.exe", scope / "report.txt"
    shutil.copy2(runtime / "tests/patch_canary.exe", target)
    model = workflow_target_model(target)
    source, finite = scope / "workflow.txt", scope / "\u590d\u7528.txt"
    source.write_text(workflow_script(target), encoding="utf-8", newline="\n")
    finite.write_text(CONTROL_SCRIPT, encoding="utf-8", newline="\n")
    child = dict(os.environ, WI_WORKFLOW_SAVE=str(saved), WI_WORKFLOW_REPORT=str(report))
    child.pop("WININSPECT_TEST_NORMAL", None)
    operations = ['scriptexec "' + str(source) + '"', "workflowfinish", "vardel $workflow_counter", "load " + str(finite), "scriptrun", "unloadapi"]
    expected = [(1, 3), (1, 3), (1, 0), (1, 0), (1, 3), (1, 3)]
    required = [plugin, runtime / "headless.exe", runtime / "wininspect.dll", runtime / "winbridge.dll",
                runtime / ("TitanEngine.dll" if engine == "TitanEngine" else "GleeBug/TitanEngine.dll")]
    with WorkflowObserver(model, child) as observer:
        receipt = run_script_session([str(runtime / "headless.exe"), "-userdir", str(profile), "-plugin", str(plugin)], operations, child, timeout, required,
                                     observe_line=observer.observe)
    normal = run_owned([str(saved)], dict(os.environ, WININSPECT_TEST_NORMAL="1", WININSPECT_TEST_PATCH_MODE="2"), timeout) if saved.is_file() else None
    return {"engine": engine, "receipt": receipt, "operations": operations, "expected": expected, "requiredModules": [file_identity(path) for path in required],
            "model": model, "osCapture": observer.capture, "source": file_identity(source), "finite": file_identity(finite),
            "targetAfter": file_identity(target), "saved": file_identity(saved) if saved.is_file() else None,
            "savedBytes": saved.read_bytes().hex() if saved.is_file() else None,
            "report": file_identity(report) if report.is_file() else None, "reportBytes": report.read_bytes().hex() if report.is_file() else None,
            "normal": normal}


def check_workflow_session(item):
    receipt, model, capture = item["receipt"], item["model"], item["osCapture"]
    check_script_session(receipt, item["operations"], item["expected"])
    assert [tuple(row) for row in item["expected"]] == [(1, 3), (1, 3), (1, 0), (1, 0), (1, 3), (1, 3)] and len(item["operations"]) == 6, "Workflow request plan differs from the declared source effects"
    assert item["requiredModules"] and all(row in receipt["loadedModules"] for row in item["requiredModules"]), "Workflow loaded different exact engine/provider artifacts"
    lines = [line for line in receipt["stdout"].splitlines() if line.startswith("WORKFLOW_TARGET ")]
    rows = [dict(field.split("=", 1) for field in line.split()[1:]) for line in lines]
    assert [row["phase"] for row in rows] == list(WORKFLOW_PHASES) and [row["phase"] for row in capture["snapshots"]] == list(WORKFLOW_PHASES), "Workflow native/independent OS captures omit, repeat or change a stop"
    codes = ["b807000000c3", "b807000000c3", "b82a000000c3", "b82a000000c3", "b807000000c3", "b807000000c3"]
    values = [[0, 0, 0], [7, 0, 0], [7, 0, 0], [7, 42, 0], [7, 42, 0], [7, 42, 7]]
    assert [row["bytes"] for row in rows] == codes and [row["values"] for row in rows] == [",".join(map(str, value)) for value in values], "Workflow original/patched/restored code or executed target effects differ"
    assert [row["counter"] for row in rows] == ["0", "1", "1", "2", "2", "3"] and [row["targetPhase"] for row in rows] == ["1", "2", "2", "3", "3", "4"], "Workflow source execution or actual target phase differs"
    assert [row["completed"] for row in rows] == ["0", "1", "1", "2", "2", "3"] and [row["verified"] for row in rows] == ["0"] * 5 + ["1"] and [row["hits"] for row in rows] == ["1", "2", "2", "3", "3", "4"], "Workflow callback or executed-call sequence differs"
    assert all(row["mode"] == row["mutation"] == "1" and row["overflow"] == "0" and row["ip"] == row["osIp"] and row["wait"] == "258" for row in rows), "Workflow state, event bound, Windows context or liveness differs"
    owner = receipt["startupThread"]
    assert all(int(row["owner"]) == owner and int(row["worker"]) != owner and int(row["worker"]) > 0 for row in rows), "Workflow script commands ran on a different GUI owner or worker"
    assert len({(row["pid"], row["creation"], row["thread"], row["worker"], row["base"], row["address"]) for row in rows}) == 1, "Workflow target generation/thread/module or worker changed"
    base, pid, thread = int(rows[0]["base"], 16), int(rows[0]["pid"]), int(rows[0]["thread"])
    assert model["machine"] in (0x8664, 0x14C) and model["pointerSize"] == (8 if model["machine"] == 0x8664 else 4) and 0 < base < 2 ** (model["pointerSize"] * 8), "Workflow target pointer architecture differs"
    assert all(int(row["address"], 16) == base + model["exports"]["PatchValue"] for row in rows), "Workflow patch address differs from its independent PE export"
    assert [int(row["ip"], 16) for row in rows] == [base + model["exports"]["PatchReady"]] * 5 + [base + model["exports"]["PatchFinish"]], "Workflow stopped at a different target function"
    for index, snapshot in enumerate(capture["snapshots"]):
        assert snapshot["processIdentity"] == {"pid": pid, "creationTime": rows[0]["creation"]} and snapshot["artifact"] == model["artifact"] and snapshot["base"] == base, "Independent workflow OS target image/generation differs"
        assert snapshot["code"] == codes[index] and snapshot["callValues"] == values[index] and snapshot["wait"] == 258 and snapshot["exitCode"] == 259 and snapshot["threadOwner"] == pid, "Independent workflow OS code, actual calls, target liveness or thread differs"
        assert snapshot["values"] == {"gPatchMode": 1, "gPatchMutation": 1, "gPatchPhase": int(rows[index]["targetPhase"]), "gPatchCompleted": int(rows[index]["completed"]),
                                      "gPatchVerified": int(rows[index]["verified"]), "gPatchPid": pid, "gPatchThread": thread, "gPatchImageBase": base}, "Independent OS target state differs from its executed phase"
    assert capture["exit"] == {"wait": 0, "exitCode": 56}, "Independent target handle did not observe script completion with exit 56"
    assert receipt["stdout"].splitlines().count("WORKFLOW_SAVED patches=1 selected=1 tracked=3") == 1, "Workflow export omits or includes a different selected patch range"
    exits = re.findall(r"^WORKFLOW_EXIT actual=(\d+) callback=(\d+) observed=(\d+) wait=(\d+) values=(\d+,\d+,\d+) worker=(\d+)$", receipt["stdout"], re.MULTILINE)
    assert exits == [("56", "56", "1", "0", "7,42,7", rows[0]["worker"])], "Native script target handle/callback exit differs"
    safe_reads = re.findall(r"^WORKFLOW_SAFE_READ phase=(before|after) pid=(\d+) handle=([0-9a-f]+) address=([0-9a-f]+) result=([01]) copied=(\d+) code=([0-9a-f]{12}) worker=(\d+) error=(\d+)$", receipt["stdout"], re.MULTILINE)
    assert len(safe_reads) == 2 and [row[0] for row in safe_reads] == ["before", "after"], "Workflow omits or repeats a native safe read across target retirement"
    assert [tuple(row[index] for index in (4, 5, 6)) for row in safe_reads] == [("1", "6", "b807000000c3"), ("0", "0", "000000000000")], "Native safe read changed live code or failed to reject the retired target"
    assert all(int(row[1]) == pid and int(row[3], 16) == base + model["exports"]["PatchValue"] and row[7] == rows[0]["worker"] for row in safe_reads), "Native safe read used a different target/address/worker"
    assert safe_reads[0][2] == safe_reads[1][2] and int(safe_reads[0][2], 16) > 0, "Native safe read changed its borrowed engine handle"
    assert item["targetAfter"] == model["artifact"], "Workflow altered its source executable"
    original = Path(model["artifact"]["path"]).read_bytes()
    expected_file = bytearray(original)
    expected_file[model["patchOffset"]] = 42
    assert item["saved"] and bytes.fromhex(item["savedBytes"]) == bytes(expected_file), "Workflow generated executable differs outside its independently mapped single code byte"
    assert item["report"] and bytes.fromhex(item["reportBytes"]) == b"original=7\npatched=42\nrestored=7\nsum=56\n", "Workflow report differs from its actual executed values/exit"
    normal = item["normal"]
    assert normal and normal["exitCode"] == 42 and normal["terminalObserved"] and normal["jobClosed"] and not normal["timedOut"], "Fresh normal generated executable did not execute 42"
    assert normal["command"] == [item["saved"]["path"]], "Fresh normal process executed a different generated artifact"
    fields = dict(line.split("=", 1) for line in normal["stdout"].splitlines())
    assert fields["pid"] == str(normal["processIdentity"]["pid"]) and fields["mode"] == "2" and fields["mutation"] == "0" and fields["phase"] == "4", "Saved executable normal process identity/selection differs"
    assert fields["completed"] == fields["verified"] == "1" and fields["sum"] == fields["value0"] == "42" and fields["marker0"] == "patched", "Saved executable omitted its actual executed patched canary"
    return {"targetIdentity": capture["snapshots"][0]["processIdentity"], "actualValues": [7, 42, 7], "targetExitCode": 56,
            "savedExitCode": 42, "changedFileOffset": model["patchOffset"], "scriptWorker": int(rows[0]["worker"]), "finiteCounter": 3}


def workflow_negative_controls(item):
    receipt, capture = item["receipt"], item["osCapture"]
    output = receipt["stdout"]
    candidates = [("missing_terminal", {"receipt": {**receipt, "terminalObserved": False}}),
                  ("wrong_owner", {"receipt": {**receipt, "startupThread": receipt["startupThread"] + 1}}),
                  ("missing_workflow_stop", {"receipt": {**receipt, "stdout": output.replace("phase=patched", "phase=omitted", 1)}}),
                  ("missing_restoration", {"receipt": {**receipt, "stdout": re.sub(r"(phase=restored .+ bytes=)b807000000c3", r"\g<1>b82a000000c3", output)}}),
                  ("wrong_executed_value", {"receipt": {**receipt, "stdout": output.replace("values=7,42,0", "values=7,7,0", 1)}}),
                  ("wrong_windows_context", {"receipt": {**receipt, "stdout": re.sub(r"osIp=[0-9a-f]+", "osIp=0", output, count=1)}}),
                  ("callback_overflow", {"receipt": {**receipt, "stdout": output.replace("overflow=0", "overflow=1", 1)}}),
                  ("wrong_native_exit", {"receipt": {**receipt, "stdout": output.replace("actual=56 callback=56", "actual=63 callback=63", 1)}}),
                  ("wrong_finite_reuse", {"receipt": {**receipt, "stdout": output.replace("command=scriptrun result=1 counter=3", "command=scriptrun result=1 counter=2", 1)}}),
                  ("missing_retired_safe_read", {"receipt": {**receipt, "stdout": re.sub(r"^WORKFLOW_SAFE_READ phase=after .+\n", "", output, flags=re.MULTILINE)}}),
                  ("wrong_live_safe_read", {"receipt": {**receipt, "stdout": re.sub(r"(WORKFLOW_SAFE_READ phase=before .+ code=)b807000000c3", r"\g<1>b82a000000c3", output)}}),
                  ("admitted_retired_safe_read", {"receipt": {**receipt, "stdout": re.sub(r"(WORKFLOW_SAFE_READ phase=after .+ )result=0 copied=0", r"\g<1>result=1 copied=6", output)}}),
                  ("missing_os_stop", {"osCapture": {**capture, "snapshots": capture["snapshots"][:-1]}}),
                  ("wrong_os_patch", {"osCapture": {**capture, "snapshots": [*capture["snapshots"][:2], {**capture["snapshots"][2], "code": "b807000000c3"}, *capture["snapshots"][3:]]}}),
                  ("wrong_os_execution", {"osCapture": {**capture, "snapshots": [*capture["snapshots"][:3], {**capture["snapshots"][3], "callValues": [7, 7, 0]}, *capture["snapshots"][4:]]}}),
                  ("wrong_os_thread_owner", {"osCapture": {**capture, "snapshots": [{**capture["snapshots"][0], "threadOwner": 0}, *capture["snapshots"][1:]]}}),
                  ("wrong_os_exit", {"osCapture": {**capture, "exit": {"wait": 0, "exitCode": 63}}}),
                  ("wrong_saved_bytes", {"savedBytes": item["savedBytes"] + "00"}),
                  ("wrong_report", {"reportBytes": b"original=7\npatched=7\nrestored=7\nsum=21\n".hex()}),
                  ("wrong_fresh_exit", {"normal": {**item["normal"], "exitCode": 7}}),
                  ("wrong_fresh_artifact", {"normal": {**item["normal"], "command": [item["model"]["artifact"]["path"]]}}),
                  ("missing_fresh_canary", {"normal": {**item["normal"], "stdout": item["normal"]["stdout"].replace("value0=42", "value0=7", 1)}}),
                  ("wrong_patch_offset", {"model": {**item["model"], "patchOffset": item["model"]["patchOffset"] + 1}}),
                  ("wrong_pe_export", {"model": {**item["model"], "exports": {**item["model"]["exports"], "PatchReady": 0}}})]
    rejected = []
    for name, changed in candidates:
        assert any(item[key] != value for key, value in changed.items()), "Workflow negative control did not change evidence: " + name
        try:
            check_workflow_session({**item, **changed})
        except (AssertionError, ValueError, KeyError) as error:
            rejected.append({"name": name, "status": "rejected", "error": str(error), "scriptExecuted": False})
        else:
            raise AssertionError("Native script workflow negative control was admitted: " + name)
    return rejected


def run_workflow_oracles(environment, runtime, plugin, engines, timeout, run_owned):
    observations = []
    for engine in engines:
        scope = environment.root / "script-workflow" / engine / "\u5de5\u4f5c\u6d41"
        item = run_workflow_session(runtime, plugin, scope, engine, timeout, run_owned)
        write_json(scope / "receipt.json", item)
        reference = check_workflow_session(item)
        controls = workflow_negative_controls(item)
        observations.append({"engine": engine, "receipt": item, "reference": reference, "negativeControls": controls})
        print(f"[VERIFIED] Native {environment.architecture} {engine} script workflow executes 7/42/7, target exit 56, report and fresh generated exit 42", flush=True)
    return observations
