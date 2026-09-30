import os
import re
import subprocess

from wi_driver import McpError, read_kv

REQUIRED_TOOLS = {"LoadBinary", "run", "GetDebugState", "StopDebug", "SetBreakpoint",
                  "DeleteAllBreakpoints", "ListBreakpoints", "GetAllRegisters", "SetRegister",
                  "ReadMemory", "WriteMemToAddress", "AllocateMemory", "FreeMemory", "Assemble",
                  "Disassemble", "ListModules", "GetMemoryMap", "GetPEB", "GetThreads",
                  "GetCallStack", "GetExports", "EvalExpression", "StepInto", "Echo",
                  "ExecuteDebuggerCommand", "GetEventLog"}


def test_echo(wi):
    assert "suite-ping-42" in wi.call("Echo", {"message": "suite-ping-42"})


def test_tools_catalog(wi):
    names = wi.list_tools()
    missing = REQUIRED_TOOLS - set(names)
    assert not missing, "missing tools: %s" % sorted(missing)
    assert len(names) >= 70, "only %d tools exposed" % len(names)


def test_state_idle(wi):
    wi.safe_stop()
    st = wi.state()
    assert st.get("isDebugging") == "false", str(st)
    assert st.get("status") == "NO_TARGET", str(st)


def test_eval_expression(wi):
    assert wi.eval_int("1+2*3") == 7


def test_exitmark_run_to_completion(wi):
    wi.safe_stop()
    wi.wipe_markers()
    r = wi.load(wi.fixture("exitmark"))
    assert "SUCCESS" in r, r[:200]
    info = wi.resume_until()
    assert info["terminated"], "debuggee did not terminate, last state: %s" % info["last"]
    assert os.path.exists(wi.marker("exitmark")), "marker file missing"
    kv = read_kv(wi.marker("exitmark"))
    assert kv.get("marker") == "done", str(kv)
    return {"marker": kv, "execution": info}


def load_paused_at_bp(wi, bp_expr):
    wi.safe_stop()
    wi.wipe_markers()
    r = wi.load(wi.fixture("bpmain"))
    assert "SUCCESS" in r, r[:200]
    r = wi.call("SetBreakpoint", {"target": bp_expr})
    assert "Breakpoint" in r, r[:200]
    addr = wi.eval_int(bp_expr)
    assert addr != 0, "unresolved breakpoint expression %s" % bp_expr
    info = wi.resume_until(bp_addr=addr, stop_at_bp=True)
    assert info["bp_hits"] >= 1, "breakpoint never hit, last state: %s" % info["last"]
    return addr


def test_breakpoint_hits(wi):
    addr = load_paused_at_bp(wi, "bpmain.exe:brk_target")
    lst = wi.call("ListBreakpoints")
    assert "0x%X" % addr in lst, lst[:300]
    info = wi.resume_until(marker=wi.marker("bpmain"), bp_addr=addr)
    assert os.path.exists(wi.marker("bpmain")), "marker file missing"
    kv = read_kv(wi.marker("bpmain"))
    assert kv.get("marker") == "done", str(kv)
    assert kv.get("hits") == "2", str(kv)
    assert info["bp_hits"] >= 1, "expected second bp hit, got %d, last state: %s" % (info["bp_hits"], info["last"])
    wi.safe_stop()
    return {"marker": kv, "breakpointAddress": "0x%X" % addr, "execution": info}


def test_inspection_at_breakpoint(wi):
    addr = load_paused_at_bp(wi, "bpmain.exe:brk_target")

    regs = wi.registers()
    assert regs.get("rip") == addr, "rip %s != bp %X" % (regs.get("rip"), addr)
    assert regs.get("rsp", 0) != 0, "rsp is zero, regs: %s" % regs

    base = wi.eval_int("bpmain.exe:base")
    assert base != 0, "module base unresolved"
    mz = wi.read_bytes(base, 2)
    assert mz == b"MZ", "got %r at base 0x%X" % (mz, base)

    dis = wi.call("Disassemble", {"address": "0x%X" % addr, "count": 1})
    assert "|" in dis and "0x%X" % addr in dis, dis[:200]

    wi.call("SetRegister", {"register": "rax", "value": "0x1234"})
    assert wi.registers().get("rax") == 0x1234, "SetRegister did not take effect"

    alloc = wi.call("AllocateMemory", {"size": 4096})
    m = re.search(r"at (0x[0-9A-Fa-f]+)", alloc)
    assert m, alloc[:200]
    mem = int(m.group(1), 16)

    wi.call("WriteMemToAddress", {"address": "0x%X" % mem, "byteString": "90 90 C3"})
    rb = wi.read_bytes(mem, 3)
    assert rb == b"\x90\x90\xc3", "write/readback got %r" % rb

    wi.call("WriteMemToAddress", {"address": "0x%X" % mem, "byteString": "B8 01 00 00 00"})
    ab = wi.read_bytes(mem, 5)
    assert ab == b"\xb8\x01\x00\x00\x00", "code write/readback got %r" % ab
    dis2 = wi.call("Disassemble", {"address": "0x%X" % mem, "count": 1})
    assert "moveax,1" in dis2.replace(" ", "").lower(), dis2[:200]

    wi.call("FreeMemory", {"address": "0x%X" % mem})

    peb = wi.call("GetPEB")
    assert "ImageBase: 0x%X" % base in peb, peb[:300]

    mods = wi.call("ListModules")
    for mod in ("bpmain.exe", "ntdll.dll", "kernel32"):
        assert mod in mods, "%s missing from module list" % mod

    mmap = wi.call("GetMemoryMap")
    assert "RW-" in mmap, mmap[:300]

    threads = wi.call("GetThreads")
    assert "Main Thread" in threads, threads[:200]

    stack = wi.call("GetCallStack")
    assert "#0" in stack, stack[:200]

    exports = wi.call("GetExports", {"module": "kernel32"})
    assert "LoadLibrary" in exports, exports[:300]

    wi.call("StepInto")
    assert wi.registers().get("rip") != addr, "StepInto did not advance rip"

    wi.call("DeleteAllBreakpoints")
    lst = wi.call("ListBreakpoints")
    assert "0x%X" % addr not in lst, lst[:300]

    info = wi.resume_until(marker=wi.marker("bpmain"))
    assert os.path.exists(wi.marker("bpmain")), "marker file missing, last state: %s" % info["last"]
    kv = read_kv(wi.marker("bpmain"))
    assert kv.get("hits") == "2", str(kv)
    wi.safe_stop()
    return {"marker": kv, "registers": regs, "moduleHeader": mz.hex(), "writtenBytes": rb.hex(),
            "execution": info}


def test_eventlog_and_command(wi):
    wi.safe_stop()
    wi.wipe_markers()
    r = wi.load(wi.fixture("exitmark"))
    assert "SUCCESS" in r, r[:200]
    log = wi.call("GetEventLog", {"count": 8})
    assert "Events" in log, log[:200]
    wi.call("ExecuteDebuggerCommand", {"command": "ClearLog"})
    assert wi.eval_int("1+1") == 2
    wi.safe_stop()


CASES = [
    test_echo,
    test_tools_catalog,
    test_state_idle,
    test_eval_expression,
    test_exitmark_run_to_completion,
    test_breakpoint_hits,
    test_inspection_at_breakpoint,
    test_eventlog_and_command,
]


def test_launch_arguments_roundtrip(wi):
    wi.safe_stop()
    wi.wipe_markers()
    intended = ["", "two words", 'a"b', "trail\\", "comma,value", "{braces}", "Hu Tao \u2764", "run"]
    response = wi.load(wi.fixture("launch_arguments"), arguments=subprocess.list2cmdline(intended))
    assert "SUCCESS" in response, response[:300]
    execution = wi.resume_until(marker=wi.marker("launch_arguments"))
    assert os.path.exists(wi.marker("launch_arguments")), "Argument marker missing: %s" % execution["last"]
    observed = read_kv(wi.marker("launch_arguments"))
    actual = [bytes.fromhex(observed["argv%d" % index]).decode("utf-16-le")
              for index in range(1, int(observed["argc"]))]
    assert actual == intended, "actual=%r intended=%r" % (actual, intended)
    return {"expectedArguments": intended, "actualArguments": actual, "marker": observed}


def test_assembly_executes_patch(wi):
    wi.safe_stop()
    wi.wipe_markers()
    response = wi.load(wi.fixture("patch_canary"))
    assert "SUCCESS" in response, response[:300]
    expression = "patch_canary.exe:patch_value"
    wi.call("SetBreakpoint", {"target": expression})
    address = wi.eval_int(expression)
    assert address, "Patch fixture export unresolved"
    execution = wi.resume_until(bp_addr=address, stop_at_bp=True)
    assert execution["bp_hits"] == 1, "Patch fixture breakpoint was not hit"
    wi.call("DeleteAllBreakpoints")
    original = wi.read_bytes(address, 16)
    response = wi.call("Assemble", {"address": "0x%X" % address, "instruction": "mov eax, 42"})
    encoded = wi.read_bytes(address, 5)
    assert encoded == bytes.fromhex("b82a000000"), "Assemble installed %s: %s" % (encoded.hex(), response)
    wi.call("Assemble", {"address": "0x%X" % (address + 5), "instruction": "ret"})
    assert wi.read_bytes(address, 6) == bytes.fromhex("b82a000000c3"), "Patched function bytes differ"
    execution = wi.resume_until(marker=wi.marker("patch_canary"))
    assert os.path.exists(wi.marker("patch_canary")), "Patched execution marker missing: %s" % execution["last"]
    observed = read_kv(wi.marker("patch_canary"))
    assert observed["value"] == "42", "Patched function returned %s" % observed["value"]
    return {"originalBytes": original.hex(), "installedBytes": "b82a000000c3", "marker": observed}


DEFECT_CASES = [test_launch_arguments_roundtrip, test_assembly_executes_patch]


def test_legacy_idle_contract_capture(wi):
    wi.safe_stop()
    observations = []
    for tool in wi.environment.legacy_catalog:
        payload = {"jsonrpc": "2.0", "id": wi.rid, "method": "tools/call",
                   "params": {"name": tool["name"], "arguments": {}}}
        wi.rid += 1
        response = wi.raw(payload)
        assert response and response.get("id") == payload["id"], "Missing matching response: %s" % tool["name"]
        assert ("result" in response) != ("error" in response), "Invalid response envelope: %s" % tool["name"]
        observations.append({"name": tool["name"], "arguments": {}, "response": response})
    assert wi.state().get("status") == "NO_TARGET", "Default calls started an unexpected target"
    return {"scope": "idle defaults and omitted required arguments", "observations": observations}


def test_runtime_surface_inventory(wi):
    from inventory import capture_runtime_surface
    return capture_runtime_surface(wi)


CONTRACT_CASES = [test_legacy_idle_contract_capture]
SURFACE_CASES = [test_runtime_surface_inventory]
