import os
import ctypes
from ctypes import wintypes
import time

from wi_driver import McpError, file_identity, write_json


class WaitLock(ctypes.Structure):
    _fields_ = [("name", wintypes.WCHAR * 128), ("timeout", ctypes.c_int64), ("alertable", wintypes.BOOL)]


class WaitThread(ctypes.Structure):
    _fields_ = [("pid", wintypes.DWORD), ("tid", wintypes.DWORD), ("waitTime", wintypes.DWORD), ("switches", wintypes.DWORD)]


class WaitPayload(ctypes.Union):
    _fields_ = [("lock", WaitLock), ("thread", WaitThread)]


class WaitNode(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("status", wintypes.DWORD), ("value", WaitPayload)]


class BasicProcessInformation(ctypes.Structure):
    _fields_ = [("reserved", ctypes.c_void_p), ("peb", ctypes.c_void_p), ("reserved2", ctypes.c_void_p * 2),
                ("pid", ctypes.c_size_t), ("reserved3", ctypes.c_void_p)]


def native_process_state(process):
    from wi_driver import process_identity
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise McpError("The cross-architecture attach oracle requires a 64-bit Windows test host")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    native = ctypes.WinDLL("ntdll")
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    kernel.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.CheckRemoteDebuggerPresent.restype = wintypes.BOOL
    native.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    native.NtQueryInformationProcess.restype = wintypes.LONG
    basic = BasicProcessInformation()
    wow64 = ctypes.c_size_t()
    handle = process._handle
    if native.NtQueryInformationProcess(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic), None) < 0 or basic.pid != process.pid or not basic.peb:
        raise McpError("The owned native process identity/PEB query failed")
    if native.NtQueryInformationProcess(handle, 26, ctypes.byref(wow64), ctypes.sizeof(wow64), None) < 0:
        raise McpError("The owned WoW64 PEB query failed")
    pebs = []
    for kind, address in (("native", basic.peb), ("wow64", wow64.value)):
        if not address:
            continue
        value = ctypes.c_ubyte()
        copied = ctypes.c_size_t()
        if not kernel.ReadProcessMemory(handle, address + 2, ctypes.byref(value), 1, ctypes.byref(copied)) or copied.value != 1 or value.value not in (0, 1):
            raise McpError("The owned BeingDebugged byte could not be independently read")
        pebs.append({"kind": kind, "address": f"{address:x}", "beingDebugged": value.value})
    port = wintypes.BOOL()
    if not kernel.CheckRemoteDebuggerPresent(handle, ctypes.byref(port)):
        raise McpError("The owned native debug port query failed")
    return {"identity": process_identity(process), "pebs": pebs, "debugPortPresent": bool(port.value)}


def wait_for_blocked_thread(process, thread_id, creation_time, timeout=10):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advanced = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
    kernel.GetProcessIdOfThread.restype = wintypes.DWORD
    kernel.GetThreadTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetThreadTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    advanced.OpenThreadWaitChainSession.argtypes = [wintypes.DWORD, ctypes.c_void_p]
    advanced.OpenThreadWaitChainSession.restype = wintypes.HANDLE
    advanced.CloseThreadWaitChainSession.argtypes = [wintypes.HANDLE]
    advanced.GetThreadWaitChain.argtypes = [wintypes.HANDLE, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(WaitNode), ctypes.POINTER(wintypes.BOOL)]
    advanced.GetThreadWaitChain.restype = wintypes.BOOL
    if ctypes.sizeof(WaitNode) != 280 or not 0 < thread_id < 1 << 32:
        raise McpError("Native wait-chain layout or thread ID is invalid")
    handle = kernel.OpenThread(0x40 | 0x100000, False, thread_id)
    if not handle:
        raise McpError("The owned parked thread could not be opened")
    session = None
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if kernel.GetProcessIdOfThread(handle) != process.pid or not kernel.GetThreadTimes(handle, *[ctypes.byref(value) for value in times]):
            raise McpError("Parked thread process/creation identity query failed")
        actual_creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if actual_creation != creation_time:
            raise McpError("Parked thread creation identity does not match the target")
        session = advanced.OpenThreadWaitChainSession(0, None)
        if not session:
            raise McpError("The native wait-chain session could not be opened")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None or kernel.WaitForSingleObject(handle, 0) != 258:
                raise McpError("The owned parked thread exited before its wait was observed")
            count = wintypes.DWORD(16)
            nodes = (WaitNode * 16)()
            cycle = wintypes.BOOL()
            if not advanced.GetThreadWaitChain(session, 0, 0, thread_id, ctypes.byref(count), nodes, ctypes.byref(cycle)):
                raise McpError(f"The native wait-chain query failed: {ctypes.get_last_error()}")
            if not 1 <= count.value <= 16 or cycle.value:
                raise McpError("The native wait-chain result is invalid or cyclic")
            node = nodes[0]
            if node.type != 8 or node.value.thread.pid != process.pid or node.value.thread.tid != thread_id:
                raise McpError("The native wait-chain refers to another process/thread")
            if node.status == 3:
                if kernel.WaitForSingleObject(handle, 0) != 258:
                    raise McpError("The parked thread retired during its wait observation")
                return {"pid": process.pid, "threadId": thread_id, "creationTime": str(actual_creation),
                        "nodeCount": count.value, "objectType": node.type, "objectStatus": node.status,
                        "rawWaitTime": node.value.thread.waitTime, "contextSwitches": node.value.thread.switches}
            time.sleep(0.01)
        raise McpError("The owned thread did not enter an independently observed blocked wait")
    finally:
        if session:
            advanced.CloseThreadWaitChainSession(session)
        kernel.CloseHandle(handle)


def thread_image_facts(binary, machine):
    import pefile
    try:
        image = pefile.PE(str(binary))
        if image.FILE_HEADER.Machine != machine:
            raise McpError("Thread reference has the wrong PE architecture")
        exports = {entry.name.decode("ascii"): entry.address for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
        required = {"ThreadProbe0", "ThreadProbe1", "ThreadStop0", "ThreadStop1", "ThreadReferenceWorker", "ThreadReady", "ThreadHeld", "ThreadFinish", "gThreadValues", "gThreadMode", "gThreadMutation"}
        if not required <= exports.keys():
            raise McpError("Thread reference is missing its declared exports")
        for index, seed in ((0, 0x10203040), (1, 0x50607080)):
            probe, stop = exports[f"ThreadProbe{index}"], exports[f"ThreadStop{index}"]
            store = exports["gThreadValues"] + index * 4
            if stop != probe + 5 or image.get_data(probe, 5) != b"\xb8" + seed.to_bytes(4, "little") or image.get_data(stop, 1) != b"\x90":
                raise McpError("Thread reference has the wrong seeded stop instructions")
            if machine == 0x8664:
                instruction = image.get_data(stop + 1, 7)
                valid = len(instruction) == 7 and instruction[:2] == b"\x89\x05" and stop + 7 + int.from_bytes(instruction[2:6], "little", signed=True) == store and instruction[6] == 0xc3
            else:
                instruction = image.get_data(stop + 1, 6)
                valid = len(instruction) == 6 and instruction[0] == 0xa3 and int.from_bytes(instruction[1:5], "little") == image.OPTIONAL_HEADER.ImageBase + store and instruction[5] == 0xc3
            if not valid:
                raise McpError("Thread reference does not execute its exact accumulator store and return")
        if image.get_data(exports["gThreadMode"], 4) != bytes(4) or image.get_data(exports["gThreadMutation"], 4) != bytes(4):
            raise McpError("Thread reference default selection is invalid")
        return {"machine": machine, "size": image.OPTIONAL_HEADER.SizeOfImage, "exports": exports, "seeds": [0x10203040, 0x50607080]}
    except (pefile.PEFormatError, AttributeError, UnicodeError, ValueError) as error:
        raise McpError("Thread reference PE facts are malformed") from error
    finally:
        if "image" in locals():
            image.close()


def check_thread_output(receipt, facts):
    assert receipt["exitCode"] == 87 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Normal thread reference did not complete with its actual canary exit"
    lines = receipt["stdout"].splitlines()
    assert len(lines) == 30 and all(line.count("=") == 1 for line in lines), "Thread summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert len(observed) == len(lines), "Thread summary fields repeat"
    identity = receipt["processIdentity"]
    main_creation = int(observed["mainCreation"])
    assert int(identity["creationTime"]) <= main_creation < 1 << 64, "Main thread creation predates its owned process"
    expected = {"mutation": "0", "phase": "4", "pid": str(identity["pid"]), "mainTid": str(receipt["startupThread"]), "mainCreation": str(main_creation),
                "extraSuspend": "0", "heldQuery": "1", "heldQueryRelease": "2", "stillHeld": "1", "finalRelease": "1", "releaseEffect": "1", "verified": "1"}
    ids = [receipt["startupThread"]]
    for index, counter, code in ((0, 11, 81), (1, 22, 82)):
        tid, creation = int(observed[f"tid{index}"]), int(observed[f"creation{index}"])
        assert 0 < tid < 1 << 32 and tid not in ids and main_creation <= creation < 1 << 64, "Worker identities are invalid or repeat"
        ids.append(tid)
        expected.update({f"tid{index}": str(tid), f"creation{index}": str(creation), f"entered{index}": "1", f"counter{index}": str(counter),
                         f"value{index}": f"{facts['seeds'][index]:x}", f"exit{index}": str(code), f"done{index}": "1", f"retired{index}": "1", f"initialRelease{index}": "1"})
    assert observed == expected, f"Actual thread outcomes differ: {observed}"
    return observed, expected


def run_thread_oracles(environment, results, fixture_identity, run_owned):
    binary, identity, machine = fixture_identity(environment, "scriptcmd_call_threads")
    facts = thread_image_facts(binary, machine)
    child = {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_THREAD_MODE": "1"}
    receipt = run_owned([str(binary)], child, 15)
    write_json(environment.root / "thread-normal.json", receipt)
    observed, expected = check_thread_output(receipt, facts)
    assert file_identity(binary) == identity, "Thread reference executable changed"
    results.append({"name": "test_native_thread_oracles", "status": "verified", "oracle": {
        "binary": identity, "sourcePeFacts": facts, "receipt": receipt, "observed": observed, "expected": expected, "debuggerUsed": False}})
    print(f"[VERIFIED] Normal native {environment.architecture} thread identities, executed counters/stores and retained suspension", flush=True)
