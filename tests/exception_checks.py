import os
from pathlib import Path

from wi_driver import McpError, file_identity, write_json


def exception_image_facts(binary, machine):
    import pefile
    try:
        image = pefile.PE(str(binary))
        if image.FILE_HEADER.Machine != machine:
            raise McpError("Exception fixture has the wrong PE architecture")
        exports = {entry.name.decode("ascii"): entry.address for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
        required = {"ExceptionRun", "ExceptionProbe", "ExceptionFault", "ExceptionAfterFault", "ExceptionAfterHandled", "ExceptionHandled", "ExceptionProtected"}
        if not required <= exports.keys() or image.get_data(exports["ExceptionFault"], 2) != b"\x0f\x0b" or exports["ExceptionAfterFault"] != exports["ExceptionFault"] + 2:
            raise McpError("Exception fixture has invalid exported fault or continuation instructions")
        frames = []
        if machine == 0x8664:
            for name in ("ExceptionRun", "ExceptionProbe", "ExceptionHandled", "ExceptionProtected"):
                found = [entry.struct for entry in image.DIRECTORY_ENTRY_EXCEPTION if entry.struct.BeginAddress <= exports[name] < entry.struct.EndAddress]
                if len(found) != 1:
                    raise McpError("Exception fixture is missing its known x64 runtime function")
                frame = found[0]
                frames.append({"name": name, "start": frame.BeginAddress, "end": frame.EndAddress, "unwindRva": frame.UnwindData})
        return {"machine": machine, "size": image.OPTIONAL_HEADER.SizeOfImage, "exports": exports, "runtimeFunctions": frames}
    except (pefile.PEFormatError, AttributeError, UnicodeError, ValueError) as error:
        raise McpError("Exception fixture PE facts are malformed") from error
    finally:
        if "image" in locals():
            image.close()


def check_exception_output(receipt, binary, facts, mode):
    assert receipt["terminalObserved"] and receipt["jobClosed"] and not receipt["timedOut"], "Exception fixture did not terminate"
    if mode == 2:
        expected = {"unhandledSearch": "1", "code": "c000001d", "sourceMatch": "1", "filters": "1"}
        assert receipt["exitCode"] & 0xffffffff == 0xc000001d, "Unhandled exception has the wrong actual exit"
    else:
        assert mode in (1, 3) and receipt["exitCode"] == (73 if mode == 1 else 74), "Handled/continued exception has the wrong actual exit"
        expected = None
    lines = receipt["stdout"].splitlines()
    assert len(lines) == (4 if mode == 2 else 34) and all(line.count("=") == 1 for line in lines), "Exception summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert len(observed) == len(lines), "Exception summary fields repeat"
    if mode == 2:
        assert observed == expected, "Unhandled exception search differs"
        return observed, expected
    continued = mode == 3
    architecture64 = facts["machine"] == 0x8664
    maximum = 1 << (64 if architecture64 else 32)
    base = int(observed["imageBase"], 16)
    fault_stack = int(observed["faultStack"], 16)
    wrapper_stack = int(observed["wrapperStack"], 16)
    assert 0 < base < maximum - facts["size"] and base & 0xffff == 0, "Exception image base is invalid"
    assert 0 < fault_stack < wrapper_stack < maximum and (not architecture64 or (fault_stack | wrapper_stack) & 15 == 0), "Exception stacks are invalid"
    context_flags = int(observed["contextFlags"], 16)
    required_context = 0x100008 if architecture64 else 0x10020
    assert context_flags & required_context == required_context, "Exception SIMD context is unavailable"
    expected = {"mode": str(mode), "phase": "3", "filters": "1", "handled": "0" if continued else "1", "finally": "1", "abnormal": "0" if continued else "1",
                "afterProbe": "1" if continued else "0", "afterProtected": "1" if continued else "0", "handlerMarker": "0" if continued else "22", "wrapperCompleted": "1",
                "instructionValue": "2468ace0" if continued else "0", "code": "c000001d", "flags": "0", "parameters": "0", "faultStack": f"{fault_stack:x}",
                "observedStack": f"{fault_stack:x}", "observedIp": f"{base + facts['exports']['ExceptionFault']:x}", "fault": f"{base + facts['exports']['ExceptionFault']:x}",
                "accumulator": "11223344", "wrapperStack": f"{wrapper_stack:x}", "afterStack": f"{wrapper_stack:x}", "afterGeneral0": "1122334455667788" if architecture64 else "55667788",
                "afterGeneral1": "8877665544332211" if architecture64 else "44332211", "verified": "1", "contextFlags": f"{context_flags:x}",
                "observedNonVol0": "2233445566778899" if architecture64 else "0", "observedNonVol1": "9988776655443322" if architecture64 else "0",
                "handledReturn": f"{base + facts['exports']['ExceptionAfterHandled']:x}", "afterHandled": f"{base + facts['exports']['ExceptionAfterHandled']:x}", "imageBase": f"{base:x}",
                "faultXmm": bytes(index ^ 0x5a for index in range(16)).hex(), "afterXmm": bytes(index ^ 0xa5 for index in range(16)).hex() if architecture64 else bytes(16).hex()}
    import pefile
    image = pefile.PE(str(binary))
    try:
        for field, child in (("probeReturn", "ExceptionProbe"), ("protectedReturn", "ExceptionProtected"), ("handledReturn", "ExceptionHandled")):
            address = int(observed[field], 16)
            assert base + 5 <= address < base + facts["size"], "Exception caller return is outside its image"
            rva = address - base
            instruction = image.get_data(rva - 5, 5)
            assert len(instruction) == 5 and instruction[0] == 0xe8 and rva + int.from_bytes(instruction[1:], "little", signed=True) == facts["exports"][child], "Exception caller does not follow its exact source PE call instruction"
            expected[field] = f"{address:x}"
    finally:
        image.close()
    assert observed == expected, f"Actual exception outcomes differ: {observed}"
    return observed, expected


def run_exception_oracles(environment, results, fixture_identity, run_owned):
    binary, identity, machine = fixture_identity(environment, "exceptions_unwind")
    facts = exception_image_facts(binary, machine)
    observations = []
    for mode in (1, 3, 2):
        child = {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_EXCEPTION_MODE": str(mode)}
        receipt = run_owned([str(binary)], child, 15)
        write_json(environment.root / f"exception-normal-{mode}.json", receipt)
        observed, expected = check_exception_output(receipt, binary, facts, mode)
        assert file_identity(binary) == identity, "Exception fixture changed"
        observations.append({"mode": mode, "receipt": receipt, "observed": observed, "expected": expected})
    results.append({"name": "test_native_exception_oracles", "status": "verified", "oracle": {
        "binary": identity, "sourcePeFacts": facts, "observations": observations, "debuggerUsed": False}})
    print(f"[VERIFIED] Three normal native {environment.architecture} handled, continued and unhandled exception outcomes", flush=True)
