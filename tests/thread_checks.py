import os

from wi_driver import McpError, file_identity, write_json


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
