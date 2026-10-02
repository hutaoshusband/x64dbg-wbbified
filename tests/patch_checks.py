import os
from pathlib import Path
import re

from wi_driver import McpError, file_identity, write_json


def patch_image_facts(binary, machine):
    import pefile
    try:
        image = pefile.PE(str(binary))
        if image.FILE_HEADER.Machine != machine:
            raise McpError("Patch reference has the wrong PE architecture")
        exports = {entry.name.decode("ascii"): entry.address for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name and not entry.forwarder}
        required = {"PatchCall", "PatchAfterCall", "PatchValue", "PatchValueEnd", "PatchReady", "PatchFinish", "gPatchMode", "gPatchMutation",
                    "gPatchPhase", "gPatchPid", "gPatchThread", "gPatchImageBase", "gPatchValues", "gPatchMarkers", "gPatchCompleted", "gPatchVerified"}
        if not required <= exports.keys():
            raise McpError("Patch reference is missing its declared exports")
        value = exports["PatchValue"]
        if exports["PatchValueEnd"] != value + 6 or image.get_data(value, 6) != bytes.fromhex("b807000000c3"):
            raise McpError("Patch reference has the wrong original MOV and RET")
        call = exports["PatchCall"]
        prologue = bytes.fromhex("4883ec2833c0" if machine == 0x8664 else "33c0")
        after = call + len(prologue) + 5
        instruction = b"\xe8" + (value - after).to_bytes(4, "little", signed=True)
        epilogue = bytes.fromhex("4883c428c3" if machine == 0x8664 else "c3")
        if exports["PatchAfterCall"] != after or image.get_data(call, len(prologue) + 5 + len(epilogue)) != prologue + instruction + epilogue:
            raise McpError("Patch reference does not clear EAX and execute its exact real CALL and return")
        for name in ("gPatchMode", "gPatchMutation", "gPatchPhase", "gPatchCompleted", "gPatchVerified"):
            if image.get_data(exports[name], 4) != bytes(4):
                raise McpError("Patch reference default selection or counters are invalid")
        sections = [section for section in image.sections if section.VirtualAddress <= value and value + 6 <= section.VirtualAddress + section.SizeOfRawData]
        if len(sections) != 1 or not sections[0].Characteristics & 0x20000000:
            raise McpError("Patch reference instructions do not have an unambiguous executable raw mapping")
        raw = sections[0].PointerToRawData + value - sections[0].VirtualAddress
        if Path(binary).read_bytes()[raw:raw + 6] != bytes.fromhex("b807000000c3"):
            raise McpError("Patch reference raw bytes differ from the mapped instructions")
        return {"machine": machine, "size": image.OPTIONAL_HEADER.SizeOfImage, "exports": exports, "valueRawOffset": raw,
                "original": "b807000000c3", "patched": "66b82a0090c3", "changedOffsets": [0, 1, 2, 4]}
    except (pefile.PEFormatError, AttributeError, UnicodeError, ValueError, OverflowError) as error:
        raise McpError("Patch reference PE facts are malformed") from error
    finally:
        if "image" in locals():
            image.close()


def check_patch_output(receipt, facts, mode):
    count = 3 if mode == 1 else 1
    assert receipt["exitCode"] == count * 7 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Normal patch reference did not complete with its actual executed sum"
    lines = receipt["stdout"].splitlines()
    assert len(lines) == 9 + count * 2 and all(line.count("=") == 1 for line in lines), "Patch summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert len(observed) == len(lines), "Patch summary fields repeat"
    base = int(observed["imageBase"], 16)
    assert base > 0 and base % 0x10000 == 0 and base + facts["size"] < 1 << (64 if facts["machine"] == 0x8664 else 32), "Patch target has an invalid actual image base"
    expected = {"mode": str(mode), "mutation": "0", "phase": "4", "pid": str(receipt["processIdentity"]["pid"]),
                "thread": str(receipt["startupThread"]), "imageBase": f"{base:x}", "completed": str(count), "verified": "1", "sum": str(count * 7)}
    for index in range(count):
        expected.update({f"value{index}": "7", f"marker{index}": "original"})
    assert observed == expected, f"Actual normal patch outcomes differ: {observed}"
    return observed


def check_patch_reference(receipt, facts):
    output = receipt["stdout"]
    finals = re.findall(r"\[wi-test\] FINAL status=(pass|fail) asserts=(\d+)(?: reason=(\w+))?", output)
    assert len(finals) == 1 and finals[0][0] == "pass" and 150 <= int(finals[0][1]) < 1000 and receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Native patch reference did not complete"
    layouts = re.findall(r"PATCH_LAYOUT pid=(\d+) thread=(\d+) base=([0-9a-f]+) address=([0-9a-f]+) creation=(\d+)", output)
    assert len(layouts) == 1, "Patch reference target identity is missing or repeats"
    pid, thread, base, address, creation = layouts[0]
    base, address = int(base, 16), int(address, 16)
    assert 0 < int(pid) < 1 << 32 and 0 < int(thread) < 1 << 32 and int(pid) != receipt["processIdentity"]["pid"] and 0 < int(creation) < 1 << 64, "Patch reference has an invalid target OS identity"
    assert base > 0 and base % 0x10000 == 0 and base + facts["size"] < 1 << (64 if facts["machine"] == 0x8664 else 32) and address == base + facts["exports"]["PatchValue"], "Patch origin differs from its source PE function"
    snapshots = re.findall(r"PATCH_BYTES patched=([01]) trapped=([01]) address=([0-9a-f]+) logical=([0-9a-f]+) raw=([0-9a-f]+)", output)
    assert [entry[0] for entry in snapshots] == list("000001100"), "Patch bytes omit or reorder pure encoding, failed writes, apply or restoration"
    for patched, trapped, location, logical, raw in snapshots:
        expected = facts["patched"] if patched == "1" else facts["original"]
        assert trapped == "1" and int(location, 16) == address and logical == expected and raw == "cc" + expected[2:], "Logical original, software trap or actual installed opcode differs"
    branches = re.findall(r"PATCH_BRANCH origin=([0-9a-f]+) destination=([0-9a-f]+) displacement=([0-9a-f]+)", output)
    assert [(int(origin, 16), int(destination, 16), int(displacement, 16)) for origin, destination, displacement in branches] == [
        (address, address + 0x1000, 0xffb), (address + 0x20, address + 0x1000, 0xfdb)], "Pure branch encoding does not bind to both actual origins"
    assembly = re.findall(r"PATCH_ASSEMBLY origin=([0-9a-f]+) instruction=mov_ax_0x2a encoded=66b82a00 fill=90 invalidRejected=1 oversizedTextRejected=1 oversizedHasError=([01])", output)
    assert len(assembly) == 1 and int(assembly[0][0], 16) == address, "Requested assembly, fill and nonmutation rejections are missing"
    records = re.findall(r"PATCH_RECORD address=([0-9a-f]+) old=([0-9a-f]{2}) new=([0-9a-f]{2}) module=(\S+)", output)
    original, patched = bytes.fromhex(facts["original"]), bytes.fromhex(facts["patched"])
    expected_records = [(address + offset, original[offset], patched[offset], "patch_canary.exe") for offset in facts["changedOffsets"]]
    assert [(int(location, 16), int(old, 16), int(new, 16), module) for location, old, new, module in records] == expected_records * 2, "Patch lookup loses the original bytes, changed bytes or exact tracked span"
    hits = re.findall(r"PATCH_HIT index=(\d+) address=([0-9a-f]+) pid=(\d+) thread=(\d+)", output)
    assert hits == [(str(index), f"{address:x}", pid, thread) for index in range(3)], "Actual software breakpoint callbacks differ from the three selected calls"
    results = re.findall(r"PATCH_RESULT values=(\d+)/(\d+)/(\d+) markers=(\w+)/(\w+)/(\w+) completed=(\d+) verified=(\d+)", output)
    assert results == [("7", "42", "7", "original", "patched", "original", "3", "1")], "Actual target outcomes do not prove changed and restored execution"
    exits = re.findall(r"PATCH_EXIT code=(\d+) observed=([01]) debugging=([01])", output)
    assert exits == [("56", "1", "0")], "Patch target exit event was not actually observed after termination"
    return {"targetIdentity": {"pid": int(pid), "thread": int(thread), "creationTime": creation, "imageBase": hex(base)}, "origin": hex(address),
            "values": [7, 42, 7], "markers": ["original", "patched", "original"], "exitCode": 56,
            "original": facts["original"], "patched": facts["patched"], "changedOffsets": facts["changedOffsets"], "oversizedNativeErrorPresent": assembly[0][1] == "1"}


def check_patch_negative_controls(receipt, facts):
    output = receipt["stdout"]
    changes = [("wrong_executed_value", "values=7/42/7", "values=7/43/7"), ("wrong_marker", "markers=original/patched/original", "markers=original/original/original"),
               ("wrong_original_byte", "old=b8 new=66", "old=90 new=66"), ("missing_trap", "raw=cc07000000c3", "raw=b807000000c3"),
               ("wrong_installed_byte", "logical=66b82a0090c3", "logical=66b82b0090c3"), ("wrong_branch_origin", "displacement=fdb", "displacement=ffb"),
               ("missing_hit", "PATCH_HIT index=1", "IGNORED_HIT index=1"), ("missing_restore", "values=7/42/7", "values=7/42/42"),
               ("wrong_exit_event", "PATCH_EXIT code=56", "PATCH_EXIT code=55"), ("missing_rejection", "oversizedTextRejected=1", "oversizedTextRejected=0")]
    controls = []
    for name, old, new in changes:
        assert old in output, f"Patch negative control has no predicate: {name}"
        controls.append((name, {**receipt, "stdout": output.replace(old, new, 1)}))
    controls.extend((name, {**receipt, **changed}) for name, changed in (("wrong_debugger_exit", {"exitCode": 1}), ("missing_terminal", {"terminalObserved": False})))
    observed = []
    for name, candidate in controls:
        try:
            check_patch_reference(candidate, facts)
        except (AssertionError, ValueError, KeyError) as error:
            observed.append({"name": name, "status": "rejected", "error": str(error), "targetExecuted": False})
        else:
            raise AssertionError(f"Patch negative control was admitted: {name}")
    return observed


def run_patch_oracles(environment, results, selected_engine, timeout, fixture_identity, run_owned):
    if selected_engine == "StaticEngine":
        raise McpError("Patch execution references require TitanEngine or GleeBug")
    engines = ("TitanEngine", "GleeBug") if selected_engine == "all" else (selected_engine,)
    binary, identity, machine = fixture_identity(environment, "patch_canary")
    facts = patch_image_facts(binary, machine)
    normals = []
    for mode in (1, 2):
        receipt = run_owned([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_PATCH_MODE": str(mode)}, timeout)
        write_json(environment.root / f"patch-normal-{mode}.json", receipt)
        normals.append({"mode": mode, "receipt": receipt, "observed": check_patch_output(receipt, facts, mode)})
    runtime = binary.parent.parent
    plugin = runtime / "tests/patch_canary" / ("patch_canary.dp64" if machine == 0x8664 else "patch_canary.dp32")
    source = plugin.parent / "test.txt"
    required = [runtime / "headless.exe", plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"]
    assert all(path.is_file() for path in [*required, source]), "Native patch runtime is incomplete"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    child.pop("WININSPECT_TEST_PATCH_MODE", None)
    observations = []
    for engine in engines:
        scope = environment.root / "patch" / engine
        profile = scope / "userdir"
        profile.mkdir(parents=True)
        engine_id = 0 if engine == "TitanEngine" else 1
        engine_path = runtime / ("TitanEngine.dll" if engine_id == 0 else "GleeBug/TitanEngine.dll")
        (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
        script = scope / "reference.txt"
        text = source.read_text(encoding="utf-8")
        assert text.count("init tests/patch_canary.exe") == 1, "Patch reference script template differs"
        script.write_text(text.replace("init tests/patch_canary.exe", f'init "{binary}"'), encoding="utf-8", newline="\n")
        receipt = run_owned([str(required[0]), "-testing", "-userdir", str(profile), "-plugin", str(plugin), "-cf", str(script)], child, timeout,
                            required_modules=[*required, engine_path])
        write_json(scope / "receipt.json", receipt)
        reference = check_patch_reference(receipt, facts)
        assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Patch reference loaded an external MCP dependency"
        controls = check_patch_negative_controls(receipt, facts)
        write_json(scope / "independent-patch.json", reference)
        write_json(scope / "negative-controls.json", controls)
        observations.append({"engine": engine, "receipt": receipt, "reference": reference, "negativeControls": controls, "script": file_identity(script), "sourceScript": file_identity(source)})
        print(f"[VERIFIED] Native {environment.architecture} {engine} software-breakpoint patch execution 7/42/7, undo and actual exit 56", flush=True)
    assert file_identity(binary) == identity, "Runtime patch reference changed its source executable"
    results.append({"name": "test_native_patch_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourcePeFacts": facts, "normal": normals, "observations": observations}})
