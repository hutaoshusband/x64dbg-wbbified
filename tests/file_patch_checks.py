import os
from pathlib import Path
import re

from patch_checks import check_patch_negative_controls, check_patch_output, check_patch_reference, patch_image_facts
from wi_driver import McpError, file_identity, write_json


OVERLAY = b"WBB_FILE_OVERLAY\0" + bytes(range(256))
GUARD = b"WBB_FILE_GUARD\0\x5a"


def file_image_facts(binary, machine):
    import pefile
    facts = patch_image_facts(binary, machine)
    data = Path(binary).read_bytes()
    image = pefile.PE(data=data)
    try:
        exports = facts["exports"]
        assert {"PatchRelocation", "PatchVirtualTail"} <= exports.keys(), "File reference omits its pointer and virtual tail"
        width = 8 if machine == 0x8664 else 4
        sections = [{"name": section.Name.rstrip(b"\0").decode("ascii"), "rva": section.VirtualAddress,
                     "virtualSize": section.Misc_VirtualSize, "rawOffset": section.PointerToRawData,
                     "rawSize": section.SizeOfRawData, "flags": section.Characteristics} for section in image.sections]
        header_size = image.OPTIONAL_HEADER.SizeOfHeaders
        raw_ranges = [(section["rawOffset"], section["rawOffset"] + section["rawSize"]) for section in sections if section["rawSize"]]
        assert 64 <= header_size <= len(data) and all(header_size <= start < end <= len(data) for start, end in raw_ranges), "PE file ranges exceed their actual bounds"
        ordered = sorted(raw_ranges)
        assert all(first[1] <= second[0] for first, second in zip(ordered, ordered[1:])), "PE raw sections overlap"
        virtual_ranges = sorted((section["rva"], section["rva"] + max(section["rawSize"], section["virtualSize"])) for section in sections)
        assert all(header_size <= start < end <= facts["size"] for start, end in virtual_ranges) and all(first[1] <= second[0] for first, second in zip(virtual_ranges, virtual_ranges[1:])), "PE virtual sections have ambiguous bounds"
        mapped = [section for section in sections if section["rva"] <= exports["PatchRelocation"] and exports["PatchRelocation"] + width <= section["rva"] + section["rawSize"]]
        assert len(mapped) == 1 and mapped[0]["name"] == "PREF", "Relocation pointer has no unique declared raw mapping"
        pointer_raw = mapped[0]["rawOffset"] + exports["PatchRelocation"] - mapped[0]["rva"]
        preferred = image.OPTIONAL_HEADER.ImageBase
        assert int.from_bytes(data[pointer_raw:pointer_raw + width], "little") == preferred + exports["PatchValue"], "Source pointer differs from its preferred-base function"
        relocations = [[entry.rva, entry.type] for block in image.DIRECTORY_ENTRY_BASERELOC for entry in block.entries if entry.type]
        assert [kind for address, kind in relocations if address == exports["PatchRelocation"]] == [10 if width == 8 else 3], "Pointer relocation has the wrong width or repeats"
        tail = [section for section in sections if section["rva"] == exports["PatchVirtualTail"]]
        assert len(tail) == 1 and tail[0]["name"] == "PBSS" and tail[0]["virtualSize"] == 8192 and tail[0]["rawSize"] == tail[0]["rawOffset"] == 0 and tail[0]["flags"] & 0x80, "Virtual zero tail unexpectedly has raw bytes"
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        assert security.VirtualAddress == security.Size == 0 and image.OPTIONAL_HEADER.CheckSum == 0, "Reference requires its declared unsigned zero-checksum source"
        assert image.OPTIONAL_HEADER.DllCharacteristics & 0x40 and data[0x1c] == 0 and 0x1c < header_size, "Source ASLR or reserved header predicate differs"
        overlay_offset = max([header_size, *(end for _, end in raw_ranges)])
        return {**facts, "pointerWidth": width, "preferredBase": preferred, "pointerRawOffset": pointer_raw,
                "headerOffset": 0x1c, "headersSize": header_size, "sections": sections, "relocations": relocations,
                "overlayOffset": overlay_offset, "overlay": data[overlay_offset:].hex(), "fileSize": len(data),
                "checksum": image.OPTIONAL_HEADER.CheckSum, "computedChecksum": image.generate_checksum(), "signed": False}
    finally:
        image.close()


def check_file_log(receipt, facts, directory, engine):
    reference = check_patch_reference(receipt, facts, engine=engine, file_exports=True)
    output = receipt["stdout"]
    paths = re.findall(r"FILE_DIRECTORY utf16=([0-9a-f]+)", output)
    assert len(paths) == 1 and bytes.fromhex(paths[0]).decode("utf-16-le") == str(directory), "Native file output directory differs from the independently requested path"
    base = int(reference["targetIdentity"]["imageBase"], 16)
    exports = facts["exports"]
    layouts = re.findall(r"FILE_LAYOUT relocation=([0-9a-f]+) pointer=([0-9a-f]+) virtual=([0-9a-f]+) zeros=(\d+)", output)
    assert layouts == [(f"{base + exports['PatchRelocation']:x}", f"{base + exports['PatchValue']:x}", f"{base + exports['PatchVirtualTail']:x}", "8192")], "Actual loaded pointer or virtual tail differs from source PE facts"
    assert base != facts["preferredBase"], "Relocation gap needs an actually rebased target"
    counts = re.findall(r"FILE_EXPORT kind=(\d+) requested=(\d+) written=(-?\d+) errorPresent=([01])", output)
    expected = [(str(kind), str(0 if kind == 6 else facts["pointerWidth"] if kind == 3 else 1 if kind in (1, 2) else 4),
                 str(-1 if kind >= 4 else 0 if kind == 1 else facts["pointerWidth"] if kind == 3 else 1 if kind == 2 else 4), "1" if kind >= 4 else "0") for kind in range(9)]
    assert counts == expected, "Native export omits a case or reports the wrong actual count/error boundary"
    pointer = (base + exports["PatchValue"]).to_bytes(facts["pointerWidth"], "little")
    selections = [(1, base + exports["PatchVirtualTail"], 0, 0x5b), (2, base + facts["headerOffset"], 0, 0x5b)]
    selections.extend((3, base + exports["PatchRelocation"] + index, value, value) for index, value in enumerate(pointer))
    observed = re.findall(r"FILE_SELECTION kind=(\d+) address=([0-9a-f]+) old=([0-9a-f]{2}) new=([0-9a-f]{2})", output)
    assert [(int(kind), int(address, 16), int(old, 16), int(new, 16)) for kind, address, old, new in observed] == selections, "Native selection is not the exact virtual, header or unmodified live pointer"
    return {"reference": reference, "directory": str(directory), "counts": [list(entry) for entry in counts], "actualBase": base,
            "nativeVirtualTailIgnored": True, "nativeRelocationNormalizationAbsent": True}


def expected_file_bytes(source, facts, kind, base):
    expected = bytearray(source)
    if kind == 0:
        start = facts["valueRawOffset"]
        expected[start:start + 6] = bytes.fromhex(facts["patched"])
    elif kind == 2:
        expected[facts["headerOffset"]] = 0x5b
    elif kind == 3:
        start = facts["pointerRawOffset"]
        expected[start:start + facts["pointerWidth"]] = (base + facts["exports"]["PatchValue"]).to_bytes(facts["pointerWidth"], "little")
    else:
        assert kind == 1, "Unknown executable file variant"
    return bytes(expected)


def check_file_bytes(data, source, facts, kind, base):
    expected = expected_file_bytes(source, facts, kind, base)
    assert data == expected, "Saved PE bytes differ from the exact independent mapping or change bytes outside the selected span"
    assert data[facts["overlayOffset"]:] == bytes.fromhex(facts["overlay"]), "Saved overlay differs"
    return [index for index, (old, new) in enumerate(zip(source, data)) if old != new]


def check_guard_files(directory):
    assert {path.name for path in directory.iterdir()} == {f"file-{kind}.exe" for kind in (0, 1, 2, 3, 4, 8)}, "Failed export publishes an unexpected destination"
    for kind in (4, 8):
        path = directory / f"file-{kind}.exe"
        assert path.read_bytes() == GUARD, "Rejected destination lost its preexisting exact bytes"
        assert bool(path.stat().st_file_attributes & 1) == (kind == 8), "Rejected destination lost its actual read-only attribute"
    assert not (directory / "missing").exists(), "Missing-directory control created a publication path"


def check_relocation_exit(receipt):
    assert receipt["exitCode"] == 114 and not receipt["stdout"] and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Fresh loader did not reject the persisted already-rebased pointer"


def check_wrong_patch_output(receipt, facts):
    assert receipt["exitCode"] == 108 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Wrong canary did not reach the target's actual failure exit"
    lines = receipt["stdout"].splitlines()
    assert len(lines) == 11 and all(line.count("=") == 1 for line in lines), "Wrong-canary target omits its actual fields"
    observed = dict(line.split("=", 1) for line in lines)
    base = int(observed["imageBase"], 16)
    assert base > 0 and base % 0x10000 == 0 and base + facts["size"] < 1 << (64 if facts["machine"] == 0x8664 else 32), "Wrong-canary target has an invalid OS image base"
    expected = {"mode": "2", "mutation": "0", "phase": "4", "pid": str(receipt["processIdentity"]["pid"]),
                "thread": str(receipt["startupThread"]), "imageBase": f"{base:x}", "completed": "1", "verified": "0", "sum": "43",
                "value0": "43", "marker0": "invalid"}
    assert observed == expected, "Wrong saved instruction did not actually execute 43 with its invalid marker"


def rejected_control(name, checker, *arguments):
    try:
        checker(*arguments)
    except (AssertionError, ValueError, KeyError) as error:
        return {"name": name, "status": "rejected", "error": str(error)}
    raise AssertionError(f"File patch negative control was admitted: {name}")


def file_negative_controls(receipt, facts, directory, engine, source, normal):
    output = receipt["stdout"]
    controls = check_patch_negative_controls(receipt, facts, engine=engine, file_exports=True)
    changes = [("missing_export", "FILE_EXPORT kind=0", "IGNORED_EXPORT kind=0"),
               ("false_virtual_write", "kind=1 requested=1 written=0", "kind=1 requested=1 written=1"),
               ("ignored_lock_failure", "kind=4 requested=4 written=-1 errorPresent=1", "kind=4 requested=4 written=4 errorPresent=0"),
               ("wrong_pointer_width", f"kind=3 requested={facts['pointerWidth']}", "kind=3 requested=1"),
               ("missing_live_pointer", "FILE_LAYOUT relocation=", "IGNORED_LAYOUT relocation=")]
    for name, old, new in changes:
        assert old in output, "File corruption control has no predicate"
        controls.append(rejected_control(name, check_file_log, {**receipt, "stdout": output.replace(old, new, 1)}, facts, directory, engine))
    base = int(re.findall(r"PATCH_LAYOUT .* base=([0-9a-f]+)", output)[0], 16)
    saved = expected_file_bytes(source, facts, 0, base)
    for name, offset in (("changed_overlay", len(saved) - 1), ("wrong_instruction", facts["valueRawOffset"] + 2),
                         ("outside_plan_raw_byte", facts["valueRawOffset"] + 16), ("wrong_header", facts["headerOffset"])):
        candidate = bytearray(saved)
        candidate[offset] ^= 1
        controls.append(rejected_control(name, check_file_bytes, candidate, source, facts, 0, base))
    controls.append(rejected_control("truncated_file", check_file_bytes, saved[:-1], source, facts, 0, base))
    controls.append(rejected_control("false_persisted_canary", check_patch_output, normal, facts, 2, 7))
    return controls


def run_file_patch_oracles(environment, results, selected_engine, timeout, fixture_identity, run_owned):
    if selected_engine == "StaticEngine":
        raise McpError("File execution references require TitanEngine or GleeBug")
    engines = ("TitanEngine", "GleeBug") if selected_engine == "all" else (selected_engine,)
    binary, identity, machine = fixture_identity(environment, "patch_canary")
    facts = file_image_facts(binary, machine)
    runtime = binary.parent.parent
    plugin = runtime / "tests/patch_canary" / ("patch_canary.dp64" if machine == 0x8664 else "patch_canary.dp32")
    source_script = plugin.parent / "test.file.txt"
    required = [runtime / "headless.exe", plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"]
    assert source_script.is_file() and all(path.is_file() for path in required), "Native file patch fixture is incomplete"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    child.pop("WININSPECT_TEST_PATCH_MODE", None)
    normal_environment = {**child, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_PATCH_MODE": "2"}
    observations = []
    for engine in engines:
        scope = environment.root / "file-patch" / engine
        profile = scope / "userdir"
        inputs = scope / "\u6e90"
        profile.mkdir(parents=True)
        inputs.mkdir()
        copied = inputs / "patch_canary.exe"
        copied.write_bytes(binary.read_bytes() + OVERLAY)
        source_identity = file_identity(copied)
        source_bytes = copied.read_bytes()
        source_facts = file_image_facts(copied, machine)
        assert source_facts["overlay"] == (bytes.fromhex(facts["overlay"]) + OVERLAY).hex(), "Source copy lacks its independently appended overlay"
        engine_id = 0 if engine == "TitanEngine" else 1
        (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
        directory = scope / "\u4fdd\u5b58"
        script = scope / "reference.txt"
        text = source_script.read_text(encoding="utf-8")
        assert text.count("init tests/patch_canary.exe") == text.count("\npatchfileexports\n") == 1, "File reference script template differs"
        text = text.replace("init tests/patch_canary.exe", f'init "{copied}"').replace("\npatchfileexports\n", f'\npatchfileexports "{directory}"\n')
        script.write_text(text, encoding="utf-8", newline="\n")
        baseline = run_owned([str(copied)], normal_environment, timeout)
        write_json(scope / "source-normal.json", baseline)
        check_patch_output(baseline, source_facts, 2)
        receipt = run_owned([str(required[0]), "-testing", "-userdir", str(profile), "-plugin", str(plugin), "-cf", str(script)], child, timeout,
                            required_modules=[*required, runtime / ("TitanEngine.dll" if engine_id == 0 else "GleeBug/TitanEngine.dll")])
        write_json(scope / "receipt.json", receipt)
        observed = check_file_log(receipt, source_facts, directory, engine)
        check_guard_files(directory)
        persisted = []
        for kind in range(4):
            destination = directory / f"file-{kind}.exe"
            changes = check_file_bytes(destination.read_bytes(), source_bytes, source_facts, kind, observed["actualBase"])
            normal = run_owned([str(destination)], normal_environment, timeout)
            write_json(scope / f"persisted-{kind}.json", normal)
            actual = check_patch_output(normal, source_facts, 2, 42 if kind == 0 else 7) if kind != 3 else check_relocation_exit(normal)
            persisted.append({"kind": kind, "binary": file_identity(destination), "changedOffsets": changes, "receipt": normal, "observed": actual})
        controls = file_negative_controls(receipt, source_facts, directory, engine, source_bytes, persisted[0]["receipt"])
        for name, offset, value, exit_code in (("wrong_canary", source_facts["valueRawOffset"] + 2, 43, 108),
                                             ("outside_plan_with_valid_canary", source_facts["valueRawOffset"] + 16, 1, 42)):
            data = bytearray(expected_file_bytes(source_bytes, source_facts, 0, observed["actualBase"]))
            data[offset] = value
            candidate = scope / f"control-{name}.exe"
            candidate.write_bytes(data)
            normal = run_owned([str(candidate)], normal_environment, timeout)
            write_json(scope / f"control-{name}.json", normal)
            assert normal["exitCode"] == exit_code and not normal["timedOut"] and normal["terminalObserved"] and normal["jobClosed"], "Actual corrupt file control did not execute its independent predicate"
            checker = check_patch_output if name == "wrong_canary" else check_file_bytes
            arguments = (normal, source_facts, 2, 42) if name == "wrong_canary" else (data, source_bytes, source_facts, 0, observed["actualBase"])
            control = rejected_control(name, checker, *arguments)
            if name == "wrong_canary":
                check_wrong_patch_output(normal, source_facts)
            else:
                check_patch_output(normal, source_facts, 2, 42)
            controls.append({**control, "targetExecuted": True, "binary": file_identity(candidate), "receipt": normal})
        controls.append({**rejected_control("unmodified_green_target", check_patch_output, persisted[1]["receipt"], source_facts, 2, 42),
                         "targetExecuted": True, "receipt": persisted[1]["receipt"]})
        assert file_identity(copied) == source_identity, "File export or controls changed their source executable"
        assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "File reference loaded an external MCP dependency"
        write_json(scope / "independent-files.json", {"source": source_identity, "facts": source_facts, "observed": observed, "persisted": persisted, "negativeControls": controls})
        observations.append({"engine": engine, "source": source_identity, "sourcePeFacts": source_facts, "script": file_identity(script),
                             "sourceScript": file_identity(source_script), "native": receipt, "observed": observed, "persisted": persisted,
                             "guardFiles": [file_identity(directory / f"file-{kind}.exe") for kind in (4, 8)], "negativeControls": controls})
        print(f"[VERIFIED] Native {environment.architecture} {engine} file save-as executes 42; header/overlay/source, five destination failures and actual relocation rejection verified", flush=True)
    assert file_identity(binary) == identity, "File patch reference changed the source-built executable"
    results.append({"name": "test_native_file_patch_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourcePeFacts": facts, "observations": observations,
        "openGates": ["strict virtual-tail rejection", "relocation normalization/rejection", "signed and ambiguous PE mappings",
                      "atomic publication", "backup/journal", "hash-bound plan", "compare-checked undo", "GUI/MCP export"]}})
