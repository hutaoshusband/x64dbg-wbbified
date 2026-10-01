import os
from pathlib import Path
import shutil

from wi_driver import McpError, file_identity, write_json


def module_image_facts(path, machine):
    import pefile
    path = Path(path)
    if not path.is_file():
        raise McpError("Native module reference DLL is missing; run --phase build")
    identity = file_identity(path)
    data = path.read_bytes()
    if not 64 <= len(data) <= 16 * 1024 * 1024:
        raise McpError("Native module reference DLL has an invalid file size")
    try:
        image = pefile.PE(data=data)
        if image.FILE_HEADER.Machine != machine or not image.FILE_HEADER.Characteristics & 0x2000:
            raise McpError("Native module reference DLL has the wrong PE architecture or type")
        exports = {entry.name.decode("ascii"): entry.address for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
        required = {"TestFunction", "ModuleValue", "ModuleObserveDetach", "gModuleCallCount", "gModuleLastArgument", "gModuleAttachCount", "gModuleCallerProcessId"}
        if not required <= exports.keys():
            raise McpError("Native module reference DLL is missing its known exports")
        value = [entry for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name == b"ModuleValue"]
        if len(value) != 1 or value[0].forwarder or not 0 < value[0].address < image.OPTIONAL_HEADER.SizeOfImage:
            raise McpError("Native module reference DLL has an invalid canary export")
        process_imports = [entry.address - image.OPTIONAL_HEADER.ImageBase for imported in image.DIRECTORY_ENTRY_IMPORT
                           for entry in imported.imports if entry.name == b"GetCurrentProcessId"]
        if len(process_imports) != 1:
            raise McpError("Native module reference DLL is missing its known process-ID import")
        facts = {"machine": machine, "entryRva": image.OPTIONAL_HEADER.AddressOfEntryPoint, "size": image.OPTIONAL_HEADER.SizeOfImage,
                 "valueRva": exports["ModuleValue"], "processIatRva": process_imports[0], "exports": exports,
                 "sections": [{"name": section.Name.rstrip(b"\0").decode("ascii"), "rva": section.VirtualAddress,
                               "size": section.Misc_VirtualSize} for section in image.sections]}
        image.close()
    except (pefile.PEFormatError, AttributeError, UnicodeError, ValueError) as error:
        raise McpError("Native module reference DLL has malformed PE facts") from error
    assert file_identity(path) == identity, "Native module reference DLL changed during admission"
    return identity, facts


def check_module_output(receipt, binary, library, directory, facts):
    assert receipt["exitCode"] == 43 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Normal module target failed"
    lines = receipt["stdout"].splitlines()
    summaries = [line for line in lines if "=" in line]
    messages = [line for line in lines if "=" not in line]
    assert len(summaries) == 34 and all(line.count("=") == 1 for line in summaries), "Module summary fields are malformed"
    observed = dict(line.split("=", 1) for line in summaries)
    assert len(observed) == 34, "Module summary fields repeat"
    assert len(messages) == 4 and messages[0].startswith("Random DLL loaded! Instance: 0x") and messages[2].startswith("Random DLL loaded! Instance: 0x")
    assert messages[1] == messages[3] == "Random DLL unloaded!", "DLL did not execute both detach paths"
    process_id = str(receipt["processIdentity"]["pid"])
    expected = {"phase": "3", "loads": "2", "unloads": "2", "referenceReleased": "1", "referenceAlive": "1", "cleanup": "2",
                "result": "43", "processId": process_id, "source": str(library), "directory": str(directory)}
    for index in range(2):
        prefix = f"module{index}."
        base = int(observed[prefix + "base"], 16)
        maximum = 1 << (64 if facts["machine"] == 0x8664 else 32)
        assert 0 < base < maximum - facts["size"] and base & 0xffff == 0, "Observed module base is invalid"
        expected.update({prefix + "base": f"{base:x}", prefix + "function": f"{base + facts['valueRva']:x}",
                         prefix + "entry": f"{base + facts['entryRva']:x}", prefix + "size": str(facts["size"]),
                         prefix + "value": str(20 + index * 3), prefix + "calls": "1", prefix + "argument": str(index + 1),
                         prefix + "attach": "1", prefix + "detach": "1", prefix + "processId": process_id,
                         prefix + "present": "0", prefix + "path": str(directory / ("first.xxl" if index == 0 else "second.xxl"))})
        assert int(messages[index * 2].split("0x", 1)[1], 16) == base, "DllMain observed a different module base"
    assert observed == expected, f"Normal module outcomes differ: {observed}"
    return observed, expected


def run_module_oracles(environment, results, fixture_identity, run_owned):
    binary, binary_identity, machine = fixture_identity(environment, "random_dll")
    library = binary.with_name("random.dll")
    library_identity, facts = module_image_facts(library, machine)
    directory = environment.root / "modules-\u6a21\u5757-\u03b1"
    directory.mkdir()
    copies = [directory / name for name in ("first.xxl", "second.xxl")]
    for path in copies:
        shutil.copyfile(library, path)
        assert path.read_bytes() == library.read_bytes(), "Prepared module copy differs from its source"
    before = [file_identity(path) for path in copies]
    child = {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_MODULE_DIRECTORY": str(directory)}
    receipt = run_owned([str(binary)], child, 15)
    write_json(environment.root / "module-normal.json", receipt)
    observed, expected = check_module_output(receipt, binary, library, directory, facts)
    assert file_identity(binary) == binary_identity and file_identity(library) == library_identity, "Module fixture artifacts changed"
    assert [file_identity(path) for path in copies] == before, "Loaded module copy changed"
    results.append({"name": "test_native_module_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "library": library_identity, "copies": before, "sourcePeFacts": facts, "receipt": receipt,
        "observed": observed, "expected": expected, "debuggerUsed": False}})
    print(f"[VERIFIED] Normal native {environment.architecture} DLL load, reference, function and detach outcomes", flush=True)
