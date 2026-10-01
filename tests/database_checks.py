import json
import os
from pathlib import Path
import re
import uuid

from wi_driver import McpError, file_identity, write_json


def check_database(path, function_rva, label, comment, color):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    for category in ("labels", "comments", "bookmarks", "functions", "arguments", "loops", "addresscolors"):
        entries = [item for item in value.get(category, []) if item["module"] == "database_callbacks.exe"]
        assert len(entries) == 1, f"Expected one {category} entry for the fixture"
        entry = entries[0]
        if category in ("labels", "comments", "bookmarks"):
            assert int(entry["address"], 16) == function_rva, f"Wrong persisted {category} address"
        else:
            assert int(entry["start"], 16) == function_rva and int(entry["end"], 16) == function_rva + 1
        if category != "loops":
            assert entry["manual"] is True, f"Expected a manual {category} entry"
        if category == "labels":
            assert entry["text"] == label, "Persisted label differs"
        if category == "comments":
            assert entry["text"] == comment, "Persisted comment differs"
        if category == "addresscolors":
            assert int(entry["color"], 16) == color, "Persisted address color differs"
        if category == "loops":
            assert entry["depth"] == 0, "Persisted loop depth differs"
    return value


def run_database_oracles(environment, results, selected_engine, timeout, fixture_identity, run_owned):
    import pefile
    if selected_engine == "StaticEngine":
        raise McpError("Database execution references require TitanEngine or GleeBug")
    engines = ("TitanEngine", "GleeBug") if selected_engine == "all" else (selected_engine,)
    binary, binary_identity, machine = fixture_identity(environment, "database_callbacks")
    image = pefile.PE(str(binary))
    exports = {item.name.decode("ascii"): item.address for item in image.DIRECTORY_ENTRY_EXPORT.symbols if item.name}
    image.close()
    function_rva = exports["FunctionTarget"]
    runtime = binary.parent.parent
    plugin = runtime / "tests" / "database_callbacks" / ("database_callbacks.dp64" if environment.architecture == "x64" else "database_callbacks.dp32")
    headless = runtime / "headless.exe"
    required = [headless, plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"]
    assert all(path.is_file() for path in required), "Native database runtime is incomplete"
    normal = run_owned([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1"}, timeout)
    write_json(environment.root / "database-normal.json", normal)
    assert normal["exitCode"] == 1 and not normal["timedOut"]
    assert normal["stdout"] == "completed=1\nvalue=1\nfunctionCalls=1\n", "Normal database fixture outcome differs"
    observations = []
    child_environment = {**os.environ}
    child_environment.pop("WININSPECT_TEST_NORMAL", None)
    for engine in engines:
        directory = environment.root / "database" / engine
        directory.mkdir(parents=True)
        engine_id = 0 if engine == "TitanEngine" else 1
        engine_path = runtime / ("TitanEngine.dll" if engine_id == 0 else "GleeBug/TitanEngine.dll")
        run_id = uuid.uuid4().hex
        label = f"wi_label_{run_id}"
        comment = f"Hu Tao \u2764\ufe0f {run_id}"
        color = 3
        database = directory / "annotations.json"
        preamble = f'init "{binary}"\n_f1 = database_callbacks:FunctionTarget\n'
        snapshot = f'dbassertsnapshot _f1, _f1+1, "{label}", "{comment}", 0x{color:X}\n'
        commands = (f'functionadd _f1, _f1+1\nargumentadd _f1, _f1+1\nloopadd _f1, _f1+1\n'
                    f'labelset _f1, "{label}"\ncommentset _f1, "{comment}"\nbookmarkset _f1\n'
                    f'addresscolorrange _f1, _f1+1, 0x{color:X}\n')
        previous_processes = set()
        persisted = None
        for stage in ("save", "empty_restart", "load", "wrong_comment"):
            stage_directory = directory / stage
            stage_directory.mkdir()
            profile = stage_directory / "userdir"
            profile.mkdir()
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\nDisableDatabaseCompression=1\n", encoding="utf-8")
            text = preamble
            if stage == "save":
                text += commands + snapshot + f'dbsave "{database}"\n'
            else:
                text += "dbclear\n"
                if stage != "empty_restart":
                    text += f'dbload "{database}"\n'
                text += snapshot if stage != "wrong_comment" else snapshot.replace(comment, comment + " wrong")
            script = stage_directory / "reference.txt"
            script.write_text(text, encoding="utf-8", newline="\n")
            command = [str(headless), "-testing", "-userdir", str(profile), "-plugin", str(plugin), "-cf", str(script)]
            receipt = run_owned(command, child_environment, timeout, required_modules=[*required, engine_path])
            write_json(stage_directory / "receipt.json", receipt)
            assert receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["loadedModules"], f"Database {stage} runner failed"
            modules = receipt["loadedModules"]
            assert not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in modules)
            current = (receipt["processIdentity"]["pid"], receipt["processIdentity"]["creationTime"])
            assert current not in previous_processes, "Database reference reused a debugger process"
            previous_processes.add(current)
            finals = re.findall(r'\[wi-test\] FINAL status=(pass|fail) asserts=(\d+)(?: reason=(\w+))?', receipt["stdout"])
            assert len(finals) == 1, f"Database {stage} has no unique final result"
            status, assertions, reason = finals[0]
            if stage in ("save", "load"):
                assert status == "pass" and int(assertions) >= 14, f"Database {stage} snapshot failed"
            else:
                expected_message = "snapshot label differs" if stage == "empty_restart" else "snapshot comment differs"
                assert status == "fail" and reason == "assert_failed" and expected_message in receipt["stdout"], f"Database {stage} negative control did not fail"
            if stage == "save":
                stored = check_database(database, function_rva, label, comment, color)
                persisted = file_identity(database)
                write_json(directory / "independent-database.json", stored)
            else:
                assert file_identity(database) == persisted, "Loading changed the persisted database"
            observations.append({"engine": engine, "stage": stage, "status": status, "asserts": int(assertions),
                                 "receipt": receipt, "script": file_identity(script), "database": persisted})
        print(f"[VERIFIED] {environment.architecture} {engine} annotations persisted across fresh debugger processes", flush=True)
    assert file_identity(binary) == binary_identity
    results.append({"name": "test_native_database_oracles", "status": "verified", "oracle": {
        "binary": binary_identity, "machine": machine, "functionRva": hex(function_rva), "normal": normal, "observations": observations}})
