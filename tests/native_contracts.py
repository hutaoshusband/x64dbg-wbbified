from datetime import datetime, timezone
import fnmatch
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
from types import SimpleNamespace

from wi_driver import KERNEL, McpError, OwnedJob, ROOT, compiler_environment, file_identity, process_identity, resolve_build_toolchain, write_json
from pe_patch_checks import check_pe_file_patch_plans, check_new_file_publication


CASE_NAMES = ("test_compiled_schema_catalog", "test_contract_boundaries", "test_context_roundtrip",
              "test_bounded_json", "test_target_pointer_ranges", "test_source_dependencies", "test_http_parser", "test_legacy_alias_contracts", "test_native_parity_catalog", "test_pe_file_patch_plans",
              "test_new_file_publication", "test_native_library_fault_oracles", "test_result_contracts", "test_registry_contracts", "test_registry_dispatch", "test_schema_references",
              "test_lifecycle_contracts", "test_execution_contracts", "test_inspection_contracts", "test_memory_contracts",
              "test_breakpoint_trace_contracts", "test_assembly_file_contracts", "test_module_analysis_contracts", "test_database_settings_contracts",
              "test_provider_ui_contracts", "test_library_script_contracts", "test_job_event_artifact_contracts", "test_native_launch_arguments", "test_native_component_builds", "test_ipc_wire_codec")

EXECUTION_TOOLS = ("execution_resume", "execution_pause", "execution_step_into", "execution_step_over", "execution_step_out", "execution_run_to",
                   "execution_skip_instruction", "execution_wait", "threads_list", "threads_select", "threads_suspend", "threads_resume", "threads_context",
                   "exceptions_state", "exceptions_policy_get", "exceptions_policy_set")
INSPECTION_TOOLS = ("registers_read", "registers_write", "expression_evaluate", "expressions_evaluate", "watches_list", "watches_set", "watches_delete",
                    "stack_read", "arguments_read", "pointers_follow", "process_peb", "thread_teb", "seh_chain", "unwind_info", "structures_list", "structures_decode")
MEMORY_TOOLS = ("memory_map", "memory_read", "memory_read_string", "memory_write", "memory_allocate", "memory_free", "memory_protection_set",
                "memory_search_pattern", "memory_search_text", "memory_strings", "memory_dump", "memory_dumpable_regions", "modules_dump", "handles_list", "heaps_list")
BREAKPOINT_TRACE_TOOLS = ("breakpoints_list", "breakpoints_create", "breakpoints_update", "breakpoints_delete", "breakpoints_enable", "breakpoints_toggle",
                         "breakpoints_reset_hits", "breakpoints_clear", "trace_start", "trace_stop", "trace_state", "trace_open", "trace_read", "trace_search", "trace_export")
ASSEMBLY_FILE_TOOLS = ("disassembly_read", "disassembly_function", "assembly_encode", "assembly_apply", "patch_sets_create", "patch_sets_list", "patch_sets_read",
                       "patch_apply_runtime", "patch_restore_runtime", "patch_restore_all", "patch_export_file", "file_inspect", "file_patch_plan", "file_patch_apply",
                       "file_patch_undo", "file_compare", "file_export")
MODULE_ANALYSIS_TOOLS = ("modules_list", "modules_sections", "modules_imports", "modules_exports", "modules_analyze_pe", "modules_oep_candidates", "symbols_list",
                         "symbols_search", "symbols_load", "symbols_unload", "analysis_start", "analysis_functions", "analysis_blocks", "analysis_graph", "analysis_references",
                         "analysis_loops", "analysis_encoding_get", "analysis_encoding_set", "analysis_function_set", "analysis_argument_set", "analysis_range_delete")
DATABASE_SETTINGS_TOOLS = ("annotations_list", "annotations_set", "annotations_delete", "annotations_import", "annotations_export", "database_save", "database_load",
                           "database_clear", "database_info", "settings_list", "settings_apply", "favorites_list", "favorites_set")
PROVIDER_UI_TOOLS = ("commands_list", "commands_describe", "commands_execute", "plugins_list", "plugins_actions", "plugins_invoke", "plugins_load", "plugins_unload",
                     "ui_actions_list", "ui_action_invoke", "ui_views_list", "ui_view_read", "ui_view_navigate", "ui_view_configure", "ui_dialogs_list", "ui_dialog_read",
                     "ui_dialog_update", "ui_dialog_submit", "ui_clipboard_export", "ui_capture")
NATIVE_EFFECT_TOOLS = ("commands_execute", "plugins_invoke", "plugins_load", "plugins_unload", "ui_action_invoke", "ui_view_configure", "ui_dialog_update", "ui_dialog_submit")
LIBRARY_SCRIPT_TOOLS = ("library_namespaces", "library_files_list", "library_file_read", "library_file_write", "library_file_rename", "library_file_delete", "library_file_restore",
                        "library_search", "library_import", "library_export", "library_quota", "scripts_list", "scripts_create", "scripts_update", "scripts_read", "scripts_revisions",
                        "scripts_validate", "scripts_run", "scripts_delete", "script_languages", "native_script_load", "native_script_control", "native_script_breakpoint", "native_script_state", "workflows_run")
SCRIPT_NATIVE_EFFECT_TOOLS = ("scripts_run", "native_script_load", "native_script_control", "native_script_breakpoint", "workflows_run")
JOB_EVENT_ARTIFACT_TOOLS = ("jobs_list", "job_get", "job_wait", "job_cancel", "operation_reconcile", "events_read", "events_wait", "events_clear", "artifacts_list", "artifacts_create",
                            "artifacts_upload_begin", "artifacts_upload_chunk", "artifacts_upload_finish", "artifacts_read", "artifacts_delete", "diagnostics_export")
JOB_NATIVE_EFFECT_TOOLS = ("job_cancel",)


def build_contract_fixture(output, architecture, cmake=None, msvc_toolset=None, unity_build=False):
    build = Path(output) / f"build-{architecture}"
    build.mkdir()
    source = ROOT / "x64dbg"
    environment, cmake_path, compiler_path, toolchain = resolve_build_toolchain(build, architecture, cmake, msvc_toolset, unity_build)
    qt = source / ("build64" if architecture == "x64" else "build32") / "_deps/qt5-src/lib/cmake/Qt5"
    configure = [str(cmake_path), "-S", str(source), "-B", str(build), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                 "-DX64DBG_BUILD_IN_TREE=OFF", "-DX64DBG_BUILD_MCP=ON", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMKR_SKIP_GENERATION=ON",
                 "-DCMAKE_UNITY_BUILD=" + ("ON" if unity_build else "OFF"),
                 f"-DCMAKE_C_COMPILER={compiler_path.as_posix()}", f"-DCMAKE_CXX_COMPILER={compiler_path.as_posix()}"]
    if qt.is_dir():
        configure.append(f"-DQt5_DIR={qt}")
    commands = []
    source_paths = [source / "cmake.toml", source / "CMakeLists.txt", *sorted((source / "src/mcp").rglob("*")), *sorted((source / "src/dbg/mcp").rglob("*"))]
    parity_header = json.loads((source / "src/mcp/common/parity_catalog.jsonl").open(encoding="ascii").readline())["data"]
    source_paths.extend(ROOT / entry["path"] for entry in parity_header["sourceInputs"])
    source_paths = list(dict.fromkeys(source_paths))
    source_inputs = [file_identity(path) for path in source_paths if path.is_file()]
    with (build / "build.log").open("w", encoding="utf-8") as log:
        for command in (configure, [str(cmake_path), "--build", str(build), "--target", "mcp_contract_fixture", "mcp_launch_reference", "mcp_broker", "mcp_connect", "mcp_worker", "--parallel", "6"]):
            print(f"Building MCP contracts {architecture}: {command[1]}", flush=True)
            process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
            log.flush()
            commands.append({"command": command, "exitCode": process.returncode})
            write_json(build / "commands.json", commands)
            if process.returncode:
                raise McpError(f"Contract fixture build failed: {(build / 'build.log').read_text(encoding='utf-8')[-6000:]}")
    binary = build / "wininspect-mcp-contract-fixture.exe"
    components = [build / "wininspect-mcp.exe", build / "wininspect-mcp-connect.exe"]
    for artifact in (binary, build / "wininspect-mcp-launch-reference.exe", *components):
        image = artifact.read_bytes()
        pe_offset = struct.unpack_from("<I", image, 0x3c)[0]
        assert image[:2] == b"MZ" and image[pe_offset:pe_offset + 4] == b"PE\0\0"
        assert struct.unpack_from("<H", image, pe_offset + 4)[0] == (0x8664 if architecture == "x64" else 0x14c)
    manifest = {"architecture": architecture, "sourceHead": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "sourceStatus": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
                "sourceInputs": source_inputs, "commands": commands, "toolchain": toolchain, "binary": file_identity(binary),
                "launchReference": file_identity(build / "wininspect-mcp-launch-reference.exe"),
                "nativeComponents": [file_identity(path) for path in components],
                "buildInputs": file_identity(build / "CMakeCache.txt"),
                "compiledDependencies": [file_identity(path) for path in sorted(build.glob("mcp_*.lib"))],
                "compileCommands": json.loads((build / "compile_commands.json").read_text(encoding="utf-8")),
                "notices": [file_identity(path) for path in sorted((build / "mcp-notices").glob("*.txt"))]}
    for input_file in source_inputs:
        assert file_identity(input_file["path"])["sha256"] == input_file["sha256"], "Build source changed during compilation"
    for key in ("cmake", "compiler"):
        assert file_identity(toolchain[key]["path"]) == toolchain[key], "Build tool changed during compilation"
    write_json(build / "build-manifest.json", manifest)
    return binary


class ContractProbe:
    def __init__(self, binary, output, timeout):
        self.binary = binary
        self.output = Path(output)
        self.output.mkdir()
        self.timeout = timeout
        self.observations = []

    def call(self, mode, value=None, argument=None, raw=None):
        command = [str(self.binary), mode]
        if argument is not None:
            command.append(argument)
        payload = raw if raw is not None else b"" if value is None else json.dumps(value, ensure_ascii=False).encode("utf-8")
        stdout, stderr, observation = self.execute(command, payload)
        response = json.loads(stdout)
        observation["response"] = response
        return response

    def execute(self, command, payload=b"", expected_exit=0):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        timed_out = False
        try:
            identity = process_identity(process)
            stdout, stderr = process.communicate(payload, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.communicate()
            raise
        observation = {"command": command, "inputSha256": hashlib.sha256(payload).hexdigest(), "inputSize": len(payload),
                       "stdoutSize": len(stdout), "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
                       "processIdentity": identity, "exitCode": process.returncode, "expectedExitCode": expected_exit,
                       "timedOut": timed_out, "stderr": stderr.decode("utf-8", "replace")}
        self.observations.append(observation)
        assert not timed_out, f"Owned contract fixture timed out: {identity}"
        assert process.returncode == expected_exit, observation
        return stdout, stderr, observation


def check_dependency_sources(build):
    record_path = ROOT / "x64dbg/src/mcp/dependencies.json"
    record_identity = file_identity(record_path)
    manifest = json.loads((build / "build-manifest.json").read_text(encoding="utf-8"))
    assert record_identity in manifest["sourceInputs"], "Dependency record differs from the built source"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    packages = {"http": ("mcp_boost", "LICENSE_1_0.txt"), "json": ("mcp_json_source", "LICENSE.MIT"),
                "store": ("mcp_sqlite_source", None), "javascript": ("mcp_quickjs_source", "LICENSE")}
    assert record["schemaVersion"] == 1 and len(record["dependencies"]) == len(packages)
    assert {entry["role"] for entry in record["dependencies"]} == set(packages)
    observations = []
    for entry in record["dependencies"]:
        package, notice_filename = packages[entry["role"]]
        archive_root = build / "_deps" / f"{package}-subbuild" / f"{package}-populate-prefix/src"
        fetch_path = archive_root / f"{package}-populate-stamp/{package}-populate-urlinfo.txt"
        fetch = dict(line.split("=", 1) for line in fetch_path.read_text(encoding="utf-8").splitlines() if "=" in line)
        if "url(s)" in fetch:
            assert fetch["url(s)"] == entry["sourceUrl"], f"{entry['role']} fetched a different source URL"
            assert fetch["hash"] == "SHA256=" + entry["archiveSha256"], f"{entry['role']} fetched a different archive pin"
        else:
            assert fetch["repository"] == "'external project URL'", f"{entry['role']} fetch is not a source archive"
            assert fetch["module"] == f"'{entry['sourceUrl']}'", f"{entry['role']} fetched a different source URL"
            assert fetch["tag"] == f"'SHA256={entry['archiveSha256']}'", f"{entry['role']} fetched a different archive pin"
        archives = [file_identity(path) for path in archive_root.iterdir() if path.is_file()]
        matches = [archive for archive in archives if archive["sha256"] == entry["archiveSha256"]]
        assert len(matches) == 1, f"{entry['role']} retained archive does not match its SHA-256"
        notice_path = build / "mcp-notices" / entry["notice"]
        source_notice = build / "_deps" / f"{package}-src" / notice_filename if notice_filename else ROOT / "x64dbg/src/mcp/notices/sqlite.txt"
        notice = file_identity(notice_path)
        assert notice["sha256"] == entry["noticeSha256"], f"{entry['role']} notice differs from its recorded SHA-256"
        assert notice_path.read_bytes() == source_notice.read_bytes(), f"{entry['role']} source notice was changed"
        observations.append({"role": entry["role"], "version": entry["version"], "license": entry["license"],
                             "sourceUrl": entry["sourceUrl"], "archive": matches[0], "fetch": file_identity(fetch_path),
                             "notice": notice, "sourceNotice": file_identity(source_notice)})
    assert file_identity(record_path) == record_identity, "Dependency record changed during verification"
    return {"dependencyRecord": record_identity, "sourceDependencies": observations}


def independent_validators(catalog):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as error:
        raise McpError("The mcp-contracts phase requires the test-only requirements in tests/requirements.txt") from error
    formats = FormatChecker()
    checks = {
        "uint64-decimal": lambda value: bool(re.fullmatch(r"0|[1-9][0-9]{0,19}", value)) and int(value) <= 2**64 - 1,
        "uint64-hex": lambda value: bool(re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", value)),
        "opaque-id": lambda value: bool(re.fullmatch(r"[A-Za-z0-9_.:-]+", value)),
        "hex-bytes": lambda value: bool(re.fullmatch(r"(?:[0-9a-f]{2})+", value)),
        "sha256": lambda value: bool(re.fullmatch(r"[0-9a-f]{64}", value)),
        "utf8-text": lambda value: "\0" not in value,
        "windows-absolute-path": lambda value: bool(re.fullmatch(r"(?:[A-Za-z]:[\\/].*|\\\\(?!\.\\|\?\\)[^\\]+\\[^\\]+(?:\\.*)?|\\\\\?\\[A-Za-z]:[\\/].*|\\\\\?\\UNC\\[^\\]+\\[^\\]+(?:\\.*)?)", value)) and not any(ord(character) < 32 for character in value)
    }
    checks["windows-command-line"] = lambda value: "\0" not in value and len(value.encode("utf-16-le")) // 2 <= 32766
    checks["windows-environment-name"] = lambda value: bool(value) and "=" not in value and "\0" not in value and len(value.encode("utf-16-le")) // 2 <= 32766
    def virtual_path(value):
        parts = value.split("/")
        if len(value.encode("utf-16-le")) // 2 > 4096 or len(parts) > 64 or re.search(r'[\x00-\x1f<>:"\\|?*]', value):
            return False
        for part in parts:
            if not part or part in (".", "..") or part.endswith((".", " ")) or len(part.encode("utf-16-le")) // 2 > 255:
                return False
            stem = part.partition(".")[0].rstrip(" ").translate(str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
            if stem in ("CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$") or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem):
                return False
        return True
    checks["library-virtual-path"] = virtual_path
    for name, check in checks.items():
        formats.checks(name)(lambda value, check=check: not isinstance(value, str) or check(value))
    validators = {}
    for entry in catalog["contracts"]:
        Draft202012Validator.check_schema(entry["schema"])
        assert entry["name"] not in validators
        assert entry["schema"]["$id"] == f"urn:wininspect:mcp:contract:v1:{entry['name']}"
        validators[entry["name"]] = Draft202012Validator(entry["schema"], format_checker=formats)
    return validators


def contract_examples():
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "18446744073709551615"}
    paused = {**target, "stopEpoch": "9007199254740993", "threadId": 4294967295}
    mutation = {**paused, "leaseId": "lease-1", "idempotencyKey": "request-1"}
    examples = {
        "InstanceRef": [(True, {"instanceId": "instance-1"}), (False, {}), (False, {"instanceId": 1})],
        "TargetRef": [(True, target), (False, {**target, "targetGeneration": 9007199254740993}), (False, {**target, "targetGeneration": "18446744073709551616"})],
        "PausedContext": [(True, paused), (False, target), (False, {**paused, "threadId": 0}), (False, {**paused, "threadId": 4294967296})],
        "MutationContext": [(True, mutation), (False, paused), (False, {**mutation, "leaseId": ""})],
        "AddressRef": [(True, {"addressHex": "0xffffffffffffffff"}), (True, {"moduleId": "module-1", "rvaHex": "0x123"}), (True, {"expression": "Hu Tao ❤ + rax"}),
                       (False, {}), (False, {"moduleId": "module-1"}), (False, {"addressHex": "0x1", "expression": "rax"})],
        "AddressRange": [(True, {"address": {"addressHex": "0x0"}, "size": 1048576}), (False, {"address": {"addressHex": "0x0"}, "size": 0}), (False, {"address": {"expression": "rax"}, "size": 1048577})],
        "FileRef": [(True, {"artifactId": "artifact-1"}), (True, {"path": "C:\\Hu Tao ❤\\target.exe"}), (True, {"path": "\\\\server\\share\\file.exe"}),
                    (True, {"path": "\\\\?\\C:\\target.exe"}), (True, {"path": "\\\\?\\UNC\\server\\share\\file.exe"}),
                    (False, {"path": "relative.exe"}), (False, {"path": "C:relative.exe"}), (False, {"path": "\\\\.\\pipe\\debug"}), (False, {"path": "C:\\file\0.exe"}),
                    (False, {"path": "C:\\target.exe", "artifactId": "artifact-1"})],
        "ExpectedBytes": [(True, {"bytesHex": "0001ff"}), (True, {"bytesHex": "00" * 1048576}), (False, {"bytesHex": "00" * 1048577}),
                          (True, {"address": {"addressHex": "0x1"}, "size": 1, "sha256": "0" * 64}),
                          (False, {"bytesHex": "0"}), (False, {"bytesHex": "GG"}), (False, {"bytesHex": "00", "size": 1})],
        "Page": [(True, {}), (True, {"limit": 1000}), (True, {"limit": 100.0}), (False, {"limit": 0}), (False, {"limit": 1001}), (False, {"limit": True}), (False, {"limit": 1.5})],
        "Deadline": [(True, {}), (True, {"timeoutMs": 1}), (True, {"timeoutMs": 60000}), (False, {"timeoutMs": 0}), (False, {"timeoutMs": 60001}), (False, {"timeoutMs": "60000"})],
        "Hex64": [(True, "0x0"), (True, "0xffffffffffffffff"), (False, 18446744073709551615), (False, "0x10000000000000000"), (False, "0x00"), (False, "0xFF")],
        "Decimal64": [(True, "0"), (True, "18446744073709551615"), (False, "18446744073709551616"), (False, "01"), (False, "-1"), (False, 9007199254740993)]
    }
    recovery = {"capabilityId": "operation_reconcile", "retry": "after_reconciliation", "reason": "Inspect the operation"}
    evidence = {"kind": "readback", "source": "native_fixture", "summary": "Observed exact bytes"}
    examples.update({
        "IpcEnvelope": [(True, {"context": {"brokerGeneration": "18446744073709551615"}, "deadlineUtcMs": "9007199254740993", "authenticationContextId": "context-fixture", "payload": {"method": "ping"}}),
                        (False, {"context": target, "deadlineUtcMs": 9007199254740993, "authenticationContextId": "context-fixture", "payload": {}}),
                        (False, {"context": target, "deadlineUtcMs": "1", "authenticationContextId": "context-fixture", "payload": []})],
        "NativeProcessIdentity": [(True, {"pid": 1, "creationTime": "18446744073709551615", "sessionId": 1, "userSid": "S-1-5-21-1", "logonSid": "S-1-5-5-1-2", "integrity": "medium", "elevated": False, "architecture": "x64",
            "image": {"path": "C:\\controlled.exe", "sha256": "0" * 64, "size": "1", "volumeSerial": 1, "fileIndex": "18446744073709551615"}}), (False, {"pid": 1})],
        "LibraryRef": [(True, {"namespaceId": "private-1", "objectId": "script-1", "revision": "rev-2"}), (False, {"namespaceId": "private-1", "objectId": "script-1"})],
        "JobRef": [(True, {"jobId": "job-1"}), (False, {"jobId": None})],
        "EventRef": [(True, {"cursor": "opaque:9007199254740993"}), (False, {"cursor": 9007199254740993})],
        "RecoveryRoute": [(True, recovery), (False, {**recovery, "retry": "automatically"})],
        "DomainError": [(True, {"code": "timeout_unknown", "message": "Reconcile", "path": "", "recovery": recovery}), (False, {"code": "success", "message": "Incorrect", "path": ""})],
        "ResultContext": [(True, {"brokerGeneration": "18446744073709551615"}), (True, target), (True, paused), (False, {**target, "brokerGeneration": "1"})],
        "VerificationEvidence": [(True, evidence), (True, {**evidence, "artifactId": "artifact-1", "sha256": "0" * 64}), (False, {**evidence, "sha256": "0" * 63})],
        "Verification": [(True, {"status": "verified", "evidence": [evidence]}), (True, {"status": "unverified", "evidence": [], "followUp": recovery}),
                         (True, {"status": "pending", "evidence": []}), (False, {"status": "verified", "evidence": []}), (False, {"status": "unverified", "evidence": []}), (False, {"status": "passed", "evidence": [evidence]})],
        "ResultWarning": [(True, {"code": "scan_holes", "message": "Some ranges are unreadable"}), (False, {"code": "", "message": "Missing warning code"})],
        "ResultTimings": [(True, {"startedUtcMs": "9007199254740993", "elapsedUs": "18446744073709551615", "queueUs": "0"}), (False, {"startedUtcMs": 9007199254740993, "elapsedUs": "1", "queueUs": "0"})],
        "EffectObservation": [(True, {"stepId": "write-1", "status": "restored", "summary": "Original bytes observed"}), (False, {"stepId": "write-1", "status": "successful", "summary": "Unknown status"})],
        "ResultPagination": [(True, {"snapshotVersion": "9007199254740993", "complete": True}), (True, {"snapshotVersion": "1", "complete": False, "nextCursor": "next"}),
                             (False, {"snapshotVersion": "1", "complete": False}), (False, {"snapshotVersion": "1", "complete": True, "nextCursor": "contradiction"}), (False, {"snapshotVersion": "1", "complete": 1})]
    })
    return examples, mutation


def check_results(probe, formats):
    from jsonschema import Draft202012Validator
    fixture = probe.call("result-cases")
    for schema in (fixture["schema"], fixture["unverifiedSchema"]):
        Draft202012Validator.check_schema(schema)
    strict = Draft202012Validator(fixture["schema"], format_checker=formats)
    relaxed = Draft202012Validator(fixture["unverifiedSchema"], format_checker=formats)
    results = fixture["results"]
    assert [result["outcome"] for result in results] == ["completed", "accepted", "partial_failure", "failed", "cancelled", "unknown", "completed"]
    for index, result in enumerate(results):
        expected = index != 6
        assert strict.is_valid(result) == expected
        assert probe.call("result-validate", result)["valid"] == expected
        assert relaxed.is_valid(result) and probe.call("result-unverified", result)["valid"]
        assert result["stateVersion"] == "18446744073709551615" and result["context"]["stopEpoch"] == "9007199254740993"
        assert result["timings"]["elapsedUs"] == "18446744073709551615"
    mutations = []
    assert results[0]["jobId"] == "job-fixture" and results[5]["effects"][0]["status"] == "applied" and results[5]["partial"] is True
    assert results[2]["recovery"]["capabilityId"] == results[5]["reconciliation"]["capabilityId"] == results[6]["verification"]["followUp"]["capabilityId"] == "operation_reconcile"
    for index, field in ((0, "operationId"), (1, "jobId"), (2, "effects"), (2, "recovery"), (5, "reconciliation"), (5, "effects")):
        changed = copy.deepcopy(results[index])
        del changed[field]
        mutations.append(changed)
    for index, field, value in ((0, "error", results[3]["error"]), (0, "jobId", ""), (1, "data", {"value": "0x1"}),
                               (1, "verification", results[0]["verification"]), (2, "effects", []), (2, "partial", False),
                               (3, "error", results[2]["error"]), (5, "outcome", "completed"), (0, "data", {"value": 9007199254740993}),
                               (0, "data", {"value": "0x1", "unknown": "reject"}), (0, "warnings", [{"code": "warning", "message": "Bounded"}] * 101),
                               (0, "page", {"snapshotVersion": "1", "complete": False}), (0, "page", {"snapshotVersion": "1", "complete": True, "nextCursor": "contradiction"})):
        changed = copy.deepcopy(results[index])
        changed[field] = value
        mutations.append(changed)
    changed = copy.deepcopy(results[0])
    changed["verification"]["evidence"] = []
    mutations.append(changed)
    changed = copy.deepcopy(results[0])
    changed["timings"]["queueUs"] = "18446744073709551616"
    mutations.append(changed)
    changed = copy.deepcopy(results[6])
    del changed["verification"]["followUp"]
    assert not relaxed.is_valid(changed) and not probe.call("result-unverified", changed)["valid"]
    for index, changed in enumerate(mutations):
        assert not strict.is_valid(changed), f"Independent result validator accepted contradiction {index}"
        assert not probe.call("result-validate", changed)["valid"], f"Native result validator accepted contradiction {index}"
    expected_codes = {"debugger_unavailable", "target_required", "target_running", "stale_context", "lease_conflict", "elevation_required", "elevation_denied", "permission_denied", "expected_bytes_mismatch", "file_hash_mismatch", "unsupported_mapping", "partial_failure", "timeout_unknown", "resource_limit", "unsupported_capability", "event_gap", "idempotency_conflict", "invalid_argument", "internal_error"}
    assert {error["code"] for error in fixture["errors"]} == expected_codes
    return {"typedOutcomes": 6, "rejectedContradictions": len(mutations) + 1, "typedErrorCodes": sorted(expected_codes)}


def check_schema_references(probe, formats):
    from jsonschema import Draft202012Validator
    schema = {"$defs": {"Count": {"type": "integer", "minimum": 1, "maximum": 100},
                        "Nested": {"type": "object", "properties": {"count": {"$ref": "#/$defs/Count"}}, "required": ["count"], "additionalProperties": False}},
              "$ref": "#/$defs/Nested"}
    validator = Draft202012Validator(schema, format_checker=formats)
    for expected, value in ((True, {"count": 1}), (False, {"count": 0}), (False, {"count": True}), (False, {"count": 1, "other": 2})):
        assert validator.is_valid(value) == expected
        assert probe.call("schema-validate", {"schema": schema, "value": value})["valid"] == expected
    failures = [("invalid_contract", {"$ref": "https://invalid.example/schema"}), ("invalid_contract", {"$ref": "#/$defs/Missing"}),
                ("resource_limit", {"$defs": {"Loop": {"$ref": "#/$defs/Loop"}}, "$ref": "#/$defs/Loop"}),
                ("invalid_contract", {"unsupportedKeyword": True}), ("invalid_contract", {"type": "string", "format": "utf8-text", "minLength": 0, "maxLength": 100, "pattern": "^accepted$"})]
    failures.extend([
        ("invalid_contract", {"$defs": {"Unused": {"unsupportedKeyword": True}}, "const": "rejected"}),
        ("invalid_contract", {"properties": {"count": {"const": 1}}}),
        ("invalid_contract", {"type": "object", "properties": {"unused": {"$ref": "#/$defs/Missing"}}, "required": [], "additionalProperties": False}),
        ("invalid_contract", {"oneOf": []}),
        ("invalid_contract", {"not": False}),
        ("invalid_contract", {"not": {"unsupportedKeyword": True}}),
        ("invalid_contract", {"not": {"$ref": "#/$defs/Missing"}}),
        ("resource_limit", {"$defs": {"Loop": {"not": {"$ref": "#/$defs/Loop"}}}, "$ref": "#/$defs/Loop"})])
    for code, unsupported in failures:
        response = probe.call("schema-validate", {"schema": unsupported, "value": "rejected"})
        assert not response["valid"] and response["error"]["code"] == code, response
    sibling = {"$defs": {"Value": {"enum": [1, 2]}}, "$ref": "#/$defs/Value", "const": 2}
    for value in (1, 2):
        assert probe.call("schema-validate", {"schema": sibling, "value": value})["valid"] == (value == 2)
    forbidden = {"$defs": {"Zero": {"const": "0"}}, "not": {"$ref": "#/$defs/Zero"}}
    for expected, value in ((False, "0"), (True, "1"), (True, 0), (True, {})):
        assert Draft202012Validator(forbidden).is_valid(value) == expected
        assert probe.call("schema-validate", {"schema": forbidden, "value": value})["valid"] == expected
    return {"independentLocalReferenceCases": 4, "rejectedUnsupportedOrCyclicSchemas": len(failures), "referenceSiblingConstraints": 2, "independentNegationCases": 4}


def registry_validators(registry, formats):
    from jsonschema import Draft202012Validator
    validators = {}
    expected = {"server_info", "server_health", "capabilities_list", "capabilities_describe", "capabilities_search", "client_context_get", "client_context_set", "control_acquire", "control_renew", "control_release"}
    expected.update({"debugger_instances", "debugger_start", "debugger_focus", "debugger_close", "debugger_settings_get", "debugger_settings_set", "processes_list", "target_open", "target_attach", "target_state", "target_snapshot", "target_stop", "target_detach", "target_restart", "target_command_line_get", "target_command_line_set"})
    expected.update(EXECUTION_TOOLS + INSPECTION_TOOLS + MEMORY_TOOLS + BREAKPOINT_TRACE_TOOLS + ASSEMBLY_FILE_TOOLS + MODULE_ANALYSIS_TOOLS + DATABASE_SETTINGS_TOOLS + PROVIDER_UI_TOOLS + LIBRARY_SCRIPT_TOOLS + JOB_EVENT_ARTIFACT_TOOLS)
    assert registry["operationalTools"] == [] and {tool["name"] for tool in registry["tools"]} == expected
    assert [tool["name"] for tool in registry["tools"]] == sorted(expected)
    for tool in registry["tools"]:
        assert tool["schemaVersion"] == 1 and tool["operational"] is False
        assert tool["completionPredicate"] and tool["nativeSource"] and tool["recovery"] and tool["acceptanceIds"]
        assert tool["annotations"]["readOnlyHint"] == (tool["effects"] == ["inspect"] and not tool["effectConditions"])
        assert tool.get("effectResolution") == ("native_classifier" if tool["name"] in NATIVE_EFFECT_TOOLS + SCRIPT_NATIVE_EFFECT_TOOLS + JOB_NATIVE_EFFECT_TOOLS else None)
        assert tool["executor"] in ("broker", "engine", "gui")
        assert tool["architectureRequirement"] == {"seh_chain": "x32", "unwind_info": "x64"}.get(tool["name"], "any")
        for direction in ("input", "output"):
            schema = tool[f"{direction}Schema"]
            Draft202012Validator.check_schema(schema)
            assert schema["$id"] == f"urn:wininspect:mcp:tool:v1:{tool['name']}:{direction}"
            validators[(tool["name"], direction)] = Draft202012Validator(schema, format_checker=formats)
    return validators


def check_legacy_alias_contracts(probe, registry):
    from jsonschema import Draft202012Validator
    baseline_path = ROOT / "tests/native_mcp/legacy-manifest.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected = {entry["legacyName"]: entry for entry in baseline["tools"]}
    canonical = {entry["name"]: entry for entry in registry["tools"]}
    observed = probe.call("legacy-registry")
    assert observed["schemaVersion"] == 1 and observed["buildId"] == registry["buildId"]
    assert observed["baselineProvider"] == baseline["baselineProvider"]
    assert observed["baselineManifestSha256"] == file_identity(baseline_path)["sha256"]
    assert observed["capturedCatalogSha256"] == "da94480c94bf61c048116e61303d6b6bef722e94ca345b1e52f6b2c1b4e43255"
    assert observed["operationalAliases"] == []
    assert [entry["name"] for entry in observed["aliases"]] == sorted(expected)
    assert len(observed["aliases"]) == len(expected) == 80
    compared_inputs = defaults = canonical_bindings = 0
    for alias in observed["aliases"]:
        name = alias["name"]
        original = expected[name]
        assert alias["description"] == original["description"] and alias["inputSchema"] == original["inputSchema"]
        assert alias["capturedAnnotations"] == original["annotations"]
        assert alias["originalRoute"] == original["canonicalRoute"] and alias["compatibilityPredicate"] == original["completionPredicate"]
        assert alias["availability"] == "planned" and alias["operational"] is False and alias["executionAdapterInstalled"] is False
        expected_kind = "protocol_echo" if name == "Echo" else "instance_or_target_state" if name == "GetDebugState" else "canonical"
        expected_routes = [] if name == "Echo" else ["debugger_instances", "target_state"] if name == "GetDebugState" else [original["canonicalRoute"]]
        assert alias["bindingKind"] == expected_kind
        assert [binding["capabilityId"] for binding in alias["canonicalBindings"]] == expected_routes
        for binding in alias["canonicalBindings"]:
            definition = canonical[binding["capabilityId"]]
            fields = ("capabilityId", "effects", "effectConditions", "executor", "stateRequirement", "architectureRequirement", "completionPredicate", "recovery", "acceptanceIds")
            inherited = {field: definition[field] for field in fields}
            if "effectResolution" in definition:
                inherited["effectResolution"] = definition["effectResolution"]
            assert binding == inherited
            canonical_bindings += 1
        assert probe.call("legacy-describe", argument=name) == {"valid": True, "alias": alias}
        schema = original["inputSchema"]
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        supplied = {field: "Hu Tao ❤,{}\\\"" if property["type"] == "string" else 42 if property["type"] == "integer" else True
                    for field, property in schema["properties"].items()}
        cases = [(supplied, True), ([], False), (None, False), ({**supplied, "unregisteredField": {"preserved": [1, True, None]}}, True)]
        minimal = {field: supplied[field] for field in schema["required"]}
        cases.append((minimal, True))
        for field in schema["required"]:
            cases.append(({key: value for key, value in supplied.items() if key != field}, False))
        for field, property in schema["properties"].items():
            type = property["type"]
            for value in ((False, "42", 1.5, None) if type == "integer" else (0, "true", None) if type == "boolean" else (0, True, None)):
                cases.append(({**supplied, field: value}, False))
            if type == "integer":
                cases.extend(({**supplied, field: value}, True) for value in (42.0, -1, 2**64 - 1))
            if type == "string":
                cases.extend(({**supplied, field: value}, True) for value in ("", "embedded\0text"))
        for arguments, valid in cases:
            assert validator.is_valid(arguments) == valid, f"Independent legacy input differs: {name}"
            response = probe.call("legacy-input", arguments, name, raw=b"null" if arguments is None else None)
            assert response["valid"] == valid, f"Native legacy input differs: {name}: {arguments}"
            if valid:
                normalized = {**arguments}
                for field, property in schema["properties"].items():
                    if field not in normalized and "default" in property:
                        normalized[field] = property["default"]
                assert response["arguments"] == normalized
            else:
                assert response["error"]["code"] == "invalid_argument"
            compared_inputs += 1
        defaults += sum("default" in property for property in schema["properties"].values())
        unsupported = probe.call("call", supplied, name)
        assert not unsupported["valid"] and unsupported["error"]["code"] == "unsupported_capability"
    for unknown in ("RUN", "echo", "loadbinary", "GetDebugstate", "UnknownAlias", ""):
        described = probe.call("legacy-describe", argument=unknown)
        assert not described["valid"] and described["error"]["code"] == "unsupported_capability"
        validated = probe.call("legacy-input", {}, unknown)
        assert not validated["valid"] and validated["error"]["code"] == "unsupported_capability"
    assert defaults == 24
    output = probe.output / "compiled-legacy-aliases.json"
    write_json(output, observed)
    return {"aliases": len(expected), "canonicalBindings": canonical_bindings, "capturedDefaults": defaults,
            "independentInputComparisons": compared_inputs, "operationalAliases": 0, "compiledAliases": file_identity(output)}


def check_registry_contracts(probe, registry, validators):
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "18446744073709551615"}
    examples = {
        "server_info": {}, "server_health": {}, "capabilities_list": {"limit": 2, "availability": "planned"},
        "capabilities_describe": {"capabilityId": "server_info"}, "capabilities_search": {"query": "capabilities", "limit": 2},
        "client_context_get": {}, "client_context_set": {"defaultTarget": target},
        "control_acquire": {**target, "purpose": "Controlled fixture", "durationMs": 30000, "idempotencyKey": "request-1"},
        "control_renew": {**target, "leaseId": "lease-1", "durationMs": 60000}, "control_release": {**target, "leaseId": "lease-1"}}
    comparisons = 0
    for name, value in examples.items():
        validator = validators[(name, "input")]
        assert validator.is_valid(value) and probe.call("tool-input", value, name)["valid"]
        unknown = {**value, "unregisteredField": "reject"}
        assert not validator.is_valid(unknown) and not probe.call("tool-input", unknown, name)["valid"]
        comparisons += 2
    for name, value in (("control_acquire", {**examples["control_acquire"], "durationMs": 0}),
                        ("control_renew", {**examples["control_renew"], "durationMs": 60001}),
                        ("control_release", {**examples["control_release"], "targetGeneration": 9007199254740993}),
                        ("capabilities_list", {"availability": "ready"}), ("capabilities_search", {"query": "x" * 257}),
                        ("client_context_set", {"defaultTarget": {**target, "targetGeneration": "18446744073709551616"}})):
        assert not validators[(name, "input")].is_valid(value) and not probe.call("tool-input", value, name)["valid"]
        comparisons += 1
    for tool in registry["tools"]:
        assert tool["availability"] == ("implemented" if tool["name"] in ("capabilities_list", "capabilities_describe", "capabilities_search") else "planned")
    return {"declaredTools": len(registry["tools"]), "independentComparisons": comparisons, "operationalTools": 0}


def check_registry_dispatch(probe, registry, validators):
    def call(name, value):
        response = probe.call("call", value, name)
        assert response["valid"], response
        result = response["result"]
        assert validators[(name, "output")].is_valid(result), f"Independent output rejection for {name}"
        assert probe.call("tool-output", result, name)["valid"]
        assert result["outcome"] == "completed" and result["verification"]["status"] == "verified"
        assert result["context"] == {"brokerGeneration": "9007199254740993"} and result["stateVersion"] == "18446744073709551615"
        return result["data"]
    actual = []
    request = {"limit": 2}
    cursors = []
    while True:
        page = call("capabilities_list", request)
        assert page["snapshotId"] == registry["buildId"] and len(page["items"]) <= 2
        actual.extend(page["items"])
        if page["complete"]:
            assert "nextCursor" not in page
            break
        cursors.append(page["nextCursor"])
        request = {"limit": 2, "cursor": page["nextCursor"]}
    assert actual == registry["tools"] and len({item["name"] for item in actual}) == len(actual)
    bounded_pages = {}
    for limit in (None, 1000):
        request = {} if limit is None else {"limit": limit}
        collected = []
        page_count = 0
        while True:
            page = call("capabilities_list", request)
            assert len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) < 1024 * 1024
            collected.extend(page["items"])
            page_count += 1
            if page["complete"]:
                assert "nextCursor" not in page
                break
            assert page["items"] and page["nextCursor"] not in request.values()
            request = {**request, "cursor": page["nextCursor"]}
        assert collected == registry["tools"] and page_count > 1
        bounded_pages[str(limit)] = page_count
    assert not probe.call("call", {"limit": 2, "cursor": cursors[0], "domain": "capabilities"}, "capabilities_list")["valid"]
    assert not probe.call("call", {"cursor": "registry:wrong-build:capabilities_list"}, "capabilities_list")["valid"]
    implemented = call("capabilities_list", {"availability": "implemented"})
    assert [item["name"] for item in implemented["items"]] == ["capabilities_describe", "capabilities_list", "capabilities_search"]
    assert call("capabilities_list", {"provider": "missing.provider"})["items"] == []
    for tool in actual:
        assert call("capabilities_describe", {"capabilityId": tool["name"]})["capability"] == tool
    search = call("capabilities_search", {"query": "CAPABILITIES_LIST", "limit": 1})
    assert search["items"][0] == {"capabilityId": "capabilities_list", "description": next(item["description"] for item in actual if item["name"] == "capabilities_list"), "score": 3}
    ranked = call("capabilities_search", {"query": "capabilities"})
    assert [item["capabilityId"] for item in ranked["items"] if item["score"] == 2] == ["capabilities_describe", "capabilities_list", "capabilities_search"]
    for name, value in (("server_info", {}), ("control_release", {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "1", "leaseId": "lease-1"}),
                        ("missing_tool", {}), ("capabilities_describe", {"capabilityId": "missing_tool"})):
        rejected = probe.call("call", value, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability"
    return {"exactDescriptors": len(actual), "paginationPages": len(cursors) + 1, "boundedDefaultAndMaximumPages": bounded_pages,
            "implementedNativeMetadataHandlers": 3, "publicOperationalTools": 0}


def check_lifecycle_contracts(probe, validators):
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "9007199254740993"}
    instance = {"instanceId": "instance-1"}
    mutation = {**target, "leaseId": "lease-1"}
    valid = {
        "debugger_instances": {"architecture": "x32", "mode": "headless"}, "debugger_start": {"architecture": "x64", "mode": "gui", "privilege": "user"},
        "debugger_focus": instance, "debugger_close": {**instance, "targetPolicy": "require_none"}, "debugger_settings_get": {**instance, "section": "Engine"},
        "debugger_settings_set": {**instance, "changes": [{"section": "Engine", "key": "Test", "value": {"kind": "uint64", "value": "18446744073709551615"}}], "expectedVersion": "9007199254740993"},
        "processes_list": {"name": "controlled.exe", "limit": 1000}, "target_open": {**instance, "path": "C:\\controlled.exe", "argv": ["", "two words", "Hu Tao ❤", "\\\""]},
        "target_attach": {**instance, "pid": 123, "creationTime": "18446744073709551615", "expectedImage": {"path": "C:\\controlled.exe", "sha256": "0" * 64}},
        "target_state": target, "target_snapshot": {**target, "parts": ["registers", "modules"], "consistency": "paused"},
        "target_stop": mutation, "target_detach": {**mutation, "resumePolicy": "resume"}, "target_restart": {**mutation, "launchOverrides": {"argv": []}},
        "target_command_line_get": target, "target_command_line_set": {**mutation, "argv": [], "expectedVersion": "18446744073709551615"}}
    cases = [(True, name, value) for name, value in valid.items()]
    cases.extend((False, name, {**value, "unknown": "reject"}) for name, value in valid.items())
    cases.extend([
        (True, "target_open", {**instance, "artifactId": "artifact-1", "rawCommandLine": '"C:\\controlled.exe" raw', "initScript": {"namespaceId": "private-1", "objectId": "script-1", "revision": "rev-1"}}),
        (False, "target_open", {**valid["target_open"], "rawCommandLine": "reject mixed forms"}),
        (False, "target_open", {**valid["target_open"], "artifactId": "artifact-1"}),
        (False, "target_open", {**instance, "path": "relative.exe"}),
        (False, "target_open", {**instance, "path": "C:\\controlled.exe", "argv": [""] * 1025}),
        (True, "target_open", {**instance, "path": "C:\\controlled.exe", "rawCommandLine": "x" * 32766}),
        (False, "target_open", {**instance, "path": "C:\\controlled.exe", "rawCommandLine": "x" * 32767}),
        (False, "target_open", {**instance, "path": "C:\\controlled.exe", "rawCommandLine": "😀" * 16384}),
        (False, "target_open", {**valid["target_open"], "environment": {"changes": [{"name": "INVALID=NAME", "value": "no"}]}}),
        (False, "target_open", {**valid["target_open"], "initScript": {"namespaceId": "private-1", "objectId": "script-1"}}),
        (False, "target_attach", {**valid["target_attach"], "creationTime": 9007199254740993}),
        (False, "target_snapshot", {**target, "parts": ["registers", "registers"]}),
        (False, "target_command_line_set", {**mutation, "expectedVersion": "1"}),
        (False, "target_restart", {**target, "launchOverrides": {}}),
        (False, "debugger_start", {**valid["debugger_start"], "privilege": "silent_admin"}),
        (False, "debugger_start", {**valid["debugger_start"], "privilege": "admin"}),
        (False, "debugger_settings_set", {**valid["debugger_settings_set"], "changes": [{"section": "Engine", "key": "Test", "value": {"kind": "uint64", "value": 9007199254740993}}]})])
    for index, (expected, name, value) in enumerate(cases):
        assert validators[(name, "input")].is_valid(value) == expected, f"Independent lifecycle case {index}"
        assert probe.call("tool-input", value, name)["valid"] == expected, f"Native lifecycle case {index}"
    assert probe.call("effects", valid["debugger_start"], "debugger_start") == {"valid": True, "effects": ["execute"]}
    assert probe.call("effects", {**valid["debugger_start"], "privilege": "administrator"}, "debugger_start") == {"valid": True, "effects": ["execute", "elevate"]}
    for name, value in valid.items():
        rejected = probe.call("call", value, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability"
    page = {"snapshotVersion": "18446744073709551615", "complete": True}
    image = {"path": "C:\\controlled.exe", "sha256": "0" * 64}
    process = {"pid": 123, "creationTime": "9007199254740993", "image": image, "architecture": "x64", "integrity": "medium"}
    registration = {"instanceId": "instance-1", "workerGeneration": "9007199254740993", "architecture": "x64", "mode": "gui", "state": "ready", "engineReady": True,
                    "process": process, "buildId": "0" * 64, "installationId": "installation-1", "profileId": "profile-1"}
    state = {"target": target, "state": "paused", "certainty": "observed", "stopEpoch": "9007199254740993", "stopReason": {"kind": "system_breakpoint"},
             "ipHex": "0x7ff123456789", "threadId": 1, "pendingJobId": None, "process": process, "allThreadsStopped": True, "exitCode": None}
    settings = {"instanceId": "instance-1", "version": "18446744073709551615", "settings": [{"section": "Engine", "key": "Test", "value": {"kind": "uint64", "value": "18446744073709551615"},
                "storage": "both", "requiresRestart": False, "nativeWidth": 64}], "complete": True}
    command_line = {"target": target, "version": "18446744073709551615", "nextLaunch": {"argv": []}, "actualCommandLine": None, "currentProcessUpdated": False}
    data = {"debugger_instances": {"items": [registration], "page": page}, "debugger_start": {"instance": registration, "launchJobId": "job-1"},
            "debugger_focus": {"instanceId": "instance-1", "visible": True, "focused": True},
            "debugger_close": {"instanceId": "instance-1", "closed": True, "targetDisposition": "none", "brokerListening": True},
            "debugger_settings_get": settings, "debugger_settings_set": settings, "processes_list": {"items": [{**process, "attachAvailable": True, "limitations": []}], "page": page},
            "target_snapshot": {"state": state, "consistency": "paused", "capturedParts": ["registers"], "registers": [{"name": "rax", "group": "general", "widthBits": 64,
                "bytesHex": "ffffffffffffffff", "validity": "valid", "reason": None}], "complete": True},
            "target_command_line_get": command_line, "target_command_line_set": command_line}
    data.update({name: state for name in ("target_open", "target_attach", "target_state", "target_stop", "target_detach", "target_restart")})
    envelope = probe.call("result-cases")["results"][0]
    output_comparisons = 0
    for name, value in data.items():
        for expected, payload in ((True, value), (False, {**value, "unknown": "reject"}), (False, {})):
            response = {**envelope, "data": payload}
            assert validators[(name, "output")].is_valid(response) == expected, f"Independent lifecycle result for {name}"
            assert probe.call("tool-output", response, name)["valid"] == expected, f"Native lifecycle result for {name}"
            output_comparisons += 1
    return {"lifecycleTools": len(valid), "independentInputComparisons": len(cases), "independentOutputComparisons": output_comparisons,
            "conditionalElevationEffects": 2, "plannedHandlersRejected": len(valid)}


def tool_context_examples():
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "9007199254740993"}
    paused = {**target, "stopEpoch": "18446744073709551615", "threadId": 123}
    mutation = {**paused, "leaseId": "lease-1", "idempotencyKey": "request-1"}
    page = {"snapshotVersion": "9007199254740993", "complete": True}
    register = {"context": paused, "architecture": "x64", "consistency": "paused", "groups": ["general", "avx512"],
                "registers": [{"name": "rax", "group": "general", "widthBits": 64, "bytesHex": "ffffffffffffffff", "aliases": ["eax"], "lanes": [], "validity": "valid", "reason": None},
                              {"name": "zmm31", "group": "avx512", "widthBits": 512, "bytesHex": "42" * 64, "aliases": ["ymm31", "xmm31"],
                               "lanes": [{"widthBits": 64, "interpretation": "unsigned", "values": ["18446744073709551615"] * 8}], "validity": "valid", "reason": None}],
                "features": [{"name": "avx512", "available": True, "enabled": True, "source": "xstate"}], "complete": True}
    frame = {"index": 0, "ipHex": "0x140001000", "spHex": "0x7ff000", "returnHex": "0x140002000", "symbol": "fixture!step", "moduleId": "module-1",
             "source": "unwind", "certainty": "verified", "bytesHex": "01020304"}
    structure = {"typeId": "type-1", "addressHex": "0x1000", "size": "8", "fields": [{"name": "value", "typeId": "uint64", "offsetHex": "0x0", "size": "8",
                 "status": "valid", "value": {"kind": "unsigned", "hex": "0xffffffffffffffff", "decimal": "18446744073709551615", "widthBits": 64}, "children": []}],
                 "complete": True, "provider": "native-types"}
    return SimpleNamespace(target=target, paused=paused, mutation=mutation, page=page, register=register, frame=frame, structure=structure)


def check_tool_family(probe, registry, validators, names, inputs, outputs, extra_inputs=(), extra_outputs=(), expected_effects=None,
                      required_fields=None, executors=None, conditions=None, native_effect_tools=(), computed_effects=None):
    assert set(names) == set(inputs) == set(outputs)
    definitions = {tool["name"]: tool for tool in registry["tools"]}
    input_cases = []
    for name, value in inputs.items():
        missing = "instanceId" if required_fields is None else required_fields[name]
        input_cases.extend(((True, name, value), (False, name, {**value, "unknown": "reject"})))
        if missing is not None:
            input_cases.append((False, name, {key: item for key, item in value.items() if key != missing}))
    input_cases.extend(extra_inputs)
    for expected, name, value in input_cases:
        assert validators[(name, "input")].is_valid(value) == expected, f"Independent input {name}: expected {expected}"
        result = probe.call("tool-input", value, name)
        assert result["valid"] == expected, f"Native input {name}: {result}"
    envelope = probe.call("result-cases")["results"][0]
    output_cases = []
    for name, value in outputs.items():
        output_cases.extend(((True, name, value), (False, name, {**value, "unknown": "reject"}), (False, name, {})))
    output_cases.extend(extra_outputs)
    for expected, name, value in output_cases:
        result = {**envelope, "data": value}
        assert validators[(name, "output")].is_valid(result) == expected, f"Independent output {name}: expected {expected}"
        response = probe.call("tool-output", result, name)
        assert response["valid"] == expected, f"Native output {name}: {response}"
    for name, value in inputs.items():
        definition = definitions[name]
        assert definition["availability"] == "planned" and definition["executor"] == ("engine" if executors is None else executors[name])
        assert definition["effectConditions"] == ([] if conditions is None else conditions.get(name, []))
        rejected = probe.call("call", value, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability", rejected
        effects = probe.call("effects", value, name)
        if name in native_effect_tools:
            assert not effects["valid"] and effects["error"]["code"] == "unsupported_capability", effects
            assert definition["effectResolution"] == "native_classifier"
        else:
            assert effects["valid"] and effects["effects"] == (computed_effects or {}).get(name, expected_effects[name])
        assert definition["effects"] == expected_effects[name]
    return {"declaredTools": len(names), "independentInputComparisons": len(input_cases), "independentOutputComparisons": len(output_cases),
            "plannedHandlersRejected": len(names), "exactEffectDeclarations": len(names)}


def check_execution_contracts(probe, registry, validators):
    c = tool_context_examples()
    exception = {"active": True, "codeHex": "0xc0000005", "addressHex": "0x140001000", "chance": "first", "handling": "debuggee", "name": "access violation", "information": ["0x1", "0x2000"]}
    observation = {"target": c.target, "state": "paused", "stopEpoch": "18446744073709551615", "threadId": 123, "ipHex": "0x140001000",
                   "eventCursor": "event:1:42", "eventSequence": "9007199254740993", "stopReason": "step", "breakpointId": None, "exception": None,
                   "exitCode": None, "completedSteps": "2", "reachedCondition": True, "allThreadsStopped": True}
    thread = {"threadId": 123, "creationIdentity": "18446744073709551615", "name": "controlled", "state": "paused", "suspendCount": 1,
              "selected": True, "ipHex": "0x140001000", "tebHex": "0x7ff000"}
    suspension = {"target": c.target, "thread": thread, "previousCount": "0", "observedCount": "1", "ownedSuspend": "suspend-1", "ownershipReleased": False}
    rule = {"range": {"firstHex": "0xc0000005", "lastHex": "0xc0000005"}, "breakOn": "first_chance", "log": True, "handledBy": "debuggee"}
    policy = {"instanceId": "instance-1", "version": "9007199254740993", "rules": [rule], "complete": True}
    inputs = {"execution_resume": {**c.mutation, "exceptionMode": "configured", "waitCondition": {"kind": "paused"}, "timeoutMs": 60000},
              "execution_pause": {**c.target, "leaseId": "lease-1"}, "execution_step_into": {**c.mutation, "count": 2, "exceptionMode": "debuggee"},
              "execution_step_over": {**c.mutation, "count": 2, "exceptionMode": "skip"},
              "execution_step_out": {**c.mutation, "returnPolicy": {"thread": "selected", "exceptionMode": "debugger"}},
              "execution_run_to": {**c.mutation, "moduleId": "module-1", "rvaHex": "0x1000", "condition": "rax == 42"},
              "execution_skip_instruction": {**c.mutation, "expectedIp": "0x140001000", "count": 1},
              "execution_wait": {**c.target, "afterCursor": "event:1:41", "condition": {"kind": "exception", "codeHex": "0xc0000005", "chance": "first"}},
              "threads_list": {**c.target, "limit": 1000}, "threads_select": {**c.mutation, "threadId": 456},
              "threads_suspend": {**c.target, "leaseId": "lease-1", "threadId": 123, "creationIdentity": "18446744073709551615"},
              "threads_resume": {**c.target, "leaseId": "lease-1", "threadId": 123, "ownedSuspend": "suspend-1"},
              "threads_context": {**c.target, "threadId": 123, "consistency": "best_effort"}, "exceptions_state": c.target,
              "exceptions_policy_get": {"instanceId": "instance-1"}, "exceptions_policy_set": {"instanceId": "instance-1", "rules": [rule], "expectedVersion": "9007199254740993"}}
    outputs = {name: observation for name in EXECUTION_TOOLS[:8]}
    outputs.update({"threads_list": {"items": [thread], "page": c.page}, "threads_select": {"context": c.paused, "thread": thread},
                    "threads_suspend": suspension, "threads_resume": suspension,
                    "threads_context": {"thread": thread, "registers": c.register, "stack": {"items": [c.frame], "page": c.page}},
                    "exceptions_state": exception, "exceptions_policy_get": policy, "exceptions_policy_set": policy})
    extra_inputs = []
    for name in ("execution_resume", "execution_step_into", "execution_step_over", "execution_step_out", "execution_run_to", "execution_skip_instruction", "threads_select"):
        extra_inputs.extend((False, name, {key: value for key, value in inputs[name].items() if key != missing}) for missing in ("stopEpoch", "threadId", "leaseId"))
    extra_inputs.extend((True, "execution_resume", {**c.mutation, "exceptionMode": mode}) for mode in ("configured", "skip", "debugger", "debuggee"))
    conditions = [{"kind": "exit"}, {"kind": "breakpoint", "breakpointId": "bp-1"}, {"kind": "address", "address": {"addressHex": "0xffffffffffffffff"}},
                  {"kind": "thread_exit", "threadId": 123, "creationIdentity": "9007199254740993"}]
    extra_inputs.extend((True, "execution_wait", {**c.target, "afterCursor": "event:1:41", "condition": condition}) for condition in conditions)
    extra_inputs.extend([(False, "execution_step_into", {**c.mutation, "count": 0}), (False, "execution_step_over", {**c.mutation, "count": 1000001}),
                         (False, "execution_resume", {**c.mutation, "exceptionMode": "force"}), (False, "execution_resume", {**c.mutation, "timeoutMs": 60001}),
                         (False, "execution_skip_instruction", {**c.mutation, "expectedIp": 9007199254740993}),
                         (False, "execution_run_to", {**inputs["execution_run_to"], "addressHex": "0x1000"}),
                         (False, "execution_wait", {**c.target, "afterCursor": "event:1:41", "condition": {"kind": "exception", "codeHex": "0x100000000"}}),
                         (False, "threads_suspend", {**inputs["threads_suspend"], "creationIdentity": "18446744073709551616"}),
                         (False, "threads_resume", {**inputs["threads_resume"], "threadId": 0}),
                         (False, "exceptions_policy_set", {**inputs["exceptions_policy_set"], "expectedVersion": 9007199254740993}),
                         (False, "exceptions_policy_set", {**inputs["exceptions_policy_set"], "rules": [{**rule, "handledBy": "skip"}]}),
                         (True, "exceptions_policy_set", {**inputs["exceptions_policy_set"], "rules": []})])
    effects = {name: ["inspect"] for name in EXECUTION_TOOLS}
    effects.update({name: ["execute"] for name in EXECUTION_TOOLS[:7] if name != "execution_skip_instruction"})
    effects.update({"execution_skip_instruction": ["modify"], "threads_select": ["configure"], "threads_suspend": ["execute"], "threads_resume": ["execute"], "exceptions_policy_set": ["configure"]})
    extra_outputs = [(True, "execution_wait", {**observation, "state": "exited", "stopReason": "exit", "exitCode": 17, "threadId": None, "ipHex": None}),
                     (False, "exceptions_state", {**exception, "codeHex": "0x100000000"}),
                     (False, "execution_pause", {**observation, "eventSequence": 9007199254740993})]
    return check_tool_family(probe, registry, validators, EXECUTION_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects)


def check_inspection_contracts(probe, registry, validators):
    c = tool_context_examples()
    expression = {"expression": "40 + 2", "value": {"kind": "unsigned", "hex": "0x2a", "decimal": "42", "widthBits": 64}, "error": None, "errorOffset": None}
    watch = {"watchId": "watch-1", "expression": "rax", "type": "unsigned", "display": "hex", "trigger": "none"}
    observed_watch = {**watch, "revision": "rev-1", "evaluation": expression}
    inputs = {"registers_read": {**c.target, "groups": ["general", "avx512"], "threadId": 123, "consistency": "paused"},
              "registers_write": {**c.mutation, "values": [{"name": "rax", "valueHex": "0x2a", "maskHex": "0xffff"}, {"name": "zmm31", "bytesHex": "42" * 64}],
                                  "expectedValues": [{"name": "rax", "valueHex": "0x1"}]},
              "expression_evaluate": {"instanceId": "instance-1", "expression": "40 + 2"}, "expressions_evaluate": {**c.target, "expressions": ["40 + 2", "rax"]},
              "watches_list": c.target, "watches_set": {**c.target, "leaseId": "lease-1", "watch": watch, "expectedRevision": "rev-1"},
              "watches_delete": {**c.target, "leaseId": "lease-1", "watchId": "watch-1"}, "stack_read": {**c.target, "threadId": 123, "frames": 1000, "includeBytes": True},
              "arguments_read": {**c.paused, "convention": "win64", "count": 1, "types": ["uint64"]},
              "pointers_follow": {**c.target, "expression": "rsp", "depth": 64, "pointerWidth": 64}, "process_peb": c.target, "thread_teb": {**c.target, "threadId": 123},
              "seh_chain": c.paused, "unwind_info": {**c.target, "addressHex": "0x140001000"},
              "structures_list": {"instanceId": "instance-1", "query": "PEB", "limit": 1000},
              "structures_decode": {**c.target, "moduleId": "module-1", "rvaHex": "0x1000", "typeId": "type-1", "depth": 16}}
    outputs = {"registers_read": c.register, "registers_write": c.register, "expression_evaluate": {"context": {"instanceId": "instance-1"}, "items": [expression], "complete": True},
               "expressions_evaluate": {"context": c.paused, "items": [expression, expression], "complete": True}, "watches_list": {"items": [observed_watch], "page": c.page},
               "watches_set": observed_watch, "watches_delete": {"watchId": "watch-1", "removed": True}, "stack_read": {"items": [c.frame], "page": c.page},
               "arguments_read": {"context": c.paused, "convention": "win64", "items": [{"index": 0, "type": "uint64", "location": {"register": "rcx"}, "bytesHex": "2a00000000000000",
                                  "value": expression["value"], "error": None}], "complete": True},
               "pointers_follow": {"pointerWidth": 64, "items": [{"level": 0, "addressHex": "0x1000", "bytesHex": "0020000000000000", "valueHex": "0x2000", "region": None, "error": None}], "complete": True},
               "seh_chain": {"context": c.paused, "items": [{"index": 0, "recordHex": "0x1000", "handlerHex": "0x401000", "nextHex": "0xffffffff", "valid": True}], "termination": "end", "complete": True},
               "structures_list": {"items": [{"typeId": "type-1", "name": "KnownFixture", "size": "8", "provider": "native-types", "architecture": "x64", "kind": "structure"}], "page": c.page}}
    outputs.update({name: c.structure for name in ("process_peb", "thread_teb", "unwind_info", "structures_decode")})
    extra_inputs = [(True, "expression_evaluate", {**c.target, "expression": "rax", "threadId": 123, "expectedEpoch": "18446744073709551615"}),
                    (True, "expressions_evaluate", {"instanceId": "instance-1", "expressions": ["40+2"]}), (True, "structures_list", {**c.target, "query": "Known"}),
                    (False, "expression_evaluate", {"instanceId": "instance-1", "targetId": "target-1", "expression": "40+2"}),
                    (False, "expression_evaluate", {**c.target, "expression": "rax", "expectedEpoch": 9007199254740993}),
                    (False, "expressions_evaluate", {**c.target, "expressions": []}),
                    (False, "registers_read", {**inputs["registers_read"], "groups": ["sse", "sse"]}),
                    (False, "registers_read", {**inputs["registers_read"], "groups": ["imaginary"]}),
                    (False, "registers_write", {**c.mutation, "values": []}),
                    (False, "registers_write", {**c.mutation, "values": [{"name": "rax", "valueHex": "0x2a", "bytesHex": "2a"}]}),
                    (False, "registers_write", {**c.mutation, "values": [{"name": "zmm31", "bytesHex": "42" * 65}]}),
                    (False, "registers_write", {**c.mutation, "values": [{"name": "rax", "valueHex": "0x10000000000000000"}]}),
                    (False, "watches_set", {**inputs["watches_set"], "watch": {**watch, "trigger": "execute"}}),
                    (False, "stack_read", {**c.target, "frames": 1001}), (False, "arguments_read", {**c.paused, "count": 257}),
                    (False, "pointers_follow", {**c.target, "addressHex": "0x1000", "depth": 65}),
                    (False, "pointers_follow", {**c.target, "addressHex": "0x1000", "depth": 1, "pointerWidth": 16}),
                    (False, "structures_decode", {**c.target, "addressHex": "0x1000", "typeId": "type-1", "depth": 17})]
    for name in ("registers_write", "arguments_read", "seh_chain"):
        extra_inputs.extend((False, name, {key: value for key, value in inputs[name].items() if key != missing}) for missing in ("stopEpoch", "threadId"))
    wide = copy.deepcopy(c.register)
    wide["registers"][1]["bytesHex"] = "42" * 65
    nested = copy.deepcopy(c.structure)
    nested["fields"][0]["children"] = [copy.deepcopy(c.structure["fields"][0])]
    nested_invalid = copy.deepcopy(nested)
    nested_invalid["fields"][0]["children"][0]["value"]["decimal"] = "18446744073709551616"
    running_register = {**c.register, "context": c.target, "consistency": "best_effort"}
    extra_outputs = [(False, "registers_read", wide), (True, "registers_read", running_register), (True, "structures_decode", nested), (False, "structures_decode", nested_invalid),
                     (False, "stack_read", {"items": [{**c.frame, "certainty": "guess"}], "page": c.page})]
    effects = {name: ["inspect"] for name in INSPECTION_TOOLS}
    effects.update({"registers_write": ["modify"], "watches_set": ["configure"], "watches_delete": ["configure"]})
    result = check_tool_family(probe, registry, validators, INSPECTION_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects)
    result["recursiveStructureFieldValidation"] = 2
    result["explicitArchitectureRoutes"] = {"seh_chain": "x32", "unwind_info": "x64"}
    return result


def check_memory_contracts(probe, registry, validators):
    c = tool_context_examples()
    address_range = {"address": {"addressHex": "0x1000"}, "size": 4}
    region = {"baseHex": "0x1000", "size": "4096", "allocationBaseHex": "0x1000", "state": "committed", "protectionHex": "0x4",
              "type": "private", "moduleId": None, "mappedPath": None, "readable": True}
    coverage = {"requestedBytes": "4", "capturedBytes": "4", "spans": [{"addressHex": "0x1000", "size": "4", "protectionHex": "0x4", "status": "read", "error": None}], "complete": True}
    string = {"addressHex": "0x1000", "encoding": "utf8", "text": "Hu Tao ❤", "byteSize": "10", "terminated": True, "truncated": False, "decoding": "valid"}
    artifact = {"artifactId": "artifact-1", "namespaceId": "private-1", "revision": "rev-1", "sha256": "0" * 64, "size": "4", "mediaType": "application/octet-stream",
                "source": "target:target-1", "coverage": coverage, "consistency": "paused"}
    inputs = {"memory_map": {**c.target, "filter": {"state": "committed", "readable": True}},
              "memory_read": {**c.target, **address_range, "encoding": "hex", "consistency": "paused"},
              "memory_read_string": {**c.target, "expression": "rsp", "encoding": "utf16le", "maxBytes": 4096},
              "memory_write": {**c.mutation, "addressHex": "0x1000", "bytes": "01020304", "expectedBytes": {"bytesHex": "00000000"}},
              "memory_allocate": {**c.mutation, "size": "4096", "protection": "0x40", "preferredAddress": {"moduleId": "module-1", "rvaHex": "0x2000"}},
              "memory_free": {**c.mutation, "allocationId": "allocation-1"},
              "memory_protection_set": {**c.mutation, **address_range, "protection": "0x2", "expectedProtection": "0x4"},
              "memory_search_pattern": {**c.target, "ranges": [address_range], "pattern": "01 ?? ?3 04", "limit": 1000},
              "memory_search_text": {**c.target, "ranges": [address_range], "text": "Hu Tao", "encoding": "utf8", "caseSensitive": True},
              "memory_strings": {**c.target, "ranges": [address_range], "encodings": ["utf8", "utf16le"], "minLength": 4},
              "memory_dump": {**c.target, **address_range, "namespaceId": "private-1", "name": "fixture.bin"},
              "memory_dumpable_regions": {**c.target, "moduleId": "module-1"},
              "modules_dump": {**c.target, "moduleId": "module-1", "format": "mapped", "namespaceId": "private-1"},
              "handles_list": {**c.target, "type": "File"}, "heaps_list": c.target}
    match = {"addressHex": "0x1000", "size": "4", "bytesHex": "01020304"}
    outputs = {"memory_map": {"items": [region], "page": c.page},
               "memory_read": {"addressHex": "0x1000", "requestedSize": 4, "encoding": "hex", "encodedBytes": "01020304", "coverage": coverage, "consistency": "paused", "partial": False},
               "memory_read_string": {**string, "coverage": coverage},
               "memory_write": {"addressHex": "0x1000", "requestedBytes": "4", "writtenBytes": "4", "observedBytesHex": "01020304", "coverage": coverage, "restoration": "not_needed"},
               "memory_allocate": {"allocationId": "allocation-1", "target": c.target, "addressHex": "0x1000", "size": "4096", "protection": "0x40", "owned": True, "region": region},
               "memory_free": {"allocationId": "allocation-1", "addressHex": "0x1000", "released": True, "ownershipReleased": True, "regionAfter": {**region, "state": "free", "allocationBaseHex": None, "protectionHex": None, "readable": False}},
               "memory_protection_set": {"pages": [{"addressHex": "0x1000", "size": "4096", "oldProtection": "0x4", "newProtection": "0x2", "status": "changed"}], "complete": True},
               "memory_search_pattern": {"items": [match], "page": c.page, "coverage": coverage}, "memory_search_text": {"items": [match], "page": c.page, "coverage": coverage},
               "memory_strings": {"items": [string], "page": c.page, "coverage": coverage}, "memory_dump": artifact,
               "memory_dumpable_regions": {"items": [{**region, "constraints": ["native read limit"]}], "page": c.page},
               "modules_dump": {**artifact, "moduleId": "module-1", "validity": {"format": "mapped", "layout": "valid", "imports": "unknown", "relocations": "unknown", "runnable": "unverified", "limitations": ["Independent execution pending"]}},
               "handles_list": {"items": [{"valueHex": "0x1234", "type": "File", "name": "C:\\controlled.bin", "accessHex": "0x120089", "provider": "native-handles", "limitations": []}], "page": c.page},
               "heaps_list": {"items": [{"heapId": "heap-1", "baseHex": "0x1000", "size": "4096", "flagsHex": "0x2", "provider": "native-heaps", "regions": [region], "complete": True, "limitations": []}], "page": c.page}}
    extra_inputs = [(True, "memory_allocate", {**c.mutation, "size": "18446744073709551615", "protection": "0x40"}),
                    (True, "memory_write", {**c.mutation, "moduleId": "module-1", "rvaHex": "0x1000", "bytes": "01020304", "expectedBytes": {"address": {"addressHex": "0x1000"}, "size": 4, "sha256": "0" * 64}}),
                    (False, "memory_write", {**inputs["memory_write"], "bytes": "abc"}),
                    (False, "memory_write", {**inputs["memory_write"], "expectedBytes": {}}),
                    (False, "memory_write", {**inputs["memory_write"], "expectedBytes": {"bytesHex": "00", "sha256": "0" * 64}}),
                    (False, "memory_write", {**inputs["memory_write"], "expression": "rax"}),
                    (False, "memory_allocate", {**inputs["memory_allocate"], "size": "0"}),
                    (False, "memory_allocate", {**inputs["memory_allocate"], "size": "18446744073709551616"}),
                    (False, "memory_allocate", {**inputs["memory_allocate"], "size": 9007199254740993}),
                    (False, "memory_allocate", {**inputs["memory_allocate"], "protection": "0x100000000"}),
                    (False, "memory_free", {**c.mutation, "addressHex": "0x1000"}),
                    (False, "memory_read", {**c.target, "address": {"addressHex": "0x1000"}, "size": 1048577}),
                    (False, "memory_read", {**inputs["memory_read"], "address": {"addressHex": "0x1000", "expression": "rax"}}),
                    (False, "memory_read_string", {**inputs["memory_read_string"], "maxBytes": 0}),
                    (False, "memory_read_string", {**inputs["memory_read_string"], "encoding": "utf32"}),
                    (False, "memory_search_pattern", {**inputs["memory_search_pattern"], "ranges": []}),
                    (False, "memory_strings", {**inputs["memory_strings"], "encodings": ["utf8", "utf8"]}),
                    (False, "memory_dump", {key: value for key, value in inputs["memory_dump"].items() if key != "namespaceId"}),
                    (False, "modules_dump", {**inputs["modules_dump"], "format": "guessed"})]
    for name in ("memory_write", "memory_allocate", "memory_free", "memory_protection_set"):
        extra_inputs.extend((False, name, {key: value for key, value in inputs[name].items() if key != missing}) for missing in ("stopEpoch", "leaseId"))
    effects = {name: ["inspect"] for name in MEMORY_TOOLS}
    effects.update({name: ["modify"] for name in ("memory_write", "memory_allocate", "memory_free", "memory_protection_set")})
    effects.update({"memory_dump": ["inspect", "file_export"], "modules_dump": ["inspect", "file_export"]})
    partial_coverage = {"requestedBytes": "4", "capturedBytes": "2", "spans": [{"addressHex": "0x1000", "size": "2", "protectionHex": "0x4", "status": "read", "error": None},
                        {"addressHex": "0x1002", "size": "2", "protectionHex": None, "status": "unreadable", "error": None}], "complete": False}
    extra_outputs = [(True, "memory_read", {**outputs["memory_read"], "encodedBytes": "0102", "coverage": partial_coverage, "partial": True}),
                     (False, "memory_map", {"items": [{**region, "size": "0"}], "page": c.page}),
                     (False, "memory_map", {"items": [{**region, "protectionHex": "0x100000000"}], "page": c.page}),
                     (False, "memory_allocate", {**outputs["memory_allocate"], "size": 4096}),
                     (False, "memory_protection_set", {"pages": [{**outputs["memory_protection_set"]["pages"][0], "newProtection": "0x100000000"}], "complete": True}),
                     (False, "memory_dump", {**artifact, "sha256": "0" * 63})]
    return check_tool_family(probe, registry, validators, MEMORY_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects)


def instruction_example():
    return {"addressHex": "0x140001000", "bytesHex": "b82a000000", "length": 5, "text": "mov eax, 42", "mnemonic": "mov",
            "operands": [{"index": 0, "kind": "register", "text": "eax", "widthBits": 32, "valueHex": None, "access": "write"},
                         {"index": 1, "kind": "immediate", "text": "42", "widthBits": 32, "valueHex": "0x2a", "access": "read"}],
            "branch": "none", "branchTargetHex": None, "labels": ["fixture!value"], "valid": True, "error": None}


def check_breakpoint_trace_contracts(probe, registry, validators):
    context = tool_context_examples()
    options = {"name": "controlled", "enabled": True, "singleShot": False, "silent": False, "fastResume": False, "breakCondition": "rax == 42",
               "logText": "hit {rax}", "logCondition": "1", "commandText": "", "commandCondition": "", "logFile": None, "encoding": "int3"}
    breakpoint = {"breakpointId": "bp-1", "revision": "rev-1", "target": context.target, "addressHex": "0x140001000", "hits": "42", "active": True,
                  "nativeTypeHex": "0x1", "hardwareSlot": None, "creatorClientId": "client-1", "state": "installed", "kind": "software",
                  "location": {"addressHex": "0x140001000"}, "options": options}
    disposition = {"items": [{"breakpointId": "bp-1", "status": "changed", "observed": breakpoint, "error": None}], "complete": True}
    limits = {"maxInstructions": "9007199254740993", "maxWallTimeMs": 60000, "maxArtifactBytes": "1048576"}
    indexing = {"state": "complete", "entries": "9007199254740993", "error": None}
    artifact = {"artifactId": "trace-artifact-1", "namespaceId": "private-1", "revision": "rev-1", "sha256": "0" * 64, "size": "8192",
                "mediaType": "application/octet-stream", "source": "trace:trace-1"}
    trace = {"traceId": "trace-1", "target": context.target, "jobId": "job-1", "mode": "into", "state": "completed", "executedInstructions": "42",
             "producedEntries": "42", "limits": limits, "recording": False, "artifact": artifact, "indexing": indexing, "stopReason": "condition"}
    entry = {"index": "9007199254740993", "threadId": 123, "instruction": instruction_example(), "registers": [{"name": "eax", "valueHex": "0x2a"}],
             "memory": [{"addressHex": "0x1000", "beforeBytesHex": "07", "afterBytesHex": "2a"}], "complete": True}
    rows = {"items": [entry], "page": context.page, "traceArtifactId": "trace-artifact-1", "traceSha256": "0" * 64, "coverage": indexing}
    target_mutation = {**context.target, "leaseId": "lease-1"}
    inputs = {"breakpoints_list": {**context.target, "kind": "software"},
              "breakpoints_create": {**context.mutation, "kind": "software", "location": {"moduleId": "module-1", "rvaHex": "0x1000"}, "options": {"encoding": "int3"}},
              "breakpoints_update": {**target_mutation, "breakpointId": "bp-1", "changes": {"breakCondition": "rax == 42"}, "expectedRevision": "rev-1"},
              "breakpoints_delete": {**target_mutation, "breakpointIds": ["bp-1"]}, "breakpoints_enable": {**target_mutation, "breakpointIds": ["bp-1"], "enabled": True},
              "breakpoints_toggle": {**target_mutation, "breakpointId": "bp-1", "expectedEnabled": False},
              "breakpoints_reset_hits": {**target_mutation, "breakpointIds": ["bp-1"]}, "breakpoints_clear": {**target_mutation, "kind": "memory"},
              "trace_start": {**context.mutation, "mode": "into", "stopCondition": "eax == 42", "limits": limits, "record": {"enabled": True, "fields": ["instructions", "registers", "memory"]}, "namespaceId": "private-1"},
              "trace_stop": {**context.target, "traceId": "trace-1"}, "trace_state": {**context.target, "traceId": "trace-1"},
              "trace_open": {"instanceId": "instance-1", "artifactId": "trace-artifact-1"}, "trace_read": {"traceArtifactId": "trace-artifact-1", "fields": ["instructions"]},
              "trace_search": {"traceArtifactId": "trace-artifact-1", "query": {"field": "instruction", "expression": "mov eax,42"}},
              "trace_export": {"traceArtifactId": "trace-artifact-1", "range": {"first": "9007199254740993", "count": "42"}, "format": "jsonl", "namespaceId": "private-1"}}
    outputs = {"breakpoints_list": {"items": [breakpoint], "page": context.page}, "breakpoints_create": breakpoint, "breakpoints_update": breakpoint,
               "breakpoints_delete": disposition, "breakpoints_enable": disposition, "breakpoints_toggle": breakpoint, "breakpoints_reset_hits": disposition, "breakpoints_clear": disposition,
               "trace_start": trace, "trace_stop": trace, "trace_state": trace, "trace_open": {"traceArtifactId": "trace-artifact-1", "sha256": "0" * 64,
                   "architecture": "x64", "formatVersion": "1", "entries": "9007199254740993", "indexing": indexing}, "trace_read": rows, "trace_search": rows,
               "trace_export": {**artifact, "traceArtifactId": "trace-artifact-1", "sourceSha256": "1" * 64, "entries": "42", "complete": True}}
    extra_inputs = [(True, "breakpoints_create", {**context.mutation, "kind": "hardware", "location": {"addressHex": "0x1000"}, "options": {"access": "read_write", "size": 8}}),
                    (True, "breakpoints_create", {**context.mutation, "kind": "hardware", "location": {"expression": "rip"}, "options": {"access": "execute", "size": 1}}),
                    (True, "breakpoints_create", {**context.mutation, "kind": "memory", "location": {"address": {"addressHex": "0x1000"}, "size": 4096}, "options": {"access": "write", "overlapPolicy": "preserve"}}),
                    (True, "breakpoints_create", {**context.mutation, "kind": "module", "location": {"moduleName": "controlled.dll"}, "options": {"event": "either"}}),
                    (True, "breakpoints_create", {**context.mutation, "kind": "exception", "location": {"codeHex": "0xc0000005"}, "options": {"chance": "first"}}),
                    (False, "breakpoints_create", {**context.mutation, "kind": "hardware", "location": {"addressHex": "0x1000"}, "options": {"access": "execute", "size": 8}}),
                    (False, "breakpoints_create", {**context.mutation, "kind": "hardware", "location": {"addressHex": "0x1000"}, "options": {"access": "read_write", "size": 3}}),
                    (False, "breakpoints_create", {**context.mutation, "kind": "memory", "location": {"addressHex": "0x1000"}}),
                    (False, "breakpoints_create", {**context.mutation, "kind": "exception", "location": {"codeHex": "0x100000000"}}),
                    (False, "breakpoints_create", {**context.mutation, "kind": "exception", "location": {"codeHex": "0xc0000005"}, "options": {"encoding": "int3"}}),
                    (False, "breakpoints_update", {**inputs["breakpoints_update"], "changes": {}}),
                    (False, "breakpoints_delete", {**target_mutation, "breakpointIds": ["bp-1", "bp-1"]}),
                    (False, "breakpoints_enable", {**target_mutation, "breakpointIds": [], "enabled": True}),
                    (False, "breakpoints_toggle", {**inputs["breakpoints_toggle"], "expectedEnabled": "false"}),
                    (True, "trace_start", {**inputs["trace_start"], "limits": {"maxWallTimeMs": 1}, "mode": "over"}),
                    (True, "trace_start", {**inputs["trace_start"], "limits": {"maxInstructions": "18446744073709551615"}, "record": {"enabled": False}}),
                    (False, "trace_start", {**inputs["trace_start"], "limits": {}}),
                    (False, "trace_start", {**inputs["trace_start"], "limits": {"maxArtifactBytes": "1048576"}}),
                    (False, "trace_start", {**inputs["trace_start"], "limits": {"maxInstructions": "0"}}),
                    (False, "trace_start", {**inputs["trace_start"], "limits": {"maxInstructions": 9007199254740993}}),
                    (False, "trace_start", {**inputs["trace_start"], "limits": {"maxWallTimeMs": 60001}}),
                    (False, "trace_start", {**inputs["trace_start"], "mode": "native"}),
                    (False, "trace_open", {"instanceId": "instance-1", "path": "relative.trace"}),
                    (False, "trace_read", {**inputs["trace_read"], "fields": ["instructions", "instructions"]}),
                    (False, "trace_export", {**inputs["trace_export"], "range": {"first": "0", "count": "0"}})]
    for name in ("breakpoints_create", "trace_start"):
        extra_inputs.extend((False, name, {key: value for key, value in inputs[name].items() if key != missing}) for missing in ("stopEpoch", "leaseId"))
    extra_inputs.append((False, "trace_start", {key: value for key, value in inputs["trace_start"].items() if key != "threadId"}))
    hardware = copy.deepcopy(breakpoint)
    hardware.update({"kind": "hardware", "hardwareSlot": 3, "options": {key: value for key, value in options.items() if key != "encoding"}})
    hardware["options"].update({"access": "read_write", "size": 8})
    invalid_hardware = {**hardware, "hardwareSlot": 4}
    invalid_entry = {**entry, "index": 9007199254740993}
    extra_outputs = [(True, "breakpoints_create", hardware), (False, "breakpoints_create", invalid_hardware),
                     (False, "trace_read", {**rows, "items": [invalid_entry]}), (False, "trace_state", {**trace, "executedInstructions": "18446744073709551616"})]
    effects = {name: ["modify"] for name in BREAKPOINT_TRACE_TOOLS[:8]}
    effects.update({"breakpoints_list": ["inspect"], "trace_start": ["execute", "file_export"], "trace_stop": ["execute"], "trace_state": ["inspect"],
                    "trace_open": ["configure"], "trace_read": ["inspect"], "trace_search": ["inspect"], "trace_export": ["inspect", "file_export"]})
    required = {name: "instanceId" for name in BREAKPOINT_TRACE_TOOLS}
    required.update({name: "traceArtifactId" for name in ("trace_read", "trace_search", "trace_export")})
    executors = {name: "engine" for name in BREAKPOINT_TRACE_TOOLS}
    executors.update({"trace_open": "gui", "trace_read": "broker", "trace_search": "broker", "trace_export": "broker"})
    result = check_tool_family(probe, registry, validators, BREAKPOINT_TRACE_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, required, executors)
    result["nativeBreakpointKinds"] = ["software", "hardware", "memory", "module", "exception"]
    result["traceLimitForms"] = ["instructions", "wall_time", "both"]
    return result


def check_assembly_file_contracts(probe, registry, validators):
    context = tool_context_examples()
    instruction = instruction_example()
    encoding = {"architecture": "x64", "originHex": "0x140001000", "bytesHex": "b82a000000", "length": "5",
                "boundaries": [{"offset": "0", "length": "5", "line": 1, "column": 1, "kind": "instruction"}], "labels": [], "backend": {"provider": "xedparse", "version": "controlled"}}
    disassembly = {"architecture": "x64", "originHex": "0x140001000", "items": [instruction], "bytesConsumed": "5", "complete": True,
                   "source": {"kind": "target", "sha256": None, "context": context.target}}
    patch_range = {"addressHex": "0x140001000", "moduleId": "module-1", "rvaHex": "0x1000", "originalBytesHex": "b807000000", "replacementBytesHex": "b82a000000",
                   "observedBytesHex": "b82a000000", "nativeTracked": True, "state": "applied", "breakpointIds": ["bp-1"], "restoration": "not_needed"}
    patch = {"patchSetId": "patch-1", "revision": "rev-1", "name": "controlled", "target": context.target, "ranges": [patch_range], "ownership": "client", "complete": True}
    file = {"file": {"path": "C:\\controlled.exe"}, "sha256": "0" * 64, "size": "4096", "architecture": "x64", "imageBaseHex": "0x140000000", "entryRvaHex": "0x1000",
            "sections": [{"name": ".text", "rvaHex": "0x1000", "virtualSize": "4096", "rawOffset": "512", "rawSize": "512", "characteristicsHex": "0x60000020", "mapping": "valid"}],
            "peStatus": "valid", "overlayOffset": None, "signature": "absent", "limitations": []}
    changed = {"fileOffset": "512", "rvaHex": "0x1000", "originalBytesHex": "b807000000", "replacementBytesHex": "b82a000000"}
    transaction = {"transactionId": "transaction-1", "mode": "save_as", "source": file, "published": {**file, "file": {"path": "C:\\controlled-patched.exe"}, "sha256": "1" * 64},
                   "backupArtifact": None, "changes": [{**changed, "verified": True}], "outsidePlanPreserved": True, "journalState": "verified", "signatureImpact": "unchanged", "runtimeVerification": "unverified"}
    plan = {"planId": "plan-1", "planDigest": "2" * 64, "source": file, "addressMode": "rva", "changes": [changed], "moduleIdentity": "3" * 64, "signatureImpact": "unchanged"}
    inputs = {"disassembly_read": {**context.target, "addressHex": "0x140001000", "count": 16, "detail": "full"},
              "disassembly_function": {**context.target, "moduleId": "module-1", "rvaHex": "0x1000", "boundarySource": "unwind"},
              "assembly_encode": {"architecture": "x64", "origin": "0x140001000", "source": "mov eax,42", "mode": "instruction"},
              "assembly_apply": {**context.mutation, "addressHex": "0x140001000", "source": "mov eax,42", "span": 5, "expectedBytes": {"bytesHex": "b807000000"}, "fill": "none"},
              "patch_sets_create": {**context.target, "leaseId": "lease-1", "name": "controlled", "ranges": [{"address": {"addressHex": "0x140001000"}, "replacementBytesHex": "b82a000000", "expectedBytes": {"bytesHex": "b807000000"}}]},
              "patch_sets_list": context.target, "patch_sets_read": {**context.target, "patchSetId": "patch-1", "revision": "rev-1"},
              "patch_apply_runtime": {**context.mutation, "patchSetId": "patch-1", "revision": "rev-1"},
              "patch_restore_runtime": {**context.mutation, "patchSetId": "patch-1", "expectedRevision": "rev-1"}, "patch_restore_all": {**context.mutation, "selection": ["patch-1"]},
              "patch_export_file": {**context.target, "patchSetId": "patch-1", "revision": "rev-1", "path": "C:\\controlled.exe", "destination": "C:\\controlled-patched.exe", "mode": "save_as", "expectedSha256": "0" * 64},
              "file_inspect": {"path": "C:\\controlled.exe"},
              "file_patch_plan": {"artifactId": "artifact-1", "expectedSha256": "0" * 64, "changes": [{"positionHex": "0x1000", "replacementBytesHex": "b82a000000", "expectedBytesHex": "b807000000"}], "addressMode": "rva"},
              "file_patch_apply": {"planId": "plan-1", "planDigest": "2" * 64, "destination": "C:\\controlled-patched.exe", "mode": "save_as"},
              "file_patch_undo": {"transactionId": "transaction-1", "expectedCurrentSha256": "1" * 64},
              "file_compare": {"left": {"path": "C:\\controlled.exe"}, "right": {"artifactId": "artifact-1"}, "ranges": [{"offset": "9007199254740993", "size": 5}]},
              "file_export": {"artifactId": "artifact-1", "destination": "C:\\exported.bin", "overwrite": False}}
    outputs = {"disassembly_read": disassembly, "disassembly_function": {"items": [instruction], "page": context.page, "startHex": "0x140001000", "endHex": "0x140001006", "boundarySource": "unwind", "certainty": "verified"},
               "assembly_encode": encoding, "assembly_apply": {"patch": patch, "encoding": encoding, "disassembly": disassembly,
                   "followingBytes": {"addressHex": "0x140001005", "expectedBytesHex": "c3", "observedBytesHex": "c3", "unchanged": True}},
               "patch_sets_create": patch, "patch_sets_list": {"items": [patch], "page": context.page}, "patch_sets_read": patch,
               "patch_apply_runtime": patch, "patch_restore_runtime": patch, "patch_restore_all": {"items": [patch], "page": context.page},
               "patch_export_file": transaction, "file_inspect": file, "file_patch_plan": plan, "file_patch_apply": transaction, "file_patch_undo": {**transaction, "mode": "undo", "journalState": "restored"},
               "file_compare": {"items": [{"offset": "512", "leftBytesHex": "07", "rightBytesHex": "2a"}], "page": context.page, "left": file, "right": transaction["published"]},
               "file_export": {**transaction, "mode": "export"}}
    extra_inputs = [(True, "disassembly_read", {"architecture": "x32", "bytes": "b82a000000c3", "origin": "0x401000"}),
                    (True, "assembly_encode", {**inputs["assembly_encode"], "mode": "block", "source": "start:\nmov eax,42\njmp start"}),
                    (True, "file_export", {**inputs["file_export"], "overwrite": "replace", "expectedDestinationSha256": "0" * 64}),
                    (False, "disassembly_read", {**inputs["disassembly_read"], "architecture": "x64", "bytes": "90", "origin": "0x1000"}),
                    (False, "disassembly_read", {"architecture": "x64", "bytes": "9", "origin": "0x1000"}),
                    (False, "assembly_encode", {**inputs["assembly_encode"], "architecture": "arm64"}),
                    (False, "assembly_encode", {**inputs["assembly_encode"], "origin": 9007199254740993}),
                    (False, "assembly_apply", {**inputs["assembly_apply"], "span": 1048577}),
                    (False, "assembly_apply", {**inputs["assembly_apply"], "fill": "truncate"}),
                    (False, "patch_sets_create", {**inputs["patch_sets_create"], "ranges": []}),
                    (False, "patch_sets_create", {**inputs["patch_sets_create"], "ranges": [{"address": {"addressHex": "0x1000"}, "replacementBytesHex": "90"}]}),
                    (False, "patch_restore_all", {**inputs["patch_restore_all"], "selection": ["patch-1", "patch-1"]}),
                    (False, "patch_export_file", {**inputs["patch_export_file"], "artifactId": "artifact-1"}),
                    (False, "patch_export_file", {**inputs["patch_export_file"], "expectedSha256": "0" * 63}),
                    (False, "file_inspect", {"path": "relative.exe"}),
                    (False, "file_patch_plan", {**inputs["file_patch_plan"], "addressMode": "va"}),
                    (False, "file_patch_plan", {**inputs["file_patch_plan"], "changes": [{"positionHex": "0x1000", "replacementBytesHex": "90", "expectedBytesHex": "GG"}]}),
                    (False, "file_patch_apply", {**inputs["file_patch_apply"], "planDigest": "tampered"}),
                    (False, "file_patch_apply", {**inputs["file_patch_apply"], "mode": "overwrite"}),
                    (False, "file_patch_undo", {**inputs["file_patch_undo"], "expectedCurrentSha256": "not a hash"}),
                    (False, "file_compare", {**inputs["file_compare"], "ranges": [{"offset": 9007199254740993, "size": 5}]}),
                    (False, "file_export", {**inputs["file_export"], "overwrite": True}),
                    (False, "file_export", {**inputs["file_export"], "overwrite": "replace"})]
    for name in ("assembly_apply", "patch_apply_runtime", "patch_restore_runtime", "patch_restore_all"):
        extra_inputs.extend((False, name, {key: value for key, value in inputs[name].items() if key != missing}) for missing in ("stopEpoch", "leaseId"))
    invalid_patch = copy.deepcopy(patch)
    invalid_patch["ranges"][0]["originalBytesHex"] = "G0"
    invalid_encoding = copy.deepcopy(encoding)
    invalid_encoding["boundaries"][0]["length"] = "0"
    extra_outputs = [(False, "assembly_encode", invalid_encoding), (False, "patch_sets_read", invalid_patch),
                     (False, "file_patch_apply", {**transaction, "runtimeVerification": "runnable"}),
                     (False, "file_inspect", {**file, "size": 9007199254740993}), (False, "disassembly_read", {**disassembly, "items": [{**instruction, "length": 16}]})]
    effects = {name: ["inspect"] for name in ASSEMBLY_FILE_TOOLS}
    effects.update({name: ["modify"] for name in ("assembly_apply", "patch_sets_create", "patch_apply_runtime", "patch_restore_runtime", "patch_restore_all")})
    effects.update({"patch_export_file": ["inspect", "file_export"], "file_patch_apply": ["file_export"], "file_patch_undo": ["file_replace"], "file_export": ["file_export"]})
    required = {name: "instanceId" for name in ASSEMBLY_FILE_TOOLS}
    required.update({"assembly_encode": "architecture", "file_inspect": "path", "file_patch_plan": "artifactId", "file_patch_apply": "planId", "file_patch_undo": "transactionId", "file_compare": "left", "file_export": "artifactId"})
    executors = {name: "engine" for name in ASSEMBLY_FILE_TOOLS}
    executors.update({name: "broker" for name in ("disassembly_read", "assembly_encode", "patch_export_file", "file_inspect", "file_patch_plan", "file_patch_apply", "file_patch_undo", "file_compare", "file_export")})
    conditions = {"patch_export_file": [{"field": "mode", "equals": "replace", "effects": ["file_replace"]}],
                  "file_patch_apply": [{"field": "mode", "equals": "replace", "effects": ["file_replace"]}], "file_export": [{"field": "overwrite", "equals": "replace", "effects": ["file_replace"]}]}
    result = check_tool_family(probe, registry, validators, ASSEMBLY_FILE_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, required, executors, conditions)
    for name, field in (("patch_export_file", "mode"), ("file_patch_apply", "mode"), ("file_export", "overwrite")):
        value = {**inputs[name], field: "replace"}
        if name == "file_export":
            value["expectedDestinationSha256"] = "0" * 64
        expected = effects[name] + ["file_replace"]
        assert validators[(name, "input")].is_valid(value) and probe.call("tool-input", value, name)["valid"]
        assert probe.call("effects", value, name) == {"valid": True, "effects": expected}
    result["conditionalReplacementEffects"] = 3
    return result


class StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR), ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
                ("x", wintypes.DWORD), ("y", wintypes.DWORD), ("xSize", wintypes.DWORD), ("ySize", wintypes.DWORD),
                ("xChars", wintypes.DWORD), ("yChars", wintypes.DWORD), ("fill", wintypes.DWORD), ("flags", wintypes.DWORD),
                ("show", wintypes.WORD), ("reservedSize", wintypes.WORD), ("reservedBytes", ctypes.c_void_p),
                ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]


class StartupInfoEx(ctypes.Structure):
    _fields_ = [("startup", StartupInfo), ("attributes", ctypes.c_void_p)]


class ProcessInformation(ctypes.Structure):
    _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE), ("pid", wintypes.DWORD), ("threadId", wintypes.DWORD)]


class SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]


def run_launch_reference(plan, binary, output, expected_bits):
    KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    KERNEL.CreateFileW.restype = wintypes.HANDLE
    KERNEL.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    KERNEL.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    KERNEL.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    KERNEL.DeleteProcThreadAttributeList.restype = None
    KERNEL.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(StartupInfoEx), ctypes.POINTER(ProcessInformation)]
    KERNEL.CreateProcessW.restype = wintypes.BOOL
    KERNEL.ResumeThread.argtypes = [wintypes.HANDLE]
    KERNEL.ResumeThread.restype = wintypes.DWORD
    KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    KERNEL.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    KERNEL.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    assert Path(plan["application"]).resolve() == binary.resolve()
    environment_bytes = bytes.fromhex(plan["environmentHex"])
    assert len(environment_bytes) == plan["environmentUnits"] * 2 and environment_bytes.endswith(b"\0\0\0\0")
    assert len(plan["commandLine"].encode("utf-16-le")) // 2 == plan["commandLineUnits"] <= 32766
    security = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)
    output_handle = KERNEL.CreateFileW(str(output), 0x40000000, 1, ctypes.byref(security), 1, 0x80, None)
    input_handle = KERNEL.CreateFileW("NUL", 0x80000000, 1 | 2, ctypes.byref(security), 3, 0x80, None)
    handles = [output_handle, input_handle]
    information = ProcessInformation()
    attribute_buffer = None
    attributes_initialized = False
    job = None
    try:
        if any(handle == ctypes.c_void_p(-1).value for handle in handles):
            raise ctypes.WinError(ctypes.get_last_error())
        job = OwnedJob()
        needed = ctypes.c_size_t()
        KERNEL.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(needed))
        attribute_buffer = ctypes.create_string_buffer(needed.value)
        if not KERNEL.InitializeProcThreadAttributeList(attribute_buffer, 1, 0, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes_initialized = True
        inherited_handles = (wintypes.HANDLE * 2)(output_handle, input_handle)
        handle_list_attribute = 0x00020002
        if not KERNEL.UpdateProcThreadAttribute(attribute_buffer, 0, handle_list_attribute, inherited_handles, ctypes.sizeof(inherited_handles), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        startup = StartupInfoEx()
        startup.startup.cb = ctypes.sizeof(StartupInfoEx)
        startup.startup.flags = 0x100
        startup.startup.stdin = input_handle
        startup.startup.stdout = startup.startup.stderr = output_handle
        startup.attributes = ctypes.cast(attribute_buffer, ctypes.c_void_p)
        command = ctypes.create_unicode_buffer(plan["commandLine"])
        submitted_command = command.value
        environment = ctypes.create_string_buffer(environment_bytes)
        create_suspended = 4
        extended_startup = 0x00080000
        create_unicode_environment = 0x400
        flags = subprocess.CREATE_NO_WINDOW | create_unicode_environment | create_suspended | extended_startup
        if not KERNEL.CreateProcessW(str(binary), command, None, None, True, flags, environment, plan["cwd"], ctypes.byref(startup), ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = SimpleNamespace(pid=information.pid, _handle=information.process)
        identity = process_identity(process)
        child_token, token_queries = process_token_oracle(information.process)
        parent_token, parent_queries = parent_token_oracle()
        assert child_token == parent_token, "Ordinary reference child token differs from its actual controller"
        job.assign(process)
        if KERNEL.ResumeThread(information.thread) == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        if KERNEL.WaitForSingleObject(information.process, 10000) != 0:
            raise McpError(f"Owned launch reference did not finish: {identity}")
        exit_code = wintypes.DWORD()
        if not KERNEL.GetExitCodeProcess(information.process, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        assert exit_code.value == 17, f"Reference exit {exit_code.value}: {output.read_bytes()[:500]!r}"
        observed = json.loads(output.read_bytes())
        assert observed["rawCommandLine"] == submitted_command, "Reference raw command line differs from the exact native CreateProcess input"
        assert observed["pid"] == identity["pid"] and observed["pointerBits"] == expected_bits
        native_identity = observed["identity"]
        image = file_identity(binary)
        actual_file = file_handle_oracle(binary)
        expected_identity = {**identity, **child_token, "architecture": "x64" if expected_bits == 64 else "x32",
                             "image": {"path": str(binary.resolve()), "sha256": image["sha256"], "size": str(image["size"]),
                                       "volumeSerial": actual_file["volumeSerial"], "fileIndex": actual_file["fileIndex"]}}
        assert native_identity == expected_identity, "Reference child identity/rights differ from independent process/token/file observations"
        return {"processIdentity": identity, "exitCode": exit_code.value, "binary": image, "output": file_identity(output),
                "observed": observed, "submittedCommandLine": submitted_command, "expectedIdentity": expected_identity, "childToken": child_token,
                "childTokenQueries": token_queries, "parentToken": parent_token, "parentTokenQueries": parent_queries}
    finally:
        if job is not None:
            job.close()
        if information.process:
            exit_code = wintypes.DWORD()
            if KERNEL.GetExitCodeProcess(information.process, ctypes.byref(exit_code)) and exit_code.value == 259:
                KERNEL.TerminateProcess(information.process, 1)
            KERNEL.WaitForSingleObject(information.process, 5000)
            KERNEL.CloseHandle(information.process)
        if information.thread:
            KERNEL.CloseHandle(information.thread)
        if attributes_initialized:
            KERNEL.DeleteProcThreadAttributeList(attribute_buffer)
        for handle in handles:
            if handle and handle != ctypes.c_void_p(-1).value:
                KERNEL.CloseHandle(handle)


def database_example():
    return {"target": tool_context_examples().target, "version": "9007199254740993", "loadedVersion": None, "savedVersion": None, "dirty": True,
            "file": None, "sha256": None, "modules": [{"moduleId": "module-1", "imageSha256": "0" * 64, "loadGeneration": "18446744073709551615"}],
            "provider": "native-database", "counts": [{"kind": "comments", "count": "9007199254740993"}], "complete": True}


def managed_artifact_example():
    return {"artifactId": "artifact-1", "namespaceId": "private-1", "revision": "rev-1", "sha256": "0" * 64,
            "size": "9007199254740993", "mediaType": "application/json", "source": "target:target-1"}


def check_module_analysis_contracts(probe, registry, validators):
    context = tool_context_examples()
    mutation = {**context.target, "leaseId": "lease-1"}
    address_range = {"address": {"moduleId": "module-1", "rvaHex": "0x1000"}, "size": 4096}
    section = {"name": ".text", "addressHex": "0x140001000", "rvaHex": "0x1000", "virtualSize": "4096", "rawOffset": "1024", "rawSize": "4096",
               "characteristicsHex": "0x60000020", "protectionHex": "0x20", "mapping": "valid"}
    module = {"moduleId": "module-1", "target": context.target, "loadGeneration": "9007199254740993", "name": "controlled.exe", "baseHex": "0x140000000",
              "size": "8192", "entryHex": "0x140001000", "image": {"path": "C:\\controlled.exe", "sha256": "0" * 64, "size": "8192"}, "architecture": "x64",
              "loaded": True, "sections": {"items": [section], "page": context.page}, "provider": "native-modules", "limitations": []}
    symbol = {"symbolId": "symbol-1", "moduleId": "module-1", "providerId": "provider-1", "name": "controlled!value", "undecoratedName": None, "kind": "debug",
              "addressHex": "0x140001000", "rvaHex": "0x1000", "size": None, "resolved": True, "sourceFile": None, "line": None}
    provider = {"moduleId": "module-1", "providerId": "provider-1", "kind": "pdb", "source": {"path": "C:\\controlled.pdb"}, "sha256": "0" * 64,
                "signature": "fixture-signature", "age": 1, "moduleMatch": "matched", "loaded": True, "networkUsed": False}
    function = {"functionId": "function-1", "moduleId": "module-1", "startHex": "0x140001000", "endHex": "0x140001005", "name": None, "kind": "heuristic",
                "source": "control-flow", "analysisVersion": "9007199254740993", "instructionCount": None, "parentFunctionId": None, "certainty": "heuristic"}
    edge = {"fromBlockId": "block-1", "toBlockId": None, "targetHex": None, "kind": "indirect", "resolution": "unresolved"}
    block = {"blockId": "block-1", "functionId": "function-1", "startHex": "0x140001000", "endHex": "0x140001005", "instructions": [instruction_example()],
             "edges": [edge], "complete": False, "analysisVersion": "9007199254740993"}
    encoding = {"target": context.target, "databaseVersion": "9007199254740993", "items": [{"addressHex": "0x140001000", "size": "4096", "encoding": "code",
                "source": "native-encoding-map", "valid": True}], "complete": True}
    inputs = {"modules_list": context.target, "modules_sections": {**context.target, "moduleId": "module-1"},
              "modules_imports": {**context.target, "moduleId": "module-1"}, "modules_exports": {**context.target, "moduleId": "module-1"},
              "modules_analyze_pe": {"path": "C:\\controlled.exe"}, "modules_oep_candidates": {**context.target, "moduleId": "module-1"},
              "symbols_list": context.target, "symbols_search": {**context.target, "query": "value"},
              "symbols_load": {**context.target, "moduleId": "module-1", "source": {"path": "C:\\controlled.pdb"}, "networkAllowed": False},
              "symbols_unload": {**context.target, "moduleId": "module-1", "providerId": "provider-1"},
              "analysis_start": {**mutation, "moduleId": "module-1", "mode": "control_flow", "range": address_range}, "analysis_functions": context.target,
              "analysis_blocks": {**context.target, "functionId": "function-1"}, "analysis_graph": {**context.target, "functionId": "function-1", "format": "structured"},
              "analysis_references": {**context.target, "expression": "rip", "direction": "from"}, "analysis_loops": context.target,
              "analysis_encoding_get": {**context.target, **address_range}, "analysis_encoding_set": {**mutation, **address_range, "encoding": "code"},
              "analysis_function_set": {**mutation, "range": address_range, "kind": "manual"}, "analysis_argument_set": {**mutation, "range": address_range, "kind": "automatic"},
              "analysis_range_delete": {**mutation, "kind": "xref", "range": address_range}}
    candidate = {"addressHex": "0x140001000", "moduleId": "module-1", "rank": 1, "score": 42, "method": "pe-entry", "rationale": ["Observed header entry"],
                 "verification": {"status": "unverified", "evidence": [], "followUp": {"capabilityId": "execution_run_to", "retry": "after_refresh", "reason": "Execution proof pending"}}}
    outputs = {"modules_list": {"items": [module], "page": context.page}, "modules_sections": {"moduleId": "module-1", "loadGeneration": "9007199254740993", "items": [section], "complete": True},
               "modules_imports": {"items": [{"moduleId": "module-1", "name": None, "ordinal": "42", "iatAddressHex": "0x140002000", "providerName": "kernel32.dll",
                                             "resolvedProviderId": None, "resolvedAddressHex": None, "resolved": False}], "page": context.page},
               "modules_exports": {"items": [{"moduleId": "module-1", "name": "value", "ordinal": "42", "rvaHex": "0x1000", "addressHex": None,
                                             "forwarder": "other.value", "resolved": False}], "page": context.page},
               "modules_analyze_pe": {"sourceKind": "target", "module": module, "file": None, "facts": [{"name": "entry-point", "offset": "40", "size": "4",
                                         "bytesHex": "00100000", "value": {"kind": "unsigned", "hex": "0x1000", "decimal": "4096", "widthBits": 32}, "status": "valid"}], "errors": [], "complete": True},
               "modules_oep_candidates": {"items": [candidate], "complete": True}, "symbols_list": {"items": [symbol], "page": context.page},
               "symbols_search": {"items": [symbol], "page": context.page}, "symbols_load": provider, "symbols_unload": {**provider, "loaded": False},
               "analysis_start": {"target": context.target, "moduleId": "module-1", "analysisId": "analysis-1", "analysisVersion": "9007199254740993", "mode": "control_flow",
                                  "jobId": "job-1", "state": "queued", "complete": False}, "analysis_functions": {"items": [function], "page": context.page},
               "analysis_blocks": {"items": [block], "page": context.page}, "analysis_graph": {"functionId": "function-1", "analysisVersion": "9007199254740993", "blocks": [block],
                                  "edges": [edge], "unresolvedEdges": "1", "artifact": None, "complete": False},
               "analysis_references": {"items": [{"fromHex": "0x140001000", "toHex": None, "kind": "unknown", "source": "native-xrefs", "analysisVersion": "9007199254740993", "resolved": False}], "page": context.page},
               "analysis_loops": {"items": [{"loopId": "loop-1", "functionId": None, "startHex": "0x140001000", "endHex": "0x140001005", "parentLoopId": None,
                                           "depth": 0, "manual": True, "instructionCount": None, "analysisVersion": "9007199254740993"}], "page": context.page},
               "analysis_encoding_get": encoding, "analysis_encoding_set": encoding,
               "analysis_function_set": database_example(), "analysis_argument_set": database_example(), "analysis_range_delete": database_example()}
    extra_inputs = [(True, "modules_analyze_pe", context.target), (True, "modules_analyze_pe", {"artifactId": "artifact-1"}),
                    (False, "modules_analyze_pe", {**context.target, "path": "C:\\controlled.exe"}), (False, "modules_analyze_pe", {"path": "relative.exe"}),
                    (False, "modules_sections", {**inputs["modules_sections"], "targetGeneration": 9007199254740993}),
                    (True, "symbols_load", {**context.target, "moduleId": "module-1", "source": {"kind": "store", "location": "controlled-store"}, "networkAllowed": True}),
                    (False, "symbols_load", {**inputs["symbols_load"], "source": {"path": "C:\\controlled.pdb", "kind": "store", "location": "reject mixed"}}),
                    (False, "symbols_search", {**inputs["symbols_search"], "query": ""}), (False, "analysis_start", {**inputs["analysis_start"], "mode": "invented"}),
                    (False, "analysis_encoding_set", {**inputs["analysis_encoding_set"], "encoding": "generic-data"}),
                    (False, "analysis_encoding_get", {**inputs["analysis_encoding_get"], "size": 1048577}),
                    (False, "analysis_encoding_get", {**inputs["analysis_encoding_get"], "address": {"addressHex": "0x1000", "expression": "rax"}}),
                    (False, "analysis_range_delete", {**inputs["analysis_range_delete"], "kind": "everything"})]
    encodings = ("unknown", "byte", "word", "dword", "fword", "qword", "tbyte", "oword", "mmword", "xmmword", "ymmword", "zmmword",
                 "real4", "real8", "real10", "ascii", "unicode", "code", "junk", "middle")
    for native_encoding in encodings:
        extra_inputs.append((True, "analysis_encoding_set", {**inputs["analysis_encoding_set"], "encoding": native_encoding}))
    for mode in ("linear", "exception_directory", "recursive", "xrefs", "advanced", "nukem"):
        extra_inputs.append((True, "analysis_start", {**inputs["analysis_start"], "mode": mode}))
    for name in ("analysis_start", "analysis_encoding_set", "analysis_function_set", "analysis_argument_set", "analysis_range_delete"):
        extra_inputs.append((False, name, {key: value for key, value in inputs[name].items() if key != "leaseId"}))
    missing_followup = copy.deepcopy(candidate)
    del missing_followup["verification"]["followUp"]
    unproved_verified = {**candidate, "verification": {"status": "verified", "evidence": []}}
    extra_outputs = [(False, "modules_oep_candidates", {"items": [missing_followup], "complete": True}),
                     (False, "modules_oep_candidates", {"items": [unproved_verified], "complete": True}),
                     (False, "modules_sections", {**outputs["modules_sections"], "items": [{**section, "characteristicsHex": "0x100000000"}]}),
                     (True, "modules_sections", {**outputs["modules_sections"], "items": [{**section, "name": "", "rawOffset": None, "rawSize": None, "mapping": "ambiguous"}]}),
                     (False, "modules_list", {"items": [{**module, "size": "0"}], "page": context.page}),
                     (False, "symbols_list", {"items": [{**symbol, "addressHex": "0x10000000000000000"}], "page": context.page}),
                     (True, "symbols_list", {"items": [{**symbol, "addressHex": None, "resolved": False, "kind": "unknown"}], "page": context.page}),
                     (False, "analysis_graph", {**outputs["analysis_graph"], "edges": [{**edge, "resolution": "guessed"}]}),
                     (False, "analysis_graph", {**outputs["analysis_graph"], "unresolvedEdges": 9007199254740993}),
                     (False, "analysis_functions", {"items": [{**function, "instructionCount": "18446744073709551616"}], "page": context.page}),
                     (True, "symbols_load", {**provider, "moduleMatch": "mismatched", "loaded": False}),
                     (True, "analysis_graph", {**outputs["analysis_graph"], "artifact": managed_artifact_example()})]
    for native_encoding in encodings:
        extra_outputs.append((True, "analysis_encoding_get", {**encoding, "items": [{**encoding["items"][0], "encoding": native_encoding}]}))
    effects = {name: ["inspect"] for name in MODULE_ANALYSIS_TOOLS}
    effects.update({name: ["configure"] for name in ("symbols_load", "symbols_unload", "analysis_start", "analysis_encoding_set", "analysis_function_set", "analysis_argument_set", "analysis_range_delete")})
    required = {name: "instanceId" for name in MODULE_ANALYSIS_TOOLS}
    required["modules_analyze_pe"] = "path"
    executors = {name: "engine" for name in MODULE_ANALYSIS_TOOLS}
    executors["modules_analyze_pe"] = "broker"
    conditions = {"analysis_graph": [{"field": "format", "equals": "svg", "effects": ["file_export"]}, {"field": "format", "equals": "png", "effects": ["file_export"]}]}
    result = check_tool_family(probe, registry, validators, MODULE_ANALYSIS_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, required, executors, conditions)
    for graph_format in ("svg", "png"):
        value = {**inputs["analysis_graph"], "format": graph_format}
        assert validators[("analysis_graph", "input")].is_valid(value) and probe.call("tool-input", value, "analysis_graph")["valid"]
        assert probe.call("effects", value, "analysis_graph") == {"valid": True, "effects": ["inspect", "file_export"]}
    result.update(nativeEncodings=list(encodings), nativeAnalysisModes=7, conditionalGraphExportEffects=2, explicitUnresolvedCfgAndOepEvidence=True)
    return result


def check_database_settings_contracts(probe, registry, validators):
    context = tool_context_examples()
    mutation = {**context.target, "leaseId": "lease-1"}
    instance = {"instanceId": "instance-1"}
    library = {"namespaceId": "private-1", "objectId": "annotations-1", "revision": "rev-1"}
    annotation = {"annotationId": "annotation-1", "revision": "rev-1", "target": context.target, "addressHex": "0x140001000", "moduleId": "module-1",
                  "rvaHex": "0x1000", "origin": "manual", "present": True, "databaseVersion": "9007199254740993", "kind": "comment", "value": "controlled annotation"}
    database = database_example()
    record = {"recordId": "record-1", "annotationId": "annotation-1", "kind": "comment", "status": "conflict", "revision": "rev-1", "error": None}
    changed = {"database": database, "records": [record], "preservedKinds": ["label", "bookmark", "color"], "complete": False}
    setting = {"settingId": "setting-1", "section": "Gui", "key": "Controlled", "value": {"kind": "uint64", "value": "18446744073709551615"},
               "valueSchema": {"type": "string", "format": "uint64-decimal"}, "storage": "both", "requiresRestart": True, "nativeWidth": 64,
               "provider": "native-configuration", "effects": ["configure"], "enabled": True, "disabledReason": None}
    favorite = {"favoriteId": "favorite-1", "name": "controlled", "description": "", "shortcut": "", "kind": "command", "commandText": "pause"}
    observed = {**favorite, "actionId": "favorite:favorite-1", "effects": ["execute"], "classification": "known", "enabled": True, "disabledReason": None}
    favorites = {**instance, "version": "9007199254740993", "entries": [observed], "persisted": True, "complete": True}
    inputs = {"annotations_list": context.target, "annotations_set": {**mutation, "moduleId": "module-1", "rvaHex": "0x1000", "kind": "comment", "value": "controlled annotation", "expectedRevision": "rev-1"},
              "annotations_delete": {**mutation, "annotationIds": ["annotation-1"]}, "annotations_import": {**mutation, **library, "mergePolicy": "reject"},
              "annotations_export": {**context.target, "namespaceId": "private-1", "selection": {"kinds": ["comment"]}},
              "database_save": {**context.target, "destination": "C:\\controlled.dd64"}, "database_load": {**mutation, "path": "C:\\controlled.dd64", "mergePolicy": "reject"},
              "database_clear": {**mutation, "kinds": ["comments"]}, "database_info": context.target, "settings_list": {**instance, "filter": {"section": "Gui"}},
              "settings_apply": {**instance, "changes": [{"settingId": "setting-1", "value": setting["value"]}], "expectedVersion": "9007199254740993"},
              "favorites_list": instance, "favorites_set": {**instance, "entries": [favorite], "expectedVersion": "9007199254740993"}}
    outputs = {"annotations_list": {"items": [annotation], "page": context.page}, "annotations_set": annotation, "annotations_delete": changed, "annotations_import": changed,
               "annotations_export": {"artifact": managed_artifact_example(), "database": database, "recordCount": "9007199254740993", "complete": True},
               "database_save": {**database, "savedVersion": database["version"], "dirty": False, "file": {"path": "C:\\controlled.dd64"}, "sha256": "0" * 64},
               "database_load": {**database, "loadedVersion": database["version"], "file": {"path": "C:\\controlled.dd64"}, "sha256": "0" * 64},
               "database_clear": database, "database_info": database, "settings_list": {"items": [setting], "page": context.page},
               "settings_apply": {**instance, "version": "9007199254740993", "items": [setting], "pendingRestartIds": ["setting-1"], "persisted": True, "complete": True},
               "favorites_list": favorites, "favorites_set": favorites}
    extra_inputs = [(True, "annotations_import", {**mutation, "path": "C:\\annotations.json", "mergePolicy": "keep_existing"}),
                    (True, "annotations_import", {**mutation, "artifactId": "artifact-1", "mergePolicy": "replace"}),
                    (False, "annotations_import", {**inputs["annotations_import"], "path": "C:\\annotations.json"}),
                    (False, "annotations_import", {key: value for key, value in inputs["annotations_import"].items() if key != "revision"}),
                    (False, "annotations_import", {**inputs["annotations_import"], "mergePolicy": "silent_replace"}),
                    (False, "annotations_set", {**inputs["annotations_set"], "addressHex": "0x1000"}),
                    (False, "annotations_delete", {**inputs["annotations_delete"], "annotationIds": ["annotation-1", "annotation-1"]}),
                    (True, "database_load", {**mutation, "artifactId": "artifact-1"}), (False, "database_load", {**inputs["database_load"], "artifactId": "artifact-1"}),
                    (False, "database_save", {**inputs["database_save"], "destination": "relative.dd64"}),
                    (False, "database_clear", {**inputs["database_clear"], "kinds": ["comments", "comments"]}),
                    (False, "database_clear", {**inputs["database_clear"], "kinds": ["unknown-provider-category"]}),
                    (False, "settings_apply", {**inputs["settings_apply"], "expectedVersion": 9007199254740993}),
                    (False, "settings_apply", {**inputs["settings_apply"], "changes": []}),
                    (False, "favorites_set", {**inputs["favorites_set"], "entries": [{**favorite, "effects": ["execute"]}]}),
                    (True, "favorites_set", {**inputs["favorites_set"], "entries": []})]
    favorite_tool = {"favoriteId": "favorite-2", "name": "controlled tool", "kind": "tool", "file": {"path": "C:\\controlled.exe"}, "rawCommandLine": '"C:\\controlled.exe" raw', "cwd": "C:\\"}
    favorite_script = {"favoriteId": "favorite-3", "name": "controlled script", "kind": "script", "script": {**library, "objectId": "script-1"}}
    for entry in (favorite_tool, favorite_script, {**favorite_script, "script": {"artifactId": "script-1"}}):
        extra_inputs.append((True, "favorites_set", {**inputs["favorites_set"], "entries": [entry]}))
    extra_inputs.extend([(False, "favorites_set", {**inputs["favorites_set"], "entries": [{**favorite_tool, "commandText": "pause"}]}),
                         (False, "favorites_set", {**inputs["favorites_set"], "entries": [{**favorite_script, "script": {key: value for key, value in library.items() if key != "revision"}}]})])
    for kind, value in (("label", "value"), ("comment", ""), ("bookmark", True), ("color", "0xffffffff")):
        extra_inputs.append((True, "annotations_set", {**inputs["annotations_set"], "kind": kind, "value": value}))
    extra_inputs.extend([(False, "annotations_set", {**inputs["annotations_set"], "kind": "bookmark", "value": "true"}),
                         (False, "annotations_set", {**inputs["annotations_set"], "kind": "color", "value": "0x100000000"})])
    for kind, value in (("boolean", False), ("uint64", "18446744073709551615"), ("text", "Hu Tao ❤")):
        extra_inputs.append((True, "settings_apply", {**inputs["settings_apply"], "changes": [{"settingId": "setting-1", "value": {"kind": kind, "value": value}}]}))
    extra_inputs.append((False, "settings_apply", {**inputs["settings_apply"], "changes": [{"settingId": "setting-1", "value": {"kind": "uint64", "value": "18446744073709551616"}}]}))
    for name in ("annotations_set", "annotations_delete", "annotations_import", "database_load", "database_clear"):
        extra_inputs.append((False, name, {key: value for key, value in inputs[name].items() if key != "leaseId"}))
    for name in ("settings_apply", "favorites_set"):
        extra_inputs.append((False, name, {key: value for key, value in inputs[name].items() if key != "expectedVersion"}))
    extra_outputs = [(False, "database_info", {**database, "version": 9007199254740993}),
                     (False, "database_save", {**outputs["database_save"], "sha256": "0" * 63}),
                     (False, "database_info", {**database, "counts": [{"kind": "comments", "count": "18446744073709551616"}]}),
                     (False, "annotations_set", {**annotation, "origin": "guessed"}),
                     (False, "annotations_import", {**changed, "records": [{**record, "status": "pretend-success"}]}),
                     (False, "settings_list", {"items": [{**setting, "valueSchema": False}], "page": context.page}),
                     (False, "settings_list", {"items": [{**setting, "effects": ["configure", "configure"]}], "page": context.page}),
                     (False, "settings_list", {"items": [{**setting, "nativeWidth": 128}], "page": context.page}),
                     (True, "favorites_list", {**favorites, "entries": [{**observed, "effects": [], "classification": "unknown", "enabled": False, "disabledReason": "Native command effect unresolved"}]}),
                     (False, "favorites_list", {**favorites, "entries": [{**observed, "classification": "trusted"}]})]
    for kind, value in (("label", "value"), ("comment", ""), ("bookmark", True), ("color", "0xffffffff")):
        extra_outputs.append((True, "annotations_set", {**annotation, "kind": kind, "value": value}))
    effects = {name: ["inspect"] for name in DATABASE_SETTINGS_TOOLS}
    effects.update({name: ["configure"] for name in ("annotations_set", "annotations_delete", "annotations_import", "database_load", "database_clear", "settings_apply", "favorites_set")})
    effects.update({"annotations_export": ["inspect", "file_export"], "database_save": ["configure", "file_export"]})
    executors = {name: "engine" for name in DATABASE_SETTINGS_TOOLS}
    executors.update({name: "gui" for name in ("settings_list", "settings_apply", "favorites_list", "favorites_set")})
    result = check_tool_family(probe, registry, validators, DATABASE_SETTINGS_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, executors=executors)
    result.update(annotationKinds=4, pinnedLibraryOrFileSources=True, explicitConflictAndPersistenceObservations=True, storingFavoritesHasNoExecuteEffect=True, guiOwnerContracts=4)
    return result


def check_provider_ui_contracts(probe, registry, validators):
    context = tool_context_examples()
    instance = {"instanceId": "instance-1"}
    ui_context = {"viewId": "view-1", "target": context.paused, "selection": ["row-1"], "sourceVersion": "9007199254740993"}
    integer = {"kind": "integer", "bitsHex": "0xffffffffffffffff", "widthBits": 64, "signed": True}
    value = {"kind": "object", "members": [{"name": "exact", "value": integer}, {"name": "choices", "value": {"kind": "array", "items": [{"kind": "boolean", "value": False}]}}]}
    action = {"actionId": "action-1", "providerId": "provider-1", "providerBuildId": "0" * 64, "name": "controlled action", "kind": "menu", "aliases": [], "syntax": "",
              "argumentsSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "resultSchema": None, "contextRequirement": "paused",
              "executor": "gui", "effects": ["configure"], "classification": "known", "leaseRequired": False, "privilege": "user", "enabled": True,
              "disabledReason": None, "completionPredicate": "Observed native state", "recovery": ["ui_view_read"]}
    command = {**action, "kind": "command", "executor": "engine", "commandId": "command-1", "category": "inspection", "aliases": ["controlled", "Hu Tao ❤"], "syntax": "controlled [address]"}
    unverified = {"status": "unverified", "evidence": [], "followUp": {"capabilityId": "operation_reconcile", "retry": "after_reconciliation", "reason": "Native postcondition unknown"}}
    outcome = {"actionId": "action-1", "providerId": "provider-1", "providerBuildId": "0" * 64, "operationId": "operation-1", "jobId": "job-1", "dialogId": "dialog-1",
               "state": "pending_input", "result": value, "effects": [], "verification": unverified, "complete": False}
    plugin = {"pluginId": "plugin-1", "providerBuildId": "0" * 64, "name": "controlled", "image": {"path": "C:\\controlled.dp64"}, "sha256": "0" * 64, "architecture": "x64",
              "version": None, "sdkVersion": 1, "loaded": True, "available": True, "trustedCodeRequired": True, "actionsCount": "9007199254740993", "missingRoutes": [], "limitations": []}
    view = {**instance, "viewId": "view-1", "providerId": "provider-1", "name": "controlled view", "kind": "tree", "visible": True, "enabled": True, "disabledReason": None,
            "version": "9007199254740993", "target": context.target, "querySchema": {"type": "object"}, "configurationSchema": None, "actions": {"items": [action], "page": context.page}, "complete": True}
    field = {"fieldId": "field-1", "name": "Value", "controlKind": "line_edit", "value": integer, "valueSchema": {"type": "object"}, "enabled": True, "visible": True,
             "writable": True, "validation": []}
    dialog = {**instance, "dialogId": "dialog-1", "operationId": "operation-1", "ownerClientId": "client-1", "providerId": "provider-1", "version": "9007199254740993",
              "state": "open", "interaction": "native_fields", "title": "Controlled dialog", "fields": {"items": [field], "page": context.page}, "actions": [action], "validation": [], "complete": True}
    inputs = {"commands_list": instance, "commands_describe": {**instance, "commandId": "command-1"}, "commands_execute": {**context.mutation, "command": "controlled 0xffffffffffffffff", "timeoutMs": 60000},
              "plugins_list": instance, "plugins_actions": {**instance, "pluginId": "plugin-1"}, "plugins_invoke": {**context.mutation, "pluginId": "plugin-1", "actionId": "action-1", "arguments": {"addressHex": "0x1000"}},
              "plugins_load": {**instance, "path": "C:\\controlled.dp64", "expectedSha256": "0" * 64}, "plugins_unload": {**instance, "pluginId": "plugin-1", "expectedBuildId": "0" * 64},
              "ui_actions_list": {**instance, "context": ui_context}, "ui_action_invoke": {**instance, "actionId": "action-1", "context": ui_context, "arguments": {"value": integer}, "expectedUiVersion": "9007199254740993", "leaseId": "lease-1"},
              "ui_views_list": instance, "ui_view_read": {**instance, "viewId": "view-1", "query": {"afterRow": "row-0"}},
              "ui_view_navigate": {**instance, "viewId": "view-1", "location": {"rowId": "row-1"}, "context": ui_context},
              "ui_view_configure": {**instance, "viewId": "view-1", "changes": {"filter": "value"}, "expectedVersion": "9007199254740993"},
              "ui_dialogs_list": instance, "ui_dialog_read": {**instance, "dialogId": "dialog-1"},
              "ui_dialog_update": {**instance, "dialogId": "dialog-1", "values": [{"fieldId": "field-1", "value": integer}], "expectedVersion": "9007199254740993"},
              "ui_dialog_submit": {**instance, "dialogId": "dialog-1", "action": "accept", "expectedVersion": "9007199254740993"},
              "ui_clipboard_export": {**instance, "source": ui_context, "format": "text", "destination": "artifact", "namespaceId": "private-1"},
              "ui_capture": {**instance, "viewId": "view-1", "namespaceId": "private-1"}}
    cell = {"columnId": "column-1", "value": value, "displayText": "controlled", "status": "valid", "error": None}
    row = {"rowId": "row-1", "parentRowId": None, "path": ["row-1"], "cells": [cell], "childIds": [], "childPage": None}
    outputs = {"commands_list": {"items": [command], "page": context.page}, "commands_describe": command,
               "commands_execute": {"commandId": "command-1", "callbackResult": None, "queued": True, "output": "", "outputTruncated": False, "eventCursor": None, "action": outcome},
               "plugins_list": {"items": [plugin], "page": context.page}, "plugins_actions": {"items": [action], "page": context.page}, "plugins_invoke": outcome,
               "plugins_load": plugin, "plugins_unload": {**plugin, "loaded": False}, "ui_actions_list": {"items": [action], "page": context.page}, "ui_action_invoke": outcome,
               "ui_views_list": {"items": [view], "page": context.page}, "ui_view_read": {"view": view, "columns": [{"columnId": "column-1", "name": "Value", "valueSchema": None, "visible": True, "order": 0}],
                   "rows": {"items": [row], "page": context.page}, "selection": ["row-1"], "value": None, "complete": True}, "ui_view_navigate": view, "ui_view_configure": view,
               "ui_dialogs_list": {"items": [dialog], "page": context.page}, "ui_dialog_read": dialog, "ui_dialog_update": dialog, "ui_dialog_submit": outcome,
               "ui_clipboard_export": {"destination": "artifact", "artifact": managed_artifact_example(), "clipboardSequence": None, "sourceVersion": "9007199254740993",
                   "format": "text", "size": "9007199254740993", "sha256": "0" * 64, "complete": True},
               "ui_capture": {"artifact": {**managed_artifact_example(), "mediaType": "image/png"}, "viewId": "view-1", "sourceVersion": "9007199254740993", "width": 1920, "height": 1080, "devicePixelRatio": "1.25", "complete": True}}
    extra_inputs = [(True, "commands_execute", {**instance, "command": "controlled"}), (True, "commands_execute", {**context.target, "command": "controlled"}),
                    (False, "commands_execute", {**inputs["commands_execute"], "targetGeneration": 9007199254740993}),
                    (False, "commands_execute", {**inputs["commands_execute"], "timeoutMs": 60001}),
                    (False, "commands_execute", {**inputs["commands_execute"], "command": ""}),
                    (True, "plugins_invoke", {**instance, "pluginId": "plugin-1", "actionId": "action-1", "arguments": {"requestedEffects": ["elevate"]}}),
                    (True, "plugins_load", {**instance, "artifactId": "artifact-1", "expectedSha256": "0" * 64}),
                    (False, "plugins_load", {**inputs["plugins_load"], "artifactId": "artifact-1"}),
                    (False, "plugins_load", {**inputs["plugins_load"], "expectedSha256": "0" * 63}),
                    (False, "plugins_unload", {key: item for key, item in inputs["plugins_unload"].items() if key != "expectedBuildId"}),
                    (False, "ui_action_invoke", {**inputs["ui_action_invoke"], "expectedUiVersion": 9007199254740993}),
                    (False, "ui_action_invoke", {**inputs["ui_action_invoke"], "context": {**ui_context, "target": {**context.target, "stopEpoch": "1", "targetGeneration": 9007199254740993}}}),
                    (False, "ui_view_navigate", {**inputs["ui_view_navigate"], "location": {"rowId": "row-1", "addressHex": "0x1000"}}),
                    (True, "ui_view_navigate", {**inputs["ui_view_navigate"], "location": {"moduleId": "module-1", "rvaHex": "0x1000"}}),
                    (True, "ui_view_navigate", {**inputs["ui_view_navigate"], "location": {"artifactId": "artifact-1", "offset": "18446744073709551615"}}),
                    (False, "ui_dialog_update", {**inputs["ui_dialog_update"], "values": []}),
                    (False, "ui_dialog_update", {**inputs["ui_dialog_update"], "expectedVersion": 9007199254740993}),
                    (False, "ui_clipboard_export", {**inputs["ui_clipboard_export"], "destination": "external"}),
                    (False, "ui_capture", {key: item for key, item in inputs["ui_capture"].items() if key != "namespaceId"})]
    clipboard_request = {**instance, "source": ui_context, "format": "text", "destination": "clipboard", "expectedClipboardSequence": "4294967295"}
    extra_inputs.extend([(True, "ui_clipboard_export", clipboard_request), (False, "ui_clipboard_export", {**clipboard_request, "namespaceId": "private-1"})])
    for name in NATIVE_EFFECT_TOOLS:
        extra_inputs.append((False, name, {**inputs[name], "effects": ["inspect"]}))
    for name in ("ui_view_configure", "ui_dialog_update", "ui_dialog_submit"):
        extra_inputs.append((False, name, {key: item for key, item in inputs[name].items() if key != "expectedVersion"}))
    typed_values = [{"kind": "null"}, {"kind": "boolean", "value": True}, integer, {"kind": "text", "text": "Hu Tao ❤"}, {"kind": "bytes", "bytesHex": ""},
                    {"kind": "bytes", "bytesHex": "0102"}, {"kind": "address", "addressHex": "0xffffffffffffffff"}, {"kind": "float", "widthBits": 32, "bytesHex": "00002842"},
                    {"kind": "float", "widthBits": 64, "bytesHex": "0000000000004540"}, value]
    for typed_value in typed_values:
        extra_inputs.append((True, "ui_dialog_update", {**inputs["ui_dialog_update"], "values": [{"fieldId": "field-1", "value": typed_value}]}))
    invalid_values = [{**integer, "bitsHex": 9007199254740993}, {**integer, "widthBits": 128}, {"kind": "float", "widthBits": 32, "bytesHex": "0000000000004540"},
                      {"kind": "object", "members": [{"name": "bad", "value": {"kind": "integer", "bitsHex": "0x10000000000000000", "widthBits": 64, "signed": False}}]},
                      {"kind": "bytes", "bytesHex": "0"}]
    for typed_value in invalid_values:
        extra_inputs.append((False, "ui_dialog_update", {**inputs["ui_dialog_update"], "values": [{"fieldId": "field-1", "value": typed_value}]}))
    unknown_action = {**action, "classification": "unknown", "effects": [], "enabled": False, "disabledReason": "No native provider classification", "argumentsSchema": None, "completionPredicate": None}
    consent = {**dialog, "state": "pending_consent", "interaction": "os_consent", "fields": {"items": [], "page": context.page}, "actions": []}
    field_error = {"fieldId": "field-1", "code": "invalid_value", "message": "Native field validation failed"}
    extra_outputs = [(True, "ui_actions_list", {"items": [unknown_action], "page": context.page}), (True, "ui_dialog_read", consent),
                     (True, "ui_dialog_update", {**dialog, "fields": {"items": [{**field, "validation": [field_error]}], "page": context.page}, "validation": [field_error]}),
                     (True, "ui_view_read", {**outputs["ui_view_read"], "rows": {"items": [{**row, "cells": [{**cell, "value": None, "status": "unreadable"}]}], "page": context.page}, "complete": False}),
                     (False, "plugins_list", {"items": [{**plugin, "actionsCount": 9007199254740993}], "page": context.page}),
                     (False, "plugins_load", {**plugin, "trustedCodeRequired": False}),
                     (False, "ui_actions_list", {"items": [{**action, "effects": ["inspect", "inspect"]}], "page": context.page}),
                     (False, "ui_dialog_read", {**dialog, "version": 9007199254740993}),
                     (False, "ui_dialog_read", {**dialog, "interaction": "agent_approved_uac"}),
                     (False, "ui_clipboard_export", {**outputs["ui_clipboard_export"], "sha256": "0" * 63}),
                     (False, "ui_capture", {**outputs["ui_capture"], "width": 0}),
                     (False, "ui_capture", {**outputs["ui_capture"], "sourceVersion": "18446744073709551616"}),
                     (True, "ui_dialog_submit", {**outcome, "state": "cancelled", "dialogId": None, "result": None})]
    for typed_value in typed_values:
        extra_outputs.append((True, "ui_view_read", {**outputs["ui_view_read"], "value": typed_value}))
    for typed_value in invalid_values:
        extra_outputs.append((False, "ui_view_read", {**outputs["ui_view_read"], "value": typed_value}))
    potential_effects = ["inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"]
    effects = {name: ["inspect"] for name in PROVIDER_UI_TOOLS}
    effects.update({name: potential_effects for name in NATIVE_EFFECT_TOOLS})
    effects.update({"ui_view_navigate": ["configure"], "ui_capture": ["inspect", "file_export"]})
    executors = {name: ("engine" if name.startswith(("commands_", "plugins_")) else "gui") for name in PROVIDER_UI_TOOLS}
    conditions = {"ui_clipboard_export": [{"field": "destination", "equals": "artifact", "effects": ["file_export"]}, {"field": "destination", "equals": "clipboard", "effects": ["configure"]}]}
    result = check_tool_family(probe, registry, validators, PROVIDER_UI_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, executors=executors, conditions=conditions,
                               native_effect_tools=NATIVE_EFFECT_TOOLS, computed_effects={"ui_clipboard_export": ["inspect", "file_export"]})
    for request, expected in ((inputs["ui_clipboard_export"], ["inspect", "file_export"]), (clipboard_request, ["inspect", "configure"])):
        assert probe.call("effects", request, "ui_clipboard_export") == {"valid": True, "effects": expected}
    for name in NATIVE_EFFECT_TOOLS:
        request = {**inputs[name], "arguments": {"requestedEffects": ["inspect"], "grantApproved": True}} if name in ("plugins_invoke", "ui_action_invoke") else inputs[name]
        rejected = probe.call("effects", request, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability", rejected
    result.update(nativeClassificationRequired=list(NATIVE_EFFECT_TOOLS), recursiveTypedValues=len(typed_values), rejectedUnsafeTypedValues=len(invalid_values),
                  clipboardDestinationEffects=2, explicitPendingOsConsent=True)
    return result


def check_library_script_contracts(probe, registry, validators):
    c = tool_context_examples()
    instance = {"instanceId": "instance-1"}
    ref = {"namespaceId": "private-1", "objectId": "object-1", "revision": "revision-1"}
    library = {**ref, "virtualPath": "scripts/Hu Tao ❤/controlled.js", "kind": "script", "mediaType": "text/javascript", "size": "9007199254740993",
               "sha256": "0" * 64, "createdAtUtc": "2026-10-01T12:00:00Z", "metadataVersion": "18446744073709551615", "tags": ["controlled"], "pinnedReferences": "1", "trashed": False}
    quota = {"namespaceId": "private-1", "usedBytes": "17", "reservedBytes": "0", "retainedBytes": "17", "pinnedBytes": "17", "namespaceLimit": "1073741824",
             "profileUsedBytes": "17", "profileLimit": "4294967296", "scriptSourceLimit": "16777216", "artifactLimit": "268435456", "chunkLimit": 1048576, "cleanupCandidates": [], "complete": True}
    limits = {"memoryBytes": 67108864, "cpuMs": 30000, "wallMs": 300000, "hostCalls": 10000, "logBytes": 8388608, "steps": 10000, "loopIterations": 10000, "waitMs": 30000}
    manifest = {"manifestVersion": "1", "apiRequirements": [{"apiId": "dbg", "version": "1"}], "dependencies": [ref],
                "targetRequirements": {"architecture": "x64", "context": "paused", "modules": [{"name": "controlled.exe", "sha256": "0" * 64}], "features": ["sse2"]},
                "effects": ["inspect", "modify"], "parametersSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "limits": limits, "failurePolicy": "stop", "tags": ["controlled"]}
    diagnostics = {"items": [], "page": c.page}
    script = {"object": library, "scriptId": "script-1", "name": "scripts/controlled.js", "engine": "x64dbg-js/v1", "engineBuildId": "0" * 64, "apiVersion": "1",
              "manifest": manifest, "previousRevision": None, "diagnostics": diagnostics, "validationStatus": "unvalidated", "trustedCode": False, "complete": True}
    trash = {"trashId": "trash-1", "object": {**library, "trashed": True}, "deletedAtUtc": "2026-10-01T12:00:00Z", "recoverable": True, "retainedRevision": ref}
    unverified = {"status": "unverified", "evidence": [], "followUp": {"capabilityId": "job_get", "retry": "after_reconciliation", "reason": "Actual runtime proof pending"}}
    job = {"jobId": "job-1", "revision": ref, "engine": "x64dbg-workflow/v1", "state": "queued", "context": None, "steps": {"items": [], "page": c.page},
           "artifacts": [], "logsArtifactId": None, "verification": unverified, "complete": False}
    native = {**instance, "ownerClientId": "client-1", "runtimeId": "runtime-1", "revision": ref, "version": "9007199254740993", "state": "ready", "ipLine": 1,
              "lineCount": "3", "lines": {"items": [{"line": 1, "text": "ret", "kind": "command", "branchTarget": None, "breakpoint": False, "enabled": True, "error": None}], "page": c.page},
              "error": None, "jobId": None, "trustedCode": True, "complete": True}
    inputs = {"library_namespaces": {}, "library_files_list": {"namespaceId": "private-1"}, "library_file_read": {**ref, "offset": "9007199254740993", "length": 1048576},
              "library_file_write": {"namespaceId": "private-1", "virtualPath": "scripts/Hu Tao ❤/controlled.js", "content": {"encoding": "utf8", "text": ""}, "expectedRevision": None},
              "library_file_rename": {**ref, "newVirtualPath": "scripts/renamed.js", "expectedRevision": "revision-1"}, "library_file_delete": {**ref, "expectedRevision": "revision-1"},
              "library_file_restore": {"namespaceId": "private-1", "trashId": "trash-1", "destination": "scripts/restored.js"},
              "library_search": {"namespaceId": "private-1", "query": "controlled"}, "library_import": {"namespaceId": "private-1", "path": "C:\\controlled.txt", "name": "scripts/imported.txt", "kind": "script", "expectedSha256": "0" * 64},
              "library_export": {**ref, "destination": "C:\\controlled.txt", "overwrite": False}, "library_quota": {"namespaceId": "private-1"},
              "scripts_list": {"namespaceId": "private-1", "engine": "x64dbg-js/v1", "tags": ["controlled"]},
              "scripts_create": {"namespaceId": "private-1", "name": "scripts/controlled.js", "engine": "x64dbg-js/v1", "source": "await dbg.call('target_state', context);", "manifest": manifest},
              "scripts_update": {**ref, "source": {"artifactId": "artifact-1", "sha256": "0" * 64}, "expectedRevision": "revision-1"}, "scripts_read": ref,
              "scripts_revisions": {"namespaceId": "private-1", "scriptId": "script-1"}, "scripts_validate": {**ref, "targetContext": c.paused},
              "scripts_run": {**ref, "instanceId": "instance-1", "targetContext": c.paused, "leaseId": "lease-1", "parameters": {"expected": "42"}, "limits": limits},
              "scripts_delete": {**ref, "expectedRevision": "revision-1"}, "script_languages": instance, "native_script_load": {**instance, "library": ref, "leaseId": "lease-1"},
              "native_script_control": {**instance, "action": "run", "line": 3, "expectedRuntimeId": "runtime-1", "expectedVersion": "9007199254740993", "leaseId": "lease-1"},
              "native_script_breakpoint": {**instance, "line": 1, "enabled": True, "expectedRevision": "revision-1"}, "native_script_state": instance,
              "workflows_run": {**ref, "context": {"instanceId": "instance-1", "targetContext": c.paused, "leaseId": "lease-1"}, "parameters": {}, "limits": limits}}
    validation = {"revision": ref, "engine": "x64dbg-js/v1", "engineBuildId": "0" * 64, "status": "valid", "diagnostics": diagnostics, "dependencies": [ref],
                  "resolvedEffects": ["inspect"], "classification": "known", "limits": limits, "executed": False, "complete": True}
    language = {"engine": "x64dbg-native", "name": "Native", "providerId": "native", "providerBuildId": "0" * 64, "apiVersion": "1", "available": True, "disabledReason": None,
                "architecture": "any", "executor": "engine", "trustedCode": True, "containment": "none", "manifestSchema": {"type": "object"}, "limits": limits,
                "controls": ["load", "run", "step", "abort", "unload", "set_ip", "breakpoint", "state"]}
    outputs = {"library_namespaces": {"items": [{"namespaceId": "private-1", "name": "Private", "visibility": "private", "ownerClientId": "client-1", "access": "read_write", "version": "1", "quota": quota}], "complete": True},
               "library_files_list": {"items": [library], "page": c.page}, "library_file_read": {"object": library, "offset": "9007199254740993", "length": 0, "bytesHex": "", "chunkSha256": "0" * 64, "eof": True},
               "library_file_write": library, "library_file_rename": library, "library_file_delete": trash, "library_file_restore": library,
               "library_search": {"items": [{"object": library, "source": "content", "offset": "9007199254740993", "snippet": "controlled", "snippetTruncated": False}], "page": c.page},
               "library_import": library, "library_export": {"revision": ref, "destination": "C:\\controlled.txt", "sha256": "0" * 64, "size": "9007199254740993", "replaced": False, "backupArtifactId": None, "journalId": "journal-1", "verified": True},
               "library_quota": quota, "scripts_list": {"items": [script], "page": c.page}, "scripts_create": script, "scripts_update": {**script, "previousRevision": "revision-1"},
               "scripts_read": {"script": script, "source": {"artifactId": "artifact-1", "sha256": "0" * 64}, "complete": True}, "scripts_revisions": {"items": [script], "page": c.page},
               "scripts_validate": validation, "scripts_run": job, "scripts_delete": trash, "script_languages": {"items": [language], "complete": True},
               "native_script_load": native, "native_script_control": native, "native_script_breakpoint": native, "native_script_state": native, "workflows_run": job}
    extra_inputs = [(True, "library_file_write", {**inputs["library_file_write"], "content": {"encoding": "hex", "bytesHex": ""}}),
                    (True, "library_file_write", {**inputs["library_file_write"], "content": {"artifactId": "artifact-1", "sha256": "0" * 64}}),
                    (True, "scripts_create", {**inputs["scripts_create"], "engine": "x64dbg-workflow/v1", "source": "x" * 65536}),
                    (False, "scripts_create", {**inputs["scripts_create"], "source": "x" * 65537}),
                    (False, "scripts_create", {**inputs["scripts_create"], "source": {"artifactId": "artifact-1"}}),
                    (False, "scripts_create", {**inputs["scripts_create"], "manifest": {**manifest, "dependencies": [{key: value for key, value in ref.items() if key != "revision"}]}}),
                    (False, "scripts_create", {**inputs["scripts_create"], "manifest": {**manifest, "dependencies": [ref, ref]}}),
                    (False, "library_file_read", {**ref, "length": 0}), (False, "library_file_read", {**ref, "length": 1048577}),
                    (False, "library_file_read", {**ref, "offset": 9007199254740993}), (False, "library_file_read", {**ref, "offset": "18446744073709551616"}),
                    (False, "library_import", {**inputs["library_import"], "artifactId": "artifact-1"}),
                    (True, "library_import", {key: value for key, value in {**inputs["library_import"], "artifactId": "artifact-1"}.items() if key != "path"}),
                    (False, "library_export", {**inputs["library_export"], "overwrite": True}),
                    (False, "library_export", {**inputs["library_export"], "overwrite": "replace"}),
                    (True, "library_export", {**inputs["library_export"], "overwrite": "replace", "expectedDestinationSha256": "0" * 64}),
                    (True, "scripts_run", ref), (True, "workflows_run", {**ref, "context": {}}),
                    (False, "native_script_breakpoint", {**inputs["native_script_breakpoint"], "line": 0}),
                    (False, "native_script_control", {**instance, "action": "set_ip"}),
                    (True, "native_script_control", {**instance, "action": "set_ip", "line": 3}),
                    (False, "native_script_control", {**instance, "action": "abort", "line": 3}),
                    (False, "native_script_control", {**instance, "action": "run_to_line", "line": 3}),
                    (False, "scripts_run", {**inputs["scripts_run"], "targetContext": {**c.target, "targetGeneration": 9007199254740993}})]
    good_paths = ["scripts/Hu Tao ❤/probe.js", "a", ".cache/log", "COM0.txt", "NULx.txt", "folder/" + "a" * 255, "folder/" + "😀" * 127]
    bad_paths = ["", ".", "..", "../other", "a/../other", "a/./b", "/absolute", "C:/outside", "a\\b", "a:stream", "a//b", "a/", "a. ", "a.", "a ",
                 "NUL", "aux.txt", "con .txt", "COM1.txt", "Lpt9", "COM¹.txt", "LPT²", "CONIN$", "conout$.txt", "a\x01b", "a?b", "a|b", "a*b", "a<b", "a>b", 'a"b', "a" * 256, "😀" * 128, "/".join(["a"] * 65)]
    for expected, paths in ((True, good_paths), (False, bad_paths)):
        for value in paths:
            extra_inputs.append((expected, "library_file_write", {**inputs["library_file_write"], "virtualPath": value}))
    for key, maximum in (("memoryBytes", 67108864), ("cpuMs", 30000), ("wallMs", 300000), ("hostCalls", 10000), ("logBytes", 8388608), ("steps", 100000), ("loopIterations", 100000), ("waitMs", 60000)):
        for value in (0, maximum + 1, "1"):
            extra_inputs.append((False, "scripts_run", {**inputs["scripts_run"], "limits": {key: value}}))
    for policy in ("stop", "declared_rollback", "independent_continuation"):
        extra_inputs.append((True, "scripts_create", {**inputs["scripts_create"], "manifest": {**manifest, "failurePolicy": policy}}))
    for action in ("run", "step", "abort", "unload"):
        extra_inputs.append((True, "native_script_control", {**instance, "action": action}))
    extra_outputs = [(False, "scripts_validate", {**validation, "executed": True}), (False, "library_file_write", {**library, "size": 9007199254740993}),
                     (False, "library_file_write", {**library, "virtualPath": "../other"}), (False, "library_quota", {**quota, "profileLimit": 4294967296}),
                     (False, "library_file_read", {**outputs["library_file_read"], "bytesHex": "f"}),
                     (True, "library_file_read", {**outputs["library_file_read"], "length": 1, "bytesHex": "ff", "eof": False}),
                     (False, "scripts_read", {**outputs["scripts_read"], "source": {"artifactId": "artifact-1", "sha256": "0" * 63}}),
                     (False, "native_script_state", {**native, "ipLine": 0}), (False, "native_script_state", {**native, "version": 9007199254740993}),
                     (False, "native_script_state", {**native, "trustedCode": False}),
                     (True, "native_script_state", {**native, "state": "unloaded", "ownerClientId": None, "runtimeId": None, "revision": None, "ipLine": None, "lineCount": "0", "lines": diagnostics}),
                     (False, "scripts_create", {**script, "manifest": {**manifest, "effects": ["inspect", "inspect"]}})]
    for state in ("queued", "running", "waiting_for_debugger", "waiting_for_event", "awaiting_user_consent", "cancelling", "completed", "cancelled", "failed", "interrupted_by_user", "unknown"):
        extra_outputs.append((True, "scripts_run", {**job, "state": state}))
    effects = {name: ["inspect"] for name in LIBRARY_SCRIPT_TOOLS}
    effects.update({name: ["configure"] for name in ("library_file_write", "library_file_rename", "library_file_delete", "library_file_restore", "library_import", "scripts_create", "scripts_update", "scripts_delete")})
    effects["library_export"] = ["file_export"]
    effects.update({name: ["inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"] for name in SCRIPT_NATIVE_EFFECT_TOOLS})
    executors = {name: ("engine" if name.startswith("native_script_") or name == "script_languages" else "broker") for name in LIBRARY_SCRIPT_TOOLS}
    required = {name: ("instanceId" if executors[name] == "engine" else "namespaceId") for name in LIBRARY_SCRIPT_TOOLS}
    required["library_namespaces"] = None
    conditions = {"library_export": [{"field": "overwrite", "equals": "replace", "effects": ["file_replace"]}]}
    result = check_tool_family(probe, registry, validators, LIBRARY_SCRIPT_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, required, executors, conditions, SCRIPT_NATIVE_EFFECT_TOOLS)
    replacement = {**inputs["library_export"], "overwrite": "replace", "expectedDestinationSha256": "0" * 64}
    assert probe.call("effects", replacement, "library_export") == {"valid": True, "effects": ["file_export", "file_replace"]}
    for name in SCRIPT_NATIVE_EFFECT_TOOLS:
        rejected = probe.call("effects", {**inputs[name], "permissions": ["all"]}, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "invalid_argument"
    result.update(nativeClassificationRequired=list(SCRIPT_NATIVE_EFFECT_TOOLS), virtualPathsAccepted=len(good_paths), virtualPathsRejected=len(bad_paths),
                  sourceInlineCharacterLimit=65536, largeSourcePinnedArtifactRoute=True, chunkByteLimit=1048576, actualRuntimeExecutionVerified=False)
    return result


def check_job_event_artifact_contracts(probe, registry, validators):
    c = tool_context_examples()
    instance = {"instanceId": "instance-1"}
    ref = {"namespaceId": "private-1", "objectId": "object-1", "revision": "revision-1"}
    recovery = {"capabilityId": "operation_reconcile", "retry": "after_reconciliation", "reason": "Observe actual effect state before retry"}
    unverified = {"status": "unverified", "evidence": [], "followUp": recovery}
    job = {"jobId": "job-1", "operationId": "operation-1", "ownerClientId": "client-1", "profileId": "profile-1", "capabilityId": "debugger_start", "version": "9007199254740993",
           "state": "awaiting_user_consent", "context": instance, "createdUtcMs": "18446744073709551615", "updatedUtcMs": "18446744073709551615", "deadlineUtcMs": None,
           "startingEventCursor": None, "progress": {"phase": "consent", "completed": "0", "total": None, "description": "Waiting for the human Windows decision"},
           "steps": {"items": [], "page": c.page}, "pendingInteraction": {"kind": "os_consent", "instanceId": "instance-1", "dialogId": None, "description": "Windows consent", "userControlled": True},
           "result": None, "effects": [], "verification": unverified, "pinnedRevisions": [ref], "artifactIds": [], "cancellationRequested": False, "reconciliationRequired": False, "complete": True}
    digest = hashlib.sha256(b"\xff").hexdigest()
    artifact = {**managed_artifact_example(), "size": "1", "sha256": digest, "name": "fixture.bin", "kind": "data", "ownerClientId": "client-1", "createdUtcMs": "9007199254740993",
                "metadataVersion": "18446744073709551615", "provenance": {"operationId": "operation-1", "jobId": "job-1", "context": c.target, "sourceArtifactIds": []},
                "referencedJobs": ["job-1"], "retainedEvidence": True, "trashed": False}
    upload = {"uploadId": "upload-1", "namespaceId": "private-1", "ownerClientId": "client-1", "name": "fixture.bin", "kind": "data", "size": "1", "sha256": digest,
              "receivedBytes": "0", "version": "9007199254740993", "expiresUtcMs": "18446744073709551615", "state": "allocated", "chunkLimit": 1048576,
              "ranges": {"items": [], "page": c.page}, "artifactId": None, "complete": True}
    event = {"cursor": "opaque:event/1", "sequence": "9007199254740993", "utcMs": "18446744073709551615", **instance, "target": c.target, "sourceThreadId": 123,
             "type": "pause", "providerId": "engine", "operationId": "operation-1", "jobId": "job-1", "payload": {"ipHex": "0xffffffffffffffff", "stopEpoch": "18446744073709551615"}, "artifactId": None}
    event_page = {"items": [event], "nextCursor": "opaque:event/1", "snapshotVersion": "18446744073709551615", "gap": None, "complete": True}
    reconciled = {"operationId": "operation-1", "journalId": "journal-1", "version": "9007199254740993", "jobId": "job-1", "state": "unknown", "context": c.target,
                  "effects": [{"stepId": "step-1", "status": "unknown", "summary": "Native owner disconnected"}],
                  "observations": {"items": [{"kind": "target", "context": c.target, "source": "worker", "state": "unavailable", "sha256": None, "artifactId": None, "data": {}}], "page": c.page},
                  "verification": unverified, "recovery": [recovery], "resumedMutation": False, "complete": False}
    scope = {"kind": "operation", "operationId": "operation-1"}
    inputs = {"jobs_list": {}, "job_get": {"jobId": "job-1"}, "job_wait": {"jobId": "job-1", "afterVersion": "9007199254740993", "timeoutMs": 60000},
              "job_cancel": {"jobId": "job-1", "reason": "Controlled cancellation"}, "operation_reconcile": {"operationId": "operation-1"},
              "events_read": {**c.target, "afterCursor": "opaque:event/0", "types": ["pause", "user_intervention"], "limit": 1000},
              "events_wait": {**c.target, "afterCursor": "opaque:event/0", "filter": {"types": ["pause"], "operationId": "operation-1"}, "timeoutMs": 60000},
              "events_clear": {**instance, "beforeCursor": "opaque:event/0"}, "artifacts_list": {"namespaceId": "private-1"},
              "artifacts_create": {"namespaceId": "private-1", "name": "fixture.bin", "kind": "data", "content": {"encoding": "hex", "bytesHex": "ff"}},
              "artifacts_upload_begin": {"namespaceId": "private-1", "name": "fixture.bin", "size": "1", "sha256": digest, "kind": "data"},
              "artifacts_upload_chunk": {"uploadId": "upload-1", "offset": "0", "bytes": "ff", "chunkSha256": digest}, "artifacts_upload_finish": {"uploadId": "upload-1"},
              "artifacts_read": {"artifactId": "artifact-1", "offset": "9007199254740993", "length": 1048576},
              "artifacts_delete": {"artifactIds": ["artifact-1"], "expectedHashes": [digest]}, "diagnostics_export": {"scope": scope, "namespaceId": "private-1", "includeTargetContent": False}}
    outputs = {"jobs_list": {"items": [job], "page": c.page}, "job_get": job, "job_wait": {"job": job, "changed": False, "timedOut": True},
               "job_cancel": {"job": {**job, "state": "cancelling", "cancellationRequested": True}, "requestAccepted": True, "terminationObserved": False}, "operation_reconcile": reconciled,
               "events_read": event_page, "events_wait": {**event_page, "matched": True, "timedOut": False},
               "events_clear": {**instance, "removedEvents": "9007199254740993", "oldestAvailableCursor": "opaque:event/1", "version": "18446744073709551615", "affectedWaits": "1", "journalsPreserved": True, "retainedEvidencePreserved": True},
               "artifacts_list": {"items": [artifact], "page": c.page}, "artifacts_create": artifact, "artifacts_upload_begin": upload,
               "artifacts_upload_chunk": {"upload": {**upload, "receivedBytes": "1", "state": "receiving", "ranges": {"items": [{"offset": "0", "length": 1, "chunkSha256": digest}], "page": c.page}},
                   "acceptedOffset": "0", "acceptedLength": 1, "chunkSha256": digest, "retransmission": False}, "artifacts_upload_finish": artifact,
               "artifacts_read": {"artifact": artifact, "offset": "0", "length": 1, "bytesHex": "ff", "chunkSha256": digest, "eof": True},
               "artifacts_delete": {"items": [{"artifactId": "artifact-1", "sha256": digest, "status": "retained", "trashId": None, "referencedJobs": ["job-1"], "retainedEvidence": True, "error": None}], "journalId": "journal-1", "complete": True},
               "diagnostics_export": {"artifact": {**artifact, "kind": "diagnostics"}, "scope": scope, "includeTargetContent": False,
                   "inventory": {"items": [{"kind": "journal", "source": "operation-1", "sha256": digest, "size": "1", "containsTargetContent": False, "redacted": True}], "page": c.page},
                   "credentialsRedacted": True, "manifestSha256": digest, "complete": True}}
    extra_inputs = [(False, "job_wait", {**inputs["job_wait"], "afterVersion": 9007199254740993}), (False, "job_wait", {**inputs["job_wait"], "timeoutMs": 60001}),
                    (True, "jobs_list", {"state": "interrupted_by_user", **instance}), (False, "jobs_list", {"state": "accepted"}),
                    (True, "events_read", instance), (False, "events_read", {**inputs["events_read"], "targetGeneration": 9007199254740993}),
                    (False, "events_read", {**inputs["events_read"], "types": ["pause", "pause"]}),
                    (False, "events_wait", {**inputs["events_wait"], "afterCursor": 1}), (False, "events_wait", {**inputs["events_wait"], "filter": {"unknown": "reject"}}),
                    (False, "events_wait", {**inputs["events_wait"], "timeoutMs": 0}), (False, "events_wait", {**inputs["events_wait"], "timeoutMs": 60001}),
                    (False, "events_wait", {key: value for key, value in inputs["events_wait"].items() if key != "filter"}),
                    (True, "artifacts_create", {**inputs["artifacts_create"], "content": {"encoding": "hex", "bytesHex": ""}}),
                    (True, "artifacts_create", {**inputs["artifacts_create"], "content": {"artifactId": "artifact-2", "sha256": digest}}),
                    (False, "artifacts_upload_begin", {**inputs["artifacts_upload_begin"], "size": 9007199254740993}),
                    (True, "artifacts_upload_begin", {**inputs["artifacts_upload_begin"], "size": "0"}),
                    (False, "artifacts_upload_chunk", {**inputs["artifacts_upload_chunk"], "offset": "18446744073709551616"}),
                    (False, "artifacts_upload_chunk", {**inputs["artifacts_upload_chunk"], "bytes": ""}),
                    (False, "artifacts_upload_chunk", {**inputs["artifacts_upload_chunk"], "bytes": "f"}),
                    (False, "artifacts_upload_chunk", {**inputs["artifacts_upload_chunk"], "chunkSha256": "0" * 63}),
                    (False, "artifacts_read", {**inputs["artifacts_read"], "length": 0}), (False, "artifacts_read", {**inputs["artifacts_read"], "length": 1048577}),
                    (False, "artifacts_delete", {**inputs["artifacts_delete"], "artifactIds": ["artifact-1", "artifact-1"]}),
                    (False, "artifacts_delete", {**inputs["artifacts_delete"], "expectedHashes": []}),
                    (False, "diagnostics_export", {**inputs["diagnostics_export"], "includeTargetContent": "false"}),
                    (False, "diagnostics_export", {key: value for key, value in inputs["diagnostics_export"].items() if key != "includeTargetContent"}),
                    (True, "diagnostics_export", {**inputs["diagnostics_export"], "scope": {"kind": "instance", **instance}, "includeTargetContent": True}),
                    (False, "diagnostics_export", {**inputs["diagnostics_export"], "scope": {"kind": "instance"}})]
    gap = {"requestedCursor": "opaque:event/0", "oldestAvailableCursor": "opaque:event/1", "missingFromSequence": "9007199254740993", "missingThroughSequence": "18446744073709551615",
           "snapshotRoute": {**recovery, "capabilityId": "target_snapshot"}}
    extra_outputs = [(True, "events_read", {**event_page, "items": [], "gap": gap, "complete": False}),
                     (False, "events_read", {**event_page, "items": [{**event, "sequence": 9007199254740993}]}),
                     (False, "events_read", {**event_page, "items": [{**event, "target": {**c.target, "targetGeneration": 9007199254740993}}]}),
                     (False, "events_read", {**event_page, "gap": {key: value for key, value in gap.items() if key != "snapshotRoute"}}),
                     (False, "events_clear", {**outputs["events_clear"], "journalsPreserved": False}),
                     (False, "events_clear", {**outputs["events_clear"], "retainedEvidencePreserved": False}),
                     (False, "operation_reconcile", {**reconciled, "resumedMutation": True}), (False, "job_get", {**job, "version": 9007199254740993}),
                     (False, "job_get", {**job, "pendingInteraction": {**job["pendingInteraction"], "userControlled": False}}),
                     (True, "job_get", {**job, "state": "unknown", "reconciliationRequired": True, "pendingInteraction": None}),
                     (False, "artifacts_upload_begin", {**upload, "receivedBytes": 9007199254740993}),
                     (False, "artifacts_upload_chunk", {**outputs["artifacts_upload_chunk"], "acceptedLength": 0}),
                     (True, "artifacts_upload_chunk", {**outputs["artifacts_upload_chunk"], "retransmission": True}),
                     (True, "artifacts_read", {**outputs["artifacts_read"], "length": 0, "bytesHex": "", "offset": "1"}),
                     (False, "artifacts_read", {**outputs["artifacts_read"], "bytesHex": "ff0"}),
                     (False, "artifacts_create", {**artifact, "size": "18446744073709551616"}),
                     (False, "diagnostics_export", {**outputs["diagnostics_export"], "credentialsRedacted": False})]
    states = ("queued", "running", "waiting_for_debugger", "waiting_for_event", "awaiting_user_consent", "cancelling", "completed", "cancelled", "failed", "interrupted_by_user", "unknown")
    for state in states:
        extra_inputs.append((True, "jobs_list", {"state": state}))
        extra_outputs.append((True, "job_get", {**job, "state": state}))
    effects = {name: ["inspect"] for name in JOB_EVENT_ARTIFACT_TOOLS}
    effects.update({name: ["configure"] for name in ("events_clear", "artifacts_create", "artifacts_upload_begin", "artifacts_upload_chunk", "artifacts_upload_finish", "artifacts_delete")})
    effects["diagnostics_export"] = ["inspect", "file_export"]
    effects["job_cancel"] = ["inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"]
    required = {"jobs_list": None, "job_get": "jobId", "job_wait": "jobId", "job_cancel": "jobId", "operation_reconcile": "operationId",
                "events_read": "instanceId", "events_wait": "instanceId", "events_clear": "instanceId", "artifacts_list": "namespaceId", "artifacts_create": "namespaceId",
                "artifacts_upload_begin": "namespaceId", "artifacts_upload_chunk": "uploadId", "artifacts_upload_finish": "uploadId", "artifacts_read": "artifactId",
                "artifacts_delete": "artifactIds", "diagnostics_export": "namespaceId"}
    result = check_tool_family(probe, registry, validators, JOB_EVENT_ARTIFACT_TOOLS, inputs, outputs, extra_inputs, extra_outputs, effects, required,
                               {name: "broker" for name in JOB_EVENT_ARTIFACT_TOOLS}, native_effect_tools=JOB_NATIVE_EFFECT_TOOLS)
    assert validators[("job_wait", "input")].schema["properties"]["timeoutMs"]["default"] == 30000
    assert all(form["properties"]["timeoutMs"]["default"] == 30000 for form in validators[("events_wait", "input")].schema["oneOf"])
    result.update(nativeClassificationRequired=list(JOB_NATIVE_EFFECT_TOOLS), jobStates=list(states), waitDefaultMs=30000, waitMaximumMs=60000,
                  protectedConsentAndRetention=True, actualJobsEventsOrPublicationVerified=False)
    return result


def check_native_launch(probe, architecture):
    import os
    import shutil
    directory = probe.output / "Hu Tao ❤ launch"
    directory.mkdir()
    binary = directory / "reference with spaces.exe"
    original = probe.binary.parent / "wininspect-mcp-launch-reference.exe"
    shutil.copy2(original, binary)
    assert file_identity(original)["sha256"] == file_identity(binary)["sha256"]
    inherited = [{"name": "SystemRoot", "value": os.environ["SystemRoot"]}, {"name": "WI_KEEP", "value": "inherited"},
                 {"name": "WI_DELETE", "value": "remove"}, {"name": "WI_EMPTY", "value": "old"}, {"name": "=C:", "value": "C:\\controlled"}]
    intended = ["", "two words", 'a"b', "trail\\", "\\\\\"", "comma,value", "{braces}", "Hu Tao ❤ 😀", "\t", "run", " a "]
    changes = [{"name": "wi_delete", "value": None}, {"name": "WI_EMPTY", "value": ""}, {"name": "WI_UNICODE", "value": "Columbina 💙"}]
    outputs = []
    for index, mode in enumerate(("argv", "raw", "replace")):
        mode_changes = [*changes, {"name": "SystemRoot", "value": os.environ["SystemRoot"]}] if mode == "replace" else changes
        request = {"instanceId": "instance-fixture", "path": str(binary), "cwd": str(directory), "environment": {"mode": "replace" if mode == "replace" else "inherit", "changes": mode_changes}}
        expected_arguments = intended if mode != "raw" else ["", 'raw " quote', "trailing\\", "Furina 💙"]
        if mode == "raw":
            request["rawCommandLine"] = subprocess.list2cmdline([str(binary), *expected_arguments])
        else:
            request["argv"] = expected_arguments
        plan = probe.call("launch-plan", {"request": request, "resolvedImage": str(binary), "inherited": inherited})
        assert plan["valid"], plan
        observed = run_launch_reference(plan, binary, directory / f"launch-{index}.json", 64 if architecture == "x64" else 32)
        assert observed["observed"]["argv"] == [str(binary), *expected_arguments]
        assert observed["observed"]["cwd"].casefold() == str(directory).casefold()
        assert observed["observed"]["environment"] == {"WI_KEEP": None if mode == "replace" else "inherited", "WI_DELETE": None, "WI_EMPTY": "", "WI_UNICODE": "Columbina 💙"}
        if mode == "raw":
            assert plan["commandLine"] == request["rawCommandLine"] == observed["observed"]["rawCommandLine"]
        outputs.append(observed)
    base = {"request": {"instanceId": "instance-fixture", "path": str(binary)}, "resolvedImage": str(binary), "inherited": inherited}
    rejected = [
        {**base, "request": {**base["request"], "argv": ["x" * 32766]}},
        {**base, "request": {**base["request"], "argv": ["😀" * 16384]}},
        {**base, "request": {**base["request"], "environment": {"changes": [{"name": "WI_KEEP", "value": "1"}, {"name": "wi_keep", "value": "2"}]}}},
        {**base, "request": {**base["request"], "environment": {"changes": [{"name": f"WI_{index}", "value": "x" * 32766} for index in range(17)]}}},
        {**base, "inherited": [*inherited, {"name": "wi_keep", "value": "collision"}]}]
    for value in rejected:
        assert not probe.call("launch-plan", value)["valid"]
    write_json(directory / "native-launch-observations.json", outputs)
    return {"actualNativeLaunches": outputs, "rejectedPreflightCases": len(rejected), "environmentMutation": "isolated child block only"}


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class TokenGroups(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD), ("groups", SidAndAttributes * 1)]


class NativeFileInformation(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME),
                ("written", wintypes.FILETIME), ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD), ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]


def process_token_oracle(process_handle=None):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    KERNEL.GetCurrentProcess.restype = wintypes.HANDLE
    KERNEL.LocalFree.argtypes = [ctypes.c_void_p]
    KERNEL.LocalFree.restype = ctypes.c_void_p
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(KERNEL.GetCurrentProcess() if process_handle is None else process_handle, 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    queries = []
    try:
        def information(kind):
            size = wintypes.DWORD()
            queried = advapi.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
            queries.append({"class": kind, "success": bool(queried), "error": ctypes.get_last_error(), "size": size.value})
            assert 0 < size.value <= 1048576
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer

        def sid_text(address):
            text = wintypes.LPWSTR()
            if not advapi.ConvertSidToStringSidW(address, ctypes.byref(text)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return text.value
            finally:
                KERNEL.LocalFree(ctypes.cast(text, ctypes.c_void_p))

        user = information(1)
        groups = information(2)
        count = wintypes.DWORD.from_buffer(groups).value
        offset = TokenGroups.groups.offset
        assert offset + count * ctypes.sizeof(SidAndAttributes) <= len(groups)
        entries = (SidAndAttributes * count).from_buffer(groups, offset)
        logon_sids = [sid_text(entry.sid) for entry in entries if entry.attributes & 0xc0000000 == 0xc0000000]
        assert len(logon_sids) == 1
        integrity = information(25)
        sid = SidAndAttributes.from_buffer(integrity).sid
        subauthorities = ctypes.c_ubyte.from_address(sid + 1).value
        assert subauthorities
        level = wintypes.DWORD.from_address(sid + 8 + (subauthorities - 1) * 4).value
        label = "untrusted" if level < 0x1000 else "low" if level < 0x2000 else "medium" if level < 0x3000 else "high" if level < 0x4000 else "system" if level < 0x5000 else "protected"
        observed = {"userSid": sid_text(SidAndAttributes.from_buffer(user).sid), "logonSid": logon_sids[0], "integrity": label,
                    "sessionId": wintypes.DWORD.from_buffer(information(12)).value, "elevated": bool(wintypes.DWORD.from_buffer(information(20)).value)}
        return observed, queries
    finally:
        KERNEL.CloseHandle(token)


def parent_token_oracle():
    return process_token_oracle()


def file_handle_oracle(binary):
    KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    KERNEL.CreateFileW.restype = wintypes.HANDLE
    KERNEL.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(NativeFileInformation)]
    handle = KERNEL.CreateFileW(str(binary), 0x80000000, 1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = NativeFileInformation()
        if not KERNEL.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"volumeSerial": information.volume, "fileIndex": str(information.indexHigh << 32 | information.indexLow),
                "size": str(information.sizeHigh << 32 | information.sizeLow)}
    finally:
        KERNEL.CloseHandle(handle)


def check_native_parity_catalog(probe, catalog):
    baseline_path = ROOT / "tests/native_mcp/parity-manifest.json"
    baseline_bytes = baseline_path.read_bytes()
    baseline = json.loads(baseline_bytes)
    collections = {"operation": baseline["operations"], "binding": baseline["bindings"],
                   "registration_factory": baseline["registrationFactories"], "excluded_declaration": baseline["excludedDeclarations"]}
    counts = {kind: len(rows) for kind, rows in collections.items()}
    assert counts == {"operation": 3940, "binding": 1623, "registration_factory": 29, "excluded_declaration": 87}
    metadata = probe.call("parity-metadata")
    captures = [{"captureRef": "runtimeCaptures." + key, "architecture": value["architecture"], "state": value["state"],
                 "snapshotSha256": value["snapshot"]["sha256"], "receiptSha256": value["captureReceiptSha256"],
                 "modules": value["loadedModules"], "currentRuntimeProof": False} for key, value in baseline["runtimeCaptures"].items()]
    expected_metadata = {"schemaVersion": 1, "baselineManifestSha256": hashlib.sha256(baseline_bytes).hexdigest(),
                         "sourceInputs": baseline["inputs"], "categories": baseline["categories"], "recordCounts": counts,
                         "historicalCaptures": captures, "coverageGaps": baseline["coverageGaps"], "buildId": catalog["buildId"],
                         "operationalActionIds": [], "runtimeValidated": False}
    assert metadata == expected_metadata
    build = json.loads((probe.binary.parent / "build-manifest.json").read_text(encoding="utf-8"))
    for entry in baseline["inputs"]:
        assert file_identity(ROOT / entry["path"])["sha256"] == entry["sha256"]
        assert file_identity(ROOT / entry["path"]) in build["sourceInputs"]
    action_ids = {row["id"]: "parity." + hashlib.sha256(row["id"].encode("utf-8")).hexdigest() for row in collections["operation"]}
    assert len(set(action_ids.values())) == counts["operation"]
    def operation(row):
        return {"actionId": action_ids[row["id"]], "inventory": row, "availability": "planned", "operational": False,
                "executionAdapterInstalled": False, "runtimeRegistrationBound": False, "classification": "unknown"}
    expected = {kind: sorted((operation(row) for row in rows), key=lambda row: row["actionId"]) if kind == "operation" else
                [{"key": str(index), "data": row} for index, row in enumerate(rows)] for kind, rows in collections.items()}
    def events(value):
        if isinstance(value, dict):
            return 3 + sum(1 + events(child) for child in value.values())
        if isinstance(value, list):
            return 3 + sum(events(child) for child in value)
        return 1
    pages = []
    cursors = []
    def collect(request):
        query = dict(request)
        items = []
        seen = set()
        for _ in range(counts[query.get("kind", "operation")] + 1):
            response = probe.call("parity-page", query)
            assert response["valid"], response
            page = response["page"]
            assert set(page) == {"schemaVersion", "buildId", "kind", "items", "hasMore", "nextCursor", "snapshotRecordCount", "operational"}
            assert page["schemaVersion"] == 1 and page["buildId"] == metadata["buildId"] and not page["operational"]
            assert page["kind"] == query.get("kind", "operation") and page["snapshotRecordCount"] == str(counts[page["kind"]])
            assert len(page["items"]) <= query.get("limit", 100)
            assert probe.observations[-1]["stdoutSize"] <= 8 * 1024 * 1024 and events(response) <= 100000
            pages.append({"kind": page["kind"], "rows": len(page["items"]), "stdoutSize": probe.observations[-1]["stdoutSize"], "events": events(response)})
            items.extend(page["items"])
            if not page["hasMore"]:
                assert page["nextCursor"] is None
                return items
            cursor = page["nextCursor"]
            assert isinstance(cursor, str) and cursor not in seen and len(cursor) <= 4096
            seen.add(cursor)
            cursors.append((dict(request), cursor))
            query["cursor"] = cursor
        raise AssertionError("Parity pagination failed to reach its finite compiled snapshot")
    for kind in collections:
        assert collect({"kind": kind, "limit": 1000}) == expected[kind]
    assert any(page["kind"] == "operation" and 0 < page["rows"] < 1000 for page in pages), "Native event bound was not exercised"
    categories = sorted(baseline["categories"])
    queries = [{"category": category, "limit": 1000} for category in categories]
    queries += [{"architecture": name, "limit": 1000} for name in ("x32", "x64")]
    queries += [{"provider": name, "limit": 1000} for name in sorted({row["provider"] for row in collections["operation"]})]
    queries += [{"category": "unknown-category", "limit": 7}, {"provider": "unknown-provider", "limit": 1}]
    for query in queries:
        rows = [item for item in expected["operation"] if
                all(value in item["inventory"]["architectures"] if key == "architecture" else item["inventory"][key] == value
                    for key, value in query.items() if key != "limit")]
        assert collect(query) == rows
    small = probe.call("parity-page", {"limit": 1})
    assert small["valid"] and small["page"]["items"] == expected["operation"][:1]
    assert probe.call("parity-page", {"limit": 2, "cursor": small["page"]["nextCursor"]})["page"]["items"] == expected["operation"][1:3]
    assert probe.call("parity-page", {})["page"]["items"] == expected["operation"][:100]
    request, cursor = cursors[0]
    prefix = cursor.rsplit(":", 1)[0] + ":"
    terminal = probe.call("parity-page", {**request, "cursor": prefix + str(counts["operation"])})
    assert terminal["valid"] and terminal["page"]["items"] == [] and terminal["page"]["nextCursor"] is None
    invalid = [[], None, 7, {"limit": 0}, {"limit": 1001}, {"limit": True}, {"limit": "1"}, {"unknown": 1},
               {"kind": "metadata"}, {"category": 1}, {"provider": None}, {"architecture": "arm64"}, {"category": "x" * 129},
               {"provider": "a\0b"}, {"cursor": "x" * 4097}, {"cursor": "wrong"}, {"kind": "binding", "category": "command"},
               {**request, "cursor": cursor, "provider": "changed"}, {"kind": "binding", "cursor": cursor},
               {**request, "cursor": cursor.replace(metadata["buildId"], "0" * 64)},
               *({**request, "cursor": prefix + suffix} for suffix in ("-1", "01", "", "18446744073709551616", "3941", "18446744073709551615"))]
    for value in invalid:
        response = probe.call("parity-page", raw=json.dumps(value).encode("utf-8"))
        assert not response["valid"] and response["error"]["code"] == "invalid_argument", response
    selected = {next(row["id"] for row in collections["operation"] if row["category"] == name) for name in categories}
    selected.add(next(name for name in action_ids if not re.fullmatch(r"[A-Za-z0-9_.:-]+", name)))
    selected.update(name for name in action_ids if not name.isascii())
    for name in sorted(selected):
        record = next(item for item in expected["operation"] if item["inventory"]["id"] == name)
        assert probe.call("parity-describe", argument=action_ids[name]) == {"valid": True, "record": record}
        assert probe.call("parity-resolve-input", name) == {"valid": True, "record": record}
    for mode, name in (("parity-describe", "parity." + "0" * 64), ("parity-describe", next(iter(action_ids.values())).upper()),
                       ("parity-resolve", "absent.inventory"), ("parity-resolve", "COMMAND.INC")):
        response = probe.call(mode, argument=name)
        assert not response["valid"] and response["error"]["code"] == "unsupported_capability"
    dispatched = probe.call("parity-dispatch-check")
    assert dispatched == {"rejectedActionIds": sorted(action_ids.values())}
    vectors = [b"", b"abc", "Hu Tao ❤ 😀".encode("utf-8"), b"a\0b", bytes(range(256)) * 4096]
    for raw in vectors:
        assert probe.call("sha256", raw=raw) == {"valid": True, "sha256": hashlib.sha256(raw).hexdigest()}
    assert probe.call("sha256", raw=b"x" * (8 * 1024 * 1024 + 1))["error"]["code"] == "payload_limit"
    assert baseline_path.read_bytes() == baseline_bytes
    write_json(probe.output / "parity-pages.json", pages)
    return {"baselineManifest": file_identity(baseline_path), "compiledMetadata": metadata, "completeRecordComparisons": counts,
            "boundedPages": len(pages), "filteredQueries": len(queries), "rejectedPageInputs": len(invalid),
            "exactLookupPairs": len(selected), "unavailableDispatchRejected": len(action_ids), "sha256Vectors": len(vectors)}


def check_native_components(probe, architecture, validators, catalog):
    expected_token, token_queries = parent_token_oracle()
    observations = []
    def verify(information, identity, binary, component):
        assert set(information) == {"schemaVersion", "component", "buildId", "wireVersion", "process", "declaredToolCount", "declaredLegacyAliasCount", "declaredParityOperationCount", "implementedTransports", "operationalTools"}
        assert information["schemaVersion"] == information["wireVersion"] == 1 and information["component"] == component
        assert information["buildId"] == catalog["buildId"] and information["declaredToolCount"] == len(catalog["tools"])
        assert information["implementedTransports"] == information["operationalTools"] == []
        assert information["declaredLegacyAliasCount"] == 80
        assert information["declaredParityOperationCount"] == 3940
        process = information["process"]
        assert validators["NativeProcessIdentity"].is_valid(process)
        assert {key: process[key] for key in identity} == identity and process["architecture"] == architecture
        assert {key: process[key] for key in expected_token} == expected_token
        image = process["image"]
        assert Path(image["path"]).resolve() == binary.resolve() and image["sha256"] == file_identity(binary)["sha256"]
        assert {key: image[key] for key in ("volumeSerial", "fileIndex", "size")} == file_handle_oracle(binary)
        observations.append({"information": information, "processIdentity": identity, "artifact": file_identity(binary)})
    for component, name in (("broker", "wininspect-mcp.exe"), ("connector", "wininspect-mcp-connect.exe")):
        binary = probe.binary.parent / name
        stdout, stderr, receipt = probe.execute([str(binary), "--build-info"])
        assert not stderr
        information = json.loads(stdout)
        receipt["response"] = information
        verify(information, receipt["processIdentity"], binary, component)
        for arguments in ([], ["--serve"], ["--unknown"]):
            stdout, stderr, receipt = probe.execute([str(binary), *arguments], expected_exit=64)
            assert not stdout and json.loads(stderr)["code"] == "unsupported_capability"
        stdout, stderr, receipt = probe.execute([str(binary), "--help"])
        assert not stdout and b"--build-info" in stderr
    worker = probe.call("worker-build-info")
    assert worker["valid"], worker
    verify(worker["information"], probe.observations[-1]["processIdentity"], probe.binary, "worker_adapter")
    write_json(probe.output / "native-components.json", observations)
    return {"componentProcesses": observations, "inheritedTokenOracle": expected_token, "tokenQueryStatuses": token_queries,
            "unimplementedTransportStartsRejected": 6, "workerLinked": True}


def check_ipc_wire(probe):
    envelope = {"context": {"brokerGeneration": "18446744073709551615"}, "deadlineUtcMs": "9007199254740993", "authenticationContextId": "fixture-context",
                "payload": {"jsonrpc": "2.0", "id": "request-1", "method": "fixture", "params": {"text": "Hu Tao ❤ 😀", "value": "18446744073709551615"}}}
    body = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    packets = []
    for kind in range(1, 8):
        request_id = 0 if kind == 5 else 2**64 - 1
        packet = struct.pack("<4sHHIIQ", b"WIMC", 1, kind, len(body) + 24, 0, request_id) + body
        encoded = probe.call("ipc-encode", {"kind": kind, "requestId": str(request_id), "envelope": envelope})
        assert encoded["valid"] and bytes.fromhex(encoded["bytesHex"]) == packet
        expected_header = {"wireVersion": 1, "kind": kind, "totalLength": len(packet), "requestId": str(request_id)}
        assert probe.call("ipc-header", raw=packet[:24]) == {"valid": True, "header": expected_header}
        assert probe.call("ipc-decode", raw=packet) == {"valid": True, "header": expected_header, "envelope": envelope}
        packets.append({"kind": kind, "sha256": hashlib.sha256(packet).hexdigest(), "bytes": len(packet)})
    def header(magic=b"WIMC", version=1, kind=3, size=len(body) + 24, flags=0, request_id=1):
        return struct.pack("<4sHHIIQ", magic, version, kind, size, flags, request_id)
    invalid_headers = [header(magic=b"BAD!"), header(version=2), header(kind=0), header(kind=8), header(size=25),
                       header(size=8 * 1024 * 1024 + 1), header(flags=1), header(request_id=0), header()[:23]]
    for value in invalid_headers:
        assert not probe.call("ipc-header", raw=value)["valid"]
    assert probe.call("ipc-header", raw=header(size=8 * 1024 * 1024))["valid"]
    invalid_bodies = [b"[]", b"\xff", b'{"deadlineUtcMs":"1","deadlineUtcMs":"2"}', json.dumps({**envelope, "unknown": 1}).encode(),
                      json.dumps({**envelope, "deadlineUtcMs": 9007199254740993}).encode(),
                      json.dumps({**envelope, "context": {"instanceId": "i", "targetId": "t"}}).encode()]
    for value in invalid_bodies:
        assert not probe.call("ipc-decode", raw=header(size=len(value) + 24) + value)["valid"]
    for value in (header() + body[:-1], header() + body + b"x", b"", header(size=8 * 1024 * 1024)):
        assert not probe.call("ipc-decode", raw=value)["valid"]
    for request in ({"kind": 3, "requestId": "0", "envelope": envelope}, {"kind": 8, "requestId": "1", "envelope": envelope},
                    {"kind": 3, "requestId": "18446744073709551616", "envelope": envelope}):
        assert not probe.call("ipc-encode", request)["valid"]
    return {"wirePackets": packets, "independentByteComparisons": 7, "rejectedHeaders": len(invalid_headers), "rejectedBodies": len(invalid_bodies) + 4, "rejectedEncodeInputs": 3}


def run_contract_checks(binary, output, architecture, selected, timeout):
    probe = ContractProbe(binary, output, timeout)
    catalog = probe.call("catalog")
    write_json(Path(output) / "compiled-contracts.json", catalog)
    validators = independent_validators(catalog)
    registry = probe.call("registry")
    write_json(Path(output) / "compiled-registry.json", registry)
    catalog["tools"] = registry["tools"]
    formats = validators["Hex64"].format_checker
    tool_validators = registry_validators(registry, formats)
    examples, mutation = contract_examples()
    results = []
    for name in CASE_NAMES:
        if selected and not any(fnmatch.fnmatchcase(name, pattern) for pattern in selected):
            continue
        result = {"name": name, "architecture": architecture, "status": "verified"}
        started = time.monotonic()
        try:
            if name == "test_compiled_schema_catalog":
                assert catalog["schemaVersion"] == 1 and re.fullmatch(r"[0-9a-f]{64}", catalog["buildId"])
                assert catalog["operationalTools"] == [] and set(validators) == set(examples)
                result["contracts"] = len(validators)
            elif name == "test_contract_boundaries":
                checked = 0
                for contract, values in examples.items():
                    for expected, value in values:
                        assert validators[contract].is_valid(value) == expected, f"{contract} example {checked}: independent acceptance differs from {expected}"
                        assert probe.call("validate", value, contract)["valid"] == expected, f"{contract} example {checked}: native acceptance differs from {expected}"
                        checked += 1
                    if values[0][1].__class__ is dict:
                        unknown = {**values[0][1], "unregisteredField": "reject"}
                        assert not validators[contract].is_valid(unknown) and not probe.call("validate", unknown, contract)["valid"]
                        checked += 1
                result["independentComparisons"] = checked
                missing = probe.call("validate", {}, "UnregisteredContract")
                assert not missing["valid"] and missing["error"]["code"] == "unknown_contract"
            elif name == "test_context_roundtrip":
                assert probe.call("normalize", {}, "Page") == {"valid": True, "limit": 100}
                assert probe.call("normalize", {}, "Deadline") == {"valid": True, "timeoutMs": 60000}
                context = probe.call("normalize", mutation, "MutationContext")
                assert context == {"valid": True, "targetGeneration": "18446744073709551615", "stopEpoch": "9007199254740993", "leaseId": "lease-1", "threadId": 4294967295}
                for value in (0, 2**32 - 1, 2**53 + 1, 2**64 - 1):
                    for contract, input_value in (("Decimal64", str(value)), ("Hex64", hex(value))):
                        assert probe.call("normalize", input_value, contract) == {"valid": True, "decimal": str(value), "hex": hex(value)}
                result["actualContext"] = context
            elif name == "test_bounded_json":
                malformed = [b'{"limit":1,"limit":2}', b'{"a":{"x":1,"x":2}}', b'{"limit":', b'{"cursor":"\xff"}', b'{"cursor":"\\ud800"}', b'[' * 66 + b'0' + b']' * 66,
                             b'{"cursor":"' + b'x' * (8 * 1024 * 1024) + b'"}', b'[' + b','.join([b'0'] * 100001) + b']']
                for raw in malformed:
                    response = probe.call("validate", argument="Page", raw=raw)
                    assert not response["valid"] and response["error"]["code"] in ("invalid_json", "payload_limit"), response
                assert probe.call("validate", {"cursor": "Hu Tao ❤"}, "Page")["valid"]
                result["rejectedMalformedInputs"] = len(malformed)
            elif name == "test_target_pointer_ranges":
                for width in (32, 64):
                    last = 2**width - 1
                    reference = {"address": {"addressHex": hex(last)}, "size": 1}
                    assert probe.call("range", reference, f"x{width}") == {"valid": True, "lastAddressHex": hex(last)}
                    assert not probe.call("range", {**reference, "size": 2}, f"x{width}")["valid"]
                    assert not probe.call("range", {"address": {"addressHex": "0x100000000"}, "size": 1}, "x32")["valid"]
                result["targetWidths"] = [32, 64]
            elif name == "test_source_dependencies":
                result.update(check_dependency_sources(binary.parent))
                observed = probe.call("dependencies")
                assert observed["pointerBits"] == (64 if architecture == "x64" else 32)
                assert observed["boostVersion"] == "1_92" and observed["jsonVersion"] == 31200
                assert observed["sqliteVersion"] == "3.53.4" and observed["sqliteValue"] == 42 and observed["sqliteDuplicateError"] == 19
                assert observed["javascriptVersion"] == "0.17.0" and observed["javascriptValue"] == 42
                result["observed"] = observed
            elif name == "test_http_parser":
                requests = [(True, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}'),
                            (True, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n{}'),
                            (False, b'GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-Test: ' + b'x' * 8192 + b'\r\n\r\n')]
                for expected, request in requests:
                    observed = probe.call("http", raw=request)
                    assert observed["valid"] == expected, observed
                    if expected:
                        assert observed["method"] == "POST" and observed["target"] == "/mcp" and observed["body"] == "{}"
                result["requestCases"] = len(requests)
            elif name == "test_result_contracts":
                result.update(check_results(probe, formats))
                fixture = probe.call("result-cases")
                assert len(set(result["typedErrorCodes"])) == 19
                for error in fixture["errors"]:
                    assert validators["DomainError"].is_valid(error) and probe.call("validate", error, "DomainError")["valid"]
            elif name == "test_registry_contracts":
                result.update(check_registry_contracts(probe, registry, tool_validators))
            elif name == "test_legacy_alias_contracts":
                result.update(check_legacy_alias_contracts(probe, registry))
            elif name == "test_native_parity_catalog":
                result.update(check_native_parity_catalog(probe, catalog))
            elif name == "test_pe_file_patch_plans":
                result.update(check_pe_file_patch_plans(probe))
            elif name == "test_new_file_publication":
                result.update(check_new_file_publication(probe))
            elif name == "test_registry_dispatch":
                result.update(check_registry_dispatch(probe, registry, tool_validators))
            elif name == "test_schema_references":
                result.update(check_schema_references(probe, formats))
            elif name == "test_lifecycle_contracts":
                result.update(check_lifecycle_contracts(probe, tool_validators))
            elif name == "test_execution_contracts":
                result.update(check_execution_contracts(probe, registry, tool_validators))
            elif name == "test_inspection_contracts":
                result.update(check_inspection_contracts(probe, registry, tool_validators))
            elif name == "test_memory_contracts":
                result.update(check_memory_contracts(probe, registry, tool_validators))
            elif name == "test_breakpoint_trace_contracts":
                result.update(check_breakpoint_trace_contracts(probe, registry, tool_validators))
            elif name == "test_assembly_file_contracts":
                result.update(check_assembly_file_contracts(probe, registry, tool_validators))
            elif name == "test_module_analysis_contracts":
                result.update(check_module_analysis_contracts(probe, registry, tool_validators))
            elif name == "test_database_settings_contracts":
                result.update(check_database_settings_contracts(probe, registry, tool_validators))
            elif name == "test_provider_ui_contracts":
                result.update(check_provider_ui_contracts(probe, registry, tool_validators))
            elif name == "test_library_script_contracts":
                result.update(check_library_script_contracts(probe, registry, tool_validators))
            elif name == "test_native_library_fault_oracles":
                from library_checks import check_library_oracles
                result.update(check_library_oracles(probe, architecture, parent_token_oracle, file_handle_oracle))
            elif name == "test_job_event_artifact_contracts":
                result.update(check_job_event_artifact_contracts(probe, registry, tool_validators))
            elif name == "test_native_launch_arguments":
                result.update(check_native_launch(probe, architecture))
            elif name == "test_native_component_builds":
                result.update(check_native_components(probe, architecture, validators, catalog))
            elif name == "test_ipc_wire_codec":
                result.update(check_ipc_wire(probe))
        except Exception as error:
            result.update(status="failed", error=str(error))
        result["seconds"] = round(time.monotonic() - started, 3)
        results.append(result)
        print(f"[{result['status'].upper()}] {architecture} {name}", flush=True)
        if result.get("error"):
            print(result["error"], flush=True)
    write_json(Path(output) / "observations.json", probe.observations)
    write_json(Path(output) / "summary.json", {"observedAtUtc": datetime.now(timezone.utc).isoformat(), "binary": file_identity(binary),
               "compiledBuildId": catalog["buildId"], "results": results})
    return results, catalog
