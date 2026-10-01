from datetime import datetime, timezone
import fnmatch
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time
from types import SimpleNamespace

from wi_driver import KERNEL, McpError, OwnedJob, ROOT, compiler_environment, file_identity, process_identity, write_json


CASE_NAMES = ("test_compiled_schema_catalog", "test_contract_boundaries", "test_context_roundtrip",
              "test_bounded_json", "test_target_pointer_ranges", "test_source_dependencies", "test_http_parser",
              "test_result_contracts", "test_registry_contracts", "test_registry_dispatch", "test_schema_references",
              "test_lifecycle_contracts", "test_execution_contracts", "test_inspection_contracts", "test_memory_contracts",
              "test_native_launch_arguments", "test_native_component_builds", "test_ipc_wire_codec")

EXECUTION_TOOLS = ("execution_resume", "execution_pause", "execution_step_into", "execution_step_over", "execution_step_out", "execution_run_to",
                   "execution_skip_instruction", "execution_wait", "threads_list", "threads_select", "threads_suspend", "threads_resume", "threads_context",
                   "exceptions_state", "exceptions_policy_get", "exceptions_policy_set")
INSPECTION_TOOLS = ("registers_read", "registers_write", "expression_evaluate", "expressions_evaluate", "watches_list", "watches_set", "watches_delete",
                    "stack_read", "arguments_read", "pointers_follow", "process_peb", "thread_teb", "seh_chain", "unwind_info", "structures_list", "structures_decode")
MEMORY_TOOLS = ("memory_map", "memory_read", "memory_read_string", "memory_write", "memory_allocate", "memory_free", "memory_protection_set",
                "memory_search_pattern", "memory_search_text", "memory_strings", "memory_dump", "memory_dumpable_regions", "modules_dump", "handles_list", "heaps_list")


def build_contract_fixture(output, architecture):
    build = Path(output) / f"build-{architecture}"
    build.mkdir()
    source = ROOT / "x64dbg"
    environment = compiler_environment(architecture)
    qt = source / ("build64" if architecture == "x64" else "build32") / "_deps/qt5-src/lib/cmake/Qt5"
    configure = ["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                 "-DX64DBG_BUILD_IN_TREE=OFF", "-DX64DBG_BUILD_MCP=ON", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
    if qt.is_dir():
        configure.append(f"-DQt5_DIR={qt}")
    commands = []
    source_paths = [source / "cmake.toml", source / "CMakeLists.txt", *sorted((source / "src/mcp").rglob("*")), *sorted((source / "src/dbg/mcp").rglob("*"))]
    source_inputs = [file_identity(path) for path in source_paths if path.is_file()]
    with (build / "build.log").open("w", encoding="utf-8") as log:
        for command in (configure, ["cmake", "--build", str(build), "--target", "mcp_contract_fixture", "mcp_launch_reference", "mcp_broker", "mcp_connect", "mcp_worker", "--parallel", "6"]):
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
                "sourceInputs": source_inputs, "commands": commands, "binary": file_identity(binary),
                "launchReference": file_identity(build / "wininspect-mcp-launch-reference.exe"),
                "nativeComponents": [file_identity(path) for path in components],
                "buildInputs": file_identity(build / "CMakeCache.txt"),
                "compiledDependencies": [file_identity(path) for path in sorted(build.glob("mcp_*.lib"))],
                "compileCommands": json.loads((build / "compile_commands.json").read_text(encoding="utf-8")),
                "notices": [file_identity(path) for path in sorted((build / "mcp-notices").glob("*.txt"))]}
    for input_file in source_inputs:
        assert file_identity(input_file["path"])["sha256"] == input_file["sha256"], "Build source changed during compilation"
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
                       "processIdentity": identity, "exitCode": process.returncode, "expectedExitCode": expected_exit,
                       "timedOut": timed_out, "stderr": stderr.decode("utf-8", "replace")}
        self.observations.append(observation)
        assert not timed_out, f"Owned contract fixture timed out: {identity}"
        assert process.returncode == expected_exit, observation
        return stdout, stderr, observation


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
    expected.update(EXECUTION_TOOLS + INSPECTION_TOOLS + MEMORY_TOOLS)
    assert registry["operationalTools"] == [] and {tool["name"] for tool in registry["tools"]} == expected
    assert [tool["name"] for tool in registry["tools"]] == sorted(expected)
    for tool in registry["tools"]:
        assert tool["schemaVersion"] == 1 and tool["operational"] is False
        assert tool["completionPredicate"] and tool["nativeSource"] and tool["recovery"] and tool["acceptanceIds"]
        assert tool["annotations"]["readOnlyHint"] == (tool["effects"] == ["inspect"] and not tool["effectConditions"])
        assert tool["executor"] in ("broker", "engine", "gui")
        assert tool["architectureRequirement"] == {"seh_chain": "x32", "unwind_info": "x64"}.get(tool["name"], "any")
        for direction in ("input", "output"):
            schema = tool[f"{direction}Schema"]
            Draft202012Validator.check_schema(schema)
            assert schema["$id"] == f"urn:wininspect:mcp:tool:v1:{tool['name']}:{direction}"
            validators[(tool["name"], direction)] = Draft202012Validator(schema, format_checker=formats)
    return validators


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


def check_tool_family(probe, registry, validators, names, inputs, outputs, extra_inputs=(), extra_outputs=(), expected_effects=None):
    assert set(names) == set(inputs) == set(outputs)
    definitions = {tool["name"]: tool for tool in registry["tools"]}
    input_cases = []
    for name, value in inputs.items():
        input_cases.extend(((True, name, value), (False, name, {**value, "unknown": "reject"}),
                            (False, name, {key: item for key, item in value.items() if key != "instanceId"})))
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
        assert definition["availability"] == "planned" and definition["executor"] == "engine" and not definition["effectConditions"]
        rejected = probe.call("call", value, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability", rejected
        effects = probe.call("effects", value, name)
        assert effects["valid"] and effects["effects"] == expected_effects[name]
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
        environment = ctypes.create_string_buffer(environment_bytes)
        create_suspended = 4
        extended_startup = 0x00080000
        create_unicode_environment = 0x400
        flags = subprocess.CREATE_NO_WINDOW | create_unicode_environment | create_suspended | extended_startup
        if not KERNEL.CreateProcessW(str(binary), command, None, None, True, flags, environment, plan["cwd"], ctypes.byref(startup), ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = SimpleNamespace(pid=information.pid, _handle=information.process)
        identity = process_identity(process)
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
        assert observed["pid"] == identity["pid"] and observed["pointerBits"] == expected_bits
        return {"processIdentity": identity, "exitCode": exit_code.value, "binary": file_identity(binary), "output": file_identity(output), "observed": observed}
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


def parent_token_oracle():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    KERNEL.GetCurrentProcess.restype = wintypes.HANDLE
    KERNEL.LocalFree.argtypes = [ctypes.c_void_p]
    KERNEL.LocalFree.restype = ctypes.c_void_p
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(KERNEL.GetCurrentProcess(), 8, ctypes.byref(token)):
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


def check_native_components(probe, architecture, validators, catalog):
    expected_token, token_queries = parent_token_oracle()
    observations = []
    def verify(information, identity, binary, component):
        assert set(information) == {"schemaVersion", "component", "buildId", "wireVersion", "process", "declaredToolCount", "implementedTransports", "operationalTools"}
        assert information["schemaVersion"] == information["wireVersion"] == 1 and information["component"] == component
        assert information["buildId"] == catalog["buildId"] and information["declaredToolCount"] == len(catalog["tools"])
        assert information["implementedTransports"] == information["operationalTools"] == []
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
