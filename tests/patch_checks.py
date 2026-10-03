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
                    "gPatchPhase", "gPatchPid", "gPatchThread", "gPatchImageBase", "gPatchValues", "gPatchMarkers", "gPatchCompleted", "gPatchVerified", "gPatchWriteFailureRegion"}
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
        section = sections[0]
        if value % 0x1000 or section.Name.rstrip(b"\0") != b"PCAN" or section.VirtualAddress != value or section.Misc_VirtualSize != 6:
            raise McpError("Patch reference function does not occupy its isolated executable page")
        if any(exports[name] // 0x1000 == value // 0x1000 for name in ("PatchCall", "PatchAfterCall", "PatchReady", "PatchFinish")):
            raise McpError("Patch reference caller or barriers share its execute-trapped page")
        if image.get_data(exports["gPatchWriteFailureRegion"], 8 if machine == 0x8664 else 4) != bytes(8 if machine == 0x8664 else 4):
            raise McpError("Patch reference failure allocation is not initialized independently at runtime")
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


def check_patch_output(receipt, facts, mode, value=7):
    assert value in (7, 42) and (mode == 2 or value == 7), "Unknown independently requested patch outcome"
    count = 3 if mode == 1 else 1
    assert receipt["exitCode"] == count * value and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Normal patch reference did not complete with its actual executed sum"
    lines = receipt["stdout"].splitlines()
    assert len(lines) == 9 + count * 2 and all(line.count("=") == 1 for line in lines), "Patch summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    assert len(observed) == len(lines), "Patch summary fields repeat"
    base = int(observed["imageBase"], 16)
    assert base > 0 and base % 0x10000 == 0 and base + facts["size"] < 1 << (64 if facts["machine"] == 0x8664 else 32), "Patch target has an invalid actual image base"
    expected = {"mode": str(mode), "mutation": "0", "phase": "4", "pid": str(receipt["processIdentity"]["pid"]),
                "thread": str(receipt["startupThread"]), "imageBase": f"{base:x}", "completed": str(count), "verified": "1", "sum": str(count * value)}
    for index in range(count):
        expected.update({f"value{index}": str(value), f"marker{index}": "original" if value == 7 else "patched"})
    assert observed == expected, f"Actual normal patch outcomes differ: {observed}"
    return observed


def check_patch_restore(receipt, facts, image_base):
    output = receipt["stdout"]
    done = re.findall(r"PATCH_RESTORE_DONE allocation=([0-9a-f]+) scenarios=(\d+) reserved=([0-9a-f]+) paused=([01])", output)
    assert len(done) == 1 and done[0][1:] == ("2", "2000", "1"), "Restore reference lacks its final paused reservation state"
    allocation = int(done[0][0], 16)
    assert allocation > 0 and allocation % 0x1000 == 0 and allocation + 0x2000 < 1 << (64 if facts["machine"] == 0x8664 else 32)
    assert not image_base <= allocation < image_base + facts["size"], "Restore allocation overlaps its executable image"
    entries = re.findall(r"PATCH_RESTORE_BYTE scenario=(\d+) phase=(\w+) index=(\d+) address=([0-9a-f]+) allocation=([0-9a-f]+) tracked=([01]) old=([0-9a-f]{2}) new=([0-9a-f]{2}) state=([0-9a-f]+) protection=([0-9a-f]+) logicalRead=([01]) logical=([0-9a-f]{2}) rawRead=([01]) raw=([0-9a-f]{2}) read=(\d+) error=(\d+) paused=([01])", output)
    counts = re.findall(r"PATCH_RESTORE_COUNT scenario=(\d+) phase=(\w+) tracked=(\d+) total=(\d+) paused=([01])", output)
    calls = re.findall(r"PATCH_RESTORE_CALL scenario=(\d+) phase=(\w+) api=(\w+) address=([0-9a-f]+) size=(\d+) result=(\d+) paused=([01])", output)
    pages = re.findall(r"PATCH_RESTORE_PAGE scenario=(\d+) page=(\d+) address=([0-9a-f]+) read=(\d+) content=([0-9a-f]{2}) state=([0-9a-f]+) protection=([0-9a-f]+)", output)
    assert len(entries) == 24 and len(counts) == 8 and len(calls) == 4 and len(pages) == 3, "Restore phase evidence is incomplete or duplicated"
    expected_entries, expected_counts, expected_calls, expected_pages, stages = [], [], [], [], []
    for scenario, offset, replacements in [(0, 0x80, [0x5b, 0x5c]), (1, 0xffe, [0x5b, 0x5c, 0x5d, 0x5e])]:
        size, address = len(replacements), allocation + offset
        full, unresolved = (1 << size) - 1, 3 if scenario == 0 else 12
        for phase, tracked_mask, changed_mask, reserved_mask in [("initial", full, full, 0), ("failed", unresolved, 0, unresolved), ("repaired", unresolved, unresolved, 0), ("restored", 0, 0, 0)]:
            total = tracked_mask.bit_count()
            expected_counts.append((str(scenario), phase, str(total), str(total), "1"))
            for index, replacement in enumerate(replacements):
                tracked, reserved = bool(tracked_mask & (1 << index)), bool(reserved_mask & (1 << index))
                actual = replacement if changed_mask & (1 << index) else 0x5a
                row = entries[len(expected_entries)]
                expected_entries.append((str(scenario), phase, str(index), f"{address + index:x}", f"{allocation:x}", str(int(tracked)),
                                         "5a" if tracked else "00", f"{replacement:02x}" if tracked else "00", "2000" if reserved else "1000", row[9] if reserved else "20",
                                         "0" if reserved else "1", "00" if reserved else f"{actual:02x}", "0" if reserved else "1", "00" if reserved else f"{actual:02x}",
                                         "0" if reserved else "1", "299" if reserved else "0", "1"))
        expected_calls.extend([(str(scenario), "failure", "byte" if scenario == 0 else "range_void", f"{address:x}", str(size), "0", "1"),
                               (str(scenario), "retry", "byte" if scenario == 0 else "range_void", f"{address:x}", str(size), "3" if scenario == 0 else "0", "1")])
        expected_pages.extend((str(scenario), str(page), f"{allocation + page * 0x1000:x}", "4096", "5a", "1000", "20") for page in range(scenario + 1))
        stages.extend([f"PATCH_RESTORE_BYTE scenario={scenario} phase=initial index=0 ", f"PATCH_RESTORE_COUNT scenario={scenario} phase=initial ",
                       f"PATCH_RESTORE_CALL scenario={scenario} phase=failure ", f"PATCH_RESTORE_BYTE scenario={scenario} phase=failed index=0 ", f"PATCH_RESTORE_COUNT scenario={scenario} phase=failed ",
                       f"PATCH_RESTORE_BYTE scenario={scenario} phase=repaired index=0 ", f"PATCH_RESTORE_COUNT scenario={scenario} phase=repaired ", f"PATCH_RESTORE_CALL scenario={scenario} phase=retry ",
                       f"PATCH_RESTORE_BYTE scenario={scenario} phase=restored index=0 ", f"PATCH_RESTORE_COUNT scenario={scenario} phase=restored ", f"PATCH_RESTORE_PAGE scenario={scenario} page=0 "])
    assert entries == expected_entries, "Restore byte states, originals, installed bytes or native readback differ"
    assert counts == expected_counts and calls == expected_calls and pages == expected_pages, "Restore loses unresolved records or retry/page verification"
    positions = [output.index(stage) for stage in ["PATCH_LAYOUT ", *stages, "PATCH_RESTORE_DONE ", "PATCH_HIT index=0 "]]
    assert positions == sorted(positions), "Restore phases do not precede actual execution in order"
    return {"allocation": hex(allocation), "scenarios": 2, "preservedFailedBytes": 4, "independentlyVerifiedPageBytes": 12288, "partialRangeRestoration": True}


def check_patch_transactions(receipt, facts, image_base, code_address, pid, creation):
    output = receipt["stdout"]
    done = re.findall(r"PATCH_TX_DONE allocation=([0-9a-f]+) scenarios=9 paused=1 epoch=(\d+)", output)
    code_epochs = re.findall(r"PATCH_TX_RESULT name=code operation=(apply|undo) .*? epoch=(\d+) paused=1", output)
    assert len(done) == 1 and [row[0] for row in code_epochs] == ["apply", "undo"], "Transaction contexts are missing or duplicated"
    allocation, epoch = int(done[0][0], 16), int(done[0][1])
    apply_epoch, undo_epoch = [int(row[1]) for row in code_epochs]
    assert 0 < epoch < apply_epoch < undo_epoch < 1 << 64, "Actual apply and undo must use later distinct paused contexts"
    assert allocation > 0 and allocation % 0x1000 == 0 and allocation + 0x2000 < 1 << (64 if facts["machine"] == 0x8664 else 32)
    assert allocation + 0x2000 <= image_base or image_base + facts["size"] <= allocation, "Private transaction allocation overlaps its source image"
    first, second = allocation + 0x80, allocation + 0x100
    expected = []

    def result(name, operation, outcome, ranges, context=epoch):
        status, error, failure, resume, patches, restores, flushes = outcome
        expected.append(f"PATCH_TX_RESULT name={name} operation={operation} status={status} error={error} failure={failure} resume={resume} ranges=2 patches={patches} restores={restores} flushes={flushes} pid={pid} creation={creation} epoch={context} paused=1")
        for index, (address, size, state, attempted, restored, observed, records) in enumerate(ranges):
            expected.append(f"PATCH_TX_RANGE name={name} operation={operation} index={index} address={address:x} size={size} state={state} attempted={attempted} restored={restored} observed={observed} records={records}")

    def private_ranges(state, attempted, restored, first_bytes, first_records, second_bytes="5a5a", second_records="--------"):
        return [(first, 2, state, attempted, restored, first_bytes, first_records), (second, 2, state, attempted, restored, second_bytes, second_records)]

    def bytes_observed(name, value="5a5a", records="--------", total=0, other=False):
        expected.append(f"PATCH_TX_BYTES name={name} address={first:x} logical={value} raw={value} records={records} total={total} state=1000 protection=20 paused=1")
        other_value, other_records = ("5d5e", "5a5d5a5e") if other else ("5a5a", "--------")
        expected.append(f"PATCH_TX_OTHER name={name} address={second:x} logical={other_value} raw={other_value} records={other_records} paused=1")

    planned = private_ranges(0, 0, 0, "unknown", "unknown", "unknown", "unknown")
    preflight = private_ranges(0, 0, 0, "5a5a", "--------")
    preflight[1] = (second, 2, 3, 0, 0, "5a5a", "--------")
    result("preflight", "apply", (0, 4, 1, 1, 0, 0, 0), preflight)
    bytes_observed("preflight")
    for name, location, outcome in [("overlap", first + 1, (0, 1, -1, 1, 0, 0, 0)), ("overflow", (1 << 64) - 1, (0, 1, -1, 1, 0, 0, 0)), ("stale", second, (0, 2, 0, 1, 0, 0, 0))]:
        rejected = [planned[0], (location, *planned[1][1:])]
        result(name, "apply", outcome, rejected)
        bytes_observed(name)
    restored = private_ranges(2, 1, 1, "5a5a", "--------")
    for name, fault, native_error, outcome in [("rollback", 1, 5, (2, 6, 1, 1, 2, 1, 3)), ("rollback_conflict", 3, 5, (3, 6, 1, 0, 2, 0, 2)), ("partial", 2, 998, (3, 6, 1, 0, 2, 0, 1))]:
        expected.append(f"PATCH_TX_NATIVE fault={fault} pid={pid} address={second:x} requested=2 written=0 success=0 error={native_error} paused=1")
        ranges = restored if fault == 1 else [(first, 2, 3, 1, 0, "5f5c", "5a5b5a5c"), restored[1]] if fault == 3 else private_ranges(4, 1, 0, "unknown", "unknown", "unknown", "unknown")
        result(name, "apply", outcome, ranges)
        if fault == 2:
            expected.append(f"PATCH_TX_PARTIAL allocation={allocation:x} address={first:x} state=2000 read=0 count=0 error=299 old=5a new=5b paused=1")
        elif fault == 3:
            bytes_observed(name, "5f5c", "5a5b5a5c", 2)
        else:
            bytes_observed(name)
        bytes_observed("recovered")
    installed = private_ranges(1, 1, 0, "5b5c", "5a5b5a5c", "5d5e", "5a5d5a5e")
    for name in ("undo_conflict", "amendment"):
        result(name, "apply", (1, 0, -1, 1, 2, 0, 2), installed)
        bytes_observed(name, "5b5c", "5a5b5a5c", 4, True)
        if name == "undo_conflict":
            result(name, "conflict", (5, 4, 0, 0, 2, 0, 2), [(first, 2, 3, 1, 0, "5f5c", "5a5b5a5c"), installed[1]])
            bytes_observed(name, "5f5c", "5a5b5a5c", 4, True)
        previous_bytes, previous_records = ("5958", "5a595a58") if name == "amendment" else ("5a5a", "--------")
        result(name, "undo", (4, 0, -1, 1, 2, 2, 4), private_ranges(2, 1, 1, previous_bytes, previous_records))
        bytes_observed(name, previous_bytes, previous_records, 2 if name == "amendment" else 0)
    bytes_observed("done")
    expected.extend([f"PATCH_TX_PAGE allocation={allocation:x} read=4096 content=5a reserved=2000 paused=1", f"PATCH_TX_DONE allocation={allocation:x} scenarios=9 paused=1 epoch={epoch}"])
    result("code", "apply", (1, 0, -1, 1, 2, 0, 2), [(code_address, 4, 1, 1, 0, "66b82a00", "b86607b8002a----"), (code_address + 4, 2, 1, 1, 0, "90c3", "0090----")], apply_epoch)
    result("code", "undo", (4, 0, -1, 1, 2, 2, 4), [(code_address, 4, 2, 1, 1, "b8070000", "----------------"), (code_address + 4, 2, 2, 1, 1, "00c3", "--------")], undo_epoch)
    actual = [line for line in output.splitlines() if line.startswith("PATCH_TX")]
    assert actual == expected, "Actual transaction identities, addresses, bytes, tracking, native effects, restoration or resume policy differ"
    stages = ["PATCH_LAYOUT ", "PATCH_TX_RESULT name=preflight ", "PATCH_TX_DONE ", "PATCH_HIT index=0 ", "PATCH_TX_RESULT name=code operation=apply ", "PATCH_HIT index=1 ", "PATCH_TX_RESULT name=code operation=undo ", "PATCH_HIT index=2 ", "PATCH_EXIT "]
    positions = [output.index(stage) for stage in stages]
    assert positions == sorted(positions), "Transaction code apply and undo do not precede their genuine execution outcomes"
    return {"allocation": hex(allocation), "scenarios": 9, "resultCount": 14, "privateEpoch": epoch, "applyEpoch": apply_epoch, "undoEpoch": undo_epoch,
            "independentlyVerifiedPageBytes": 4096, "compareBeforeUndo": True, "oldestOriginalPreserved": True, "partialFailureResumeAllowed": False}


def check_patch_reference(receipt, facts, kind="software", engine="TitanEngine", file_exports=False, single_shot=False, hardware_slot=0, restore_failure=False, transaction=False):
    assert kind in ("software", "hardware", "memory") and engine in ("TitanEngine", "GleeBug"), "Unknown patch reference variant"
    assert not file_exports or kind == "software", "File reference requires its declared software breakpoint"
    assert not single_shot or kind == "hardware", "Single-shot reference requires its declared hardware breakpoint"
    assert not restore_failure or (kind == "software" and not file_exports and not single_shot), "Restore failure requires its declared software reference"
    assert not transaction or (kind == "software" and not file_exports and not single_shot and not restore_failure), "Transaction requires its declared software reference"
    assert hardware_slot in range(4), "Unknown independently requested hardware slot"
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
    expected_snapshots = "0" * 5 + "1" * 20 + "00" if file_exports else "0000001100" if kind == "memory" else "000001100"
    assert [entry[0] for entry in snapshots] == list(expected_snapshots), "Patch bytes omit or reorder pure encoding, failed writes, apply or restoration"
    for patched, trapped, location, logical, raw in snapshots:
        expected = facts["patched"] if patched == "1" else facts["original"]
        assert trapped == ("1" if kind == "software" else "0") and int(location, 16) == address and logical == expected and raw == ("cc" + expected[2:] if kind == "software" else expected), "Logical original, selected trap or actual installed opcode differs"
    breakpoint_type = {"software": 1, "hardware": 2, "memory": 4}[kind]
    breakpoints = re.findall(r"PATCH_BREAKPOINT type=(\d+) address=([0-9a-f]+) typeEx=(\d+) enabled=([01]) active=([01]) singleshoot=([01]) hits=(\d+) protection=([0-9a-f]+) originalProtection=([0-9a-f]+)", output)
    expected_hits = [0, 1, 1, 1, 1, 1, 2, 2, 3] if kind != "memory" else [0, 1, 1, 1, 1, 1, 1, 2, 2, 3]
    if file_exports:
        expected_hits = [0] + [1] * 23 + [2, 2, 3]
    if single_shot:
        expected_hits = [0]
    assert len(breakpoints) == (1 if single_shot else len(snapshots)) and [int(item[6]) for item in breakpoints] == expected_hits, "Breakpoint metadata omits its exact stop sequence"
    protection = 2 if kind == "memory" else 0x20
    for observed_type, location, extended, enabled, active, singleshoot, _, actual, original in breakpoints:
        assert int(observed_type) == breakpoint_type and int(location, 16) == address and int(extended) == (2 if kind == "hardware" else 3 if kind == "memory" else 0), "Selected breakpoint type or exact execute range differs"
        assert (enabled, active, singleshoot) == ("1", "1", str(int(single_shot))) and int(actual, 16) == protection and int(original, 16) == 0x20, "Patch write or restore loses actual breakpoint protection"
    hardware = re.findall(r"PATCH_HARDWARE slot=(\d+) address=([0-9a-f]+) dr7=([0-9a-f]+)", output)
    assert len(hardware) == (1 if single_shot else len(snapshots) if kind == "hardware" else 0), "Hardware reference omits or invents actual OS debug-register observations"
    for slot, location, dr7 in hardware:
        slot, dr7 = int(slot), int(dr7, 16)
        assert 0 <= slot < 4 and int(location, 16) == address and dr7 & (3 << (slot * 2)) and ((dr7 >> (16 + slot * 4)) & 15) == 0, "Hardware slot has the wrong address, enable or access/size bits"
    steps = re.findall(r"PATCH_STEP index=(\d+) hits=(\d+) nativeIP=([0-9a-f]+) nativeAX=([0-9a-f]+) osRead=([01]) osIP=([0-9a-f]+) osAX=([0-9a-f]+) flags=([0-9a-f]+) dr6=([0-9a-f]+) dr7=([0-9a-f]+)", output)
    step_ips = [address + 5, base + facts["exports"]["PatchAfterCall"], address + 4, address + 5, base + facts["exports"]["PatchAfterCall"], address + 5, base + facts["exports"]["PatchAfterCall"]]
    assert len(steps) == 7, "Actual CPU step evidence is missing or repeats"
    for index, (entry, expected_ip, expected_ax, expected_hit) in enumerate(zip(steps, step_ips, [7, 7, 42, 42, 42, 7, 7], [1, 1, 2, 2, 2, 3, 3])):
        sequence, hit, native_ip, native_ax, read, os_ip, os_ax, _, _, _ = entry
        assert int(sequence) == index and int(hit) == expected_hit and read == "1" and int(native_ip, 16) == int(os_ip, 16) == expected_ip and int(native_ax, 16) == int(os_ax, 16) == expected_ax, "Native or independent OS context reports a step before its actual instruction outcome"
    arms = re.findall(r"PATCH_ARM index=(\d+) address=([0-9a-f]+) slot=(\d+) dr7=([0-9a-f]+) pid=(\d+) thread=(\d+) creation=(\d+) singleshoot=([01]) hits=(\d+)", output)
    single_states = re.findall(r"PATCH_SINGLESHOT address=([0-9a-f]+) slot=(\d+) actualSlot=([0-9a-f]+) dr7=([0-9a-f]+) present=([01]) armed=([01]) hits=(\d+) arms=(\d+)", output)
    single_steps = re.findall(r"PATCH_SINGLESTEP index=(\d+) present=([01]) dr7=([0-9a-f]+)", output)
    if single_shot:
        assert len(arms) == 3 and len(single_states) == 12 and len(single_steps) == 7, "Single-shot rearming, removal or actual CPU-step evidence is missing"
        arm_slots = []
        for index, arm in enumerate(arms):
            sequence, location, slot, dr7, arm_pid, arm_thread, thread_creation, singleshoot, arm_hits = arm
            slot, dr7 = int(slot), int(dr7, 16)
            assert sequence == str(index) and int(location, 16) == address and slot == hardware_slot and dr7 & (3 << (slot * 2)) and ((dr7 >> (16 + slot * 4)) & 15) == 0
            assert (arm_pid, arm_thread, singleshoot, arm_hits) == (pid, thread, "1", "0") and int(thread_creation) > int(creation)
            arm_slots.append(slot)
        assert len({arm[6] for arm in arms}) == 1, "Rearming changed actual target thread generation"
        expected_single_hits = [0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3]
        for index, (state, expected_hit) in enumerate(zip(single_states, expected_single_hits)):
            location, slot, actual_slot, dr7, present, armed, single_hits, arm_count = state
            expected_arms = max(expected_hit, 1)
            assert int(location, 16) == address and int(slot) == arm_slots[expected_arms - 1] and int(single_hits) == expected_hit and int(arm_count) == expected_arms
            assert present == armed == str(int(index == 0))
            if index == 0:
                assert int(actual_slot, 16) == address and int(dr7, 16) & (3 << (int(slot) * 2))
                assert (slot, actual_slot, dr7) == hardware[0], "Initial single-shot state differs from the independent OS hardware snapshot"
            else:
                assert int(dr7, 16) & 0xff == 0, "Consumed single-shot retains an enabled OS hardware slot"
        for index, (single_step, step) in enumerate(zip(single_steps, steps)):
            assert single_step == (str(index), "0", step[-1]) and int(single_step[-1], 16) & 0xff == 0
        positions = lambda prefix: [match.start() for match in re.finditer(re.escape(prefix), output)]
        arm_positions, hit_positions = positions("PATCH_ARM "), positions("PATCH_HIT ")
        assert len(arm_positions) == len(hit_positions) == 3, "Single-shot arm/hit sequence is incomplete"
        for index in range(3):
            assert arm_positions[index] < hit_positions[index] and (index == 0 or hit_positions[index - 1] < arm_positions[index])
        step_positions, single_step_positions = positions("PATCH_STEP "), positions("PATCH_SINGLESTEP ")
        assert len(step_positions) == len(single_step_positions) == 7
        for index in range(7):
            assert hit_positions[[1, 1, 2, 2, 2, 3, 3][index] - 1] < step_positions[index] < single_step_positions[index]
            assert single_step_positions[index] < (step_positions[index + 1] if index < 6 else positions("PATCH_RESULT ")[0])
    else:
        assert not arms and not single_states and not single_steps, "Unexpected single-shot evidence"
    failures = re.findall(r"PATCH_WRITE_FAILURE engine=([01]) address=([0-9a-f]+) requested=(\d+) written=(\d+) success=([01]) before=([0-9a-f]+) after=([0-9a-f]+) reserved=([0-9a-f]+) error=(\d+) softwareOffset=(\d+) softwareLogical=([0-9a-f]+) softwareRaw=([0-9a-f]+) prefix=([0-9a-f]+) remainder=([0-9a-f]+)", output)
    assert len(failures) == (1 if kind == "memory" else 0), "Actual failed-write restoration control is missing or unexpected"
    if failures:
        selected, allocation, requested, written, success, before, after, reserved, error, offset, logical, raw, prefix, remainder = failures[0]
        allocation = int(allocation, 16)
        assert int(selected) == (0 if engine == "TitanEngine" else 1) and allocation > 0 and allocation % 0x1000 == 0 and not base <= allocation < base + facts["size"], "Failed-write allocation or actual engine identity differs"
        assert requested == "4097" and 0 <= int(written) <= 4096 and success == "0" and before == after == "2" and reserved == "2000" and 0 <= int(error) < 1 << 32, "Failed raw write loses the actual partial count or restored memory trap"
        assert engine != "GleeBug" or written == "4096", "GleeBug did not execute the complete committed prefix before rejecting the reserved tail"
        expected_byte = "5b" if int(written) > 16 else "5a"
        assert (offset, logical, raw, prefix, remainder) == ("16", expected_byte, "cc", "5b", "5a"), "Software breakpoint cache or raw trap differs from the independently verified changed prefix"
        restored = re.findall(r"PATCH_WRITE_RESTORE address=([0-9a-f]+) written=(\d+) protection=([0-9a-f]+) logical=([0-9a-f]+) raw=([0-9a-f]+)", output)
        assert restored == [(f"{allocation:x}", written, "20", expected_byte, expected_byte)], "Clearing both breakpoints does not restore actual prefix bytes and original page protection"
    else:
        assert "PATCH_WRITE_RESTORE " not in output, "Unexpected failure allocation restoration evidence"
    branches = re.findall(r"PATCH_BRANCH origin=([0-9a-f]+) destination=([0-9a-f]+) displacement=([0-9a-f]+)", output)
    assert [(int(origin, 16), int(destination, 16), int(displacement, 16)) for origin, destination, displacement in branches] == [
        (address, address + 0x1000, 0xffb), (address + 0x20, address + 0x1000, 0xfdb)], "Pure branch encoding does not bind to both actual origins"
    assembly = re.findall(r"PATCH_ASSEMBLY origin=([0-9a-f]+) instruction=mov_ax_0x2a encoded=66b82a00 fill=90 invalidRejected=1 oversizedTextRejected=1 oversizedHasError=([01])", output)
    assert len(assembly) == 1 and int(assembly[0][0], 16) == address, "Requested assembly, fill and nonmutation rejections are missing"
    records = re.findall(r"PATCH_RECORD address=([0-9a-f]+) old=([0-9a-f]{2}) new=([0-9a-f]{2}) module=(\S+)", output)
    original, patched = bytes.fromhex(facts["original"]), bytes.fromhex(facts["patched"])
    expected_records = [(address + offset, original[offset], patched[offset], "patch_canary.exe") for offset in facts["changedOffsets"]]
    assert [(int(location, 16), int(old, 16), int(new, 16), module) for location, old, new, module in records] == expected_records * (20 if file_exports else 2), "Patch lookup loses the original bytes, changed bytes or exact tracked span"
    hits = re.findall(r"PATCH_HIT index=(\d+) address=([0-9a-f]+) pid=(\d+) thread=(\d+) type=(\d+)", output)
    assert hits == [(str(index), f"{address:x}", pid, thread, str(breakpoint_type)) for index in range(3)], "Actual selected breakpoint callbacks differ from the three source-bound calls"
    results = re.findall(r"PATCH_RESULT values=(\d+)/(\d+)/(\d+) markers=(\w+)/(\w+)/(\w+) completed=(\d+) verified=(\d+)", output)
    assert results == [("7", "42", "7", "original", "patched", "original", "3", "1")], "Actual target outcomes do not prove changed and restored execution"
    exits = re.findall(r"PATCH_EXIT code=(\d+) observed=([01]) debugging=([01])", output)
    assert exits == [("56", "1", "0")], "Patch target exit event was not actually observed after termination"
    restore = check_patch_restore(receipt, facts, base) if restore_failure else None
    assert restore_failure or "PATCH_RESTORE_" not in output, "Unexpected restoration reference evidence"
    transactions = check_patch_transactions(receipt, facts, base, address, pid, creation) if transaction else None
    assert transaction or "PATCH_TX" not in output, "Unexpected transaction reference evidence"
    return {"targetIdentity": {"pid": int(pid), "thread": int(thread), "creationTime": creation, "imageBase": hex(base)}, "origin": hex(address),
            "values": [7, 42, 7], "markers": ["original", "patched", "original"], "exitCode": 56,
            "original": facts["original"], "patched": facts["patched"], "changedOffsets": facts["changedOffsets"], "breakpointKind": kind,
            "pageProtection": hex(protection), "cpuStepCount": len(steps), "partialFailedWrite": {"written": int(failures[0][3]), "requested": 4097} if failures else None,
            "oversizedNativeErrorPresent": assembly[0][1] == "1", "singleShot": single_shot, "hardwareSlot": hardware_slot if single_shot else None, "restoreFailure": restore, "transaction": transactions}


def check_patch_negative_controls(receipt, facts, kind="software", engine="TitanEngine", file_exports=False, single_shot=False, hardware_slot=0, restore_failure=False, transaction=False):
    output = receipt["stdout"]
    changes = [("wrong_executed_value", "values=7/42/7", "values=7/43/7"), ("wrong_marker", "markers=original/patched/original", "markers=original/original/original"),
               ("wrong_original_byte", "old=b8 new=66", "old=90 new=66"), ("wrong_raw_opcode", "raw=cc07000000c3" if kind == "software" else "raw=b807000000c3", "raw=9007000000c3"),
               ("wrong_installed_byte", "logical=66b82a0090c3", "logical=66b82b0090c3"), ("wrong_branch_origin", "displacement=fdb", "displacement=ffb"),
               ("missing_hit", "PATCH_HIT index=1", "IGNORED_HIT index=1"), ("missing_restore", "values=7/42/7", "values=7/42/42"),
               ("wrong_exit_event", "PATCH_EXIT code=56", "PATCH_EXIT code=55"), ("missing_rejection", "oversizedTextRejected=1", "oversizedTextRejected=0"),
               ("missing_cpu_step", "PATCH_STEP index=0", "IGNORED_STEP index=0"), ("missing_actual_context", "osRead=1", "osRead=0"),
               ("lost_breakpoint", "enabled=1 active=1", "enabled=0 active=1"), ("lost_page_protection", "originalProtection=20", "originalProtection=4")]
    if kind == "hardware":
        changes.append(("wrong_hardware_slot", f"PATCH_HARDWARE slot={hardware_slot}", "PATCH_HARDWARE slot=4"))
    if single_shot:
        changes.extend((("missing_rearm", "PATCH_ARM index=1", "IGNORED_ARM index=1"), ("missing_single_removal", "present=0 armed=0", "present=1 armed=0"),
                        ("lost_single_setting", "singleshoot=1 hits=0", "singleshoot=0 hits=0"), ("missing_single_step", "PATCH_SINGLESTEP index=0", "IGNORED_SINGLESTEP index=0")))
    if kind == "memory":
        changes.extend((("wrong_failed_write", "requested=4097", "requested=4096"), ("lost_failure_restoration", "before=2 after=2", "before=2 after=20"),
                        ("lost_partial_software_trap", "softwareRaw=cc", "softwareRaw=5a"), ("lost_partial_cache", "softwareLogical=" + ("5b" if engine == "GleeBug" else "5a"), "softwareLogical=cc"),
                        ("missing_overlap_clear", "PATCH_WRITE_RESTORE ", "IGNORED_WRITE_RESTORE ")))
    if restore_failure:
        changes.extend([("false_restore_success", "phase=failure api=byte", "phase=retry api=byte"), ("lost_restore_record", "phase=failed index=0", "phase=restored index=0"),
                        ("missing_native_retry", "PATCH_RESTORE_CALL scenario=1 phase=retry", "IGNORED_RESTORE_CALL scenario=1 phase=retry"), ("unverified_full_page", "read=4096 content=5a", "read=4095 content=5a")])
    if transaction:
        changes.extend([("false_rollback_success", "name=partial operation=apply status=3", "name=partial operation=apply status=2"),
                        ("false_resume_permission", "status=3 error=6 failure=1 resume=0", "status=3 error=6 failure=1 resume=1"),
                        ("lost_manual_change", "observed=5f5c", "observed=5b5c"), ("lost_oldest_original", "records=5a595a58", "records=5b595c58"),
                        ("missing_second_native_range", "PATCH_TX_OTHER ", "IGNORED_TX_OTHER "), ("false_native_write_count", "requested=2 written=0", "requested=2 written=2"),
                        ("unverified_transaction_page", "read=4096 content=5a", "read=4095 content=5a"), ("missing_transaction_undo", "name=code operation=undo", "name=code operation=apply")])
    controls = []
    for name, old, new in changes:
        assert old in output, f"Patch negative control has no predicate: {name}"
        controls.append((name, {**receipt, "stdout": output.replace(old, new, 1)}))
    controls.extend((name, {**receipt, **changed}) for name, changed in (("wrong_debugger_exit", {"exitCode": 1}), ("missing_terminal", {"terminalObserved": False})))
    observed = []
    for name, candidate in controls:
        try:
            check_patch_reference(candidate, facts, kind, engine, file_exports, single_shot, hardware_slot, restore_failure, transaction)
        except (AssertionError, ValueError, KeyError) as error:
            observed.append({"name": name, "status": "rejected", "error": str(error), "targetExecuted": False})
        else:
            raise AssertionError(f"Patch negative control was admitted: {name}")
    return observed


def patch_reference_script(text, single_shot=False, hardware_slot=0):
    assert hardware_slot in range(4)
    if not single_shot:
        return text
    placeholders = [f"patch_canary:PatchValue+0x{0x100 + index * 0x10:x}" for index in range(hardware_slot)]
    arming = "\n".join([*(f"bph {address},x,1" for address in placeholders), "bph patch_canary:PatchValue,x,1",
                        "SetHardwareBreakpointSingleshoot patch_canary:PatchValue,1", *(f"bphc {address}" for address in placeholders), "patchsinglearm"])
    assert text.count("patchselect 2") == 1 and text.count("bph patch_canary:PatchValue,x,1") == 1
    text = text.replace("patchselect 2", "patchselect 2,ss").replace("bph patch_canary:PatchValue,x,1", arming)
    for index in (1, 2):
        original = f"run\npatchhit {index}"
        assert text.count(original) == 1
        text = text.replace(original, arming + "\n" + original)
    return text


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
    required = [runtime / "headless.exe", plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"]
    assert all(path.is_file() for path in required), "Native patch runtime is incomplete"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    child.pop("WININSPECT_TEST_PATCH_MODE", None)
    observations = []
    for engine in engines:
        for kind, single_shot, hardware_slot, restore_failure, transaction in (("software", False, 0, False, False), ("hardware", False, 0, False, False), ("memory", False, 0, False, False), *(("hardware", True, slot, False, False) for slot in range(4)), ("software", False, 0, True, False), ("software", False, 0, False, True)):
            source = plugin.parent / ("test.txt" if kind == "software" else f"test.{kind}.txt")
            assert source.is_file(), "Native patch variant script is missing"
            scope = environment.root / "patch" / engine / ("software-transaction" if transaction else "software-restore" if restore_failure else f"hardware-single-{hardware_slot}" if single_shot else kind)
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            engine_id = 0 if engine == "TitanEngine" else 1
            engine_path = runtime / ("TitanEngine.dll" if engine_id == 0 else "GleeBug/TitanEngine.dll")
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
            script = scope / "reference.txt"
            text = patch_reference_script(source.read_text(encoding="utf-8"), single_shot, hardware_slot)
            if restore_failure or transaction:
                assert text.count("patchprepare\n") == 1
                text = text.replace("patchprepare\n", "patchprepare\n" + ("patchtransactionchecks\n" if transaction else "patchrestorefailure\n"))
            assert text.count("init tests/patch_canary.exe") == 1, "Patch reference script template differs"
            script.write_text(text.replace("init tests/patch_canary.exe", f'init "{binary}"'), encoding="utf-8", newline="\n")
            receipt = run_owned([str(required[0]), "-testing", "-userdir", str(profile), "-plugin", str(plugin), "-cf", str(script)], child, timeout,
                                required_modules=[*required, engine_path])
            write_json(scope / "receipt.json", receipt)
            reference = check_patch_reference(receipt, facts, kind, engine, single_shot=single_shot, hardware_slot=hardware_slot, restore_failure=restore_failure, transaction=transaction)
            assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Patch reference loaded an external MCP dependency"
            controls = check_patch_negative_controls(receipt, facts, kind, engine, single_shot=single_shot, hardware_slot=hardware_slot, restore_failure=restore_failure, transaction=transaction)
            write_json(scope / "independent-patch.json", reference)
            write_json(scope / "negative-controls.json", controls)
            observations.append({"engine": engine, "breakpointKind": kind, "singleShot": single_shot, "hardwareSlot": hardware_slot if single_shot else None, "restoreFailure": restore_failure, "transaction": transaction, "receipt": receipt, "reference": reference, "negativeControls": controls, "script": file_identity(script), "sourceScript": file_identity(source)})
            print(f"[VERIFIED] Native {environment.architecture} {engine} {'transaction/preflight/rollback/conflict' if transaction else 'failed-native-restore/retry' if restore_failure else f'single-shot hardware slot {hardware_slot}' if single_shot else kind}-breakpoint patch execution 7/42/7, seven OS-verified CPU steps, undo and actual exit 56", flush=True)
    assert file_identity(binary) == identity, "Runtime patch reference changed its source executable"
    results.append({"name": "test_native_patch_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourcePeFacts": facts, "normal": normals, "observations": observations}})
