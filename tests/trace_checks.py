import json
import os
from pathlib import Path
import re
import struct

from wi_driver import McpError, file_identity, write_json


def trace_source_hash(data, pointer_size):
    bits = pointer_size * 8
    mask = (1 << bits) - 1

    def rotate(value, count):
        value &= mask
        return ((value << count) | (value >> (bits - count))) & mask

    def mix(value, first, count, second):
        return rotate(value * first, count) * second & mask

    def finalize(value):
        if bits == 32:
            value = (value ^ (value >> 16)) * 0x85ebca6b & mask
            value = (value ^ (value >> 13)) * 0xc2b2ae35 & mask
            return value ^ (value >> 16)
        value = (value ^ (value >> 33)) * 0xff51afd7ed558ccd & mask
        value = (value ^ (value >> 33)) * 0xc4ceb9fe1a85ec53 & mask
        return value ^ (value >> 33)

    first_hash = 0x1337
    if pointer_size == 4:
        first_constant, second_constant = 0xcc9e2d51, 0x1b873593
        boundary = len(data) // 4 * 4
        for offset in range(0, boundary, 4):
            first_hash ^= mix(int.from_bytes(data[offset:offset + 4], "little"), first_constant, 15, second_constant)
            first_hash = (rotate(first_hash, 13) * 5 + 0xe6546b64) & mask
        if boundary < len(data):
            first_hash ^= mix(int.from_bytes(data[boundary:], "little"), first_constant, 15, second_constant)
        return finalize(first_hash ^ len(data))
    assert pointer_size == 8, "Trace hash pointer size is invalid"
    first_constant, second_constant = 0x87c37b91114253d5, 0x4cf5ad432745937f
    second_hash = 0x1337
    boundary = len(data) // 16 * 16
    for offset in range(0, boundary, 16):
        first_word, second_word = struct.unpack_from("<QQ", data, offset)
        first_hash ^= mix(first_word, first_constant, 31, second_constant)
        first_hash = ((rotate(first_hash, 27) + second_hash) * 5 + 0x52dce729) & mask
        second_hash ^= mix(second_word, second_constant, 33, first_constant)
        second_hash = ((rotate(second_hash, 31) + first_hash) * 5 + 0x38495ab5) & mask
    tail = data[boundary:]
    if len(tail) > 8:
        second_hash ^= mix(int.from_bytes(tail[8:], "little"), second_constant, 33, first_constant)
    if tail:
        first_hash ^= mix(int.from_bytes(tail[:8], "little"), first_constant, 31, second_constant)
    first_hash ^= len(data)
    second_hash ^= len(data)
    first_hash = (first_hash + second_hash) & mask
    second_hash = (second_hash + first_hash) & mask
    return (finalize(first_hash) + finalize(second_hash)) & mask


def trace_image_facts(binary, machine):
    import pefile
    try:
        image = pefile.PE(str(binary))
        if image.FILE_HEADER.Machine != machine:
            raise McpError("Trace reference has the wrong PE architecture")
        exports = {entry.name.decode("ascii"): entry.address for entry in image.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
        required = {"TraceRun", "TraceBody", "TraceLoop", "TraceCall", "TraceAfterCall", "TraceAfterLoop", "TraceDone", "TraceLeaf", "TraceOdd",
                    "gTraceMode", "gTraceSeed", "gTraceValues", "gTraceSum", "gTraceCalls", "gTraceEven", "gTraceOdd", "gTraceCompleted"}
        if not required <= exports.keys():
            raise McpError("Trace reference is missing its declared exports")
        instructions = []
        current = exports["TraceRun"]
        pointer_size = 8 if machine == 0x8664 else 4
        image_base = image.OPTIONAL_HEADER.ImageBase

        def add(name, opcode):
            nonlocal current
            if image.get_data(current, len(opcode)) != opcode:
                raise McpError(f"Trace reference has the wrong source instruction: {name}")
            instructions.append({"name": name, "rva": current, "bytes": opcode.hex()})
            current += len(opcode)

        def memory(name, prefix, field, suffix=b""):
            if pointer_size == 8:
                address = (exports[field] - current - len(prefix) - 4 - len(suffix)).to_bytes(4, "little", signed=True)
            else:
                address = (image_base + exports[field]).to_bytes(4, "little")
            add(name, prefix + address + suffix)

        if pointer_size == 8:
            add("allocate", b"\x48\x83\xec\x28")
        if current != exports["TraceBody"]:
            raise McpError("Trace body does not follow its declared prologue")
        add("clearIndex", b"\x33\xc9")
        add("clearSum", b"\x33\xd2")
        if pointer_size == 8:
            memory("valuesAddress", b"\x4c\x8d\x05", "gTraceValues")
        memory("seed", b"\x8b\x05" if pointer_size == 8 else b"\xa1", "gTraceSeed")
        boundaries = {"TraceLoop": "sentinel", "TraceCall": "call", "TraceAfterCall": "store", "TraceAfterLoop": "result",
                      "TraceDone": "done", "TraceLeaf": "callsIncrement", "TraceOdd": "oddAdd"}
        add("sentinel", b"\x48\xc7\x44\x24\xf8\x44\x33\x22\x11" if pointer_size == 8 else b"\xc7\x44\x24\xfc\x44\x33\x22\x11")
        add("call", b"\xe8" + (exports["TraceLeaf"] - current - 5).to_bytes(4, "little", signed=True))
        if pointer_size == 8:
            add("store", b"\x41\x89\x04\x88")
        else:
            memory("store", b"\x89\x04\x8d", "gTraceValues")
        add("addSum", b"\x03\xd0")
        add("incrementIndex", b"\xff\xc1" if pointer_size == 8 else b"\x41")
        add("compareIndex", b"\x83\xf9\x04")
        add("loopBranch", b"\x75" + (exports["TraceLoop"] - current - 2).to_bytes(1, "little", signed=True))
        memory("result", b"\x89\x15", "gTraceSum")
        memory("completed", b"\xc7\x05", "gTraceCompleted", b"\x01\x00\x00\x00")
        add("done", b"\x90")
        if pointer_size == 8:
            add("restore", b"\x48\x83\xc4\x28")
        add("return", b"\xc3")
        memory("callsIncrement", b"\xff\x05", "gTraceCalls")
        add("parityTest", b"\xf7\xc1\x01\x00\x00\x00")
        add("parityBranch", b"\x75" + (exports["TraceOdd"] - current - 2).to_bytes(1, "little", signed=True))
        add("evenAdd", b"\x83\xc0\x02")
        memory("evenIncrement", b"\xff\x05", "gTraceEven")
        add("evenReturn", b"\xc3")
        add("oddAdd", b"\x83\xc0\x03")
        memory("oddIncrement", b"\xff\x05", "gTraceOdd")
        add("oddReturn", b"\xc3")
        named = {instruction["name"]: instruction for instruction in instructions}
        if any(exports[label] != named[name]["rva"] for label, name in boundaries.items()):
            raise McpError("Trace reference label boundaries differ")
        if image.get_data(exports["gTraceMode"], 4) != bytes(4) or image.get_data(exports["gTraceSeed"], 4) != b"\x07\x00\x00\x00":
            raise McpError("Trace reference default mode or seed differs")
        relocations = []
        for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", []):
            for entry in block.entries:
                if exports["TraceRun"] <= entry.rva < current:
                    if pointer_size != 4 or entry.type != 3:
                        raise McpError("Trace reference has an unexpected code relocation")
                    relocations.append(entry.rva)
        return {"machine": machine, "pointerSize": pointer_size, "imageBase": image_base, "exports": exports, "instructions": instructions,
                "relocations": relocations, "size": image.OPTIONAL_HEADER.SizeOfImage, "traceHash": hex(trace_source_hash(Path(binary).read_bytes(), pointer_size))}
    except (pefile.PEFormatError, AttributeError, UnicodeError, ValueError, OverflowError) as error:
        raise McpError("Trace reference PE facts are malformed") from error
    finally:
        if "image" in locals():
            image.close()


def check_trace_output(receipt, facts):
    assert receipt["exitCode"] == 52 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Normal trace reference did not complete with its actual sum exit"
    lines = receipt["stdout"].splitlines()
    assert len(lines) == 17 and all(line.count("=") == 1 for line in lines), "Trace summary fields are malformed"
    observed = dict(line.split("=", 1) for line in lines)
    expected = {"mode": "1", "phase": "3", "pid": str(receipt["processIdentity"]["pid"]), "thread": str(receipt["startupThread"]), "imageBase": observed["imageBase"],
                "seed": "7", "calls": "4", "even": "2", "odd": "2", "completed": "1", "sum": "52", "returned": "17", "verified": "1",
                "value0": "9", "value1": "12", "value2": "14", "value3": "17"}
    assert 0 < int(observed["imageBase"], 16) <= (1 << (facts["pointerSize"] * 8)) - facts["size"] and observed == expected, f"Actual trace outcomes differ: {observed}"
    return observed


def read_trace_reference(path, pointer_size):
    data = Path(path).read_bytes()
    assert 8 <= len(data) <= 2 * 1024 * 1024 and data[:4] == b"TRAC", "Trace reference header is invalid"
    header_size = struct.unpack_from("<I", data, 4)[0]
    assert 0 < header_size <= min(65536, len(data) - 8), "Trace reference header length is invalid"
    header = json.loads(data[8:8 + header_size].decode("utf-8"))
    offset = 8 + header_size
    word_count = 172 if pointer_size == 8 else 216
    records, registers, thread = [], [0] * word_count, None
    word_format = "<Q" if pointer_size == 8 else "<I"

    def take(count):
        nonlocal offset
        assert 0 <= count <= len(data) - offset, "Trace reference is truncated"
        value = data[offset:offset + count]
        offset += count
        return value

    def word():
        return struct.unpack(word_format, take(pointer_size))[0]

    while offset < len(data):
        assert len(records) < 128, "Trace reference exceeds its instruction bound"
        block_offset = offset
        block, changed, memory_count, flags = take(4)
        assert block == 0 and flags & 0x70 == 0 and 0 < flags & 15 <= 15 and memory_count <= 32 and changed <= word_count, "Trace reference block fields are invalid"
        if flags & 0x80:
            thread = struct.unpack("<I", take(4))[0]
        assert thread, "Trace reference has no thread identity"
        opcode = take(flags & 15)
        positions, position = [], -1
        for delta in take(changed):
            position += delta + 1
            assert position < word_count, "Trace reference register delta exceeds its layout"
            positions.append(position)
        if not records:
            assert positions == list(range(word_count)), "Trace reference has no complete first register snapshot"
        for position in positions:
            registers[position] = word()
        memory_flags = take(memory_count)
        assert all(value in (0, 1) for value in memory_flags), "Trace reference memory flags are invalid"
        addresses = [word() for _ in memory_flags]
        previous = [word() for _ in memory_flags]
        following = [old if flag & 1 else word() for flag, old in zip(memory_flags, previous)]
        records.append({"offset": block_offset, "opcode": opcode.hex(), "thread": thread, "registers": list(registers),
                        "memory": [{"address": address, "old": old, "new": new} for address, old, new in zip(addresses, previous, following)]})
    assert records, "Trace reference has no instructions"
    return header, records


def relocated_opcode(facts, instruction, base):
    opcode = bytearray.fromhex(instruction["bytes"])
    for relocation in facts["relocations"]:
        index = relocation - instruction["rva"]
        if 0 <= index <= len(opcode) - 4:
            value = (int.from_bytes(opcode[index:index + 4], "little") + base - facts["imageBase"]) & 0xffffffff
            opcode[index:index + 4] = value.to_bytes(4, "little")
    return opcode.hex()


def check_graph_reference(facts, base, output):
    named = {instruction["name"]: instruction for instruction in facts["instructions"]}
    ordered = [instruction["name"] for instruction in facts["instructions"]]

    def block(start, end):
        return ordered[ordered.index(start):ordered.index(end) + 1]

    def address(name):
        return base + named[name]["rva"]

    main_entry = "allocate" if facts["pointerSize"] == 8 else "clearIndex"
    shapes = [("TraceRun", block(main_entry, "seed"), [], False, True, ["sentinel"]),
              ("TraceRun", block("sentinel", "loopBranch"), ["sentinel", "result"], False, False, ["sentinel", "result"]),
              ("TraceRun", block("result", "return"), [], True, False, []),
              ("TraceLeaf", block("callsIncrement", "parityBranch"), ["oddAdd", "evenAdd"], False, False, ["oddAdd", "evenAdd"]),
              ("TraceLeaf", block("evenAdd", "evenReturn"), [], True, False, []),
              ("TraceLeaf", block("oddAdd", "oddReturn"), [], True, False, [])]
    graphs = re.findall(r"TRACE_GRAPH name=(\w+) entry=([0-9a-f]+) nodes=(\d+)", output)
    assert len(graphs) == 2 and {(name, int(entry, 16), int(count)) for name, entry, count in graphs} == {
        ("TraceRun", base + facts["exports"]["TraceRun"], 3), ("TraceLeaf", base + facts["exports"]["TraceLeaf"], 3)}, "Native graph entry/count differs from the source PE"
    nodes = re.findall(r"TRACE_NODE name=(\w+) start=([0-9a-f]+) end=([0-9a-f]+) true=([0-9a-f]+) false=([0-9a-f]+) count=(\d+) terminal=(\d+) split=(\d+) indirect=(\d+)", output)
    edges = re.findall(r"TRACE_EDGE name=(\w+) node=([0-9a-f]+) index=(\d+) destination=([0-9a-f]+)", output)
    instructions = re.findall(r"TRACE_GRAPH_INSTRUCTION name=(\w+) node=([0-9a-f]+) ip=([0-9a-f]+) bytes=([0-9a-f]+)", output)
    wanted_nodes, wanted_edges, wanted_instructions = [], [], []
    for function, names, branches, terminal, split, exits in shapes:
        start, end = address(names[0]), address(names[-1])
        wanted_nodes.append((function, start, end, address(branches[0]) if branches else 0, address(branches[1]) if branches else 0, len(names), int(terminal), int(split), 0))
        wanted_edges.extend((function, start, index, address(destination)) for index, destination in enumerate(exits))
        wanted_instructions.extend((function, start, address(name), relocated_opcode(facts, named[name], base)) for name in names)
    assert [(name, *(int(value, 16) for value in (start, end, yes, no)), *(int(value) for value in (count, terminal, split, indirect)))
            for name, start, end, yes, no, count, terminal, split, indirect in nodes] == wanted_nodes, "Native graph blocks/branches/terminals differ from the source PE"
    assert [(name, int(node, 16), int(index), int(destination, 16)) for name, node, index, destination in edges] == wanted_edges, "Native graph fallthrough/loop edges differ from the source PE"
    assert [(name, int(node, 16), int(ip, 16), opcode) for name, node, ip, opcode in instructions] == wanted_instructions, "Native graph instructions differ from the source PE"
    return {"nodes": wanted_nodes, "edges": wanted_edges, "instructions": wanted_instructions}


def expected_trace_reference(facts, base, stack, initial, kind):
    assert kind in ("into", "over"), "Trace reference mode is invalid"
    pointer_size = facts["pointerSize"]
    exports = facts["exports"]
    named = {instruction["name"]: instruction for instruction in facts["instructions"]}
    registers = {0: initial[0], 1: initial[1], 2: initial[2], 4: stack}
    if pointer_size == 8:
        registers[8] = initial[8]
    expected = []
    flag_zero = None

    def emit(name, memory=()):
        instruction = named[name]
        expected.append({"name": name, "ip": base + instruction["rva"], "opcode": relocated_opcode(facts, instruction, base), "registers": dict(registers), "zeroFlag": flag_zero, "memory": list(memory)})

    def access(address, old, new, width=4):
        return {"address": address, "old": old, "new": new, "width": width}

    emit("clearIndex")
    registers[1] = 0
    emit("clearSum")
    registers[2] = 0
    if pointer_size == 8:
        emit("valuesAddress")
        registers[8] = base + exports["gTraceValues"]
    emit("seed", [access(base + exports["gTraceSeed"], 7, 7)])
    registers[0] = 7
    return_address = base + exports["TraceAfterCall"]
    for index in range(4):
        slot = stack - pointer_size
        emit("sentinel", [access(slot, return_address if index else None, 0x11223344, pointer_size)])
        emit("call", [access(slot, 0x11223344, return_address, pointer_size)])
        branch = "odd" if index & 1 else "even"
        increment = 3 if index & 1 else 2
        if kind == "into":
            registers[4] = slot
            emit("callsIncrement", [access(base + exports["gTraceCalls"], index, index + 1)])
            emit("parityTest")
            flag_zero = 0 if index & 1 else 0x40
            emit("parityBranch")
            emit(branch + "Add")
            registers[0] += increment
            flag_zero = 0
            emit(branch + "Increment", [access(base + exports["gTrace" + branch.title()], index // 2, index // 2 + 1)])
            emit(branch + "Return", [access(slot, return_address, return_address, pointer_size)])
            registers[4] = stack
        else:
            registers[0] += increment
            flag_zero = 0
        emit("store", [access(base + exports["gTraceValues"] + index * 4, 0, registers[0])])
        emit("addSum")
        registers[2] += registers[0]
        emit("incrementIndex")
        registers[1] += 1
        emit("compareIndex")
        flag_zero = 0x40 if index == 3 else 0
        emit("loopBranch")
    emit("result", [access(base + exports["gTraceSum"], 0, 52)])
    emit("completed", [access(base + exports["gTraceCompleted"], 0, 1)])
    return expected


def check_trace_reference(path, facts, binary, output, kind):
    pointer_size = facts["pointerSize"]
    header, records = read_trace_reference(path, pointer_size)
    layouts = re.findall(r"TRACE_LAYOUT words=(\d+) ipIndex=(\d+) pointerSize=(\d+) stack=([0-9a-f]+) pid=(\d+) thread=(\d+) base=([0-9a-f]+) creation=(\d+)", output)
    starts = re.findall(r"TRACE_START ax=([0-9a-f]+) cx=([0-9a-f]+) dx=([0-9a-f]+) r8=([0-9a-f]+)", output)
    assert len(layouts) == len(starts) == 1, "Trace reference has no unique starting context"
    words, ip_index, size, stack, pid, thread, base, creation = layouts[0]
    assert (int(words), int(ip_index), int(size)) == ((172, 16, 8) if pointer_size == 8 else (216, 8, 4)), "Trace reference register layout differs"
    stack, pid, thread, base, creation = int(stack, 16), int(pid), int(thread), int(base, 16), int(creation)
    assert 0 < stack < 1 << (pointer_size * 8) and 0 < base <= (1 << (pointer_size * 8)) - facts["size"] and pid > 0 and thread > 0 and creation > 0, "Trace reference identity is invalid"
    assert header["ver"] == 1 and header["arch"] == ("x64" if pointer_size == 8 else "x86") and header["compression"] == "", "Trace reference format differs"
    assert header["hashAlgorithm"] == "murmurhash" and re.fullmatch(r"0x[0-9A-Fa-f]{1,16}", header["hash"]) and int(header["hash"], 16) == int(facts["traceHash"], 16) and Path(header["path"]).resolve() == Path(binary).resolve(), "Trace reference source binding differs"
    initial = {index: int(value, 16) for index, value in zip((0, 1, 2, 8), starts[0])}
    graph = check_graph_reference(facts, base, output)
    expected = expected_trace_reference(facts, base, stack, initial, kind)
    assert len(records) == len(expected), "Trace reference instruction count differs"
    flags_index = int(ip_index) + 1
    for index, (record, wanted) in enumerate(zip(records, expected)):
        assert record["thread"] == thread and record["registers"][int(ip_index)] == wanted["ip"] and record["opcode"] == wanted["opcode"], f"Trace instruction/identity differs at {index}: {wanted['name']}"
        assert all(record["registers"][position] == value for position, value in wanted["registers"].items()), f"Trace registers differ at {index}: {wanted['name']}"
        if wanted["zeroFlag"] is not None:
            assert record["registers"][flags_index] & 0x40 == wanted["zeroFlag"], f"Trace branch flag differs at {index}: {wanted['name']}"
        assert len(record["memory"]) == len(wanted["memory"]), f"Trace memory operand count differs at {index}: {wanted['name']}"
        for actual, memory in zip(record["memory"], wanted["memory"]):
            mask = (1 << (memory["width"] * 8)) - 1
            assert actual["address"] == memory["address"] and actual["new"] & mask == memory["new"] and (memory["old"] is None or actual["old"] & mask == memory["old"]), f"Trace memory effects differ at {index}: {wanted['name']}"
    callbacks = re.findall(r"TRACE_CALLBACK index=(\d+) ip=([0-9a-f]+) pid=(\d+) thread=(\d+) stop=(\d+)", output)
    addresses = [item["ip"] for item in expected[1:]] + [base + facts["exports"]["TraceDone"]]
    assert len(callbacks) == len(addresses), "Trace callback count differs"
    assert all((int(item[0]), int(item[1], 16), int(item[2]), int(item[3]), int(item[4])) == (index, address, pid, thread, int(index == len(addresses) - 1))
               for index, (item, address) in enumerate(zip(callbacks, addresses))), "Trace callback order/stop identity differs"
    return {"header": header, "instructions": len(records), "kind": kind, "targetIdentity": {"pid": pid, "creationTime": str(creation)},
            "thread": thread, "base": hex(base), "stack": hex(stack), "records": records, "expected": expected, "graph": graph}


def check_trace_negative_controls(path, facts, binary, output, kind, reference):
    source = Path(path).read_bytes()
    pointer_size = facts["pointerSize"]
    records = reference["records"]
    call_index = next(index for index, wanted in enumerate(reference["expected"]) if wanted["name"] == "call")

    def layout(record):
        start = record["offset"]
        changed, memory_count, flags = source[start + 1:start + 4]
        opcode = start + 4 + (4 if flags & 0x80 else 0)
        positions = opcode + (flags & 15)
        values = positions + changed
        addresses = values + changed * pointer_size + memory_count
        return {"opcode": opcode, "positions": positions, "values": values, "addresses": addresses, "oldMemory": addresses + memory_count * pointer_size}

    first, call = layout(records[0]), layout(records[call_index])
    controls = []
    mutations = [("wrong_opcode", call["opcode"], 1), ("wrong_thread", records[0]["offset"] + 4, 1),
                 ("wrong_initial_register", first["values"] + 2 * pointer_size, 1), ("wrong_memory_address", call["addresses"], pointer_size),
                 ("wrong_call_old_value", call["oldMemory"], 1), ("invalid_register_delta", first["positions"], 255)]
    for name, offset, value in mutations:
        data = bytearray(source)
        data[offset] = value if name == "invalid_register_delta" else data[offset] ^ value
        controls.append((name, bytes(data), output))
    controls.append(("truncated", source[:-1], output))
    start = records[call_index + 1]["offset"]
    end = records[call_index + 2]["offset"]
    controls.append(("missing_instruction", source[:start] + source[end:], output))
    header_size = struct.unpack_from("<I", source, 4)[0]
    header = dict(reference["header"])
    header["arch"] = "x86" if pointer_size == 8 else "x64"
    encoded = json.dumps(header).encode("utf-8")
    controls.append(("wrong_architecture", b"TRAC" + struct.pack("<I", len(encoded)) + encoded + source[8 + header_size:], output))
    header = dict(reference["header"])
    header["hash"] = hex(int(header["hash"], 16) ^ 1)
    encoded = json.dumps(header).encode("utf-8")
    controls.append(("wrong_source_hash", b"TRAC" + struct.pack("<I", len(encoded)) + encoded + source[8 + header_size:], output))
    altered_edge = re.sub(r"(TRACE_EDGE name=TraceRun node=[0-9a-f]+ index=0 destination=)[0-9a-f]+", r"\g<1>1", output, count=1)
    controls.append(("wrong_graph_edge", source, altered_edge))
    altered_callback = re.sub(r"(TRACE_CALLBACK index=0 ip=)[0-9a-f]+", r"\g<1>1", output, count=1)
    controls.append(("wrong_callback_order", source, altered_callback))
    altered_stop = re.sub(r"(TRACE_CALLBACK index=\d+ ip=[0-9a-f]+ pid=\d+ thread=\d+ stop=)1", r"\g<1>0", output, count=1)
    controls.append(("missing_final_stop", source, altered_stop))
    directory = Path(path).parent / "negative-controls"
    directory.mkdir()
    observed = []
    for name, data, text in controls:
        candidate = directory / f"{name}.trace"
        candidate.write_bytes(data)
        try:
            check_trace_reference(candidate, facts, binary, text, kind)
        except (AssertionError, ValueError, KeyError, struct.error) as error:
            observed.append({"name": name, "status": "rejected", "error": str(error), "trace": file_identity(candidate), "targetExecuted": False})
        else:
            raise AssertionError(f"Trace negative control was admitted: {name}")
    assert Path(path).read_bytes() == source, "Trace negative controls changed the original artifact"
    write_json(directory / "results.json", observed)
    return observed


def trace_reference_report(reference):
    report = dict(reference)
    report["records"] = [{**record, "registers": [hex(value) for value in record["registers"]],
                          "memory": [{key: hex(value) for key, value in access.items()} for access in record["memory"]]} for record in reference["records"]]
    report["expected"] = [{**instruction, "ip": hex(instruction["ip"]), "registers": {str(position): hex(value) for position, value in instruction["registers"].items()},
                           "memory": [{**access, "address": hex(access["address"]), "old": None if access["old"] is None else hex(access["old"]), "new": hex(access["new"])}
                                      for access in instruction["memory"]]} for instruction in reference["expected"]]
    graph = reference["graph"]
    report["graph"] = {
        "nodes": [[node[0], *(hex(value) for value in node[1:5]), *node[5:]] for node in graph["nodes"]],
        "edges": [[name, hex(node), index, hex(destination)] for name, node, index, destination in graph["edges"]],
        "instructions": [[name, hex(node), hex(ip), opcode] for name, node, ip, opcode in graph["instructions"]]}
    return report


def trace_recording_script(source, binary, trace, kind):
    text = Path(source).read_text(encoding="utf-8")
    entry = "init tests/trace_cmd_condition.exe"
    command = f'Trace{kind.title()}Conditional "cip==trace_cmd_condition:TraceDone", .128'
    sequence = command + "\ntraceinspect\n"
    assert text.count(entry) == 1 and text.count(sequence) == 1, "Trace reference script template differs"
    text = text.replace(entry, f'init "{binary}"')
    return text.replace(sequence, f'StartRunTrace "{trace}"\n{sequence}StopRunTrace\n')


def run_trace_oracles(environment, results, selected_engine, timeout, fixture_identity, run_owned):
    if selected_engine == "StaticEngine":
        raise McpError("Trace references require TitanEngine or GleeBug")
    engines = ("TitanEngine", "GleeBug") if selected_engine == "all" else (selected_engine,)
    binary, identity, machine = fixture_identity(environment, "trace_cmd_condition")
    facts = trace_image_facts(binary, machine)
    normal = run_owned([str(binary)], {**os.environ, "WININSPECT_TEST_NORMAL": "1", "WININSPECT_TEST_TRACE_MODE": "1"}, timeout)
    write_json(environment.root / "trace-normal.json", normal)
    observed = check_trace_output(normal, facts)
    runtime = binary.parent.parent
    plugin = runtime / "tests/trace_cmd_condition" / ("trace_cmd_condition.dp64" if machine == 0x8664 else "trace_cmd_condition.dp32")
    required = [runtime / "headless.exe", plugin, runtime / "wininspect.dll", runtime / "winbridge.dll"]
    assert all(path.is_file() for path in required), "Native trace runtime is incomplete"
    child = dict(os.environ)
    child.pop("WININSPECT_TEST_NORMAL", None)
    child.pop("WININSPECT_TEST_TRACE_MODE", None)
    observations = []
    for engine in engines:
        engine_id = 0 if engine == "TitanEngine" else 1
        engine_path = runtime / ("TitanEngine.dll" if engine_id == 0 else "GleeBug/TitanEngine.dll")
        for kind in ("into", "over"):
            scope = environment.root / "trace" / engine / kind
            profile = scope / "userdir"
            profile.mkdir(parents=True)
            (profile / "headless.ini").write_text(f"[Engine]\nDebugEngine={engine_id}\nNoConsoleWindow=1\n", encoding="utf-8")
            trace = scope / ("record.trace64" if machine == 0x8664 else "record.trace32")
            source = runtime / "tests/trace_cmd_condition" / f"test.{kind}.txt"
            script = scope / "reference.txt"
            text = trace_recording_script(source, binary, trace, kind)
            script.write_text(text, encoding="utf-8", newline="\n")
            receipt = run_owned([str(required[0]), "-testing", "-userdir", str(profile), "-plugin", str(plugin), "-cf", str(script)], child, timeout,
                                required_modules=[*required, engine_path])
            write_json(scope / "receipt.json", receipt)
            finals = re.findall(r"\[wi-test\] FINAL status=(pass|fail) asserts=(\d+)(?: reason=(\w+))?", receipt["stdout"])
            assert len(finals) == 1 and finals[0][0] == "pass" and int(finals[0][1]) >= 100 and receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Native trace execution did not complete"
            assert receipt["loadedModules"] and not any("mcp-server" in item["path"].lower() or "agent smithers" in item["path"].lower() for item in receipt["loadedModules"]), "Trace reference loaded an external MCP dependency"
            reference = check_trace_reference(trace, facts, binary, receipt["stdout"], kind)
            write_json(scope / "independent-trace.json", trace_reference_report(reference))
            controls = check_trace_negative_controls(trace, facts, binary, receipt["stdout"], kind, reference)
            observations.append({"engine": engine, "kind": kind, "receipt": receipt, "script": file_identity(script), "sourceScript": file_identity(source), "trace": file_identity(trace),
                                 "independentTrace": file_identity(scope / "independent-trace.json"), "instructions": reference["instructions"], "targetIdentity": reference["targetIdentity"], "negativeControls": controls})
            print(f"[VERIFIED] Native {environment.architecture} {engine} trace-{kind} file, callbacks and actual exit 52", flush=True)
    assert file_identity(binary) == identity, "Trace reference executable changed"
    results.append({"name": "test_native_trace_oracles", "status": "verified", "oracle": {
        "binary": identity, "plugin": file_identity(plugin), "sourcePeFacts": facts, "normal": normal, "observed": observed, "observations": observations}})
