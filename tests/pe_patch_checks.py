import hashlib
from pathlib import Path
import struct

from wi_driver import file_identity


def pe_fixture(bits):
    source = bytearray(0xa00)
    source[:2] = b"MZ"
    struct.pack_into("<I", source, 0x3c, 0x80)
    source[0x80:0x84] = b"PE\0\0"
    optional = 0x98
    optional_size = 240 if bits == 64 else 224
    directory = optional + (112 if bits == 64 else 96)
    preferred = 0x140000000 if bits == 64 else 0x400000
    struct.pack_into("<HH", source, 0x84, 0x8664 if bits == 64 else 0x14c, 4)
    struct.pack_into("<H", source, 0x94, optional_size)
    struct.pack_into("<H", source, optional, 0x20b if bits == 64 else 0x10b)
    image_base = optional + (24 if bits == 64 else 28)
    struct.pack_into("<Q" if bits == 64 else "<I", source, image_base, preferred)
    struct.pack_into("<II", source, optional + 56, 0x5000, 0x400)
    struct.pack_into("<I", source, directory - 4, 16)
    struct.pack_into("<II", source, directory + 40, 0x3000, 12)
    section_table = optional + optional_size
    for index, (rva, raw, size) in enumerate(((0x1000, 0x400, 0x200), (0x2000, 0x600, 0x200), (0x3000, 0x800, 0x200), (0x4000, 0, 0))):
        entry = section_table + index * 40
        struct.pack_into("<IIII", source, entry + 8, 0x200, rva, size, raw)
    source[0x400:0x406] = bytes.fromhex("b807000000c3")
    source[0x600:0x600 + bits // 8] = (preferred + 0x1000).to_bytes(bits // 8, "little")
    struct.pack_into("<IIHH", source, 0x800, 0x2000, 12, (10 if bits == 64 else 3) << 12, 0)
    source += b"PRIVATE_PE_OVERLAY\0" + bytes(range(256))
    return bytes(source), {"bits": bits, "preferred": preferred, "optional": optional, "directory": directory,
                           "imageBaseOffset": image_base, "sectionTable": section_table}


def pe_request(domain, address, old, new=None, encoding="file_bytes"):
    return {"domain": domain, "addressHex": hex(address), "encoding": encoding,
            "expectedHex": old.hex(), "replacementHex": (old if new is None else new).hex()}


def check_pe_file_patch_plans(probe):
    directory = Path(probe.output) / "PE \u4fdd\u5b58"
    directory.mkdir()
    observations = []
    input_hashes = []

    def check(name, source, facts, ranges, error=None, expected=None, loaded=None, render=None):
        path = directory / f"{len(observations):03}-{name}.exe"
        output = directory / f"{len(observations):03}-{name}-output.exe"
        path.write_bytes(source)
        identity = file_identity(path)
        request = {"sourcePath": str(path), "outputPath": str(output), "loadedBaseHex": hex(loaded if loaded is not None else facts["preferred"] + 0x10000000), "ranges": ranges}
        if render is not None:
            render_path = directory / f"{len(observations):03}-{name}-changed.exe"
            render_path.write_bytes(render)
            request["renderSourcePath"] = str(render_path)
        response = probe.call("pe-plan", request)
        assert file_identity(path) == identity, f"{name}: source changed during planning"
        if error:
            assert response["valid"] is False and response["error"]["code"] == error, (name, response)
            assert not output.exists(), f"{name}: rejected plan wrote a destination"
        else:
            assert response["valid"] is True, (name, response)
            plan = response["plan"]
            expected = source if expected is None else expected
            assert output.read_bytes() == expected, f"{name}: output bytes differ from the independent complete-file oracle"
            assert response["outputSha256"] == hashlib.sha256(expected).hexdigest()
            assert plan["sourceSha256"] == hashlib.sha256(source).hexdigest() and int(plan["sourceSize"]) == len(source)
            assert plan["pointerBits"] == facts["bits"] and int(plan["preferredBaseHex"], 16) == facts["preferred"]
        input_hashes.append(identity)
        observations.append({"name": name, "expectedError": error, "response": response, "output": file_identity(output) if output.exists() else None})
        return response

    for bits in (32, 64):
        source, facts = pe_fixture(bits)
        prefix = f"x{bits}-"
        base = facts["preferred"] + 0x10000000
        old = source[0x400:0x406]
        changed = bytes.fromhex("66b82a0090c3")
        expected = source[:0x400] + changed + source[0x406:]
        pointer = (base + 0x1000).to_bytes(bits // 8, "little")
        pointer_request = pe_request("loaded_va", base + 0x2000, pointer, encoding="loaded_bytes")
        for domain, address in (("file_offset", 0x400), ("rva", 0x1000), ("loaded_va", base + 0x1000)):
            check(prefix + domain, source, facts, [pe_request(domain, address, old, changed)], expected=expected)
        normalized = check(prefix + "relocated", source, facts, [pointer_request])
        assert normalized["plan"]["ranges"] == [{"fileOffset": "1536", "expectedHex": source[0x600:0x600 + bits // 8].hex(),
                                                  "replacementHex": source[0x600:0x600 + bits // 8].hex(), "normalizedRelocations": 1}]
        check(prefix + "combined", source, facts, [pe_request("loaded_va", base + 0x1000, old, changed), pointer_request], expected=expected)
        check(prefix + "header", source, facts, [pe_request("file_offset", 0x1c, b"\0", b"\x5b"), pointer_request], expected=source[:0x1c] + b"\x5b" + source[0x1d:])
        check(prefix + "overlay", source, facts, [pe_request("file_offset", len(source) - 1, source[-1:], b"\x5a")], expected=source[:-1] + b"\x5a")
        check(prefix + "large-file-hash", source + bytes(range(256)) * 36865, facts, [pointer_request])
        check(prefix + "virtual-tail", source, facts, [pe_request("rva", 0x4000, b"\0", b"\x5b")], "unsupported_mapping")
        check(prefix + "header-gap", source, facts, [pe_request("rva", 0x800, b"\0")], "unsupported_mapping")
        check(prefix + "partial-relocation", source, facts, [pe_request("loaded_va", base + 0x2001, pointer[1:], encoding="loaded_bytes")], "unsupported_mapping")
        check(prefix + "loaded-raw", source, facts, [pe_request("file_offset", 0x600, pointer, encoding="loaded_bytes")], "invalid_argument")
        check(prefix + "address-underflow", source, facts, [pe_request("loaded_va", base - 1, b"\0")], "unsupported_mapping")
        check(prefix + "base-overflow", source, facts, [pointer_request], "invalid_argument", loaded=(1 << bits) - 1)
        check(prefix + "raw-overflow", source, facts, [pe_request("file_offset", (1 << 64) - 1, b"\0\0")], "unsupported_mapping")
        check(prefix + "expected-conflict", source, facts, [pe_request("rva", 0x1000, b"\x90")], "expected_bytes_mismatch")
        check(prefix + "overlap", source, facts, [pointer_request, pointer_request], "invalid_argument")
        check(prefix + "empty-range", source, facts, [pe_request("rva", 0x1000, b"")], "invalid_argument")
        check(prefix + "unequal-range", source, facts, [pe_request("rva", 0x1000, old, b"\x90")], "invalid_argument")
        check(prefix + "range-quota", source, facts, [pe_request("rva", 0x1000, old)] * 1001, "invalid_argument")
        large_source = source + b"\0" * 1048576
        check(prefix + "byte-quota", large_source, facts, [pe_request("file_offset", 0, large_source[:1048576]),
              pe_request("file_offset", 1048576, large_source[1048576:1048577])], "invalid_argument")
        for name, offset, width, value in (("MZ", 0, 2, 0), ("PE", 0x80, 4, 0), ("machine", 0x84, 2, 0xaa64),
                ("magic", facts["optional"], 2, 0), ("PE-offset", 0x3c, 4, 0xfffffff0), ("optional-size", 0x94, 2, 0xffff),
                ("section-count", 0x86, 2, 97), ("header-size", facts["optional"] + 60, 4, 0x100),
                ("directory-count", facts["directory"] - 4, 4, 17), ("raw-overlap", facts["sectionTable"] + 60, 4, 0x400),
                ("virtual-overlap", facts["sectionTable"] + 52, 4, 0x1000), ("raw-outside", facts["sectionTable"] + 20, 4, 0xfffffe00),
                ("virtual-outside", facts["sectionTable"] + 12, 4, 0xffffff00), ("reloc-short", facts["directory"] + 44, 4, 7),
                ("reloc-incomplete", facts["directory"] + 40, 4, 0), ("reloc-page", 0x800, 4, 0x2001),
                ("reloc-size", 0x804, 4, 10), ("reloc-too-long", 0x804, 4, 16), ("reloc-kind", 0x808, 2, 0x9000),
                ("reloc-duplicate", 0x80a, 2, (10 if bits == 64 else 3) << 12), ("highadj-missing", 0x80a, 2, 0x4000),
                ("certificate-misaligned", facts["directory"] + 32, 8, (8 << 32) | 0xa01)):
            damaged = bytearray(source)
            damaged[offset:offset + width] = value.to_bytes(width, "little")
            check(prefix + name, bytes(damaged), facts, [pe_request("rva", 0x1000, old)], "unsupported_mapping")
        check(prefix + "truncated", source[:60], facts, [pe_request("rva", 0x1000, old)], "unsupported_mapping")
        for name, relocation_data in (("reloc-block-quota", struct.pack("<II", 0x2000, 8) * 100001),
                                      ("reloc-slot-quota", struct.pack("<II", 0x2000, 200012) + b"\0" * 200004),
                                      ("highadj-slot-quota", struct.pack("<II", 0x2000, 200012) + b"\0" * 199998 + struct.pack("<HHH", 0x4000, 0, 0))):
            bounded = bytearray(source[:0x800] + relocation_data)
            struct.pack_into("<II", bounded, facts["directory"] + 40, 0x3000, len(relocation_data))
            struct.pack_into("<I", bounded, facts["optional"] + 56, 0x100000)
            struct.pack_into("<I", bounded, facts["sectionTable"] + 132, 0xf0000)
            struct.pack_into("<I", bounded, facts["sectionTable"] + 88, len(relocation_data))
            struct.pack_into("<I", bounded, facts["sectionTable"] + 96, len(relocation_data))
            check(prefix + name, bytes(bounded), facts, [pe_request("rva", 0x1000, old)], "resource_limit")
        unaligned = bytearray(source)
        unaligned[0x801:0x80d] = source[0x800:0x80c]
        struct.pack_into("<I", unaligned, facts["directory"] + 40, 0x3001)
        check(prefix + "reloc-directory-alignment", bytes(unaligned), facts, [pe_request("rva", 0x1000, old)], "unsupported_mapping")
        for name, offset, width in (("image-base-mutation", facts["imageBaseOffset"], bits // 8),
                ("section-mutation", facts["sectionTable"] + 12, 4), ("reloc-mutation", 0x808, 2)):
            initial = source[offset:offset + width]
            altered = bytes([initial[0] ^ 1]) + initial[1:]
            check(prefix + name, source, facts, [pointer_request, pe_request("file_offset", offset, initial, altered)], "unsupported_mapping")
        for name, rendered in (("source-byte-conflict", source[:0x400] + b"\x90" + source[0x401:]),
                ("outside-byte-conflict", source[:-1] + b"\0"), ("source-size-conflict", source + b"\0")):
            check(prefix + name, source, facts, [pointer_request], "file_hash_mismatch", render=rendered)
        certificate = bytearray(source + b"\0" * 16)
        offset = (len(source) + 7) & ~7
        struct.pack_into("<II", certificate, facts["directory"] + 32, offset, 8)
        signed = check(prefix + "certificate-preserved", bytes(certificate), facts, [pointer_request])
        assert signed["plan"]["hasCertificate"] is True
        adjacent = bytearray(source)
        struct.pack_into("<I", adjacent, facts["sectionTable"] + 20, 0x600)
        struct.pack_into("<II", adjacent, facts["sectionTable"] + 52, 0x1200, 0x200)
        struct.pack_into("<I", adjacent, facts["sectionTable"] + 60, 0x400)
        struct.pack_into("<IIHH", adjacent, 0x800, 0x1000, 12, ((10 if bits == 64 else 3) << 12) | 0x200, 0)
        joined = bytes(adjacent[0x7fe:0x800] + adjacent[0x400:0x402])
        changed_adjacent = bytearray(adjacent)
        changed_adjacent[0x7fe:0x800] = b"\x11\x22"
        changed_adjacent[0x400:0x402] = b"\x33\x44"
        split = check(prefix + "segmented-mapping", bytes(adjacent), facts, [pe_request("rva", 0x11fe, joined, bytes.fromhex("11223344"))], expected=bytes(changed_adjacent))
        assert [int(item["fileOffset"]) for item in split["plan"]["ranges"]] == [0x7fe, 0x400]
        for kind, width in ((1, 2), (2, 2), (3, 4), (4, 2), (10, 8)):
            for delta in (0, 0x10000001, -0x10001):
                for low in ((0, 0x8000, 0x7fff, 0xffff) if kind == 4 else (0,)):
                    candidate = bytearray(source)
                    mask = (1 << (width * 8)) - 1
                    initial = mask - 7
                    candidate[0x600:0x600 + width] = initial.to_bytes(width, "little")
                    struct.pack_into("<HH", candidate, 0x808, kind << 12, low if kind == 4 else 0)
                    signed_low = low if low < 0x8000 else low - 0x10000
                    adjustment = delta >> 16 if kind == 1 else delta & 0xffff if kind == 2 else ((delta + signed_low + 0x8000) & 0xffffffff) >> 16 if kind == 4 else delta
                    loaded_old = ((initial + adjustment) & mask).to_bytes(width, "little")
                    loaded_new = ((initial + adjustment + 5) & mask).to_bytes(width, "little")
                    target = bytearray(candidate)
                    target[0x600:0x600 + width] = ((initial + 5) & mask).to_bytes(width, "little")
                    check(prefix + f"arithmetic-{kind}-{delta}-{low}", bytes(candidate), facts,
                          [pe_request("rva", 0x2000, loaded_old, loaded_new, "loaded_bytes")], expected=bytes(target), loaded=facts["preferred"] + delta)
        valid = {"sourcePath": str(directory / "schema.exe"), "loadedBaseHex": hex(base), "ranges": [pointer_request]}
        (directory / "schema.exe").write_bytes(source)
        for field, value in (("unknown", True), ("loadedBaseHex", -1), ("ranges", []), ("sourcePath", "relative.exe")):
            rejected = probe.call("pe-plan", {**valid, field: value})
            assert rejected["valid"] is False and rejected["error"]["code"] == "invalid_argument", rejected
    assert all(file_identity(item["path"]) == item for item in input_hashes), "Private PE fixture inputs changed"
    for data in (b"", b"abc", bytes(range(256)), "Hu Tao \u2764".encode("utf-8")):
        assert probe.call("sha256", raw=data) == {"valid": True, "sha256": hashlib.sha256(data).hexdigest()}
    bounded = probe.call("sha256", raw=b"x" * (8 * 1024 * 1024 + 1))
    assert bounded["valid"] is False and bounded["error"]["code"] == "payload_limit"
    return {"planCases": len(observations), "rejectedPlans": sum(bool(item["expectedError"]) for item in observations),
            "fixtureKind": "independently constructed PE component cases; actual loader outcomes are a separate native file oracle",
            "schemaRejections": 8, "retainedFrameHashVectors": 4, "retainedFrameHashLimitRejections": 1, "filePlans": observations}
