#include "patch_types.h"
#include "schema_helpers.h"

namespace wininspect::mcp
{
namespace
{
Json id() { return string_schema("opaque-id"); }
Json hex() { return reference_schema("Hex64"); }
Json decimal() { return reference_schema("Decimal64"); }
Json bytes() { return string_schema("hex-bytes", MaximumPayloadBytes * 2); }
Json bool_schema() { return {{"type", "boolean"}}; }
}

Json decoded_instruction_schema()
{
    const auto operand = closed_object_schema({{"index", bounded_integer_schema(0, 15)}, {"kind", enum_schema({"register", "memory", "immediate", "pointer", "other"})},
        {"text", string_schema("utf8-text", 4096)}, {"widthBits", bounded_integer_schema(0, 512)}, {"valueHex", nullable_schema(hex())},
        {"access", enum_schema({"none", "read", "write", "read_write", "conditional", "unknown"})}}, {"index", "kind", "text", "widthBits", "valueHex", "access"});
    return closed_object_schema({{"addressHex", hex()}, {"bytesHex", string_schema("hex-bytes", 30)}, {"length", bounded_integer_schema(1, 15)},
        {"text", string_schema("utf8-text", 4096)}, {"mnemonic", string_schema("utf8-text", 128)}, {"operands", bounded_array_schema(operand, 16)},
        {"branch", enum_schema({"none", "call", "return", "conditional", "unconditional", "indirect", "other"})}, {"branchTargetHex", nullable_schema(hex())},
        {"labels", bounded_array_schema(string_schema("utf8-text", 1024), 64)}, {"valid", bool_schema()}, {"error", nullable_schema(reference_schema("DomainError"))}},
        {"addressHex", "bytesHex", "length", "text", "mnemonic", "operands", "branch", "branchTargetHex", "labels", "valid", "error"});
}

Json encoded_block_schema()
{
    const auto boundary = closed_object_schema({{"offset", decimal()}, {"length", positive_decimal_schema()}, {"line", bounded_integer_schema(1, MaximumPayloadBytes)},
        {"column", bounded_integer_schema(1, MaximumPayloadBytes)}, {"kind", enum_schema({"instruction", "data"})}}, {"offset", "length", "line", "column", "kind"});
    const auto label = closed_object_schema({{"name", string_schema("utf8-text", 1024)}, {"addressHex", hex()}}, {"name", "addressHex"});
    return closed_object_schema({{"architecture", enum_schema({"x32", "x64"})}, {"originHex", hex()}, {"bytesHex", bytes()}, {"length", positive_decimal_schema()},
        {"boundaries", bounded_array_schema(boundary, MaximumPageLimit, 1)}, {"labels", bounded_array_schema(label, MaximumPageLimit)},
        {"backend", closed_object_schema({{"provider", id()}, {"version", string_schema("utf8-text", 128)}}, {"provider", "version"})}},
        {"architecture", "originHex", "bytesHex", "length", "boundaries", "labels", "backend"});
}

Json patch_range_schema()
{
    return closed_object_schema({{"addressHex", hex()}, {"moduleId", nullable_schema(id())}, {"rvaHex", nullable_schema(hex())},
        {"originalBytesHex", bytes()}, {"replacementBytesHex", bytes()}, {"observedBytesHex", nullable_schema(bytes())}, {"nativeTracked", bool_schema()},
        {"state", enum_schema({"planned", "applied", "restored", "conflict", "failed", "unknown"})}, {"breakpointIds", bounded_array_schema(id(), MaximumPageLimit, 0, true)},
        {"restoration", enum_schema({"not_needed", "restored", "partial", "failed", "unknown"})}},
        {"addressHex", "moduleId", "rvaHex", "originalBytesHex", "replacementBytesHex", "observedBytesHex", "nativeTracked", "state", "breakpointIds", "restoration"});
}

Json patch_set_schema()
{
    return closed_object_schema({{"patchSetId", id()}, {"revision", id()}, {"name", string_schema("utf8-text", 1024)}, {"target", reference_schema("TargetRef")},
        {"ranges", bounded_array_schema(patch_range_schema(), MaximumPageLimit, 1)}, {"ownership", enum_schema({"client", "shared", "native", "unknown"})},
        {"complete", bool_schema()}}, {"patchSetId", "revision", "name", "target", "ranges", "ownership", "complete"});
}

Json file_observation_schema()
{
    const auto section = closed_object_schema({{"name", string_schema("utf8-text", 128, 0)}, {"rvaHex", hex()}, {"virtualSize", decimal()},
        {"rawOffset", decimal()}, {"rawSize", decimal()}, {"characteristicsHex", hex()}, {"mapping", enum_schema({"valid", "ambiguous", "unmapped", "invalid"})}},
        {"name", "rvaHex", "virtualSize", "rawOffset", "rawSize", "characteristicsHex", "mapping"});
    return closed_object_schema({{"file", reference_schema("FileRef")}, {"sha256", string_schema("sha256", 64)}, {"size", decimal()},
        {"architecture", enum_schema({"x32", "x64", "unknown"})}, {"imageBaseHex", nullable_schema(hex())}, {"entryRvaHex", nullable_schema(hex())},
        {"sections", bounded_array_schema(section, MaximumPageLimit)}, {"peStatus", enum_schema({"valid", "invalid", "not_pe", "unsupported"})},
        {"overlayOffset", nullable_schema(decimal())}, {"signature", enum_schema({"absent", "valid", "invalid", "unverified", "unsupported"})},
        {"limitations", bounded_array_schema(string_schema("utf8-text", 4096), 32)}},
        {"file", "sha256", "size", "architecture", "imageBaseHex", "entryRvaHex", "sections", "peStatus", "overlayOffset", "signature", "limitations"});
}

Json file_transaction_schema()
{
    const auto changed = closed_object_schema({{"fileOffset", decimal()}, {"rvaHex", nullable_schema(hex())}, {"originalBytesHex", bytes()},
        {"replacementBytesHex", bytes()}, {"verified", bool_schema()}}, {"fileOffset", "rvaHex", "originalBytesHex", "replacementBytesHex", "verified"});
    return closed_object_schema({{"transactionId", id()}, {"mode", enum_schema({"save_as", "replace", "undo", "export"})}, {"source", nullable_schema(file_observation_schema())},
        {"published", file_observation_schema()}, {"backupArtifact", nullable_schema(reference_schema("FileRef"))}, {"changes", bounded_array_schema(changed, MaximumPageLimit)},
        {"outsidePlanPreserved", bool_schema()}, {"journalState", enum_schema({"prepared", "published", "verified", "restored", "partial", "conflict", "unknown"})},
        {"signatureImpact", enum_schema({"unchanged", "invalidated", "removed", "unknown"})}, {"runtimeVerification", enum_schema({"verified", "unverified", "unsupported"})}},
        {"transactionId", "mode", "source", "published", "backupArtifact", "changes", "outsidePlanPreserved", "journalState", "signatureImpact", "runtimeVerification"});
}
}
