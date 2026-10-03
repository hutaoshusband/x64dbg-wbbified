#pragma once

#include "contracts.h"
#include "patch_transaction.h"
#include <string_view>

namespace wininspect::mcp
{
enum class PePatchAddress { FileOffset, Rva, LoadedVa };
enum class PePatchEncoding { FileBytes, LoadedBytes };

struct PePatchRequest
{
    PePatchAddress domain;
    std::uint64_t address;
    PePatchEncoding encoding;
    PatchBytes expected;
    PatchBytes replacement;
};

struct PePlannedRange
{
    std::uint64_t fileOffset;
    PatchBytes expected;
    PatchBytes replacement;
    std::size_t normalizedRelocations;
};

struct PeFilePatchPlan
{
    std::uint64_t sourceSize;
    std::string sourceSha256;
    std::uint64_t preferredBase;
    std::uint32_t imageSize;
    unsigned pointerBits;
    std::uint64_t overlayOffset;
    bool hasCertificate;
    std::vector<PePlannedRange> ranges;
};

Checked<PeFilePatchPlan> plan_pe_file_patch(std::string_view source, std::uint64_t loadedBase, const std::vector<PePatchRequest>& requests);
Checked<std::string> render_pe_file_patch(std::string_view source, const PeFilePatchPlan& plan);
}
