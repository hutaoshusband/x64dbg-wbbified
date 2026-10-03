#include "pe_file_patch.h"
#include "platform.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace wininspect::mcp
{
namespace
{
constexpr std::size_t MaximumPeSections = 96;
constexpr std::size_t MaximumPeRelocations = 100000;

struct PlanningFailure
{
    ContractError error;
};

[[noreturn]] void fail(const char* code, const std::string& message, const std::string& path = "")
{
    throw PlanningFailure{{code, path, message}};
}

struct Span
{
    std::uint64_t start;
    std::uint64_t size;
};

bool contains(Span outer, Span inner)
{
    return inner.start >= outer.start && inner.start - outer.start <= outer.size && inner.size <= outer.size - (inner.start - outer.start);
}

bool overlaps(Span left, Span right)
{
    return left.size && right.size && (left.start <= right.start ? right.start - left.start < left.size : left.start - right.start < right.size);
}

std::uint64_t number(std::string_view source, std::uint64_t offset, unsigned width)
{
    if(!contains({0, source.size()}, {offset, width}))
        fail("unsupported_mapping", "PE field exceeds the source file");
    std::uint64_t value = 0;
    for(unsigned index = 0; index < width; ++index)
        value |= std::uint64_t(static_cast<unsigned char>(source[static_cast<std::size_t>(offset) + index])) << (index * 8);
    return value;
}

struct Section
{
    Span virtualSpan;
    Span rawSpan;
};

struct Mapping
{
    std::uint64_t rva;
    std::uint64_t fileOffset;
    std::size_t size;
};

struct Relocation
{
    std::uint32_t rva;
    unsigned kind;
    unsigned width;
    std::uint16_t low;
};

struct Layout
{
    std::uint64_t preferredBase;
    std::uint32_t imageSize;
    std::uint32_t headersSize;
    unsigned pointerBits;
    std::uint64_t overlayOffset;
    bool hasCertificate;
    Span relocationDirectory;
    std::vector<Span> metadata;
    std::vector<Section> sections;
    std::vector<Relocation> relocations;
};

std::vector<Mapping> map_rva(const Layout& layout, Span range)
{
    if(!range.size || !contains({0, layout.imageSize}, range))
        fail("unsupported_mapping", "Requested RVA range exceeds the image");
    std::vector<Mapping> result;
    while(range.size)
    {
        std::uint64_t offset = 0, available = 0;
        if(range.start < layout.headersSize)
        {
            offset = range.start;
            available = layout.headersSize - range.start;
        }
        else
            for(const auto& section : layout.sections)
                if(contains(section.virtualSpan, {range.start, 1}))
                {
                    const auto displacement = range.start - section.virtualSpan.start;
                    if(displacement >= section.rawSpan.size)
                        fail("unsupported_mapping", "Requested RVA includes a virtual-only section tail");
                    offset = section.rawSpan.start + displacement;
                    available = section.rawSpan.size - displacement;
                    break;
                }
        if(!available)
            fail("unsupported_mapping", "Requested RVA has no file backing");
        const auto size = (std::min)(available, range.size);
        result.push_back({range.start, offset, static_cast<std::size_t>(size)});
        if(result.size() > MaximumPatchRanges)
            fail("resource_limit", "Mapped range exceeds the patch range quota");
        range.start += size;
        range.size -= size;
    }
    return result;
}

std::uint64_t mapped_number(std::string_view source, const Layout& layout, std::uint64_t rva, unsigned width)
{
    std::uint64_t value = 0;
    unsigned shift = 0;
    for(const auto& part : map_rva(layout, {rva, width}))
        for(std::size_t index = 0; index < part.size; ++index)
        {
            value |= number(source, part.fileOffset + index, 1) << shift;
            shift += 8;
        }
    return value;
}

Layout parse_layout(std::string_view source)
{
    if(number(source, 0, 2) != 0x5a4d)
        fail("unsupported_mapping", "Source is not an MZ image");
    const auto pe = number(source, 0x3c, 4);
    if(pe < 0x40 || number(source, pe, 4) != 0x4550)
        fail("unsupported_mapping", "Source has no valid PE signature");
    const auto machine = number(source, pe + 4, 2);
    const auto sectionCount = number(source, pe + 6, 2);
    const auto optionalSize = number(source, pe + 20, 2);
    const auto optional = pe + 24;
    const auto magic = number(source, optional, 2);
    const bool wide = machine == 0x8664 && magic == 0x20b;
    if(!wide && (machine != 0x14c || magic != 0x10b))
        fail("unsupported_mapping", "Source requires a supported x32 or x64 PE optional header");
    const auto directoryOffset = wide ? 112u : 96u;
    if(optionalSize < directoryOffset || !contains({0, source.size()}, {optional, optionalSize}) || sectionCount > MaximumPeSections)
        fail("unsupported_mapping", "PE optional header or section table exceeds its bounds");
    Layout result{};
    result.metadata = {{0, 2}, {0x3c, 4}, {pe, 8}, {pe + 20, 2}, {optional, 2},
        {optional + (wide ? 24 : 28), wide ? 8u : 4u}, {optional + 56, 8}, {optional + directoryOffset - 4, 4}};
    result.preferredBase = number(source, optional + (wide ? 24 : 28), wide ? 8 : 4);
    result.imageSize = static_cast<std::uint32_t>(number(source, optional + 56, 4));
    result.headersSize = static_cast<std::uint32_t>(number(source, optional + 60, 4));
    result.pointerBits = wide ? 64 : 32;
    const auto sectionTable = optional + optionalSize;
    result.metadata.push_back({sectionTable, sectionCount * 40});
    if(!result.imageSize || result.headersSize < sectionTable + sectionCount * 40 || result.headersSize > source.size() || result.headersSize > result.imageSize)
        fail("unsupported_mapping", "PE headers lack complete bounded section declarations");
    const auto maximumAddress = wide ? UINT64_MAX : UINT32_MAX;
    if(result.preferredBase > maximumAddress - (result.imageSize - 1))
        fail("unsupported_mapping", "Preferred image range exceeds its pointer width");
    result.overlayOffset = result.headersSize;
    for(std::size_t index = 0; index < sectionCount; ++index)
    {
        const auto entry = sectionTable + index * 40;
        const auto virtualSize = number(source, entry + 8, 4);
        const auto rva = number(source, entry + 12, 4);
        const auto rawSize = number(source, entry + 16, 4);
        const auto rawOffset = number(source, entry + 20, 4);
        Section section{{rva, (std::max)(virtualSize, rawSize)}, {rawOffset, rawSize}};
        if(section.virtualSpan.size && (rva < result.headersSize || !contains({0, result.imageSize}, section.virtualSpan)))
            fail("unsupported_mapping", "PE section virtual extent is invalid or overlaps the headers");
        if(rawSize && (rawOffset < result.headersSize || !contains({0, source.size()}, section.rawSpan)))
            fail("unsupported_mapping", "PE section raw extent is invalid or overlaps the headers");
        for(const auto& prior : result.sections)
            if(overlaps(prior.virtualSpan, section.virtualSpan) || overlaps(prior.rawSpan, section.rawSpan))
                fail("unsupported_mapping", "PE sections have ambiguous virtual or raw extents");
        if(rawSize)
            result.overlayOffset = (std::max)(result.overlayOffset, rawOffset + rawSize);
        result.sections.push_back(section);
    }
    const auto directoryCount = number(source, optional + directoryOffset - 4, 4);
    if(directoryCount > 16 || directoryCount * 8 > optionalSize - directoryOffset)
        fail("unsupported_mapping", "PE data directory count exceeds the declared optional header");
    if(directoryCount > 4)
    {
        const auto offset = number(source, optional + directoryOffset + 32, 4);
        const auto size = number(source, optional + directoryOffset + 36, 4);
        if(bool(offset) != bool(size) || (size && (offset < result.overlayOffset || offset % 8 || !contains({0, source.size()}, {offset, size}))))
            fail("unsupported_mapping", "PE certificate directory has invalid file bounds");
        result.hasCertificate = size != 0;
    }
    if(directoryCount <= 5)
        return result;
    result.relocationDirectory = {number(source, optional + directoryOffset + 40, 4), number(source, optional + directoryOffset + 44, 4)};
    result.metadata.push_back({optional + directoryOffset + 40, 8});
    if(bool(result.relocationDirectory.start) != bool(result.relocationDirectory.size))
        fail("unsupported_mapping", "PE relocation directory has incomplete bounds");
    if(!result.relocationDirectory.size)
        return result;
    if(result.relocationDirectory.start % 4)
        fail("unsupported_mapping", "PE relocation blocks lack their required DWORD alignment");
    for(const auto& mapping : map_rva(result, result.relocationDirectory))
        result.metadata.push_back({mapping.fileOffset, mapping.size});
    std::uint64_t consumed = 0;
    std::size_t slots = 0, blocks = 0;
    while(consumed < result.relocationDirectory.size)
    {
        if(++blocks > MaximumPeRelocations)
            fail("resource_limit", "PE relocation blocks exceed the planning quota");
        const auto remaining = result.relocationDirectory.size - consumed;
        if(remaining < 8)
            fail("unsupported_mapping", "PE relocation directory has a truncated block");
        const auto block = result.relocationDirectory.start + consumed;
        const auto page = mapped_number(source, result, block, 4);
        const auto size = mapped_number(source, result, block + 4, 4);
        if(page % 4096 || size < 8 || size % 4 || size > remaining)
            fail("unsupported_mapping", "PE relocation block has invalid size or page alignment");
        for(std::uint64_t offset = 8; offset < size; offset += 2)
        {
            if(++slots > MaximumPeRelocations)
                fail("resource_limit", "PE relocation entries exceed the planning quota");
            const auto entry = mapped_number(source, result, block + offset, 2);
            const auto kind = static_cast<unsigned>(entry >> 12);
            if(!kind)
                continue;
            const auto width = kind == 1 || kind == 2 || kind == 4 ? 2u : kind == 3 ? 4u : kind == 10 ? 8u : 0u;
            if(!width)
                fail("unsupported_mapping", "PE relocation type has no supported x86 arithmetic");
            const auto rva = page + (entry & 0xfff);
            map_rva(result, {rva, width});
            std::uint16_t low = 0;
            if(kind == 4)
            {
                if(offset + 4 > size)
                    fail("unsupported_mapping", "HIGHADJ relocation lacks its signed addend");
                if(++slots > MaximumPeRelocations)
                    fail("resource_limit", "PE relocation entries exceed the planning quota");
                offset += 2;
                low = static_cast<std::uint16_t>(mapped_number(source, result, block + offset, 2));
            }
            result.relocations.push_back({static_cast<std::uint32_t>(rva), kind, width, low});
        }
        consumed += size;
    }
    std::sort(result.relocations.begin(), result.relocations.end(), [](const auto& left, const auto& right) { return left.rva < right.rva; });
    for(std::size_t index = 1; index < result.relocations.size(); ++index)
    {
        const auto& previous = result.relocations[index - 1];
        const auto& current = result.relocations[index];
        if(overlaps({previous.rva, previous.width}, {current.rva, current.width}))
            fail("unsupported_mapping", "PE relocation fields overlap or repeat");
    }
    return result;
}

void normalize(PatchBytes& bytes, std::size_t offset, const Relocation& relocation, std::uint64_t delta)
{
    const auto value = number(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), offset, relocation.width);
    const auto adjustment = relocation.kind == 1 ? delta >> 16 : relocation.kind == 2 ? delta & 0xffff : relocation.kind == 4 ?
        static_cast<std::uint32_t>(delta + static_cast<std::int16_t>(relocation.low) + 0x8000u) >> 16 : delta;
    const auto normalized = value - adjustment;
    for(unsigned index = 0; index < relocation.width; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(normalized >> (index * 8));
}

std::optional<ContractError> ranges_valid(const std::vector<PePlannedRange>& ranges, std::size_t sourceSize)
{
    if(ranges.empty() || ranges.size() > MaximumPatchRanges)
        return ContractError{"invalid_argument", "/ranges", "File plan requires bounded nonempty ranges"};
    std::size_t total = 0;
    for(std::size_t index = 0; index < ranges.size(); ++index)
    {
        const auto& range = ranges[index];
        const auto size = range.expected.size();
        if(!size || size != range.replacement.size() || size > MaximumPatchBytes - total || !contains({0, sourceSize}, {range.fileOffset, size}))
            return ContractError{"invalid_argument", "/ranges/" + std::to_string(index), "File plan range has invalid size or extent"};
        for(std::size_t prior = 0; prior < index; ++prior)
            if(overlaps({ranges[prior].fileOffset, ranges[prior].expected.size()}, {range.fileOffset, size}))
                return ContractError{"invalid_argument", "/ranges/" + std::to_string(index), "File plan ranges overlap"};
        total += size;
    }
    return {};
}
}

Checked<PeFilePatchPlan> plan_pe_file_patch(std::string_view source, std::uint64_t loadedBase, const std::vector<PePatchRequest>& requests)
{
    try
    {
        if(requests.empty() || requests.size() > MaximumPatchRanges)
            fail("invalid_argument", "File patch requests require bounded nonempty ranges", "/ranges");
        const auto digest = sha256_file_bytes(source);
        if(const auto* error = std::get_if<ContractError>(&digest))
            return *error;
        const auto layout = parse_layout(source);
        PeFilePatchPlan plan{source.size(), std::get<std::string>(digest), layout.preferredBase, layout.imageSize, layout.pointerBits,
            layout.overlayOffset, layout.hasCertificate, {}};
        std::size_t total = 0;
        for(std::size_t index = 0; index < requests.size(); ++index)
        {
            const auto path = "/ranges/" + std::to_string(index);
            const auto& request = requests[index];
            const auto size = request.expected.size();
            if(!size || size != request.replacement.size() || size > MaximumPatchBytes - total)
                fail("invalid_argument", "Patch bytes exceed their length or aggregate quota", path);
            total += size;
            if(request.domain != PePatchAddress::FileOffset && request.domain != PePatchAddress::Rva && request.domain != PePatchAddress::LoadedVa)
                fail("invalid_argument", "Unknown PE patch address domain", path);
            if(request.encoding != PePatchEncoding::FileBytes && request.encoding != PePatchEncoding::LoadedBytes)
                fail("invalid_argument", "Unknown PE patch byte encoding", path);
            if(request.encoding == PePatchEncoding::LoadedBytes && request.domain == PePatchAddress::FileOffset)
                fail("invalid_argument", "Loaded bytes require an explicit image address", path);
            std::uint64_t rva = request.address;
            if(request.domain == PePatchAddress::LoadedVa || request.encoding == PePatchEncoding::LoadedBytes)
            {
                const auto maximum = layout.pointerBits == 32 ? UINT32_MAX : UINT64_MAX;
                if(!loadedBase || loadedBase > maximum - (layout.imageSize - 1))
                    fail("invalid_argument", "Actual loaded image exceeds its pointer width", path);
                if(request.domain == PePatchAddress::LoadedVa)
                {
                    if(request.address < loadedBase)
                        fail("unsupported_mapping", "Loaded address precedes its image", path);
                    rva -= loadedBase;
                }
            }
            const auto mappings = request.domain == PePatchAddress::FileOffset ? std::vector<Mapping>{{rva, request.address, size}} : map_rva(layout, {rva, size});
            auto expected = request.expected, replacement = request.replacement;
            std::size_t normalized = 0;
            if(request.encoding == PePatchEncoding::LoadedBytes)
            {
                if(overlaps({rva, size}, layout.relocationDirectory))
                    fail("unsupported_mapping", "Runtime bytes cannot mutate their own relocation declarations", path);
                auto first = std::lower_bound(layout.relocations.begin(), layout.relocations.end(), rva,
                    [](const auto& relocation, auto address) { return std::uint64_t(relocation.rva) + relocation.width <= address; });
                for(auto current = first; current != layout.relocations.end() && current->rva < rva + size; ++current)
                {
                    const auto& relocation = *current;
                    if(overlaps({rva, size}, {relocation.rva, relocation.width}))
                    {
                        if(!contains({rva, size}, {relocation.rva, relocation.width}))
                            fail("unsupported_mapping", "Runtime patch includes an incomplete relocation field", path);
                        const auto offset = static_cast<std::size_t>(relocation.rva - rva);
                        normalize(expected, offset, relocation, loadedBase - layout.preferredBase);
                        normalize(replacement, offset, relocation, loadedBase - layout.preferredBase);
                        ++normalized;
                    }
                }
            }
            std::size_t consumed = 0;
            for(const auto& mapping : mappings)
            {
                if(!contains({0, source.size()}, {mapping.fileOffset, mapping.size}))
                    fail("unsupported_mapping", "Patch file offset exceeds the source", path);
                PatchBytes old(expected.begin() + consumed, expected.begin() + consumed + mapping.size);
                PatchBytes changed(replacement.begin() + consumed, replacement.begin() + consumed + mapping.size);
                for(std::size_t byte = 0; byte < old.size(); ++byte)
                    if(static_cast<unsigned char>(source[static_cast<std::size_t>(mapping.fileOffset) + byte]) != old[byte])
                        fail("expected_bytes_mismatch", "Normalized expected bytes differ from the source file", path);
                plan.ranges.push_back({mapping.fileOffset, std::move(old), std::move(changed), consumed ? 0 : normalized});
                consumed += mapping.size;
            }
        }
        if(auto error = ranges_valid(plan.ranges, source.size()))
            return *error;
        if(std::any_of(requests.begin(), requests.end(), [](const auto& request) { return request.encoding == PePatchEncoding::LoadedBytes; }))
            for(const auto& range : plan.ranges)
                if(range.expected != range.replacement)
                    for(const auto& metadata : layout.metadata)
                        if(overlaps({range.fileOffset, range.expected.size()}, metadata))
                            fail("unsupported_mapping", "Loaded-byte plans cannot rewrite their source layout or relocation arithmetic");
        return plan;
    }
    catch(const PlanningFailure& failure)
    {
        return failure.error;
    }
    catch(const std::exception& error)
    {
        return ContractError{"internal_error", "", error.what()};
    }
}

Checked<std::string> render_pe_file_patch(std::string_view source, const PeFilePatchPlan& plan)
{
    try
    {
        if(source.size() != plan.sourceSize)
            return ContractError{"file_hash_mismatch", "", "Source file size differs from the admitted plan"};
        const auto digest = sha256_file_bytes(source);
        if(const auto* error = std::get_if<ContractError>(&digest))
            return *error;
        if(std::get<std::string>(digest) != plan.sourceSha256)
            return ContractError{"file_hash_mismatch", "", "Source bytes differ from the admitted plan"};
        if(auto error = ranges_valid(plan.ranges, source.size()))
            return *error;
        for(const auto& range : plan.ranges)
            for(std::size_t index = 0; index < range.expected.size(); ++index)
                if(static_cast<unsigned char>(source[static_cast<std::size_t>(range.fileOffset) + index]) != range.expected[index])
                    return ContractError{"expected_bytes_mismatch", "", "Planned source bytes differ before rendering"};
        std::string output(source);
        for(const auto& range : plan.ranges)
            std::copy(range.replacement.begin(), range.replacement.end(), output.begin() + static_cast<std::size_t>(range.fileOffset));
        return output;
    }
    catch(const std::exception& error)
    {
        return ContractError{"internal_error", "", error.what()};
    }
}
}
