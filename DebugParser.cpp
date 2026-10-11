
// PE32/PE32+ and CodeView RSDS debug section parser
#include "DebugParser.h"

#include <cstdio>
#include <cstring>

namespace {

constexpr uint16_t kDosMagic = 0x5A4D;
constexpr uint32_t kPeSignature = 0x00004550;
constexpr uint16_t kPe32Magic = 0x10B;
constexpr uint16_t kPe32PlusMagic = 0x20B;
constexpr uint16_t kMachineI386 = 0x14C;
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint32_t kDebugTypeCodeView = 2;
constexpr uint32_t kRsdsSignature = 0x53445352;
constexpr uint32_t kNb10Signature = 0x3031424E;
constexpr size_t kSectionBytes = 40;
constexpr size_t kDebugEntryBytes = 28;
constexpr size_t kMaxSections = 96;
constexpr size_t kMaxDebugEntries = 32;
constexpr size_t kMaxRsdsBytes = 1024;

// PE image read tracking
struct Reader
{
	PeReadFn read;
	void* context;
	uint64_t fileSize;
	PeIo last;
};

// Return whether a byte range lies inside the file.
bool range_in_file(uint64_t offset, uint64_t length, uint64_t fileSize)
{
	return length <= fileSize && offset <= fileSize - length;
}

// Read a range through the PE reader.
bool load(Reader& reader, uint64_t offset, void* destination, size_t size)
{
	if (!range_in_file(offset, size, reader.fileSize))
	{
		reader.last = PeIo::Truncated;
		return false;
	}
	reader.last = reader.read(reader.context, offset, destination, size);
	return reader.last == PeIo::Ok;
}

// Read a little-endian 16-bit value.
bool read_u16(Reader& reader, uint64_t offset, uint16_t& value)
{
	uint8_t bytes[2];
	if (!load(reader, offset, bytes, sizeof(bytes)))
		return false;
	value = uint16_t(bytes[0] | (uint16_t(bytes[1]) << 8));
	return true;
}

// Read a little-endian 32-bit value.
bool read_u32(Reader& reader, uint64_t offset, uint32_t& value)
{
	uint8_t bytes[4];
	if (!load(reader, offset, bytes, sizeof(bytes)))
		return false;
	value = uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
	return true;
}

// Read a little-endian 64-bit value.
bool read_u64(Reader& reader, uint64_t offset, uint64_t& value)
{
	uint32_t low = 0;
	uint32_t high = 0;
	if (!read_u32(reader, offset, low) || !read_u32(reader, offset + 4, high))
		return false;
	value = uint64_t(low) | (uint64_t(high) << 32);
	return true;
}

// Return failed parse result
PeImage fail(PeParseStatus status, const std::string& detail)
{
	PeImage image;
	image.status = status;
	image.detail = detail;
	return image;
}

// Return the parse status for the last read failure.
PeParseStatus io_status(const Reader& reader)
{
	if (reader.last == PeIo::Unavailable)
		return PeParseStatus::MissingBytes;
	return PeParseStatus::Malformed;
}

// PE section name into a string.
std::string section_name(const uint8_t raw[8])
{
	char name[9] = {};
	size_t length = 0;
	while (length < 8 && raw[length] != 0)
		++length;
	std::memcpy(name, raw, length);
	return name;
}

// Map an RVA range to a file offset.
bool map_rva_to_file(const PeImage& image, uint32_t rva, uint32_t size, uint32_t& fileOffset)
{
	if (size == 0)
		return false;
	const uint64_t end = uint64_t(rva) + size;
	if (end < rva)
		return false;
	for (const PeSection& section : image.sections)
	{
		const uint64_t rawEnd = uint64_t(section.virtualAddress) + section.sizeOfRawData;
		if (section.sizeOfRawData == 0)
			continue;
		if (uint64_t(rva) < section.virtualAddress || end > rawEnd)
			continue;
		const uint32_t delta = rva - section.virtualAddress;
		const uint64_t offset = uint64_t(section.pointerToRawData) + delta;
		if (offset > 0xFFFFFFFFu || offset + size < offset)
			return false;
		fileOffset = uint32_t(offset);
		return true;
	}
	return false;
}

} // namespace

// Format a CodeView GUID
std::string format_guid(const uint8_t guid[16])
{
	char text[40];
	const uint32_t data1 = uint32_t(guid[0]) | (uint32_t(guid[1]) << 8) | (uint32_t(guid[2]) << 16) | (uint32_t(guid[3]) << 24);
	const uint16_t data2 = uint16_t(guid[4] | (uint16_t(guid[5]) << 8));
	const uint16_t data3 = uint16_t(guid[6] | (uint16_t(guid[7]) << 8));
	std::snprintf(
		text,
		sizeof(text),
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1,
		data2,
		data3,
		guid[8],
		guid[9],
		guid[10],
		guid[11],
		guid[12],
		guid[13],
		guid[14],
		guid[15]);
	return text;
}

// Update a zlib CRC32
uint32_t crc32_zlib(uint32_t crc, const void* data, size_t size)
{
	struct Table
	{
		uint32_t entry[256];
		Table()
		{
			for (uint32_t index = 0; index < 256; ++index)
			{
				uint32_t value = index;
				for (int bit = 0; bit < 8; ++bit)
					value = (value >> 1) ^ (0xEDB88320u & (0u - (value & 1u)));
				entry[index] = value;
			}
		}
	};
	static const Table table;
	const auto* bytes = static_cast<const uint8_t*>(data);
	uint32_t value = crc ^ 0xFFFFFFFFu;
	for (size_t index = 0; index < size; ++index)
		value = (value >> 8) ^ table.entry[(value ^ bytes[index]) & 0xFFu];
	return value ^ 0xFFFFFFFFu;
}

// Parse a PE32 or PE32+ image and its RSDS identity.
PeImage parse_pe_image(PeReadFn read, void* context, uint64_t fileSize)
{
	Reader reader{ read, context, fileSize, PeIo::Ok };
	PeImage image;
	const auto ioFail = [&](const char* detail) -> PeImage {
		image.status = io_status(reader);
		image.detail = detail;
		return image;
	};
	if (fileSize < 0x40)
		return fail(PeParseStatus::Malformed, "The input is shorter than a DOS header.");

	uint16_t dosMagic = 0;
	uint32_t peOffset = 0;
	if (!read_u16(reader, 0, dosMagic) || !read_u32(reader, 0x3C, peOffset))
	{
		image.status = io_status(reader);
		image.detail = "The DOS header could not be read.";
		return image;
	}
	if (dosMagic != kDosMagic)
		return fail(PeParseStatus::Malformed, "The DOS signature is not MZ.");
	if (peOffset < 0x40 || !range_in_file(peOffset, 24, fileSize))
		return fail(PeParseStatus::Malformed, "The PE header offset is outside the input.");

	uint32_t signature = 0;
	uint16_t machine = 0;
	uint16_t sectionCount = 0;
	uint16_t optionalSize = 0;
	if (!read_u32(reader, peOffset, signature) || !read_u16(reader, peOffset + 4, machine) || !read_u16(reader, peOffset + 6, sectionCount) || !read_u16(reader, peOffset + 20, optionalSize))
	{
		image.status = io_status(reader);
		image.detail = "The COFF header could not be read.";
		return image;
	}
	if (signature != kPeSignature)
		return fail(PeParseStatus::Malformed, "The PE signature is missing.");
	if (machine != kMachineI386 && machine != kMachineAmd64)
	{
		image.status = PeParseStatus::Unsupported;
		image.detail = "Only PE32 x86 and PE32+ AMD64 images are supported.";
		image.hasMachine = true;
		image.machine = machine;
		return image;
	}
	if (sectionCount == 0 || sectionCount > kMaxSections)
		return fail(PeParseStatus::Malformed, "The section count is zero or larger than 96.");
	image.hasMachine = true;
	image.machine = machine;

	const uint64_t optional = uint64_t(peOffset) + 24;
	if (!range_in_file(optional, optionalSize, fileSize) || optionalSize < 2)
		return fail(PeParseStatus::Malformed, "The optional header does not fit in the input.");
	uint16_t magic = 0;
	if (!read_u16(reader, optional, magic))
		return ioFail("The optional header magic could not be read.");

	uint32_t directoryOffset = 0;
	if (magic == kPe32Magic)
	{
		if (machine != kMachineI386)
			return fail(PeParseStatus::Malformed, "PE32 magic does not match the AMD64 machine.");
		if (optionalSize < 28 + 4)
			return fail(PeParseStatus::Malformed, "The PE32 optional header is too small.");
		uint32_t imageBase = 0;
		if (!read_u32(reader, optional + 28, imageBase))
			return ioFail("The PE32 image base could not be read.");
		image.originalImageBase = imageBase;
		image.pe32Plus = false;
		directoryOffset = 96;
	}
	else if (magic == kPe32PlusMagic)
	{
		if (machine != kMachineAmd64)
			return fail(PeParseStatus::Malformed, "PE32+ magic does not match the x86 machine.");
		if (optionalSize < 24 + 8)
			return fail(PeParseStatus::Malformed, "The PE32+ optional header is too small.");
		if (!read_u64(reader, optional + 24, image.originalImageBase))
			return ioFail("The PE32+ image base could not be read.");
		image.pe32Plus = true;
		directoryOffset = 112;
	}
	else
	{
		return fail(PeParseStatus::Malformed, "The optional header magic is not PE32 or PE32+.");
	}
	image.hasImageBase = true;

	if (!read_u32(reader, optional + 16, image.entryRva) || !read_u32(reader, optional + 56, image.sizeOfImage) || !read_u32(reader, optional + 60, image.sizeOfHeaders))
		return ioFail("The optional header sizes could not be read.");
	if (image.sizeOfImage == 0 || image.sizeOfHeaders == 0 || image.sizeOfHeaders > fileSize)
		return fail(PeParseStatus::Malformed, "SizeOfImage or SizeOfHeaders is invalid.");

	const uint64_t sectionTable = optional + optionalSize;
	if (!range_in_file(sectionTable, uint64_t(sectionCount) * kSectionBytes, fileSize))
		return fail(PeParseStatus::Malformed, "The section table does not fit in the input.");
	image.sections.reserve(sectionCount);
	for (uint16_t index = 0; index < sectionCount; ++index)
	{
		const uint64_t at = sectionTable + uint64_t(index) * kSectionBytes;
		uint8_t raw[kSectionBytes];
		if (!load(reader, at, raw, sizeof(raw)))
			return ioFail("A section header could not be read.");
		PeSection section = {};
		const std::string name = section_name(raw);
		std::memcpy(section.name, name.c_str(), name.size());
		section.virtualSize = uint32_t(raw[8]) | (uint32_t(raw[9]) << 8) | (uint32_t(raw[10]) << 16) | (uint32_t(raw[11]) << 24);
		section.virtualAddress = uint32_t(raw[12]) | (uint32_t(raw[13]) << 8) | (uint32_t(raw[14]) << 16) | (uint32_t(raw[15]) << 24);
		section.sizeOfRawData = uint32_t(raw[16]) | (uint32_t(raw[17]) << 8) | (uint32_t(raw[18]) << 16) | (uint32_t(raw[19]) << 24);
		section.pointerToRawData = uint32_t(raw[20]) | (uint32_t(raw[21]) << 8) | (uint32_t(raw[22]) << 16) | (uint32_t(raw[23]) << 24);
		section.characteristics = uint32_t(raw[36]) | (uint32_t(raw[37]) << 8) | (uint32_t(raw[38]) << 16) | (uint32_t(raw[39]) << 24);
		if (uint64_t(section.virtualAddress) + section.virtualSize < section.virtualAddress)
			return fail(PeParseStatus::Malformed, "A section virtual range overflows.");
		if (section.virtualSize != 0 && uint64_t(section.virtualAddress) + section.virtualSize > image.sizeOfImage)
			return fail(PeParseStatus::Malformed, "A section extends past SizeOfImage.");
		if (section.sizeOfRawData != 0 && !range_in_file(section.pointerToRawData, section.sizeOfRawData, fileSize))
			return fail(PeParseStatus::Malformed, "A section's raw bytes extend past the input.");
		image.sections.push_back(section);
	}
	image.hasSections = true;

	uint32_t directoryCount = 0;
	if (optionalSize < directoryOffset + 4)
	{
		image.status = PeParseStatus::Unsupported;
		image.detail = "The PE header has no data directories.";
		return image;
	}
	if (!read_u32(reader, optional + directoryOffset - 4, directoryCount))
		return ioFail("The data-directory count could not be read.");
	if (directoryCount > 16)
		return fail(PeParseStatus::Malformed, "The data-directory count is larger than 16.");
	if (directoryCount <= 6)
	{
		image.status = PeParseStatus::Unsupported;
		image.detail = "The PE header has no debug directory.";
		return image;
	}
	const uint64_t debugDirInfo = optional + directoryOffset + 6 * 8;
	if (optionalSize < directoryOffset + (6 + 1) * 8)
		return fail(PeParseStatus::Malformed, "The optional header claims a debug directory it does not contain.");
	uint32_t debugRva = 0;
	uint32_t debugSize = 0;
	if (!read_u32(reader, debugDirInfo, debugRva) || !read_u32(reader, debugDirInfo + 4, debugSize))
		return ioFail("The debug data directory could not be read.");
	if (debugRva == 0 || debugSize == 0)
	{
		image.status = PeParseStatus::Unsupported;
		image.detail = "The PE debug directory is empty.";
		return image;
	}
	if (debugSize % kDebugEntryBytes != 0 || debugSize / kDebugEntryBytes > kMaxDebugEntries)
		return fail(PeParseStatus::Malformed, "The debug directory size is not a short multiple of 28 bytes.");
	uint32_t debugFile = 0;
	if (!map_rva_to_file(image, debugRva, debugSize, debugFile))
		return fail(PeParseStatus::Malformed, "The debug directory RVA is outside section raw data.");

	bool sawLegacy = false;
	bool sawOther = false;
	const char* malformed = nullptr;
	const uint32_t entryCount = debugSize / uint32_t(kDebugEntryBytes);
	for (uint32_t index = 0; index < entryCount; ++index)
	{
		const uint64_t at = uint64_t(debugFile) + uint64_t(index) * kDebugEntryBytes;
		uint8_t raw[kDebugEntryBytes];
		if (!load(reader, at, raw, sizeof(raw)))
			return ioFail("A debug directory entry could not be read.");
		const uint32_t type = uint32_t(raw[12]) | (uint32_t(raw[13]) << 8) | (uint32_t(raw[14]) << 16) | (uint32_t(raw[15]) << 24);
		const uint32_t dataSize = uint32_t(raw[16]) | (uint32_t(raw[17]) << 8) | (uint32_t(raw[18]) << 16) | (uint32_t(raw[19]) << 24);
		const uint32_t dataRva = uint32_t(raw[20]) | (uint32_t(raw[21]) << 8) | (uint32_t(raw[22]) << 16) | (uint32_t(raw[23]) << 24);
		const uint32_t dataFile = uint32_t(raw[24]) | (uint32_t(raw[25]) << 8) | (uint32_t(raw[26]) << 16) | (uint32_t(raw[27]) << 24);
		if (type != kDebugTypeCodeView)
		{
			sawOther = true;
			continue;
		}
		// A bad CodeView entry is remembered, and a later valid RSDS entry can still be used.
		if (dataSize < 4 || dataSize > kMaxRsdsBytes)
		{
			malformed = "The CodeView debug data size is invalid.";
			continue;
		}
		uint32_t mappedFile = 0;
		if (!map_rva_to_file(image, dataRva, dataSize, mappedFile))
		{
			malformed = "The CodeView data RVA is outside section raw data.";
			continue;
		}
		if (dataFile != 0 && dataFile != mappedFile)
		{
			malformed = "The CodeView file offset does not match its RVA.";
			continue;
		}
		std::vector<uint8_t> data(dataSize);
		if (!load(reader, mappedFile, data.data(), data.size()))
			return ioFail("The CodeView data could not be read.");
		const uint32_t codeView = uint32_t(data[0]) | (uint32_t(data[1]) << 8) | (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
		if (codeView == kNb10Signature)
		{
			sawLegacy = true;
			continue;
		}
		if (codeView != kRsdsSignature)
		{
			malformed = "The CodeView record is neither RSDS nor NB10.";
			continue;
		}
		// RSDS: signature, 16-byte GUID, age, then a NUL-terminated path.
		if (dataSize < 25)
		{
			malformed = "The RSDS record is too short to hold a PDB path.";
			continue;
		}
		const char* pathStart = reinterpret_cast<const char*>(data.data() + 24);
		const void* terminator = std::memchr(pathStart, 0, dataSize - 24);
		if (terminator == nullptr)
		{
			malformed = "The RSDS PDB path is not terminated inside the debug data.";
			continue;
		}
		const std::string pdbPath(pathStart, static_cast<const char*>(terminator));
		const size_t slash = pdbPath.find_last_of("\\/");
		const std::string pdbBasename = slash == std::string::npos ? pdbPath : pdbPath.substr(slash + 1);
		if (pdbBasename.empty())
		{
			malformed = "The RSDS PDB path has an empty file name.";
			continue;
		}
		std::memcpy(image.guid, data.data() + 4, 16);
		image.age = uint32_t(data[20]) | (uint32_t(data[21]) << 8) | (uint32_t(data[22]) << 16) | (uint32_t(data[23]) << 24);
		image.pdbPath = pdbPath;
		image.pdbBasename = pdbBasename;
		image.hasRsds = true;
		image.rsdsFileOffset = mappedFile;
		image.status = PeParseStatus::Ok;
		image.detail.clear();
		return image;
	}

	if (malformed != nullptr)
	{
		image.status = PeParseStatus::Malformed;
		image.detail = malformed;
		return image;
	}
	image.status = PeParseStatus::Unsupported;
	if (sawLegacy)
		image.detail = "Only an NB10 CodeView record is present. RSDS GUID/age identity is required.";
	else if (sawOther)
		image.detail = "The debug directory has no RSDS identity. Checksum and feature entries are not a PDB identity.";
	else
		image.detail = "The debug directory has no CodeView record.";
	return image;
}

// Return whether two images share machine, base, and section layout.
bool pe_layouts_compatible(const PeImage& idbImage, const PeImage& fileImage, std::string& why)
{
	if (!idbImage.hasMachine || !idbImage.hasImageBase || !idbImage.hasSections)
	{
		why = "The database does not have a PE layout to compare.";
		return false;
	}
	if (!fileImage.hasMachine || !fileImage.hasImageBase || !fileImage.hasSections)
	{
		why = "The file does not have a PE layout.";
		return false;
	}
	if (idbImage.machine != fileImage.machine || idbImage.pe32Plus != fileImage.pe32Plus)
	{
		why = "The file machine does not match the database.";
		return false;
	}
	if (idbImage.originalImageBase != fileImage.originalImageBase)
	{
		why = "The file image base does not match the database.";
		return false;
	}
	if (idbImage.sections.size() != fileImage.sections.size())
	{
		why = "The file section count does not match the database.";
		return false;
	}
	for (size_t index = 0; index < idbImage.sections.size(); ++index)
	{
		const PeSection& left = idbImage.sections[index];
		const PeSection& right = fileImage.sections[index];
		if (std::strcmp(left.name, right.name) != 0 || left.virtualAddress != right.virtualAddress || left.virtualSize != right.virtualSize || left.sizeOfRawData != right.sizeOfRawData || left.pointerToRawData != right.pointerToRawData)
		{
			why = "The file section table does not match the database.";
			return false;
		}
	}
	why.clear();
	return true;
}

// Map an address to its section, RVA, and file offset.
MapStatus map_ea(uint64_t ea, uint64_t currentImageBase, const PeImage& image, MappedAddress& mapped)
{
	mapped = {};
	mapped.ea = ea;
	if (ea < currentImageBase)
		return MapStatus::BelowImage;
	const uint64_t rva64 = ea - currentImageBase;
	if (rva64 > 0xFFFFFFFFu || (image.sizeOfImage != 0 && rva64 >= image.sizeOfImage))
		return MapStatus::OutsideImage;
	mapped.rva = rva64;
	const uint32_t rva = uint32_t(rva64);

	if (image.sizeOfHeaders != 0 && rva < image.sizeOfHeaders)
	{
		bool inSection = false;
		for (const PeSection& section : image.sections)
		{
			if (section.virtualAddress <= rva && uint64_t(rva) < uint64_t(section.virtualAddress) + section.virtualSize)
				inSection = true;
		}
		if (!inSection)
		{
			mapped.sectionIndex = 0;
			mapped.sectionOffset = rva;
			mapped.hasFileOffset = true;
			mapped.fileOffset = rva;
			return MapStatus::Ok;
		}
	}

	uint32_t index = 1;
	for (const PeSection& section : image.sections)
	{
		const uint64_t virtualEnd = uint64_t(section.virtualAddress) + (section.virtualSize != 0 ? section.virtualSize : section.sizeOfRawData);
		if (uint64_t(rva) >= section.virtualAddress && uint64_t(rva) < virtualEnd)
		{
			mapped.sectionIndex = index;
			mapped.sectionOffset = rva - section.virtualAddress;
			if (section.sizeOfRawData != 0 && mapped.sectionOffset < section.sizeOfRawData)
			{
				mapped.hasFileOffset = true;
				mapped.fileOffset = section.pointerToRawData + mapped.sectionOffset;
			}
			return MapStatus::Ok;
		}
		++index;
	}
	return MapStatus::Unmapped;
}
