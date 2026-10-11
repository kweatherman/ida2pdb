
// PE32/PE32+ and CodeView RSDS debug section parser
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// PE image read result
enum class PeIo
{
	Ok,
	Unavailable,
	Truncated
};

// Read bytes from a PE image.
using PeReadFn = PeIo (*)(void* context, uint64_t offset, void* destination, size_t size);

// PE image parsing result
enum class PeParseStatus
{
	Ok,
	MissingBytes,
	Malformed,
	Unsupported
};

// PE section container
struct PeSection
{
	char name[9];
	uint32_t virtualSize;
	uint32_t virtualAddress;
	uint32_t sizeOfRawData;
	uint32_t pointerToRawData;
	uint32_t characteristics;
};

// Checked PE32 or PE32+ image and CodeView RSDS identity
struct PeImage
{
	PeParseStatus status = PeParseStatus::Malformed;
	std::string detail;

	bool hasMachine = false;
	uint16_t machine = 0;
	bool pe32Plus = false;

	bool hasImageBase = false;
	uint64_t originalImageBase = 0;
	uint32_t sizeOfImage = 0;
	uint32_t sizeOfHeaders = 0;
	uint32_t entryRva = 0;

	bool hasSections = false;
	std::vector<PeSection> sections;

	bool hasRsds = false;
	uint32_t rsdsFileOffset = 0;
	uint8_t guid[16] = {};
	uint32_t age = 0;
	std::string pdbPath;
	std::string pdbBasename;
};

// Result of mapping and address into the image
enum class MapStatus
{
	Ok,
	BelowImage,
	OutsideImage,
	Unmapped
};

// Section, RVA, and file offset for a mapped address.
struct MappedAddress
{
	uint64_t ea;
	uint64_t rva;
	uint32_t sectionIndex;
	uint32_t sectionOffset;
	bool hasFileOffset;
	uint32_t fileOffset;
};

// Parse a PE32 or PE32+ image and its RSDS identity.
PeImage parse_pe_image(PeReadFn read, void* context, uint64_t fileSize);

// Return whether two images share machine, base, and section layout.
bool pe_layouts_compatible(const PeImage& idbImage, const PeImage& fileImage, std::string& why);

// Map an address to its section, RVA, and file offset.
MapStatus map_ea(uint64_t ea, uint64_t currentImageBase, const PeImage& image, MappedAddress& mapped);

// Format a CodeView GUID as text.
std::string format_guid(const uint8_t guid[16]);

// Update a zlib CRC32.
uint32_t crc32_zlib(uint32_t crc, const void* data, size_t size);
