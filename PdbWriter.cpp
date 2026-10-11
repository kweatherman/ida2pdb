
// Public-symbol PDB writer
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "PdbWriter.h"
#include "SymbolStore.h"

// LLVM headers
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244) // LLVM BinaryStreamArray.h narrowing conversion.
#endif

#include "llvm/BinaryFormat/COFF.h"
#include "llvm/DebugInfo/CodeView/CodeView.h"
#include "llvm/DebugInfo/CodeView/GUID.h"
#include "llvm/DebugInfo/MSF/MSFBuilder.h"
#include "llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h"
#include "llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h"
#include "llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h"
#include "llvm/DebugInfo/PDB/Native/PDBFileBuilder.h"
#include "llvm/DebugInfo/PDB/Native/RawConstants.h"
#include "llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h"
#include "llvm/DebugInfo/PDB/PDBTypes.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/Error.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// LLVM drops the tail of a public name that cannot fit in a CodeView record.
// Refuse those names here so a published PDB never contains a shortened name.
constexpr uint32_t kMaxPublicName = 0xF000;

// Consume an LLVM error and store its text
bool failed(llvm::Error error, std::string& detail)
{
	if (!error)
		return false;
	detail = llvm::toString(std::move(error));
	return true;
}

// Return whether the path is an existing directory or not
bool is_directory(const std::wstring& path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Delete existing file
bool delete_file_if_present(const std::wstring& path, std::string& detail)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
		return true;
	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
	{
		detail = "Temporary PDB path is a directory.";
		return false;
	}
	if (!DeleteFileW(path.c_str()))
	{
		detail = "Could not remove the temporary PDB.";
		return false;
	}
	return true;
}

// Append a count to the export report
void count_line(std::string& text, const char* key, size_t value)
{
	char line[96];
	std::snprintf(line, sizeof(line), "%s=%u\n", key, static_cast<unsigned>(value));
	text += line;
}

// Format the export report
std::string result_text(const PdbExportResult& result, const PeImage& image)
{
	std::string text;
	text += result.ok ? "ok=yes\n" : "ok=no\n";
	text += result.canceled ? "canceled=yes\n" : "canceled=no\n";
	text += "summary=" + result.summary + "\n";
	if (!result.path.empty())
		text += "path=" + result.path + "\n";
	if (image.hasRsds)
	{
		text += "guid=" + format_guid(image.guid) + "\n";
		count_line(text, "age", image.age);
	}
	if (image.hasMachine)
	{
		char machine[32];
		std::snprintf(machine, sizeof(machine), "machine=0x%x\n", image.machine);
		text += machine;
	}
	if (!image.pdbBasename.empty())
		text += "pdb_basename=" + image.pdbBasename + "\n";
	count_line(text, "exported", result.exported);
	count_line(text, "functions", result.functions);
	count_line(text, "code", result.code);
	count_line(text, "data", result.data);
	count_line(text, "ida_locals", result.idaLocals);
	count_line(text, "omitted_header", result.omittedHeader);
	count_line(text, "omitted_long", result.omittedLong);
	count_line(text, "omitted_section", result.omittedSection);
	char bytes[64];
	std::snprintf(bytes, sizeof(bytes), "pdb_bytes=%llu\n", static_cast<unsigned long long>(result.pdbBytes));
	text += bytes;
	return text;
}

// Return the CodeView public flags for a name kind
llvm::codeview::PublicSymFlags public_flags(NameKind kind)
{
	if (kind == NameKind::Function)
		return llvm::codeview::PublicSymFlags::Function | llvm::codeview::PublicSymFlags::Code;
	if (kind == NameKind::Code)
		return llvm::codeview::PublicSymFlags::Code;
	return llvm::codeview::PublicSymFlags::None;
}

} // namespace

// Write names to PDB
PdbExportResult export_public_pdb(const PeImage& image, const std::vector<CollectedName>& names, const std::string& outputPath, PdbHook hook, void* hookContext)
{
	PdbExportResult result;
	auto finish = [&](bool ok, bool canceled, const std::string& summary) {
		result.ok = ok;
		result.canceled = canceled;
		result.summary = summary;
		result.text = result_text(result, image);
		return result;
	};

	if (outputPath.empty())
		return finish(false, false, "No PDB output path was selected.");
	if (!image.hasMachine || !image.hasSections || image.sections.empty())
		return finish(false, false, "PE section layout is incomplete.");
	if (!image.hasRsds || image.pdbBasename.empty())
		return finish(false, false, "RSDS identity is incomplete.");
	if (image.machine != 0x14c && image.machine != 0x8664)
		return finish(false, false, "PDB export supports x86 and AMD64 only.");

	const std::wstring finalPath = wide_path(outputPath);
	if (finalPath.empty())
		return finish(false, false, "PDB output path could not be encoded.");
	if (is_directory(finalPath))
		return finish(false, false, "PDB output path is a directory.");

	const std::string tempUtf8 = outputPath + ".ida2pdb-tmp";
	const std::wstring tempPath = wide_path(tempUtf8);
	if (tempPath.empty())
		return finish(false, false, "Temporary PDB path could not be encoded.");

	std::string detail;
	if (is_directory(tempPath))
		return finish(false, false, "Temporary PDB path is a directory.");

	// BulkPublic keeps a pointer to each name. names outlives builder.commit().
	std::vector<llvm::pdb::BulkPublic> publics;
	publics.reserve(names.size());
	for (const CollectedName& name : names)
	{
		if (hook != nullptr && (publics.size() % 8192u) == 0 && hook(hookContext, "publics"))
			return finish(false, true, "Canceled.");
		if (name.name.empty())
			continue;
		if (name.sectionIndex == 0)
		{
			++result.omittedHeader;
			continue;
		}
		if (name.sectionIndex > image.sections.size() || name.sectionIndex > 0xFFFFu)
		{
			++result.omittedSection;
			continue;
		}
		const PeSection& section = image.sections[name.sectionIndex - 1];
		const uint32_t extent = section.virtualSize != 0 ? section.virtualSize : section.sizeOfRawData;
		if (extent != 0 && name.sectionOffset >= extent)
		{
			++result.omittedSection;
			continue;
		}
		if (name.name.size() > kMaxPublicName)
		{
			++result.omittedLong;
			continue;
		}
		llvm::pdb::BulkPublic symbol;
		symbol.Name = name.name.c_str();
		symbol.NameLen = static_cast<uint32_t>(name.name.size());
		symbol.Offset = name.sectionOffset;
		symbol.Segment = static_cast<uint16_t>(name.sectionIndex);
		symbol.setFlags(public_flags(name.kind));
		publics.push_back(symbol);
		++result.exported;
		if (name.local)
			++result.idaLocals;
		if (name.kind == NameKind::Function)
			++result.functions;
		else if (name.kind == NameKind::Code)
			++result.code;
		else
			++result.data;
	}

	if (hook != nullptr && hook(hookContext, "publish"))
		return finish(false, true, "Canceled.");
	if (publics.empty())
		return finish(false, false, "No public names to export.");

	std::vector<llvm::object::coff_section> sections(image.sections.size());
	for (size_t index = 0; index < image.sections.size(); ++index)
	{
		const PeSection& source = image.sections[index];
		llvm::object::coff_section& section = sections[index];
		std::memset(&section, 0, sizeof(section));
		std::memcpy(section.Name, source.name, sizeof(section.Name));
		section.VirtualSize = source.virtualSize;
		section.VirtualAddress = source.virtualAddress;
		section.SizeOfRawData = source.sizeOfRawData;
		section.PointerToRawData = source.pointerToRawData;
		section.Characteristics = source.characteristics;
	}
	const auto sectionBytes = llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(sections.data()), sections.size() * sizeof(llvm::object::coff_section));

	if (!delete_file_if_present(tempPath, detail))
		return finish(false, false, detail);

	llvm::BumpPtrAllocator allocator;
	llvm::pdb::PDBFileBuilder builder(allocator);
	if (failed(builder.initialize(4096), detail))
		return finish(false, false, detail);

	for (uint32_t index = 0; index < llvm::pdb::kSpecialStreamCount; ++index)
	{
		auto added = builder.getMsfBuilder().addStream(0);
		if (!added)
			return finish(false, false, llvm::toString(added.takeError()));
	}

	llvm::codeview::GUID guid = {};
	std::memcpy(guid.Guid, image.guid, sizeof(guid.Guid));
	auto& info = builder.getInfoBuilder();
	info.setVersion(llvm::pdb::PdbImplVC70);
	info.setAge(image.age);
	info.setGuid(guid);
	info.setSignature(0);

	auto& dbi = builder.getDbiBuilder();
	dbi.setVersionHeader(llvm::pdb::PdbDbiV70);
	dbi.setAge(image.age);
	dbi.setBuildNumber(14, 0);
	dbi.setMachineType(image.machine == 0x8664 ? llvm::pdb::PDB_Machine::Amd64 : llvm::pdb::PDB_Machine::x86);
	dbi.createSectionMap(sections);
	if (failed(dbi.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionBytes), detail))
		return finish(false, false, detail);
	for (size_t index = 0; index < sections.size(); ++index)
	{
		llvm::pdb::SectionContrib contrib = {};
		contrib.ISect = static_cast<uint16_t>(index + 1);
		contrib.Off = 0;
		contrib.Size = sections[index].VirtualSize != 0 ? sections[index].VirtualSize : sections[index].SizeOfRawData;
		contrib.Characteristics = sections[index].Characteristics;
		dbi.addSectionContrib(contrib);
	}

	builder.getTpiBuilder().setVersionHeader(llvm::pdb::PdbTpiV80);
	builder.getIpiBuilder().setVersionHeader(llvm::pdb::PdbTpiV80);
	builder.getGsiBuilder().addPublicSymbols(std::move(publics));

	if (hook != nullptr && hook(hookContext, "commit"))
	{
		std::string ignored;
		delete_file_if_present(tempPath, ignored);
		return finish(false, true, "Canceled.");
	}

	if (failed(builder.commit(tempUtf8, nullptr), detail))
	{
		std::string ignored;
		delete_file_if_present(tempPath, ignored);
		return finish(false, false, detail);
	}

	if (!MoveFileExW(tempPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	{
		const DWORD error = GetLastError();
		std::string ignored;
		delete_file_if_present(tempPath, ignored);
		char message[96];
		std::snprintf(message, sizeof(message), "Could not publish the PDB (Win32 %lu).", error);
		return finish(false, false, message);
	}

	result.path = outputPath;
	WIN32_FILE_ATTRIBUTE_DATA attributes = {};
	if (GetFileAttributesExW(finalPath.c_str(), GetFileExInfoStandard, &attributes))
		result.pdbBytes = (static_cast<uint64_t>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
	char summary[128];
	std::snprintf(summary, sizeof(summary), "Exported %u public names.", static_cast<unsigned>(result.exported));
	return finish(true, false, summary);
}
