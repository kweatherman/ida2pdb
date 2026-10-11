
// Attempt to parse PE and PDB info from the loaded IDB, fall back to original executable if it doesn't exist
#include "StdAfx.h"
#include "PeParser.h"
#include "DebugParser.h"

#include <bcrypt.h>
#include <bytes.hpp>
#include <diskio.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

// PE image memory container
struct MemoryView
{
	const uint8_t* data;
	size_t size;
};

// Read bytes from a memory view
PeIo read_view_bytes(PVOID context, uint64_t offset, PVOID destination, size_t size)
{
	const auto* view = static_cast<const MemoryView*>(context);
	if (offset > view->size || size > view->size - offset)
		return PeIo::Truncated;
	std::memcpy(destination, view->data + offset, size);
	return PeIo::Ok;
}

// Open PE file used as a read source.
struct FileView
{
	linput_t* input;
	uint64_t size;
};

// Read bytes from an open PE file.
PeIo read_file_bytes(PVOID context, uint64_t offset, PVOID destination, size_t size)
{
	auto* view = static_cast<FileView*>(context);
	if (offset > view->size || size > view->size - offset)
		return PeIo::Truncated;
	if (qlseek(view->input, qoff64_t(offset), SEEK_SET) != qoff64_t(offset))
		return PeIo::Truncated;
	uint8_t* out = static_cast<uint8_t*>(destination);
	size_t done = 0;
	while (done < size)
	{
		const ssize_t got = qlread(view->input, out + done, size - done);
		if (got <= 0)
			return PeIo::Truncated;
		done += size_t(got);
	}
	return PeIo::Ok;
}

// Read original file bytes stored in the database
PeIo read_idb_bytes(PVOID context, uint64_t offset, PVOID destination, size_t size)
{
	auto* fileSize = static_cast<uint64_t*>(context);
	if (offset > *fileSize || size > *fileSize - offset)
		return PeIo::Truncated;
	const ea_t start = get_fileregion_ea(qoff64_t(offset));
	if (start == BADADDR || get_fileregion_offset(start) != qoff64_t(offset))
		return PeIo::Unavailable;
	if (size > 1)
	{
		const ea_t end = get_fileregion_ea(qoff64_t(offset + size - 1));
		if (end == BADADDR || end != start + ea_t(size - 1))
			return PeIo::Unavailable;
	}
	const ssize_t got = get_bytes(destination, ssize_t(size), start, 0, nullptr);
	if (got != ssize_t(size))
		return PeIo::Unavailable;
	return PeIo::Ok;
}

// Open CNG hash algorithm
bool open_hash(const wchar_t* algorithmId, BCRYPT_ALG_HANDLE& algorithm, BCRYPT_HASH_HANDLE& hash, std::vector<UCHAR>& object)
{
	algorithm = nullptr;
	hash = nullptr;
	if (BCryptOpenAlgorithmProvider(&algorithm, algorithmId, nullptr, 0) < 0)
		return false;
	DWORD objectLength = 0;
	DWORD written = 0;
	if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &written, 0) < 0)
	{
		BCryptCloseAlgorithmProvider(algorithm, 0);
		algorithm = nullptr;
		return false;
	}
	object.resize(objectLength);
	if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0)
	{
		BCryptCloseAlgorithmProvider(algorithm, 0);
		algorithm = nullptr;
		return false;
	}
	return true;
}

// Hash a file with CRC32, MD5, and SHA256
bool get_file_hashes(linput_t* input, uint64_t size, uint32_t& crc, uint8_t md5[16], uint8_t sha256[32])
{
	if (qlseek(input, 0, SEEK_SET) != 0)
		return false;
	crc = 0;
	BCRYPT_ALG_HANDLE md5Alg = nullptr;
	BCRYPT_ALG_HANDLE shaAlg = nullptr;
	BCRYPT_HASH_HANDLE md5Hash = nullptr;
	BCRYPT_HASH_HANDLE shaHash = nullptr;
	std::vector<UCHAR> md5Object;
	std::vector<UCHAR> shaObject;
	if (!open_hash(BCRYPT_MD5_ALGORITHM, md5Alg, md5Hash, md5Object) || !open_hash(BCRYPT_SHA256_ALGORITHM, shaAlg, shaHash, shaObject))
	{
		if (md5Hash != nullptr)
			BCryptDestroyHash(md5Hash);
		if (md5Alg != nullptr)
			BCryptCloseAlgorithmProvider(md5Alg, 0);
		return false;
	}
	std::vector<uint8_t> buffer(64 * 1024);
	uint64_t done = 0;
	bool ok = true;
	while (ok && done < size)
	{
		const uint64_t remaining = size - done;
		const size_t want = remaining > buffer.size() ? buffer.size() : size_t(remaining);
		const ssize_t got = qlread(input, buffer.data(), want);
		if (got <= 0)
		{
			ok = false;
			break;
		}
		crc = crc32_zlib(crc, buffer.data(), size_t(got));
		if (BCryptHashData(md5Hash, buffer.data(), ULONG(got), 0) < 0 || BCryptHashData(shaHash, buffer.data(), ULONG(got), 0) < 0)
			ok = false;
		done += uint64_t(got);
	}
	if (ok)
		ok = BCryptFinishHash(md5Hash, md5, 16, 0) >= 0 && BCryptFinishHash(shaHash, sha256, 32, 0) >= 0;
	BCryptDestroyHash(md5Hash);
	BCryptDestroyHash(shaHash);
	BCryptCloseAlgorithmProvider(md5Alg, 0);
	BCryptCloseAlgorithmProvider(shaAlg, 0);
	return ok && done == size;
}

// Return whether a hash buffer contains any nonzero byte
bool any_nonzero(const uint8_t* data, size_t size)
{
	for (size_t index = 0; index < size; ++index)
	{
		if (data[index] != 0)
			return true;
	}
	return false;
}

// Return whether a field came from the file or the database
const char* source_name(bool fromFile)
{
	return fromFile ? "file" : "idb";
}

// Append a hexadecimal field to the identity report
void append_hex(std::string& text, const char* key, uint64_t value, const char* source)
{
	char line[160];
	if (source != nullptr)
		std::snprintf(line, sizeof(line), "%s=0x%llx source=%s\n", key, static_cast<unsigned long long>(value), source);
	else
		std::snprintf(line, sizeof(line), "%s=0x%llx\n", key, static_cast<unsigned long long>(value));
	text += line;
}

// Return IDA's stored input-file path.
std::string input_path()
{
	char path[4096] = {};
	if (get_input_file_path(path, sizeof(path)) <= 0)
		return {};
	return path;
}

// Return the directory portion of a path.
std::string directory_of(const std::string& path)
{
	const size_t slash = path.find_last_of("\\/");
	if (slash == std::string::npos)
		return {};
	return path.substr(0, slash);
}

// Return the file name portion of a path
std::string basename_of(const std::string& path)
{
	const size_t slash = path.find_last_of("\\/");
	const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
	if (name.empty() || name == "." || name == "..")
		return {};
	return name;
}

// Return the directory that contains the loaded database
std::string idb_directory()
{
	const char* idb = get_path(PATH_TYPE_IDB);
	if (idb == nullptr || idb[0] == '\0')
		return {};
	return directory_of(idb);
}

// Return the original input file name
std::string input_basename(const std::string& storedPath)
{
	const std::string fromPath = basename_of(storedPath);
	if (!fromPath.empty())
		return fromPath;
	char name[1024] = {};
	if (get_root_filename(name, sizeof(name)) > 0)
		return basename_of(name);
	return {};
}

// Join the original input file name to the database directory.
std::string join_idb_path(const std::string& storedPath)
{
	const std::string directory = idb_directory();
	const std::string name = input_basename(storedPath);
	if (directory.empty() || name.empty() || name.find_first_of("\\/:") != std::string::npos)
		return {};
	return directory + "\\" + name;
}

// Compare paths with slash and case differences folded.
std::string normalized_path(std::string path)
{
	for (char& ch : path)
	{
		if (ch == '/')
			ch = '\\';
		else if (ch >= 'A' && ch <= 'Z')
			ch = char(ch - 'A' + 'a');
	}
	while (!path.empty() && path.back() == '\\')
		path.pop_back();
	return path;
}

// Open a candidate executable and read its length.
bool open_pe_file(const std::string& path, linput_t*& input, uint64_t& size, std::string& error)
{
	input = open_linput(path.c_str(), false);
	if (input == nullptr)
	{
		error = "The original executable could not be opened: " + path;
		return false;
	}
	const int64 bytes = qlsize(input);
	if (bytes <= 0)
	{
		close_linput(input);
		input = nullptr;
		error = "The original executable length could not be read: " + path;
		return false;
	}
	size = uint64_t(bytes);
	return true;
}

// Check a file against the database length, hashes, and layout.
bool file_matches_database(linput_t* input, uint64_t size, const PeImage& idbImage, std::string& error)
{
	const size_t recordedSize = retrieve_input_file_size();
	if (recordedSize != 0 && uint64_t(recordedSize) != size)
	{
		error = "The file length does not match the length stored in the database.";
		return false;
	}
	uint32_t crc = 0;
	uint8_t md5[16] = {};
	uint8_t sha256[32] = {};
	if (!get_file_hashes(input, size, crc, md5, sha256))
	{
		error = "The file hash could not be calculated.";
		return false;
	}
	const uint32_t recordedCrc = retrieve_input_file_crc32();
	uint8_t recordedMd5[16] = {};
	uint8_t recordedSha[32] = {};
	const bool hasMd5 = retrieve_input_file_md5(recordedMd5) && any_nonzero(recordedMd5, sizeof(recordedMd5));
	const bool hasSha = retrieve_input_file_sha256(recordedSha) && any_nonzero(recordedSha, sizeof(recordedSha));
	const bool hasCrc = recordedCrc != 0;
	if (!hasCrc && !hasMd5 && !hasSha && !(idbImage.hasMachine && idbImage.hasImageBase && idbImage.hasSections))
	{
		error = "The database has no input hash and no PE layout, so the selected file cannot be checked.";
		return false;
	}
	if (hasCrc && crc != recordedCrc)
	{
		error = "The file CRC32 does not match the database.";
		return false;
	}
	if (hasMd5 && std::memcmp(md5, recordedMd5, sizeof(md5)) != 0)
	{
		error = "The file MD5 does not match the database.";
		return false;
	}
	if (hasSha && std::memcmp(sha256, recordedSha, sizeof(sha256)) != 0)
	{
		error = "The file SHA256 does not match the database.";
		return false;
	}
	return true;
}

// Accept a candidate only when it validates and supplies the required PE identity.
// lacksRsds is set when a matching file was read and has no RSDS record.
bool candidate_usable(const std::string& path, const PeImage& idbImage, PeImage& fileImage, std::string& error, bool& lacksRsds)
{
	if (path.empty())
	{
		error = "No executable path was available.";
		return false;
	}
	linput_t* input = nullptr;
	uint64_t fileSize = 0;
	if (!open_pe_file(path, input, fileSize, error))
		return false;
	std::string matchError;
	if (!file_matches_database(input, fileSize, idbImage, matchError))
	{
		close_linput(input);
		error = matchError;
		return false;
	}
	FileView view{ input, fileSize };
	fileImage = parse_pe_image(read_file_bytes, &view, fileSize);
	close_linput(input);
	if (fileImage.status == PeParseStatus::Malformed || fileImage.status == PeParseStatus::MissingBytes)
	{
		error = fileImage.detail.empty() ? "The original executable is malformed." : fileImage.detail;
		return false;
	}
	if (idbImage.hasMachine && idbImage.hasImageBase && idbImage.hasSections)
	{
		std::string why;
		if (!pe_layouts_compatible(idbImage, fileImage, why))
		{
			error = why;
			return false;
		}
	}
	if (fileImage.status != PeParseStatus::Ok || !fileImage.hasMachine || !fileImage.hasImageBase || !fileImage.hasSections || !fileImage.hasRsds)
	{
		if (fileImage.status == PeParseStatus::Unsupported && fileImage.hasSections)
			lacksRsds = true;
		error = fileImage.detail.empty() ? "The original executable does not contain the required PE identity." : fileImage.detail;
		return false;
	}
	return true;
}

// Return whether the database already stores this RSDS record
bool idb_contains_rsds(uint64_t fileSize, uint32_t offset, const uint8_t guid[16], const std::string& pdbPath)
{
	const size_t rsdsBytes = 24 + pdbPath.size() + 1;
	std::vector<uint8_t> idbRsds(rsdsBytes);
	if (read_idb_bytes(&fileSize, offset, idbRsds.data(), idbRsds.size()) != PeIo::Ok)
		return false;
	if (idbRsds[0] != 'R' || idbRsds[1] != 'S' || idbRsds[2] != 'D' || idbRsds[3] != 'S')
		return false;
	if (std::memcmp(idbRsds.data() + 4, guid, 16) != 0)
		return false;
	return std::memcmp(idbRsds.data() + 24, pdbPath.data(), pdbPath.size() + 1) == 0;
}

// Explain that the original executable is needed and ask for its path.
std::string choose_file(const std::string& initial, const std::string& reason)
{
	warning("%s", reason.c_str());
	const char* chosen = ask_file(false, initial.empty() ? nullptr : initial.c_str(), "Select the original PE file|*.exe;*.dll;*.sys");
	if (chosen == nullptr)
		return {};
	return chosen;
}

} // namespace

// Parse PE and PDB identity, optionally asking with file dialog to get the source executable file.
// allowDialog opens the file picker after the stored input path and the basename beside the IDB both fail.
// The caller sets it only when the Qt interface is available, IDA is not suppressing dialogs, and this invocation
// did not request unattended operation.
IdentityReport parse_pe_info(bool allowDialog)
{
	IdentityReport report;
	if (inf_get_filetype() != f_PE)
	{
		report.summary = "This database is not a PE file.";
		report.text = "ok=no\nsummary=" + report.summary + "\n";
		return report;
	}

	uint64_t idbFileSize = retrieve_input_file_size();
	if (idbFileSize == 0)
		idbFileSize = 0xFFFFFFFFull;
	PeImage idbImage = parse_pe_image(read_idb_bytes, &idbFileSize, idbFileSize);
	if (idbImage.hasMachine && idbImage.machine != 0x14c && idbImage.machine != 0x8664)
	{
		report.summary = idbImage.detail.empty() ? "Only PE32 x86 and PE32+ AMD64 images are supported." : idbImage.detail;
		report.text = "ok=no\nsummary=" + report.summary + "\n";
		return report;
	}

	// The database bytes were read and show no RSDS record. The matching file has the same bytes.
	if (idbImage.status == PeParseStatus::Unsupported && idbImage.hasMachine && idbImage.hasImageBase && idbImage.hasSections)
	{
		report.summary = idbImage.detail.empty() ? "The executable has no RSDS PDB identity." : idbImage.detail;
		report.text = "ok=no\nsummary=" + report.summary + "\nrsds=absent source=database\n";
		return report;
	}

	const bool idbComplete = idbImage.status == PeParseStatus::Ok && idbImage.hasMachine && idbImage.hasImageBase && idbImage.hasSections && idbImage.hasRsds;
	PeImage chosen = idbImage;
	bool machineFromFile = false;
	bool baseFromFile = false;
	bool sectionsFromFile = false;
	bool rsdsFromFile = false;
	std::string usedPath;
	std::string fileCandidate;
	if (!idbComplete)
	{
		const std::string storedPath = input_path();
		const std::string besidePath = join_idb_path(storedPath);
		PeImage fileImage;
		std::string storedError;
		std::string besideError;
		std::string path;
		bool lacksRsds = false;
		bool opened = candidate_usable(storedPath, idbImage, fileImage, storedError, lacksRsds);
		if (opened)
		{
			path = storedPath;
			fileCandidate = "stored-input";
		}
		else if (!lacksRsds && !besidePath.empty() && normalized_path(besidePath) != normalized_path(storedPath))
		{
			opened = candidate_usable(besidePath, idbImage, fileImage, besideError, lacksRsds);
			if (opened)
			{
				path = besidePath;
				fileCandidate = "beside-idb";
			}
		}
		if (!opened && lacksRsds)
		{
			report.summary = !storedError.empty() && besideError.empty() ? storedError : besideError;
			report.text = "ok=no\nsummary=" + report.summary + "\nrsds=absent source=file\n";
			return report;
		}
		if (!opened && allowDialog)
		{
			std::string reason = "The original executable is needed.";
			if (!storedError.empty())
				reason += " Stored input path: " + storedError;
			if (!besideError.empty())
				reason += " Beside the database: " + besideError;
			const std::string initial = !besidePath.empty() ? besidePath : storedPath;
			const std::string replacement = choose_file(initial, reason);
			if (replacement.empty())
			{
				report.summary = "The original executable is required and was not selected.";
				report.text = "ok=no\nsummary=" + report.summary + "\n";
				return report;
			}
			std::string selectedError;
			opened = candidate_usable(replacement, idbImage, fileImage, selectedError, lacksRsds);
			if (!opened)
			{
				report.summary = selectedError.empty() ? "The selected file does not match the database." : selectedError;
				report.text = "ok=no\nsummary=" + report.summary + "\n";
				return report;
			}
			path = replacement;
			fileCandidate = "selected";
		}
		if (!opened)
		{
			std::string summary = "The database is missing PE information and the original executable is unavailable.";
			if (!storedError.empty())
				summary += " Stored input path: " + storedError;
			if (!besideError.empty())
				summary += " Beside the database: " + besideError;
			report.summary = summary;
			report.text = "ok=no\nsummary=" + report.summary + "\n";
			return report;
		}
		if (!idbImage.hasMachine)
			machineFromFile = true;
		if (!idbImage.hasImageBase)
			baseFromFile = true;
		if (!idbImage.hasSections)
			sectionsFromFile = true;
		if (!idbImage.hasRsds)
			rsdsFromFile = true;
		if (machineFromFile)
		{
			chosen.hasMachine = true;
			chosen.machine = fileImage.machine;
			chosen.pe32Plus = fileImage.pe32Plus;
		}
		if (baseFromFile)
		{
			chosen.hasImageBase = true;
			chosen.originalImageBase = fileImage.originalImageBase;
		}
		if (!idbImage.sizeOfImage)
		{
			chosen.sizeOfImage = fileImage.sizeOfImage;
			chosen.sizeOfHeaders = fileImage.sizeOfHeaders;
			chosen.entryRva = fileImage.entryRva;
		}
		if (sectionsFromFile)
			chosen.sections = fileImage.sections;
		chosen.hasSections = true;
		chosen.hasRsds = true;
		std::memcpy(chosen.guid, fileImage.guid, sizeof(chosen.guid));
		chosen.age = fileImage.age;
		chosen.pdbPath = fileImage.pdbPath;
		chosen.pdbBasename = fileImage.pdbBasename;
		chosen.rsdsFileOffset = fileImage.rsdsFileOffset;
		if (machineFromFile || baseFromFile)
			chosen.pe32Plus = fileImage.pe32Plus;
		usedPath = path;

		if (idb_contains_rsds(idbFileSize, chosen.rsdsFileOffset, chosen.guid, chosen.pdbPath))
			rsdsFromFile = false;
	}

	if (!chosen.hasMachine || !chosen.hasImageBase || !chosen.hasSections || !chosen.hasRsds)
	{
		report.summary = "PE identity is incomplete.";
		report.text = "ok=no\nsummary=" + report.summary + "\n";
		return report;
	}

	const uint64_t currentBase = get_imagebase();
	MappedAddress entry;
	const MapStatus mapped = map_ea(currentBase + chosen.entryRva, currentBase, chosen, entry);
	std::string text;
	text += "ok=yes\n";
	text += "summary=Recovered PE identity\n";
	append_hex(text, "machine", chosen.machine, source_name(machineFromFile));
	text += std::string("pe=") + (chosen.pe32Plus ? "PE32+" : "PE32") + "\n";
	append_hex(text, "original_image_base", chosen.originalImageBase, source_name(baseFromFile));
	append_hex(text, "current_image_base", currentBase, nullptr);
	text += std::string("rebased=") + (currentBase == chosen.originalImageBase ? "no" : "yes") + "\n";
	char count[64];
	std::snprintf(count, sizeof(count), "section_count=%u source=%s\n", static_cast<unsigned>(chosen.sections.size()), source_name(sectionsFromFile));
	text += count;
	uint32_t index = 1;
	for (const PeSection& section : chosen.sections)
	{
		char line[256];
		std::snprintf(line, sizeof(line), "section=%u name=%s va=0x%x vsize=0x%x raw_size=0x%x raw_ptr=0x%x source=%s\n", index, section.name, section.virtualAddress, section.virtualSize, section.sizeOfRawData, section.pointerToRawData, source_name(sectionsFromFile));
		text += line;
		++index;
	}
	text += std::string("rsds=yes source=") + source_name(rsdsFromFile) + "\n";
	text += "guid=" + format_guid(chosen.guid) + "\n";
	char age[64];
	std::snprintf(age, sizeof(age), "age=%u\n", chosen.age);
	text += age;
	text += "pdb_basename=" + chosen.pdbBasename + "\n";
	text += "pdb_path=" + chosen.pdbPath + "\n";
	if (mapped == MapStatus::Ok)
	{
		append_hex(text, "entry_rva", entry.rva, nullptr);
		append_hex(text, "entry_ea", entry.ea, nullptr);
		char place[128];
		std::snprintf(place, sizeof(place), "entry_section=%u\nentry_section_offset=0x%x\n", entry.sectionIndex, entry.sectionOffset);
		text += place;
		if (entry.hasFileOffset)
			append_hex(text, "entry_file_offset", entry.fileOffset, nullptr);
		else
			text += "entry_file_offset=none\n";
	}
	else
	{
		text += "entry_map=rejected\n";
	}
	text += std::string("file_used=") + (usedPath.empty() ? "no" : "yes") + "\n";
	if (!usedPath.empty())
	{
		text += "file_path=" + usedPath + "\n";
		text += "file_candidate=" + fileCandidate + "\n";
	}
	report.ok = true;
	report.hasImage = true;
	report.image = chosen;
	report.currentImageBase = currentBase;
	report.summary = "Recovered PE identity.";
	report.text = text;
	return report;
}
