
// Push finished PDB into the local symbol store support
#include "SymbolStore.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Convert UTF-8 path to UTF-16
std::wstring wide_path(const std::string& path)
{
	if (path.empty())
		return std::wstring();
	int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0);
	UINT codePage = CP_UTF8;
	DWORD flags = MB_ERR_INVALID_CHARS;
	if (count <= 0)
	{
		codePage = CP_ACP;
		flags = 0;
		count = MultiByteToWideChar(CP_ACP, 0, path.data(), static_cast<int>(path.size()), nullptr, 0);
	}
	if (count <= 0)
		return std::wstring();
	std::wstring wide(static_cast<size_t>(count), L'\0');
	MultiByteToWideChar(codePage, flags, path.data(), static_cast<int>(path.size()), wide.data(), count);
	return wide;
}

// UTF-16 path to UTF-8
std::string narrow_utf8(const std::wstring& path)
{
	if (path.empty())
		return std::string();
	const int count = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (count <= 1)
		return std::string();
	std::string text(static_cast<size_t>(count - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, text.data(), count, nullptr, nullptr);
	return text;
}

namespace {

// Expand a path to its full form
std::wstring full_path(const std::wstring& path)
{
	const DWORD length = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
	if (length == 0)
		return path;
	std::wstring full(length, L'\0');
	const DWORD written = GetFullPathNameW(path.c_str(), length, full.data(), nullptr);
	if (written == 0 || written >= length)
		return path;
	full.resize(written);
	return full;
}

// Return true if path is a directory
bool is_directory(const std::wstring& path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Return whether two paths name the same file
bool same_existing_file(const std::wstring& left, const std::wstring& right)
{
	const HANDLE leftHandle = CreateFileW(left.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (leftHandle == INVALID_HANDLE_VALUE)
		return false;
	const HANDLE rightHandle = CreateFileW(right.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (rightHandle == INVALID_HANDLE_VALUE)
	{
		CloseHandle(leftHandle);
		return false;
	}
	BY_HANDLE_FILE_INFORMATION leftInfo = {};
	BY_HANDLE_FILE_INFORMATION rightInfo = {};
	const BOOL leftOk = GetFileInformationByHandle(leftHandle, &leftInfo);
	const BOOL rightOk = GetFileInformationByHandle(rightHandle, &rightInfo);
	CloseHandle(leftHandle);
	CloseHandle(rightHandle);
	if (!leftOk || !rightOk)
		return false;
	return leftInfo.dwVolumeSerialNumber == rightInfo.dwVolumeSerialNumber
		&& leftInfo.nFileIndexLow == rightInfo.nFileIndexLow
		&& leftInfo.nFileIndexHigh == rightInfo.nFileIndexHigh;
}

// Create directory if it doesn't exist
bool create_directory_if_needed(const std::wstring& path, std::string& why)
{
	if (is_directory(path))
		return true;
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES)
	{
		why = "A store path component exists and is not a directory.";
		return false;
	}
	if (CreateDirectoryW(path.c_str(), nullptr))
		return true;
	why = "A store directory could not be created.";
	return false;
}

// Create the store root and its parent directories
bool ensure_store_root(const std::wstring& root, std::string& why)
{
	const DWORD attributes = GetFileAttributesW(root.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES)
	{
		if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
			return true;
		why = "The symbol store path is not a directory.";
		return false;
	}
	const int created = SHCreateDirectoryExW(nullptr, root.c_str(), nullptr);
	if (created != ERROR_SUCCESS && created != ERROR_ALREADY_EXISTS && created != ERROR_FILE_EXISTS)
	{
		why = "A store directory could not be created.";
		return false;
	}
	if (!is_directory(root))
	{
		why = "The symbol store path is not a directory.";
		return false;
	}
	return true;
}

// Return a file size
uint64_t file_size(const std::wstring& path)
{
	const HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return ~uint64_t(0);
	LARGE_INTEGER size = {};
	const BOOL ok = GetFileSizeEx(handle, &size);
	CloseHandle(handle);
	if (!ok || size.QuadPart < 0)
		return ~uint64_t(0);
	return static_cast<uint64_t>(size.QuadPart);
}

// Delete file if path is one
void delete_file_if_file(const std::wstring& path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
		return;
	DeleteFileW(path.c_str());
}

// Create pingme.txt when it is absent
void ensure_store_marker(const std::wstring& root)
{
	const std::wstring marker = root + L"\\pingme.txt";
	const DWORD attributes = GetFileAttributesW(marker.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES)
		return;
	const HANDLE handle = CreateFileW(marker.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return;
	const char text[] = "ida2pdb\n";
	DWORD written = 0;
	WriteFile(handle, text, sizeof(text) - 1, &written, nullptr);
	CloseHandle(handle);
}

std::wstring trim_copy(const std::wstring& text)
{
	size_t begin = 0;
	while (begin < text.size() && (text[begin] == L' ' || text[begin] == L'\t' || text[begin] == L'\r' || text[begin] == L'\n'))
		++begin;
	size_t end = text.size();
	while (end > begin && (text[end - 1] == L' ' || text[end - 1] == L'\t' || text[end - 1] == L'\r' || text[end - 1] == L'\n'))
		--end;
	return text.substr(begin, end - begin);
}

std::wstring strip_quotes(const std::wstring& text)
{
	if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"')
		return text.substr(1, text.size() - 2);
	return text;
}

// Caseless prefix compare
bool starts_with_ci(const std::wstring& text, const wchar_t* prefix)
{
	const size_t length = std::wcslen(prefix);
	if (text.size() < length)
		return false;
	return _wcsnicmp(text.c_str(), prefix, length) == 0;
}

// Split text and keep empty fields
std::vector<std::wstring> split_keep_empty(const std::wstring& text, wchar_t separator)
{
	std::vector<std::wstring> parts;
	std::wstring current;
	for (wchar_t ch : text)
	{
		if (ch == separator)
		{
			parts.push_back(current);
			current.clear();
		}
		else
			current.push_back(ch);
	}
	parts.push_back(current);
	return parts;
}

// Return a full directory path without a trailing slash
std::wstring normalize_directory(const std::wstring& path)
{
	std::wstring full = full_path(trim_copy(path));
	while (full.size() > 3 && (full.back() == L'\\' || full.back() == L'/'))
		full.pop_back();
	return full;
}

// Type of symbol-path element
enum class PathClass
{
	Empty,
	Local,
	Unc,
	Url
};

// Classify a path type
PathClass classify_path(const std::wstring& path)
{
	const std::wstring text = trim_copy(path);
	if (text.empty())
		return PathClass::Empty;
	if (starts_with_ci(text, L"https://") || starts_with_ci(text, L"http://"))
		return PathClass::Url;
	if (text.size() >= 2 && ((text[0] == L'\\' && text[1] == L'\\') || (text[0] == L'/' && text[1] == L'/')))
		return PathClass::Unc;
	return PathClass::Local;
}

// Append a discovery note when it is not already present.
void add_note(std::vector<std::string>& notes, const std::string& note)
{
	for (const std::string& existing : notes)
	{
		if (existing == note)
			return;
	}
	notes.push_back(note);
}

// Shorten a symbol-path element for a discovery note.
std::string note_element(const std::wstring& element)
{
	std::string text = narrow_utf8(element);
	if (text.size() > 80)
		text.resize(80);
	return text;
}

// Expand environment variables in a directory token.
bool expand_directory_token(
	const std::wstring& input,
	std::wstring& output,
	std::string& note,
	StoreEnvLookup lookup,
	void* context)
{
	std::wstring current = input;
	for (int pass = 0; pass < 4; ++pass)
	{
		if (current.find(L'%') == std::wstring::npos)
		{
			output = current;
			return true;
		}
		std::wstring next;
		bool expanded = false;
		for (size_t index = 0; index < current.size();)
		{
			if (current[index] == L'%' && index + 1 < current.size() && current[index + 1] == L'%')
			{
				next.push_back(L'%');
				index += 2;
				expanded = true;
				continue;
			}
			if (current[index] != L'%')
			{
				next.push_back(current[index]);
				++index;
				continue;
			}
			const size_t end = current.find(L'%', index + 1);
			if (end == std::wstring::npos || end == index + 1)
			{
				note = "malformed environment reference in " + note_element(input);
				return false;
			}
			const std::wstring name = current.substr(index + 1, end - (index + 1));
			std::wstring value;
			if (lookup == nullptr || !lookup(name.c_str(), value, context))
			{
				note = "unresolved environment variable %" + narrow_utf8(name) + "%";
				return false;
			}
			next += value;
			expanded = true;
			index = end + 1;
		}
		if (!expanded)
			break;
		current = next;
	}
	if (current.find(L'%') != std::wstring::npos)
	{
		note = "environment expansion did not finish in " + note_element(input);
		return false;
	}
	output = current;
	return true;
}

// Append a path when it is not already listed.
void add_unique_path(std::vector<std::wstring>& paths, const std::wstring& path)
{
	for (const std::wstring& existing : paths)
	{
		if (_wcsicmp(existing.c_str(), path.c_str()) == 0)
			return;
	}
	paths.push_back(path);
}

// Directories accepted while scanning a symbol path.
struct PathScan
{
	std::vector<std::wstring> explicitStores;
	std::vector<std::wstring> plainStores;
	bool wantsDefault = false;
};

// Expand and classify a directory token.
bool prepare_directory_token(
	const std::wstring& token,
	std::wstring& prepared,
	std::string& note,
	StoreEnvLookup lookup,
	void* context)
{
	if (!expand_directory_token(token, prepared, note, lookup, context))
		return false;
	prepared = strip_quotes(trim_copy(prepared));
	if (prepared.find(L'*') != std::wstring::npos || prepared.find(L';') != std::wstring::npos)
	{
		note = "malformed directory token " + note_element(prepared);
		return false;
	}
	return true;
}

// Record a explicit cache or srv store.
void consider_explicit_store(const std::wstring& expanded, PathScan& scan, std::vector<std::string>& notes)
{
	const PathClass kind = classify_path(expanded);
	if (kind == PathClass::Url)
	{
		scan.wantsDefault = true;
		add_note(notes, "HTTP symbol store is not a publication destination");
		return;
	}
	if (kind == PathClass::Unc)
	{
		add_note(notes, "skipped UNC symbol store");
		return;
	}
	if (kind == PathClass::Empty)
	{
		scan.wantsDefault = true;
		return;
	}
	add_unique_path(scan.explicitStores, normalize_directory(expanded));
}

// Apply a srv or cache chain, keeping only its leftmost store.
void apply_store_chain(
	const std::vector<std::wstring>& tokens,
	PathScan& scan,
	std::vector<std::string>& notes,
	StoreEnvLookup lookup,
	void* context)
{
	if (tokens.empty())
		return;
	if (tokens.size() > 10)
		add_note(notes, "symbol server lists more than 10 stores");
	if (trim_copy(tokens[0]).empty())
	{
		scan.wantsDefault = true;
		return;
	}
	std::wstring expanded;
	std::string note;
	if (!prepare_directory_token(tokens[0], expanded, note, lookup, context))
	{
		add_note(notes, note);
		return;
	}
	consider_explicit_store(expanded, scan, notes);
}

// Parse a symbol-path element.
void parse_symbol_element(
	const std::wstring& rawElement,
	PathScan& scan,
	std::vector<std::string>& notes,
	StoreEnvLookup lookup,
	void* context)
{
	const std::wstring element = trim_copy(rawElement);
	if (element.empty())
		return;
	if (starts_with_ci(element, L"cache*"))
	{
		const std::wstring rest = trim_copy(element.substr(6));
		if (rest.find(L'*') != std::wstring::npos)
		{
			add_note(notes, "malformed cache element " + note_element(element));
			return;
		}
		if (rest.empty())
		{
			scan.wantsDefault = true;
			return;
		}
		std::wstring expanded;
		std::string note;
		if (!prepare_directory_token(rest, expanded, note, lookup, context))
		{
			add_note(notes, note);
			return;
		}
		const PathClass kind = classify_path(expanded);
		if (kind == PathClass::Url)
		{
			add_note(notes, "HTTP symbol store is not a publication destination");
			return;
		}
		if (kind == PathClass::Unc)
		{
			add_note(notes, "skipped UNC symbol store");
			return;
		}
		if (kind == PathClass::Empty)
		{
			scan.wantsDefault = true;
			return;
		}
		add_unique_path(scan.explicitStores, normalize_directory(expanded));
		return;
	}
	if (starts_with_ci(element, L"symsrv*"))
	{
		const std::vector<std::wstring> tokens = split_keep_empty(element, L'*');
		if (tokens.size() < 2 || _wcsicmp(trim_copy(tokens[1]).c_str(), L"symsrv.dll") != 0)
		{
			add_note(notes, "unsupported symbol server provider in " + note_element(element));
			return;
		}
		std::vector<std::wstring> stores;
		for (size_t index = 2; index < tokens.size(); ++index)
			stores.push_back(trim_copy(tokens[index]));
		apply_store_chain(stores, scan, notes, lookup, context);
		return;
	}
	if (starts_with_ci(element, L"srv*"))
	{
		const std::wstring body = element.substr(4);
		if (body.empty())
			return;
		std::vector<std::wstring> stores = split_keep_empty(body, L'*');
		for (std::wstring& store : stores)
			store = trim_copy(store);
		apply_store_chain(stores, scan, notes, lookup, context);
		return;
	}
	if (element.find(L'*') != std::wstring::npos)
	{
		add_note(notes, "unsupported symbol-path syntax " + note_element(element));
		return;
	}
	std::wstring expanded;
	std::string note;
	if (!prepare_directory_token(element, expanded, note, lookup, context))
	{
		add_note(notes, note);
		return;
	}
	const PathClass kind = classify_path(expanded);
	if (kind == PathClass::Url)
	{
		add_note(notes, "HTTP symbol store is not a publication destination");
		return;
	}
	if (kind == PathClass::Unc)
	{
		add_note(notes, "skipped UNC symbol store");
		return;
	}
	if (kind != PathClass::Local)
		return;
	const std::wstring full = normalize_directory(expanded);
	const std::wstring marker = full + L"\\pingme.txt";
	const DWORD attributes = GetFileAttributesW(marker.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 && is_directory(full))
		add_unique_path(scan.plainStores, full);
}

// Scan a symbol-path variable for a publication directory.
PathScan scan_symbol_path(const std::wstring& text, std::vector<std::string>& notes, StoreEnvLookup lookup, void* context)
{
	PathScan scan;
	const std::vector<std::wstring> elements = split_keep_empty(text, L';');
	for (const std::wstring& element : elements)
		parse_symbol_element(element, scan, notes, lookup, context);
	return scan;
}

// Return the ProgramData Dbg sym directory.
std::wstring program_data_store()
{
	PWSTR known = nullptr;
	if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DONT_VERIFY, nullptr, &known)) || known == nullptr)
		return std::wstring();
	std::wstring path = known;
	CoTaskMemFree(known);
	if (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
		path.pop_back();
	return path + L"\\Dbg\\sym";
}

// Return whether DBGHELP_HOMEDIR is a local directory.
bool home_directory_usable(const std::wstring& home)
{
	if (home.empty() || home.find_first_of(L"*?\"<>|") != std::wstring::npos)
		return false;
	return classify_path(home) == PathClass::Local;
}

// Choose the implicit downstream store.
std::wstring default_downstream_store(bool& fromHome, std::vector<std::string>& notes, StoreEnvLookup lookup, void* context)
{
	fromHome = false;
	std::wstring home;
	if (lookup != nullptr && lookup(L"DBGHELP_HOMEDIR", home, context))
	{
		std::wstring expanded;
		std::string note;
		if (!expand_directory_token(home, expanded, note, lookup, context))
			add_note(notes, note);
		else
		{
			expanded = strip_quotes(trim_copy(expanded));
			if (home_directory_usable(expanded))
			{
				fromHome = true;
				return normalize_directory(expanded) + L"\\sym";
			}
			if (!trim_copy(home).empty())
				add_note(notes, "DBGHELP_HOMEDIR is not a local directory");
		}
	}
	return program_data_store();
}

// Join discovery notes into a line.
std::string join_notes(const std::vector<std::string>& notes)
{
	std::string text;
	for (const std::string& note : notes)
	{
		if (!text.empty())
			text += "; ";
		text += note;
	}
	return text;
}

} // namespace

// Read a variable from the process environment.
bool store_env_lookup_process(const wchar_t* name, std::wstring& value, void* context)
{
	(void)context;
	if (name == nullptr || name[0] == L'\0')
		return false;
	SetLastError(ERROR_SUCCESS);
	const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
	if (required == 0)
		return GetLastError() != ERROR_ENVVAR_NOT_FOUND;
	value.assign(required, L'\0');
	const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
	if (written == 0 || written >= required)
	{
		value.clear();
		return GetLastError() != ERROR_ENVVAR_NOT_FOUND;
	}
	value.resize(written);
	return true;
}

// Select the publication directory.
StoreDiscovery discover_publication_store(
	const std::string& explicitOverride,
	StoreEnvLookup lookup,
	void* context)
{
	StoreDiscovery result;
	const std::wstring overrideWide = trim_copy(wide_path(explicitOverride));
	if (!overrideWide.empty())
	{
		result.explicitOverride = true;
		result.path = narrow_utf8(normalize_directory(overrideWide));
		result.source = "explicit";
		result.detail = "explicit store override";
		return result;
	}
	if (lookup == nullptr)
		lookup = store_env_lookup_process;

	const wchar_t* variables[] = {
		L"_NT_SYMBOL_PATH",
		L"_NT_ALT_SYMBOL_PATH",
		L"_NT_ALTERNATE_SYMBOL_PATH"
	};
	const char* sources[] = {
		"_NT_SYMBOL_PATH",
		"_NT_ALT_SYMBOL_PATH",
		"_NT_ALTERNATE_SYMBOL_PATH"
	};
	std::vector<std::string> notes;
	std::string defaultRequester;
	for (int index = 0; index < 3; ++index)
	{
		std::wstring value;
		if (!lookup(variables[index], value, context) || trim_copy(value).empty())
			continue;
		const PathScan scan = scan_symbol_path(value, notes, lookup, context);
		if (!scan.explicitStores.empty())
		{
			result.path = narrow_utf8(scan.explicitStores.front());
			result.source = sources[index];
			result.detail = "explicit cache or symbol-server store";
			result.notes = join_notes(notes);
			return result;
		}
		if (!scan.plainStores.empty())
		{
			result.path = narrow_utf8(scan.plainStores.front());
			result.source = sources[index];
			result.detail = "plain directory with pingme.txt";
			result.notes = join_notes(notes);
			return result;
		}
		if (scan.wantsDefault && defaultRequester.empty())
			defaultRequester = sources[index];
	}

	bool fromHome = false;
	const std::wstring fallback = default_downstream_store(fromHome, notes, lookup, context);
	result.path = narrow_utf8(fallback);
	result.source = fromHome ? "DBGHELP_HOMEDIR" : "ProgramData";
	if (!defaultRequester.empty())
		result.detail = "default downstream requested by " + defaultRequester;
	else
		result.detail = "no eligible symbol-path store";
	result.notes = join_notes(notes);
	return result;
}

// Return whether two store paths name the same directory.
bool store_paths_equivalent(const std::string& left, const std::string& right)
{
	const std::wstring leftWide = normalize_directory(wide_path(left));
	const std::wstring rightWide = normalize_directory(wide_path(right));
	if (leftWide.empty() || rightWide.empty())
		return false;
	return _wcsicmp(leftWide.c_str(), rightWide.c_str()) == 0;
}

// Build the GUID-and-age directory name.
std::string symbol_store_key(const uint8_t guid[16], uint32_t age)
{
	const uint32_t data1 = uint32_t(guid[0]) | (uint32_t(guid[1]) << 8) | (uint32_t(guid[2]) << 16) | (uint32_t(guid[3]) << 24);
	const uint16_t data2 = uint16_t(guid[4] | (uint16_t(guid[5]) << 8));
	const uint16_t data3 = uint16_t(guid[6] | (uint16_t(guid[7]) << 8));
	char text[48];
	std::snprintf(
		text,
		sizeof(text),
		"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
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
		guid[15],
		age);
	return text;
}

// Return whether a PDB basename is safe to use as a path component.
bool pdb_basename_ok(const std::string& name, std::string& why)
{
	if (name.empty() || name == "." || name == "..")
	{
		why = "The PDB basename is empty.";
		return false;
	}
	if (name.back() == ' ' || name.back() == '.')
	{
		why = "The PDB basename ends with a space or a dot.";
		return false;
	}
	if (name.find_first_of("\\/:*?\"<>|") != std::string::npos || name.find('\0') != std::string::npos)
	{
		why = "The PDB basename contains a path separator or a reserved character.";
		return false;
	}
	for (unsigned char ch : name)
	{
		if (ch < 0x20)
		{
			why = "The PDB basename contains a control character.";
			return false;
		}
	}
	return true;
}

// Copy a finished PDB into the local symbol store.
StorePublishResult publish_local_store(
	const uint8_t guid[16],
	uint32_t age,
	const std::string& expectedBasename,
	const std::string& sourcePdb,
	const std::string& storeRoot)
{
	StorePublishResult result;
	std::string why;
	if (!pdb_basename_ok(expectedBasename, why))
	{
		result.summary = why;
		return result;
	}
	if (sourcePdb.empty() || storeRoot.empty())
	{
		result.summary = "The PDB path or symbol store path is empty.";
		return result;
	}

	const std::wstring source = full_path(wide_path(sourcePdb));
	const std::wstring root = full_path(wide_path(storeRoot));
	if (source.empty() || root.empty())
	{
		result.summary = "The PDB path or symbol store path could not be converted.";
		return result;
	}
	if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES || is_directory(source))
	{
		result.summary = "The standalone PDB is not a file.";
		return result;
	}
	if (!ensure_store_root(root, why))
	{
		result.summary = why;
		return result;
	}

	result.key = symbol_store_key(guid, age);
	const std::wstring base = wide_path(expectedBasename);
	const std::wstring key = wide_path(result.key);
	const std::wstring baseDir = root + L"\\" + base;
	const std::wstring keyDir = baseDir + L"\\" + key;
	const std::wstring destination = keyDir + L"\\" + base;
	const std::wstring temporary = destination + L".ida2pdb-tmp";
	result.path = narrow_utf8(destination);

	if (full_path(temporary) == source || same_existing_file(temporary, source))
	{
		result.summary = "The temporary store path is the standalone PDB.";
		return result;
	}

	const DWORD destinationAttributes = GetFileAttributesW(destination.c_str());
	const bool destinationExists = destinationAttributes != INVALID_FILE_ATTRIBUTES;
	if (destinationExists && (destinationAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
	{
		result.summary = "The store entry path is a directory.";
		return result;
	}
	if (!create_directory_if_needed(baseDir, why) || !create_directory_if_needed(keyDir, why))
	{
		result.summary = why;
		return result;
	}

	const DWORD temporaryAttributes = GetFileAttributesW(temporary.c_str());
	if (temporaryAttributes != INVALID_FILE_ATTRIBUTES && (temporaryAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
	{
		result.summary = "The temporary store path is a directory.";
		return result;
	}
	delete_file_if_file(temporary);

	const uint64_t sourceSize = file_size(source);
	if (sourceSize == ~uint64_t(0))
	{
		result.summary = "The standalone PDB size could not be read.";
		return result;
	}
	if (!CopyFileW(source.c_str(), temporary.c_str(), FALSE))
	{
		delete_file_if_file(temporary);
		result.summary = "The PDB could not be copied into the symbol store.";
		return result;
	}
	if (file_size(temporary) != sourceSize)
	{
		delete_file_if_file(temporary);
		result.summary = "The staged symbol-store copy is incomplete.";
		return result;
	}
	if (!MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	{
		delete_file_if_file(temporary);
		result.summary = "The staged symbol-store file could not replace the store entry.";
		return result;
	}
	if (file_size(destination) != sourceSize)
	{
		result.summary = "The published symbol-store file is incomplete.";
		return result;
	}

	result.ok = true;
	result.replaced = destinationExists;
	result.summary = destinationExists ? "Replaced the existing store entry." : "Published the PDB to the symbol store.";
	ensure_store_marker(root);
	return result;
}

#if defined(SYMBOL_STORE_CHECKS)

namespace {

// Print a check failure and return an error code.
int fail(const char* message)
{
	std::fprintf(stderr, "FAIL: %s\n", message);
	return 1;
}

// Write a small file for a store check.
bool write_bytes(const wchar_t* path, const char* bytes, size_t size)
{
	const HANDLE handle = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return false;
	DWORD written = 0;
	const BOOL ok = WriteFile(handle, bytes, static_cast<DWORD>(size), &written, nullptr);
	CloseHandle(handle);
	return ok && written == size;
}

// Read a check file into a string.
std::string read_file_bytes(const std::wstring& path)
{
	const HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return {};
	char buffer[64] = {};
	DWORD read = 0;
	ReadFile(handle, buffer, sizeof(buffer), &read, nullptr);
	CloseHandle(handle);
	return std::string(buffer, buffer + read);
}

// Check the age suffix of a store key.
bool expect_key_age(uint32_t age, const char* suffix)
{
	const uint8_t guid[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	const std::string key = symbol_store_key(guid, age);
	const std::string tail = key.size() >= std::strlen(suffix) ? key.substr(key.size() - std::strlen(suffix)) : std::string();
	if (tail != suffix)
	{
		std::fprintf(stderr, "FAIL: age %u key %s does not end with %s\n", age, key.c_str(), suffix);
		return false;
	}
	if (age == 10 && key.size() != 33)
	{
		std::fprintf(stderr, "FAIL: age 10 used a decimal suffix in %s\n", key.c_str());
		return false;
	}
	return true;
}

// Name and value pairs for a test environment.
using EnvEntries = std::vector<std::pair<std::wstring, std::wstring>>;

// Look up a variable in the test environment.
bool lookup_entries(const wchar_t* name, std::wstring& value, void* context)
{
	const EnvEntries* entries = static_cast<const EnvEntries*>(context);
	for (const std::pair<std::wstring, std::wstring>& entry : *entries)
	{
		if (_wcsicmp(entry.first.c_str(), name) == 0)
		{
			value = entry.second;
			return true;
		}
	}
	return false;
}

// Return the ProgramData path used by the discovery checks.
std::wstring program_data_store_for_check()
{
	PWSTR known = nullptr;
	if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DONT_VERIFY, nullptr, &known)) || known == nullptr)
		return std::wstring();
	std::wstring path = known;
	CoTaskMemFree(known);
	if (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
		path.pop_back();
	return path + L"\\Dbg\\sym";
}

// Compare a discovery result with the expected path.
int expect_discovery(
	const EnvEntries& entries,
	const char* explicitOverride,
	const std::wstring& expectedPath,
	const char* expectedSource,
	const char* noteFragment,
	const char* label)
{
	const StoreDiscovery found = discover_publication_store(explicitOverride == nullptr ? std::string() : explicitOverride, lookup_entries, const_cast<EnvEntries*>(&entries));
	if (!store_paths_equivalent(found.path, narrow_utf8(expectedPath)) || found.source != expectedSource)
	{
		std::fprintf(stderr, "FAIL: %s path=%s source=%s expected source=%s\n", label, found.path.c_str(), found.source.c_str(), expectedSource);
		return 1;
	}
	if (noteFragment != nullptr && found.notes.find(noteFragment) == std::string::npos)
	{
		std::fprintf(stderr, "FAIL: %s notes missing '%s' in '%s'\n", label, noteFragment, found.notes.c_str());
		return 1;
	}
	if (found.explicitOverride != (explicitOverride != nullptr && explicitOverride[0] != '\0'))
		return fail(label);
	return 0;
}

// Create a directory for a discovery check.
bool ensure_dir(const std::wstring& path)
{
	if (is_directory(path))
		return true;
	return CreateDirectoryW(path.c_str(), nullptr) != FALSE;
}

// Delete a directory tree left by a check.
void remove_tree(const std::wstring& path)
{
	WIN32_FIND_DATAW data = {};
	const HANDLE find = FindFirstFileW((path + L"\\*").c_str(), &data);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (std::wcscmp(data.cFileName, L".") == 0 || std::wcscmp(data.cFileName, L"..") == 0)
				continue;
			const std::wstring child = path + L"\\" + data.cFileName;
			if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
				remove_tree(child);
			else
				DeleteFileW(child.c_str());
		} while (FindNextFileW(find, &data));
		FindClose(find);
	}
	RemoveDirectoryW(path.c_str());
}

// Run the symbol-store discovery checks.
int discovery_checks(const std::wstring& root)
{
	if (!ensure_dir(root))
		return fail("resolve directory");
	const std::wstring plainSearch = root + L"\\plain-search";
	const std::wstring plainStore = root + L"\\plain-store";
	const std::wstring cafe = root + L"\\caf\u00e9";
	const std::wstring spaced = root + L"\\cache dir";
	if (!ensure_dir(plainSearch) || !ensure_dir(plainStore) || !ensure_dir(cafe))
		return fail("fixture directories");
	if (!write_bytes((plainStore + L"\\pingme.txt").c_str(), "existing\n", 9))
		return fail("plain pingme");
	if (!write_bytes((cafe + L"\\pingme.txt").c_str(), "existing\n", 9))
		return fail("unicode pingme");
	DeleteFileW((plainSearch + L"\\pingme.txt").c_str());

	const std::wstring programData = program_data_store_for_check();
	if (programData.empty())
		return fail("programdata known folder");
	EnvEntries none;
	if (expect_discovery(none, nullptr, programData, "ProgramData", nullptr, "unset variables") != 0)
		return 1;
	EnvEntries emptyVars = {
		{ L"_NT_SYMBOL_PATH", L"" },
		{ L"_NT_ALT_SYMBOL_PATH", L"" },
		{ L"_NT_ALTERNATE_SYMBOL_PATH", L"" }
	};
	if (expect_discovery(emptyVars, "", programData, "ProgramData", nullptr, "empty variables") != 0)
		return 1;

	const std::wstring first = L"C:\\ida2pdb-resolve-first";
	const std::wstring second = L"C:\\ida2pdb-resolve-second";
	const std::wstring third = L"C:\\ida2pdb-resolve-third";
	EnvEntries precedence = {
		{ L"_NT_SYMBOL_PATH", L"cache*" + first },
		{ L"_NT_ALT_SYMBOL_PATH", L"cache*" + second },
		{ L"_NT_ALTERNATE_SYMBOL_PATH", L"cache*" + third }
	};
	if (expect_discovery(precedence, nullptr, first, "_NT_SYMBOL_PATH", nullptr, "symbol path precedence") != 0)
		return 1;
	EnvEntries altOnly = {
		{ L"_NT_SYMBOL_PATH", L"srv*https://msdl.microsoft.com/download/symbols" },
		{ L"_NT_ALT_SYMBOL_PATH", L"cache*" + second }
	};
	if (expect_discovery(altOnly, nullptr, second, "_NT_ALT_SYMBOL_PATH", "HTTP", "alt after remote-only") != 0)
		return 1;
	EnvEntries alternateOnly = {
		{ L"_NT_SYMBOL_PATH", L"srv*\\\\server\\share" },
		{ L"_NT_ALT_SYMBOL_PATH", L"https://msdl.microsoft.com/download/symbols" },
		{ L"_NT_ALTERNATE_SYMBOL_PATH", L"srv*" + third + L"*https://msdl.microsoft.com/download/symbols" }
	};
	if (expect_discovery(alternateOnly, nullptr, third, "_NT_ALTERNATE_SYMBOL_PATH", "UNC", "alternate after unc") != 0)
		return 1;

	const std::wstring named = root + L"\\named-cache";
	EnvEntries category = {
		{ L"_NT_SYMBOL_PATH", plainStore + L";cache*" + named + L";cache*" + named + L"\\" }
	};
	if (expect_discovery(category, nullptr, named, "_NT_SYMBOL_PATH", nullptr, "cache preferred and deduped") != 0)
		return 1;
	EnvEntries plainOnly = { { L"_NT_SYMBOL_PATH", plainSearch + L";" + plainStore } };
	if (expect_discovery(plainOnly, nullptr, plainStore, "_NT_SYMBOL_PATH", nullptr, "pingme plain directory") != 0)
		return 1;
	EnvEntries searchOnly = { { L"_NT_SYMBOL_PATH", plainSearch } };
	if (expect_discovery(searchOnly, nullptr, programData, "ProgramData", nullptr, "search directory is not a store") != 0)
		return 1;

	const std::wstring home = root + L"\\not-created-home";
	const std::wstring homeSym = home + L"\\sym";
	RemoveDirectoryW(homeSym.c_str());
	RemoveDirectoryW(home.c_str());
	EnvEntries implicit = {
		{ L"_NT_SYMBOL_PATH", L"srv**https://msdl.microsoft.com/download/symbols" },
		{ L"DBGHELP_HOMEDIR", home }
	};
	if (expect_discovery(implicit, nullptr, homeSym, "DBGHELP_HOMEDIR", nullptr, "default downstream placeholder") != 0)
		return 1;
	if (GetFileAttributesW(home.c_str()) != INVALID_FILE_ATTRIBUTES || GetFileAttributesW(homeSym.c_str()) != INVALID_FILE_ATTRIBUTES)
		return fail("discovery created DBGHELP_HOMEDIR");
	EnvEntries cacheStar = {
		{ L"_NT_SYMBOL_PATH", L"cache*" },
		{ L"DBGHELP_HOMEDIR", L"https://not-a-home" }
	};
	if (expect_discovery(cacheStar, nullptr, programData, "ProgramData", "DBGHELP_HOMEDIR", "invalid home uses programdata") != 0)
		return 1;
	EnvEntries symsrv = {
		{ L"_NT_SYMBOL_PATH", L"symsrv*symsrv.dll*" + cafe + L"*https://msdl.microsoft.com/download/symbols" }
	};
	if (expect_discovery(symsrv, nullptr, cafe, "_NT_SYMBOL_PATH", nullptr, "symsrv.dll downstream") != 0)
		return 1;
	EnvEntries otherProvider = {
		{ L"_NT_SYMBOL_PATH", L"symsrv*other.dll*C:\\secret;cache*" + spaced }
	};
	if (expect_discovery(otherProvider, nullptr, spaced, "_NT_SYMBOL_PATH", "unsupported", "other provider") != 0)
		return 1;
	EnvEntries upstream = {
		{ L"_NT_SYMBOL_PATH", L"srv**C:\\upstream-not-used" },
		{ L"DBGHELP_HOMEDIR", home }
	};
	if (expect_discovery(upstream, nullptr, homeSym, "DBGHELP_HOMEDIR", nullptr, "placeholder is not the upstream") != 0)
		return 1;
	if (GetFileAttributesW(L"C:\\upstream-not-used") != INVALID_FILE_ATTRIBUTES)
		return fail("upstream directory was created");

	EnvEntries expanded = {
		{ L"_NT_SYMBOL_PATH", L"cache*%IDA2PDB_TEST_STORE%" },
		{ L"IDA2PDB_TEST_STORE", spaced }
	};
	if (expect_discovery(expanded, nullptr, spaced, "_NT_SYMBOL_PATH", nullptr, "environment expansion") != 0)
		return 1;
	EnvEntries unresolved = {
		{ L"_NT_SYMBOL_PATH", L"cache*%IDA2PDB_MISSING%\\x;cache*" + first }
	};
	if (expect_discovery(unresolved, nullptr, first, "_NT_SYMBOL_PATH", "IDA2PDB_MISSING", "unresolved variable") != 0)
		return 1;
	EnvEntries malformed = {
		{ L"_NT_SYMBOL_PATH", L"cache*C:\\a*C:\\b;cache*" + second }
	};
	if (expect_discovery(malformed, nullptr, second, "_NT_SYMBOL_PATH", "malformed", "malformed cache") != 0)
		return 1;
	EnvEntries bareSrv = { { L"_NT_SYMBOL_PATH", L"srv*" } };
	if (expect_discovery(bareSrv, nullptr, programData, "ProgramData", nullptr, "srv star has no downstream") != 0)
		return 1;

	const char* explicitPath = "\\\\explicit-server\\share";
	EnvEntries ignored = { { L"_NT_SYMBOL_PATH", L"cache*" + first } };
	const StoreDiscovery chosen = discover_publication_store(explicitPath, lookup_entries, &ignored);
	if (!chosen.explicitOverride || chosen.source != "explicit" || chosen.path.find("explicit-server") == std::string::npos)
		return fail("explicit override");

	const std::wstring missing = root + L"\\nested\\child\\store";
	const std::wstring fileStore = root + L"\\store-is-a-file";
	const std::wstring blockedParent = root + L"\\blocked-parent";
	remove_tree(root + L"\\nested");
	EnvEntries unusable = { { L"_NT_SYMBOL_PATH", L"cache*" + missing } };
	const StoreDiscovery missingFound = discover_publication_store("", lookup_entries, &unusable);
	if (!store_paths_equivalent(missingFound.path, narrow_utf8(missing)))
		return fail("missing store selection");
	if (GetFileAttributesW((root + L"\\nested").c_str()) != INVALID_FILE_ATTRIBUTES)
		return fail("discovery created a nested store");
	const std::wstring source = root + L"\\source.pdb";
	if (!write_bytes(source.c_str(), "source-pdb", 10))
		return fail("source pdb");
	const uint8_t guid[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
	const StorePublishResult created = publish_local_store(guid, 1, "Name.pdb", narrow_utf8(source), missingFound.path);
	const std::wstring createdFile = missing + L"\\Name.pdb\\" + wide_path(created.key) + L"\\Name.pdb";
	if (!created.ok || !is_directory(missing) || read_file_bytes(createdFile) != "source-pdb" || read_file_bytes(source) != "source-pdb" || read_file_bytes(missing + L"\\pingme.txt") != "ida2pdb\n")
		return fail("create nested store");
	if (!write_bytes(fileStore.c_str(), "not-a-directory", 15))
		return fail("file store fixture");
	const StorePublishResult fileBlocked = publish_local_store(guid, 1, "Name.pdb", narrow_utf8(source), narrow_utf8(fileStore));
	if (fileBlocked.ok || read_file_bytes(fileStore) != "not-a-directory" || read_file_bytes(source) != "source-pdb")
		return fail("file destination");
	if (!write_bytes(blockedParent.c_str(), "parent-file", 11))
		return fail("blocked parent fixture");
	const StorePublishResult parentBlocked = publish_local_store(guid, 1, "Name.pdb", narrow_utf8(source), narrow_utf8(blockedParent + L"\\child"));
	if (parentBlocked.ok || GetFileAttributesW((blockedParent + L"\\child").c_str()) != INVALID_FILE_ATTRIBUTES || read_file_bytes(source) != "source-pdb" || read_file_bytes(blockedParent) != "parent-file")
		return fail("parent file blocks creation");

	const std::wstring markerStore = root + L"\\marker-store";
	if (!ensure_dir(markerStore))
		return fail("marker store");
	DeleteFileW((markerStore + L"\\pingme.txt").c_str());
	const StorePublishResult published = publish_local_store(guid, 1, "Name.pdb", narrow_utf8(source), narrow_utf8(markerStore));
	if (!published.ok || read_file_bytes(markerStore + L"\\pingme.txt") != "ida2pdb\n")
		return fail("created pingme");
	if (!write_bytes((markerStore + L"\\pingme.txt").c_str(), "keep-me", 7))
		return fail("rewrite pingme");
	const StorePublishResult again = publish_local_store(guid, 1, "Name.pdb", narrow_utf8(source), narrow_utf8(markerStore));
	if (!again.ok || !again.replaced || read_file_bytes(markerStore + L"\\pingme.txt") != "keep-me")
		return fail("preserved pingme");

	if (!SetEnvironmentVariableW(L"IDA2PDB_RESOLVE_PROBE", L"probe-value"))
		return fail("set probe");
	std::wstring probe;
	if (!store_env_lookup_process(L"IDA2PDB_RESOLVE_PROBE", probe, nullptr) || probe != L"probe-value")
		return fail("process lookup");
	SetEnvironmentVariableW(L"IDA2PDB_RESOLVE_PROBE", nullptr);
	if (store_env_lookup_process(L"IDA2PDB_RESOLVE_PROBE", probe, nullptr))
		return fail("probe remained set");

	std::printf("discover-check ok\n");
	return 0;
}

} // namespace

// Run the symbol-store checks.
int main()
{
	wchar_t tempRoot[MAX_PATH] = {};
	if (GetTempPathW(MAX_PATH, tempRoot) == 0)
		return fail("temp path");
	const std::wstring scratch = std::wstring(tempRoot) + L"ida2pdb-store-check";
	remove_tree(scratch);
	if (!ensure_dir(scratch))
		return fail("scratch directory");
	if (discovery_checks(scratch + L"\\resolve") != 0)
		return 1;

	const uint8_t kernelGuid[16] = {
		0x8F, 0x9D, 0x9E, 0xAE, 0xC1, 0x7A, 0x7A, 0x46,
		0x64, 0x53, 0x20, 0xFD, 0xC2, 0x32, 0x35, 0xD0
	};
	const std::string kernelKey = symbol_store_key(kernelGuid, 1);
	if (kernelKey != "AE9E9D8F7AC1467A645320FDC23235D01")
		return fail("kernel32 GUID byte order");
	if (!expect_key_age(10, "A") || !expect_key_age(27, "1B") || !expect_key_age(0x35B, "35B") || !expect_key_age(0xFFFFFFFFu, "FFFFFFFF"))
		return 1;

	std::string why;
	if (pdb_basename_ok("..", why) || pdb_basename_ok("a\\b.pdb", why) || pdb_basename_ok("", why))
		return fail("basename validation accepted a bad name");
	if (!pdb_basename_ok("SymbolSourceTest.pdb", why))
		return fail("basename validation rejected a normal name");

	const std::wstring root = scratch + L"\\publish";
	if (!ensure_dir(root))
		return fail("publish directory");
	const std::wstring source = root + L"\\source.pdb";
	const std::wstring other = root + L"\\other.pdb";
	if (!write_bytes(source.c_str(), "first-pdb", 9) || !write_bytes(other.c_str(), "second-pdb", 10))
		return fail("write fixtures");

	char rootUtf8[MAX_PATH] = {};
	char sourceUtf8[MAX_PATH] = {};
	WideCharToMultiByte(CP_UTF8, 0, root.c_str(), -1, rootUtf8, MAX_PATH, nullptr, nullptr);
	WideCharToMultiByte(CP_UTF8, 0, source.c_str(), -1, sourceUtf8, MAX_PATH, nullptr, nullptr);
	const uint8_t guid[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
	const std::string key = symbol_store_key(guid, 27);
	if (key.size() < 2 || key.substr(key.size() - 2) != "1B")
		return fail("publish fixture age");

	StorePublishResult published = publish_local_store(guid, 27, "CustomName.pdb", sourceUtf8, rootUtf8);
	if (!published.ok || published.replaced)
		return fail("first publish");
	const std::wstring publishedPath = root + L"\\CustomName.pdb\\" + std::wstring(key.begin(), key.end()) + L"\\CustomName.pdb";
	if (read_file_bytes(publishedPath) != "first-pdb")
		return fail("published bytes");
	if (read_file_bytes(source) != "first-pdb")
		return fail("source removed");

	char otherUtf8[MAX_PATH] = {};
	WideCharToMultiByte(CP_UTF8, 0, other.c_str(), -1, otherUtf8, MAX_PATH, nullptr, nullptr);
	const HANDLE lock = CreateFileW(publishedPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (lock == INVALID_HANDLE_VALUE)
		return fail("lock store entry");
	StorePublishResult blocked = publish_local_store(guid, 27, "CustomName.pdb", otherUtf8, rootUtf8);
	CloseHandle(lock);
	if (blocked.ok || read_file_bytes(publishedPath) != "first-pdb" || read_file_bytes(other) != "second-pdb")
		return fail("locked replacement");

	StorePublishResult replaced = publish_local_store(guid, 27, "CustomName.pdb", otherUtf8, rootUtf8);
	if (!replaced.ok || !replaced.replaced || read_file_bytes(publishedPath) != "second-pdb" || read_file_bytes(other) != "second-pdb")
		return fail("replacement");

	StorePublishResult ontoSource = publish_local_store(guid, 27, "CustomName.pdb", otherUtf8, rootUtf8);
	// The source here is not the store file. Publish the store file onto itself.
	char publishedUtf8[MAX_PATH * 2] = {};
	WideCharToMultiByte(CP_UTF8, 0, publishedPath.c_str(), -1, publishedUtf8, sizeof(publishedUtf8), nullptr, nullptr);
	ontoSource = publish_local_store(guid, 27, "CustomName.pdb", publishedUtf8, rootUtf8);
	if (!ontoSource.ok || read_file_bytes(publishedPath) != "second-pdb")
		return fail("publish onto source");

	const std::wstring fileStore = root + L"\\not-a-directory";
	write_bytes(fileStore.c_str(), "x", 1);
	char fileStoreUtf8[MAX_PATH] = {};
	WideCharToMultiByte(CP_UTF8, 0, fileStore.c_str(), -1, fileStoreUtf8, MAX_PATH, nullptr, nullptr);
	StorePublishResult badRoot = publish_local_store(guid, 27, "CustomName.pdb", otherUtf8, fileStoreUtf8);
	if (badRoot.ok || read_file_bytes(other) != "second-pdb" || read_file_bytes(publishedPath) != "second-pdb")
		return fail("store path that is a file");

	const std::string ageTen = symbol_store_key(guid, 10);
	const std::wstring ageTenTemp = root + L"\\AgeTen.pdb\\" + std::wstring(ageTen.begin(), ageTen.end()) + L"\\AgeTen.pdb.ida2pdb-tmp";
	CreateDirectoryW((root + L"\\AgeTen.pdb").c_str(), nullptr);
	CreateDirectoryW((root + L"\\AgeTen.pdb\\" + std::wstring(ageTen.begin(), ageTen.end())).c_str(), nullptr);
	CreateDirectoryW(ageTenTemp.c_str(), nullptr);
	const StorePublishResult tempBlocked = publish_local_store(guid, 10, "AgeTen.pdb", otherUtf8, rootUtf8);
	if (tempBlocked.ok)
		return fail("temporary directory was replaced");
	if (read_file_bytes(other) != "second-pdb")
		return fail("failed publish changed the source");

	remove_tree(scratch);
	if (GetFileAttributesW(scratch.c_str()) != INVALID_FILE_ATTRIBUTES)
		return fail("scratch directory was not removed");
	std::printf("store-check ok key27=%s age10-length=%zu\n", key.c_str(), symbol_store_key(guid, 10).size());
	return 0;
}
#endif
