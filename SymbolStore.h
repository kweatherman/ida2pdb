
// Push finished PDB into the local symbol store support
#pragma once

#include <cstdint>
#include <string>

// Direct single-tier symbol store:
//   <store>/<expected PDB basename>/<GUID and age>/<expected PDB basename>
// Uncompressed files only. No symstore.exe, DbgHelp.dll, use nor transaction index.

// PDB push result
struct StorePublishResult
{
	bool ok = false;            // True when the entry was published or replaced.
	bool replaced = false;      // True when an existing store file was replaced.
	std::string summary;        // Result sentence reported for the publication.
	std::string path;           // Full path of the store PDB: <store>\<basename>\<key>\<basename>.
	std::string key;            // GUID-and-age directory name.
};

// Uppercase GUID fields in symbol-server order, then age in hexadecimal with no leading zeros. Age 10 is "A", not "10".
std::string symbol_store_key(const uint8_t guid[16], uint32_t age);

// Return whether a PDB basename is safe to use as a path component
bool pdb_basename_ok(const std::string& name, std::string& why);

// Copy sourcePdb into the store. The source file is not deleted.
// An existing entry is replaced. Failure leaves any previous store file in place.
// A successful publication creates pingme.txt when that marker is absent.
StorePublishResult publish_local_store(
	const uint8_t guid[16],
	uint32_t age,
	const std::string& expectedBasename,
	const std::string& sourcePdb,
	const std::string& storeRoot);

// Convert a UTF-8 path to UTF-16. Text that is not valid UTF-8 is read as the ANSI code page.
std::wstring wide_path(const std::string& path);

// Convert a UTF-16 path to UTF-8.
std::string narrow_utf8(const std::wstring& path);

// Selected publication directory container.
// source is "explicit", "_NT_SYMBOL_PATH", "_NT_ALT_SYMBOL_PATH",
// "_NT_ALTERNATE_SYMBOL_PATH", "DBGHELP_HOMEDIR", or "ProgramData".
// An explicit override is not refreshed from the environment.
// Discovery does not create directories.
struct StoreDiscovery
{
	std::string path;    // Selected store directory. An explicit override is kept as given, including a UNC path.
	std::string source;  // Which rule selected the directory: "explicit", a symbol-path variable, "DBGHELP_HOMEDIR", or "ProgramData".
	std::string detail;  // Why that directory was eligible, such as an explicit override, a cache entry, or a plain directory with pingme.txt.
	std::string notes;   // Skipped paths and other scan remarks, joined with "; ". Empty when nothing was skipped.
	bool explicitOverride = false; // True when the caller supplied a non-empty override, so the environment was not scanned.
};

// Return false when the variable is unset. An empty value is present
typedef bool (*StoreEnvLookup)(const wchar_t* name, std::wstring& value, void* context);

bool store_env_lookup_process(const wchar_t* name, std::wstring& value, void* context);

// explicitOverride wins unchanged, including a UNC path chosen by the user.
// Otherwise scan _NT_SYMBOL_PATH, then _NT_ALT_SYMBOL_PATH, then
// _NT_ALTERNATE_SYMBOL_PATH. The last resort is <DBGHELP_HOMEDIR>\sym when
// that variable is a local path, or the ProgramData known folder plus \Dbg\sym.
StoreDiscovery discover_publication_store(
	const std::string& explicitOverride,
	StoreEnvLookup lookup,
	void* context);

// Return whether two store paths name the same directory.
bool store_paths_equivalent(const std::string& left, const std::string& right);
