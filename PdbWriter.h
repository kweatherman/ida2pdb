
// Public-symbol PDB writer
#pragma once

#include "NameCollector.h"

#include <cstdint>
#include <string>

// PDB export result
struct PdbExportResult
{
	bool ok = false;
	bool canceled = false;
	std::string summary;
	std::string text;
	std::string path;
	uint64_t pdbBytes = 0;
	size_t exported = 0;
	size_t functions = 0;
	size_t code = 0;
	size_t data = 0;
	size_t idaLocals = 0;
	size_t omittedHeader = 0;
	size_t omittedLong = 0;
	size_t omittedSection = 0;
};

// Return true from the hook to cancel before the final PDB is published
using PdbHook = bool (*)(void* context, const char* phase);

#ifndef _DEBUG
// Write names to PDB
PdbExportResult export_public_pdb(const PeImage& image, const std::vector<CollectedName>& names, const std::string& outputPath, PdbHook hook, void* hookContext);
#else
// Refuse PDB export from the debug build.
inline PdbExportResult export_public_pdb(const PeImage&, const std::vector<CollectedName>&, const std::string&, PdbHook, void*)
{
	PdbExportResult result;
	result.summary = "PDB export requires the Release plugin.";
	result.text = "ok=no\nsummary=" + result.summary + "\n";
	return result;
}
#endif
