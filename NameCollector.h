
// Collect name/labels that have an address from the loaded IDB for export
#pragma once

#include "DebugParser.h"

#include <cstdint>
#include <string>
#include <vector>

// Name types
enum class NameKind
{
	Function,
	Code,
	Data
};

// Name entry
struct CollectedName
{
	std::string name;
	std::string scope;
	uint64_t rva = 0;
	uint32_t sectionIndex = 0;
	uint32_t sectionOffset = 0;
	NameKind kind = NameKind::Data;
	bool imported = false;
	bool generated = false;
	bool duplicate = false;
	bool alias = false;
	bool local = false;
};

// Collection result, including the preview text and accepted names.
struct NamePreview
{
	bool ok = false;
	bool canceled = false;
	std::string summary;
	std::string text;
	std::vector<CollectedName> names;
};

// Return true to cancel collection. "phase" is a short label such as "heads".
using NameHook = bool (*)(void* context, const char* phase);

// Collect public-symbol names from the current database.
// includeGenerated keeps IDA dummy address names (sub_, loc_, and the other names has_dummy_name reports). 
// User, import, and meaningful auto names are collected either way. diagnostic keeps the per-name preview text.
NamePreview collect_names(const PeImage& image, uint64_t currentImageBase, bool includeGenerated, bool diagnostic, NameHook hook, void* hookContext);
