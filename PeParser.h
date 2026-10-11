
// Attempt to parse PE and PDB info from the loaded IDB, fall back to original executable if it doesn't exist
#pragma once

#include "DebugParser.h"

#include <string>

// PE parse result
struct IdentityReport
{
	bool ok = false;                  // True when the machine, image base, sections, and PDB debug record were recovered.
	bool hasImage = false;            // True when image contains that recovered PE.
	std::string summary;              // Short result sentence. A failed recovery uses this text in the warning dialog.
	std::string text;                 // Full key=value identity report. A headless run also writes it to the identity file.
	PeImage image;                    // Recovered PE image, including the original image base, sections, and RSDS record.
	uint64_t currentImageBase = 0;    // IDA's current image base, used to map names after a rebase.
};

// Parse PE and PDB identity, optionally asking with file dialog to get the source executable file 
IdentityReport parse_pe_info(bool allowDialog);
