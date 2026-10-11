
// IDB2PD plug-in by Kevin Weatherman
// https://github.com/kweatherman/ida2pdb
#include "StdAfx.h"
#include "NameCollector.h"
#include "PdbWriter.h"
#include "PeParser.h"
#include "SymbolStore.h"
#include <WaitBoxEx.h>
#include <kernwin.hpp>
#include <chrono>

#include <cstdio>
#include <cstring>
#include <string>

// Option flags. The first two headless bits mirror the GUI checkbox order.
static const WORD OPT_PUSH_PDB = 1u << 0;
static const WORD OPT_INCLUDE_GENERATED = 1u << 1;
static const size_t BATCH_PUBLISH = 1u << 0;
static const size_t BATCH_INCLUDE_GENERATED = 1u << 1;
static const size_t BATCH_DIAGNOSTIC = 1u << 2;
static const size_t BATCH_CANCEL_BEFORE_PUBLISH = 1u << 3;

struct ProgressTracker
{
	bool interactive = false;
	bool cancelBeforePublish = false;
};

static const char SITE_URL[] = { "https://github.com/kweatherman/ida2pdb" };
static const char dialogForm[] =
{
	"BUTTON YES* Continue\n" // "Continue" instead of the "okay" button

	// Title, then the two blank lines ask_form requirement
	"IDA to PDB export utility\n\n\n"
    #ifdef _DEBUG
    "** DEBUG BUILD **\n"
    #endif

	// Message text
    "ida2pdb: version %A, by Kevin Weatherman\n"    
	"Export function and data labels to a PDB file to aid in debugging.\n"
	"<#Click to open repo page.#ida2pdb Github:k:2:1::>\n\n"

	// Options (order matches the option bits).
	"Options:\n"
	"<#Push the generated PDB to the local symbol store for automatic debugger loading.#Push PDB to symbol store:C>\n"
	"<#Include names (with addresses) such as sub_401000 and loc_401000. Assigned, imported, and meaningful auto names are collected either way.#Include generated names:C>>\n"
	"\n"
};

static const char waitboxStyle[] =
{
	"QProgressDialog {"
		"background: qradialgradient("
		"cx:0.22, cy:0.08, radius:1.25, fx:0.22, fy:0.08,"
		"stop:0 #FFF9EE, stop:0.5 #FBF3E6, stop:1 #E4CBA3);"
		"color: #30282A;"
	"}"

	"QLabel {"
		"background: transparent;"
		"color: #30282A;"
		"border: none;"
		"padding: 0px;"
		"font-size: 11pt;"
		"font-weight: bold;"
	"}"

	"QPushButton {"
		"background: qlineargradient("
			"x1:0, y1:0, x2:0, y2:1,"
			"stop:0 #9C1A27, stop:1 #650E17);"
		"color: #FBF3E6;"
		"border: 1px solid #650E17;"
		"border-radius: 5px;"
		"padding: 1px 6px;"
		"margin: 0px;"
		"font-size: 10pt;"
		"font-weight: bold;"
	"}"
	"QPushButton:hover {"
		"background: #AF2331;"
	"}"
	"QPushButton:focus {"
		"border: 1px dashed #D9AD69;"
	"}"
	"QPushButton:pressed {"
		"background: #550B13;"
		"border: 1px solid #D9AD69;"
	"}"
	"QPushButton:disabled {"
		"background: #D8C3A3;"
		"color: #8B8072;"
		"border: 1px solid #8B8072;"
	"}"

	"QProgressBar {"
		"background: #D8C3A3;"
		"border: none;"
		"border-radius: 2px;"
		"padding: 0px;"
		"margin: 0px;"
		"color: #30282A;"
		"qproperty-textVisible: false;"
	"}"
	"QProgressBar::chunk {"
		"background: qlineargradient("
			"x1:0, y1:0, x2:1, y2:0,"
			"stop:0 #650E17, stop:0.55 #B52C3A, stop:1 #850B15);"
		"border: none;"
		"border-radius: 2px;"
		"width: 24px;"
		"margin: 0px;"
	"}"
};

static BOOL optPushPdb = TRUE;
static BOOL optIncludeGenerated = TRUE;

// ============================================================================

// Return the directory portion of a path.
static std::string directory_of(const std::string& path)
{
	const size_t slash = path.find_last_of("\\/");
	if (slash == std::string::npos)
		return std::string();
	return path.substr(0, slash);
}

// Build the default PDB path beside the loaded database.
static std::string pdb_path_beside_database(const PeImage& image)
{
	const char* idb = get_path(PATH_TYPE_IDB);
	if (idb == nullptr || idb[0] == '\0' || image.pdbBasename.empty())
		return std::string();
	std::string why;
	if (!pdb_basename_ok(image.pdbBasename, why))
		return std::string();
	const std::string directory = directory_of(idb);
	if (directory.empty())
		return image.pdbBasename;
	return directory + "\\" + image.pdbBasename;
}

// Build a UTF-8 PDB path in the process temporary directory.
static std::string temporary_pdb_path(const std::string& basename, std::string& why)
{
	if (!pdb_basename_ok(basename, why))
		return std::string();
	wchar_t folder[MAX_PATH + 1] = {};
	const DWORD length = GetTempPathW(MAX_PATH + 1, folder);
	if (length == 0 || length > MAX_PATH)
	{
		why = "The temporary directory could not be read.";
		return std::string();
	}
	std::wstring path = folder;
	if (path.back() != L'\\' && path.back() != L'/')
		path += L'\\';
	path += L"ida2pdb-" + std::to_wstring(GetCurrentProcessId()) + L"-" + wide_path(basename);
	return narrow_utf8(path);
}

// Return whether path is an existing file.
static bool file_exists(const std::string& path)
{
	if (path.empty())
		return false;
	const DWORD attributes = GetFileAttributesW(wide_path(path).c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// Read the first line of a side file. A missing file gives an empty line.
// Returns false when the file is present but cannot be read.
static bool read_line_file(const std::string& path, std::string& line)
{
	line.clear();
	if (path.empty())
		return true;
	const std::wstring widePath = wide_path(path);
	if (GetFileAttributesW(widePath.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		const DWORD error = GetLastError();
		return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
	}
	FILE* input = nullptr;
	if (_wfopen_s(&input, widePath.c_str(), L"rb") != 0 || input == nullptr)
		return false;
	char buffer[4096] = {};
	const size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, input);
	const bool failed = std::ferror(input) != 0;
	std::fclose(input);
	if (failed)
		return false;
	std::string text(buffer, buffer + read);
	if (text.compare(0, 3, "\xEF\xBB\xBF") == 0)
		text.erase(0, 3);
	const size_t end = text.find_first_of("\r\n");
	if (end != std::string::npos)
		text.resize(end);
	while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
		text.pop_back();
	line = text;
	return true;
}

// Write text to a file and return false when the write fails.
static bool write_text_file(const std::string& path, const std::string& text)
{
	FILE* output = nullptr;
	if (_wfopen_s(&output, wide_path(path).c_str(), L"wb") != 0 || output == nullptr)
		return false;
	const bool ok = std::fwrite(text.data(), 1, text.size(), output) == text.size();
	std::fclose(output);
	return ok;
}

// Join a file name to the directory that contains the loaded database.
static std::string idb_side_file(const char* name)
{
	const char* idb = get_path(PATH_TYPE_IDB);
	if (idb == nullptr || idb[0] == '\0')
		return std::string();
	const std::string directory = directory_of(idb);
	if (directory.empty())
		return name;
	return directory + "\\" + name;
}

// ============================================================================

// Accept the plugin and let IDA unload it after each run.
plugmod_t* idaapi init()
{
	return PLUGIN_OK;
}

// Clean up when the plugin is unloaded.
void idaapi term()
{
}

// Open the project page when the Github link is clicked.
static int idaapi doHyperlink(int button_code, form_actions_t &fa)
{
	(void)button_code;
	(void)fa;
	open_url(SITE_URL);
	return 0;
}

// ============================================================================

// Update the progress label and report cancellation during an export.
static bool idaapi export_hook(PVOID context, const char* phase)
{
	auto* state = static_cast<ProgressTracker*>(context);
	if (state->interactive)
	{
		//if (phase != nullptr)
		//	WaitBox::setLabelText(phase);
		if (WaitBox::updateAndCancelCheck(-1))
			return true;
	}
	if (state->cancelBeforePublish && phase != nullptr && std::strcmp(phase, "publish") == 0)
		return true;
	return false;
}

// Write a batch report beside the command-line file or database: <base>.<kind>-<arg>.txt
static void write_report(size_t arg, const char* kind, const std::string& text)
{
	const char* base = get_path(PATH_TYPE_CMD);
	if (base == nullptr || base[0] == '\0')
		base = get_path(PATH_TYPE_IDB);
	if (base == nullptr)
		return;
	char path[4096];
	std::snprintf(path, sizeof(path), "%s.%s-%llu.txt", base, kind, static_cast<unsigned long long>(arg));
	if (!write_text_file(path, text))
		msg(" Could not write the report: \"%s\"\n", path);
}

// Write the PE identity report beside the command-line file or database.
static void write_identity_report(size_t arg, const IdentityReport& report)
{
	write_report(arg, "identity", report.text);
}

// Write the export summary beside the command-line file or database.
static void write_export_report(size_t arg, const std::string& text)
{
	write_report(arg, "export", text);
}

// Write the diagnostic name preview beside the command-line file or database.
static void write_named_report(size_t arg, const std::string& text)
{
	write_report(arg, "names", text);
}

// Count PE sections that carry code or data. The name walk still visits every IDA segment.
static size_t code_and_data_section_count(const PeImage& image, size_t& otherSections)
{
	const uint32_t codeOrData = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
	size_t codeData = 0;
	for (const PeSection& section : image.sections)
	{
		if ((section.characteristics & codeOrData) != 0)
			++codeData;
	}
	otherSections = image.sections.size() - codeData;
	return codeData;
}

// Print the section walk that is about to start.
static void log_section_iteration(const PeImage& image)
{
	size_t otherSections = 0;
	const size_t codeData = code_and_data_section_count(image, otherSections);
	if (otherSections == 0)
		msg("Iterating %u code and data sections for names.\n", static_cast<unsigned>(codeData));
	else
		msg("Iterating %u code and data sections, plus %u other sections names..\n", static_cast<unsigned>(codeData), static_cast<unsigned>(otherSections));
	WaitBox::processIdaEvents();
}

// Print the embedded CodeView PDB path after it has been parsed.
static void log_codeview(const PeImage& image)
{
	if (!image.hasRsds)
		return;
	msg("\nParsed IMAGE_DEBUG_TYPE_CODEVIEW:\n");
	msg(" PdbFileName: \"%s\"\n", image.pdbPath.c_str());
}

// Print the store source that actually selected the destination.
static void log_symbol_store(const std::string& source, const std::string& path)
{
	msg("\nSymbol store:\n");
	if (path.empty())
	{
		msg("No destination was determined.\n");
		return;
	}
	const bool environment = source == "_NT_SYMBOL_PATH"
		|| source == "_NT_ALT_SYMBOL_PATH"
		|| source == "_NT_ALTERNATE_SYMBOL_PATH"
		|| source == "DBGHELP_HOMEDIR";
	if (environment)
		msg(" Parsed env var(s): %s\n", source.c_str());
	else if (source == "explicit")
		msg(" Source: explicit directory\n");
	else if (source == "ProgramData")
		msg(" Source: ProgramData\\Dbg\\sym\n");
	else if (!source.empty())
		msg(" Source: %s\n", source.c_str());
	msg(" Determined: \"%s\"\n", path.c_str());
}

// Format an integer with comma thousands separators.
static const char* comma_count(size_t value, char* buffer)
{
	return NumberCommaString(static_cast<UINT64>(value), buffer);
}

// Format a byte size as binary mebibytes with one decimal place.
static void format_mib(uint64_t bytes, char* buffer, size_t bufferSize)
{
	const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
	std::snprintf(buffer, bufferSize, "%.1f MiB", mib);
}

// Print a failed operation without hiding the concrete reason.
static void log_failure(const char* operation, const std::string& reason, const std::string& path)
{
	msg("\n%s failed:\n", operation);
	msg(" %s\n", reason.empty() ? "No details were reported." : reason.c_str());
	if (!path.empty())
		msg(" Path: \"%s\"\n", path.c_str());
	if (std::strcmp(operation, "Export") == 0)
		msg("** Plugin aborted! **\n");
}

// Print the exported category counts. Locals and imports are already inside these categories.
static void log_export_counts(const PdbExportResult& exported)
{
	char functions[32];
	char code[32];
	char data[32];
	char total[32];
	comma_count(exported.functions, functions);
	comma_count(exported.code, code);
	comma_count(exported.data, data);
	comma_count(exported.exported, total);
	const size_t accounted = exported.functions + exported.code + exported.data;
	if (accounted == exported.exported)
	{
		msg(" %s functions, %s code labels, %s data symbols; total %s names.\n", functions, code, data, total);
		return;
	}
	char other[32];
	const size_t remainder = accounted > exported.exported ? accounted - exported.exported : exported.exported - accounted;
	comma_count(remainder, other);
	msg(" %s functions, %s code labels, %s data symbols, %s other; total %s names.\n", functions, code, data, other, total);
}

// Print symbols the writer counted but did not export.
static void log_omissions(const PdbExportResult& exported)
{
	if (exported.omittedHeader != 0)
	{
		char count[32];
		comma_count(exported.omittedHeader, count);
		msg(" Omitted %s symbols in the PE header.\n", count);
	}
	if (exported.omittedSection != 0)
	{
		char count[32];
		comma_count(exported.omittedSection, count);
		msg(" Omitted %s symbols outside a section.\n", count);
	}
	if (exported.omittedLong != 0)
	{
		char count[32];
		comma_count(exported.omittedLong, count);
		msg(" Omitted %s symbols whose names exceed the PDB limit.\n", count);
	}
}

// Print the finished PDB. path and the size refer to that same file.
static void log_export_success(const PdbExportResult& exported, const std::string& path)
{
	msg("\nExported:\n");
	log_export_counts(exported);
	msg(" Path: \"%s\"\n", path.c_str());
	char size[32];
	format_mib(exported.pdbBytes, size, sizeof(size));
	msg(" Size: %s\n", size);
	log_omissions(exported);
}

// Append a "key=value" line to a batch report.
static void report_line(std::string& text, const char* key, const std::string& value)
{
	text += key;
	text += "=";
	text += value;
	text += "\n";
}

// ============================================================================

// Plugin run
bool idaapi run(size_t arg)
{
	qstring version;
	msg("\n>> ida2pdb: v%s, built %s\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);
	WaitBox::processIdaEvents();
	// GUI vs headless tracking
	const bool qtInterface = is_idaq();
	const bool dialogsSuppressed = batch;
	const bool interactive = qtInterface && !dialogsSuppressed;

	try
	{
		if (!auto_is_ok())
		{
			if (interactive)
				warning("Auto-analysis must finish first before you run this plug-in!");
			log_failure("Export", "Auto-analysis must finish first.", std::string());
			if (!interactive)
			{
				IdentityReport report;
				report.summary = "Auto-analysis must finish first.";
				report.text = "ok=no\nsummary=" + report.summary + "\n";
				write_identity_report(arg, report);
			}			
			goto exit;
		}

		// Do main dialog
		WORD optionFlags = 0;
		if (optPushPdb) optionFlags |= OPT_PUSH_PDB;
		if (optIncludeGenerated) optionFlags |= OPT_INCLUDE_GENERATED;

		if (interactive)
		{			
			int result = ask_form(dialogForm, version.c_str(), doHyperlink, &optionFlags);
			if (!result)
			{
				msg("* Plugin canceled  *\n");
				goto exit;
			}
			optPushPdb = ((optionFlags & OPT_PUSH_PDB) > 0);
			optIncludeGenerated = ((optionFlags & OPT_INCLUDE_GENERATED) > 0);
		}

		TIMESTAMP startTime = GetTimeStamp();
		const bool includeGenerated = interactive ? (optIncludeGenerated != FALSE) : ((arg & BATCH_INCLUDE_GENERATED) != 0);
		const bool diagnostic = (arg & BATCH_DIAGNOSTIC) != 0;
		ProgressTracker hookState;
		hookState.interactive = interactive;
		hookState.cancelBeforePublish = !interactive && (arg & BATCH_CANCEL_BEFORE_PUBLISH) != 0;
		
		BOOL aborted = FALSE;
		// Get PDB info from the IDB if it exists
		const IdentityReport report = parse_pe_info(interactive);
		if (!report.ok)
		{
			log_failure("Export", report.summary, std::string());
			aborted = TRUE;
		}
		if (!report.ok && interactive)
			warning("%s", report.summary.c_str());
		if (!interactive)
			write_identity_report(arg, report);
		if (report.hasImage)
		{
			const bool publishSelected = interactive ? (optPushPdb != FALSE) : ((arg & BATCH_PUBLISH) != 0);
			std::string tempWhy;
			std::string outputPath = publishSelected ? temporary_pdb_path(report.image.pdbBasename, tempWhy) : pdb_path_beside_database(report.image);
			bool replacingExisting = !publishSelected && file_exists(outputPath);
			if (publishSelected && outputPath.empty())
			{
				log_failure("Export", "The temporary PDB path could not be created. " + tempWhy, std::string());
				aborted = TRUE;
			}
			else 
			if (!publishSelected && interactive)
			{
				const char* chosen = outputPath.empty() ? nullptr : ask_file(true, outputPath.c_str(), "Save PDB file|*.pdb");
				if (chosen == nullptr || chosen[0] == '\0')
				{
					msg("* Plugin canceled  *\n");
					aborted = TRUE;
				}
				else
				{
					outputPath = chosen;
					replacingExisting = file_exists(outputPath);
				}
			}
			else
			if (!publishSelected)
			{
				const std::string sideFile = idb_side_file("ida2pdb-output.txt");
				std::string overridePath;
				if (!read_line_file(sideFile, overridePath))
				{
					log_failure("Export", "The output path file could not be read.", sideFile);
					aborted = TRUE;
				}
				if (!overridePath.empty())
					outputPath = overridePath;
				replacingExisting = file_exists(outputPath);
			}

			std::string storeRoot;
			std::string storeSource;
			std::string storeDetail;
			std::string storeNotes;
			std::string explicitPath;
			if (!interactive && !aborted && publishSelected && !read_line_file(idb_side_file("ida2pdb-store.txt"), explicitPath))
			{
				log_failure("Export", "The symbol store path file could not be read.", idb_side_file("ida2pdb-store.txt"));
				aborted = TRUE;
			}
			if (!aborted && publishSelected)
			{
				const StoreDiscovery discovered = discover_publication_store(explicitPath, store_env_lookup_process, nullptr);
				storeRoot = discovered.path;
				storeSource = discovered.source;
				storeDetail = discovered.detail;
				storeNotes = discovered.notes;
			}

			if (!aborted)
			{
				log_section_iteration(report.image);
				log_codeview(report.image);
				if (publishSelected)
					log_symbol_store(storeSource, storeRoot);

				// Start wait box now we're past possible dialog open points
				if (interactive)
				{
					WaitBox::show("IDA to PDB", "Working..", waitboxStyle);
					WaitBox::updateAndCancelCheck(-1);
				}

				// Gather labels that have an address
				WaitBox::processIdaEvents();
				const auto collectStarted = std::chrono::steady_clock::now();
				const NamePreview preview = collect_names(report.image, report.currentImageBase, includeGenerated, diagnostic, export_hook, &hookState);
				const double collectMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - collectStarted).count();
				if (preview.canceled)
				{
					msg("* Plugin canceled  *\n");
					aborted = TRUE;
				}
				else if (!preview.ok)
				{
					log_failure("Export", preview.summary, "");
					aborted = TRUE;
					if (interactive)
					{
						WaitBox::hide();
						warning("%s", preview.summary.c_str());
					}
				}
				else if (diagnostic)
					write_named_report(arg, preview.text);

				if (!aborted)
				{
					// Write the generated PDB file out
					const auto writeStarted = std::chrono::steady_clock::now();
					const PdbExportResult exported = export_public_pdb(report.image, preview.names, outputPath, export_hook, &hookState);
					const double writeMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - writeStarted).count();
					std::string exportText = exported.text;
					//char timing[128];
					//std::snprintf(timing, sizeof(timing), "timing collect_ms=%.1f write_ms=%.1f\n", collectMs, writeMs);
					//exportText += timing;
						(void)collectMs;
						(void)writeMs;
					std::string shownPath = exported.path.empty() ? outputPath : exported.path;
					bool publicationFailed = false;
					std::string publicationReason;
					std::string publicationPath;

					if (exported.canceled)
					{
						msg("* Plugin canceled  *\n");
						aborted = TRUE;
					}
					else if (!exported.ok)
					{
						log_failure("Export", exported.summary, shownPath);
						aborted = TRUE;
					}
					else if (publishSelected)
					{
						// The writer's path= names the temporary PDB. path= below is the final output.
						const std::string writerPath = "path=" + exported.path + "\n";
						const size_t writerAt = exportText.find(writerPath);
						if (writerAt != std::string::npos && (writerAt == 0 || exportText[writerAt - 1] == '\n'))
							exportText.erase(writerAt, writerPath.size());
						report_line(exportText, "store_root", storeRoot);
						report_line(exportText, "store_source", storeSource);
						if (storeRoot.empty())
						{
							const std::string missing =
								std::string("Summary: The symbol store path was not provided.\n")
								+ " Store source: " + storeSource + "\n"
								+ " Details: " + storeDetail + "\n"
								+ " Notes: " + storeNotes + "\n";
							exportText += missing;
							publicationFailed = true;
							publicationReason = "The symbol store path was not provided.";
							if (interactive)
							{
								WaitBox::hide();
								warning("The symbol store path was not provided. The temporary PDB was kept.");
							}
						}
						else
						{
							if (interactive)
							{
								WaitBox::setLabelText("Publishing..");
								WaitBox::updateAndCancelCheck(-1);
							}

							const auto publishStarted = std::chrono::steady_clock::now();
							const StorePublishResult published = publish_local_store(
								report.image.guid,
								report.image.age,
								report.image.pdbBasename,
								outputPath,
								storeRoot);
							const double publishMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - publishStarted).count();
							//char publishTiming[64];
							//std::snprintf(publishTiming, sizeof(publishTiming), "timing publication_ms=%.1f\n", publishMs);
							(void)publishMs;
							report_line(exportText, "store_path", published.path);
							report_line(exportText, "publication_summary", published.summary);
							if (published.ok)
							{
								if (published.replaced)
									replacingExisting = true;
								if (!published.path.empty())
									shownPath = published.path;
								const bool deleted = DeleteFileW(wide_path(outputPath).c_str()) != FALSE;
								if (!deleted)
									msg("** The temporary PDB could not be deleted **\n");
								report_line(exportText, "publication", published.replaced ? "replaced" : "published");
								report_line(exportText, "path", shownPath);
								report_line(exportText, "temporary_path", outputPath);
								report_line(exportText, "temporary_deleted", deleted ? "yes" : "no");
							}
							else
							{
								publicationFailed = true;
								publicationReason = published.summary;
								publicationPath = published.path;
								if (interactive)
								{
									WaitBox::hide();
									warning("%s The temporary PDB was kept.", published.summary.c_str());
								}
							}
						}
						if (publicationFailed)
						{
							report_line(exportText, "publication", "failed");
							report_line(exportText, "publication_failure", publicationReason);
							report_line(exportText, "path", shownPath);
							report_line(exportText, "temporary_path", outputPath);
							report_line(exportText, "temporary_deleted", "no");
						}
						if (replacingExisting)
							msg(" Replaced existing PDB.\n");
						log_export_success(exported, shownPath);
						if (publicationFailed)
						{
							log_failure("Symbol store publication", publicationReason, publicationPath);
							aborted = TRUE;
						}
					}
					else
					{
						const char* skipped = "Publication not-selected\n";
						exportText += skipped;
						if (replacingExisting)
							msg(" Replaced existing PDB.\n");
						log_export_success(exported, shownPath);
					}

					if (!interactive)
						write_export_report(arg, exportText);
					if (interactive && !exported.ok && !exported.canceled)
					{
						WaitBox::hide();
						warning("%s", exported.summary.c_str());
					}
				}
			}
		}

		if (!aborted)
		{
			msg("ida2pdb: Done. Took %s.\n\n", TimeString(GetTimeStamp() - startTime));
			WaitBox::processIdaEvents();
		}
	}
	CATCH();

exit:;
	if (interactive)
		WaitBox::hide();
	return true;
}


// ============================================================================
// Plug-in description block
const static char IDAP_name[] = "IDA to PDB export utility.";
__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
    PLUGIN_UNL,				// Plug-in flags
    init,					// Initialization function
    term,					// Clean-up function
    run,					// Main plug-in body
    IDAP_name,	            // Long comment
    NULL,                   // Multiline help
    IDAP_name,	            // Short name shown in Edit->Plugins menu
	NULL                    // Default hot key
};
