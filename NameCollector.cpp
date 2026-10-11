
// Collect name/labels that have an address from the loaded IDB for export
#include "StdAfx.h"
#include "NameCollector.h"

#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <WaitBoxEx.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

// Name candidates
struct Candidate
{
	ea_t ea = BADADDR;
	std::string name;
	std::string scope;
	bool imported = false;
	bool local = false;
};

// Return the preview word for a name kind.
const char* kind_name(NameKind kind)
{
	if (kind == NameKind::Function)
		return "function";
	if (kind == NameKind::Code)
		return "code";
	return "data";
}

// Return yes or no for a preview flag.
const char* yes_no(bool value)
{
	return value ? "yes" : "no";
}

// Cancellation hook for a collection pass.
struct NameControl
{
	NameHook hook = nullptr;
	void* hookContext = nullptr;
	bool canceled = false;
	size_t nlistSteps = 0;
	size_t headSteps = 0;
	size_t localSteps = 0;
	size_t aliasSteps = 0;
	size_t generatedSkipped = 0;
	std::vector<Candidate> generatedLines;
	std::string failure;

	// Ask the hook whether this collection phase should stop.
	bool stop(const char* phase)
	{
		if (canceled)
			return true;
		if (hook != nullptr && hook(hookContext, phase))
			canceled = true;
		return canceled;
	}
};

// Step counts that land about one wait-box sample every 110ms on a large
// database. The modulo skips the flag read. isUpdateTime() is one memory
// read, and the Qt update runs only after the internal 100ms timer.
// GameAssembly.dll.i64, headless, 2026-10-10 (all names):
//   nlist 211854 steps / 1407ms, named bytes 1483711 / 4910ms,
//   aliases 1483711 / 320ms, filter 1483711 / 238ms, duplicates 1456180 / 1452ms.
static const size_t kNlistStride = 17000;
static const size_t kHeadsStride = 33000;
static const size_t kAliasStride = 500000;
static const size_t kFilterStride = 360000;
static const size_t kDuplicateStride = 110000;

// One segment can be very large. Past this many steps the
// walk stops and the export fails instead of returning a partial name list.
static const int kWalkLimit = 500000000;

// Sample the wait box when this step is on the stride.
bool pump(NameControl& control, const char* phase, size_t step, size_t stride)
{
	if (stride == 0 || (step % stride) != 0)
		return false;
	if (!WaitBox::isUpdateTime())
		return false;
	return control.stop(phase);
}

// Sample the wait box once, outside a counted loop.
bool pump_now(NameControl& control, const char* phase)
{
	if (!WaitBox::isUpdateTime())
		return false;
	return control.stop(phase);
}

// Candidates gathered so far, indexed by address.
struct NameSet
{
	std::vector<Candidate> items;
	std::unordered_map<uint64_t, std::vector<size_t>> byAddress;
};

// Import callback context for the current name set.
struct ImportPass
{
	NameSet* names = nullptr;
};

// Record a candidate, merging a repeated name at the same address.
void remember(NameSet& names, Candidate item)
{
	if (item.name.empty() || item.ea == BADADDR)
		return;
	std::vector<size_t>& bucket = names.byAddress[static_cast<uint64_t>(item.ea)];
	for (size_t index : bucket)
	{
		Candidate& existing = names.items[index];
		if (existing.name == item.name && existing.scope == item.scope && existing.local == item.local)
		{
			existing.imported = existing.imported || item.imported;
			return;
		}
	}
	bucket.push_back(names.items.size());
	names.items.push_back(std::move(item));
}

// Collect names from IDA's global name list.
void append_global_names(NameSet& names, NameControl& control)
{
	if (control.canceled)
		return;
	const size_t count = get_nlist_size();
	control.nlistSteps = count;
	for (size_t index = 0; index < count; ++index)
	{
		if (pump(control, "names", index, kNlistStride))
			return;
		const char* raw = get_nlist_name(index);
		if (raw == nullptr || raw[0] == '\0')
			continue;
		Candidate item;
		item.ea = get_nlist_ea(index);
		item.name = raw;
		remember(names, std::move(item));
	}
}

// next_that() test for any byte carrying a name, including unexplored bytes.
bool idaapi named_byte(flags64_t flags, void*)
{
	return has_any_name(flags);
}

// Return the first named address in [start, end).
ea_t first_named(ea_t start, ea_t end)
{
	if (start >= end)
		return BADADDR;
	if (has_any_name(get_flags(start)))
		return start;
	return next_that(start, end, named_byte);
}

// A named byte with no global name carries a function-local name.
void remember_local(NameSet& names, NameControl& control, ea_t ea)
{
	++control.localSteps;
	qstring localName;
	if (get_ea_name(&localName, ea, GN_LOCAL) <= 0 || localName.empty())
		return;
	Candidate item;
	item.ea = ea;
	item.name = localName.c_str();
	item.local = true;
	const ea_t functionEa = get_func_start(ea);
	if (functionEa != BADADDR)
	{
		qstring functionName;
		get_ea_name(&functionName, functionEa, 0);
		item.scope = functionName.c_str();
	}
	remember(names, std::move(item));
}

// Visit every named byte in every segment, including unexplored bytes and all
// function chunks. Dummy address names such as sub_, loc_ and unk_ carry FF_LABL
// but are absent from the global name list. Local names are absent from it too,
// and have FF_NAME with no global name.
void append_named_heads(NameSet& names, NameControl& control, bool includeGenerated, bool diagnostic)
{
	if (control.canceled)
		return;
	for (ea_t segmentEa = get_first_segment_ea(); segmentEa != BADADDR; segmentEa = get_next_segment_ea(segmentEa))
	{
		segment_info_t info;
		if (!get_segment_info(&info, segmentEa, 0))
			continue;
		ea_t ea = first_named(info.start_ea, info.end_ea);
		int step = 0;
		for (; ea < info.end_ea && ea != BADADDR && step < kWalkLimit; ++step)
		{
			if (pump(control, "heads", control.headSteps, kHeadsStride))
				return;
			++control.headSteps;
			const bool generated = has_dummy_name(get_flags(ea));
			if (!generated || includeGenerated || diagnostic)
			{
				qstring name;
				if (get_ea_name(&name, ea, 0) > 0 && !name.empty())
				{
					Candidate item;
					item.ea = ea;
					item.name = name.c_str();
					if (generated && !includeGenerated)
						control.generatedLines.push_back(std::move(item));
					else
						remember(names, std::move(item));
				}
				else if (!generated)
				{
					remember_local(names, control, ea);
				}
			}
			if (generated && !includeGenerated)
				++control.generatedSkipped;
			ea = next_that(ea, info.end_ea, named_byte);
		}
		if (step >= kWalkLimit && ea < info.end_ea && ea != BADADDR)
		{
			qstring segmentName;
			get_segment_name(&segmentName, segmentEa, 0);
			char message[192];
			if (!segmentName.empty())
				std::snprintf(message, sizeof(message), "The segment \"%s\" exceeded 500,000,000 heads.", segmentName.c_str());
			else
				std::snprintf(message, sizeof(message), "The segment at 0x%llx exceeded 500,000,000 heads.", static_cast<unsigned long long>(segmentEa));
			control.failure = message;
			return;
		}
	}
}

// Mark names IDA already has at an import slot. The bare import name is not
// added; it would collide with same-named functions in the debugger.
int idaapi remember_import(ea_t ea, const char*, uval_t, void* param)
{
	auto* pass = static_cast<ImportPass*>(param);
	const auto found = pass->names->byAddress.find(static_cast<uint64_t>(ea));
	if (found == pass->names->byAddress.end())
		return 1;
	for (size_t index : found->second)
	{
		if (!pass->names->items[index].local)
			pass->names->items[index].imported = true;
	}
	return 1;
}

// Classify import slots.
void append_imports(NameSet& names, NameControl& control)
{
	if (control.canceled || control.stop("imports"))
		return;
	ImportPass pass;
	pass.names = &names;
	const uint modules = get_import_module_qty();
	for (uint index = 0; index < modules; ++index)
		enum_import_names(int(index), remember_import, &pass);
}

// Collect other names stored at the same address.
void append_alternative_names(NameSet& names, NameControl& control)
{
	if (control.canceled)
		return;
	std::vector<ea_t> addresses;
	addresses.reserve(names.items.size());
	for (const Candidate& item : names.items)
		addresses.push_back(item.ea);
	std::sort(addresses.begin(), addresses.end());
	addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
	control.aliasSteps = addresses.size();
	const std::string marker = "Alternative name is ";
	for (size_t index = 0; index < addresses.size(); ++index)
	{
		if (pump(control, "aliases", index, kAliasStride))
			return;
		const ea_t ea = addresses[index];
		qstring comment;
		if (get_cmt(&comment, ea, false) <= 0)
			continue;
		const std::string text = comment.c_str();
		size_t at = 0;
		while ((at = text.find(marker, at)) != std::string::npos)
		{
			const size_t begin = at + marker.size();
			const size_t end = text.find_first_of("\r\n", begin);
			std::string alias = text.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
			while (!alias.empty() && (alias.back() == ' ' || alias.back() == '\t'))
				alias.pop_back();
			if (alias.size() >= 2 && alias.front() == '\'' && alias.back() == '\'')
				alias = alias.substr(1, alias.size() - 2);
			Candidate item;
			item.ea = ea;
			item.name = std::move(alias);
			remember(names, std::move(item));
			if (end == std::string::npos)
				break;
			at = end;
		}
	}
}

// Return the preview word for an address that could not be mapped.
const char* map_reason(MapStatus status)
{
	if (status == MapStatus::BelowImage)
		return "below_image";
	if (status == MapStatus::OutsideImage)
		return "outside_image";
	return "unmapped";
}

// Append a count to the preview.
void count_line(std::string& text, const char* key, size_t value)
{
	char line[64];
	std::snprintf(line, sizeof(line), "%s=%u\n", key, static_cast<unsigned>(value));
	text += line;
}

// Format a skipped candidate for the preview.
std::string skip_line(const char* reason, const Candidate& candidate)
{
	char eaText[32];
	std::snprintf(eaText, sizeof(eaText), "0x%llx", static_cast<unsigned long long>(candidate.ea));
	return std::string("skipped reason=") + reason + " ea=" + eaText + " name=" + candidate.name;
}

// Return elapsed milliseconds since a phase started.
double elapsed_ms(std::chrono::steady_clock::time_point started)
{
	return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
}

} // namespace

// Collect public-symbol names from the current database.
NamePreview collect_names(const PeImage& image, uint64_t currentImageBase, bool includeGenerated, bool diagnostic, NameHook hook, void* hookContext)
{
	NamePreview preview;
	NameControl control;
	control.hook = hook;
	control.hookContext = hookContext;
	NameSet names;
	const auto started = std::chrono::steady_clock::now();
	const auto give_up = [&]() -> NamePreview {
		preview.summary = control.failure;
		preview.text = "ok=no\nsummary=" + control.failure + "\n";
		return preview;
	};
	append_global_names(names, control);
	const double nlistMs = elapsed_ms(started);
	const auto headsStarted = std::chrono::steady_clock::now();
	append_named_heads(names, control, includeGenerated, diagnostic);
	if (!control.failure.empty())
		return give_up();
	const double headsMs = elapsed_ms(headsStarted);
	const auto importsStarted = std::chrono::steady_clock::now();
	append_imports(names, control);
	const double importsMs = elapsed_ms(importsStarted);
	const auto aliasesStarted = std::chrono::steady_clock::now();
	append_alternative_names(names, control);
	const double aliasesMs = elapsed_ms(aliasesStarted);
	if (control.canceled)
	{
		preview.canceled = true;
		preview.summary = "Canceled.";
		preview.text = "ok=no\ncanceled=yes\nsummary=Canceled.\n";
		return preview;
	}
	const auto filterStarted = std::chrono::steady_clock::now();
	const std::vector<Candidate>& candidates = names.items;

	std::map<std::string, size_t> skipCounts;
	std::vector<std::string> skipLines;
	if (control.generatedSkipped != 0)
		skipCounts["generated_name"] = control.generatedSkipped;
	for (const Candidate& candidate : control.generatedLines)
		skipLines.push_back(skip_line("generated_name", candidate));

	std::vector<range_t> syntheticSegments;
	for (ea_t segmentEa = get_first_segment_ea(); segmentEa != BADADDR; segmentEa = get_next_segment_ea(segmentEa))
	{
		segment_info_t info;
		qstring segmentName;
		if (get_segment_info(&info, segmentEa, 0) && get_segment_name(&segmentName, segmentEa, 0) > 0 && segmentName == ".fake_strings")
			syntheticSegments.push_back(range_t(info.start_ea, info.end_ea));
	}

	for (size_t index = 0; index < candidates.size(); ++index)
	{
		if (pump(control, "filter", index, kFilterStride))
		{
			preview.canceled = true;
			preview.summary = "Canceled.";
			preview.text = "ok=no\ncanceled=yes\nsummary=Canceled.\n";
			return preview;
		}
		const Candidate& candidate = candidates[index];
		bool synthetic = false;
		for (const range_t& range : syntheticSegments)
			synthetic = synthetic || range.contains(candidate.ea);
		if (synthetic)
		{
			++skipCounts["synthetic_segment"];
			if (diagnostic)
				skipLines.push_back(skip_line("synthetic_segment", candidate));
			continue;
		}

		MappedAddress mapped;
		const MapStatus status = map_ea(candidate.ea, currentImageBase, image, mapped);
		if (status != MapStatus::Ok)
		{
			const char* reason = map_reason(status);
			++skipCounts[reason];
			if (diagnostic)
				skipLines.push_back(skip_line(reason, candidate));
			continue;
		}

		const flags64_t flags = get_flags(candidate.ea);
		const bool generated = !candidate.local && has_dummy_name(flags);
		if (generated && !includeGenerated)
		{
			++skipCounts["generated_name"];
			if (diagnostic)
				skipLines.push_back(skip_line("generated_name", candidate));
			continue;
		}

		CollectedName collected;
		collected.name = candidate.name;
		collected.scope = candidate.scope;
		collected.rva = mapped.rva;
		collected.sectionIndex = mapped.sectionIndex;
		collected.sectionOffset = mapped.sectionOffset;
		collected.imported = candidate.imported;
		collected.generated = generated;
		collected.local = candidate.local;
		if (candidate.local)
			collected.kind = is_code(flags) ? NameKind::Code : NameKind::Data;
		else if (is_func(flags) || get_func_start(candidate.ea) == candidate.ea)
			collected.kind = NameKind::Function;
		else if (is_code(flags))
			collected.kind = NameKind::Code;
		else
			collected.kind = NameKind::Data;
		preview.names.push_back(std::move(collected));
	}
	const double filterMs = elapsed_ms(filterStarted);
	const auto duplicateStarted = std::chrono::steady_clock::now();
	if (pump_now(control, "sort"))
	{
		preview.canceled = true;
		preview.summary = "Canceled.";
		preview.text = "ok=no\ncanceled=yes\nsummary=Canceled.\n";
		return preview;
	}

	std::sort(preview.names.begin(), preview.names.end(), [](const CollectedName& left, const CollectedName& right) {
		if (left.rva != right.rva)
			return left.rva < right.rva;
		if (left.local != right.local)
			return left.local < right.local;
		if (left.name != right.name)
			return left.name < right.name;
		return left.scope < right.scope;
	});

	std::map<std::string, std::vector<size_t>> byName;
	std::map<uint64_t, std::vector<size_t>> byRva;
	for (size_t index = 0; index < preview.names.size(); ++index)
	{
		if (pump(control, "duplicates", index, kDuplicateStride))
		{
			preview.canceled = true;
			preview.summary = "Canceled.";
			preview.text = "ok=no\ncanceled=yes\nsummary=Canceled.\n";
			return preview;
		}
		byName[preview.names[index].name].push_back(index);
		byRva[preview.names[index].rva].push_back(index);
	}
	for (const auto& entry : byName)
	{
		if (entry.second.size() < 2)
			continue;
		for (size_t index : entry.second)
			preview.names[index].duplicate = true;
	}
	for (const auto& entry : byRva)
	{
		if (entry.second.size() < 2)
			continue;
		for (size_t index : entry.second)
			preview.names[index].alias = true;
	}
	const double duplicateMs = elapsed_ms(duplicateStarted);
	const auto reportStarted = std::chrono::steady_clock::now();

	size_t functions = 0;
	size_t codeLabels = 0;
	size_t data = 0;
	size_t imports = 0;
	size_t locals = 0;
	size_t duplicates = 0;
	size_t aliases = 0;
	for (const CollectedName& name : preview.names)
	{
		if (name.kind == NameKind::Function)
			++functions;
		else if (name.kind == NameKind::Code)
			++codeLabels;
		else
			++data;
		imports += name.imported ? 1u : 0u;
		locals += name.local ? 1u : 0u;
		duplicates += name.duplicate ? 1u : 0u;
		aliases += name.alias ? 1u : 0u;
	}

	std::string text;
	//text += "ok=yes\n";
	char summary[80];
	std::snprintf(summary, sizeof(summary), "summary=Collected %u names\n", static_cast<unsigned>(preview.names.size()));
	text += summary;
	text += std::string("include_generated=") + yes_no(includeGenerated) + "\n";
	count_line(text, "collected", preview.names.size());
	size_t skipped = 0;
	for (const auto& entry : skipCounts)
		skipped += entry.second;
	count_line(text, "skipped", skipped);
	count_line(text, "functions", functions);
	count_line(text, "code_labels", codeLabels);
	count_line(text, "data", data);
	count_line(text, "imports", imports);
	count_line(text, "locals", locals);
	count_line(text, "duplicates", duplicates);
	count_line(text, "aliases", aliases);
	for (const auto& entry : skipCounts)
		count_line(text, ("skip_" + entry.first).c_str(), entry.second);
	if (diagnostic)
	{
	for (const CollectedName& name : preview.names)
	{
		char prefix[160];
		std::snprintf(prefix, sizeof(prefix), "symbol rva=0x%llx kind=%s section=%u offset=0x%x imported=%s generated=%s local=%s duplicate=%s alias=%s scope=", static_cast<unsigned long long>(name.rva), kind_name(name.kind), name.sectionIndex, name.sectionOffset, yes_no(name.imported), yes_no(name.generated), yes_no(name.local), yes_no(name.duplicate), yes_no(name.alias));
		text += prefix;
		text += name.scope;
		text += " name=";
		text += name.name;
		text += "\n";
	}
	for (const std::string& line : skipLines)
		text += line + "\n";
	}
	const double reportMs = elapsed_ms(reportStarted);
	char timing[640];
	std::snprintf(timing, sizeof(timing), "timing candidates=%u nlist_ms=%.1f heads_ms=%.1f imports_ms=%.1f alias_ms=%.1f filter_ms=%.1f duplicate_ms=%.1f report_ms=%.1f nlist_steps=%u head_steps=%u local_steps=%u alias_steps=%u kept=%u\n", static_cast<unsigned>(candidates.size()), nlistMs, headsMs, importsMs, aliasesMs, filterMs, duplicateMs, reportMs, static_cast<unsigned>(control.nlistSteps), static_cast<unsigned>(control.headSteps), static_cast<unsigned>(control.localSteps), static_cast<unsigned>(control.aliasSteps), static_cast<unsigned>(preview.names.size()));
	text += timing;

	preview.ok = true;
	preview.summary = std::string("Collected ") + std::to_string(preview.names.size()) + " names.";
	preview.text = std::move(text);
	return preview;
}
