#include "fingerprint.hpp"
#include "fingerprint_rules.hpp"
#include "memory.hpp"
#include "pe_meta.hpp"
#include "resolve.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

void ToLowerInPlace(std::wstring& s) {
    for (auto& c : s) {
        c = static_cast<wchar_t>(towlower(c));
    }
}

void ToLowerInPlaceA(std::string& s) {
    for (auto& c : s) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }
}

std::wstring BasenameLower(const wchar_t* path) {
    if (!path || !path[0]) {
        return {};
    }
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') {
            base = p + 1;
        }
    }
    std::wstring out(base);
    ToLowerInPlace(out);
    return out;
}

std::string NarrowLower(const char* s) {
    if (!s) {
        return {};
    }
    std::string out(s);
    ToLowerInPlaceA(out);
    return out;
}

/* Simple glob: '*' matches any sequence. Case already normalized. */
bool GlobMatchW(const wchar_t* pat, const wchar_t* text) {
    if (!pat || !text) {
        return false;
    }
    const wchar_t* star = nullptr;
    const wchar_t* star_text = nullptr;
    while (*text) {
        if (*pat == L'*') {
            star = pat++;
            star_text = text;
            continue;
        }
        if (*pat && (*pat == *text || *pat == L'?')) {
            ++pat;
            ++text;
            continue;
        }
        if (star) {
            pat = star + 1;
            text = ++star_text;
            continue;
        }
        return false;
    }
    while (*pat == L'*') {
        ++pat;
    }
    return *pat == 0;
}

bool GlobMatchA(const char* pat, const char* text) {
    if (!pat || !text) {
        return false;
    }
    const char* star = nullptr;
    const char* star_text = nullptr;
    while (*text) {
        if (*pat == '*') {
            star = pat++;
            star_text = text;
            continue;
        }
        if (*pat && (*pat == *text || *pat == '?')) {
            ++pat;
            ++text;
            continue;
        }
        if (star) {
            pat = star + 1;
            text = ++star_text;
            continue;
        }
        return false;
    }
    while (*pat == '*') {
        ++pat;
    }
    return *pat == 0;
}

bool AnyModuleGlob(const wchar_t* const* globs, const std::vector<std::wstring>& mods,
                   std::wstring* matched) {
    if (!globs) {
        return false;
    }
    for (size_t i = 0; globs[i]; ++i) {
        for (const auto& m : mods) {
            if (GlobMatchW(globs[i], m.c_str())) {
                if (matched) {
                    *matched = m;
                }
                return true;
            }
        }
    }
    return false;
}

bool AnyImportMatch(const char* const* imp_mods, const char* const* imp_names,
                    const std::vector<FpImportSignal>& imports, std::string* matched_mod,
                    std::string* matched_name) {
    if (!imp_names && !imp_mods) {
        return false;
    }
    for (const auto& im : imports) {
        bool mod_ok = true;
        if (imp_mods) {
            mod_ok = false;
            for (size_t i = 0; imp_mods[i]; ++i) {
                if (GlobMatchA(imp_mods[i], im.module.c_str())) {
                    mod_ok = true;
                    break;
                }
            }
        }
        if (!mod_ok) {
            continue;
        }
        if (!imp_names) {
            if (matched_mod) {
                *matched_mod = im.module;
            }
            if (matched_name) {
                matched_name->clear();
            }
            return true;
        }
        for (size_t i = 0; imp_names[i]; ++i) {
            /* API names: exact case-insensitive (already lowercased signal vs mixed pattern). */
            std::string want = NarrowLower(imp_names[i]);
            if (im.name == want) {
                if (matched_mod) {
                    *matched_mod = im.module;
                }
                if (matched_name) {
                    *matched_name = im.name;
                }
                return true;
            }
        }
    }
    return false;
}

void AppendEvidence(char* dst, size_t cap, const char* piece) {
    if (!dst || !cap || !piece || !piece[0]) {
        return;
    }
    const size_t cur = strnlen(dst, cap);
    if (cur + 1 >= cap) {
        return;
    }
    if (cur > 0) {
        if (cur + 2 >= cap) {
            return;
        }
        dst[cur] = ';';
        dst[cur + 1] = ' ';
        dst[cur + 2] = 0;
    }
    const size_t now = strnlen(dst, cap);
    const size_t room = cap - now - 1;
    strncpy_s(dst + now, room + 1, piece, _TRUNCATE);
}

void MergeTag(std::vector<HdlFingerprintTag>* tags, uint32_t category, const char* id,
              uint32_t confidence, uint32_t flags, const char* evidence_piece) {
    if (!tags || !id) {
        return;
    }
    if (confidence > 100) {
        confidence = 100;
    }
    for (auto& t : *tags) {
        if (t.category == category && strcmp(t.id, id) == 0) {
            if (confidence > t.confidence) {
                t.confidence = confidence;
            }
            t.flags |= flags;
            AppendEvidence(t.evidence, sizeof(t.evidence), evidence_piece);
            return;
        }
    }
    HdlFingerprintTag t{};
    t.category = category;
    t.confidence = confidence;
    t.flags = flags;
    strncpy_s(t.id, id, _TRUNCATE);
    if (evidence_piece) {
        strncpy_s(t.evidence, evidence_piece, _TRUNCATE);
    }
    tags->push_back(t);
}

bool HasTagId(const std::vector<HdlFingerprintTag>& tags, uint32_t category, const char* id) {
    for (const auto& t : tags) {
        if (t.category == category && strcmp(t.id, id) == 0) {
            return true;
        }
    }
    return false;
}

bool HasAnyId(const std::vector<HdlFingerprintTag>& tags, uint32_t category,
              const char* const* ids) {
    if (!ids) {
        return false;
    }
    for (size_t i = 0; ids[i]; ++i) {
        if (HasTagId(tags, category, ids[i])) {
            return true;
        }
    }
    return false;
}

bool HasCategory(const std::vector<HdlFingerprintTag>& tags, uint32_t category) {
    for (const auto& t : tags) {
        if (t.category == category) {
            return true;
        }
    }
    return false;
}

uint16_t ReadMainSubsystem() {
    uint64_t base = 0;
    if (ModuleBase(nullptr, &base) != HDL_OK || !base) {
        return 0;
    }
    IMAGE_DOS_HEADER dos{};
    size_t got = 0;
    if (ReadMemory(base, &dos, sizeof(dos), &got) != HDL_OK || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (ReadMemory(base + dos.e_lfanew, &nt, sizeof(nt), &got) != HDL_OK || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    return nt.OptionalHeader.Subsystem;
}

}  // namespace

void ClassifyFingerprint(const std::vector<std::wstring>& module_basenames,
                         const std::vector<FpImportSignal>& imports, uint16_t pe_subsystem,
                         uint32_t scan_flags, std::vector<HdlFingerprintTag>* out) {
    if (!out) {
        return;
    }
    out->clear();
    if (scan_flags == 0) {
        scan_flags = HDL_FP_SCAN_DEFAULT;
    }

    std::vector<std::wstring> mods = module_basenames;
    for (auto& m : mods) {
        ToLowerInPlace(m);
    }

    std::vector<FpImportSignal> imps = imports;
    for (auto& im : imps) {
        ToLowerInPlaceA(im.module);
        ToLowerInPlaceA(im.name);
        /* Strip path from import module if present. */
        const auto slash = im.module.find_last_of("\\/");
        if (slash != std::string::npos) {
            im.module = im.module.substr(slash + 1);
        }
    }

    if (scan_flags & (HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS)) {
        for (size_t ri = 0; ri < fp::kRuleCount; ++ri) {
            const fp::FpRule& rule = fp::kRules[ri];
            std::wstring matched_mod;
            std::string matched_imp_mod;
            std::string matched_imp_name;

            const bool want_mod = (scan_flags & HDL_FP_SCAN_MODULES) != 0 && rule.module_globs;
            const bool want_imp =
                (scan_flags & HDL_FP_SCAN_IMPORTS) != 0 && (rule.import_modules || rule.import_names);

            bool mod_hit = false;
            bool imp_hit = false;
            if (want_mod) {
                mod_hit = AnyModuleGlob(rule.module_globs, mods, &matched_mod);
            }
            if (want_imp) {
                imp_hit = AnyImportMatch(rule.import_modules, rule.import_names, imps,
                                         &matched_imp_mod, &matched_imp_name);
            }

            if (!mod_hit && !imp_hit) {
                continue;
            }
            /* Rules with only module_globs: need module. Rules with prefer_import may fire on
               module alone at reduced confidence. */
            if (rule.module_globs && !rule.import_names && !rule.import_modules && !mod_hit) {
                continue;
            }
            if (!rule.module_globs && (rule.import_names || rule.import_modules) && !imp_hit) {
                continue;
            }

            uint32_t conf = rule.base_confidence;
            uint32_t flags = 0;
            char ev[192] = {};

            if (mod_hit) {
                flags |= HDL_FP_FROM_MODULE;
                char piece[96];
                snprintf(piece, sizeof(piece), "module:%ls", matched_mod.c_str());
                AppendEvidence(ev, sizeof(ev), piece);
            }
            if (imp_hit) {
                flags |= HDL_FP_FROM_IMPORT;
                char piece[128];
                if (!matched_imp_name.empty()) {
                    snprintf(piece, sizeof(piece), "import:%s!%s", matched_imp_mod.c_str(),
                             matched_imp_name.c_str());
                } else {
                    snprintf(piece, sizeof(piece), "import:%s", matched_imp_mod.c_str());
                }
                AppendEvidence(ev, sizeof(ev), piece);
                if (mod_hit) {
                    conf = (std::min)(100u, conf + 15u);
                }
            } else if (rule.prefer_import && mod_hit) {
                /* Ambient module without confirming IAT API. */
                if (conf > 20) {
                    conf -= 20;
                } else {
                    conf = 10;
                }
            }

            MergeTag(out, rule.category, rule.id, conf, flags, ev);
        }
    }

    if (scan_flags & HDL_FP_SCAN_PE) {
        if (pe_subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            MergeTag(out, HDL_FP_CAT_APP, "subsystem_gui", 90, HDL_FP_FROM_PE, "pe:subsystem=gui");
        } else if (pe_subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
            MergeTag(out, HDL_FP_CAT_APP, "subsystem_cui", 90, HDL_FP_FROM_PE, "pe:subsystem=cui");
        }
    }

    /* Suppress ambient win32/gdi when a strong UI framework is present. */
    const bool strong_ui = HasAnyId(*out, HDL_FP_CAT_UI, fp::kStrongUiIds) ||
                           HasTagId(*out, HDL_FP_CAT_WEBHOST, "electron") ||
                           HasTagId(*out, HDL_FP_CAT_RUNTIME, "electron");
    if (strong_ui) {
        for (auto& t : *out) {
            if (t.category == HDL_FP_CAT_UI &&
                (strcmp(t.id, "win32") == 0 || strcmp(t.id, "gdi") == 0)) {
                if (t.confidence > 40) {
                    t.confidence = 40;
                }
            }
        }
    }

    const bool strong_gfx = HasAnyId(*out, HDL_FP_CAT_GRAPHICS, fp::kStrongGfxIds);
    if (strong_gfx) {
        for (auto& t : *out) {
            if (t.category == HDL_FP_CAT_UI && strcmp(t.id, "gdi") == 0) {
                if (t.confidence > 35) {
                    t.confidence = 35;
                }
            }
        }
    }

    /* native fallback: no language/runtime tag and only CRT/OS-ish modules. */
    if ((scan_flags & HDL_FP_SCAN_MODULES) && !HasCategory(*out, HDL_FP_CAT_LANGUAGE) &&
        !HasCategory(*out, HDL_FP_CAT_RUNTIME) && !HasCategory(*out, HDL_FP_CAT_ENGINE)) {
        MergeTag(out, HDL_FP_CAT_LANGUAGE, "native", 40, HDL_FP_FROM_MODULE, "fallback:no-runtime");
    }

    /* Mark primary per category (highest confidence; ties prefer FROM_IMPORT). */
    for (uint32_t cat = HDL_FP_CAT_LANGUAGE; cat <= HDL_FP_CAT_APP; ++cat) {
        int best = -1;
        for (size_t i = 0; i < out->size(); ++i) {
            if ((*out)[i].category != cat) {
                continue;
            }
            if (best < 0) {
                best = static_cast<int>(i);
                continue;
            }
            const auto& a = (*out)[static_cast<size_t>(best)];
            const auto& b = (*out)[i];
            if (b.confidence > a.confidence) {
                best = static_cast<int>(i);
            } else if (b.confidence == a.confidence) {
                const bool a_imp = (a.flags & HDL_FP_FROM_IMPORT) != 0;
                const bool b_imp = (b.flags & HDL_FP_FROM_IMPORT) != 0;
                if (b_imp && !a_imp) {
                    best = static_cast<int>(i);
                }
            }
        }
        if (best >= 0) {
            (*out)[static_cast<size_t>(best)].flags |= HDL_FP_PRIMARY;
        }
    }

    std::sort(out->begin(), out->end(), [](const HdlFingerprintTag& a, const HdlFingerprintTag& b) {
        if (a.category != b.category) {
            return a.category < b.category;
        }
        if (a.confidence != b.confidence) {
            return a.confidence > b.confidence;
        }
        return strcmp(a.id, b.id) < 0;
    });
}

HdlStatus EnumFingerprintTags(uint32_t scan_flags, HdlFingerprintTag* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (scan_flags == 0) {
        scan_flags = HDL_FP_SCAN_DEFAULT;
    }

    std::vector<std::wstring> mods;
    if (scan_flags & HDL_FP_SCAN_MODULES) {
        uint32_t count = 0;
        EnumModules(nullptr, &count);
        std::vector<HdlModuleInfo> modules(count);
        if (count) {
            const HdlStatus st = EnumModules(modules.data(), &count);
            if (st != HDL_OK && st != HDL_E_BUFFER_SMALL) {
                /* proceed with whatever we got */
            }
            modules.resize(count);
        }
        mods.reserve(modules.size());
        for (const auto& m : modules) {
            mods.push_back(BasenameLower(m.path));
        }
    }

    std::vector<FpImportSignal> imps;
    if (scan_flags & HDL_FP_SCAN_IMPORTS) {
        uint32_t count = 0;
        EnumImports(0, nullptr, &count);
        std::vector<HdlImportInfo> imports(count);
        if (count) {
            EnumImports(0, imports.data(), &count);
            imports.resize(count);
        }
        imps.reserve(imports.size());
        for (const auto& im : imports) {
            FpImportSignal s;
            s.module = NarrowLower(im.module);
            s.name = NarrowLower(im.name);
            imps.push_back(std::move(s));
        }
    }

    uint16_t subsystem = 0;
    if (scan_flags & HDL_FP_SCAN_PE) {
        subsystem = ReadMainSubsystem();
    }

    std::vector<HdlFingerprintTag> tags;
    ClassifyFingerprint(mods, imps, subsystem, scan_flags, &tags);

    const uint32_t need = static_cast<uint32_t>(tags.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, tags.data(), need * sizeof(HdlFingerprintTag));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus ClassifyFingerprintApi(const wchar_t* const* module_basenames, uint32_t module_count,
                                 const HdlFingerprintImport* imports, uint32_t import_count,
                                 uint16_t pe_subsystem, uint32_t scan_flags, HdlFingerprintTag* out,
                                 uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    std::vector<std::wstring> mods;
    if (module_basenames && module_count) {
        mods.reserve(module_count);
        for (uint32_t i = 0; i < module_count; ++i) {
            mods.push_back(BasenameLower(module_basenames[i]));
        }
    }
    std::vector<FpImportSignal> imps;
    if (imports && import_count) {
        imps.reserve(import_count);
        for (uint32_t i = 0; i < import_count; ++i) {
            FpImportSignal s;
            s.module = NarrowLower(imports[i].module);
            s.name = NarrowLower(imports[i].name);
            imps.push_back(std::move(s));
        }
    }
    std::vector<HdlFingerprintTag> tags;
    ClassifyFingerprint(mods, imps, pe_subsystem, scan_flags, &tags);
    const uint32_t need = static_cast<uint32_t>(tags.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, tags.data(), need * sizeof(HdlFingerprintTag));
    }
    *inout_count = need;
    return HDL_OK;
}

}  // namespace hdl
