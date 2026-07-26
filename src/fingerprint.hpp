#pragma once

#include "hdllib/hdllib.h"

#include <string>
#include <vector>

namespace hdl {

struct FpImportSignal {
    std::string module; /* basename, lowercase */
    std::string name;   /* API name */
};

/*
 * Pure classifier: no process walk. module_basenames should be lowercase basenames.
 * pe_subsystem: IMAGE_SUBSYSTEM_* (0 = unknown).
 */
void ClassifyFingerprint(const std::vector<std::wstring>& module_basenames,
                         const std::vector<FpImportSignal>& imports, uint16_t pe_subsystem,
                         uint32_t scan_flags, std::vector<HdlFingerprintTag>* out);

HdlStatus EnumFingerprintTags(uint32_t scan_flags, HdlFingerprintTag* out, uint32_t* inout_count);

HdlStatus ClassifyFingerprintApi(const wchar_t* const* module_basenames, uint32_t module_count,
                                 const HdlFingerprintImport* imports, uint32_t import_count,
                                 uint16_t pe_subsystem, uint32_t scan_flags, HdlFingerprintTag* out,
                                 uint32_t* inout_count);

}  // namespace hdl
