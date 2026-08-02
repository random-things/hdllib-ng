#include "discover_internal.hpp"

#include "json/json.hpp"

namespace hdl {

HdlStatus DiscoverExport(HdlDiscoverSession* session, char* buf, uint32_t* inout_size) {
    if (!session || !inout_size) {
        return HDL_E_INVALID_ARG;
    }
    constexpr uint32_t kMaxExport = 4u * 1024u * 1024u;

    auto* s = reinterpret_cast<Session*>(session);
    hdl::json::Writer w;
    {
        std::lock_guard<std::mutex> lock(s->mu);
        w.BeginObject();
        w.Key("version");
        w.Num(1);
        w.Key("actions");
        w.BeginArray();
        for (size_t i = 0; i < s->actions.size(); ++i) {
            w.Str(s->actions[i].name);
        }
        w.EndArray();
        w.Key("candidates");
        w.BeginArray();
        for (size_t i = 0; i < s->cands.size(); ++i) {
            const auto& c = s->cands[i];
            w.BeginObject();
            w.Key("id");
            w.Num(c.id);
            w.Key("kind");
            w.Num(c.kind);
            w.Key("address");
            w.Num(c.address);
            w.Key("confidence");
            w.Num(c.confidence);
            w.Key("field_offset");
            w.Num(c.field_offset);
            w.Key("tag");
            w.Str(c.tag);
            w.Key("evidence");
            const auto ev = s->evidence.find(c.id);
            w.Str(ev != s->evidence.end() ? ev->second.data() : "");
            w.EndObject();
        }
        w.EndArray();
        w.Key("heat");
        w.BeginArray();
        for (size_t ri = 0; ri < s->regions.size(); ++ri) {
            const auto& r = s->regions[ri];
            w.BeginObject();
            w.Key("base");
            w.Num(r.base);
            w.Key("fields");
            w.BeginArray();
            for (size_t fi = 0; fi < r.heat.size(); ++fi) {
                const auto& hf = r.heat[fi];
                w.BeginObject();
                w.Key("offset");
                w.Num(hf.offset);
                w.Key("changes");
                w.Num(hf.changes);
                w.Key("kind");
                w.Num(hf.kind);
                w.Key("size");
                w.Num(hf.reserved);
                w.Key("last_value");
                w.Num(hf.last_value);
                w.EndObject();
            }
            w.EndArray();
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
    }
    const std::string json = w.Take();

    const uint32_t need = static_cast<uint32_t>(json.size() + 1);
    if (need > kMaxExport) {
        return HDL_E_FAILED;
    }
    if (!buf || *inout_size < need) {
        *inout_size = need;
        return HDL_E_BUFFER_SMALL;
    }
    memcpy(buf, json.c_str(), need);
    *inout_size = need - 1;
    return HDL_OK;
}

HdlStatus DiscoverImport(HdlDiscoverSession* session, const char* json, uint32_t size) {
    if (!session || !json || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    const std::string text(json, json + size);
    std::vector<std::string> objs;
    if (!hdl::json::ExtractObjectArray(text, "candidates", &objs)) {
        return HDL_E_INVALID_ARG;
    }

    auto* s = reinterpret_cast<Session*>(session);
    uint32_t added = 0;
    std::lock_guard<std::mutex> lock(s->mu);
    for (const auto& obj : objs) {
        uint64_t address = 0;
        uint32_t kind = HDL_CAND_ADDRESS;
        uint32_t confidence = 50;
        uint32_t field_offset = 0;
        std::string tag;
        std::string evidence;
        if (!hdl::json::ExtractU64(obj, "address", &address) || !address) {
            continue;
        }
        hdl::json::ExtractU32(obj, "kind", &kind);
        hdl::json::ExtractU32(obj, "confidence", &confidence);
        hdl::json::ExtractU32(obj, "field_offset", &field_offset);
        hdl::json::ExtractString(obj, "tag", &tag);
        hdl::json::ExtractString(obj, "evidence", &evidence);
        if (kind != HDL_CAND_ADDRESS && kind != HDL_CAND_FUNCTION && kind != HDL_CAND_OBJECT &&
            kind != HDL_CAND_FIELD) {
            kind = HDL_CAND_ADDRESS;
        }
        HdlCandidate c =
            MakeCand(s, kind, address, tag.empty() ? nullptr : tag.c_str(), confidence);
        if (kind == HDL_CAND_FIELD) {
            c.field_offset = field_offset;
        }
        if (!evidence.empty()) {
            s->evidence[c.id] = {};
            strncpy_s(s->evidence[c.id].data(), s->evidence[c.id].size(), evidence.c_str(),
                      _TRUNCATE);
        }
        s->cands.push_back(c);
        ++added;
    }
    return added ? HDL_OK : HDL_E_NOT_FOUND;
}

} // namespace hdl
