#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdllib/hdllib.h"
#include "ipc/wire.hpp"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static bool JsonWriteCandidates(JsonWriter& w, hdl::proto::Reader& r, uint32_t count) {
    w.Key("candidates");
    w.BeginArray();
    for (uint32_t i = 0; i < count; ++i) {
        HdlCandidate cand{};
        if (!hdl::proto::TakeHdlCandidate(r, cand)) {
            w.EndArray();
            return false;
        }
        w.BeginObject();
        w.Key("id");
        w.HexStr(cand.id);
        w.Key("kind");
        w.Num(cand.kind);
        w.Key("conf");
        w.Num(cand.confidence);
        w.Key("addr");
        w.HexStr(cand.address);
        w.Key("tag");
        w.Str(cand.tag);
        w.EndObject();
    }
    w.EndArray();
    return true;
}

static bool JsonWriteHeatFields(JsonWriter& w, hdl::proto::Reader& r, uint32_t count) {
    w.Key("fields");
    w.BeginArray();
    for (uint32_t i = 0; i < count; ++i) {
        HdlHeatField hf{};
        if (!hdl::proto::TakeHdlHeatField(r, hf)) {
            w.EndArray();
            return false;
        }
        w.BeginObject();
        w.Key("offset");
        w.Num(hf.offset);
        w.Key("changes");
        w.Num(hf.changes);
        w.Key("kind");
        w.Num(hf.kind);
        w.Key("size");
        w.Num(hf.reserved);
        w.Key("value");
        w.HexStr(hf.last_value);
        w.EndObject();
    }
    w.EndArray();
    return true;
}

static std::string Narrow(const wchar_t* w) {
    return WideToUtf8(w ? w : L"");
}

bool ClientParsePred(const wchar_t* spec, HdlFieldPred* out) {
    if (!spec || !out) {
        return false;
    }
    std::wstring s(spec);
    auto take = [&](std::wstring& rest) -> std::wstring {
        const size_t p = rest.find(L':');
        if (p == std::wstring::npos) {
            std::wstring t = rest;
            rest.clear();
            return t;
        }
        std::wstring t = rest.substr(0, p);
        rest = rest.substr(p + 1);
        return t;
    };
    const std::wstring kind = take(s);
    const std::wstring off = take(s);
    out->offset = _wtoi(off.c_str());
    out->a = 0;
    out->b = 0;
    if (kind == L"eq_i32") {
        out->kind = HDL_PRED_EQ_I32;
        out->a = _wtoi64(s.c_str());
    } else if (kind == L"range_i32") {
        out->kind = HDL_PRED_RANGE_I32;
        out->a = _wtoi64(take(s).c_str());
        out->b = _wtoi64(s.c_str());
    } else if (kind == L"le_i32") {
        out->kind = HDL_PRED_LE_I32;
        out->a = _wtoi64(s.c_str());
    } else if (kind == L"eq_u64") {
        out->kind = HDL_PRED_EQ_U64;
        out->a = static_cast<int64_t>(_wcstoui64(s.c_str(), nullptr, 0));
    } else if (kind == L"eq_f32") {
        out->kind = HDL_PRED_EQ_F32;
        float f = static_cast<float>(_wtof(s.c_str()));
        uint32_t bits = 0;
        memcpy(&bits, &f, 4);
        out->a = bits;
    } else if (kind == L"ptr") {
        out->kind = HDL_PRED_PTR;
    } else if (kind == L"vtable") {
        out->kind = HDL_PRED_VTABLE;
    } else {
        return false;
    }
    return true;
}

CommandResult CmdDiscoverCreate(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    AppendPod(req, static_cast<uint32_t>(OpDiscoverCreate));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t id = 0;
    if (!r.TakePod(st) || !r.TakePod(id)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("session");
    w.HexStr(id);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdDiscoverClose(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint64_t id = 0;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverClose));
    AppendPod(req, id);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    return CmdStatus(ctx.cmd.c_str(), st, "{}");
}

CommandResult CmdDiscoverAdd(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint64_t id = 0;
    uint32_t kind = HDL_CAND_ADDRESS;
    uint64_t addr = 0;
    std::string tag;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--kind") == 0 && i + 1 < ctx.argc) {
            ++i;
            if (_wcsicmp(ctx.argv[i], L"function") == 0) {
                kind = HDL_CAND_FUNCTION;
            } else if (_wcsicmp(ctx.argv[i], L"object") == 0) {
                kind = HDL_CAND_OBJECT;
            } else {
                kind = HDL_CAND_ADDRESS;
            }
        } else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc) {
            addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc) {
            tag = Narrow(ctx.argv[++i]);
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverAddCandidate));
    AppendPod(req, id);
    AppendPod(req, kind);
    AppendPod(req, addr);
    AppendString(req, tag.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t cand = 0;
    r.TakePod(st);
    r.TakePod(cand);
    JsonWriter w;
    w.BeginObject();
    w.Key("cand");
    w.HexStr(cand);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdDiscoverConstraint(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint64_t id = 0;
    uint32_t size = 0;
    uint32_t flags = 0;
    uint32_t max_results = 64;
    std::wstring module;
    std::string tag;
    std::vector<HdlFieldPred> preds;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
            size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--pred") == 0 && i + 1 < ctx.argc) {
            HdlFieldPred p{};
            if (!ClientParsePred(ctx.argv[++i], &p)) {
                return FailArg(ctx, L"Bad --pred");
            }
            preds.push_back(p);
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_results = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc) {
            tag = Narrow(ctx.argv[++i]);
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverConstraintScan));
    AppendPod(req, id);
    AppendPod(req, size);
    AppendPod(req, static_cast<uint32_t>(preds.size()));
    AppendPod(req, flags);
    AppendPod(req, max_results);
    AppendWString(req, module.c_str());
    AppendString(req, tag.c_str());
    for (const auto& p : preds) {
        hdl::proto::AppendHdlFieldPred(req, p);
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    return CmdStatus(ctx.cmd.c_str(), st, "{}");
}

CommandResult CmdDiscoverSynth(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint64_t id = 0;
    uint64_t cand = 0;
    uint32_t before = 0;
    uint32_t after = 24;
    uint32_t flags = HDL_SEARCH_IMAGE;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--cand") == 0 && i + 1 < ctx.argc) {
            cand = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--before") == 0 && i + 1 < ctx.argc) {
            before = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--after") == 0 && i + 1 < ctx.argc) {
            after = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverSynthesizePattern));
    AppendPod(req, id);
    AppendPod(req, cand);
    AppendPod(req, before);
    AppendPod(req, after);
    AppendPod(req, flags);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    HdlSynthesizedPattern out{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlSynthesizedPattern(r, out)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("hits");
    w.Num(out.unique_hits);
    w.Key("match");
    w.HexStr(out.match_addr);
    w.Key("resolved");
    w.HexStr(out.resolved_addr);
    w.Key("pattern");
    w.Str(out.pattern);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdDiscoverPathscan(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t depth = 2;
    uint32_t max_off = 0x1000;
    uint32_t max_n = 64;
    uint32_t flags = HDL_SEARCH_IMAGE;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--depth") == 0 && i + 1 < ctx.argc) {
            depth = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max-offset") == 0 && i + 1 < ctx.argc) {
            max_off = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_n = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverPathConsensus));
    AppendPod(req, target);
    AppendPod(req, depth);
    AppendPod(req, max_off);
    AppendPod(req, max_n);
    AppendPod(req, flags);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlPointerPath> paths;
    paths.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlPointerPath path{};
        if (!hdl::proto::TakeHdlPointerPath(r, path)) {
            return FailBadResp(ctx);
        }
        if (i == 0) {
            hdlcli::RememberPath(ctx.controller, path, module.empty() ? nullptr : module.c_str());
        }
        paths.push_back(path);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("paths");
    w.BeginArray();
    for (const auto& path : paths) {
        w.BeginObject();
        w.Key("base");
        w.HexStr(path.static_base);
        w.Key("depth");
        w.Num(path.depth);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdDiscoverPathValidate(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t expected = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint64_t base = 0;
    uint32_t depth = 0;
    int32_t offs[8]{};
    uint32_t off_n = 0;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--base") == 0 && i + 1 < ctx.argc) {
            base = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--depth") == 0 && i + 1 < ctx.argc) {
            depth = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--offs") == 0 && i + 1 < ctx.argc) {
            ++i;
            wchar_t* p = ctx.argv[i];
            while (p && *p && off_n < 8) {
                offs[off_n++] = static_cast<int32_t>(wcstol(p, &p, 0));
                if (*p == L',') {
                    ++p;
                }
            }
        }
    }
    if (!base || depth == 0 || depth > 8 || off_n < depth) {
        return FailArg(ctx, L"Need --base HEX --depth N --offs A,B,...");
    }
    HdlPointerPath path{};
    path.static_base = base;
    path.depth = depth;
    for (uint32_t i = 0; i < depth; ++i) {
        path.offsets[i] = offs[i];
    }
    AppendPod(req, static_cast<uint32_t>(OpDiscoverPathValidate));
    AppendPod(req, expected);
    AppendPod(req, static_cast<uint32_t>(1));
    hdl::proto::AppendHdlPointerPath(req, path);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t kept = 0;
    if (!r.TakePod(st) || !r.TakePod(kept)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlPointerPath> paths;
    paths.reserve(kept);
    for (uint32_t i = 0; i < kept; ++i) {
        HdlPointerPath p{};
        if (!hdl::proto::TakeHdlPointerPath(r, p)) {
            return FailBadResp(ctx);
        }
        if (i == 0) {
            hdlcli::RememberPath(ctx.controller, p, nullptr);
        }
        paths.push_back(p);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("kept");
    w.Num(kept);
    w.Key("paths");
    w.BeginArray();
    for (const auto& p : paths) {
        w.BeginObject();
        w.Key("base");
        w.HexStr(p.static_base);
        w.Key("depth");
        w.Num(p.depth);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdDiscoverScan(CmdCtx& ctx) {
    using namespace hdl::proto;
    extern bool ParseValueType(const wchar_t* s, int32_t* out);
    extern bool EncodeTypedValue(int32_t type, const wchar_t* text, std::vector<uint8_t>& out);

    uint64_t disc_id = 0;
    int32_t value_type = HDL_VALUE_I32;
    std::wstring value_w;
    std::string tag = "scan";
    uint32_t search_flags = 0;
    std::wstring module;
    uint32_t max_hits = 64;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            disc_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--type") == 0 && i + 1 < ctx.argc) {
            if (!ParseValueType(ctx.argv[++i], &value_type)) {
                return FailArg(ctx, L"Bad --type");
            }
        } else if (wcscmp(ctx.argv[i], L"--value") == 0 && i + 1 < ctx.argc) {
            value_w = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc) {
            tag = Narrow(ctx.argv[++i]);
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            search_flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            search_flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_hits = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    if (!disc_id || value_w.empty()) {
        return FailArg(ctx, L"Need --session ID --type T --value V");
    }

    std::vector<uint8_t> value_bytes;
    if (!EncodeTypedValue(value_type, value_w.c_str(), value_bytes)) {
        return FailArg(ctx, L"Bad --value");
    }

    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverScanValue));
    AppendPod(req, disc_id);
    AppendPod(req, static_cast<uint64_t>(0));
    AppendPod(req, static_cast<uint64_t>(0));
    AppendPod(req, value_type);
    AppendPod(req, static_cast<int32_t>(HDL_CMP_EXACT));
    AppendPod(req, static_cast<uint32_t>(0));
    AppendPod(req, max_hits);
    AppendPod(req, static_cast<uint32_t>(value_bytes.size()));
    AppendBytes(req, value_bytes.data(), value_bytes.size());
    AppendPod(req, search_flags);
    AppendWString(req, module.c_str());
    AppendString(req, tag.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t added = 0;
    if (!r.TakePod(st) || !r.TakePod(added)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("added");
    w.Num(added);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

static bool OpenInWide(const wchar_t* path, std::ifstream* out) {
    if (!path || !out) {
        return false;
    }
    out->open(path, std::ios::binary);
    return static_cast<bool>(*out);
}

static bool OpenOutWide(const wchar_t* path, std::ofstream* out) {
    if (!path || !out) {
        return false;
    }
    out->open(path, std::ios::binary);
    return static_cast<bool>(*out);
}

CommandResult CmdDiscoverMisc(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint64_t id = 0;
    uint64_t addr = 0;
    uint64_t cand_id = 0;
    uint32_t size = 64;
    uint32_t args_n = 0;
    uint32_t flags = 0;
    uint32_t rank_flags = 0;
    std::wstring module;
    std::wstring out_path;
    std::wstring in_path;
    std::string name;
    std::string dll;
    std::string import_name;
    std::vector<uint64_t> diff_addrs;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc) {
            const uint64_t a = _wcstoui64(ctx.argv[++i], nullptr, 0);
            if (ctx.cmd == L"discover-diff") {
                diff_addrs.push_back(a);
            } else {
                addr = a;
            }
        } else if (wcscmp(ctx.argv[i], L"--seed") == 0 && i + 1 < ctx.argc) {
            addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
            size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc) {
            args_n = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--name") == 0 && i + 1 < ctx.argc) {
            name = Narrow(ctx.argv[++i]);
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--dll") == 0 && i + 1 < ctx.argc) {
            dll = Narrow(ctx.argv[++i]);
        } else if (wcscmp(ctx.argv[i], L"--import") == 0 && i + 1 < ctx.argc) {
            import_name = Narrow(ctx.argv[++i]);
        } else if (wcscmp(ctx.argv[i], L"--out") == 0 && i + 1 < ctx.argc) {
            out_path = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--in") == 0 && i + 1 < ctx.argc) {
            in_path = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--id") == 0 && i + 1 < ctx.argc) {
            cand_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--flags") == 0 && i + 1 < ctx.argc) {
            rank_flags = static_cast<uint32_t>(wcstoul(ctx.argv[++i], nullptr, 0));
        }
    }
    if (ctx.cmd == L"discover-watch") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverWatch));
        AppendPod(req, id);
        AppendPod(req, addr);
        AppendPod(req, args_n);
    } else if (ctx.cmd == L"discover-unwatch") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverUnwatchAll));
        AppendPod(req, id);
    } else if (ctx.cmd == L"discover-action-begin") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverActionBegin));
        AppendPod(req, id);
        AppendString(req, name.c_str());
    } else if (ctx.cmd == L"discover-action-end") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverActionEnd));
        AppendPod(req, id);
    } else if (ctx.cmd == L"discover-watch-region") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverWatchRegion));
        AppendPod(req, id);
        AppendPod(req, addr);
        AppendPod(req, size);
    } else if (ctx.cmd == L"discover-heat") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetHeat));
        AppendPod(req, id);
        AppendPod(req, addr);
        AppendPod(req, size ? size : static_cast<uint32_t>(64));
    } else if (ctx.cmd == L"discover-rank") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverRankFunctions));
        AppendPod(req, id);
        AppendString(req, name.c_str());
        AppendPod(req, rank_flags);
        AppendPod(req, static_cast<uint32_t>(64));
    } else if (ctx.cmd == L"discover-cluster") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverClusterType));
        AppendPod(req, id);
        AppendPod(req, addr);
        AppendPod(req, size);
        AppendPod(req, flags ? flags : 0u);
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, module.c_str());
    } else if (ctx.cmd == L"discover-cands") {
        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetCandidates));
        AppendPod(req, id);
        AppendPod(req, static_cast<uint32_t>(256));
    } else if (ctx.cmd == L"discover-watch-import") {
        if (!id || dll.empty() || import_name.empty()) {
            return FailArg(ctx,
                           L"Need --session ID --dll NAME --import NAME [--args N] [--module MOD]");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverWatchImport));
        AppendPod(req, id);
        AppendWString(req, module.c_str());
        AppendString(req, dll.c_str());
        AppendString(req, import_name.c_str());
        AppendPod(req, args_n);
    } else if (ctx.cmd == L"discover-reset-heat") {
        if (!id || !addr) {
            return FailArg(ctx, L"Need --session ID --addr HEX");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverResetHeat));
        AppendPod(req, id);
        AppendPod(req, addr);
    } else if (ctx.cmd == L"discover-export") {
        if (!id || out_path.empty()) {
            return FailArg(ctx, L"Need --session ID --out PATH");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverExport));
        AppendPod(req, id);
        AppendPod(req, static_cast<uint32_t>(65536));
    } else if (ctx.cmd == L"discover-import") {
        if (!id || in_path.empty()) {
            return FailArg(ctx, L"Need --session ID --in PATH");
        }
        std::ifstream fin;
        if (!OpenInWide(in_path.c_str(), &fin)) {
            return FailArg(ctx, L"Cannot read --in file");
        }
        std::string json((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        AppendPod(req, static_cast<uint32_t>(OpDiscoverImport));
        AppendPod(req, id);
        AppendString(req, json.c_str());
    } else if (ctx.cmd == L"discover-diff") {
        if (!id || diff_addrs.size() < 2) {
            return FailArg(ctx, L"Need --session ID --addr A --addr B ... [--size N]");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverDiffObjects));
        AppendPod(req, id);
        AppendPod(req, static_cast<uint32_t>(diff_addrs.size()));
        AppendPod(req, size ? size : static_cast<uint32_t>(64));
        AppendPod(req, static_cast<uint32_t>(64));
        for (uint64_t a : diff_addrs) {
            AppendPod(req, a);
        }
    } else if (ctx.cmd == L"discover-apply-watch") {
        if (!id || !addr) {
            return FailArg(ctx, L"Need --session ID --addr HEX [--size N]");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverApplyWatchHits));
        AppendPod(req, id);
        AppendPod(req, addr);
        AppendPod(req, size ? size : static_cast<uint32_t>(64));
    } else if (ctx.cmd == L"discover-evidence") {
        if (!id || !cand_id) {
            return FailArg(ctx, L"Need --session ID --id CAND_ID");
        }
        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetEvidence));
        AppendPod(req, id);
        AppendPod(req, cand_id);
        AppendPod(req, static_cast<uint32_t>(160));
    } else {
        return FailArg(ctx, L"Unknown discover command");
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return FailBadResp(ctx);
    }
    if (ctx.cmd == L"discover-heat" || ctx.cmd == L"discover-diff") {
        uint32_t count = 0;
        r.TakePod(count);
        JsonWriter w;
        w.BeginObject();
        if (!JsonWriteHeatFields(w, r, count)) {
            return FailBadResp(ctx);
        }
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    } else if (ctx.cmd == L"discover-rank" || ctx.cmd == L"discover-cands") {
        uint32_t count = 0;
        r.TakePod(count);
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        if (!JsonWriteCandidates(w, r, count)) {
            return FailBadResp(ctx);
        }
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    } else if (ctx.cmd == L"discover-export") {
        uint32_t json_size = 0;
        r.TakePod(json_size);
        if (st == HDL_OK && json_size) {
            std::string json(json_size, '\0');
            if (r.Take(json.data(), json_size)) {
                std::ofstream fout;
                if (!OpenOutWide(out_path.c_str(), &fout)) {
                    JsonWriter w;
                    w.BeginObject();
                    w.Key("bytes");
                    w.Num(json_size);
                    w.Key("out");
                    w.Str(out_path);
                    w.EndObject();
                    return CmdStatus(ctx.cmd.c_str(), HDL_E_FAILED, w.Take());
                }
                fout.write(json.data(), static_cast<std::streamsize>(json.size()));
            }
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("bytes");
        w.Num(json_size);
        w.Key("out");
        w.Str(out_path);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    } else if (ctx.cmd == L"discover-evidence") {
        std::string ev;
        r.TakeString(ev);
        JsonWriter w;
        w.BeginObject();
        w.Key("evidence");
        w.Str(ev);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    } else {
        return CmdStatus(ctx.cmd.c_str(), st, "{}");
    }
}
